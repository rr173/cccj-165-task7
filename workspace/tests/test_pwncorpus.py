"""End-to-end tests for the pwncorpus pipeline.

core.PREFIX_LEN is shrunk to 2 during tests so bucket membership is cheap to
control; every module reads it at call time, so server + core stay consistent.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from pwncorpus import core, db, server, verifier

core.PREFIX_LEN = 2  # test-only: 256 buckets instead of 1M


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest().upper()


def pw_with_prefix(prefix: str, n: int, start: int = 0, tag: str = "pw"):
    """Deterministically find n distinct passwords whose SHA-1 starts with prefix."""
    out, i = [], start
    while len(out) < n:
        cand = f"{tag}-{i}"
        if sha1(cand).startswith(prefix):
            out.append(cand)
        i += 1
    return out


class CoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-test-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    # -- helpers -----------------------------------------------------------
    def publish(self, k=2):
        info = core.build_candidate(self.conn, k)
        core.activate(self.conn, info["version"])
        return info["version"]

    def bucket(self, version, prefix):
        return self.conn.execute(
            "SELECT suffix, cnt FROM pub_buckets WHERE version=? AND prefix=?",
            (version, prefix)).fetchall()

    # -- tests -------------------------------------------------------------
    def test_ingest_dedup_same_batch_not_double_counted(self):
        items = ["alpha", "beta", "alpha", "gamma"]
        r1 = core.ingest_batch(self.conn, "breach-a", items)
        r2 = core.ingest_batch(self.conn, "breach-a", list(items))  # same content
        r3 = core.ingest_batch(self.conn, "breach-a", ["different", "set"],
                               idem_key="key-1")
        r4 = core.ingest_batch(self.conn, "breach-a", ["different", "set"],
                               idem_key="key-1")  # same idempotency key
        self.assertFalse(r1["duplicate"])
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r1["batch_id"], r2["batch_id"])
        self.assertFalse(r3["duplicate"])
        self.assertTrue(r4["duplicate"])
        self.assertEqual(r3["batch_id"], r4["batch_id"])
        # occurrences of 'alpha' must be exactly 2 (from the single batch)
        version = self.publish(k=1)
        rows = self.conn.execute(
            "SELECT cnt FROM pub_buckets WHERE version=? AND suffix=?",
            (version, sha1("alpha")[core.PREFIX_LEN:])).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cnt"], 2)

    def test_concurrent_ingest_same_batch(self):
        items = [f"shared-{i}" for i in range(50)]
        results, errors = [], []

        def work():
            c = db.connect(self.db_path)
            try:
                results.append(core.ingest_batch(c, "breach-x", list(items)))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(lambda _: work(), range(8)))
        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for r in results if not r["duplicate"]), 1)
        self.assertEqual(len({r["batch_id"] for r in results}), 1)
        n = self.conn.execute("SELECT COUNT(*) c FROM batches").fetchone()["c"]
        self.assertEqual(n, 1)
        total = self.conn.execute(
            "SELECT COALESCE(SUM(cnt),0) s FROM batch_items").fetchone()["s"]
        self.assertEqual(total, 50)  # counted exactly once

    def test_concurrent_ingest_distinct_batches(self):
        def work(i):
            c = db.connect(self.db_path)
            try:
                return core.ingest_batch(c, f"src-{i}", [f"u-{i}-{j}" for j in range(20)])
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(work, range(8)))
        self.assertEqual(len({r["batch_id"] for r in results}), 8)
        total = self.conn.execute(
            "SELECT COALESCE(SUM(cnt),0) s FROM batch_items").fetchone()["s"]
        self.assertEqual(total, 160)

    def test_threshold_suppresses_small_buckets(self):
        lonely = pw_with_prefix("AB", 1, tag="lonely")          # bucket of 1
        trio = pw_with_prefix("CD", 3, tag="trio")              # bucket of 3
        core.ingest_batch(self.conn, "s", lonely + trio)
        version = self.publish(k=3)
        self.assertEqual(self.bucket(version, "AB"), [])        # suppressed
        self.assertEqual(len(self.bucket(version, "CD")), 3)    # kept
        v, body = core.query_range(self.conn, "AB")
        self.assertIsNone(body)                                 # not queryable
        v, body = core.query_range(self.conn, "CD")
        self.assertEqual(len(body.strip().split("\n")), 3)

    def test_retraction_only_via_new_publication(self):
        pw = pw_with_prefix("EF", 2, tag="victim")
        b1 = core.ingest_batch(self.conn, "leak-1", pw)
        v1 = self.publish(k=1)
        _, body = core.query_range(self.conn, "EF")
        self.assertIsNotNone(body)

        core.retract_batch(self.conn, b1["batch_id"])
        # current version untouched until a new one is built AND activated
        _, body = core.query_range(self.conn, "EF")
        self.assertIsNotNone(body)

        info = core.build_candidate(self.conn, k=1)
        _, body = core.query_range(self.conn, "EF")  # candidate not active yet
        self.assertIsNotNone(body)
        core.activate(self.conn, info["version"])
        _, body = core.query_range(self.conn, "EF")
        self.assertIsNone(body)  # gone from the serving version
        # old version still stored and exportable/verifiable
        out = os.path.join(self.tmp, "v1")
        core.export_version(self.conn, v1, out)
        self.assertEqual(verifier.verify_export(out), [])
        self.assertEqual(verifier.lookup(out, pw[0]), 1)

    def test_correction_removes_false_positive(self):
        good = pw_with_prefix("11", 2, tag="good")
        bad = pw_with_prefix("22", 1, tag="oops")
        b = core.ingest_batch(self.conn, "leak-2", good + bad)
        core.add_corrections(self.conn, b["batch_id"], [bad[0]])
        self.publish(k=1)
        _, body = core.query_range(self.conn, "22")
        self.assertIsNone(body)
        _, body = core.query_range(self.conn, "11")
        self.assertEqual(len(body.strip().split("\n")), 2)

    def test_threshold_change_requires_new_version_and_old_stays_valid(self):
        pair = pw_with_prefix("33", 2, tag="pair")
        core.ingest_batch(self.conn, "s", pair)
        v1 = self.publish(k=2)
        self.assertEqual(len(self.bucket(v1, "33")), 2)
        v2 = self.publish(k=3)  # stricter threshold: bucket disappears
        self.assertEqual(self.bucket(v2, "33"), [])
        _, body = core.query_range(self.conn, "33")
        self.assertIsNone(body)
        # v1 export still verifies against ITS OWN threshold
        out1, out2 = os.path.join(self.tmp, "v1"), os.path.join(self.tmp, "v2")
        core.export_version(self.conn, v1, out1)
        core.export_version(self.conn, v2, out2)
        self.assertEqual(verifier.verify_export(out1), [])
        self.assertEqual(verifier.verify_export(out2), [])
        with open(os.path.join(out1, "manifest.json")) as fh:
            self.assertEqual(json.load(fh)["threshold_k"], 2)

    def test_export_tampering_detected(self):
        core.ingest_batch(self.conn, "s", pw_with_prefix("44", 3, tag="t"))
        v = self.publish(k=2)
        out = os.path.join(self.tmp, "exp")
        core.export_version(self.conn, v, out)
        self.assertEqual(verifier.verify_export(out), [])
        # tamper: inflate a count
        f = os.path.join(out, "buckets", "44.txt")
        lines = open(f).read().splitlines()
        s, c = lines[0].split(":")
        lines[0] = f"{s}:{int(c) + 100}"
        open(f, "w").write("\n".join(lines) + "\n")
        self.assertTrue(any("sha256" in e for e in verifier.verify_export(out)))

    def test_verifier_rejects_below_threshold_bucket(self):
        core.ingest_batch(self.conn, "s", pw_with_prefix("55", 3, tag="z"))
        v = self.publish(k=2)
        out = os.path.join(self.tmp, "exp")
        core.export_version(self.conn, v, out)
        # hand-craft a below-threshold bucket + matching manifest entry
        body = "0" * (40 - core.PREFIX_LEN) + ":1\n"
        open(os.path.join(out, "buckets", "99.txt"), "w").write(body)
        mpath = os.path.join(out, "manifest.json")
        m = json.load(open(mpath))
        m["files"]["99"] = hashlib.sha256(body.encode()).hexdigest()
        payload = {f: m[f] for f in
                   ("version", "hash_algo", "prefix_len", "threshold_k",
                    "created_at", "files")}
        m["manifest_sha256"] = hashlib.sha256(
            core.canonical_json(payload).encode()).hexdigest()
        json.dump(m, open(mpath, "w"))
        errors = verifier.verify_export(out)
        self.assertTrue(any("below threshold" in e for e in errors), errors)

    def test_no_raw_password_in_storage(self):
        secret = "correct-horse-battery-staple-!9"
        core.ingest_batch(self.conn, "leak", [secret, "other-1", "other-2"])
        self.publish(k=1)
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.close()
        with open(self.db_path, "rb") as fh:
            raw = fh.read()
        self.assertNotIn(secret.encode(), raw)
        self.assertIn(sha1(secret).encode(), raw)  # fingerprint IS there
        self.conn = db.connect(self.db_path)

    # -- draft staleness / refresh -----------------------------------------
    def test_ingest_before_confirm_blocks_activation(self):
        pa = pw_with_prefix("A1", 2, tag="first")
        pb = pw_with_prefix("B2", 2, tag="late")
        core.ingest_batch(self.conn, "base", pa)
        v1 = self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)  # draft of current data
        # source data changes while the draft awaits confirmation
        core.ingest_batch(self.conn, "late-arrival", pb)
        self.assertTrue(core.review_state(self.conn)["candidate"]["stale"])
        with self.assertRaises(core.Conflict):
            core.activate(self.conn, info["version"])
        # the confirmation did not take effect; serving version unchanged
        self.assertEqual(core.current_version(self.conn), v1)
        v, body = core.query_range(self.conn, "B2")
        self.assertEqual((v, body), (v1, None))  # late batch not served
        _, body = core.query_range(self.conn, "A1")
        self.assertIsNotNone(body)

    def test_activate_before_ingest_leaves_update_for_next_version(self):
        pa = pw_with_prefix("A3", 2, tag="base")
        pb = pw_with_prefix("B4", 2, tag="next")
        core.ingest_batch(self.conn, "base", pa)
        self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)
        core.activate(self.conn, info["version"])  # confirmation commits first
        core.ingest_batch(self.conn, "late", pb)   # later source update
        v, body = core.query_range(self.conn, "B4")
        self.assertEqual(v, info["version"])
        self.assertIsNone(body)  # not in the just-activated version
        nxt = core.build_candidate(self.conn, k=1)  # ...waits for the next one
        core.activate(self.conn, nxt["version"])
        _, body = core.query_range(self.conn, "B4")
        self.assertIsNotNone(body)

    def test_refresh_candidate_keeps_threshold_and_version(self):
        pa = pw_with_prefix("C1", 3, tag="r1")
        core.ingest_batch(self.conn, "s1", pa)
        self.publish(k=2)
        info = core.build_candidate(self.conn, k=2)
        pb = pw_with_prefix("C1", 2, start=100, tag="r2")
        core.ingest_batch(self.conn, "s2", pb)  # makes the draft stale
        out = core.refresh_candidate(self.conn, info["version"])
        self.assertEqual(out["version"], info["version"])   # same draft
        self.assertEqual(out["threshold_k"], 2)             # threshold kept
        self.assertEqual(out["suffix_count"], 5)
        self.assertFalse(core.review_state(self.conn)["candidate"]["stale"])
        core.activate(self.conn, info["version"])  # now allowed
        _, body = core.query_range(self.conn, "C1")
        self.assertEqual(len(body.strip().split("\n")), 5)
        # refresh is only for candidates
        with self.assertRaises(core.Conflict):
            core.refresh_candidate(self.conn, info["version"])  # now active
        with self.assertRaises(core.NotFound):
            core.refresh_candidate(self.conn, 999)

    def test_retract_and_corrections_stale_the_candidate(self):
        pa = pw_with_prefix("D1", 2, tag="d1")
        pb = pw_with_prefix("D2", 2, tag="d2")
        b1 = core.ingest_batch(self.conn, "s1", pa)
        b2 = core.ingest_batch(self.conn, "s2", pb)
        self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)
        core.retract_batch(self.conn, b1["batch_id"])
        self.assertTrue(core.review_state(self.conn)["candidate"]["stale"])
        with self.assertRaises(core.Conflict):
            core.activate(self.conn, info["version"])
        core.refresh_candidate(self.conn, info["version"])
        self.assertFalse(core.review_state(self.conn)["candidate"]["stale"])
        core.add_corrections(self.conn, b2["batch_id"], [pb[0]])
        self.assertTrue(core.review_state(self.conn)["candidate"]["stale"])
        core.refresh_candidate(self.conn, info["version"])
        core.activate(self.conn, info["version"])
        _, body = core.query_range(self.conn, "D1")
        self.assertIsNone(body)  # retracted batch is gone
        _, body = core.query_range(self.conn, "D2")
        self.assertEqual(len(body.strip().split("\n")), 1)  # one corrected away

    def test_noop_source_writes_do_not_stale_candidate(self):
        pa = pw_with_prefix("E1", 2, tag="e1")
        b = core.ingest_batch(self.conn, "s", pa)
        self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)

        def stale():
            return core.review_state(self.conn)["candidate"]["stale"]

        core.ingest_batch(self.conn, "s", list(pa))  # duplicate batch: no change
        self.assertFalse(stale())
        core.retract_batch(self.conn, b["batch_id"])  # effective
        self.assertTrue(stale())
        core.refresh_candidate(self.conn, info["version"])
        core.retract_batch(self.conn, b["batch_id"])  # no-op: already retracted
        self.assertFalse(stale())
        core.add_corrections(self.conn, b["batch_id"], [pa[0]])  # new rows
        self.assertTrue(stale())
        core.refresh_candidate(self.conn, info["version"])
        core.add_corrections(self.conn, b["batch_id"], [pa[0]])  # duplicates
        self.assertFalse(stale())
        core.activate(self.conn, info["version"])  # unchanged path still works

    def test_activate_expected_manifest_binding(self):
        pa = pw_with_prefix("F1", 2, tag="f1")
        core.ingest_batch(self.conn, "s", pa)
        self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)
        with self.assertRaises(core.Conflict):
            core.activate(self.conn, info["version"], expected_manifest="0" * 64)
        # a refresh replaces the draft: a confirmation prepared before it
        # (bound to the old manifest) must no longer go through
        pb = pw_with_prefix("F2", 2, tag="f2")
        core.ingest_batch(self.conn, "s2", pb)
        core.refresh_candidate(self.conn, info["version"])
        with self.assertRaises(core.Conflict):
            core.activate(self.conn, info["version"],
                          expected_manifest=info["manifest_sha256"])
        pub = core.get_publication(self.conn, info["version"])
        core.activate(self.conn, info["version"],
                      expected_manifest=pub["manifest_sha256"])
        self.assertEqual(core.current_version(self.conn), info["version"])

    def test_concurrent_activate_and_ingest_ordering(self):
        pa = pw_with_prefix("80", 2, tag="raceA")
        pb = pw_with_prefix("81", 2, tag="raceB")
        core.ingest_batch(self.conn, "A", pa)
        v1 = self.publish(k=1)
        info = core.build_candidate(self.conn, k=1)  # candidate holds only A
        barrier = threading.Barrier(2)
        outcome, errors = {}, []

        def do_ingest():
            c = db.connect(self.db_path)
            try:
                barrier.wait()
                outcome["ingest"] = core.ingest_batch(c, "B", list(pb))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        def do_activate():
            c = db.connect(self.db_path)
            try:
                barrier.wait()
                try:
                    outcome["activate"] = core.activate(c, info["version"])
                except core.Conflict as exc:
                    outcome["activate_conflict"] = str(exc)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        t1 = threading.Thread(target=do_ingest)
        t2 = threading.Thread(target=do_activate)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(errors, [])
        self.assertIn("ingest", outcome)  # the source write always commits
        if "activate_conflict" in outcome:
            # update committed first: confirmation rejected, serving unchanged
            self.assertEqual(core.current_version(self.conn), v1)
            v, body = core.query_range(self.conn, "81")
            self.assertEqual((v, body), (v1, None))
        else:
            # activation committed first: update waits for the next version
            self.assertEqual(core.current_version(self.conn), info["version"])
            v, body = core.query_range(self.conn, "81")
            self.assertEqual(v, info["version"])
            self.assertIsNone(body)
        # either way the late batch is picked up by the NEXT build
        nxt = core.build_candidate(self.conn, k=1)
        core.activate(self.conn, nxt["version"])
        _, body = core.query_range(self.conn, "81")
        self.assertIsNotNone(body)


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-http-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        db.init(self.db_path)
        conn = db.connect(self.db_path)
        self.tok_ingest = core.create_token(conn, "ing", ["ingest"])
        self.tok_pub = core.create_token(conn, "pub", ["publish"])
        self.tok_retract = core.create_token(conn, "ret", ["retract"])
        conn.close()
        self.srv = server.make_server(self.db_path, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def http(self, method, path, body=None, token=None, raw=False):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                return resp.status, (payload if raw else json.loads(payload)), dict(resp.headers)
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                return e.code, json.loads(payload), dict(e.headers)
            except json.JSONDecodeError:
                return e.code, payload, dict(e.headers)

    def http_form(self, path, fields):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def publish(self, k=2):
        st, body, _ = self.http("POST", "/api/publications/build", {"k": k},
                                token=self.tok_pub)
        self.assertEqual(st, 201, body)
        v = body["version"]
        st, body, _ = self.http("POST", f"/api/publications/{v}/activate",
                                token=self.tok_pub)
        self.assertEqual(st, 200, body)
        return v

    def test_authz_enforced(self):
        st, _, _ = self.http("POST", "/api/batches",
                             {"source": "x", "items": ["a"]})
        self.assertEqual(st, 401)
        st, _, _ = self.http("POST", "/api/batches",
                             {"source": "x", "items": ["a"]}, token=self.tok_pub)
        self.assertEqual(st, 403)  # publish token may not ingest
        st, _, _ = self.http("POST", "/api/publications/build", {"k": 1},
                             token=self.tok_ingest)
        self.assertEqual(st, 403)  # ingest token may not publish
        st, body, _ = self.http("POST", "/api/batches",
                                {"source": "x", "items": ["a"]},
                                token=self.tok_ingest)
        self.assertEqual(st, 201, body)
        bid = body["batch_id"]
        st, _, _ = self.http("POST", f"/api/batches/{bid}/retract",
                             token=self.tok_ingest)
        self.assertEqual(st, 403)  # ingest token may not retract
        st, _, _ = self.http("POST", f"/api/batches/{bid}/retract",
                             token=self.tok_retract)
        self.assertEqual(st, 200)

    def test_range_api_and_version_header(self):
        pws = pw_with_prefix("77", 3, tag="api")
        self.http("POST", "/api/batches", {"source": "s", "items": pws},
                  token=self.tok_ingest)
        st, body, _ = self.http("GET", "/api/range/77")
        self.assertEqual(st, 503)  # nothing published yet
        v = self.publish(k=2)
        st, body, hdr = self.http("GET", "/api/range/77", raw=True)
        self.assertEqual(st, 200)
        self.assertEqual(hdr.get("X-Corpus-Version"), str(v))
        lines = body.decode().strip().split("\n")
        self.assertEqual(len(lines), 3)
        suffixes = {l.split(":")[0] for l in lines}
        self.assertEqual(suffixes, {sha1(p)[core.PREFIX_LEN:] for p in pws})
        st, body, _ = self.http("GET", "/api/range/zz")
        self.assertEqual(st, 400)  # invalid prefix
        st, body, _ = self.http("GET", "/api/range/99")
        self.assertEqual(st, 404)  # unknown bucket

    def test_no_raw_password_in_api_surface(self):
        secret = "sup3r-secret-p@ssphrase"
        st, body, _ = self.http("POST", "/api/batches",
                                {"source": "s", "items": [secret, "x", "x"]},
                                token=self.tok_ingest)
        self.assertEqual(st, 201)
        self.assertNotIn(secret, json.dumps(body))
        self.publish(k=1)
        prefix = sha1(secret)[:core.PREFIX_LEN]
        st, body, hdr = self.http("GET", f"/api/range/{prefix}", raw=True)
        self.assertNotIn(secret.encode(), body)
        st, body, _ = self.http("GET", "/api/publications", token=self.tok_pub)
        self.assertNotIn(secret, json.dumps(body))
        st, body, _ = self.http("GET", f"/review?token={self.tok_pub}", raw=True)
        self.assertEqual(st, 200)
        self.assertNotIn(secret.encode(), body)

    def test_duplicate_batch_over_http(self):
        payload = {"source": "s", "items": ["a", "b", "a"], "idempotency_key": "k1"}
        st1, b1, _ = self.http("POST", "/api/batches", payload, token=self.tok_ingest)
        st2, b2, _ = self.http("POST", "/api/batches", payload, token=self.tok_ingest)
        self.assertEqual((st1, st2), (201, 200))
        self.assertEqual(b1["batch_id"], b2["batch_id"])
        self.assertTrue(b2["duplicate"])

    def test_no_version_mixing_during_activation(self):
        # v1: bucket 80 has suffixes from batch A; v2 adds batch B suffixes.
        pa = pw_with_prefix("80", 2, tag="batchA")
        pb = pw_with_prefix("80", 2, tag="batchB")
        self.http("POST", "/api/batches", {"source": "A", "items": pa},
                  token=self.tok_ingest)
        v1 = self.publish(k=2)
        self.http("POST", "/api/batches", {"source": "B", "items": pb},
                  token=self.tok_ingest)
        st, cand, _ = self.http("POST", "/api/publications/build", {"k": 2},
                                token=self.tok_pub)
        v2 = cand["version"]

        _, body_v1, _ = self.http("GET", "/api/range/80", raw=True)
        expected = {}
        conn = db.connect(self.db_path)
        for v in (v1,):
            _, b = core.query_range(conn, "80")
            expected[v] = b
        conn.close()

        stop = threading.Event()
        violations = []

        def reader():
            while not stop.is_set():
                try:
                    st, body, hdr = self.http("GET", "/api/range/80", raw=True)
                except Exception:
                    continue
                if st != 200:
                    continue
                ver = int(hdr["X-Corpus-Version"])
                text = body.decode()
                ok = (ver == v1 and text == expected[v1]) or \
                     (ver == v2 and len(text.strip().split("\n")) == 4
                      and ver == int(hdr["X-Corpus-Version"]))
                if not ok:
                    violations.append((ver, text))

        def activator():
            import time
            time.sleep(0.15)
            self.http("POST", f"/api/publications/{v2}/activate",
                      token=self.tok_pub)

        readers = [threading.Thread(target=reader) for _ in range(6)]
        act = threading.Thread(target=activator)
        for t in readers:
            t.start()
        act.start()
        act.join()
        import time
        time.sleep(0.4)
        stop.set()
        for t in readers:
            t.join()
        # every response must be a complete, single-version body
        self.assertEqual(violations, [])
        # and after the switch, only v2 is served
        _, body, hdr = self.http("GET", "/api/range/80", raw=True)
        self.assertEqual(int(hdr["X-Corpus-Version"]), v2)
        self.assertEqual(len(body.decode().strip().split("\n")), 4)

    def test_retired_version_not_served_but_verifiable(self):
        pws = pw_with_prefix("90", 2, tag="old")
        st, b, _ = self.http("POST", "/api/batches",
                             {"source": "s", "items": pws}, token=self.tok_ingest)
        bid = b["batch_id"]
        v1 = self.publish(k=2)
        # retract + rebuild + activate
        self.http("POST", f"/api/batches/{bid}/retract", token=self.tok_retract)
        v2 = self.publish(k=2)
        st, body, hdr = self.http("GET", "/api/range/90")
        self.assertEqual((st, hdr.get("X-Corpus-Version")), (404, str(v2)))
        # v1 manifest still fetchable (verifiability), export verifies
        st, manifest, _ = self.http("GET", f"/api/publications/{v1}/manifest")
        self.assertEqual(st, 200)
        self.assertEqual(manifest["status"], "retired")
        conn = db.connect(self.db_path)
        out = os.path.join(self.tmp, "v1-export")
        core.export_version(conn, v1, out)
        conn.close()
        self.assertEqual(verifier.verify_export(out), [])
        self.assertEqual(verifier.lookup(out, pws[0]), 1)

    def test_review_page_requires_publish_scope(self):
        st, _, _ = self.http("GET", "/review")
        self.assertEqual(st, 401)
        st, _, _ = self.http("GET", f"/review?token={self.tok_ingest}")
        self.assertEqual(st, 403)
        st, body, _ = self.http("GET", f"/review?token={self.tok_pub}", raw=True)
        self.assertEqual(st, 200)
        self.assertIn(b"Publication review", body)

    def test_stale_activation_rejected_and_refresh_over_api(self):
        pa = pw_with_prefix("A0", 2, tag="apiA")
        pb = pw_with_prefix("A1", 2, tag="apiB")
        self.http("POST", "/api/batches", {"source": "a", "items": pa},
                  token=self.tok_ingest)
        v1 = self.publish(k=1)
        st, cand, _ = self.http("POST", "/api/publications/build", {"k": 1},
                                token=self.tok_pub)
        v2 = cand["version"]
        # source data changes before the draft is confirmed
        self.http("POST", "/api/batches", {"source": "b", "items": pb},
                  token=self.tok_ingest)
        st, body, _ = self.http("POST", f"/api/publications/{v2}/activate",
                                token=self.tok_pub)
        self.assertEqual(st, 409)
        self.assertIn("stale", body["error"])
        # the serving version is untouched
        st, _, hdr = self.http("GET", "/api/range/A1")
        self.assertEqual((st, hdr.get("X-Corpus-Version")), (404, str(v1)))
        # the detail endpoint flags the stale draft
        st, detail, _ = self.http("GET", f"/api/publications/{v2}",
                                  token=self.tok_pub)
        self.assertTrue(detail["publication"]["stale"])
        # refresh keeps version + threshold, then activation succeeds
        st, refreshed, _ = self.http("POST", f"/api/publications/{v2}/refresh",
                                     token=self.tok_pub)
        self.assertEqual(st, 200)
        self.assertEqual((refreshed["version"], refreshed["threshold_k"]), (v2, 1))
        st, detail, _ = self.http("GET", f"/api/publications/{v2}",
                                  token=self.tok_pub)
        self.assertFalse(detail["publication"]["stale"])
        st, _, _ = self.http("POST", f"/api/publications/{v2}/activate",
                             token=self.tok_pub)
        self.assertEqual(st, 200)
        st, body, hdr = self.http("GET", "/api/range/A1", raw=True)
        self.assertEqual(st, 200)
        self.assertEqual(hdr.get("X-Corpus-Version"), str(v2))
        # refresh is only for candidates
        st, _, _ = self.http("POST", f"/api/publications/{v2}/refresh",
                             token=self.tok_pub)
        self.assertEqual(st, 409)

    def test_review_page_stale_banner_and_refresh_form(self):
        pa = pw_with_prefix("B0", 2, tag="pgA")
        pb = pw_with_prefix("B1", 2, tag="pgB")
        self.http("POST", "/api/batches", {"source": "a", "items": pa},
                  token=self.tok_ingest)
        self.publish(k=1)
        st, cand, _ = self.http("POST", "/api/publications/build", {"k": 1},
                                token=self.tok_pub)
        v2 = cand["version"]
        self.http("POST", "/api/batches", {"source": "b", "items": pb},
                  token=self.tok_ingest)
        # stale draft: banner + refresh form, no activate form
        st, page, _ = self.http("GET", f"/review?token={self.tok_pub}", raw=True)
        self.assertEqual(st, 200)
        self.assertIn(b"STALE", page)
        self.assertIn(b"/review/refresh", page)
        self.assertNotIn(b"Activate v", page)
        # confirming the stale draft via the form is rejected, serving intact
        st, _ = self.http_form("/review/activate",
                               {"version": v2, "token": self.tok_pub})
        self.assertEqual(st, 409)
        _, health, _ = self.http("GET", "/api/health")
        self.assertNotEqual(health["active_version"], v2)
        # refresh via the review form (token re-entry), then activate
        st, _ = self.http_form("/review/refresh",
                               {"version": v2, "token": self.tok_pub})
        self.assertEqual(st, 200)
        st, page, _ = self.http("GET", f"/review?token={self.tok_pub}", raw=True)
        self.assertIn(b"Activate v", page)
        # the confirmation is bound to the reviewed draft's manifest
        st, detail, _ = self.http("GET", f"/api/publications/{v2}",
                                  token=self.tok_pub)
        manifest = detail["publication"]["manifest_sha256"]
        st, _ = self.http_form("/review/activate",
                               {"version": v2, "token": self.tok_pub,
                                "expected_manifest": "bogus"})
        self.assertEqual(st, 409)
        st, _ = self.http_form("/review/activate",
                               {"version": v2, "token": self.tok_pub,
                                "expected_manifest": manifest})
        self.assertEqual(st, 200)
        _, health, _ = self.http("GET", "/api/health")
        self.assertEqual(health["active_version"], v2)


if __name__ == "__main__":
    unittest.main()
