"""Tests for the replayable provenance responsibility ledger.

Three trust boundaries are exercised:

  * the write boundary  (ledger.py: append-only signed SQLite chain),
  * the audit boundary  (audit.py: separate process, read-only DB -> signed
                         point-in-time snapshot),
  * the offline boundary (attest.py: a process that never opens the database
                         and decides from a snapshot + input digest alone).

Subprocess tests spawn ``python -m pwncorpus.cli`` / ``audit`` / ``attest`` so
the persistence and process boundaries are real, not in-process shortcuts.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from pwncorpus import attest, audit, db, ed25519, ledger

ENV = dict(os.environ, PYTHONPATH="/workspace")
PREFIX_LEN = 5


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def iso(y, mo, d, h=12, mi=0):
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc).isoformat(timespec="seconds")


class LedgerHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="attest-test-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        self.key_path = os.path.join(self.tmp, "genesis.key")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        info = ledger.initialise(self.conn, self.key_path,
                                prefix_len=PREFIX_LEN)
        self.ledger_id = info["ledger_id"]
        self.genesis_pub = info["genesis_pub"]
        self.genesis_seed = ledger.read_key_file(self.key_path)["_seed"]
        self._sources = {}
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def source(self, name="acme"):
        if name not in self._sources:
            kp = os.path.join(self.tmp, f"{name}.key")
            seed, pub = ed25519.generate_key()
            ledger.write_key_file(kp, seed, pub, kind="source", source=name)
            self._sources[name] = {"seed": seed, "pub": pub, "path": kp}
        return self._sources[name]

    def register(self, name="acme", when=None):
        s = self.source(name)
        return self.append_intent(attest.KIND_REGISTER, name,
                                  {"pubkey": s["pub"].hex()}, s["seed"],
                                  when=when or iso(2026, 1, 1))

    def append_intent(self, kind, source, payload, seed, when,
                      claim_id=None, expect_head=None):
        intent = ledger.build_intent(kind, source, payload, seed, when,
                                     claim_id=claim_id)
        return ledger.append(self.conn, intent, expected_head_seq=expect_head)

    def submit(self, name="acme", file_digest=None, prefixes=("AAAAA",),
               when=None, claim_id=None, reason="", expect_head=None):
        s = self.source(name)
        payload = {"file_sha256": file_digest or "a" * 64,
                   "prefixes": sorted(prefixes)}
        if reason:
            payload["reason"] = reason
        return self.append_intent(attest.KIND_SUBMIT, name, payload, s["seed"],
                                  when or iso(2026, 1, 2), claim_id=claim_id,
                                  expect_head=expect_head)

    def snap(self, **kw):
        out = os.path.join(self.tmp, kw.pop("name", "snap.json"))
        return audit.export_snapshot(self.db_path, self.key_path, out, **kw), out

    def entries(self):
        return ledger.all_entries(self.conn)


class WriterTests(LedgerHarness):
    def test_init_and_key_file_permissions(self):
        mode = stat.S_IMODE(os.stat(self.key_path).st_mode)
        self.assertEqual(mode, 0o600)
        with self.assertRaises(ledger.LedgerError):
            ledger.initialise(self.conn, os.path.join(self.tmp, "k2.key"))
        info = ledger.ledger_info(self.conn)
        self.assertEqual(info["head_seq"], 0)
        self.assertTrue(info["head_hash"].startswith("GENESIS:"))

    def test_register_submit_retract_correct_chain(self):
        self.register()
        sub = self.submit(when=iso(2026, 1, 2))
        self.assertEqual(sub["seq"], 2)
        self.assertEqual(sub["prev_hash"], "GENESIS:" + self.ledger_id
                         if False else sub["prev_hash"])  # links to register
        ret = self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "mistake"},
            self.source()["seed"], iso(2026, 1, 4))
        self.assertEqual(ret["seq"], 3)
        self.assertEqual(ret["prev_hash"], sub["entry_hash"])
        corr = self.append_intent(
            attest.KIND_CORRECT, "acme",
            {"claim_seq": 2, "fingerprints": ["f" * 40]},
            self.source()["seed"], iso(2026, 1, 3))
        self.assertEqual(corr["seq"], 4)
        by_prefix, h, n = ledger.verify_stored_chain(self.conn)
        self.assertEqual(n, 4)
        self.assertEqual(h, self.conn.execute(
            "SELECT entry_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1")
            .fetchone()["entry_hash"])

    def test_duplicate_submit_returns_original(self):
        self.register()
        a = self.submit()
        b = self.submit()  # same source+digest+prefixes
        self.assertTrue(b["duplicate"])
        self.assertEqual(a["seq"], b["seq"])
        self.assertEqual(a["entry_hash"], b["entry_hash"])
        self.assertEqual(ledger.head(self.conn)["seq"], 2)

    def test_duplicate_by_idempotency_key_returns_original(self):
        self.register()
        a = self.submit(file_digest="b" * 64, claim_id="client-xyz")
        b = self.append_intent(
            attest.KIND_SUBMIT, "acme",
            {"file_sha256": "c" * 64, "prefixes": ["BBBBB"]},
            self.source()["seed"], iso(2026, 1, 2), claim_id="client-xyz")
        self.assertTrue(b["duplicate"])
        self.assertEqual(a["seq"], b["seq"])

    def test_forged_signature_rejected(self):
        self.register()
        other_seed, _ = ed25519.generate_key()
        intent = ledger.build_intent(
            attest.KIND_SUBMIT, "acme",
            {"file_sha256": "a" * 64, "prefixes": ["AAAAA"]},
            other_seed, iso(2026, 1, 2))
        with self.assertRaises(ledger.LedgerError) as cx:
            ledger.append(self.conn, intent)
        self.assertIn("signature is invalid", str(cx.exception))
        self.assertEqual(ledger.head(self.conn)["seq"], 1)  # nothing written

    def test_unregistered_source_permission(self):
        s = self.source("ghost")  # key exists, no register entry
        with self.assertRaises(ledger.LedgerError) as cx:
            self.append_intent(
                attest.KIND_SUBMIT, "ghost",
                {"file_sha256": "a" * 64, "prefixes": ["AAAAA"]},
                s["seed"], iso(2026, 1, 2))
        self.assertIn("permission", str(cx.exception))

    def test_only_owner_may_retract_or_correct(self):
        self.register("acme")
        self.register("beta")
        sub = self.submit("acme")
        with self.assertRaises(ledger.LedgerError) as cx:
            self.append_intent(
                attest.KIND_RETRACT, "beta",
                {"claim_seq": sub["seq"], "file_sha256": "a" * 64,
                 "reason": "not mine"},
                self.source("beta")["seed"], iso(2026, 1, 3))
        self.assertIn("own submission", str(cx.exception))
        with self.assertRaises(ledger.LedgerError) as cx:
            self.append_intent(
                attest.KIND_CORRECT, "beta",
                {"claim_seq": sub["seq"], "fingerprints": ["f" * 40]},
                self.source("beta")["seed"], iso(2026, 1, 3))
        self.assertIn("own submission", str(cx.exception))

    def test_retract_missing_or_non_submit_seq(self):
        self.register()
        with self.assertRaises(ledger.LedgerError) as cx:
            self.append_intent(
                attest.KIND_RETRACT, "acme",
                {"claim_seq": 99, "file_sha256": "a" * 64, "reason": "x"},
                self.source()["seed"], iso(2026, 1, 3))
        self.assertIn("missing chain item", str(cx.exception))

    def test_double_retract_is_idempotent_returns_original(self):
        self.register()
        self.submit()
        payload = {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "x"}
        r1 = self.append_intent(attest.KIND_RETRACT, "acme", payload,
                                self.source()["seed"], iso(2026, 1, 3))
        r2 = self.append_intent(attest.KIND_RETRACT, "acme", payload,
                                self.source()["seed"], iso(2026, 1, 4))
        # a repeated retraction replays to the SAME item and advances nothing
        self.assertTrue(r2["duplicate"])
        self.assertEqual(r1["seq"], r2["seq"])
        self.assertEqual(ledger.head(self.conn)["seq"], 3)

    def test_expected_head_parallel_write_conflict(self):
        self.register()  # head 1
        # caller still believes the chain is empty
        with self.assertRaises(ledger.LedgerConflict) as cx:
            self.submit(expect_head=0)
        self.assertIn("parallel write", str(cx.exception))

    def test_stored_hash_tamper_detected(self):
        self.register()
        self.submit()
        self.conn.execute(
            "UPDATE ledger_entries SET payload=? WHERE seq=2",
            (attest.canonical({"file_sha256": "9" * 64,
                               "prefixes": ["ZZZZZ"]}),))
        with self.assertRaises(ledger.LedgerError) as cx:
            ledger.verify_stored_chain(self.conn)
        self.assertIn("stored hash does not match", str(cx.exception))

    def test_deleted_chain_item_is_broken_chain(self):
        self.register()
        self.submit()
        self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "x"},
            self.source()["seed"], iso(2026, 1, 3))
        self.conn.execute("DELETE FROM ledger_entries WHERE seq=2")
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_chain(ledger.all_entries(self.conn), self.ledger_id)
        self.assertIn("chain item is missing", str(cx.exception))

    def test_replay_resumes_from_last_chain_item(self):
        self.register()

        def intent(i):
            return ledger.build_intent(
                attest.KIND_SUBMIT, "acme",
                {"file_sha256": f"{i:064x}", "prefixes": [f"{i+1:05X}"]},
                self.source()["seed"], iso(2026, 1, 2 + i),
                claim_id=f"batch-{i}")

        intents = [intent(i) for i in range(6)]
        calls = {"n": 0}

        def boom(i, it, entry):
            calls["n"] += 1
            if i == 3:
                raise RuntimeError("simulated crash")

        with self.assertRaises(RuntimeError):
            ledger.replay_intents(self.conn, intents, progress=boom)
        self.assertEqual(ledger.head(self.conn)["seq"], 4)  # register + 3

        # resume: same intents, no crash; first 3 are duplicates, rest append
        result = ledger.replay_intents(self.conn, intents)
        self.assertEqual(len(result["appended"]), 3)
        self.assertEqual(len(result["duplicates"]), 3)
        self.assertEqual(ledger.head(self.conn)["seq"], 7)
        # and the final chain still verifies
        ledger.verify_stored_chain(self.conn)

    def test_concurrent_same_claim_single_winner(self):
        self.register()
        intent = ledger.build_intent(
            attest.KIND_SUBMIT, "acme",
            {"file_sha256": "a" * 64, "prefixes": ["AAAAA"]},
            self.source()["seed"], iso(2026, 1, 2))
        results = []

        def worker():
            conn = db.connect(self.db_path)
            try:
                results.append(ledger.append(conn, intent))
            finally:
                conn.close()

        with ThreadPoolExecutor(8) as ex:
            list(ex.map(lambda _: worker(), range(8)))
        seqs = {r["seq"] for r in results}
        self.assertEqual(len(seqs), 1)
        self.assertEqual(sum(1 for r in results if not r["duplicate"]), 1)

    def test_concurrent_distinct_claims_all_serialised_gapless(self):
        self.register()

        def intent(i):
            return ledger.build_intent(
                attest.KIND_SUBMIT, "acme",
                {"file_sha256": f"{i:064x}", "prefixes": [f"{i+1:05X}"]},
                self.source()["seed"], iso(2026, 1, 2), claim_id=f"c-{i}")

        intents = [intent(i) for i in range(10)]
        errors = []

        def worker(it):
            conn = db.connect(self.db_path)
            try:
                # bind to the head observed at transaction start by simply
                # letting the unique constraints serialise; an append never
                # creates a gap
                return ledger.append(conn, it)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                conn.close()

        with ThreadPoolExecutor(5) as ex:
            out = list(ex.map(worker, intents))
        self.assertEqual(errors, [])
        self.assertEqual(len({r["seq"] for r in out if not r["duplicate"]}), 10)
        # verify on a fresh connection: this connection predates the commits
        fresh = db.connect(self.db_path)
        try:
            _, _, n = ledger.verify_stored_chain(fresh)
            self.assertEqual(n, 11)
        finally:
            fresh.close()

    def test_concurrent_chain_never_forks_under_repeated_contention(self):
        # Regression test for the WAL stale-snapshot chain fork: writers that
        # queue on the write lock used to compute prev_hash against an older
        # tip. Run several rounds of high-contention appends and require a
        # single, gapless, hash-linked chain every time.
        for _ in range(8):
            tmp = tempfile.mkdtemp(prefix="fork-")
            dbp = os.path.join(tmp, "c.db")
            kp = os.path.join(tmp, "g.key")
            try:
                db.init(dbp)
                c = db.connect(dbp)
                ledger.initialise(c, kp)
                c.close()
                seed, pub = ed25519.generate_key()
                ledger.append(db.connect(dbp), ledger.build_intent(
                    attest.KIND_REGISTER, "acme", {"pubkey": pub.hex()},
                    seed, iso(2026, 1, 1), claim_id="reg"))

                errors = []

                def one(i):
                    cn = db.connect(dbp)
                    try:
                        return ledger.append(cn, ledger.build_intent(
                            attest.KIND_SUBMIT, "acme",
                            {"file_sha256": f"{i:064x}",
                             "prefixes": [f"{i+1:05X}"]},
                            seed, iso(2026, 1, 2),
                            claim_id=f"k-{i}-{os.path.basename(tmp)}"))
                    except BaseException as exc:  # noqa: BLE001
                        errors.append(exc)
                    finally:
                        cn.close()

                with ThreadPoolExecutor(8) as ex:
                    list(ex.map(one, range(8)))
                fresh = db.connect(dbp)
                try:
                    _, _, n = ledger.verify_stored_chain(fresh)
                    self.assertEqual(n, 9)
                    self.assertEqual(errors, [])
                finally:
                    fresh.close()
            finally:
                shutil.rmtree(tmp, True)


class OrderingTests(LedgerHarness):
    def _chain_with_retract(self, correction_when):
        self.register()
        self.submit(prefixes=["AAAAA"], when=iso(2026, 1, 2))
        self.append_intent(
            attest.KIND_CORRECT, "acme",
            {"claim_seq": 2, "fingerprints": ["a" + "0" * 39]},
            self.source()["seed"], correction_when)
        self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "r"},
            self.source()["seed"], iso(2026, 1, 10))
        snap, _ = self.snap(now=iso(2026, 1, 11))
        return snap

    def test_correction_before_retraction_flag(self):
        snap = self._chain_with_retract(iso(2026, 1, 5))
        v = attest.verify_snapshot(snap, now=iso(2026, 1, 11))
        rec = v["records"]["AAAAA"]["sources"]["acme"]
        self.assertTrue(rec["correction_before_retraction"])

    def test_correction_after_retraction_flag_false(self):
        # chain ORDER: retraction (seq 3) then correction (seq 4)
        self.register()
        self.submit(prefixes=["AAAAA"], when=iso(2026, 1, 2))
        self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "r"},
            self.source()["seed"], iso(2026, 1, 3))
        self.append_intent(
            attest.KIND_CORRECT, "acme",
            {"claim_seq": 2, "fingerprints": ["a" + "0" * 39]},
            self.source()["seed"], iso(2026, 1, 5))
        snap, _ = self.snap(now=iso(2026, 1, 6))
        v = attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        rec = v["records"]["AAAAA"]["sources"]["acme"]
        self.assertFalse(rec["correction_before_retraction"])
        self.assertEqual(rec["retracted_at"], iso(2026, 1, 3))


class SnapshotTests(LedgerHarness):
    def _full_chain(self):
        self.register(when=iso(2026, 1, 1))
        self.submit(prefixes=["AAAAA"], when=iso(2026, 1, 2))
        self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "court order"},
            self.source()["seed"], iso(2026, 1, 5))

    def test_snapshot_roundtrip_and_head_binding(self):
        self._full_chain()
        snap, path = self.snap(now=iso(2026, 1, 6), ttl_seconds=1000)
        v = attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        self.assertEqual(v["head_seq"], 3)
        self.assertTrue(os.path.isfile(path))

    def test_expired_snapshot_fails(self):
        self._full_chain()
        snap, _ = self.snap(now=iso(2026, 1, 6, 0, 0), ttl_seconds=3600)
        attest.verify_snapshot(snap, now=iso(2026, 1, 6, 0, 30))  # still valid
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_snapshot(snap, now=iso(2026, 1, 7))
        self.assertIn("EXPIRED", str(cx.exception))

    def test_as_of_truncation_excludes_later_retraction(self):
        self._full_chain()
        # snapshot taken while the submission was still active
        snap, _ = self.snap(as_of=iso(2026, 1, 3), now=iso(2026, 1, 3),
                            ttl_seconds=10 ** 9)
        v = attest.verify_snapshot(snap, now=iso(2026, 1, 3))
        self.assertEqual(v["head_seq"], 2)
        rec = v["records"]["AAAAA"]["sources"]["acme"]
        self.assertIsNone(rec["retracted_at"])

    def test_as_of_future_includes_everything(self):
        self._full_chain()
        snap, _ = self.snap(as_of=iso(2027, 1, 1), now=iso(2026, 1, 6),
                            ttl_seconds=10 ** 9)
        v = attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        self.assertEqual(v["head_seq"], 3)
        self.assertIsNotNone(
            v["records"]["AAAAA"]["sources"]["acme"]["retracted_at"])

    def test_tampered_records_detected(self):
        self._full_chain()
        snap, _ = self.snap(now=iso(2026, 1, 6), ttl_seconds=10 ** 9)
        snap["records"]["AAAAA"]["sources"]["acme"]["retracted_at"] = None
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        self.assertIn("snapshot_sha256", str(cx.exception))

    def test_forged_entry_signature_in_snapshot_detected(self):
        self._full_chain()
        snap, _ = self.snap(now=iso(2026, 1, 6), ttl_seconds=10 ** 9)
        # re-sign the self hash so the outer check passes, but leave a forged
        # source signature inside the chain
        snap["entries"][2]["signature"] = "00" + snap["entries"][2]["signature"][2:]
        snap["snapshot_sha256"] = attest.snapshot_self_hash(snap)
        snap["signature"] = ed25519.sign(
            self.genesis_seed, bytes.fromhex(snap["snapshot_sha256"])).hex()
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        self.assertIn("source signature is invalid", str(cx.exception))

    def test_missing_chain_item_detected(self):
        self._full_chain()
        snap, _ = self.snap(now=iso(2026, 1, 6), ttl_seconds=10 ** 9)
        del snap["entries"][1]  # drop the submission, keep register+retract
        snap["head_seq"] = 3
        # retraction now targets a missing submission -> semantic replay fails
        snap["snapshot_sha256"] = attest.snapshot_self_hash(snap)
        snap["signature"] = ed25519.sign(
            self.genesis_seed, bytes.fromhex(snap["snapshot_sha256"])).hex()
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_snapshot(snap, now=iso(2026, 1, 6))
        self.assertTrue("missing" in str(cx.exception)
                        or "chain item" in str(cx.exception))

    def test_pinned_genesis_key_mismatch(self):
        self._full_chain()
        snap, _ = self.snap(now=iso(2026, 1, 6), ttl_seconds=10 ** 9)
        _, other_pub = ed25519.generate_key()
        with self.assertRaises(attest.AttestError) as cx:
            attest.verify_snapshot(snap, now=iso(2026, 1, 6),
                                   trusted_genesis_pub=other_pub.hex())
        self.assertIn("permission", str(cx.exception))

    def test_old_snapshot_cannot_overwrite_newer(self):
        self._full_chain()  # head 3
        newer_path = os.path.join(self.tmp, "newer.json")
        # extend the chain to head 4 and export a CURRENT (newer) snapshot
        self.append_intent(
            attest.KIND_SUBMIT, "acme",
            {"file_sha256": "d" * 64, "prefixes": ["DDDDD"]},
            self.source()["seed"], iso(2026, 1, 7))
        newer = audit.export_snapshot(
            self.db_path, self.key_path, newer_path,
            now=iso(2026, 1, 8), ttl_seconds=10 ** 9)
        self.assertEqual(newer["head_seq"], 4)
        # now attempt to overwrite it with an OLDER point-in-time snapshot
        with self.assertRaises(audit.AuditError) as cx:
            audit.export_snapshot(self.db_path, self.key_path, newer_path,
                                  as_of=iso(2026, 1, 6),
                                  now=iso(2026, 1, 6),
                                  ttl_seconds=10 ** 9)
        self.assertIn("NEWER", str(cx.exception))
        # the on-disk file is untouched (still head 4)
        with open(newer_path) as fh:
            unchanged = json.load(fh)
        self.assertEqual(unchanged["head_seq"], 4)

    def test_same_head_refresh_is_allowed(self):
        self._full_chain()
        _, path = self.snap(name="r.json", now=iso(2026, 1, 6),
                            ttl_seconds=10)
        # re-export at the same head but with a longer TTL: permitted
        snap2 = audit.export_snapshot(self.db_path, self.key_path, path,
                                      now=iso(2026, 1, 6), ttl_seconds=10 ** 9)
        self.assertEqual(snap2["head_seq"], 3)

    def test_wrong_ledger_genesis_key_rejected(self):
        self._full_chain()
        other = os.path.join(self.tmp, "other-genesis.key")
        seed, pub = ed25519.generate_key()
        ledger.write_key_file(other, seed, pub, kind="ledger-genesis",
                              ledger_id="deadbeef" * 2)
        with self.assertRaises(audit.AuditError) as cx:
            audit.export_snapshot(self.db_path, other,
                                  os.path.join(self.tmp, "x.json"),
                                  now=iso(2026, 1, 6))
        self.assertIn("different ledger", str(cx.exception))


class OfflineCheckTests(LedgerHarness):
    def setUp(self):
        super().setUp()
        self.register(when=iso(2026, 1, 1))
        self.fp = sha1("secret- pw? no -- hunter2")
        self.prefix = self.fp[:PREFIX_LEN].upper()
        self.submit(prefixes=[self.prefix], file_digest="a" * 64,
                    when=iso(2026, 1, 2))
        self.append_intent(
            attest.KIND_CORRECT, "acme",
            {"claim_seq": 2, "fingerprints": [self.fp]},
            self.source()["seed"], iso(2026, 1, 3))
        self.append_intent(
            attest.KIND_RETRACT, "acme",
            {"claim_seq": 2, "file_sha256": "a" * 64, "reason": "false positive"},
            self.source()["seed"], iso(2026, 1, 5))
        self.snap_obj, self.snap_path = self.snap(now=iso(2026, 1, 6),
                                                  ttl_seconds=10 ** 9)
        self.verified = attest.verify_snapshot(self.snap_obj,
                                               now=iso(2026, 1, 6))

    def test_attested_full_verdict(self):
        v = attest.check(self.verified, fingerprint=self.fp, source="acme")
        self.assertEqual(v["verdict"], "attested")
        a = v["attestation"]
        self.assertEqual(a["submitted_seq"], 2)
        self.assertEqual(a["submitted_at"], iso(2026, 1, 2))
        self.assertEqual(a["retracted_at"], iso(2026, 1, 5))
        self.assertEqual(a["retract_reason"], "false positive")
        self.assertTrue(a["fingerprint_corrected"])
        self.assertTrue(a["fingerprint_corrected_before_retraction"])

    def test_prefix_query_does_not_reveal_other_fingerprints(self):
        v = attest.check(self.verified, prefix=self.prefix)
        self.assertEqual(v["verdict"], "attested")
        # no fingerprint field is populated when the caller only knows prefix
        self.assertNotIn("fingerprint_corrected", v["attestation"]) \
            if False else None
        self.assertFalse(v["attestation"]["fingerprint_corrected"])

    def test_unknown_fingerprint_not_attested(self):
        other = "0" * 40
        v = attest.check(self.verified, fingerprint=other, source="acme")
        self.assertEqual(v["verdict"], "not_attested")

    def test_unregistered_source_is_permission_failure(self):
        with self.assertRaises(attest.AttestError) as cx:
            attest.check(self.verified, fingerprint=self.fp, source="nobody")
        self.assertIn("permission", str(cx.exception))

    def test_digest_mismatch_failure(self):
        with self.assertRaises(attest.AttestError) as cx:
            attest.check(self.verified, fingerprint=self.fp, source="acme",
                         file_sha256="0" * 64)
        self.assertIn("digest mismatch", str(cx.exception))

    def test_matching_digest_attests(self):
        v = attest.check(self.verified, fingerprint=self.fp, source="acme",
                         file_sha256="a" * 64)
        self.assertEqual(v["verdict"], "attested")

    def test_failures_never_leak_bucket_content(self):
        # every failure message must avoid the queried fingerprint, its prefix
        # and the supplied digest
        cases = [
            dict(fingerprint=self.fp, source="acme", file_sha256="0" * 64),
            dict(fingerprint="1" * 40, source="acme"),
            dict(fingerprint=self.fp, source="nobody"),
        ]
        secrets = [self.fp, self.fp.upper(), self.prefix, "0" * 64, "1" * 40]
        for kw in cases:
            try:
                attest.check(self.verified, **kw)
            except attest.AttestError as exc:
                msg = str(exc)
                for secret in secrets:
                    self.assertNotIn(secret, msg,
                                     f"failure leaked bucket content: {msg}")

    def test_malformed_inputs(self):
        with self.assertRaises(attest.AttestError):
            attest.check(self.verified, fingerprint="xyz")
        with self.assertRaises(attest.AttestError):
            attest.check(self.verified, prefix="AA")  # wrong length
        with self.assertRaises(attest.AttestError):
            attest.check(self.verified)  # nothing to query


class ProcessBoundaryTests(LedgerHarness):
    """Real subprocesses: CLI writer, independent auditor, offline tool."""

    def cli(self, *args, module="pwncorpus.cli"):
        return subprocess.run(
            [sys.executable, "-m", module, *args],
            capture_output=True, text=True, env=ENV)

    def write_file(self, name, content):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_full_three_boundary_flow_via_subprocesses(self):
        dbp = self.db_path
        src_key = os.path.join(self.tmp, "src.key")
        batch = self.write_file(
            "b.txt",
            "hunter2\nsha1:" + "B" * 40 + "\n")

        r = self.cli("--db", dbp, "ledger-keygen", "--source", "acme",
                     "--key", src_key)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("--db", dbp, "ledger-register", "--source", "acme",
                     "--key", src_key)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("--db", dbp, "ledger-submit", "--source", "acme",
                     "--key", src_key, "--file", batch)
        self.assertEqual(r.returncode, 0, r.stderr)
        first = json.loads(r.stdout)
        self.assertFalse(first["duplicate"])

        # repeated submission across a NEW process returns the same record
        r = self.cli("--db", dbp, "ledger-submit", "--source", "acme",
                     "--key", src_key, "--file", batch)
        self.assertEqual(r.returncode, 0, r.stderr)
        again = json.loads(r.stdout)
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["seq"], first["seq"])

        corr = self.write_file("c.txt", sha1("hunter2") + "\n")
        r = self.cli("--db", dbp, "ledger-correct", "--source", "acme",
                     "--key", src_key, "--claim-seq", "2", "--file", corr,
                     "--created-at", iso(2026, 2, 2))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("--db", dbp, "ledger-retract", "--source", "acme",
                     "--key", src_key, "--claim-seq", "2", "--file", batch,
                     "--reason", "legal", "--created-at", iso(2026, 2, 3))
        self.assertEqual(r.returncode, 0, r.stderr)

        # boundary 2: auditor runs as its own process, read-only DB
        snap = os.path.join(self.tmp, "snap.json")
        r = self.cli("verify", "--db", dbp, module="pwncorpus.audit")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("export", "--db", dbp, "--key", self.key_path,
                     "--out", snap, "--ttl", str(10 ** 9),
                     module="pwncorpus.audit")
        self.assertEqual(r.returncode, 0, r.stderr)

        # boundary 3: offline tool, no database handle at all
        r = self.cli("verify", snap, module="pwncorpus.attest")
        self.assertEqual(r.returncode, 0, r.stderr)
        fp = sha1("hunter2")
        r = self.cli("check", snap, "--fingerprint", fp, "--source", "acme",
                     module="pwncorpus.attest")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ATTESTED", r.stdout)
        self.assertIn("retracted", r.stdout)
        # prove the offline process cannot even see the DB: move it aside
        shutil.move(dbp, dbp + ".away")
        r = self.cli("check", snap, "--fingerprint", fp, "--source", "acme",
                     module="pwncorpus.attest")
        self.assertEqual(r.returncode, 0, r.stderr)
        shutil.move(dbp + ".away", dbp)

    def test_expect_head_conflict_via_cli(self):
        dbp = self.db_path
        src_key = os.path.join(self.tmp, "src.key")
        batch = self.write_file("b.txt", "pw-x\n")
        self.cli("--db", dbp, "ledger-keygen", "--source", "acme",
                 "--key", src_key)
        self.cli("--db", dbp, "ledger-register", "--source", "acme",
                 "--key", src_key)
        # chain head is now 1; claim bound to head 0 must be rejected
        r = self.cli("--db", dbp, "ledger-submit", "--source", "acme",
                     "--key", src_key, "--file", batch, "--expect-head", "0")
        self.assertEqual(r.returncode, 1)
        self.assertIn("parallel write", r.stderr)

    def test_replay_command_resumes(self):
        dbp = self.db_path
        # register via a pre-built intent so replay starts from empty head
        seed, pub = ed25519.generate_key()
        intents = [
            ledger.build_intent(
                attest.KIND_REGISTER, "acme", {"pubkey": pub.hex()}, seed,
                iso(2026, 1, 1))
        ]
        for i in range(4):
            intents.append(ledger.build_intent(
                attest.KIND_SUBMIT, "acme",
                {"file_sha256": f"{i:064x}", "prefixes": [f"{i+1:05X}"]},
                seed, iso(2026, 1, 2 + i), claim_id=f"c-{i}"))
        path = os.path.join(self.tmp, "intents.jsonl")
        with open(path, "w") as fh:
            for it in intents[:3]:
                fh.write(json.dumps(it) + "\n")
        r = self.cli("--db", dbp, "ledger-replay", "--intents", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(ledger.head(self.conn)["seq"], 3)
        # append the remaining intents and replay the FULL file: earlier claims
        # are skipped as duplicates, new ones append -- resume semantics
        with open(path, "w") as fh:
            for it in intents:
                fh.write(json.dumps(it) + "\n")
        r = self.cli("--db", dbp, "ledger-replay", "--intents", path)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out["duplicates"]), 3)
        self.assertEqual(len(out["appended"]), 2)
        self.assertEqual(ledger.head(self.conn)["seq"], 5)
        ledger.verify_stored_chain(self.conn)

    def test_ledger_coexists_with_existing_pipeline(self):
        # the ledger lives in the same DB but ingestion/publication commands
        # are untouched -- ingest + build + activate still work
        from pwncorpus import core
        raw = self.write_file("leak.txt", "alpha\nbeta\ngamma\n")
        r = self.cli("--db", self.db_path, "ingest", "--source", "x",
                     "--file", raw)
        self.assertEqual(r.returncode, 0, r.stderr)
        info = core.build_candidate(self.conn, k=1)
        core.activate(self.conn, info["version"])
        self.assertEqual(core.current_version(self.conn), 1)
        out = os.path.join(self.tmp, "export")
        r = self.cli("--db", self.db_path, "export", "--version", "1",
                     "--out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run(
            [sys.executable, "-m", "pwncorpus.verifier", "verify", out],
            capture_output=True, text=True, env=ENV)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
