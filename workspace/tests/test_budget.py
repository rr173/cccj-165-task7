"""Acceptance tests for the per-caller privacy budget module.

Coverage map (requested scenarios):
  first request / repeated request (idempotency) / parallel races / restart
  recovery / budget exhaustion / freeze permissions / UTC window rollover /
  forged exports / digest mismatch / original ingest+publish regression,
  plus two-token stricter handling, revocation-vs-consume FCFS ordering,
  admin-vs-export count agreement and the three-process boundary.

core.PREFIX_LEN is shrunk to 2 like the other suites.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from pwncorpus import budget, budgetaudit, budgetverify, core, db, ed25519
from pwncorpus import server as srvmod

core.PREFIX_LEN = 2  # test-only, same as the other suites

UTC = timezone.utc


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest().upper()


def pw_with_prefix(prefix: str, n: int, start: int = 0, tag: str = "pw"):
    out, i = [], start
    while len(out) < n:
        cand = f"{tag}-{i}"
        if sha1(cand).startswith(prefix):
            out.append(cand)
        i += 1
    return out


def fingerprints_with_prefix(prefix: str, n: int = 2):
    """Distinct 40-hex fingerprints under a (possibly long) hex prefix.

    Searching for a RAW password whose SHA-1 begins with 5 hex chars would take
    ~16^5 tries, so the suffix is derived by hashing a counter; callers ingest
    these via the pre-hashed ``{"sha1": ...}`` path (never a stored password)."""
    prefix = prefix.upper()
    width = 40 - len(prefix)  # BUD01 (5) -> 35 suffix chars
    out, i = [], 0
    while len(out) < n:
        suffix = format(i, "X").zfill(width)
        if len(suffix) > width:
            raise ValueError("counter overflow for this prefix length")
        fp = prefix + suffix
        assert len(fp) == 40 and re.fullmatch(r"[0-9A-F]{40}", fp), fp
        out.append(fp)
        i += 1
    return out


class BudgetBase(unittest.TestCase):
    quota = 5

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-budget-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        self.key_path = os.path.join(self.tmp, "budget.key")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        self.addCleanup(self._cleanup)
        info = budget.initialise(self.conn, self.key_path,
                                 daily_quota=self.quota)
        self.budget_id = info["budget_id"]
        # a tiny active publication: bucket AA served, bucket BB absent
        core.ingest_batch(self.conn, "s", pw_with_prefix("AA", 3, tag="a"))
        v = core.build_candidate(self.conn, k=1)
        core.activate(self.conn, v["version"])
        self.version = v["version"]

    def _cleanup(self):
        try:
            self.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, True)

    def issue(self, tenant="t1", label="l"):
        return budget.issue_token(self.conn, tenant, label)

    def bucket(self, tenant="t1", ws=None):
        ws = ws or budget.current_window_start()
        return budget.get_bucket(self.conn, tenant, ws)

    def consume(self, token, prefix="AA", **kw):
        return budget.consume(self.conn, [token], prefix, **kw)

    def export_doc(self, as_of=None, previous=None, now=None):
        return budgetaudit.build_export(
            self.db_path, self.key_path, as_of=as_of,
            previous_path=previous, now=now)

    def write_export(self, name="export.json", previous=None, **kw):
        path = os.path.join(self.tmp, name)
        kw.setdefault("previous_path", previous)
        doc = budgetaudit.export_file(self.db_path, self.key_path, path, **kw)
        return path, doc


# --------------------------------------------------------------------------
# First request, basic deduction and storage transaction balances
# --------------------------------------------------------------------------

class FirstRequestTests(BudgetBase):
    def test_first_request_creates_bucket_and_deducts_atomically(self):
        t = self.issue()["token"]
        before = self.bucket  # bucket absent before first request
        self.assertIsNone(before())
        r = self.consume(t)
        self.assertEqual(r["status"], "allowed")
        self.assertEqual(r["http_result"], 200)
        self.assertIsNotNone(r["body"])
        self.assertEqual(r["remaining_before"], self.quota)
        self.assertEqual((r["remaining_after"], r["spent"]),
                         (self.quota - 1, 1))
        b = self.bucket()
        self.assertEqual((b["remaining"], b["spent"], b["frozen"],
                          b["policy_revision"]),
                         (self.quota - 1, 1, 0, 1))
        # six exact fields
        cols = [r["name"] for r in self.conn.execute(
            "PRAGMA table_info(budget_buckets)")]
        self.assertEqual(sorted(cols),
                         sorted(["frozen", "policy_revision", "remaining",
                                 "spent", "tenant_id", "window_start"]))

    def test_missing_bucket_404_still_charges(self):
        t = self.issue()["token"]
        r = self.consume(t, "BB")
        self.assertEqual((r["status"], r["http_result"]), ("allowed", 404))
        self.assertEqual(r["body"], "")
        self.assertEqual(self.bucket()["spent"], 1)  # a read happened

    def test_no_active_publication_costs_nothing(self):
        # a fresh DB with budget initialised but nothing active
        tmp2 = tempfile.mkdtemp(prefix="pwncorpus-budget-empty-")
        self.addCleanup(shutil.rmtree, tmp2, True)
        p2 = os.path.join(tmp2, "c.db")
        k2 = os.path.join(tmp2, "k.key")
        db.init(p2)
        c2 = db.connect(p2)
        budget.initialise(c2, k2, daily_quota=3)
        tok = budget.issue_token(c2, "t", "l")["token"]
        with self.assertRaises(budget.NoActivePublication):
            budget.consume(c2, [tok], "AA")
        self.assertIsNone(budget.get_bucket(c2, "t",
                                            budget.current_window_start()))
        c2.close()


# --------------------------------------------------------------------------
# Repeated requests (idempotency)
# --------------------------------------------------------------------------

class RepeatedRequestTests(BudgetBase):
    def test_repeated_idempotency_key_does_not_double_charge(self):
        t = self.issue()["token"]
        r1 = self.consume(t, idem_key="k-1")
        r2 = self.consume(t, idem_key="k-1")
        r3 = self.consume(t, idem_key="k-1")
        self.assertEqual(r1["status"], "allowed")
        self.assertEqual(r2["status"], "replay")
        self.assertEqual(r3["status"], "replay")
        self.assertEqual(self.bucket()["spent"], 1)
        self.assertEqual(self.bucket()["remaining"], self.quota - 1)
        # replay returns the same version/body content
        self.assertEqual(r2["body"], r1["body"])

    def test_same_key_from_parallel_requests_single_charge(self):
        t = self.issue()["token"]
        results, errors = [], []

        def work():
            c = db.connect(self.db_path)
            try:
                results.append(budget.consume(c, [t], "AA", idem_key="once"))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(lambda _: work(), range(8)))
        self.assertEqual(errors, [])
        self.assertEqual(sum(1 for r in results if r["status"] == "allowed"), 1)
        self.assertEqual(self.bucket()["spent"], 1)

    def test_idem_key_bound_to_tenant(self):
        t1 = self.issue("a")["token"]
        t2 = self.issue("b")["token"]
        self.consume(t1, idem_key="shared")
        with self.assertRaises(budget.BudgetError):
            self.consume(t2, idem_key="shared")

    def test_replay_after_exhaustion_returns_stored_outcome(self):
        t = self.issue()["token"]
        for _ in range(self.quota - 1):
            self.consume(t, idem_key=None)
        r_ok = self.consume(t, idem_key="keep")  # spends the last unit
        self.assertEqual(r_ok["http_result"], 200)
        self.assertEqual(self.consume(t)["http_result"], 429)
        # replaying the key still returns the stored 200 and spends nothing
        r = self.consume(t, idem_key="keep")
        self.assertEqual(r["status"], "replay")
        self.assertEqual(r["http_result"], 200)
        self.assertEqual(self.bucket()["spent"], self.quota)


# --------------------------------------------------------------------------
# Exhaustion
# --------------------------------------------------------------------------

class ExhaustionTests(BudgetBase):
    quota = 2

    def test_exactly_quota_served_then_clear_limit(self):
        t = self.issue()["token"]
        codes = [self.consume(t)["http_result"] for _ in range(4)]
        self.assertEqual(codes, [200, 200, 429, 429])
        b = self.bucket()
        self.assertEqual((b["remaining"], b["spent"]), (0, self.quota))
        rows = self.conn.execute(
            "SELECT result, COUNT(*) c FROM budget_events GROUP BY result"
        ).fetchall()
        counts = {r["result"]: r["c"] for r in rows}
        self.assertEqual(counts, {"served": self.quota,
                                  "budget_exhausted": 2})

    def test_exhaustion_result_does_not_distinguish_bucket_existence(self):
        t = self.issue()["token"]
        for _ in range(self.quota):
            self.consume(t, "AA")
        # an existing bucket and an absent one yield byte-identical denial shape
        a = self.consume(t, "AA")
        b = self.consume(t, "BB")
        self.assertEqual(a["status"], b["status"], "denied")
        self.assertEqual(a["reason"], b["reason"], "budget_exhausted")
        self.assertEqual(a["http_result"], b["http_result"], 429)
        self.assertIsNone(a["body"])
        self.assertIsNone(b["body"])

    def test_negative_remaining_impossible_even_with_raw_sql(self):
        t = self.issue()["token"]
        for _ in range(self.quota):
            self.consume(t)
        b = self.bucket()
        self.assertEqual(b["remaining"], 0)
        # even a hand-written UPDATE can't push the column below zero
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE budget_buckets SET remaining = remaining - 1"
                " WHERE tenant_id=? AND window_start=?",
                ("t1", b["window_start"]))
        self.conn.rollback()

    def test_topup_raises_capacity_same_day(self):
        t = self.issue()["token"]
        for _ in range(self.quota):
            self.consume(t)
        self.assertEqual(self.consume(t)["http_result"], 429)
        budget.topup(self.conn, "t1", 2, note="n")
        r = self.consume(t)
        self.assertEqual(r["http_result"], 200)
        self.assertEqual(r["remaining_before"], 2)


# --------------------------------------------------------------------------
# Parallel contention: no double spend, no bypass
# --------------------------------------------------------------------------

class ParallelTests(BudgetBase):
    quota = 100

    def test_parallel_spends_serialise_to_exact_quota(self):
        t = self.issue()["token"]
        results, errors = [], []

        def work():
            c = db.connect(self.db_path)
            try:
                results.append(budget.consume(c, [t], "AA"))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                c.close()

        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(lambda _: work(), range(self.quota * 3)))
        self.assertEqual(errors, [])
        served = sum(1 for r in results if r["http_result"] == 200)
        denied = sum(1 for r in results if r["http_result"] == 429)
        self.assertEqual(served, self.quota)
        self.assertEqual(served + denied, self.quota * 3)
        b = self.bucket()
        self.assertEqual((b["remaining"], b["spent"]), (0, self.quota))

    def test_distinct_tenants_get_independent_buckets(self):
        toks = {tid: self.issue(tid)["token"]
                for tid in ("a", "b", "c")}
        for tok in toks.values():
            for _ in range(self.quota + 2):
                budget.consume(self.conn, [tok], "AA")
        for tid in toks:
            b = self.bucket(tid)
            self.assertEqual(b["spent"], self.quota)
            self.assertEqual(b["remaining"], 0)

    def test_two_tokens_stricter_tenant_pays(self):
        rich = self.issue("rich", "l")["token"]
        poor = self.issue("poor", "l")["token"]
        budget.topup(self.conn, "rich", 50)
        for _ in range(self.quota):
            budget.consume(self.conn, [poor], "AA")
        r = budget.consume(self.conn, [rich, poor], "AA")
        self.assertEqual(r["tenant_id"], "poor")  # exhausted is stricter
        self.assertEqual((r["status"], r["http_result"]), ("denied", 429))
        # rich was not charged
        self.assertEqual(self.bucket("rich")["spent"], 0)

    def test_two_tokens_lower_remaining_governs(self):
        a = self.issue("g1")["token"]
        b = self.issue("g2")["token"]
        for _ in range(3):
            budget.consume(self.conn, [b], "AA")  # b has less left
        r = budget.consume(self.conn, [a, b], "AA")
        self.assertEqual(r["tenant_id"], "g2")
        self.assertEqual(self.bucket("g1")["spent"], 0)
        self.assertEqual(self.bucket("g2")["spent"], 4)

    def test_two_tokens_one_frozen_frozen_governs(self):
        a = self.issue("fz")["token"]
        b = self.issue("ok")["token"]
        budget.freeze_tenant(self.conn, "fz")
        r = budget.consume(self.conn, [a, b], "AA")
        self.assertEqual((r["tenant_id"], r["http_result"], r["reason"]),
                         ("fz", 403, "frozen"))
        self.assertEqual(self.bucket("ok")["spent"], 0)


# --------------------------------------------------------------------------
# Freeze / unfreeze and token revocation: permissions and FCFS ordering
# --------------------------------------------------------------------------

class FreezeRevokeTests(BudgetBase):
    def test_frozen_tenant_never_gets_body_then_unfreeze_restores(self):
        t = self.issue()["token"]
        budget.freeze_tenant(self.conn, "t1")
        r = self.consume(t, "AA")
        self.assertEqual((r["http_result"], r["reason"]), (403, "frozen"))
        self.assertIsNone(r["body"])
        self.assertEqual(self.bucket()["spent"], 0)  # no charge while frozen
        # even with remaining budget, frozen stays denied
        budget.unfreeze_tenant(self.conn, "t1")
        r2 = self.consume(t, "AA")
        self.assertEqual(r2["http_result"], 200)
        self.assertIsNotNone(r2["body"])

    def test_freeze_idempotent_and_durable_flag_sync(self):
        self.issue()
        r1 = budget.freeze_tenant(self.conn, "t1")
        r2 = budget.freeze_tenant(self.conn, "t1")
        self.assertTrue(r1["changed"])
        self.assertFalse(r2["changed"])
        t = self.conn.execute(
            "SELECT frozen FROM budget_tenants WHERE tenant_id='t1'") \
            .fetchone()["frozen"]
        b = self.bucket()["frozen"]
        self.assertEqual((t, b), (1, 1))

    def test_freeze_crash_leaves_no_half_record(self):
        self.issue("victim")
        with self.assertRaises(RuntimeError):
            budget.freeze_tenant(self.conn, "victim",
                                 probe=lambda: (_ for _ in ()).throw(
                                     RuntimeError("simulated crash")))
        # tenant flag and the absence of both current bucket and admin log agree
        self.assertEqual(self.conn.execute(
            "SELECT frozen FROM budget_tenants WHERE tenant_id='victim'")
            .fetchone()["frozen"], 0)
        self.assertIsNone(self.bucket("victim"))
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM budget_admin_log"
            " WHERE action='freeze' AND tenant_id='victim'").fetchone()["c"]
        self.assertEqual(n, 0)

    def test_freeze_follows_into_next_utc_window(self):
        t = self.issue()["token"]
        budget.freeze_tenant(self.conn, "t1")
        day2 = budget.utcnow() + timedelta(days=1)
        ws2 = budget.window_start_for(day2)
        r = self.consume(t, "AA", now=day2)
        self.assertEqual(r["http_result"], 403)
        self.assertEqual(self.bucket(ws=ws2)["frozen"], 1)
        # past window's bucket stays frozen exactly as it was at the time
        ws1 = budget.current_window_start()
        self.assertEqual(self.bucket(ws=ws1)["frozen"], 1)

    def test_revoked_token_denied_with_reason_and_event(self):
        info = self.issue()
        budget.revoke_token(self.conn, info["token_id"])
        r = self.consume(info["token"], "AA")
        self.assertEqual((r["http_result"], r["reason"]),
                         (403, "token_revoked"))
        self.assertIsNone(r["body"])

    def test_revocation_is_idempotent(self):
        info = self.issue()
        r1 = budget.revoke_token(self.conn, info["token_id"])
        r2 = budget.revoke_token(self.conn, info["token_id"])
        self.assertFalse(r1["already_revoked"])
        self.assertTrue(r2["already_revoked"])

    def test_revoke_and_consume_first_come_first_served(self):
        """Interleave consume and revoke attempts; exactly FCFS order wins.
        With remaining=1: either the consume gets the body and revoke follows
        (next consume revoked), or revoke lands first (consume revoked)."""
        outcomes = {"served_then_revoked": 0, "revoked_first": 0}
        for trial in range(20):
            info = self.issue(f"rt-{trial}")
            barrier = threading.Barrier(2)
            res = {}

            def consumer():
                c = db.connect(self.db_path)
                try:
                    barrier.wait()
                    res["consume"] = budget.consume(
                        c, [info["token"]], "AA")
                finally:
                    c.close()

            def revoker():
                c = db.connect(self.db_path)
                try:
                    barrier.wait()
                    c  # separate connection -> BEGIN IMMEDIATE serialises
                    budget.revoke_token(c, info["token_id"])
                    res["revoked"] = True
                finally:
                    c.close()

            th = [threading.Thread(target=consumer),
                  threading.Thread(target=revoker)]
            for x in th:
                x.start()
            for x in th:
                x.join()
            cr = res["consume"]
            if cr["http_result"] == 200:
                outcomes["served_then_revoked"] += 1
                # the single unit was spent; nothing over budget afterwards
                b = self.bucket(info["tenant_id"])
                self.assertEqual(b["spent"], 1)
            else:
                self.assertEqual(cr["reason"], "token_revoked")
                outcomes["revoked_first"] += 1
                self.assertEqual(self.bucket(info["tenant_id"])["spent"], 0)
        self.assertTrue(all(v >= 0 for v in outcomes.values()))
        self.assertEqual(sum(outcomes.values()), 20)

    def test_unknown_token_is_auth_error_no_event(self):
        with self.assertRaises(budget.BudgetAuth):
            self.consume("pwb_nonsense")
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM budget_events").fetchone()["c"]
        self.assertEqual(n, 0)


# --------------------------------------------------------------------------
# Crash mid-consume: deduction and body share one transaction
# --------------------------------------------------------------------------

class CrashTests(BudgetBase):
    def test_crash_after_deduction_rolls_back_everything(self):
        t = self.issue()["token"]
        # establish the bucket with a prior spend so we can assert exact rollback
        first = self.consume(t, "AA")
        self.assertEqual(first["remaining_after"], self.quota - 1)
        before_remaining = self.quota - 1
        before_spent = 1

        def boom(conn):
            raise RuntimeError("power loss right after deduct+event")

        with self.assertRaises(RuntimeError):
            budget.consume(self.conn, [t], "AA", crash_after_deduct=boom)
        b = self.bucket()
        self.assertEqual((b["remaining"], b["spent"]),
                         (before_remaining, before_spent))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) c FROM budget_events WHERE result IN"
            " ('served','not_found')").fetchone()["c"], 1)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) c FROM budget_idem").fetchone()["c"], 0)
        # afterwards the would-be-spent unit is still available
        r = self.consume(t, "AA")
        self.assertEqual(r["http_result"], 200)
        self.assertEqual(r["remaining_after"], before_remaining - 1)

    def test_first_request_crash_leaves_no_bucket_at_all(self):
        t = self.issue()["token"]
        with self.assertRaises(RuntimeError):
            budget.consume(self.conn, [t], "AA",
                           crash_after_deduct=lambda c: (_ for _ in ()).throw(
                               RuntimeError("x")))
        # the whole transaction (bucket creation included) rolled back
        self.assertIsNone(self.bucket())
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) c FROM budget_events").fetchone()["c"], 0)

    def test_crash_with_idem_records_nothing(self):
        t = self.issue()["token"]
        # a prior normal request establishes the bucket
        self.consume(t, "AA")
        with self.assertRaises(RuntimeError):
            budget.consume(self.conn, [t], "AA", idem_key="x",
                           crash_after_deduct=lambda c: (_ for _ in ()).throw(
                               RuntimeError("x")))
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) c FROM budget_idem").fetchone()["c"], 0)
        self.assertEqual(self.bucket()["spent"], 1)


# --------------------------------------------------------------------------
# UTC window rollover
# --------------------------------------------------------------------------

class WindowTests(BudgetBase):
    def test_window_bounds_use_utc_not_local(self):
        # 2026-01-01 23:59:59 local in +05:00 is already 2026-01-02 in UTC
        local = datetime(2026, 1, 1, 23, 59, 59,
                         tzinfo=timezone(timedelta(hours=5)))
        ws = budget.window_start_for(local)
        self.assertEqual(
            datetime.fromtimestamp(ws, UTC).isoformat(timespec="seconds"),
            "2026-01-01T00:00:00+00:00")  # UTC day is the 1st, not the 2nd
        # and an unsuffixed local-time CLI string is treated as UTC
        self.assertEqual(budget.parse_window("2026-01-02"),
                         int(datetime(2026, 1, 2, tzinfo=UTC).timestamp()))

    def test_rollover_gives_fresh_bucket_under_same_revision(self):
        t = self.issue()["token"]
        for _ in range(2):
            self.consume(t)
        day2 = budget.utcnow() + timedelta(days=1)
        r = self.consume(t, "AA", now=day2)
        self.assertEqual(r["remaining_before"], self.quota)
        ws1, ws2 = budget.current_window_start(), r["window_start"]
        self.assertNotEqual(ws1, ws2)
        self.assertEqual(self.bucket(ws=ws1)["spent"], 2)
        self.assertEqual(self.bucket(ws=ws2)["spent"], 1)

    def test_policy_revision_change_does_not_rewrite_old_window(self):
        t = self.issue()["token"]
        self.consume(t)
        budget.add_policy_revision(self.conn, 50)
        day2 = budget.utcnow() + timedelta(days=1)
        r = self.consume(t, "AA", now=day2)
        self.assertEqual(r["policy_revision"], 2)
        self.assertEqual(r["remaining_before"], 50)
        ws1 = budget.current_window_start()
        self.assertEqual(self.bucket(ws=ws1)["policy_revision"], 1)
        # offline export recomputes each window under ITS OWN revision
        path, _ = self.write_export()
        v = budgetverify.verify_export(budgetverify.load_export(path))
        old = [w for w in v["windows"].values()
               if w["policy_revision"] == 1][0]
        new = [w for w in v["windows"].values()
               if w["policy_revision"] == 2][0]
        self.assertEqual(old["base_quota"], self.quota)
        self.assertEqual(new["base_quota"], 50)

    def test_same_quota_revision_rejected(self):
        with self.assertRaises(budget.BudgetError):
            budget.add_policy_revision(self.conn, self.quota)


# --------------------------------------------------------------------------
# Restart recovery
# --------------------------------------------------------------------------

class RestartTests(BudgetBase):
    def test_balances_recover_after_reopen(self):
        t = self.issue()["token"]
        for _ in range(3):
            self.consume(t)
        budget.topup(self.conn, "t1", 4)
        self.consume(t)
        self.conn.close()
        c2 = db.connect(self.db_path)
        b = budget.get_bucket(c2, "t1", budget.current_window_start())
        self.assertEqual((b["remaining"], b["spent"]),
                         (self.quota - 4 + 4, 4))
        # internal cross-check passes on the reopened store
        budget.verify_internal_consistency(c2)
        c2.close()
        self.conn = db.connect(self.db_path)  # cleanup-safe

    def test_recovery_via_subprocess_then_real_query(self):
        t = self.issue()["token"]
        for _ in range(2):
            self.consume(t)
        expected_remaining = self.quota - 2
        self.conn.close()

        # a fresh PROCESS opens the DB and performs a real consume, not a
        # mere liveness probe
        code, out = self._run_python(f"""
from pwncorpus import budget, db
c = db.connect({self.db_path!r})
b = budget.get_bucket(c, 't1', budget.current_window_start())
assert (b['remaining'], b['spent']) == ({expected_remaining}, 2), b
r = budget.consume(c, [{t!r}], 'AA', prefix_len=2)
assert r['http_result'] == 200, r
assert r['remaining_after'] == {expected_remaining - 1}, r
print('recovered-and-served')
c.close()
""")
        self.assertEqual(code, 0, out)
        self.assertIn("recovered-and-served", out)
        self.conn = db.connect(self.db_path)
        self.assertEqual(self.bucket()["spent"], 3)

    def _run_python(self, script: str):
        env = dict(os.environ, PYTHONPATH="/workspace")
        p = subprocess.run([sys.executable, "-c", script],
                           capture_output=True, text=True, env=env)
        return p.returncode, p.stdout + p.stderr


# --------------------------------------------------------------------------
# Audit export and the isolated verifier
# --------------------------------------------------------------------------

class ExportTests(BudgetBase):
    quota = 4

    def _activity(self):
        t1 = self.issue("t1")["token"]
        t2 = self.issue("t2")["token"]
        self.consume(t1)
        self.consume(t1, "BB")  # 404 still charged
        budget.topup(self.conn, "t1", 2, note="grant")
        self.consume(t1)
        budget.freeze_tenant(self.conn, "t1")
        self.consume(t1)          # frozen failure
        budget.unfreeze_tenant(self.conn, "t1")
        for _ in range(self.quota):
            self.consume(t2)
        self.consume(t2)          # exhausted failure

    def test_export_contains_only_permitted_fields(self):
        self._activity()
        path, doc = self.write_export()
        text = open(path, encoding="utf-8").read()
        # no queried prefix / suffix / raw secret anywhere
        for banned in ("AA", "BB", "pwb_", "alpha", "password"):
            self.assertNotIn(banned, text)
        wkeys = {tuple(sorted(w)) for w in doc["windows"]}
        self.assertEqual(wkeys, {("deductions", "failures", "grants",
                                  "policy_revision", "tenant_id", "window")})
        for f in [x for w in doc["windows"] for x in w["failures"]]:
            self.assertEqual(set(f), {"reason", "count"})
        for g in [x for w in doc["windows"] for x in w["grants"]]:
            self.assertEqual(set(g), {"amount", "created_at"})

    def test_admin_counts_and_export_add_up_item_by_item(self):
        self._activity()
        status = budget.admin_status(self.conn)
        _, doc = self.write_export()
        admin = {(w["tenant_id"], w["window_start"]): w
                 for w in status["windows"]}
        self.assertEqual(len(admin), len(doc["windows"]))
        for w in doc["windows"]:
            label = w["window"]
            aw = admin[(w["tenant_id"], label)]
            self.assertEqual(aw["deductions"], w["deductions"])
            self.assertEqual(
                sorted((f["reason"], f["count"]) for f in aw["failures"]),
                sorted((f["reason"], f["count"]) for f in w["failures"]))
            self.assertEqual(aw["grants_total"],
                             sum(g["amount"] for g in w["grants"]))
            self.assertEqual(aw["remaining"],
                             w and budgetverify.verify_export(
                                 doc)["windows"][
                                     (w["tenant_id"], w["window"])]["remaining"])
        # explicit totals line
        self.assertEqual(sum(w["deductions"] for w in doc["windows"]),
                         sum(a["deductions"] for a in admin.values()))

    def test_file_alone_recomputes_daily_balance(self):
        self._activity()
        path, _ = self.write_export()
        # move the database away: the verifier must not touch it
        away = self.db_path + ".away"
        os.rename(self.db_path, away)
        try:
            doc = budgetverify.load_export(path)
            verified = budgetverify.verify_export(doc)
            today = datetime.now(UTC).date().isoformat()
            bal = budgetverify.daily_balance(verified, "t1", today)
            self.assertEqual(
                (bal["base_quota"], bal["grants_total"], bal["deductions"],
                 bal["remaining"]),
                (4, 2, 3, 3))
            # capacity 6: the recorded deductions are 1..3; the 3rd is within
            v = budgetverify.request_in_budget(verified, "t1", today, 3)
            self.assertEqual(v["verdict"], "within_budget")
            self.assertTrue(v["recorded"])
            # a request position beyond capacity is provably over budget
            v = budgetverify.request_in_budget(verified, "t1", today, 7)
            self.assertEqual(v["verdict"], "over_budget")
            # within capacity but not recorded -> a distinct honest verdict
            v = budgetverify.request_in_budget(verified, "t1", today, 6)
            self.assertEqual(v["verdict"], "within_budget_unrecorded")
        finally:
            os.rename(away, self.db_path)

    def test_forged_export_rejected(self):
        self.issue("real")  # create a tenant; fabricate the window by hand
        path, _ = self.write_export()
        doc = json.load(open(path))
        today = budget.window_iso(budget.current_window_start())
        # fabricate an entire window with a fake tenant and impossibly large
        # deductions: the arithmetic check must catch it
        doc["windows"].append({
            "tenant_id": "ghost", "window": today,
            "policy_revision": 1, "deductions": 99999, "failures": [],
            "grants": []})
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(doc)

    def test_tampered_digest_rejected(self):
        t = self.issue()["token"]
        self.consume(t)
        path, _ = self.write_export()
        doc = json.load(open(path))
        doc["windows"][0]["deductions"] += 1
        with self.assertRaises(budgetverify.BudgetVerifyError) as cm:
            budgetverify.verify_export(doc)
        self.assertIn("export_sha256", str(cm.exception))

    def test_signature_forgery_rejected(self):
        t = self.issue()["token"]
        self.consume(t)
        path, _ = self.write_export()
        doc = json.load(open(path))
        doc["windows"][0]["deductions"] += 1
        doc["export_sha256"] = budgetverify.export_self_hash(doc)
        # re-hashed but NOT signed by the budget genesis key
        with self.assertRaises(budgetverify.BudgetVerifyError) as cm:
            budgetverify.verify_export(doc)
        self.assertIn("signature", str(cm.exception))

    def test_wrong_genesis_pub_pinned_rejected(self):
        path, _ = self.write_export()
        seed, pub = ed25519.generate_key()
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(budgetverify.load_export(path),
                                       trusted_genesis_pub=pub.hex())

    def test_unexpected_field_rejected(self):
        t = self.issue()["token"]
        self.consume(t)
        path, _ = self.write_export()
        doc = json.load(open(path))
        doc["windows"][0]["queried_prefix"] = "AA"
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(doc)

    def test_policy_revision_rewrite_attack_rejected(self):
        t = self.issue()["token"]
        self.consume(t)
        path, _ = self.write_export()
        doc = json.load(open(path))
        # claim the old window ran under a nonexistent revision
        doc["windows"][0]["policy_revision"] = 99
        doc["export_sha256"] = budgetverify.export_self_hash(doc)
        with self.assertRaises(budgetverify.BudgetVerifyError):
            budgetverify.verify_export(doc)

    def test_chained_exports_and_old_material_protected(self):
        t = self.issue()["token"]
        self.consume(t)
        p1, d1 = self.write_export("e1.json")
        self.consume(t)
        p2, d2 = self.write_export("e2.json", previous=p1)
        self.assertEqual(d2["previous_export_sha256"], d1["export_sha256"])
        # cannot write NEWER material over e1.json
        with self.assertRaises(budgetaudit.BudgetAuditError):
            budgetaudit.export_file(self.db_path, self.key_path, p1)
        # an older (point-in-time) export cannot chain on from a NEWER file
        with self.assertRaises(budgetaudit.BudgetAuditError):
            budgetaudit.build_export(
                self.db_path, self.key_path,
                previous_path=p2,
                as_of=(budget.utcnow() - timedelta(days=1)).isoformat())
        # identical re-export to the same path is a guarded no-op
        budgetaudit.export_file(self.db_path, self.key_path, p2,
                                previous_path=p1)

    def test_as_of_export_is_point_in_time(self):
        t = self.issue()["token"]
        day = datetime.now(UTC).date()
        yesterday = datetime(day.year, day.month, day.day, tzinfo=UTC) \
            - timedelta(days=1)
        self.consume(t, now=yesterday)         # yesterday's window: 1 deduction
        self.consume(t)                        # today's window: 1 deduction
        doc = self.export_doc(
            as_of=(yesterday + timedelta(hours=12)).isoformat())
        # only yesterday's window/activity is inside the cutoff
        self.assertEqual(len(doc["windows"]), 1)
        self.assertEqual(doc["windows"][0]["deductions"], 1)

    def test_tampered_storage_blocks_export(self):
        t = self.issue()["token"]
        self.consume(t)
        # corrupt the bucket out-of-band: auditor must refuse, not paper over
        self.conn.execute(
            "UPDATE budget_buckets SET spent = spent + 1 WHERE tenant_id='t1'")
        self.conn.commit()
        with self.assertRaises(budget.BudgetError):
            budgetaudit.build_export(self.db_path, self.key_path)


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

class HttpTests(BudgetBase):
    def setUp(self):
        super().setUp()
        self.admin = core.create_token(self.conn, "adm", ["budget-admin"])
        self.conn.close()
        self.srv = srvmod.make_server(self.db_path, "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        # reopen a connection for direct assertions
        self.conn = db.connect(self.db_path)

    def http(self, method, path, body=None, token=None, raw=False,
             extra_headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                return resp.status, (payload if raw else
                                     _maybe_json(payload)), dict(resp.headers)
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                return e.code, json.loads(payload), dict(e.headers)
            except json.JSONDecodeError:
                return e.code, payload, dict(e.headers)

    def btoken(self, tenant="t1", label="l"):
        st, body, _ = self.http("POST", "/api/budget/tenants/tokens",
                                {"tenant_id": tenant, "label": label},
                                token=self.admin)
        self.assertEqual(st, 201, body)
        return body["token"], body["token_id"]

    def test_status_headers_and_real_body(self):
        tok, _ = self.btoken()
        st, body, hdr = self.http("GET", "/api/range/AA", token=tok, raw=True)
        self.assertEqual(st, 200)
        self.assertEqual(hdr["X-Corpus-Version"], str(self.version))
        self.assertEqual(hdr["X-Budget-Tenant"], "t1")
        self.assertEqual(hdr["X-Budget-Remaining"], str(self.quota - 1))
        self.assertEqual(hdr["X-Budget-Policy-Revision"], "1")
        self.assertTrue(len(body) > 0)

    def test_missing_token_401(self):
        st, body, _ = self.http("GET", "/api/range/AA")
        self.assertEqual(st, 401)

    def test_missing_bucket_404_charges_and_exhaustion_429(self):
        tok, _ = self.btoken("tiny")
        # in-process server shares PREFIX_LEN=2; "CC" is a valid absent prefix
        seen = []
        for _ in range(self.quota + 2):
            st, _, _ = self.http("GET", "/api/range/CC", token=tok)
            seen.append(st)
        self.assertEqual(seen.count(404), self.quota)
        self.assertEqual(seen.count(429), 2)
        # exhausted: the response must not hint whether a bucket exists
        st429, body, hdr = self.http("GET", "/api/range/AA", token=tok)
        self.assertEqual(st429, 429)
        self.assertIn("Retry-After", hdr)
        self.assertEqual(body["error"], "budget_exhausted")

    def test_frozen_through_admin_api_blocks_body(self):
        tok, _ = self.btoken("fz")
        st, _, _ = self.http("POST", "/api/budget/tenants/fz/freeze",
                             token=self.admin)
        self.assertEqual(st, 200)
        sc, body, _ = self.http("GET", "/api/range/AA", token=tok)
        self.assertEqual(sc, 403)
        self.assertEqual(body["error"], "frozen")
        st, _, _ = self.http("POST", "/api/budget/tenants/fz/unfreeze",
                             token=self.admin)
        self.assertEqual(st, 200)
        sc2, _, _ = self.http("GET", "/api/range/AA", token=tok)
        self.assertEqual(sc2, 200)

    def test_revocation_over_http_then_403(self):
        tok, tid = self.btoken("rv")
        st, _, _ = self.http("POST",
                             f"/api/budget/tokens/{tid}/revoke",
                             token=self.admin)
        self.assertEqual(st, 200)
        sc, body, _ = self.http("GET", "/api/range/AA", token=tok)
        self.assertEqual(sc, 403)
        self.assertEqual(body["error"], "token_revoked")

    def test_admin_endpoints_require_scope(self):
        tok, _ = self.btoken()
        st, _, _ = self.http("GET", "/api/budget/status")
        self.assertEqual(st, 401)
        st, _, _ = self.http("GET", "/api/budget/status", token=tok)
        self.assertEqual(st, 403)
        st, body, _ = self.http("GET", "/api/budget/status", token=self.admin)
        self.assertEqual(st, 200)

    def test_topup_over_http_extends_capacity(self):
        tok, _ = self.btoken("tu")
        st, body, _ = self.http("POST",
                                "/api/budget/tenants/tu/topup",
                                {"amount": 3, "note": "x"}, token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(body["remaining"], self.quota + 3)

    def test_response_leaks_no_other_tenant_state(self):
        a, _ = self.btoken("alpha-t")
        b, _ = self.btoken("bravo-t")
        self.http("GET", "/api/range/AA", token=b)
        st, body, hdr = self.http("GET", "/api/range/AA", token=a, raw=True)
        self.assertEqual(st, 200)
        self.assertNotIn("bravo", body.decode())
        self.assertEqual(hdr["X-Budget-Tenant"], "alpha-t")

    def test_two_tokens_one_header_stricter_applied(self):
        a, _ = self.btoken("multi-a")
        b, _ = self.btoken("multi-b")
        for _ in range(self.quota):
            self.http("GET", "/api/range/AA", token=b)
        st, body, hdr = self.http(
            "GET", "/api/range/AA",
            token=None, extra_headers={"Authorization": f"Bearer {a}, {b}"})
        self.assertEqual(st, 429)
        self.assertEqual(hdr["X-Budget-Tenant"], "multi-b")

    def test_idempotency_header_dedups_over_http(self):
        tok, _ = self.btoken("idem")
        h = {"Idempotency-Key": "abc123"}
        st1, _, _ = self.http("GET", "/api/range/AA", token=tok,
                              extra_headers=h)
        st2, _, _ = self.http("GET", "/api/range/AA", token=tok,
                              extra_headers=h)
        self.assertEqual((st1, st2), (200, 200))
        st, body, _ = self.http("GET",
                                "/api/budget/tenants/idem/status",
                                token=self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(body["windows"][0]["spent"], 1)


def _maybe_json(payload):
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload


# --------------------------------------------------------------------------
# Three-process boundary via real subprocesses, incl. offline server restart
# --------------------------------------------------------------------------

class SubprocessBoundaryTests(BudgetBase):
    def setUp(self):
        super().setUp()
        self.conn.close()

    def _cli(self, *args):
        env = dict(os.environ, PYTHONPATH="/workspace")
        p = subprocess.run(
            [sys.executable, "-m", "pwncorpus.cli", "--db", self.db_path,
             *args], capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def _audit(self, *args):
        env = dict(os.environ, PYTHONPATH="/workspace")
        p = subprocess.run(
            [sys.executable, "-m", "pwncorpus.budgetaudit", *args],
            capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def _verify(self, *args):
        env = dict(os.environ, PYTHONPATH="/workspace")
        p = subprocess.run(
            [sys.executable, "-m", "pwncorpus.budgetverify", *args],
            capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def test_cli_then_audit_export_then_offline_verify(self):
        import re as _re
        code, out, err = self._cli("budget-token", "--tenant", "svc",
                                   "--label", "l")
        self.assertEqual(code, 0, err)
        m = _re.search(r"pwb_[A-Za-z0-9_-]+", out)
        self.assertIsNotNone(m, out)
        token = m.group(0)
        code, out, err = self._cli("budget-topup", "--tenant", "svc",
                                   "--amount", "3")
        self.assertEqual(code, 0, err)

        # serve real HTTP, spend budget, kill, restart, spend again
        def serve(port):
            env = dict(os.environ, PYTHONPATH="/workspace")
            return subprocess.Popen(
                [sys.executable, "-m", "pwncorpus.cli", "--db", self.db_path,
                 "serve", "--host", "127.0.0.1", "--port", str(port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

        port = _free_port()
        proc = serve(port)
        self.addCleanup(proc.kill)
        _wait_port(port)
        # The server subprocess runs with the REAL PREFIX_LEN=5 (this test
        # process runs with PREFIX_LEN=2), so ingest+publish through a fresh
        # subprocess too -- using pre-hashed fingerprints under a 5-hex prefix.
        prefix = "ABC01"
        fps = fingerprints_with_prefix(prefix, 2)
        seed = os.path.join(self.tmp, "fps.json")
        with open(seed, "w") as fh:
            json.dump([{"sha1": x} for x in fps], fh)
        env = dict(os.environ, PYTHONPATH="/workspace")
        inj = subprocess.run(
            [sys.executable, "-c",
             "import json,sys\n"
             "from pwncorpus import core, db\n"
             f"c=db.connect({self.db_path!r})\n"
             f"items=json.load(open({seed!r}))\n"
             "core.ingest_batch(c,'five-bucket',items)\n"
             "v=core.build_candidate(c,k=1)\n"
             "core.activate(c,v['version'])\n"
             "print(v['version'])\nc.close()"],
            capture_output=True, text=True, env=env)
        self.assertEqual(inj.returncode, 0, inj.stderr)

        def q():
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/range/{prefix}",
                headers={"Authorization": f"Bearer {token}"})
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, r.read(), dict(r.headers)
            except urllib.error.HTTPError as e:
                return e.code, e.read(), dict(e.headers)

        st1, _, h1 = q()
        self.assertEqual(st1, 200)
        self.assertEqual(h1["X-Budget-Remaining"],
                         str(self.quota + 3 - 1))
        proc.kill()
        proc.wait()
        proc = serve(port)
        self.addCleanup(proc.kill)
        _wait_port(port)
        st2, _, h2 = q()  # after restart the remaining balance is recovered
        self.assertEqual(st2, 200)
        self.assertEqual(h2["X-Budget-Remaining"],
                         str(self.quota + 3 - 2))
        proc.kill()
        proc.wait()

        export = os.path.join(self.tmp, "sub-export.json")
        code, out, err = self._audit(
            "export", "--db", self.db_path, "--key", self.key_path,
            "--out", export)
        self.assertEqual(code, 0, err)
        # verifier runs with the DB moved away
        os.rename(self.db_path, self.db_path + ".x")
        try:
            code, out, err = self._verify("verify", export)
            self.assertEqual(code, 0, err)
            today = datetime.now(UTC).date().isoformat()
            code, out, err = self._verify(
                "daily", export, "--tenant", "svc", "--date", today)
            self.assertEqual(code, 0, err)
            bal = json.loads(out)
            self.assertEqual(bal["deductions"], 2)
            self.assertEqual(bal["grants_total"], 3)
            self.assertEqual(bal["remaining"], self.quota + 1)
        finally:
            os.rename(self.db_path + ".x", self.db_path)

    def test_audit_verify_command_catches_tampering(self):
        c = db.connect(self.db_path)
        t = budget.issue_token(c, "z", "l")["token"]
        budget.consume(c, [t], "AA")
        c.close()
        code, out, err = self._audit("verify", "--db", self.db_path)
        self.assertEqual(code, 0, err)
        c = db.connect(self.db_path)
        c.execute("UPDATE budget_buckets SET remaining = remaining - 1")
        c.commit()
        c.close()
        code, out, err = self._audit("verify", "--db", self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("disagrees", err)


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 10.0) -> None:
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("server never came up")


# --------------------------------------------------------------------------
# Regression: the original ingestion/publication flow is unchanged when the
# budget module is present, and stays anonymous when not initialised.
# --------------------------------------------------------------------------

class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-budget-reg-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_range_remains_anonymous_without_budget_init(self):
        core.ingest_batch(self.conn, "s",
                          pw_with_prefix("77", 3, tag="reg"))
        info = core.build_candidate(self.conn, k=2)
        core.activate(self.conn, info["version"])
        srv = srvmod.make_server(self.db_path, "127.0.0.1", 0)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/api/range/77") as r:
                self.assertEqual(r.status, 200)
                self.assertNotIn("X-Budget-Remaining", dict(r.headers))
                body = r.read().decode()
            self.assertEqual(len(body.strip().splitlines()), 3)
        finally:
            self.conn.close()

    def test_full_ingest_build_activate_export_pipeline(self):
        from pwncorpus import verifier
        pws = pw_with_prefix("44", 3, tag="pipeline")
        core.ingest_batch(self.conn, "s", pws)
        v = core.build_candidate(self.conn, k=2)["version"]
        core.activate(self.conn, v)
        out = os.path.join(self.tmp, "exp")
        core.export_version(self.conn, v, out)
        self.assertEqual(verifier.verify_export(out), [])
        # budget tables can be added afterwards without disturbing publication
        kp = os.path.join(self.tmp, "b.key")
        budget.initialise(self.conn, kp, daily_quota=2)
        t = budget.issue_token(self.conn, "post", "l")["token"]
        r = budget.consume(self.conn, [t], "44")
        self.assertEqual(r["http_result"], 200)
        self.assertEqual(verifier.verify_export(out), [])


if __name__ == "__main__":
    unittest.main()
