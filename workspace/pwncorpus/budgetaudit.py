"""Independent privacy-budget auditor: export a signed, verifiable budget file.

Runs as its OWN process (``python -m pwncorpus.budgetaudit export ...``), opens
the database read-only, cross-checks the live buckets against the append-only
event/grant streams (see ``budget.verify_internal_consistency``) and writes a
single signed JSON document consumable by ``pwncorpus.budgetverify`` on a
machine with no database and no network.

Rules:

  * the export contains only tenant ids, UTC windows, policy revisions,
    deduction counts, failure reasons and grant amounts -- never a queried
    prefix/suffix, a fingerprint or a token;
  * EVERY policy revision is embedded and each window is bound to the revision
    it was created under, so changing the current policy can never rewrite how
    an old window's balance is recomputed;
  * ``--as-of`` truncates the event/grant streams at an ISO 8601 instant
    (point-in-time audit) without touching live buckets;
  * ``--previous`` chains exports: the previous file must verify and describe
    the same budget at no greater event sequence;
  * an existing target file is never silently overwritten with different
    material (old audit material is preserved, not covered by newer state).
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

from . import budget, budgetverify, db, ed25519
from .attest import parse_ts

DEFAULT_TTL_NOT_APPLICABLE = None


class BudgetAuditError(Exception):
    pass


def _connect_read_only(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise BudgetAuditError(f"database not found: {db_path}")
    uri = "file:" + os.path.abspath(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _window_label(ws: int) -> str:
    return datetime.fromtimestamp(ws, timezone.utc).isoformat(timespec="seconds")


def _events_seq_through(conn, as_of_s: str | None) -> int:
    if as_of_s is None:
        r = conn.execute("SELECT COALESCE(MAX(seq),0) AS m FROM budget_events") \
            .fetchone()
        return int(r["m"])
    r = conn.execute(
        "SELECT COALESCE(MAX(seq),0) AS m FROM budget_events"
        " WHERE created_at <= ?", (as_of_s,)).fetchone()
    return int(r["m"])


def build_export(db_path: str, key_path: str, *,
                 as_of: str | None = None,
                 previous_path: str | None = None,
                 now: datetime | None = None) -> dict:
    """Verify the budget store and assemble a genesis-signed export document."""
    as_of_dt = parse_ts(as_of) if as_of is not None else None
    as_of_s = as_of_dt.astimezone(timezone.utc).isoformat(timespec="seconds") \
        if as_of_dt is not None else None

    conn = _connect_read_only(db_path)
    try:
        if not budget.is_initialised(conn):
            raise BudgetAuditError(
                "budget module is not initialised in this database")
        bid = budget.budget_id(conn)
        gpub = budget.genesis_pub(conn)
        # full live cross-check for a current export; point-in-time exports
        # cannot compare against live buckets and are re-derived instead.
        if as_of_dt is None:
            budget.verify_internal_consistency(conn)
        rows = budget.window_rows(conn, as_of=as_of_dt)
        pol = budget.policy_map(conn)
        last_seq = _events_seq_through(conn, as_of_s)
    finally:
        conn.close()

    keydata = budget.read_genesis_key(key_path)
    if keydata.get("budget_id") != bid:
        raise BudgetAuditError(
            "genesis key belongs to a different budget (key/budget mismatch)")
    genesis_pub = keydata["_pub"].hex()
    if genesis_pub != gpub:
        raise BudgetAuditError(
            "genesis public key in the key file does not match the budget")
    seed = keydata["_seed"]

    policies = [{"revision": p["revision"], "daily_quota": p["daily_quota"],
                 "created_at": p["created_at"]}
                for p in sorted(pol.values(), key=lambda p: p["revision"])]

    windows = []
    for w in rows:
        if as_of_dt is not None and w["deductions"] == 0 \
                and not w["failures"] and not w["grants"]:
            continue  # no activity in scope: not part of a point-in-time audit
        windows.append({
            "tenant_id": w["tenant_id"],
            "window": _window_label(w["window_start"]),
            "policy_revision": w["policy_revision"],
            "deductions": w["deductions"],
            "failures": [dict(f) for f in w["failures"]],
            "grants": [{"amount": g["amount"], "created_at": g["created_at"]}
                       for g in w["grants"]],
        })
    windows.sort(key=lambda w: (w["tenant_id"], w["window"]))

    prev_hash = None
    if previous_path is not None:
        prev_hash = _check_previous(previous_path, bid, last_seq, windows)

    now = now or datetime.now(timezone.utc)
    doc = {
        "format": budgetverify.EXPORT_FORMAT,
        "budget_id": bid,
        "genesis_pub": genesis_pub,
        "created_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "as_of": as_of_s,
        "last_event_seq": last_seq,
        "policies": policies,
        "windows": windows,
        "previous_export_sha256": prev_hash,
    }
    doc["export_sha256"] = budgetverify.export_self_hash(doc)
    doc["signature"] = ed25519.sign(
        seed, bytes.fromhex(doc["export_sha256"])).hex()
    # the offline verifier must accept everything we just produced
    budgetverify.verify_export(doc)
    return doc


def _check_previous(path: str, bid: str, new_last_seq: int,
                    new_windows: list[dict]) -> str:
    prev = budgetverify.load_export(path)
    budgetverify.verify_export(prev)  # full structural + signature check
    if prev["budget_id"] != bid:
        raise BudgetAuditError(
            "previous export belongs to a different budget id")
    if prev["last_event_seq"] > new_last_seq:
        raise BudgetAuditError(
            f"previous export covers last_event_seq {prev['last_event_seq']}"
            f" which is NEWER than {new_last_seq}; an older export cannot"
            " overwrite newer audit material")
    return prev["export_sha256"]


def _atomic_write(path: str, raw: bytes) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".budget-export.tmp-{os.getpid()}")
    with open(tmp, "wb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def export_file(db_path: str, key_path: str, out_path: str, *,
                as_of: str | None = None, previous_path: str | None = None,
                now: datetime | None = None, overwrite: bool = False) -> dict:
    doc = build_export(db_path, key_path, as_of=as_of,
                       previous_path=previous_path, now=now)
    raw = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if os.path.exists(out_path) and not overwrite:
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                old = json.load(fh)
        except (OSError, json.JSONDecodeError):
            raise BudgetAuditError(
                f"refusing to overwrite {out_path!r}: it exists but is not a"
                " budget export; move it aside or pass --overwrite")
        if not isinstance(old, dict) \
                or old.get("format") != budgetverify.EXPORT_FORMAT:
            raise BudgetAuditError(
                f"refusing to overwrite {out_path!r}: not a budget export")
        if old.get("budget_id") != doc["budget_id"]:
            raise BudgetAuditError(
                "refusing to overwrite an export for a different budget")
        if budgetverify.canonical(old) != budgetverify.canonical(doc):
            raise BudgetAuditError(
                f"refusing to overwrite {out_path!r} with different audit"
                " material; old audit material cannot be covered by newer"
                " state (choose a new --out path, or pass --overwrite)")
        # identical content: safe no-op rewrite
    _atomic_write(out_path, raw)
    return doc


def verify(db_path: str) -> dict:
    conn = _connect_read_only(db_path)
    try:
        if not budget.is_initialised(conn):
            raise BudgetAuditError("budget module is not initialised")
        bid = budget.budget_id(conn)
        budget.verify_internal_consistency(conn)
        rows = budget.window_rows(conn)
        tenants = conn.execute("SELECT COUNT(*) AS c FROM budget_tenants") \
            .fetchone()["c"]
    finally:
        conn.close()
    deductions = sum(w["deductions"] for w in rows)
    failures = sum(sum(f["count"] for f in w["failures"]) for w in rows)
    return {"budget_id": bid, "windows": len(rows),
            "tenants": tenants, "deductions": deductions,
            "failures": failures}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-budget-audit",
        description="independent privacy-budget auditor (separate process,"
                    " read-only database access)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("export", help="verify the budget and write a signed"
                                      " export file")
    p.add_argument("--db", required=True)
    p.add_argument("--key", required=True, help="budget genesis key file")
    p.add_argument("--out", required=True)
    p.add_argument("--as-of", dest="as_of", default=None,
                   help="ISO 8601 instant; include only events/grants at/before")
    p.add_argument("--previous", default=None,
                   help="previous export file to chain to")
    p.add_argument("--now", default=None, help="override export time (testing)")
    p.add_argument("--overwrite", action="store_true",
                   help="allow replacing an existing file (old material is"
                        " otherwise protected)")

    p = sub.add_parser("verify", help="cross-check live buckets vs event stream")
    p.add_argument("--db", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "verify":
            r = verify(args.db)
            print(f"OK: budget {r['budget_id']} internally consistent:"
                  f" {r['tenants']} tenants, {r['windows']} windows,"
                  f" {r['deductions']} deductions, {r['failures']} failures")
            return 0
        now = parse_ts(args.now) if args.now else None
        doc = export_file(args.db, args.key, args.out, as_of=args.as_of,
                          previous_path=args.previous, now=now,
                          overwrite=args.overwrite)
        total_ded = sum(w["deductions"] for w in doc["windows"])
        print(f"exported budget {doc['budget_id']}: {len(doc['windows'])}"
              f" windows, {total_ded} deductions, last_event_seq"
              f" {doc['last_event_seq']}")
        print(f"  {args.out}  export {doc['export_sha256'][:16]}...")
        return 0
    except (BudgetAuditError, budget.BudgetError,
            budgetverify.BudgetVerifyError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
