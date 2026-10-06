"""Independent auditor: export a signed, point-in-time accountability snapshot
from the append-only ledger.

This runs as its OWN process (``python -m pwncorpus.audit export ...``), opens
the database read-only, verifies the ENTIRE chain (stored hashes, prev_hash
links, source signatures and semantics) and hands the entries to
``attest.build_snapshot``, which genesis-signs a self-describing snapshot file.

The offline tool (``pwncorpus.attest``) then answers provenance questions from
that file alone -- it never opens the database.

Export rules:

  * ``--as-of`` truncates the chain at an ISO 8601 instant (chain order is the
    tie-breaker for events sharing a timestamp);
  * every snapshot carries ``not_after`` (default 24h); an expired snapshot is
    a hard FAIL on the offline side;
  * an export never overwrites a NEWER on-disk snapshot with an OLDER one
    (compare the signed head_seq / snapshot_sha256), so a replayed or delayed
    audit cannot roll responsibility state backwards.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

from . import attest, db, ed25519, ledger

DEFAULT_TTL_SECONDS = 24 * 3600


class AuditError(Exception):
    pass


def _connect_read_only(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        raise AuditError(f"database not found: {db_path}")
    uri = "file:" + os.path.abspath(db_path) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _entries_through(entries: list[dict], as_of: datetime) -> list[dict]:
    cutoff = as_of.astimezone(timezone.utc)
    out = []
    for e in entries:
        ts = attest.parse_ts(e["created_at"])
        if ts <= cutoff:
            out.append(e)
    return out


def _head_of(entries: list[dict], ledger_id: str):
    if not entries:
        return 0, "GENESIS:" + ledger_id
    last = entries[-1]
    return last["seq"], attest.entry_hash_hex(last)


def export_snapshot(db_path: str, key_path: str, out_path: str, *,
                    as_of: str | None = None,
                    ttl_seconds: int = DEFAULT_TTL_SECONDS,
                    now: datetime | None = None) -> dict:
    """Verify the ledger and write a genesis-signed snapshot atomically."""
    if not isinstance(ttl_seconds, int) or ttl_seconds < 0:
        raise AuditError("ttl must be a non-negative integer")
    if isinstance(now, str):
        now = attest.parse_ts(now)
    conn = _connect_read_only(db_path)
    try:
        if not ledger.is_initialised(conn):
            raise AuditError("ledger is not initialised in this database")
        info = ledger.ledger_info(conn)
        ledger_id = info["ledger_id"]
        prefix_len = info["prefix_len"]

        # full verification before anything is exported
        ledger.verify_stored_chain(conn)
        entries = ledger.all_entries(conn)
    finally:
        conn.close()

    keydata = ledger.read_key_file(key_path)
    if keydata.get("kind") != "ledger-genesis":
        raise AuditError("the supplied key is not a ledger genesis key")
    if keydata.get("ledger_id") != ledger_id:
        raise AuditError(
            "genesis key belongs to a different ledger (key/ledger mismatch)")
    genesis_pub = keydata["_pub"].hex()
    if genesis_pub != info["genesis_pub"]:
        raise AuditError("genesis public key in the key file does not match"
                         " the ledger (source/key permission)")
    seed = keydata["_seed"]

    if as_of is not None:
        cutoff = attest.parse_ts(as_of)
        chosen = _entries_through(entries, cutoff)
        head_seq, head_hash = _head_of(chosen, ledger_id)
    else:
        chosen = entries
        head_seq, head_hash = info["head_seq"], info["head_hash"]

    # build_snapshot re-verifies the (possibly truncated) chain internally
    snap = attest.build_snapshot(
        ledger_id, seed, genesis_pub, head_seq, head_hash, chosen,
        prefix_len, ttl_seconds, now=now)

    _guard_against_rewrite(out_path, snap)
    raw = (json.dumps(snap, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(out_path, raw)
    return snap


def _guard_against_rewrite(out_path: str, new_snap: dict) -> None:
    """An older snapshot must never overwrite a newer responsibility state.

    Refuse when an existing file is a VALID snapshot for the same ledger whose
    signed head_seq is strictly newer (or equal-head but a different, newer
    export). Identical head_seq re-exports are allowed (refresh of an expiring
    snapshot); everything newer is blocked.
    """
    if not os.path.exists(out_path):
        return
    try:
        with open(out_path, "r", encoding="utf-8") as fh:
            old = json.load(fh)
    except (OSError, json.JSONDecodeError):
        raise AuditError(
            f"refusing to overwrite {out_path!r}: it exists but is not a"
            f" snapshot; move it aside first")
    if not isinstance(old, dict) or old.get("format") != attest.SNAPSHOT_FORMAT:
        raise AuditError(
            f"refusing to overwrite {out_path!r}: not a snapshot file")
    if old.get("ledger_id") != new_snap["ledger_id"]:
        raise AuditError(
            "refusing to overwrite a snapshot belonging to a different ledger")
    # only compare when the on-disk snapshot is itself trustworthy
    try:
        attest.verify_snapshot(old)  # expiry tolerated? no -- still compares
    except attest.AttestError as exc:
        # an EXPIRED but otherwise intact newer snapshot still must not be
        # downgraded; verify content+signature ignoring the clock.
        _verify_ignoring_expiry(old)
    old_seq = old.get("head_seq")
    new_seq = new_snap["head_seq"]
    if isinstance(old_seq, int) and old_seq > new_seq:
        raise AuditError(
            f"refusing to export: the existing snapshot is at head_seq"
            f" {old_seq}, which is NEWER than head_seq {new_seq}; an older"
            f" snapshot cannot overwrite newer responsibility state")


def _verify_ignoring_expiry(snap: dict) -> None:
    """Structural/hash/signature/chain verification without applying TTL."""
    attest._require_snapshot_fields(snap)
    if attest.snapshot_self_hash(snap) != snap["snapshot_sha256"]:
        raise AuditError("existing snapshot fails its self hash; refusing to"
                         " overwrite an untrustworthy file")
    try:
        ed25519.verify(bytes.fromhex(snap["genesis_pub"]),
                       bytes.fromhex(snap["snapshot_sha256"]),
                       bytes.fromhex(snap["signature"]))
    except ed25519.BadSignature as exc:
        raise AuditError(
            "existing snapshot has an invalid genesis signature; refusing to"
            " overwrite it") from exc
    by_prefix, head_hash, head_seq = attest.verify_chain(
        snap["entries"], snap["ledger_id"],
        expected_head_seq=snap["head_seq"],
        expected_head_hash=snap["head_hash"])
    if attest.canonical(attest.materialize_records(by_prefix)) \
            != attest.canonical(snap["records"]):
        raise AuditError("existing snapshot records do not replay; refusing to"
                         " overwrite it")


def _atomic_write(path: str, raw: bytes) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".snapshot.tmp-{os.getpid()}")
    with open(tmp, "wb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def verify(db_path: str) -> dict:
    conn = _connect_read_only(db_path)
    try:
        info = ledger.ledger_info(conn)
        by_prefix, head_hash, head_seq = ledger.verify_stored_chain(conn)
        return {"ledger_id": info["ledger_id"], "head_seq": head_seq,
                "head_hash": head_hash, "prefixes": len(by_prefix),
                "sources": len({s for b in by_prefix.values()
                                for s in b["sources"]})}
    finally:
        conn.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-audit",
        description="independent provenance-ledger auditor (separate process,"
                    " read-only database access)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("export", help="verify the chain and export a signed"
                                      " accountability snapshot")
    p.add_argument("--db", required=True)
    p.add_argument("--key", required=True, help="ledger genesis key file")
    p.add_argument("--out", required=True, help="output snapshot JSON path")
    p.add_argument("--as-of", dest="as_of", default=None,
                   help="ISO 8601 instant; include only chain items at/before it")
    p.add_argument("--ttl", dest="ttl", type=int,
                   default=DEFAULT_TTL_SECONDS,
                   help="snapshot validity in seconds (default 86400 = 24h)")
    p.add_argument("--now", default=None, help="override export time (testing)")

    p = sub.add_parser("verify", help="verify the full ledger chain only")
    p.add_argument("--db", required=True)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "verify":
            r = verify(args.db)
            print(f"OK: ledger {r['ledger_id']} chain verified to head_seq"
                  f" {r['head_seq']} ({r['prefixes']} bucket prefixes,"
                  f" {r['sources']} sources)")
            return 0
        now = attest.parse_ts(args.now) if args.now else None
        snap = export_snapshot(
            args.db, args.key, args.out, as_of=args.as_of,
            ttl_seconds=args.ttl, now=now)
        print(f"exported snapshot: ledger {snap['ledger_id']}, head_seq"
              f" {snap['head_seq']}, head {snap['head_hash'][:16]}...,"
              f" valid until {snap['not_after']}")
        print(f"  {args.out}  snapshot {snap['snapshot_sha256'][:16]}...")
        return 0
    except (AuditError, ledger.LedgerError, attest.AttestError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
