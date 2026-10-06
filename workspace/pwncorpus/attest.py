"""Offline accountability checks against a signed provenance snapshot.

This module NEVER imports sqlite3 and never opens the corpus database. It runs
on a fully disconnected machine with only:

  * a snapshot file (produced by ``pwncorpus.audit`` from the append-only
    ledger), and
  * the input a reviewer already holds (a fingerprint, a prefix or a file
    digest).

A snapshot binds:

    format / ledger_id / genesis_pub / head_seq / head_hash
    created_at / not_after / ttl_seconds / prefix_len
    entries   : every ledger chain item (source-signed payloads + hashes)
    records   : the responsibility state derived at the snapshot point
    snapshot_sha256
    signature : the ledger genesis key's Ed25519 signature over snapshot_sha256

Failure results are deliberately specific (expired / malformed / signature /
tampered chain / missing chain item / digest mismatch / source-permission) but
never echo the queried prefix, fingerprint or file digest: a failed check must
not disclose bucket content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from . import ed25519

SNAPSHOT_FORMAT = "pwncorpus-attest/1"

# Claim kinds recorded on the chain.
KIND_REGISTER = "register"
KIND_SUBMIT = "submit"
KIND_RETRACT = "retract"
KIND_CORRECT = "correct"
CLAIM_KINDS = (KIND_REGISTER, KIND_SUBMIT, KIND_RETRACT, KIND_CORRECT)

# Fields of each chain item covered by its entry hash.
ENTRY_FIELDS = ("seq", "kind", "source", "payload", "created_at",
                "claim_id", "pubkey", "signature", "prev_hash")

# Snapshot fields covered by snapshot_sha256 (everything except the hash and
# the outer signature).
SNAPSHOT_FIELDS = ("format", "ledger_id", "genesis_pub", "head_seq",
                   "head_hash", "created_at", "not_after", "ttl_seconds",
                   "prefix_len", "entries", "records")


class AttestError(Exception):
    """A snapshot is structurally invalid, untrusted, expired or tampered."""


# --------------------------------------------------------------------------
# Canonical serialisation (the ledger writes the same bytes it signs)
# --------------------------------------------------------------------------

def canonical(obj) -> str:
    """Deterministic JSON used for every signed/hashed byte string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


_canon = canonical


def hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def entry_hash_hex(entry: dict) -> str:
    """Hash of one chain item over its canonical ENTRY_FIELDS content."""
    payload = {f: entry[f] for f in ENTRY_FIELDS}
    return hashlib.sha256(_canon(payload).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------

def parse_ts(value: str) -> datetime:
    if not isinstance(value, str):
        raise AttestError("timestamp is not a string")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AttestError(f"unparseable timestamp: {type(value).__name__}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utcnow_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# Chain replay (used by the ledger writer, the auditor and this module -- no
# sqlite3 anywhere in this module)
# --------------------------------------------------------------------------

class _Replay:
    def __init__(self, ledger_id: str):
        self.ledger_id = ledger_id
        self.pubkeys: dict[str, str] = {}
        # submit claims remembered so retract/correct can bind to one.
        self.submits: dict[str, dict] = {}
        # responsibility accumulation, keyed by bucket prefix
        self.by_prefix: dict[str, dict] = {}


def _check_signature(pub_hex: str, entry: dict) -> None:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(entry["signature"])
    except (ValueError, TypeError) as exc:
        raise AttestError("invalid hex in signature material") from exc
    msg = _sign_message(entry["kind"], entry["source"], entry["payload"],
                        entry["created_at"], entry["claim_id"])
    try:
        ed25519.verify(pub, msg, sig)
    except ed25519.BadSignature as exc:
        raise AttestError(
            f"chain item {entry.get('seq')}: source signature is invalid"
            f" ({entry.get('kind')})") from exc


def _sign_message(kind: str, source: str, payload: dict,
                  created_at: str, claim_id: str) -> bytes:
    body = _canon({"kind": kind, "source": source, "payload": payload,
                   "created_at": created_at, "claim_id": claim_id})
    return body.encode("utf-8")


def sign_claim(seed: bytes, kind: str, source: str, payload: dict,
               created_at: str, claim_id: str) -> str:
    """Sign one claim exactly as the verifier checks it. Returns hex sig."""
    msg = _sign_message(kind, source, payload, created_at, claim_id)
    return ed25519.sign(seed, msg).hex()


def _valid_hex(value, length: int) -> bool:
    return isinstance(value, str) and len(value) == length \
        and all(c in "0123456789abcdef" for c in value.lower()) \
        and value == value.lower()


def _require_fields(payload, fields, entry):
    for f in fields:
        if f not in payload:
            raise AttestError(
                f"chain item {entry.get('seq')}: {entry.get('kind')} payload"
                f" missing field {f!r}")


def _replay_apply(state: _Replay, entry: dict) -> None:
    """Validate one entry's signature + semantics against accumulated state,
    then fold it into the responsibility map."""
    seq = entry.get("seq")
    kind = entry.get("kind")
    source = entry.get("source")
    payload = entry.get("payload")
    if not isinstance(source, str) or not source:
        raise AttestError(f"chain item {seq}: missing source")
    if not isinstance(payload, dict):
        raise AttestError(f"chain item {seq}: payload is not an object")
    if kind not in CLAIM_KINDS:
        raise AttestError(f"chain item {seq}: unknown kind {kind!r}")

    if kind == KIND_REGISTER:
        _require_fields(payload, ("pubkey",), entry)
        pub = payload["pubkey"]
        if not _valid_hex(pub, 64):
            raise AttestError(f"chain item {seq}: invalid register pubkey")
        # the entry's own signature must verify against the pubkey it binds
        _check_signature(pub, entry)
        if source in state.pubkeys:
            raise AttestError(
                f"chain item {seq}: source {source!r} is already registered")
        state.pubkeys[source] = pub
        return

    if source not in state.pubkeys:
        raise AttestError(
            f"chain item {seq}: source {source!r} is not registered (permission)")
    _check_signature(state.pubkeys[source], entry)

    if kind == KIND_SUBMIT:
        _require_fields(payload, ("file_sha256", "prefixes"), entry)
        if not _valid_hex(payload["file_sha256"], 64):
            raise AttestError(f"chain item {seq}: invalid file digest")
        prefixes = payload["prefixes"]
        if not isinstance(prefixes, list) or not prefixes:
            raise AttestError(f"chain item {seq}: prefixes must be a non-empty list")
        pfx = set()
        for p in prefixes:
            if not isinstance(p, str):
                raise AttestError(f"chain item {seq}: bad prefix entry")
            pfx.add(p)
        state.submits[seq] = entry
        rec = {
            "seq": seq, "source": source,
            "file_sha256": payload["file_sha256"],
            "submitted_at": entry["created_at"],
            "prefixes": sorted(pfx),
            "reason": payload.get("reason", ""),
            "retracted_at": None, "retract_reason": None,
            "corrections": [],
        }
        for p in rec["prefixes"]:
            bucket = state.by_prefix.setdefault(
                p, {"sources": {}, "first_submitted_seq": seq,
                    "first_submitted_at": entry["created_at"]})
            bucket["sources"][source] = rec
            if seq < bucket["first_submitted_seq"]:
                bucket["first_submitted_seq"] = seq
                bucket["first_submitted_at"] = entry["created_at"]

    elif kind == KIND_RETRACT:
        _require_fields(payload, ("claim_seq", "reason"), entry)
        if not isinstance(payload["reason"], str) or not payload["reason"]:
            raise AttestError(f"chain item {seq}: retraction needs a reason")
        target = state.submits.get(payload.get("claim_seq"))
        if target is None:
            raise AttestError(
                f"chain item {seq}: retraction refers to an unknown/non-submit"
                f" claim_seq (missing chain item)")
        if target["source"] != source:
            raise AttestError(
                f"chain item {seq}: source may only retract its own submission"
                f" (permission)")
        if target["payload"]["file_sha256"] != payload.get("file_sha256"):
            raise AttestError(
                f"chain item {seq}: retraction file digest does not match the"
                f" submission it targets")
        # a second retraction of the same submission is a clear conflict
        tfile = target["payload"]["file_sha256"]
        for p in target["payload"]["prefixes"]:
            rec = state.by_prefix[p]["sources"].get(source)
            if rec is not None and rec["file_sha256"] == tfile \
                    and rec["retracted_at"] is not None:
                raise AttestError(
                    f"chain item {seq}: submission {payload['claim_seq']} is"
                    f" already retracted")
        for p in target["payload"]["prefixes"]:
            rec = state.by_prefix[p]["sources"][source]
            if rec["retracted_at"] is None:
                rec["retracted_at"] = entry["created_at"]
                rec["retract_reason"] = payload["reason"]

    else:  # KIND_CORRECT
        _require_fields(payload, ("claim_seq", "fingerprints"), entry)
        target = state.submits.get(payload.get("claim_seq"))
        if target is None:
            raise AttestError(
                f"chain item {seq}: correction refers to an unknown/non-submit"
                f" claim_seq (missing chain item)")
        if target["source"] != source:
            raise AttestError(
                f"chain item {seq}: source may only correct its own submission"
                f" (permission)")
        fps = payload["fingerprints"]
        if not isinstance(fps, list) or not fps:
            raise AttestError(f"chain item {seq}: fingerprints must be non-empty list")
        for fp in fps:
            if not _valid_hex(fp, 40):
                raise AttestError(f"chain item {seq}: invalid fingerprint")
        # record each corrected fingerprint once per submission, at the time of
        # the FIRST correction entry that contained it
        new_fps = set(fps)
        for p in target["payload"]["prefixes"]:
            rec = state.by_prefix[p]["sources"][source]
            existing = {c["fingerprint"] for c in rec["corrections"]}
            for fp in sorted(new_fps - existing):
                rec["corrections"].append({
                    "fingerprint": fp, "at": entry["created_at"], "seq": seq})
            rec["corrections"].sort(key=lambda c: c["seq"])


def verify_chain(entries, ledger_id: str,
                 expected_head_seq: int | None = None,
                 expected_head_hash: str | None = None) -> tuple[dict, str, int]:
    """Full structural + hash-link + signature + semantic verification.

    Returns (responsibility_map, head_hash, head_seq). Used by the ledger
    writer, the auditor and snapshot verification.
    """
    state = _Replay(ledger_id)
    prev = "GENESIS:" + ledger_id
    if not isinstance(entries, list):
        raise AttestError("entries is not a list")
    expected_seq = 1
    head_hash = prev
    seq = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise AttestError("chain item is not an object")
        missing = [f for f in ENTRY_FIELDS if f not in entry]
        if missing:
            raise AttestError(f"chain item {expected_seq} missing fields: "
                              + ", ".join(missing))
        seq = entry["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise AttestError(f"chain item {expected_seq}: seq must be an int")
        if seq != expected_seq:
            raise AttestError(
                f"chain item {seq}: expected seq {expected_seq} (a chain item"
                f" is missing or the order was changed)")
        if entry["prev_hash"] != prev:
            raise AttestError(
                f"chain item {seq}: prev_hash linkage broken (chain item"
                f" missing or reordered)")
        _replay_apply(state, entry)
        h = entry_hash_hex(entry)
        prev, head_hash, expected_seq = h, h, expected_seq + 1
    if expected_head_seq is not None and seq != expected_head_seq:
        raise AttestError(
            f"snapshot head_seq {expected_head_seq} does not match the replayed"
            f" chain length {seq} (chain truncated or extended)")
    if expected_head_hash is not None and head_hash != expected_head_hash:
        raise AttestError(
            "snapshot head_hash does not match the replayed chain tip")
    return state.by_prefix, head_hash, seq


def materialize_records(by_prefix: dict[str, dict]) -> dict:
    """Turn the replay map into the canonical, hash-stable 'records' object.

    Structure per prefix:
      sources.<source>.{submitted_seq,submitted_at,file_sha256,retracted_at,
                        retract_reason,correction_before_retraction,
                        corrections:[{seq,at,fingerprint}...]}
    """
    out: dict[str, dict] = {}
    for prefix in sorted(by_prefix):
        bucket = by_prefix[prefix]
        sources_out: dict[str, dict] = {}
        for source in sorted(bucket["sources"]):
            rec = bucket["sources"][source]
            corr = [{"seq": c["seq"], "at": c["at"],
                     "fingerprint": c["fingerprint"]}
                    for c in rec["corrections"]]
            corr.sort(key=lambda c: c["seq"])
            first_corr_at = corr[0]["at"] if corr else None
            cbr = bool(rec["retracted_at"] and first_corr_at
                       and first_corr_at < rec["retracted_at"])
            sources_out[source] = {
                "submitted_seq": rec["seq"],
                "submitted_at": rec["submitted_at"],
                "file_sha256": rec["file_sha256"],
                "retracted_at": rec["retracted_at"],
                "retract_reason": rec["retract_reason"],
                "corrections": corr,
                "correction_before_retraction": cbr,
            }
        out[prefix] = {"sources": sources_out}
    return out


# --------------------------------------------------------------------------
# Snapshot assembly / verification (the latter needs NO database)
# --------------------------------------------------------------------------

def snapshot_self_hash(snap: dict) -> str:
    return hashlib.sha256(
        _canon({f: snap[f] for f in SNAPSHOT_FIELDS}).encode("utf-8")
    ).hexdigest()


def build_snapshot(ledger_id: str, genesis_seed: bytes, genesis_pub: str,
                   head_seq: int, head_hash: str, entries: list[dict],
                   prefix_len: int, ttl_seconds: int,
                   now: datetime | None = None) -> dict:
    """Assemble and genesis-sign a snapshot. Used by the auditor only."""
    now = now or datetime.now(timezone.utc)
    created = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    not_after_ts = (now.timestamp() + ttl_seconds)
    not_after = datetime.fromtimestamp(not_after_ts, timezone.utc) \
        .isoformat(timespec="seconds")
    by_prefix, replay_head, replay_seq = verify_chain(entries, ledger_id)
    if replay_seq != head_seq or replay_head != head_hash:
        raise AttestError("ledger head does not match the entries to export")
    records = materialize_records(by_prefix)
    snap = {
        "format": SNAPSHOT_FORMAT,
        "ledger_id": ledger_id,
        "genesis_pub": genesis_pub,
        "head_seq": head_seq,
        "head_hash": head_hash,
        "created_at": created,
        "not_after": not_after,
        "ttl_seconds": ttl_seconds,
        "prefix_len": prefix_len,
        "entries": entries,
        "records": records,
    }
    snap["snapshot_sha256"] = snapshot_self_hash(snap)
    snap["signature"] = ed25519.sign(
        genesis_seed, bytes.fromhex(snap["snapshot_sha256"])).hex()
    return snap


def _require_snapshot_fields(snap) -> None:
    if not isinstance(snap, dict):
        raise AttestError("snapshot is not a JSON object")
    missing = [f for f in SNAPSHOT_FIELDS + ("snapshot_sha256", "signature")
               if f not in snap]
    if missing:
        raise AttestError("snapshot missing fields: " + ", ".join(missing))


def verify_snapshot(snap: dict, now: datetime | None = None,
                    trusted_genesis_pub: str | None = None) -> dict:
    """Full offline verification of a snapshot. Returns its verified records.

    Checks: structure, self hash, genesis signature, expiry, prefix length,
    and a full chain replay whose derived records must byte-match the embedded
    responsibility state. Nothing here touches a database.
    """
    _require_snapshot_fields(snap)
    if snap["format"] != SNAPSHOT_FORMAT:
        raise AttestError(f"unsupported snapshot format: {snap['format']!r}")
    if not _valid_hex(snap["ledger_id"], 16):
        raise AttestError("invalid ledger_id")
    if not _valid_hex(snap["genesis_pub"], 64):
        raise AttestError("invalid genesis_pub")
    if trusted_genesis_pub is not None \
            and snap["genesis_pub"] != trusted_genesis_pub:
        raise AttestError(
            "snapshot genesis key differs from the pinned ledger key"
            " (source/key permission)")
    if not isinstance(snap["prefix_len"], int) or isinstance(snap["prefix_len"], bool) \
            or not (1 <= snap["prefix_len"] < 40):
        raise AttestError("invalid prefix_len")
    if not isinstance(snap["head_seq"], int) or isinstance(snap["head_seq"], bool) \
            or snap["head_seq"] < 0:
        raise AttestError("invalid head_seq")
    if not isinstance(snap["ttl_seconds"], int) or snap["ttl_seconds"] < 0:
        raise AttestError("invalid ttl_seconds")

    if snapshot_self_hash(snap) != snap["snapshot_sha256"]:
        raise AttestError(
            "snapshot_sha256 does not match recomputed hash (snapshot altered)")
    try:
        ed25519.verify(bytes.fromhex(snap["genesis_pub"]),
                       bytes.fromhex(snap["snapshot_sha256"]),
                       bytes.fromhex(snap["signature"]))
    except ed25519.BadSignature as exc:
        raise AttestError("genesis signature over the snapshot is invalid") from exc

    not_after = parse_ts(snap["not_after"])
    created = parse_ts(snap["created_at"])
    if created > not_after:
        raise AttestError("snapshot created_at is after its not_after")
    if isinstance(now, str):
        now = parse_ts(now)
    now = now or datetime.now(timezone.utc)
    if now.astimezone(timezone.utc) > not_after:
        raise AttestError(
            "snapshot is EXPIRED (not_after " + snap["not_after"]
            + "); obtain a fresh snapshot")

    by_prefix, head_hash, head_seq = verify_chain(
        snap["entries"], snap["ledger_id"],
        expected_head_seq=snap["head_seq"],
        expected_head_hash=snap["head_hash"])
    derived = materialize_records(by_prefix)
    if _canon(derived) != _canon(snap["records"]):
        raise AttestError(
            "embedded records do not match a replay of the signed chain"
            " (responsibility state tampered)")
    return {"records": derived, "head_seq": head_seq,
            "head_hash": head_hash, "prefix_len": snap["prefix_len"],
            "ledger_id": snap["ledger_id"], "not_after": snap["not_after"],
            "registered_sources":
                sorted({e["source"] for e in snap["entries"]
                        if e["kind"] == KIND_REGISTER})}


def load_snapshot(path: str) -> dict:
    if not os.path.isfile(path):
        raise AttestError(f"snapshot file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestError(f"snapshot unreadable or not JSON: {exc}") from exc


# --------------------------------------------------------------------------
# Offline verdict: did a specified source attest a bucket record, when was it
# retracted, and did a correction precede/follow the retraction?
# --------------------------------------------------------------------------

def _normalize_fingerprint(value: str) -> str:
    v = (value or "").strip().lower()
    if not _valid_hex(v, 40):
        raise AttestError("invalid fingerprint (expected 40 hex chars)")
    return v


def _normalize_prefix(value: str) -> str:
    v = (value or "").strip().upper()
    if not v or any(c not in "0123456789ABCDEF" for c in v):
        raise AttestError("invalid prefix (hex characters only)")
    return v


def check(verified: dict, *, fingerprint: str | None = None,
          prefix: str | None = None, file_sha256: str | None = None,
          source: str | None = None) -> dict:
    """Produce a verdict from a VERIFIED snapshot. Never raises 'not found'
    for an absent record (that is a legitimate ``not_attested`` verdict);
    raises only for malformed input or a digest mismatch.

    No output field carries the queried fingerprint/prefix/digest, so a failed
    check cannot disclose bucket content.
    """
    records = verified["records"]
    prefix_len = verified["prefix_len"]

    # Every source that registered is discoverable from the signed chain.
    registered_sources = set(verified.get("registered_sources", ()))

    if fingerprint is not None:
        fp = _normalize_fingerprint(fingerprint)
        qprefix = fp[:prefix_len].upper()
    elif prefix is not None:
        qprefix = _normalize_prefix(prefix)
        if len(qprefix) != prefix_len:
            raise AttestError(
                f"prefix length must equal the snapshot prefix_len={prefix_len}")
    else:
        raise AttestError("check requires a fingerprint or a prefix")

    bucket = records.get(qprefix)
    sources = bucket["sources"] if bucket else {}

    # An explicit --source that the ledger never registered is a source
    # PERMISSION failure, distinct from "registered but never attested here".
    if source is not None:
        if not isinstance(source, str) or not source:
            raise AttestError("invalid source")
        if source not in registered_sources:
            raise AttestError(
                "source permission: the named source is not registered in"
                " this ledger")

    # A claimed input digest binds the query to a specific submitted input.
    # A mismatch is an explicit FAIL, distinct from "never attested". When a
    # source is named, the digest must be one of THAT source's submissions.
    if file_sha256 is not None:
        if not _valid_hex(file_sha256.strip().lower(), 64):
            raise AttestError("invalid file_sha256 (expected 64 hex chars)")
        fd = file_sha256.strip().lower()
        candidates = {source} if source is not None else sources.keys()
        if not any(sources.get(s, {}).get("file_sha256") == fd
                   for s in candidates):
            raise AttestError(
                "digest mismatch: no attested submission of this input"
                " (by the specified source) in the queried bucket")

    def describe(s: str) -> dict:
        rec = sources[s]
        corrections = rec["corrections"]
        # corrections relevant to THIS fingerprint are surfaced only when the
        # caller already holds the fingerprint -- never otherwise.
        fp_corrections = []
        if fingerprint is not None:
            fp_corrections = [c for c in corrections if c["fingerprint"] == fp]
        fp_corr_before = False
        if rec["retracted_at"] and fp_corrections:
            fp_corr_before = min(c["at"] for c in fp_corrections) \
                < rec["retracted_at"]
        return {
            "source": s,
            "submitted_at": rec["submitted_at"],
            "submitted_seq": rec["submitted_seq"],
            "retracted_at": rec["retracted_at"],
            "retract_reason": rec["retract_reason"],
            "corrected_before_retraction": rec["correction_before_retraction"],
            "fingerprint_corrected": bool(fp_corrections),
            "fingerprint_corrected_before_retraction": fp_corr_before,
        }

    base = {
        "verdict": None,
        "ledger_id": verified["ledger_id"],
        "head_seq": verified["head_seq"],
        "snapshot_not_after": verified["not_after"],
        "queried_source": source,
    }

    if source is not None:
        # registration/permission and digest binding are checked above; here
        # only attestation of THIS bucket by the named source matters.
        if source in sources:
            base.update({"verdict": "attested", "attestation": describe(source)})
        else:
            base.update({"verdict": "not_attested"})
        return base

    if not sources:
        base.update({"verdict": "not_attested"})
        return base
    # choose the earliest attested source deterministically
    earliest = min(sources, key=lambda s: (sources[s]["submitted_seq"], s))
    base.update({"verdict": "attested", "attestation": describe(earliest),
                 "attesting_sources": sorted(sources)})
    return base


# --------------------------------------------------------------------------
# Command line (fully offline)
# --------------------------------------------------------------------------

def _read_input_digest(args) -> str | None:
    if args.file is not None:
        h = hashlib.sha256()
        with open(args.file, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    return args.file_sha256


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-attest",
        description="offline accountability verification against a snapshot"
                    " (no database, no network)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="verify a snapshot and answer one query")
    p.add_argument("snapshot")
    p.add_argument("--fingerprint", default=None,
                   help="40-hex SHA-1 fingerprint the reviewer holds")
    p.add_argument("--prefix", default=None,
                   help=f"bucket prefix (length = snapshot prefix_len)")
    p.add_argument("--file", default=None,
                   help="input file whose sha256 must match the submission")
    p.add_argument("--file-sha256", dest="file_sha256", default=None)
    p.add_argument("--source", default=None,
                   help="assert a specific source; permission error if absent")
    p.add_argument("--genesis-pub", default=None,
                   help="pin the ledger genesis public key (hex)")
    p.add_argument("--now", default=None,
                   help="override current time (ISO 8601), for replayable tests")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    p = sub.add_parser("verify", help="verify the snapshot only (no query)")
    p.add_argument("snapshot")
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--now", default=None)

    args = ap.parse_args(argv)
    try:
        now = parse_ts(args.now) if args.now else None
        snap = load_snapshot(args.snapshot)
        verified = verify_snapshot(
            snap, now=now, trusted_genesis_pub=args.genesis_pub)
        if args.cmd == "verify":
            print(f"OK: snapshot valid, ledger {verified['ledger_id']}, "
                  f"head_seq {verified['head_seq']}, valid until "
                  f"{verified['not_after']}")
            return 0

        digest = _read_input_digest(args)
        verdict = check(verified, fingerprint=args.fingerprint,
                        prefix=args.prefix, file_sha256=digest,
                        source=args.source)
        if args.json:
            print(json.dumps(verdict, indent=2, sort_keys=True))
        else:
            _print_verdict(verdict)
        return 0 if verdict["verdict"] == "attested" else 3
    except AttestError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


def _print_verdict(v: dict) -> None:
    if v["verdict"] == "not_attested":
        print("NOT_ATTESTED: no matching signed submission in this snapshot")
        return
    a = v["attestation"]
    print(f"ATTESTED: source {a['source']} submitted at {a['submitted_at']}"
          f" (chain seq {a['submitted_seq']})")
    if a["retracted_at"]:
        print(f"  retracted at {a['retracted_at']}; reason: {a['retract_reason']}")
    else:
        print("  not retracted (as of this snapshot)")
    if a["fingerprint_corrected"]:
        when = "before" if a["fingerprint_corrected_before_retraction"] \
            else "after/no-retraction"
        print(f"  this fingerprint was corrected ({when} the retraction)")
    elif a["corrected_before_retraction"]:
        print("  a correction exists in this bucket before the retraction"
              " (different fingerprint)")
    print(f"  snapshot head_seq {v['head_seq']}, valid until "
          f"{v['snapshot_not_after']}")


if __name__ == "__main__":
    raise SystemExit(main())
