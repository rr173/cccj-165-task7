"""Append-only provenance responsibility ledger (writer side).

Every ingestion batch reaches this module as a signed *claim* from a named
source. Claims are written to an append-only SQLite table where each chain
item stores the hash of its predecessor (``prev_hash``); hashes and source
signatures make every item independently verifiable and tamper-evident.

Chain item kinds:

    register  bind a source name to an Ed25519 public key (self-signed)
    submit    a batch: input file digest + the set of bucket prefixes it
              contributes (+ optional free-text claim note)
    retract   withdraw one earlier *submit* claim, with a mandatory reason
    correct   flag fingerprints inside one earlier *submit* claim as errors

Trust and ordering rules (enforced here on write AND re-checked from the
bytes by ``attest.verify_chain`` on read):

  * a source must register before it can sign anything else;
  * every signature is checked against the registered key inside the write
    transaction, so a forged claim never reaches the chain;
  * only the source that made a submission may retract or correct it
    (``source permission error``);
  * retraction/correction order is simply chain order -- the offline snapshot
    records whether a correction landed before or after the retraction;
  * seq is gapless and ``prev_hash`` links every item, so a deleted item is a
    broken chain, not a silent gap;
  * repeated submissions (same claim_id, or same source+file digest) return
    the ORIGINAL chain item and append nothing -- including from a second
    process after an interrupted run;
  * a writer that expected a specific chain head fails with a clear
    ``LedgerConflict`` instead of blindly extending a chain someone else
    advanced first.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time

from . import attest, db, ed25519

LEDGER_PREFIX_LEN = 5
GENESIS_KEY_PERMS = 0o600

META_LEDGER_ID = "attest_ledger_id"
META_GENESIS_PUB = "attest_genesis_pub"
META_PREFIX_LEN = "attest_prefix_len"

LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_sources (
  source       TEXT PRIMARY KEY,
  pubkey       TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  register_seq  INTEGER NOT NULL
);

-- One row: the current chain tip. Advancing it with a conditional UPDATE
-- (WHERE head_seq = <the predecessor this writer observed>) is an atomic
-- compare-and-set that detects a writer whose WAL snapshot was stale even
-- though it held the write lock.
CREATE TABLE IF NOT EXISTS ledger_head (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  head_seq   INTEGER NOT NULL,
  head_hash  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_entries (
  seq              INTEGER PRIMARY KEY AUTOINCREMENT,
  kind             TEXT NOT NULL CHECK (kind IN ('register','submit','retract','correct')),
  source           TEXT NOT NULL,
  payload          TEXT NOT NULL,             -- canonical JSON, signed as-is
  created_at       TEXT NOT NULL,
  claim_id         TEXT NOT NULL UNIQUE,
  pubkey           TEXT NOT NULL,             -- key the signature was checked with
  signature        TEXT NOT NULL,
  prev_hash        TEXT NOT NULL,
  entry_hash       TEXT NOT NULL UNIQUE,
  file_sha256_dedup TEXT                      -- semantic dedup digest (nullable)
);
-- One submit / retract / correct semantic record per source and digest.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_semantic_dedup
  ON ledger_entries(source, kind, file_sha256_dedup)
  WHERE kind IN ('submit','retract','correct');
"""


class LedgerError(Exception):
    """Bad input or a malformed/unsigned claim. Never echoes raw input."""


class LedgerConflict(LedgerError):
    """The chain head advanced under us, or the claim is already settled."""


# --------------------------------------------------------------------------
# Key files (source keys and the ledger genesis key live outside the DB)
# --------------------------------------------------------------------------

def write_key_file(path: str, seed: bytes, public_key: bytes, *,
                   kind: str = "source", source: str | None = None,
                   ledger_id: str | None = None) -> None:
    data = {
        "kind": kind,
        "seed_hex": seed.hex(),
        "pubkey_hex": public_key.hex(),
    }
    if source is not None:
        data["source"] = source
    if ledger_id is not None:
        data["ledger_id"] = ledger_id
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except BaseException:
        os.unlink(path)
        raise


def read_key_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="ascii") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise LedgerError(f"key file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError(f"unreadable key file: {exc}") from exc
    for field in ("seed_hex", "pubkey_hex"):
        if field not in data:
            raise LedgerError(f"key file missing {field}")
    try:
        seed = bytes.fromhex(data["seed_hex"])
        pub = bytes.fromhex(data["pubkey_hex"])
    except ValueError as exc:
        raise LedgerError("key file contains invalid hex") from exc
    if ed25519.public_from_seed(seed) != pub:
        raise LedgerError("key file seed does not match its public key")
    data["_seed"] = seed
    data["_pub"] = pub
    return data


# --------------------------------------------------------------------------
# Initialisation
# --------------------------------------------------------------------------

def is_initialised(conn) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ledger_entries'"
    ).fetchone()
    if row is None:
        return False
    return conn.execute(
        "SELECT 1 FROM meta WHERE key=?", (META_LEDGER_ID,)).fetchone() is not None


def initialise(conn, key_path: str, *, prefix_len: int = LEDGER_PREFIX_LEN,
               force_new_key: bool = False) -> dict:
    """Create ledger tables and the genesis signing key.

    The genesis private key is written to ``key_path`` (mode 0600) and only
    its public half is stored in the DB. Re-running on an initialised ledger
    is an error.
    """
    if not isinstance(prefix_len, int) or not (1 <= prefix_len < 40):
        raise LedgerError("prefix_len must be between 1 and 39")
    conn.executescript(LEDGER_SCHEMA)
    existing = conn.execute(
        "SELECT value FROM meta WHERE key=?", (META_LEDGER_ID,)).fetchone()
    if existing is not None:
        raise LedgerError("ledger is already initialised")
    if os.path.exists(key_path) and not force_new_key:
        raise LedgerError(f"key file already exists: {key_path}")

    seed, pub = ed25519.generate_key()
    ledger_id = os.urandom(8).hex()
    with db.write_tx(conn):
        conn.execute(
            "INSERT INTO meta(key,value) VALUES (?,?)",
            (META_LEDGER_ID, ledger_id))
        conn.execute(
            "INSERT INTO meta(key,value) VALUES (?,?)",
            (META_GENESIS_PUB, pub.hex()))
        conn.execute(
            "INSERT INTO meta(key,value) VALUES (?,?)",
            (META_PREFIX_LEN, str(prefix_len)))
        conn.execute(
            "INSERT INTO ledger_head(id, head_seq, head_hash) VALUES (1,0,?)",
            ("GENESIS:" + ledger_id,))
    write_key_file(key_path, seed, pub, kind="ledger-genesis",
                   ledger_id=ledger_id)
    return {"ledger_id": ledger_id, "genesis_pub": pub.hex(),
            "key_file": key_path, "prefix_len": prefix_len}


def _meta(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def ledger_info(conn) -> dict:
    if not is_initialised(conn):
        raise LedgerError("ledger is not initialised (run ledger-init)")
    h = head(conn)
    return {
        "ledger_id": _meta(conn, META_LEDGER_ID),
        "genesis_pub": _meta(conn, META_GENESIS_PUB),
        "prefix_len": int(_meta(conn, META_PREFIX_LEN)),
        "head_seq": h["seq"], "head_hash": h["hash"], "entries": h["seq"],
    }


def head(conn) -> dict:
    row = conn.execute(
        "SELECT head_seq, head_hash FROM ledger_head WHERE id=1").fetchone()
    if row is None:
        lid = _meta(conn, META_LEDGER_ID)
        return {"seq": 0, "hash": "GENESIS:" + (lid or "")}
    return {"seq": row["head_seq"], "hash": row["head_hash"]}


# --------------------------------------------------------------------------
# Claim construction (signing happens on the source side / CLI boundary)
# --------------------------------------------------------------------------

def canonical_payload(payload: dict) -> str:
    return attest.canonical(payload)


def make_claim_id(kind: str, source: str, payload: dict,
                  explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if kind == attest.KIND_SUBMIT:
        return f"submit:{source}:{payload['file_sha256']}"
    if kind == attest.KIND_RETRACT:
        return f"retract:{source}:{payload['claim_seq']}"
    if kind == attest.KIND_CORRECT:
        fps = attest.canonical(payload["fingerprints"])
        return "correct:" + source + ":" + hashlib.sha256(
            f"{payload['claim_seq']}:{fps}".encode()).hexdigest()[:32]
    return f"register:{source}"


def build_intent(kind: str, source: str, payload: dict, seed: bytes,
                 created_at: str, claim_id: str | None = None) -> dict:
    """A signed, serialisable claim INTENT. It carries no pubkey (that comes
    from the chain registration) and is what an interrupted/replayed process
    writes to and reads back from disk."""
    cid = claim_id or make_claim_id(kind, source, payload)
    signature = attest.sign_claim(seed, kind, source, payload, created_at, cid)
    return {"kind": kind, "source": source, "payload": payload,
            "created_at": created_at, "claim_id": cid, "signature": signature}


def validate_submit_payload(payload: dict, prefix_len: int) -> None:
    if not isinstance(payload, dict):
        raise LedgerError("submit payload must be an object")
    if not attest._valid_hex(payload.get("file_sha256"), 64):
        raise LedgerError("submit payload needs a 64-hex file_sha256")
    prefixes = payload.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        raise LedgerError("submit payload needs a non-empty prefixes list")
    for p in prefixes:
        if not isinstance(p, str) or len(p) != prefix_len \
                or any(c not in "0123456789ABCDEF" for c in p):
            raise LedgerError(
                f"prefix must be {prefix_len} uppercase hex characters")
    if "reason" in payload and not isinstance(payload["reason"], str):
        raise LedgerError("submit reason must be a string")


def validate_retract_payload(payload: dict) -> None:
    if not isinstance(payload.get("claim_seq"), int) \
            or isinstance(payload["claim_seq"], bool) \
            or payload["claim_seq"] < 1:
        raise LedgerError("retract payload needs an integer claim_seq")
    if not attest._valid_hex(payload.get("file_sha256"), 64):
        raise LedgerError("retract payload needs the target file_sha256")
    if not isinstance(payload.get("reason"), str) or not payload["reason"]:
        raise LedgerError("retract payload requires a non-empty reason")


def validate_correct_payload(payload: dict) -> None:
    if not isinstance(payload.get("claim_seq"), int) \
            or isinstance(payload["claim_seq"], bool) \
            or payload["claim_seq"] < 1:
        raise LedgerError("correct payload needs an integer claim_seq")
    fps = payload.get("fingerprints")
    if not isinstance(fps, list) or not fps:
        raise LedgerError("correct payload needs a non-empty fingerprints list")
    for fp in fps:
        if not attest._valid_hex(fp, 40):
            raise LedgerError("each fingerprint must be 40 lowercase hex chars")


def validate_register_payload(payload: dict) -> None:
    if not attest._valid_hex(payload.get("pubkey"), 64):
        raise LedgerError("register payload needs a 64-hex pubkey")


# --------------------------------------------------------------------------
# Append (the write transaction boundary)
# --------------------------------------------------------------------------

def _row_to_entry(row) -> dict:
    return {
        "seq": row["seq"], "kind": row["kind"], "source": row["source"],
        "payload": json.loads(row["payload"]), "created_at": row["created_at"],
        "claim_id": row["claim_id"], "pubkey": row["pubkey"],
        "signature": row["signature"], "prev_hash": row["prev_hash"],
        "entry_hash": row["entry_hash"],
    }


def find_by_claim(conn, claim_id: str):
    return conn.execute(
        "SELECT * FROM ledger_entries WHERE claim_id=?", (claim_id,)
    ).fetchone()


def find_submit(conn, source: str, file_sha256: str):
    """The original submit entry for (source, digest) if it exists."""
    return conn.execute(
        "SELECT * FROM ledger_entries WHERE source=? AND kind='submit'"
        "  AND file_sha256_dedup=?",
        (source, file_sha256)).fetchone()


def append(conn, intent: dict, *, expected_head_seq: int | None = None) -> dict:
    """Append one signed claim to the hash chain.

    Idempotent: a claim already present (by claim_id, or for submit/retract/
    correct by its semantic key) returns the ORIGINAL item with
    ``duplicate=True`` and appends nothing -- including from a separate process
    after an interrupted run.

    Concurrent writers are serialised by BEGIN IMMEDIATE, and the chain tip is
    advanced with an atomic compare-and-set on the single-row ``ledger_head``:
    a writer whose WAL read snapshot is older than the commit it waited past
    observes the CAS affect zero rows, rolls back and retries on the SAME
    connection after yielding, so the hash chain can never fork. ``expected_head_seq``
    adds an explicit caller-side conflict for stale batches.
    """
    kind = intent.get("kind")
    source = intent.get("source")
    payload = intent.get("payload")
    created_at = intent.get("created_at")
    claim_id = intent.get("claim_id")
    signature = intent.get("signature")
    if kind not in attest.CLAIM_KINDS:
        raise LedgerError(f"unknown claim kind: {kind!r}")
    if not isinstance(source, str) or not source:
        raise LedgerError("claim needs a source")
    if not isinstance(payload, dict) or not isinstance(claim_id, str) \
            or not claim_id or not isinstance(created_at, str) or not created_at:
        raise LedgerError("claim is missing payload/created_at/claim_id")
    if not attest._valid_hex(signature, 128):
        raise LedgerError("claim needs a 128-hex Ed25519 signature")
    attest.parse_ts(created_at)
    prefix_len = int(_meta(conn, META_PREFIX_LEN))
    if kind == attest.KIND_SUBMIT:
        validate_submit_payload(payload, prefix_len)
    elif kind == attest.KIND_RETRACT:
        validate_retract_payload(payload)
    elif kind == attest.KIND_CORRECT:
        validate_correct_payload(payload)
    else:
        validate_register_payload(payload)

    payload_json = attest.canonical(payload)
    semantic_key = _semantic_digest(kind, payload)

    for attempt in range(60):
        try:
            with db.write_tx(conn):
                return _append_locked(conn, kind, source, payload, payload_json,
                                      semantic_key, created_at, claim_id,
                                      signature, expected_head_seq)
        except _Duplicate as dup:
            entry = _row_to_entry(dup.row)
            entry["duplicate"] = True
            return entry
        except _StaleChain:
            time.sleep(0.005 * (attempt + 1))
            continue
        except sqlite3.IntegrityError as exc:
            # Another writer won a unique constraint after our snapshot. If the
            # same semantic claim is now present, this is an idempotent replay;
            # otherwise surface a clear parallel-write conflict.
            row = _find_semantic(conn, kind, source, payload, claim_id)
            if row is not None:
                entry = _row_to_entry(row)
                entry["duplicate"] = True
                return entry
            raise LedgerConflict(
                f"parallel write conflict on the append chain ({exc})") from exc
    raise LedgerConflict(
        "append kept losing the chain-head race under parallel writes")


class _StaleChain(Exception):
    """The chain-tip compare-and-set lost: retry the whole append."""


def _append_locked(conn, kind, source, payload, payload_json, semantic_key,
                   created_at, claim_id, signature, expected_head_seq):
    # Fast duplicate check now that we hold the exclusive write lock.
    row = _find_semantic(conn, kind, source, payload, claim_id)
    if row is not None:
        raise _Duplicate(row)

    tip = conn.execute(
        "SELECT head_seq, head_hash FROM ledger_head WHERE id=1").fetchone()
    cur_seq, cur_hash = tip["head_seq"], tip["head_hash"]
    if expected_head_seq is not None and cur_seq != expected_head_seq:
        raise LedgerConflict(
            f"chain head is now seq {cur_seq}, expected seq"
            f" {expected_head_seq}; a parallel write committed first")

    if kind == attest.KIND_REGISTER:
        if conn.execute("SELECT 1 FROM ledger_sources WHERE source=?",
                        (source,)).fetchone() is not None:
            raise LedgerConflict(f"source {source!r} is already registered")
        signer_pub = payload["pubkey"]
    else:
        srow = conn.execute(
            "SELECT pubkey FROM ledger_sources WHERE source=?",
            (source,)).fetchone()
        if srow is None:
            raise LedgerError(
                f"source {source!r} is not registered (source permission)")
        signer_pub = srow["pubkey"]

    new_seq = cur_seq + 1
    entry_for_hash = {
        "seq": new_seq, "kind": kind, "source": source, "payload": payload,
        "created_at": created_at, "claim_id": claim_id, "pubkey": signer_pub,
        "signature": signature, "prev_hash": cur_hash,
    }
    try:
        attest._check_signature(signer_pub, entry_for_hash)
    except attest.AttestError as exc:
        raise LedgerError(str(exc)) from exc

    if kind == attest.KIND_RETRACT:
        _check_retract_target(conn, payload, source)
    elif kind == attest.KIND_CORRECT:
        _check_correct_target(conn, payload, source)

    entry_hash = attest.entry_hash_hex(entry_for_hash)
    conn.execute(
        "INSERT INTO ledger_entries(kind, source, payload, created_at,"
        " claim_id, pubkey, signature, prev_hash, entry_hash,"
        " file_sha256_dedup) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (kind, source, payload_json, created_at, claim_id, signer_pub,
         signature, cur_hash, entry_hash, semantic_key))
    if kind == attest.KIND_REGISTER:
        conn.execute(
            "INSERT INTO ledger_sources(source, pubkey, registered_at,"
            " register_seq) VALUES (?,?,?,?)",
            (source, signer_pub, created_at, new_seq))

    # Atomic chain-tip compare-and-set. A stale snapshot makes this UPDATE
    # match zero rows (another writer already advanced past cur_seq); abort so
    # the transaction rolls back and the append is retried against the new tip.
    cas = conn.execute(
        "UPDATE ledger_head SET head_seq=?, head_hash=?"
        " WHERE id=1 AND head_seq=? AND head_hash=?",
        (new_seq, entry_hash, cur_seq, cur_hash))
    if cas.rowcount != 1:
        raise _StaleChain(f"chain tip advanced past {cur_seq}")

    result = dict(entry_for_hash)
    result["entry_hash"] = entry_hash
    result["duplicate"] = False
    return result


def _check_retract_target(conn, payload, source):
    target = conn.execute(
        "SELECT * FROM ledger_entries WHERE seq=? AND kind='submit'",
        (payload["claim_seq"],)).fetchone()
    if target is None:
        raise LedgerError(
            "retraction targets a seq that is missing or not a submission"
            " (missing chain item)")
    if target["source"] != source:
        raise LedgerError(
            "a source may only retract its own submission (source permission)")
    if json.loads(target["payload"])["file_sha256"] != payload["file_sha256"]:
        raise LedgerError(
            "retraction digest does not match the targeted submission")
    if conn.execute(
            "SELECT 1 FROM ledger_entries WHERE kind='retract' AND source=?"
            "  AND file_sha256_dedup=?",
            (source, payload["file_sha256"])).fetchone() is not None:
        raise LedgerConflict("that submission is already retracted")


def _check_correct_target(conn, payload, source):
    target = conn.execute(
        "SELECT * FROM ledger_entries WHERE seq=? AND kind='submit'",
        (payload["claim_seq"],)).fetchone()
    if target is None:
        raise LedgerError(
            "correction targets a seq that is missing or not a submission"
            " (missing chain item)")
    if target["source"] != source:
        raise LedgerError(
            "a source may only correct its own submission (source permission)")


def _semantic_digest(kind, payload):
    if kind in (attest.KIND_SUBMIT, attest.KIND_RETRACT):
        return payload["file_sha256"]
    if kind == attest.KIND_CORRECT:
        return hashlib.sha256(
            attest.canonical({"claim_seq": payload["claim_seq"],
                              "fingerprints": payload["fingerprints"]}).encode()
        ).hexdigest()
    return None



class _Duplicate(Exception):
    """Internal: the claim already exists (detected under the write lock)."""

    def __init__(self, row):
        self.row = row
        super().__init__("duplicate claim")


def _find_semantic(conn, kind, source, payload, claim_id):
    """Existing row for a claim, by claim_id first then the semantic key."""
    row = find_by_claim(conn, claim_id)
    if row is not None:
        return row
    digest = _semantic_digest(kind, payload)
    if digest is None:
        return None
    return conn.execute(
        "SELECT * FROM ledger_entries WHERE source=? AND kind=?"
        "  AND file_sha256_dedup=?",
        (source, kind, digest)).fetchone()


# --------------------------------------------------------------------------
# Batch replay: append many intents, resuming from the last chain item after
# an interruption (already-present claims are skipped, not re-appended)
# --------------------------------------------------------------------------

def replay_intents(conn, intents, *, expected_head_seq: int | None = None,
                   progress=None) -> dict:
    """Append each intent in order. A claim already on the chain (by claim_id
    or by semantic dedup) is skipped with ``duplicate=True`` -- this is what
    makes a crashed batch safely re-runnable from the last chain item.
    """
    appended, duplicates = [], []
    first_head = head(conn)["seq"]
    if expected_head_seq is not None and first_head != expected_head_seq:
        raise LedgerConflict(
            f"chain head is seq {first_head}, expected {expected_head_seq};"
            " refusing to replay a batch bound to a different head")
    for idx, intent in enumerate(intents, 1):
        # bind every append to the head the previous item just produced,
        # catching any out-of-band writer between intents
        before = head(conn)["seq"]
        entry = append(conn, intent, expected_head_seq=before)
        if entry["duplicate"]:
            duplicates.append({"claim_id": entry["claim_id"],
                               "seq": entry["seq"]})
        else:
            appended.append({"claim_id": entry["claim_id"],
                             "seq": entry["seq"]})
        if progress is not None:
            progress(idx, intent, entry)
    h = head(conn)
    return {"appended": appended, "duplicates": duplicates,
            "head_seq": h["seq"], "head_hash": h["hash"]}


# --------------------------------------------------------------------------
# Read-side verification (used by the auditor; mirrors the offline replay)
# --------------------------------------------------------------------------

def all_entries(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM ledger_entries ORDER BY seq").fetchall()
    return [_row_to_entry(r) for r in rows]


def verify_stored_chain(conn) -> tuple[dict, str, int]:
    """Verify the whole stored chain: stored entry_hash vs recomputed,
    prev_hash linkage, gapless seq, source signatures and semantics."""
    if not is_initialised(conn):
        raise LedgerError("ledger is not initialised")
    lid = _meta(conn, META_LEDGER_ID)
    entries = all_entries(conn)
    # the offline verifier recomputes every hash itself; here also compare the
    # stored hash so a corrupted row is caught even if links still align.
    prev = "GENESIS:" + lid
    for e in entries:
        row = conn.execute(
            "SELECT entry_hash FROM ledger_entries WHERE seq=?",
            (e["seq"],)).fetchone()
        recomputed = attest.entry_hash_hex(e)
        if row["entry_hash"] != recomputed:
            raise LedgerError(
                f"chain item {e['seq']}: stored hash does not match its"
                f" content (the ledger was modified outside the append path)")
        if e["prev_hash"] != prev:
            raise LedgerError(
                f"chain item {e['seq']}: prev_hash linkage broken")
        prev = row["entry_hash"]
    by_prefix, head_hash, head_seq = attest.verify_chain(entries, lid)
    h = head(conn)
    if head_hash != h["hash"] or head_seq != h["seq"]:
        raise LedgerError("replayed chain tip does not match the ledger head")
    return by_prefix, head_hash, head_seq
