"""Core pipeline: ingest -> build candidate -> review -> activate -> serve.

Invariants enforced here:
  * Raw passwords are hashed (SHA-1) the moment they enter the system and are
    never stored, logged, or returned.
  * A publication is immutable. Retractions / corrections only take effect by
    building and activating a NEW version; old versions stay verifiable.
  * A bucket (prefix) is published only if it contains >= threshold_k distinct
    suffixes. Smaller buckets are dropped entirely so no small-set inference
    is possible.
  * Range queries read the version pointer and the bucket rows inside a single
    SQLite snapshot, so a query can never mix two versions.
  * A candidate records the corpus-state token of the snapshot it was built
    from. Source mutations (new batch / retraction / corrections) advance the
    token inside their own write transaction; activation compares the tokens
    and rejects a stale candidate instead of letting an old snapshot override
    newer source state. A stale candidate can be refreshed in place (same
    version, same k) and reviewed again.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

from . import db

# Fixed system-wide prefix length (hex chars of the SHA-1 fingerprint).
# Changing it requires a code change and a full rebuild of every publication,
# which keeps bucketing stable and comparable across versions.
PREFIX_LEN = 5
SHA1_HEX_LEN = 40
DEFAULT_THRESHOLD_K = 50
MAX_THRESHOLD_K = 1_000_000

_SHA1_RE = re.compile(r"^[0-9A-F]{40}$")


class CorpusError(Exception):
    """Bad input / bad state. Messages must never contain submitted items."""


class NotFound(CorpusError):
    pass


class Conflict(CorpusError):
    pass


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fingerprint(item) -> str:
    """Normalise one submitted item to an uppercase SHA-1 hex fingerprint.

    * ``{"sha1": "<hex>"}``  -> pre-hashed submission (preferred: the raw
      password never leaves the client).
    * any other string       -> raw password, hashed here and discarded.

    Raw passwords are intentionally NOT stripped: leading/trailing spaces may
    be part of the password.
    """
    if isinstance(item, dict):
        h = str(item.get("sha1", "")).strip().upper()
        if not _SHA1_RE.fullmatch(h):
            raise CorpusError("invalid sha1 digest in items")
        return h
    return hashlib.sha1(str(item).encode("utf-8")).hexdigest().upper()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# --------------------------------------------------------------------------
# Corpus-state token (staleness detection for candidates)
# --------------------------------------------------------------------------

def corpus_state(conn) -> int:
    """Monotonic token identifying the current source-data state. It is bumped
    by every EFFECTIVE corpus mutation (new batch, retraction, new correction
    rows) inside the same write transaction as the mutation itself, so a
    candidate built at token N is stale iff the current token differs from N."""
    r = conn.execute("SELECT value FROM meta WHERE key='corpus_state'").fetchone()
    return int(r["value"]) if r else 0


def _bump_corpus_state(conn) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES ('corpus_state', '1')"
        " ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1"
    )


# --------------------------------------------------------------------------
# Auth tokens
# --------------------------------------------------------------------------

SCOPES = ("ingest", "retract", "publish", "budget-admin")


def create_token(conn, label: str, scopes) -> str:
    bad = set(scopes) - set(SCOPES)
    if bad:
        raise CorpusError(f"unknown scopes: {sorted(bad)}")
    token = "pwc_" + secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO tokens(token_sha256, label, scopes, created_at) VALUES (?,?,?,?)",
        (hashlib.sha256(token.encode()).hexdigest(), label, ",".join(sorted(scopes)), utcnow()),
    )
    return token  # shown once; only its hash persists


def lookup_token(conn, token: str):
    h = hashlib.sha256(token.encode()).hexdigest()
    return conn.execute("SELECT * FROM tokens WHERE token_sha256 = ?", (h,)).fetchone()


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------

def ingest_batch(conn, source: str, items, idem_key: str | None = None) -> dict:
    """Ingest one batch. Idempotent: a repeated batch (same idempotency key,
    or same content from the same source) returns the existing batch and does
    NOT double-count."""
    if not source or not isinstance(source, str):
        raise CorpusError("source is required")
    if not isinstance(items, list) or not items:
        raise CorpusError("items must be a non-empty list")

    counts: Counter[str] = Counter()
    for it in items:
        counts[fingerprint(it)] += 1
    del items  # drop the reference to raw material as early as possible

    canonical = "\n".join(f"{h}:{c}" for h, c in sorted(counts.items()))
    content_hash = hashlib.sha256(f"{source}\n{canonical}".encode()).hexdigest()
    key = idem_key or content_hash
    batch_id = secrets.token_hex(16)
    now = utcnow()
    try:
        with db.write_tx(conn):
            conn.execute(
                "INSERT INTO batches(batch_id, source, idem_key, content_sha256,"
                " item_count, occurrence_count, status, created_at)"
                " VALUES (?,?,?,?,?,?,'active',?)",
                (batch_id, source, key, content_hash, len(counts), sum(counts.values()), now),
            )
            conn.executemany(
                "INSERT INTO batch_items(batch_id, hash_hex, cnt) VALUES (?,?,?)",
                [(batch_id, h, c) for h, c in counts.items()],
            )
            _bump_corpus_state(conn)
        return {
            "batch_id": batch_id, "duplicate": False,
            "distinct_fingerprints": len(counts),
            "occurrences": sum(counts.values()),
        }
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT batch_id, item_count, occurrence_count FROM batches"
            " WHERE idem_key = ? OR (source = ? AND content_sha256 = ?)",
            (key, source, content_hash),
        ).fetchone()
        if row is None:  # pragma: no cover - defensive
            raise
        return {
            "batch_id": row["batch_id"], "duplicate": True,
            "distinct_fingerprints": row["item_count"],
            "occurrences": row["occurrence_count"],
        }


def retract_batch(conn, batch_id: str) -> dict:
    """Mark a batch retracted. Takes effect only in the NEXT publication
    build; the currently active publication is untouched."""
    with db.write_tx(conn):
        row = conn.execute("SELECT status FROM batches WHERE batch_id = ?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("batch not found")
        if row["status"] == "active":
            conn.execute(
                "UPDATE batches SET status='retracted', retracted_at=? WHERE batch_id=?",
                (utcnow(), batch_id),
            )
            _bump_corpus_state(conn)
    return {
        "batch_id": batch_id, "status": "retracted",
        "note": "effective in the next publication build; current version unchanged",
    }


def add_corrections(conn, batch_id: str, items) -> dict:
    """False-positive correction: exclude specific fingerprints of a batch
    from future publications. Also only effective via a new build."""
    if not isinstance(items, list) or not items:
        raise CorpusError("items must be a non-empty list")
    hashes = {fingerprint(i) for i in items}
    del items
    with db.write_tx(conn):
        if conn.execute("SELECT 1 FROM batches WHERE batch_id = ?", (batch_id,)).fetchone() is None:
            raise NotFound("batch not found")
        before = conn.total_changes
        conn.executemany(
            "INSERT OR IGNORE INTO corrections(batch_id, hash_hex, created_at) VALUES (?,?,?)",
            [(batch_id, h, utcnow()) for h in hashes],
        )
        if conn.total_changes > before:  # only genuinely new corrections matter
            _bump_corpus_state(conn)
    return {
        "batch_id": batch_id, "corrected_fingerprints": len(hashes),
        "note": "effective in the next publication build; current version unchanged",
    }


# --------------------------------------------------------------------------
# Publication build / activate
# --------------------------------------------------------------------------

def _active_corpus(conn) -> list[tuple[str, int]]:
    """Aggregated fingerprint counts over active batches minus corrections."""
    rows = conn.execute(
        "SELECT bi.hash_hex AS h, SUM(bi.cnt) AS c"
        " FROM batch_items bi JOIN batches b ON b.batch_id = bi.batch_id"
        " WHERE b.status = 'active'"
        "   AND NOT EXISTS (SELECT 1 FROM corrections c"
        "                   WHERE c.batch_id = bi.batch_id AND c.hash_hex = bi.hash_hex)"
        " GROUP BY bi.hash_hex"
    ).fetchall()
    return sorted((r["h"], r["c"]) for r in rows)


def _bucketize(corpus, prefix_len: int) -> dict[str, list[tuple[str, int]]]:
    buckets: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for h, c in corpus:
        buckets[h[:prefix_len]].append((h[prefix_len:], c))
    return {p: sorted(v) for p, v in buckets.items()}


def _manifest_payload(version: int, k: int, created_at: str,
                      kept: dict[str, list[tuple[str, int]]], prefix_len: int) -> dict:
    files = {}
    for prefix in sorted(kept):
        body = "".join(f"{s}:{c}\n" for s, c in kept[prefix])
        files[prefix] = hashlib.sha256(body.encode("ascii")).hexdigest()
    return {
        "version": version,
        "hash_algo": "sha1",
        "prefix_len": prefix_len,
        "threshold_k": k,
        "created_at": created_at,
        "files": files,
    }


def _corpus_snapshot(conn) -> tuple[list[tuple[str, int]], int]:
    """Read the active corpus AND the corpus-state token in one snapshot, so
    the recorded token always corresponds to the data that was aggregated."""
    conn.execute("BEGIN")  # deferred read transaction = stable snapshot
    try:
        return _active_corpus(conn), corpus_state(conn)
    finally:
        conn.execute("ROLLBACK")


def build_candidate(conn, k: int = DEFAULT_THRESHOLD_K) -> dict:
    """Materialise a new candidate publication from the current active corpus.

    Buckets with fewer than k distinct suffixes are suppressed entirely.
    The candidate does not affect the active version; if source data changes
    afterwards the candidate becomes stale (see activate/refresh_candidate).

    The corpus and the corpus-state token are read in one snapshot and the
    token is re-checked before the insert commits, so the recorded token
    always matches the data the candidate was built from.
    """
    if not isinstance(k, int) or not (1 <= k <= MAX_THRESHOLD_K):
        raise CorpusError("invalid threshold k")
    corpus, state = _corpus_snapshot(conn)
    corpus_hash = hashlib.sha256(
        "\n".join(f"{h}:{c}" for h, c in corpus).encode()
    ).hexdigest()
    buckets = _bucketize(corpus, PREFIX_LEN)
    kept = {p: v for p, v in buckets.items() if len(v) >= k}
    suppressed = len(buckets) - len(kept)
    suffix_count = sum(len(v) for v in kept.values())
    now = utcnow()
    with db.write_tx(conn):
        if corpus_state(conn) != state:
            raise Conflict("source data changed while building; retry the build")
        cur = conn.execute(
            "INSERT INTO publications(threshold_k, prefix_len, status, created_at,"
            " bucket_count, suffix_count, suppressed_bucket_count, corpus_sha256,"
            " corpus_state, manifest_sha256) VALUES (?,?, 'candidate', ?, ?,?,?,?,?, '')",
            (k, PREFIX_LEN, now, len(kept), suffix_count, suppressed, corpus_hash, state),
        )
        version = cur.lastrowid
        conn.executemany(
            "INSERT INTO pub_buckets(version, prefix, suffix, cnt) VALUES (?,?,?,?)",
            [(version, p, s, c) for p, entries in kept.items() for s, c in entries],
        )
        manifest = _manifest_payload(version, k, now, kept, PREFIX_LEN)
        mhash = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
        conn.execute(
            "UPDATE publications SET manifest_sha256 = ? WHERE version = ?",
            (mhash, version),
        )
    return {
        "version": version, "status": "candidate", "threshold_k": k,
        "prefix_len": PREFIX_LEN, "bucket_count": len(kept),
        "suffix_count": suffix_count, "suppressed_bucket_count": suppressed,
        "corpus_sha256": corpus_hash, "manifest_sha256": mhash,
        "corpus_state": state,
    }


def refresh_candidate(conn, version: int) -> dict:
    """Rebuild a candidate from the CURRENT source data, in place: same
    version number, same threshold k. This is the way out of a stale-draft
    conflict — the refreshed candidate can be previewed and activated again.
    Published (active/retired) versions are never touched."""
    conn.execute("BEGIN")
    try:
        row = conn.execute(
            "SELECT status, threshold_k FROM publications WHERE version = ?",
            (version,)).fetchone()
        if row is None:
            raise NotFound("publication not found")
        if row["status"] != "candidate":
            raise Conflict(
                f"publication {version} is '{row['status']}';"
                " only a candidate can be refreshed")
        k = row["threshold_k"]
        corpus = _active_corpus(conn)
        state = corpus_state(conn)
    finally:
        conn.execute("ROLLBACK")
    corpus_hash = hashlib.sha256(
        "\n".join(f"{h}:{c}" for h, c in corpus).encode()
    ).hexdigest()
    buckets = _bucketize(corpus, PREFIX_LEN)
    kept = {p: v for p, v in buckets.items() if len(v) >= k}
    suppressed = len(buckets) - len(kept)
    suffix_count = sum(len(v) for v in kept.values())
    now = utcnow()
    with db.write_tx(conn):
        if corpus_state(conn) != state:
            raise Conflict("source data changed while refreshing; retry the refresh")
        cur = conn.execute(
            "SELECT status FROM publications WHERE version = ?", (version,)).fetchone()
        if cur["status"] != "candidate":  # e.g. activated concurrently
            raise Conflict(
                f"publication {version} is '{cur['status']}';"
                " only a candidate can be refreshed")
        conn.execute("DELETE FROM pub_buckets WHERE version = ?", (version,))
        conn.executemany(
            "INSERT INTO pub_buckets(version, prefix, suffix, cnt) VALUES (?,?,?,?)",
            [(version, p, s, c) for p, entries in kept.items() for s, c in entries],
        )
        manifest = _manifest_payload(version, k, now, kept, PREFIX_LEN)
        mhash = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
        conn.execute(
            "UPDATE publications SET created_at=?, bucket_count=?, suffix_count=?,"
            " suppressed_bucket_count=?, corpus_sha256=?, manifest_sha256=?,"
            " corpus_state=? WHERE version=?",
            (now, len(kept), suffix_count, suppressed, corpus_hash, mhash,
             state, version),
        )
    return {
        "version": version, "status": "candidate", "threshold_k": k,
        "prefix_len": PREFIX_LEN, "bucket_count": len(kept),
        "suffix_count": suffix_count, "suppressed_bucket_count": suppressed,
        "corpus_sha256": corpus_hash, "manifest_sha256": mhash,
        "corpus_state": state, "refreshed": True,
    }


def activate(conn, version: int, expected_manifest: str | None = None) -> dict:
    """Atomically switch the active publication. Single write transaction:
    old active -> retired, candidate -> active, pointer swap. Concurrent
    queries see either the old or the new version, never a mix.

    The switch is a compare-and-swap against concurrent source writes: the
    candidate carries the corpus-state token of the snapshot it was built
    from. If a source update (new batch, retraction, corrections) committed
    first, the tokens differ and the activation is rejected WITHOUT touching
    the serving version; if the activation commits first, the later source
    update simply waits for the next build. ``expected_manifest`` optionally
    binds the confirmation to the exact draft the admin reviewed.
    """
    with db.write_tx(conn):
        row = conn.execute(
            "SELECT status, manifest_sha256, corpus_state FROM publications"
            " WHERE version = ?", (version,)).fetchone()
        if row is None:
            raise NotFound("publication not found")
        if row["status"] != "candidate":
            raise Conflict(f"publication {version} is '{row['status']}'; only a candidate can be activated")
        if expected_manifest is not None and expected_manifest != row["manifest_sha256"]:
            raise Conflict(
                f"publication {version} changed since this confirmation was"
                " prepared; reload the review page")
        if row["corpus_state"] != corpus_state(conn):
            raise Conflict(
                f"publication {version} is stale: source data changed after it"
                " was built; refresh the candidate and review again")
        now = utcnow()
        conn.execute(
            "UPDATE publications SET status='retired', retired_at=? WHERE status='active'",
            (now,),
        )
        conn.execute(
            "UPDATE publications SET status='active', activated_at=? WHERE version=?",
            (now, version),
        )
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('current_version', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(version),),
        )
    return {"version": version, "status": "active"}


# --------------------------------------------------------------------------
# Anonymous range query (served ONLY from the active publication)
# --------------------------------------------------------------------------

def current_version(conn) -> int | None:
    r = conn.execute("SELECT value FROM meta WHERE key='current_version'").fetchone()
    return int(r["value"]) if r else None


def query_range(conn, prefix: str):
    """Return (version, body) for a prefix, or (version, None) if the bucket
    does not exist in the active version, or (None, None) if nothing is
    active. Runs inside one read snapshot: no cross-version mixing."""
    prefix = prefix.upper()
    if not re.fullmatch(r"[0-9A-F]{%d}" % PREFIX_LEN, prefix):
        raise CorpusError(f"prefix must be exactly {PREFIX_LEN} hex characters")
    conn.execute("BEGIN")  # deferred read transaction = stable snapshot
    try:
        v = current_version(conn)
        if v is None:
            return None, None
        rows = conn.execute(
            "SELECT suffix, cnt FROM pub_buckets WHERE version = ? AND prefix = ?"
            " ORDER BY suffix",
            (v, prefix),
        ).fetchall()
        body = "".join(f"{r['suffix']}:{r['cnt']}\n" for r in rows)
        return v, (body if rows else None)
    finally:
        conn.execute("ROLLBACK")


# --------------------------------------------------------------------------
# Review helpers
# --------------------------------------------------------------------------

def get_publication(conn, version: int):
    row = conn.execute("SELECT * FROM publications WHERE version = ?", (version,)).fetchone()
    if row is None:
        raise NotFound("publication not found")
    return dict(row)


def list_publications(conn) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM publications ORDER BY version DESC").fetchall()]


def list_batches(conn, limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT batch_id, source, item_count, occurrence_count, status, created_at,"
        " retracted_at FROM batches ORDER BY created_at DESC, batch_id LIMIT ?",
        (limit,)).fetchall()]


def diff_versions(conn, old_v: int, new_v: int) -> dict:
    def load(v):
        rows = conn.execute(
            "SELECT prefix, suffix, cnt FROM pub_buckets WHERE version = ?", (v,)
        ).fetchall()
        return {(r["prefix"], r["suffix"]): r["cnt"] for r in rows}

    a, b = load(old_v), load(new_v)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    buckets_a = {p for p, _ in a}
    buckets_b = {p for p, _ in b}
    sample = (
        [("added", p, s, None, b[(p, s)]) for p, s in added[:40]]
        + [("removed", p, s, a[(p, s)], None) for p, s in removed[:40]]
        + [("count_changed", p, s, a[(p, s)], b[(p, s)]) for p, s in changed[:40]]
    )[:100]
    return {
        "from_version": old_v, "to_version": new_v,
        "buckets_added": sorted(buckets_b - buckets_a),
        "buckets_removed": sorted(buckets_a - buckets_b),
        "suffixes_added": len(added),
        "suffixes_removed": len(removed),
        "counts_changed": len(changed),
        "sample": sample,
    }


def review_state(conn) -> dict:
    token = corpus_state(conn)
    pubs = list_publications(conn)
    for p in pubs:
        if p["status"] == "candidate":
            p["stale"] = p["corpus_state"] != token
    active = next((p for p in pubs if p["status"] == "active"), None)
    candidate = next((p for p in pubs if p["status"] == "candidate"), None)
    diff = None
    if active and candidate:
        diff = diff_versions(conn, active["version"], candidate["version"])
    stats = conn.execute(
        "SELECT"
        " (SELECT COUNT(*) FROM batches WHERE status='active') AS active_batches,"
        " (SELECT COUNT(*) FROM batches WHERE status='retracted') AS retracted_batches,"
        " (SELECT COUNT(*) FROM corrections) AS corrections"
    ).fetchone()
    return {
        "active": active, "candidate": candidate, "diff": diff,
        "publications": pubs, "batches": list_batches(conn),
        "stats": dict(stats), "corpus_state": token,
    }


# --------------------------------------------------------------------------
# Export (for the offline verifier)
# --------------------------------------------------------------------------

def bucket_bodies(conn, version: int) -> dict[str, str]:
    rows = conn.execute(
        "SELECT prefix, suffix, cnt FROM pub_buckets WHERE version = ?"
        " ORDER BY prefix, suffix",
        (version,),
    ).fetchall()
    bodies: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        bodies[r["prefix"]].append(f"{r['suffix']}:{r['cnt']}\n")
    return {p: "".join(lines) for p, lines in bodies.items()}


def manifest_for(conn, version: int) -> dict:
    pub = get_publication(conn, version)
    files = {
        p: hashlib.sha256(body.encode("ascii")).hexdigest()
        for p, body in bucket_bodies(conn, version).items()
    }
    return {
        "version": pub["version"],
        "hash_algo": "sha1",
        "prefix_len": pub["prefix_len"],
        "threshold_k": pub["threshold_k"],
        "created_at": pub["created_at"],
        "files": files,
    }


def export_version(conn, version: int, outdir: str) -> dict:
    """Write buckets/<PREFIX>.txt files + manifest.json, and self-check the
    recomputed manifest hash against the value stored at build time."""
    pub = get_publication(conn, version)
    bodies = bucket_bodies(conn, version)
    bdir = os.path.join(outdir, "buckets")
    os.makedirs(bdir, exist_ok=True)
    files = {}
    for prefix, body in sorted(bodies.items()):
        with open(os.path.join(bdir, f"{prefix}.txt"), "w", encoding="ascii") as fh:
            fh.write(body)
        files[prefix] = hashlib.sha256(body.encode("ascii")).hexdigest()
    manifest = {
        "version": pub["version"],
        "hash_algo": "sha1",
        "prefix_len": pub["prefix_len"],
        "threshold_k": pub["threshold_k"],
        "created_at": pub["created_at"],
        "files": files,
    }
    mhash = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
    if mhash != pub["manifest_sha256"]:
        raise CorpusError(
            f"manifest mismatch for version {version}: stored buckets do not"
            " match the hash recorded at build time")
    manifest["manifest_sha256"] = mhash
    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest
