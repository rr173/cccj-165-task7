"""SQLite storage layer.

WAL mode + one connection per caller (thread). Writers serialise through
BEGIN IMMEDIATE with a busy timeout plus a small retry loop, so concurrent
ingestion is safe. Readers get snapshot isolation, which is what guarantees
that a range query never mixes two publication versions.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
  batch_id          TEXT PRIMARY KEY,
  source            TEXT NOT NULL,
  idem_key          TEXT NOT NULL UNIQUE,          -- client key or content hash
  content_sha256    TEXT NOT NULL,                 -- sha256 of canonical item list
  item_count        INTEGER NOT NULL,              -- distinct fingerprints
  occurrence_count  INTEGER NOT NULL,              -- total occurrences
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retracted')),
  created_at        TEXT NOT NULL,
  retracted_at      TEXT
);
-- Same content from the same source is the same batch, whatever the client key.
CREATE UNIQUE INDEX IF NOT EXISTS idx_batches_source_content
  ON batches(source, content_sha256);

CREATE TABLE IF NOT EXISTS batch_items (
  batch_id  TEXT NOT NULL REFERENCES batches(batch_id),
  hash_hex  TEXT NOT NULL,                          -- full SHA-1 hex, uppercase
  cnt       INTEGER NOT NULL CHECK (cnt >= 1),
  PRIMARY KEY (batch_id, hash_hex)
);

CREATE TABLE IF NOT EXISTS corrections (
  batch_id    TEXT NOT NULL REFERENCES batches(batch_id),
  hash_hex    TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  PRIMARY KEY (batch_id, hash_hex)
);

CREATE TABLE IF NOT EXISTS publications (
  version                  INTEGER PRIMARY KEY AUTOINCREMENT,
  threshold_k              INTEGER NOT NULL,        -- min bucket set size for THIS version
  prefix_len               INTEGER NOT NULL,        -- fixed prefix length for THIS version
  status                   TEXT NOT NULL CHECK (status IN ('candidate','active','retired')),
  created_at               TEXT NOT NULL,
  activated_at             TEXT,
  retired_at               TEXT,
  bucket_count             INTEGER NOT NULL,
  suffix_count             INTEGER NOT NULL,
  suppressed_bucket_count  INTEGER NOT NULL DEFAULT 0,
  corpus_sha256            TEXT NOT NULL,           -- hash of the full active corpus snapshot
  corpus_state             INTEGER NOT NULL DEFAULT 0,  -- source-state token at build/refresh time
  manifest_sha256          TEXT NOT NULL            -- hash of the canonical manifest
);

CREATE TABLE IF NOT EXISTS pub_buckets (
  version  INTEGER NOT NULL REFERENCES publications(version),
  prefix   TEXT NOT NULL,
  suffix   TEXT NOT NULL,
  cnt      INTEGER NOT NULL CHECK (cnt >= 1),
  PRIMARY KEY (version, prefix, suffix)
);
CREATE INDEX IF NOT EXISTS idx_pub_buckets_query ON pub_buckets(version, prefix);

CREATE TABLE IF NOT EXISTS meta (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token_sha256  TEXT PRIMARY KEY,                   -- only the hash of the token is stored
  label         TEXT NOT NULL,
  scopes        TEXT NOT NULL,                      -- comma separated: ingest,retract,publish
  created_at    TEXT NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Idempotent schema upgrades for databases created by older versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(publications)")}
    if not cols:
        return  # fresh database; init() applies the full schema next
    if "corpus_state" not in cols:
        try:
            conn.execute("ALTER TABLE publications ADD COLUMN"
                         " corpus_state INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError as exc:  # another connection beat us to it
            if "duplicate column" not in str(exc).lower():
                raise


def init(path: str) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def write_tx(conn: sqlite3.Connection, retries: int = 40):
    """Exclusive write transaction with lock retry (concurrent ingesters)."""
    for attempt in range(retries):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() and attempt < retries - 1:
                time.sleep(0.02 * (attempt + 1))
                continue
            raise
    try:
        yield
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
