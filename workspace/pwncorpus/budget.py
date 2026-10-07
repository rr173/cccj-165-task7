"""Per-caller daily privacy budget for anonymous corpus range queries.

A caller (tenant) holds a FIXED quota per UTC calendar day. Reading one prefix
costs exactly one unit, and the deduction and the corpus read happen in ONE
SQLite write transaction: a response body can never be returned without its
deduction being committed, nor a deduction committed without the body having
been read inside that same atomic transaction.

The budget table itself has exactly the six mandated fields:

    tenant_id      the caller identity (never derived from queried material)
    window_start   unix second of the UTC midnight that starts the window
    remaining      units left in the window (CHECK >= 0, never negative)
    spent          units deducted in the window
    frozen         deny-all flag for this (tenant, window)
    policy_revision which default-quota policy revision seeded this bucket

Everything else lives in separate tables: policy revisions (immutable; a new
revision only affects windows created afterwards), per-query tokens (only their
SHA-256 is stored), an append-only event stream (the audit source of truth),
top-up grants, an admin log, and idempotency records.

Isolation / ordering rules:

  * writers serialise through BEGIN IMMEDIATE and the deduction is a CONDITIONAL
    UPDATE (``... SET remaining = remaining - 1 WHERE remaining > 0 AND
    frozen = 0``), so parallel requests can never double-spend, bypass the cap
    or drive the balance negative;
  * a request presenting two tokens for two tenants is charged against the
    STRICTER tenant only (frozen beats exhausted beats lower remaining);
  * token revocation and consumption take the same write lock, so their order
    is simply first-committed-first-served;
  * freezing flips the tenant flag and the current bucket flag (plus an admin
    log row) in one transaction -- a crash leaves none or all of them;
  * windows roll at UTC midnight regardless of the host timezone;
  * policy changes add a revision row; old buckets keep their revision forever,
    so older audit material can never be recomputed under a newer policy.

The module never stores queried prefixes, suffixes, fingerprints or raw
passwords: budget events carry only tenant, window, result and timestamp.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from . import core, db, ed25519

WINDOW_SECONDS = 86_400
DEFAULT_DAILY_QUOTA = 100

META_BUDGET_ID = "budget_id"
META_GENESIS_PUB = "budget_genesis_pub"
META_INITIALISED_AT = "budget_initialised_at"

# One budget unit is spent only on these two outcomes: the caller was served a
# body or was served a definitive "bucket absent". Everything else is a failure
# that cost nothing.
RESULT_SERVED = "served"
RESULT_NOT_FOUND = "not_found"
REASON_EXHAUSTED = "budget_exhausted"
REASON_FROZEN = "frozen"
REASON_TOKEN_REVOKED = "token_revoked"
DEDUCTION_RESULTS = (RESULT_SERVED, RESULT_NOT_FOUND)
FAILURE_REASONS = (REASON_EXHAUSTED, REASON_FROZEN, REASON_TOKEN_REVOKED)
RESULT_CHECK = DEDUCTION_RESULTS + FAILURE_REASONS

_TENANT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

BUDGET_SCHEMA = """
CREATE TABLE IF NOT EXISTS budget_meta (
  key    TEXT PRIMARY KEY,
  value  TEXT NOT NULL
);

-- Immutable policy revisions. A new revision changes the DEFAULT daily quota
-- for windows created from then on; existing buckets keep their revision.
CREATE TABLE IF NOT EXISTS budget_policy (
  revision     INTEGER PRIMARY KEY AUTOINCREMENT,
  daily_quota  INTEGER NOT NULL CHECK (daily_quota >= 0),
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_tenants (
  tenant_id   TEXT PRIMARY KEY,
  created_at  TEXT NOT NULL,
  frozen      INTEGER NOT NULL DEFAULT 0 CHECK (frozen IN (0,1)),
  frozen_at   TEXT
);

-- Exactly six fields (two of which form the primary key).
CREATE TABLE IF NOT EXISTS budget_buckets (
  tenant_id        TEXT NOT NULL,
  window_start     INTEGER NOT NULL,
  remaining        INTEGER NOT NULL CHECK (remaining >= 0),
  spent            INTEGER NOT NULL CHECK (spent >= 0),
  frozen           INTEGER NOT NULL DEFAULT 0 CHECK (frozen IN (0,1)),
  policy_revision  INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, window_start)
);

-- Query tokens (distinct from the administrative tokens table in core):
-- only the hash is stored.
CREATE TABLE IF NOT EXISTS budget_tokens (
  token_sha256  TEXT PRIMARY KEY,
  token_id      TEXT NOT NULL UNIQUE,
  tenant_id     TEXT NOT NULL,
  label         TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
  revoked_at    TEXT
);

-- Append-only request outcomes. This is the source the audit export is summed
-- from; it deliberately contains NO prefix/suffix/fingerprint material.
CREATE TABLE IF NOT EXISTS budget_events (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT NOT NULL,
  window_start  INTEGER NOT NULL,
  result        TEXT NOT NULL
                CHECK (result IN ('served','not_found','budget_exhausted',
                                  'frozen','token_revoked')),
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_budget_events_window
  ON budget_events(tenant_id, window_start);

-- Administrative quota grants (top-ups), one row per granted amount.
CREATE TABLE IF NOT EXISTS budget_grants (
  seq              INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id        TEXT NOT NULL,
  window_start     INTEGER NOT NULL,
  amount           INTEGER NOT NULL CHECK (amount > 0),
  policy_revision  INTEGER NOT NULL,
  created_at       TEXT NOT NULL,
  note             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_budget_grants_window
  ON budget_grants(tenant_id, window_start);

-- Administrative actions, for internal accountability (never exported to the
-- isolated auditor; exports contain only tenant/window/counts/reasons).
CREATE TABLE IF NOT EXISTS budget_admin_log (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  action      TEXT NOT NULL,
  tenant_id   TEXT,
  detail      TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

-- Idempotent replays. A key is bound to a FULL request fingerprint: the
-- resource selector (prefix), the exact set of presented credentials and the
-- version condition. The FIRST outcome (status, version, body) is frozen
-- forever: any later request reusing the key with a different fingerprint is
-- rejected with 409 and changes nothing, while identical requests replay the
-- original outcome -- including its ORIGINAL publication version and the exact
-- first response body, regardless of later activation/retirement -- and spend
-- again nothing.
CREATE TABLE IF NOT EXISTS budget_idem (
  idem_key          TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL,
  window_start      INTEGER NOT NULL,
  result            TEXT NOT NULL,
  http_result       INTEGER NOT NULL,
  version           INTEGER,
  prefix            TEXT,
  body_snapshot     TEXT,
  request_sha256    TEXT NOT NULL,
  credentials_sha   TEXT NOT NULL,
  version_condition TEXT,
  created_at        TEXT NOT NULL
);
"""


class BudgetError(Exception):
    """Bad input or bad budget state. Messages never carry queried material."""


class BudgetAuth(BudgetError):
    """No usable presented token (unknown token / none presented)."""


class IdempotencyConflict(BudgetError):
    """An idempotency key was reused with a different request fingerprint
    (resource selector, credentials or version condition). The request is
    refused with 409 and a fixed body and mutates nothing."""


# Fixed conflict body -- constant across all fingerprint-mismatch cases so the
# response never reveals which component differed.
IDEMPOTENCY_CONFLICT = "idempotency_key_conflict"


class VersionConditionMismatch(BudgetError):
    """The client pinned a publication version (X-Corpus-Version request
    header) that is not the one being served. Refused with 409; nothing is
    charged and no outcome is stored."""


VERSION_MISMATCH = "version_mismatch"


# Canonical HTTP status for every storable outcome, in one place.
RESULT_HTTP = {
    RESULT_SERVED: 200,
    RESULT_NOT_FOUND: 404,
    REASON_EXHAUSTED: 429,
    REASON_FROZEN: 403,
    REASON_TOKEN_REVOKED: 403,
}


class NoActivePublication(BudgetError):
    """The corpus has no active version; nothing can be served (no charge)."""


class _Retry(Exception):
    """Internal: re-run the serialised consume attempt (lost a race)."""


# --------------------------------------------------------------------------
# Time: windows are UTC calendar days, never local time
# --------------------------------------------------------------------------

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def window_start_for(dt: datetime) -> int:
    """Unix second of the UTC midnight of the day containing ``dt``."""
    d = dt.astimezone(timezone.utc).date()
    return int(datetime(d.year, d.month, d.day, tzinfo=timezone.utc).timestamp())


def current_window_start(now: datetime | None = None) -> int:
    return window_start_for(now or utcnow())


def window_iso(window_start: int) -> str:
    return datetime.fromtimestamp(window_start, timezone.utc) \
        .isoformat(timespec="seconds")


def parse_window(value: str) -> int:
    """Accept ``YYYY-MM-DD`` (UTC) or an ISO timestamp; return window start."""
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value or ""):
            d = datetime.strptime(value, "%Y-%m-%d").date()
            return int(datetime(d.year, d.month, d.day,
                                tzinfo=timezone.utc).timestamp())
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return window_start_for(dt)
    except (ValueError, TypeError) as exc:
        raise BudgetError(f"invalid window {value!r}; use YYYY-MM-DD (UTC)") from exc


def seconds_until_next_window(window_start: int, now: datetime | None = None) -> int:
    now = now or utcnow()
    return max(0, window_start + WINDOW_SECONDS - int(now.timestamp()))


# --------------------------------------------------------------------------
# Keys (budget genesis key lives outside the DB, like the ledger genesis key)
# --------------------------------------------------------------------------

GENESIS_KEY_PERMS = 0o600


def write_genesis_key(path: str, seed: bytes, pub: bytes, budget_id: str) -> None:
    data = {"kind": "budget-genesis", "budget_id": budget_id,
            "seed_hex": seed.hex(), "pubkey_hex": pub.hex()}
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


def read_genesis_key(path: str) -> dict:
    try:
        with open(path, "r", encoding="ascii") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise BudgetError(f"key file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise BudgetError(f"unreadable key file: {exc}") from exc
    if data.get("kind") != "budget-genesis":
        raise BudgetError("the supplied key is not a budget genesis key")
    for f in ("seed_hex", "pubkey_hex", "budget_id"):
        if f not in data:
            raise BudgetError(f"key file missing {f}")
    try:
        seed = bytes.fromhex(data["seed_hex"])
        pub = bytes.fromhex(data["pubkey_hex"])
    except ValueError as exc:
        raise BudgetError("key file contains invalid hex") from exc
    if ed25519.public_from_seed(seed) != pub:
        raise BudgetError("key file seed does not match its public key")
    data["_seed"] = seed
    data["_pub"] = pub
    return data


# --------------------------------------------------------------------------
# Initialisation and policy
# --------------------------------------------------------------------------

def is_initialised(conn) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='budget_policy'"
    ).fetchone()
    if row is None:
        return False
    ready = conn.execute(
        "SELECT 1 FROM budget_meta WHERE key=?", (META_BUDGET_ID,)).fetchone() \
        is not None
    if ready:
        _migrate_idem_schema(conn)
    return ready


# Columns added when idempotency keys became bound to full request
# fingerprints. (Fresh databases get the full NOT NULL shape from
# BUDGET_SCHEMA; ALTER ADD COLUMN cannot carry NOT NULL without a default.)
_IDEM_ADDED_COLUMNS = (
    ("http_result", "INTEGER"),
    ("prefix", "TEXT"),
    ("body_snapshot", "TEXT"),
    ("request_sha256", "TEXT"),
    ("credentials_sha", "TEXT"),
    ("version_condition", "TEXT"),
)


def _migrate_idem_schema(conn) -> None:
    """Upgrade a pre-fingerprint budget_idem table in place.

    Rows written by older versions carry neither the bound resource selector
    nor the credential set, so their fingerprint can never be verified; they
    are dropped (they are replay hints only, never counters or events)."""
    existing = {r["name"] for r in
                conn.execute("PRAGMA table_info(budget_idem)")}
    if not existing or "request_sha256" in existing:
        return
    for name, decl in _IDEM_ADDED_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE budget_idem ADD COLUMN {name} {decl}")
    for result, code in RESULT_HTTP.items():
        conn.execute(
            "UPDATE budget_idem SET http_result=? WHERE result=? AND"
            " http_result IS NULL", (code, result))
    conn.execute("DELETE FROM budget_idem WHERE request_sha256 IS NULL")


def _require_init(conn) -> None:
    if not is_initialised(conn):
        raise BudgetError(
            "budget module is not initialised (run budget-init)")


def initialise(conn, key_path: str, daily_quota: int = DEFAULT_DAILY_QUOTA) -> dict:
    """Create budget tables, policy revision 1 and the budget genesis key.

    Idempotent only as schema bootstrap; initialising twice is an error, so an
    existing policy/ledger can never be silently reset.
    """
    if not isinstance(daily_quota, int) or isinstance(daily_quota, bool) \
            or daily_quota < 0:
        raise BudgetError("daily quota must be a non-negative integer")
    conn.executescript(BUDGET_SCHEMA)
    _migrate_idem_schema(conn)
    if conn.execute("SELECT 1 FROM budget_meta WHERE key=?",
                    (META_BUDGET_ID,)).fetchone() is not None:
        raise BudgetError("budget module is already initialised")
    if os.path.exists(key_path):
        raise BudgetError(f"key file already exists: {key_path}")

    budget_id = os.urandom(8).hex()
    seed, pub = ed25519.generate_key()
    now = core.utcnow()
    with db.write_tx(conn):
        conn.execute("INSERT INTO budget_meta(key,value) VALUES (?,?)",
                     (META_BUDGET_ID, budget_id))
        conn.execute("INSERT INTO budget_meta(key,value) VALUES (?,?)",
                     (META_GENESIS_PUB, pub.hex()))
        conn.execute("INSERT INTO budget_meta(key,value) VALUES (?,?)",
                     (META_INITIALISED_AT, now))
        conn.execute("INSERT INTO budget_policy(daily_quota, created_at)"
                     " VALUES (?,?)", (daily_quota, now))
        conn.execute("INSERT INTO budget_admin_log(action, tenant_id, detail,"
                     " created_at) VALUES ('init', NULL, ?, ?)",
                     (json.dumps({"daily_quota": daily_quota},
                                 sort_keys=True), now))
    write_genesis_key(key_path, seed, pub, budget_id)
    return {"budget_id": budget_id, "genesis_pub": pub.hex(),
            "daily_quota": daily_quota, "policy_revision": 1,
            "key_file": key_path}


def budget_id(conn) -> str:
    _require_init(conn)
    return conn.execute("SELECT value FROM budget_meta WHERE key=?",
                        (META_BUDGET_ID,)).fetchone()["value"]


def genesis_pub(conn) -> str:
    return conn.execute("SELECT value FROM budget_meta WHERE key=?",
                        (META_GENESIS_PUB,)).fetchone()["value"]


def current_policy(conn) -> dict:
    _require_init(conn)
    return conn.execute(
        "SELECT revision, daily_quota, created_at FROM budget_policy"
        " ORDER BY revision DESC LIMIT 1").fetchone()


def add_policy_revision(conn, daily_quota: int) -> dict:
    """Append a new default-quota policy. Existing buckets are untouched; only
    windows created afterwards seed from the new revision."""
    _require_init(conn)
    if not isinstance(daily_quota, int) or isinstance(daily_quota, bool) \
            or daily_quota < 0:
        raise BudgetError("daily quota must be a non-negative integer")
    cur = current_policy(conn)
    if daily_quota == cur["daily_quota"]:
        raise BudgetError(
            f"revision {cur['revision']} already sets daily quota"
            f" {daily_quota}; a new revision must change the quota")
    now = core.utcnow()
    with db.write_tx(conn):
        cur = conn.execute(
            "INSERT INTO budget_policy(daily_quota, created_at) VALUES (?,?)",
            (daily_quota, now))
        revision = cur.lastrowid
        conn.execute("INSERT INTO budget_admin_log(action, tenant_id, detail,"
                     " created_at) VALUES ('policy', NULL, ?, ?)",
                     (json.dumps({"revision": revision,
                                  "daily_quota": daily_quota}, sort_keys=True),
                      now))
    return {"policy_revision": revision, "daily_quota": daily_quota}


def policy_map(conn) -> dict:
    _require_init(conn)
    return {r["revision"]: {"revision": r["revision"],
                            "daily_quota": r["daily_quota"],
                            "created_at": r["created_at"]}
            for r in conn.execute(
                "SELECT revision, daily_quota, created_at FROM budget_policy"
                " ORDER BY revision")}


# --------------------------------------------------------------------------
# Tenants and query tokens
# --------------------------------------------------------------------------

def _validate_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not _TENANT_RE.fullmatch(tenant_id):
        raise BudgetError(
            "tenant_id is required (1-128 chars: letters, digits, _ . : -)")
    return tenant_id


def _get_tenant(conn, tenant_id: str):
    return conn.execute("SELECT * FROM budget_tenants WHERE tenant_id=?",
                        (tenant_id,)).fetchone()


def issue_token(conn, tenant_id: str, label: str) -> dict:
    """Register (if needed) a tenant and issue one query token. The plaintext
    token is shown exactly once; only its SHA-256 persists."""
    _require_init(conn)
    _validate_tenant(tenant_id)
    if not isinstance(label, str) or not label:
        raise BudgetError("token label is required")
    token = "pwb_" + secrets.token_urlsafe(32)
    token_id = "btid_" + secrets.token_hex(8)
    now = core.utcnow()
    with db.write_tx(conn):
        if _get_tenant(conn, tenant_id) is None:
            conn.execute(
                "INSERT INTO budget_tenants(tenant_id, created_at, frozen)"
                " VALUES (?, ?, 0)", (tenant_id, now))
            conn.execute(
                "INSERT INTO budget_admin_log(action, tenant_id, detail,"
                " created_at) VALUES ('tenant', ?, ?, ?)",
                (tenant_id, json.dumps({"label": label}, sort_keys=True), now))
        conn.execute(
            "INSERT INTO budget_tokens(token_sha256, token_id, tenant_id,"
            " label, created_at) VALUES (?,?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), token_id, tenant_id,
             label, now))
        conn.execute(
            "INSERT INTO budget_admin_log(action, tenant_id, detail,"
            " created_at) VALUES ('token', ?, ?, ?)",
            (tenant_id, json.dumps({"token_id": token_id, "label": label},
                                   sort_keys=True), now))
    return {"tenant_id": tenant_id, "token_id": token_id, "token": token,
            "label": label}


def revoke_token(conn, token_id: str) -> dict:
    """Revoke a query token. Idempotent; the state change and the admin log row
    commit together. Serialised against consumption via the write lock."""
    _require_init(conn)
    now = core.utcnow()
    with db.write_tx(conn):
        row = conn.execute(
            "SELECT token_id, tenant_id, revoked FROM budget_tokens"
            " WHERE token_id=?", (token_id,)).fetchone()
        if row is None:
            raise BudgetError("unknown token id")
        if row["revoked"]:
            return {"token_id": token_id, "tenant_id": row["tenant_id"],
                    "revoked": True, "already_revoked": True}
        conn.execute(
            "UPDATE budget_tokens SET revoked=1, revoked_at=? WHERE token_id=?",
            (now, token_id))
        conn.execute(
            "INSERT INTO budget_admin_log(action, tenant_id, detail,"
            " created_at) VALUES ('revoke', ?, ?, ?)",
            (row["tenant_id"],
             json.dumps({"token_id": token_id}, sort_keys=True), now))
    return {"token_id": token_id, "tenant_id": row["tenant_id"],
            "revoked": True, "already_revoked": False}


def _resolve_tokens(conn, raw_tokens: list[str]):
    """Return (tenants, revoked_tenant, cred_hashes) for the presented tokens.

    tenants: ordered distinct tenant ids backing valid, non-revoked tokens.
    An unrecognised token is an authentication failure (no tenant exists).
    A recognised-but-revoked token yields its tenant as a revocation failure.
    cred_hashes: the exact, de-duplicated, sorted set of SHA-256 hashes of the
    presented token strings (revoked ones included). It is the credential part
    of the request fingerprint, so reusing an idempotency key with a different
    token set is a conflict even when the tokens resolve to the same tenant.
    """
    cleaned = []
    for t in raw_tokens or []:
        t = (t or "").strip()
        if t:
            cleaned.append(t)
    if not cleaned:
        raise BudgetAuth("missing budget token")
    tenants, revoked, cred = [], [], set()
    for token in cleaned:
        h = hashlib.sha256(token.encode()).hexdigest()
        cred.add(h)
        row = conn.execute(
            "SELECT tenant_id, revoked FROM budget_tokens"
            " WHERE token_sha256=?", (h,)).fetchone()
        if row is None:
            raise BudgetAuth("invalid budget token")
        if row["revoked"]:
            revoked.append(row["tenant_id"])
        elif row["tenant_id"] not in set(tenants):
            tenants.append(row["tenant_id"])
    if revoked:
        # deterministic first revoked tenant (one failure event per request)
        return sorted(tenants), sorted(revoked)[0], sorted(cred)
    return sorted(tenants), None, sorted(cred)


def _request_fingerprint(prefix: str, cred_hashes,
                         version_condition: str | None) -> str:
    """Hash the request identity that an idempotency key is bound to.

    Components: the resource selector (validated prefix), the exact set of
    presented credentials, and the client's version condition. Canonical
    JSON keeps the representation stable across processes/restarts."""
    material = json.dumps(
        {"prefix": prefix, "credentials": sorted(cred_hashes),
         "version_condition": version_condition},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Freeze / unfreeze / top-up (admin side)
# --------------------------------------------------------------------------

def _set_frozen(conn, tenant_id: str, frozen: bool, now: datetime,
                probe=None) -> dict:
    tenant_id = _validate_tenant(tenant_id)
    now_s = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    ws = window_start_for(now)
    with db.write_tx(conn):
        t = _get_tenant(conn, tenant_id)
        if t is None:
            raise BudgetError("unknown tenant")
        if bool(t["frozen"]) == frozen:
            return {"tenant_id": tenant_id, "frozen": frozen, "changed": False}
        conn.execute(
            "UPDATE budget_tenants SET frozen=?, frozen_at=? WHERE tenant_id=?",
            (1 if frozen else 0, now_s if frozen else None, tenant_id))
        # keep the CURRENT window's bucket flag consistent with the tenant;
        # create it so the deny/allow state is observable immediately. Past
        # windows keep whatever flag they held and are never rewritten.
        _ensure_bucket_locked(conn, tenant_id, ws)
        conn.execute(
            "UPDATE budget_buckets SET frozen=? WHERE tenant_id=?"
            " AND window_start=?",
            (1 if frozen else 0, tenant_id, ws))
        if probe is not None:
            probe()  # test seam: crash between tenant flip and commit
        conn.execute(
            "INSERT INTO budget_admin_log(action, tenant_id, detail,"
            " created_at) VALUES (?, ?, ?, ?)",
            ("freeze" if frozen else "unfreeze", tenant_id,
             json.dumps({"window_start": ws}, sort_keys=True), now_s))
    return {"tenant_id": tenant_id, "frozen": frozen, "changed": True,
            "window_start": ws}


def freeze_tenant(conn, tenant_id: str, *, now: datetime | None = None,
                  probe=None) -> dict:
    _require_init(conn)
    return _set_frozen(conn, tenant_id, True, now or utcnow(), probe)


def unfreeze_tenant(conn, tenant_id: str, *, now: datetime | None = None) -> dict:
    _require_init(conn)
    return _set_frozen(conn, tenant_id, False, now or utcnow())


def topup(conn, tenant_id: str, amount: int, note: str = "", *,
          now: datetime | None = None) -> dict:
    """Add units to the tenant's CURRENT UTC window. Grant, bucket update and
    admin log commit together; the event stream is untouched."""
    _require_init(conn)
    tenant_id = _validate_tenant(tenant_id)
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise BudgetError("top-up amount must be a positive integer")
    if not isinstance(note, str) or len(note) > 500:
        raise BudgetError("note must be a string of at most 500 chars")
    now = now or utcnow()
    ws = window_start_for(now)
    now_s = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    with db.write_tx(conn):
        t = _get_tenant(conn, tenant_id)
        if t is None:
            raise BudgetError("unknown tenant")
        b = _ensure_bucket_locked(conn, tenant_id, ws)
        policy_rev = b["policy_revision"]
        cur = conn.execute(
            "UPDATE budget_buckets SET remaining = remaining + ?"
            " WHERE tenant_id=? AND window_start=?",
            (amount, tenant_id, ws))
        if cur.rowcount != 1:  # pragma: no cover - defensive
            raise BudgetError("budget bucket update failed")
        conn.execute(
            "INSERT INTO budget_grants(tenant_id, window_start, amount,"
            " policy_revision, created_at, note) VALUES (?,?,?,?,?,?)",
            (tenant_id, ws, amount, policy_rev, now_s, note))
        conn.execute(
            "INSERT INTO budget_admin_log(action, tenant_id, detail,"
            " created_at) VALUES ('topup', ?, ?, ?)",
            (tenant_id, json.dumps({"window_start": ws, "amount": amount,
                                    "note": note}, sort_keys=True), now_s))
        row = conn.execute(
            "SELECT remaining, spent, frozen, policy_revision FROM budget_buckets"
            " WHERE tenant_id=? AND window_start=?", (tenant_id, ws)).fetchone()
    return {"tenant_id": tenant_id, "window_start": ws, "amount": amount,
            "remaining": row["remaining"], "spent": row["spent"],
            "frozen": bool(row["frozen"]),
            "policy_revision": row["policy_revision"]}


# --------------------------------------------------------------------------
# Buckets
# --------------------------------------------------------------------------

def _ensure_bucket_locked(conn, tenant_id: str, ws: int):
    """Get-or-create the (tenant, window) bucket. Caller holds the write lock.
    A new bucket seeds from the CURRENT policy revision and inherits the
    tenant's frozen flag, so a frozen tenant stays frozen across day rollover
    without anyone touching past windows."""
    row = conn.execute(
        "SELECT * FROM budget_buckets WHERE tenant_id=? AND window_start=?",
        (tenant_id, ws)).fetchone()
    if row is not None:
        return row
    pol = conn.execute(
        "SELECT revision, daily_quota FROM budget_policy"
        " ORDER BY revision DESC LIMIT 1").fetchone()
    t = _get_tenant(conn, tenant_id)
    frozen = t["frozen"] if t is not None else 0
    conn.execute(
        "INSERT INTO budget_buckets(tenant_id, window_start, remaining, spent,"
        " frozen, policy_revision) VALUES (?,?,?,?,?,?)",
        (tenant_id, ws, pol["daily_quota"], 0, frozen, pol["revision"]))
    return conn.execute(
        "SELECT * FROM budget_buckets WHERE tenant_id=? AND window_start=?",
        (tenant_id, ws)).fetchone()


def get_bucket(conn, tenant_id: str, ws: int):
    _require_init(conn)
    return conn.execute(
        "SELECT * FROM budget_buckets WHERE tenant_id=? AND window_start=?",
        (tenant_id, ws)).fetchone()


# --------------------------------------------------------------------------
# Consumption: the atomic heart of the module
# --------------------------------------------------------------------------

def _validate_prefix(prefix: str, prefix_len: int) -> str:
    p = (prefix or "").strip().upper()
    if not (len(p) == prefix_len
            and all(c in "0123456789ABCDEF" for c in p)):
        raise BudgetError(f"prefix must be exactly {prefix_len} hex characters")
    return p


def _governing(candidates: list[dict]) -> dict:
    """Strictest tenant: frozen beats exhausted beats least remaining.
    Deterministic tenant_id tie-break."""
    def rank(b):
        if b["frozen"]:
            state = 0
        elif b["remaining"] <= 0:
            state = 1
        else:
            state = 2
        return (state, b["remaining"], b["tenant_id"])
    return min(candidates, key=rank)


def consume(conn, raw_tokens: list[str], prefix: str, *,
            idem_key: str | None = None, now: datetime | None = None,
            prefix_len: int | None = None, crash_after_deduct=None,
            expected_version: int | None = None) -> dict:
    """Atomically check budget, deduct one unit and read the corpus body.

    Returns a result dict:
      {status: 'allowed'|'denied'|'replay', reason?, tenant_id, window_start,
       remaining_before, remaining_after, spent, policy_revision, version,
       body ('' allowed/404 -> ''), http_result}

    Denial reasons: budget_exhausted, frozen, token_revoked. Unknown tokens
    raise BudgetAuth. No active publication raises NoActivePublication (nothing
    is charged in either case).

    ``expected_version`` pins the request to a publication version: the request
    is refused with VersionConditionMismatch (HTTP 409) when a DIFFERENT
    version is active, without charging or recording anything.

    An idempotency key binds a full request fingerprint (prefix, presented
    credentials, version condition). A repeated identical request replays the
    original, frozen outcome (including its original version body); a repeated
    key with a different fingerprint raises IdempotencyConflict (HTTP 409) and
    leaves counters, the event sequence and every stored row untouched.

    ``crash_after_deduct`` is a test seam: invoked inside the write transaction
    after the deduction and the event row are written but before COMMIT, letting
    a test force a crash that must roll the deduction fully back."""
    _require_init(conn)
    if prefix_len is None:
        prefix_len = core.PREFIX_LEN  # read at call time, like every other module
    now = now or utcnow()
    ws = window_start_for(now)
    now_s = now.astimezone(timezone.utc).isoformat(timespec="seconds")

    for attempt in range(30):
        try:
            with db.write_tx(conn):
                return _consume_locked(
                    conn, raw_tokens, prefix, prefix_len, ws, now_s, idem_key,
                    crash_after_deduct=crash_after_deduct,
                    expected_version=expected_version)
        except _Retry:
            time.sleep(0.005 * (attempt + 1))
            continue
        except sqlite3.IntegrityError as exc:
            # Lost an idempotency-key insert race: the winner's record is now
            # visible; re-run and return its stored outcome.
            if idem_key is not None and _idem_exists(conn, idem_key):
                continue
            raise BudgetError(f"budget write conflict ({exc})") from exc
    raise BudgetError("budget consume kept losing a parallel race")  # pragma: no cover


def _idem_exists(conn, key: str) -> bool:
    return conn.execute("SELECT 1 FROM budget_idem WHERE idem_key=?",
                        (key,)).fetchone() is not None


def _consume_locked(conn, raw_tokens, prefix, prefix_len, ws, now_s, idem_key,
                    crash_after_deduct=None, expected_version=None):
    # Authentication precedes prefix semantics: an invalid token must not learn
    # whether a prefix is well-formed; _resolve_tokens raises on unknown tokens.
    tenants, revoked_tenant, cred_hashes = _resolve_tokens(conn, raw_tokens)
    prefix = _validate_prefix(prefix, prefix_len)
    version_condition = _normalise_version_condition(expected_version)
    fingerprint = _request_fingerprint(prefix, cred_hashes, version_condition)

    if revoked_tenant is not None:
        b = _ensure_bucket_locked(conn, revoked_tenant, ws)
        conn.execute(
            "INSERT INTO budget_events(tenant_id, window_start, result,"
            " created_at) VALUES (?,?,?,?)",
            (revoked_tenant, ws, REASON_TOKEN_REVOKED, now_s))
        return _denied(REASON_TOKEN_REVOKED, revoked_tenant, ws, b,
                       http_result=403)

    # Idempotent replay / fingerprint conflict: decided BEFORE any deduction,
    # bucket creation or event write, so a mismatched reuse can never charge,
    # never emits an event and never creates storage.
    if idem_key:
        prior = conn.execute(
            "SELECT * FROM budget_idem WHERE idem_key=?", (idem_key,)).fetchone()
        if prior is not None:
            # Another tenant's key is just one more fingerprint mismatch.
            if prior["tenant_id"] not in tenants \
                    or prior["request_sha256"] != fingerprint:
                raise IdempotencyConflict(IDEMPOTENCY_CONFLICT)
            return _replay_outcome(conn, prior)

    buckets = [_ensure_bucket_locked(conn, tid, ws) for tid in tenants]
    candidates = [
        {"tenant_id": b["tenant_id"], "remaining": b["remaining"],
         "spent": b["spent"], "frozen": bool(b["frozen"]),
         "policy_revision": b["policy_revision"]}
        for b in buckets
    ]
    gov = _governing(candidates)
    gtid = gov["tenant_id"]

    # A 503 costs nothing and is decided before any deduction.
    version, body = _read_corpus(conn, prefix)
    if version is None:
        raise NoActivePublication("no active publication")

    # A pinned version condition that does not match the served snapshot is a
    # conflict: no deduction, no event, no stored outcome.
    if version_condition is not None and int(version_condition) != version:
        raise VersionConditionMismatch(VERSION_MISMATCH)

    if gov["frozen"]:
        conn.execute(
            "INSERT INTO budget_events(tenant_id, window_start, result,"
            " created_at) VALUES (?,?,?,?)",
            (gtid, ws, REASON_FROZEN, now_s))
        denied = _denied(REASON_FROZEN, gtid, ws,
                         _bucket_row(conn, gtid, ws), http_result=403)
        _store_idem(conn, idem_key, gtid, ws, REASON_FROZEN, version, prefix,
                    None, fingerprint, cred_hashes, version_condition, now_s)
        return denied
    if gov["remaining"] <= 0:
        conn.execute(
            "INSERT INTO budget_events(tenant_id, window_start, result,"
            " created_at) VALUES (?,?,?,?)",
            (gtid, ws, REASON_EXHAUSTED, now_s))
        denied = _denied(REASON_EXHAUSTED, gtid, ws,
                         _bucket_row(conn, gtid, ws), http_result=429)
        _store_idem(conn, idem_key, gtid, ws, REASON_EXHAUSTED, version, prefix,
                    None, fingerprint, cred_hashes, version_condition, now_s)
        return denied

    before = gov["remaining"]
    cur = conn.execute(
        "UPDATE budget_buckets SET remaining = remaining - 1,"
        " spent = spent + 1 WHERE tenant_id=? AND window_start=?"
        " AND remaining > 0 AND frozen = 0",
        (gtid, ws))
    if cur.rowcount != 1:
        # Lost a race against an admin freeze / parallel spend despite the
        # serialised lock: classify honestly and record the failure.
        fresh = _bucket_row(conn, gtid, ws)
        reason = REASON_FROZEN if fresh["frozen"] else REASON_EXHAUSTED
        conn.execute(
            "INSERT INTO budget_events(tenant_id, window_start, result,"
            " created_at) VALUES (?,?,?,?)",
            (gtid, ws, reason, now_s))
        denied = _denied(reason, gtid, ws, fresh,
                         http_result=403 if fresh["frozen"] else 429)
        _store_idem(conn, idem_key, gtid, ws, reason, version, prefix, None,
                    fingerprint, cred_hashes, version_condition, now_s)
        return denied

    result = RESULT_SERVED if body is not None else RESULT_NOT_FOUND
    conn.execute(
        "INSERT INTO budget_events(tenant_id, window_start, result,"
        " created_at) VALUES (?,?,?,?)",
        (gtid, ws, result, now_s))
    if crash_after_deduct is not None:
        crash_after_deduct(conn)  # test seam: force rollback post-deduction
    _store_idem(conn, idem_key, gtid, ws, result, version, prefix,
                body if body is not None else None,
                fingerprint, cred_hashes, version_condition, now_s)
    after = _bucket_row(conn, gtid, ws)
    return {"status": "allowed", "reason": None, "tenant_id": gtid,
            "window_start": ws, "remaining_before": before,
            "remaining_after": after["remaining"], "spent": after["spent"],
            "policy_revision": after["policy_revision"], "frozen": False,
            "version": version, "body": body if body is not None else "",
            "http_result": 200 if body is not None else 404,
            "stored_result": result}


def _normalise_version_condition(expected_version) -> str | None:
    """Canonical client version condition (``X-Corpus-Version`` request
    header). None means unpinned; otherwise it is a positive integer rendered
    canonically, so the fingerprint is identical across equivalent inputs."""
    if expected_version is None:
        return None
    if isinstance(expected_version, bool) or not isinstance(expected_version, int) \
            or expected_version <= 0:
        raise BudgetError("version condition must be a positive integer")
    return str(expected_version)


def _store_idem(conn, idem_key, tenant_id, ws, result, version, prefix,
                body_snapshot, fingerprint, cred_hashes, version_condition,
                now_s):
    """Persist the FIRST outcome for an idempotency key, frozen forever.
    A parallel writer winning the PRIMARY KEY race must redo the whole request
    as a replay (its deduction/event already rolled back with the retry)."""
    if not idem_key:
        return
    try:
        conn.execute(
            "INSERT INTO budget_idem(idem_key, tenant_id, window_start,"
            " result, http_result, version, prefix, body_snapshot,"
            " request_sha256, credentials_sha, version_condition, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (idem_key, tenant_id, ws, result, RESULT_HTTP[result], version,
             prefix, body_snapshot, fingerprint, _credentials_sha(cred_hashes),
             version_condition, now_s))
    except sqlite3.IntegrityError:
        raise _Retry()


def _credentials_sha(cred_hashes) -> str:
    return hashlib.sha256(json.dumps(
        sorted(cred_hashes), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _replay_outcome(conn, prior) -> dict:
    """Reconstruct the FIRST response for a stored idempotency key.

    Nothing is charged and no event is written. The body is the exact frozen
    snapshot of the FIRST response; a later activation/retirement can neither
    change it nor expose the NEW resource. Denial outcomes replay with their
    original status code and no body. Current budget headers describe the
    caller's live bucket, exactly like a fresh denial would."""
    b = _bucket_row(conn, prior["tenant_id"], prior["window_start"])
    result = prior["result"]
    http_result = prior["http_result"] if prior["http_result"] is not None \
        else RESULT_HTTP[result]
    body_out = prior["body_snapshot"] if result == RESULT_SERVED else ""
    return {
        "status": "replay", "reason": None,
        "tenant_id": prior["tenant_id"],
        "window_start": prior["window_start"],
        "remaining_before": b["remaining"],
        "remaining_after": b["remaining"], "spent": b["spent"],
        "policy_revision": b["policy_revision"],
        "version": prior["version"],
        "body": body_out or "",
        "http_result": http_result,
        "stored_result": result,
    }


def _bucket_row(conn, tenant_id: str, ws: int):
    return conn.execute(
        "SELECT * FROM budget_buckets WHERE tenant_id=? AND window_start=?",
        (tenant_id, ws)).fetchone()


def _denied(reason: str, tenant_id: str, ws: int, b, http_result: int) -> dict:
    return {"status": "denied", "reason": reason, "tenant_id": tenant_id,
            "window_start": ws, "remaining_before": b["remaining"],
            "remaining_after": b["remaining"], "spent": b["spent"],
            "policy_revision": b["policy_revision"], "frozen": bool(b["frozen"]),
            "version": None, "body": None, "http_result": http_result}


def _read_corpus(conn, prefix: str):
    """Read the active publication pointer and the prefix rows. MUST run inside
    the caller's transaction so the body and the budget deduction share one
    atomic snapshot. Returns (None, None) when no publication is active."""
    v = core.current_version(conn)
    if v is None:
        return None, None
    rows = conn.execute(
        "SELECT suffix, cnt FROM pub_buckets WHERE version = ? AND prefix = ?"
        " ORDER BY suffix",
        (v, prefix)).fetchall()
    body = "".join(f"{r['suffix']}:{r['cnt']}\n" for r in rows)
    return v, (body if rows else None)


# --------------------------------------------------------------------------
# Audit aggregation (the ONLY source of the export numbers; the admin status
# endpoint and the export share it, so their counts necessarily agree)
# --------------------------------------------------------------------------

def last_event_seq(conn) -> int:
    r = conn.execute("SELECT COALESCE(MAX(seq),0) AS m FROM budget_events") \
        .fetchone()
    return int(r["m"])


def window_rows(conn, as_of: datetime | None = None) -> list[dict]:
    """Per (tenant, window): deductions, failure counts and grants.

    Only rows for windows that have a bucket are produced (every event and
    grant creates one). ``as_of`` excludes events/grants timestamped after the
    cutoff (used for point-in-time audit exports).
    """
    _require_init(conn)
    cutoff_s = None
    if as_of is not None:
        cutoff_s = as_of.astimezone(timezone.utc).isoformat(timespec="seconds")

    def windows():
        rows = conn.execute(
            "SELECT DISTINCT tenant_id, window_start FROM budget_buckets"
            " ORDER BY tenant_id, window_start").fetchall()
        return [(r["tenant_id"], r["window_start"]) for r in rows]

    out = []
    for tid, ws in windows():
        if cutoff_s is None:
            ev = conn.execute(
                "SELECT result, COUNT(*) AS c FROM budget_events"
                " WHERE tenant_id=? AND window_start=? GROUP BY result",
                (tid, ws)).fetchall()
            gr = conn.execute(
                "SELECT amount, created_at FROM budget_grants"
                " WHERE tenant_id=? AND window_start=? ORDER BY seq",
                (tid, ws)).fetchall()
        else:
            ev = conn.execute(
                "SELECT result, COUNT(*) AS c FROM budget_events"
                " WHERE tenant_id=? AND window_start=? AND created_at <= ?"
                " GROUP BY result", (tid, ws, cutoff_s)).fetchall()
            gr = conn.execute(
                "SELECT amount, created_at FROM budget_grants"
                " WHERE tenant_id=? AND window_start=? AND created_at <= ?"
                " ORDER BY seq", (tid, ws, cutoff_s)).fetchall()
        counts = {r["result"]: r["c"] for r in ev}
        deductions = sum(counts.get(k, 0) for k in DEDUCTION_RESULTS)
        failures = [{"reason": reason, "count": counts[reason]}
                    for reason in FAILURE_REASONS if counts.get(reason)]
        grants = [{"amount": r["amount"], "created_at": r["created_at"]}
                  for r in gr]
        b = conn.execute(
            "SELECT policy_revision, remaining, spent, frozen FROM budget_buckets"
            " WHERE tenant_id=? AND window_start=?", (tid, ws)).fetchone()
        out.append({
            "tenant_id": tid, "window_start": ws,
            "policy_revision": b["policy_revision"],
            "deductions": deductions, "failures": failures, "grants": grants,
            # live snapshot fields, used by the admin endpoint and the
            # auditor's consistency cross-check; stripped from exports:
            "_remaining": b["remaining"], "_spent": b["spent"],
            "_frozen": bool(b["frozen"]),
        })
    return out


def verify_internal_consistency(conn) -> None:
    """Cross-check the live bucket table against the append-only event stream
    and the grant journal. Any discrepancy means out-of-band storage tampering
    and makes the auditor refuse to export."""
    _require_init(conn)
    pol = {int(k): v["daily_quota"] for k, v in policy_map(conn).items()}
    rows = window_rows(conn)
    for w in rows:
        tid, ws = w["tenant_id"], w["window_start"]
        if w["policy_revision"] not in pol:
            raise BudgetError(
                f"bucket ({tid},{ws}) refers to missing policy revision"
                f" {w['policy_revision']}")
        failure_events = sum(f["count"] for f in w["failures"])
        all_events = conn.execute(
            "SELECT COUNT(*) AS c FROM budget_events"
            " WHERE tenant_id=? AND window_start=?", (tid, ws)).fetchone()["c"]
        if all_events != w["deductions"] + failure_events:
            raise BudgetError(
                f"event stream for ({tid},{ws}) contains unknown result rows")
        if w["_spent"] != w["deductions"]:
            raise BudgetError(
                f"bucket spent for ({tid},{ws}) = {w['_spent']} disagrees with"
                f" {w['deductions']} deduction events (storage tampered)")
        granted = sum(g["amount"] for g in w["grants"])
        expected_remaining = pol[w["policy_revision"]] + granted - w["deductions"]
        if expected_remaining < 0:
            raise BudgetError(
                f"recomputed balance for ({tid},{ws}) is negative")
        if w["_remaining"] != expected_remaining:
            raise BudgetError(
                f"bucket remaining for ({tid},{ws}) = {w['_remaining']}"
                f" disagrees with recomputed {expected_remaining}"
                " (storage tampered)")
        t = _get_tenant(conn, tid)
        cur_ws = current_window_start()
        if ws == cur_ws and t is not None and w["_frozen"] != bool(t["frozen"]):
            raise BudgetError(
                f"current-window frozen flag for {tid} disagrees with the"
                " tenant record (half-applied freeze)")


def admin_status(conn, tenant_id: str | None = None,
                 ws: int | None = None) -> dict:
    """Admin counts per (tenant, window), plus live bucket fields. The count
    columns are computed by the exact same aggregation the signed export uses,
    so admin totals and export totals add up item by item."""
    _require_init(conn)
    windows = []
    for w in window_rows(conn):
        if tenant_id is not None and w["tenant_id"] != tenant_id:
            continue
        if ws is not None and w["window_start"] != ws:
            continue
        windows.append({
            "tenant_id": w["tenant_id"],
            "window_start": window_iso(w["window_start"]),
            "policy_revision": w["policy_revision"],
            "deductions": w["deductions"],
            "failures": w["failures"],
            "grants_total": sum(g["amount"] for g in w["grants"]),
            "remaining": w["_remaining"], "spent": w["_spent"],
            "frozen": w["_frozen"],
        })
    tenants = [dict(r) for r in conn.execute(
        "SELECT tenant_id, created_at, frozen, frozen_at FROM budget_tenants"
        " ORDER BY tenant_id").fetchall()]
    for t in tenants:
        t["frozen"] = bool(t["frozen"])
    return {"windows": windows, "tenants": tenants,
            "policy": dict(current_policy(conn))}
