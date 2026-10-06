"""Offline privacy-budget verifier (fully isolated process).

Like ``pwncorpus.attest`` for the provenance ledger, this module NEVER imports
sqlite3 and never opens the corpus database. Given only a signed budget export
produced by ``pwncorpus.budgetaudit`` it can:

  * verify the export structurally and cryptographically;
  * recompute every daily balance from the embedded policy + grants + deduction
    counts, so the file remains auditable after it has left the service;
  * decide whether an individual request (the n-th deduction of a tenant in a
    UTC window) was within the budget.

Privacy contract: an export contains ONLY tenant identifiers, UTC windows,
deduction counts, failure reasons and grant amounts. It contains no queried
prefix, no suffix, no fingerprint and no token/secret material. The verifier
rejects any record carrying an unexpected key, so a future exporter cannot
silently smuggle sensitive fields into a file an auditor trusts.

Export document (single JSON file):

    format, budget_id, genesis_pub, created_at, as_of (or null),
    last_event_seq, policies, windows, previous_export_sha256 (or null)
    export_sha256  : sha256 over the canonical form of the fields above
    signature      : budget genesis key Ed25519 signature over export_sha256

A policy revision binds (revision, daily_quota); a window record binds
(tenant_id, window, policy_revision, deductions, failures, grants). The daily
balance is recomputable from those alone:

    remaining = policy[revision].daily_quota + sum(grants.amount) - deductions

A window with a negative recomputed balance is a forged/inconsistent export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from . import ed25519

EXPORT_FORMAT = "pwncorpus-budget/1"

SIGNED_FIELDS = ("format", "budget_id", "genesis_pub", "created_at", "as_of",
                 "last_event_seq", "policies", "windows",
                 "previous_export_sha256")

POLICY_KEYS = {"revision", "daily_quota", "created_at"}
GRANT_KEYS = {"amount", "created_at"}
FAILURE_KEYS = {"reason", "count"}
WINDOW_KEYS = {"tenant_id", "window", "policy_revision", "deductions",
               "failures", "grants"}
ALLOWED_FAILURE_REASONS = {"budget_exhausted", "frozen", "token_revoked"}


class BudgetVerifyError(Exception):
    """The export is malformed, tampered or untrusted."""


# --------------------------------------------------------------------------
# Canonical serialisation / hashing (identical bytes on the audit side)
# --------------------------------------------------------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def export_self_hash(doc: dict) -> str:
    return hashlib.sha256(
        canonical({f: doc[f] for f in SIGNED_FIELDS}).encode("utf-8")
    ).hexdigest()


def _valid_hex(value, length: int) -> bool:
    return isinstance(value, str) and len(value) == length \
        and all(c in "0123456789abcdef" for c in value.lower()) \
        and value == value.lower()


def parse_iso_date(value: str) -> str:
    """Normalise a YYYY-MM-DD day (UTC) or ISO timestamp to the window label
    'YYYY-MM-DDT00:00:00+00:00' used inside exports."""
    try:
        if isinstance(value, str) and len(value) == 10 \
                and value[4] == "-" and value[7] == "-":
            datetime.strptime(value, "%Y-%m-%d")
            return f"{value}T00:00:00+00:00"
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise BudgetVerifyError(
            "window must be YYYY-MM-DD (UTC) or an ISO 8601 timestamp") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    d = dt.date()
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc) \
        .isoformat(timespec="seconds")


def load_export(path: str) -> dict:
    if not os.path.isfile(path):
        raise BudgetVerifyError(f"export file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BudgetVerifyError(f"export unreadable or not JSON: {exc}") from exc


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def _check_str(name, value) -> None:
    if not isinstance(value, str) or not value:
        raise BudgetVerifyError(f"export field {name!r} must be a string")


def verify_export(doc: dict, trusted_genesis_pub: str | None = None) -> dict:
    """Full offline verification. Returns the re-derived balance ledger.

    Checks, in order: structure/whitelist, self hash, genesis signature,
    policy completeness, per-window arithmetic and non-negativity.
    """
    if not isinstance(doc, dict):
        raise BudgetVerifyError("export is not a JSON object")
    missing = [f for f in SIGNED_FIELDS + ("export_sha256", "signature")
               if f not in doc]
    if missing:
        raise BudgetVerifyError("export missing fields: " + ", ".join(missing))
    extra = set(doc) - set(SIGNED_FIELDS) - {"export_sha256", "signature"}
    if extra:
        raise BudgetVerifyError("export carries unexpected fields: "
                                + ", ".join(sorted(extra)))
    if doc["format"] != EXPORT_FORMAT:
        raise BudgetVerifyError(f"unsupported export format: {doc['format']!r}")
    if not _valid_hex(doc["budget_id"], 16):
        raise BudgetVerifyError("invalid budget_id")
    if not _valid_hex(doc["genesis_pub"], 64):
        raise BudgetVerifyError("invalid genesis_pub")
    if trusted_genesis_pub is not None \
            and doc["genesis_pub"] != trusted_genesis_pub:
        raise BudgetVerifyError(
            "export genesis key differs from the pinned budget key")
    _check_str("created_at", doc["created_at"])
    if doc["as_of"] is not None:
        _check_str("as_of", doc["as_of"])
    if not isinstance(doc["last_event_seq"], int) \
            or isinstance(doc["last_event_seq"], bool) \
            or doc["last_event_seq"] < 0:
        raise BudgetVerifyError("invalid last_event_seq")
    if doc["previous_export_sha256"] is not None \
            and not _valid_hex(doc["previous_export_sha256"], 64):
        raise BudgetVerifyError("invalid previous_export_sha256")

    if export_self_hash(doc) != doc["export_sha256"]:
        raise BudgetVerifyError(
            "export_sha256 does not match recomputed hash (export altered)")
    try:
        ed25519.verify(bytes.fromhex(doc["genesis_pub"]),
                       bytes.fromhex(doc["export_sha256"]),
                       bytes.fromhex(doc["signature"]))
    except ed25519.BadSignature as exc:
        raise BudgetVerifyError(
            "genesis signature over the export is invalid") from exc

    policies = _verify_policies(doc["policies"])
    windows = _verify_windows(doc["windows"], policies)
    return {"budget_id": doc["budget_id"], "policies": policies,
            "windows": windows, "created_at": doc["created_at"],
            "as_of": doc["as_of"], "last_event_seq": doc["last_event_seq"]}


def _verify_policies(raw) -> dict:
    if not isinstance(raw, list) or not raw:
        raise BudgetVerifyError("policies must be a non-empty list")
    out = {}
    revisions = []
    for p in raw:
        if not isinstance(p, dict) or set(p) != POLICY_KEYS:
            raise BudgetVerifyError(
                "a policy record must contain exactly "
                + ", ".join(sorted(POLICY_KEYS)))
        rev = p["revision"]
        if not isinstance(rev, int) or isinstance(rev, bool) or rev < 1:
            raise BudgetVerifyError("policy revision must be a positive int")
        q = p["daily_quota"]
        if not isinstance(q, int) or isinstance(q, bool) or q < 0:
            raise BudgetVerifyError("policy daily_quota must be >= 0")
        _check_str("policy.created_at", p["created_at"])
        if rev in out:
            raise BudgetVerifyError(f"duplicate policy revision {rev}")
        out[rev] = q
        revisions.append(rev)
    if revisions != sorted(revisions) or revisions[0] != 1 \
            or revisions != list(range(1, len(revisions) + 1)):
        raise BudgetVerifyError(
            "policy revisions must be a gapless sequence starting at 1")
    return out


def _verify_windows(raw, policies: dict) -> dict:
    if not isinstance(raw, list):
        raise BudgetVerifyError("windows must be a list")
    out = {}
    seen = set()
    for w in raw:
        if not isinstance(w, dict) or set(w) != WINDOW_KEYS:
            raise BudgetVerifyError(
                "a window record must contain exactly "
                + ", ".join(sorted(WINDOW_KEYS)))
        tenant = w["tenant_id"]
        _check_str("window.tenant_id", tenant)
        window = w["window"]
        _check_str("window.window", window)
        try:  # must be a UTC midnight label
            dt = datetime.fromisoformat(window)
        except ValueError as exc:
            raise BudgetVerifyError("invalid window label") from exc
        if dt.tzinfo is None or dt.astimezone(timezone.utc) != dt \
                or (dt.hour, dt.minute, dt.second) != (0, 0, 0):
            raise BudgetVerifyError("window label must be a UTC midnight")
        rev = w["policy_revision"]
        if not isinstance(rev, int) or rev not in policies:
            raise BudgetVerifyError(
                f"window {tenant}/{window} refers to unknown policy"
                f" revision {rev} (a newer policy cannot rewrite old audit"
                " material)")
        ded = w["deductions"]
        if not isinstance(ded, int) or isinstance(ded, bool) or ded < 0:
            raise BudgetVerifyError("deductions must be a non-negative int")
        failures = w["failures"]
        if not isinstance(failures, list):
            raise BudgetVerifyError("failures must be a list")
        fail_total = 0
        reasons = set()
        for f in failures:
            if not isinstance(f, dict) or set(f) != FAILURE_KEYS:
                raise BudgetVerifyError(
                    "a failure record must contain exactly reason and count")
            if f["reason"] not in ALLOWED_FAILURE_REASONS:
                raise BudgetVerifyError(
                    f"unknown failure reason {f['reason']!r}")
            if f["reason"] in reasons:
                raise BudgetVerifyError(
                    f"duplicate failure reason {f['reason']!r} in one window")
            reasons.add(f["reason"])
            if not isinstance(f["count"], int) or isinstance(f["count"], bool) \
                    or f["count"] < 0:
                raise BudgetVerifyError("failure count must be a non-negative int")
            fail_total += f["count"]
        grants = w["grants"]
        if not isinstance(grants, list):
            raise BudgetVerifyError("grants must be a list")
        grant_total = 0
        for g in grants:
            if not isinstance(g, dict) or set(g) != GRANT_KEYS:
                raise BudgetVerifyError(
                    "a grant record must contain exactly amount and created_at")
            if not isinstance(g["amount"], int) or isinstance(g["amount"], bool) \
                    or g["amount"] <= 0:
                raise BudgetVerifyError("grant amount must be a positive int")
            _check_str("grant.created_at", g["created_at"])
            grant_total += g["amount"]
        key = (tenant, window)
        if key in seen:
            raise BudgetVerifyError(f"duplicate window record {key}")
        seen.add(key)
        remaining = policies[rev] + grant_total - ded
        if remaining < 0:
            raise BudgetVerifyError(
                f"window {tenant}/{window}: deductions {ded} exceed quota"
                f" {policies[rev]} + grants {grant_total} (forged/negative"
                " balance)")
        out[key] = {
            "tenant_id": tenant, "window": window, "policy_revision": rev,
            "deductions": ded, "failures": failures, "grants": grants,
            "grants_total": grant_total, "base_quota": policies[rev],
            "remaining": remaining, "failure_total": fail_total,
        }
    return out


# --------------------------------------------------------------------------
# Offline verdicts
# --------------------------------------------------------------------------

def _find(verified: dict, tenant_id: str, window_label: str) -> dict | None:
    return verified["windows"].get((tenant_id, window_label))


def daily_balance(verified: dict, tenant_id: str, date_value: str) -> dict:
    """Recomputed daily balance from the export alone. A window absent from the
    export means zero recorded activity."""
    label = parse_iso_date(date_value)
    w = _find(verified, tenant_id, label)
    if w is None:
        raise BudgetVerifyError(
            "no audit record for that tenant/window in this export")
    return {
        "tenant_id": tenant_id, "window": label,
        "policy_revision": w["policy_revision"],
        "base_quota": w["base_quota"], "grants_total": w["grants_total"],
        "deductions": w["deductions"], "remaining": w["remaining"],
        "failures": w["failures"],
    }


def request_in_budget(verified: dict, tenant_id: str, date_value: str,
                      nth: int) -> dict:
    """Was the n-th deduction (1-based) of tenant in that UTC window within
    the budget available for that window?

    A deduction is within budget iff n <= base_quota + grants_total. Whether
    the service actually granted that particular request is answerable too:
    n <= deductions means it was recorded; n > deductions means the export
    carries no such deduction.
    """
    if not isinstance(nth, int) or isinstance(nth, bool) or nth < 1:
        raise BudgetVerifyError("nth must be a positive integer")
    label = parse_iso_date(date_value)
    w = _find(verified, tenant_id, label)
    if w is None:
        return {"tenant_id": tenant_id, "window": label, "nth": nth,
                "verdict": "no_record", "within_budget": None,
                "recorded": False, "budget_capacity": None,
                "deductions": 0}
    capacity = w["base_quota"] + w["grants_total"]
    within = nth <= capacity
    recorded = nth <= w["deductions"]
    if not within:
        verdict = "over_budget"
    elif recorded:
        verdict = "within_budget"
    else:
        verdict = "within_budget_unrecorded"
    return {"tenant_id": tenant_id, "window": label, "nth": nth,
            "verdict": verdict, "within_budget": within,
            "recorded": recorded, "budget_capacity": capacity,
            "deductions": w["deductions"], "remaining": w["remaining"]}


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pwncorpus-budget-verify",
        description="offline privacy-budget export verifier (no database,"
                    " no network; sees no prefixes, suffixes or secrets)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verify", help="verify a signed budget export")
    p.add_argument("export")
    p.add_argument("--genesis-pub", default=None,
                   help="pin the budget genesis public key (hex)")

    p = sub.add_parser("daily", help="recompute one tenant/window balance")
    p.add_argument("export")
    p.add_argument("--tenant", required=True)
    p.add_argument("--date", required=True, help="UTC date YYYY-MM-DD")
    p.add_argument("--genesis-pub", default=None)

    p = sub.add_parser("check", help="was the n-th deduction within budget?")
    p.add_argument("export")
    p.add_argument("--tenant", required=True)
    p.add_argument("--date", required=True, help="UTC date YYYY-MM-DD")
    p.add_argument("--nth", type=int, required=True)
    p.add_argument("--genesis-pub", default=None)
    p.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    try:
        doc = load_export(args.export)
        verified = verify_export(doc,
                                 trusted_genesis_pub=args.genesis_pub)
        if args.cmd == "verify":
            total_ded = sum(w["deductions"] for w in verified["windows"].values())
            total_fail = sum(w["failure_total"]
                             for w in verified["windows"].values())
            print(f"OK: budget {verified['budget_id']} export valid,"
                  f" policies={len(verified['policies'])},"
                  f" windows={len(verified['windows'])},"
                  f" deductions={total_ded}, failures={total_fail},"
                  f" last_event_seq={verified['last_event_seq']}")
            return 0
        if args.cmd == "daily":
            bal = daily_balance(verified, args.tenant, args.date)
            print(json.dumps(bal, indent=2, sort_keys=True))
            return 0
        v = request_in_budget(verified, args.tenant, args.date, args.nth)
        if args.json:
            print(json.dumps(v, indent=2, sort_keys=True))
        else:
            print(f"{v['verdict'].upper()}: tenant {v['tenant_id']} window"
                  f" {v['window']} nth={v['nth']} deductions="
                  f"{v['deductions']} capacity={v['budget_capacity']}")
        return 0 if v["verdict"] == "within_budget" else 3
    except BudgetVerifyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
