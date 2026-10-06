"""Offline bucket verifier.

Verifies an exported publication directory (buckets/*.txt + manifest.json)
without any network access:

  * manifest hash recomputed and compared (integrity of the manifest itself)
  * every bucket file's SHA-256 matches the manifest
  * every line is a well-formed `<suffix>:<count>` for the file's prefix
  * suffixes are sorted and unique inside each bucket
  * every bucket satisfies the minimum set size (threshold_k)
  * no unexpected / missing files

Also supports:
  * verifying that a live API range response matches a published bucket file
  * fully offline password lookup against an export (k-anonymity locally)

Usage:
  python -m pwncorpus.verifier verify EXPORT_DIR
  python -m pwncorpus.verifier check-response EXPORT_DIR PREFIX RESPONSE_FILE
  python -m pwncorpus.verifier lookup EXPORT_DIR [--password PW]
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import sys

_HASH_HEX = {"sha1": 40}

# Fields covered by manifest_sha256 (the hash signs everything except itself).
MANIFEST_FIELDS = ("version", "hash_algo", "prefix_len", "threshold_k",
                   "created_at", "files")


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def manifest_payload(manifest: dict) -> dict:
    """The signed manifest content (everything except manifest_sha256)."""
    return {f: manifest[f] for f in MANIFEST_FIELDS}


def manifest_self_hash(manifest: dict) -> str:
    return hashlib.sha256(_canonical(manifest_payload(manifest)).encode()).hexdigest()


def _load_manifest(export_dir: str):
    path = os.path.join(export_dir, "manifest.json")
    if not os.path.isfile(path):
        return None, [f"missing manifest: {path}"]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), []
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"unreadable manifest: {exc}"]


def check_manifest_fields(manifest) -> list[str]:
    """Structural validation of a manifest object."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest is not a JSON object"]
    for field in MANIFEST_FIELDS + ("manifest_sha256",):
        if field not in manifest:
            errors.append(f"manifest missing field: {field}")
    if errors:
        return errors
    if manifest["hash_algo"] not in _HASH_HEX:
        errors.append(f"unsupported hash_algo: {manifest['hash_algo']}")
        return errors
    if not isinstance(manifest["prefix_len"], int) or not (1 <= manifest["prefix_len"] < _HASH_HEX[manifest["hash_algo"]]):
        errors.append(f"invalid prefix_len: {manifest['prefix_len']!r}")
        return errors
    k = manifest["threshold_k"]
    if not isinstance(k, int) or k < 1:
        errors.append(f"invalid threshold_k: {k!r}")
        return errors
    if not isinstance(manifest["files"], dict):
        errors.append("manifest 'files' must be an object")
    return errors


def check_bucket_bytes(raw: bytes, prefix: str, prefix_len: int,
                       hash_algo: str, k: int) -> list[str]:
    """Validate one bucket file's bytes: hash vs caller's manifest entry is
    checked separately; here we cover encoding, line format, ordering,
    uniqueness and the minimum set size."""
    errors: list[str] = []
    suffix_len = _HASH_HEX[hash_algo] - prefix_len
    try:
        text = raw.decode("ascii", "strict")
    except UnicodeDecodeError:
        return [f"bucket {prefix}: not ASCII"]
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    suffixes = []
    for i, line in enumerate(lines, 1):
        m = re.fullmatch(r"([0-9A-F]{%d}):([0-9]+)" % suffix_len, line)
        if not m:
            errors.append(f"bucket {prefix} line {i}: malformed entry")
            continue
        if int(m.group(2)) < 1:
            errors.append(f"bucket {prefix} line {i}: count must be >= 1")
        suffixes.append(m.group(1))
    if len(suffixes) != len(set(suffixes)):
        errors.append(f"bucket {prefix}: duplicate suffixes")
    if suffixes != sorted(suffixes):
        errors.append(f"bucket {prefix}: suffixes not in canonical order")
    if 0 < len(suffixes) < k:
        errors.append(
            f"bucket {prefix}: set size {len(suffixes)} below threshold k={k}")
    return errors


def check_files_against_manifest(manifest: dict, export_dir: str) -> list[str]:
    """Every bucket file must match its manifest hash / content rules, and
    there must be no stray or missing files under buckets/."""
    errors: list[str] = []
    prefix_len = manifest["prefix_len"]
    k = manifest["threshold_k"]
    algo = manifest["hash_algo"]
    bdir = os.path.join(export_dir, "buckets")
    files = manifest["files"]

    for prefix, expected_sha in sorted(files.items()):
        if not re.fullmatch(r"[0-9A-F]{%d}" % prefix_len, prefix or ""):
            errors.append(f"bad prefix in manifest: {prefix!r}")
            continue
        fpath = os.path.join(bdir, f"{prefix}.txt")
        if not os.path.isfile(fpath):
            errors.append(f"missing bucket file for prefix {prefix}")
            continue
        with open(fpath, "rb") as fh:
            raw = fh.read()
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            errors.append(f"bucket {prefix}: sha256 mismatch with manifest")
        errors.extend(check_bucket_bytes(raw, prefix, prefix_len, algo, k))

    if os.path.isdir(bdir):
        for name in sorted(os.listdir(bdir)):
            stem = name[:-4] if name.endswith(".txt") else None
            if stem is None or stem not in files:
                errors.append(f"unexpected file in buckets/: {name}")
    elif files:
        errors.append("missing buckets/ directory")
    return errors


def verify_manifest(manifest: dict, export_dir: str) -> list[str]:
    """All offline checks for an already-loaded manifest: self hash, bucket
    files, format rules, threshold and stray/missing files."""
    errors = check_manifest_fields(manifest)
    if errors:
        return errors
    if manifest_self_hash(manifest) != manifest["manifest_sha256"]:
        errors.append("manifest_sha256 does not match recomputed hash")
    errors.extend(check_files_against_manifest(manifest, export_dir))
    return errors


def load_manifest(export_dir: str):
    """Public wrapper around the manifest loader: (manifest, errors)."""
    return _load_manifest(export_dir)


def verify_export(export_dir: str) -> list[str]:
    """Return a list of problems; empty list means the export is valid."""
    manifest, errs = _load_manifest(export_dir)
    if manifest is None:
        return errs
    return verify_manifest(manifest, export_dir)


def check_response(export_dir: str, prefix: str, response_path: str) -> list[str]:
    """Verify a live API range response against the published bucket file."""
    errors = verify_export(export_dir)
    if errors:
        return [f"export invalid, cannot check response: {e}" for e in errors[:5]]
    manifest, _ = _load_manifest(export_dir)
    prefix = prefix.upper()
    if prefix not in manifest["files"]:
        return [f"prefix {prefix} not present in manifest"]
    with open(response_path, "rb") as fh:
        body = fh.read()
    if hashlib.sha256(body).hexdigest() != manifest["files"][prefix]:
        return [f"response for {prefix} does not match published bucket "
                f"(version {manifest['version']})"]
    return []


def lookup(export_dir: str, password: str | None = None) -> int:
    """Offline k-anonymity lookup. Returns the count, or 0 if absent."""
    manifest, errs = _load_manifest(export_dir)
    if manifest is None:
        raise SystemExit(f"invalid export: {errs[0]}")
    if password is None:
        password = getpass.getpass("password to check (not echoed): ")
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[: manifest["prefix_len"]], digest[manifest["prefix_len"]:]
    fpath = os.path.join(export_dir, "buckets", f"{prefix}.txt")
    if not os.path.isfile(fpath):
        return 0
    with open(fpath, "r", encoding="ascii") as fh:
        for line in fh:
            s, _, c = line.rstrip("\n").partition(":")
            if s == suffix:
                return int(c)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pwncorpus-verifier",
                                 description="offline bucket verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("verify", help="verify an exported publication directory")
    p.add_argument("export_dir")
    p = sub.add_parser("check-response",
                       help="verify a live API response against the export")
    p.add_argument("export_dir")
    p.add_argument("prefix")
    p.add_argument("response_file")
    p = sub.add_parser("lookup", help="offline password lookup against the export")
    p.add_argument("export_dir")
    p.add_argument("--password", default=None,
                   help="password to check (omit for an interactive, hidden prompt)")
    args = ap.parse_args(argv)

    if args.cmd == "verify":
        errors = verify_export(args.export_dir)
        if errors:
            for e in errors:
                print(f"FAIL: {e}", file=sys.stderr)
            return 1
        manifest, _ = _load_manifest(args.export_dir)
        print(f"OK: version {manifest['version']}, k={manifest['threshold_k']}, "
              f"{len(manifest['files'])} buckets, "
              f"manifest {manifest['manifest_sha256'][:16]}...")
        return 0
    if args.cmd == "check-response":
        errors = check_response(args.export_dir, args.prefix, args.response_file)
        if errors:
            for e in errors:
                print(f"FAIL: {e}", file=sys.stderr)
            return 1
        print("OK: response matches published bucket")
        return 0
    if args.cmd == "lookup":
        count = lookup(args.export_dir, args.password)
        if count:
            print(f"FOUND: seen {count} time(s) in the corpus - change this password")
            return 2
        print("not found in this publication")
        return 0
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
