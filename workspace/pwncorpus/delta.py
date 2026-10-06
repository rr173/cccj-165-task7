"""Verifiable incremental packages between two published releases.

A full offline export (see ``core.export_version`` / ``verifier``) is a
``manifest.json`` plus ``buckets/<PREFIX>.txt`` files. Re-downloading every
bucket for every release is wasteful, so a *delta package* carries only what
changed between two releases while staying independently verifiable:

    <delta-dir>/
      delta.json
        metadata, the FULL start/target manifests (so the package is
        self-contained), the added/modified/deleted/unchanged bucket
        partition, per-payload hashes, and a self hash
      payloads/
        added/<PREFIX>.txt       bucket exists only in the target release
        modified/<PREFIX>.txt    bucket exists in both, content differs
        deleted buckets are not payloads: only the prefix and the baseline
        bucket's SHA-256 are recorded, so application can (a) confirm the
        exact file it is about to delete and (b) roll it back from a local
        backup.

Trust chain
-----------
* ``delta.json`` self-hashes canonically (``delta_sha256``), exactly like an
  export manifest. Any tampering with metadata, the embedded manifests or the
  recorded file hashes breaks ``delta_sha256``.
* Every embedded manifest is itself self-hashed, and every carried payload is
  hashed twice-bound: to the target manifest and in ``payload_sha256``.
* Before application BOTH sides are checked: the delta package as a whole AND
  the local mirror, which must be a valid *start* release
  (``from_manifest_sha256`` binding). A mismatched baseline, a tampered
  package, a missing payload, or a write interruption never leaves a
  half-upgraded mirror:

    - all checks run before the mirror is touched;
    - the switch is journaled (``.delta-apply.json``) with every replaced or
      deleted bucket backed up under ``.delta-stage/``;
    - an interrupted switch is resumed forward to completion, or rolled back
      to the exact start release with ``--rollback`` -- in every terminal
      state the mirror passes the original ``verifier.verify_export``;
    - a crash after staging but before the journal is registered leaves only
      an orphaned ``.delta-stage/`` beside the untouched mirror: the next
      ``apply`` discards it and stages fresh, and ``--rollback`` removes it
      while reporting truthfully that there was nothing to roll back.

Applying an already-completed delta is a no-op that verifies the target.

Usage:
  python -m pwncorpus.delta build FROM_EXPORT TO_EXPORT OUT_DELTA_DIR
  python -m pwncorpus.delta check DELTA_DIR [--baseline FROM_EXPORT_DIR]
  python -m pwncorpus.delta apply DELTA_DIR MIRROR_DIR [--rollback]
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone

from . import verifier

DELTA_FORMAT = "pwncorpus-delta/1"
DELTA_FILE = "delta.json"
JOURNAL_NAME = ".delta-apply.json"
STAGE_NAME = ".delta-stage"

# Fields covered by delta_sha256 (everything except the hash itself).
_DELTA_FIELDS = (
    "format", "from_version", "to_version", "hash_algo", "prefix_len",
    "from_manifest_sha256", "to_manifest_sha256", "created_at",
    "from_manifest", "to_manifest", "added", "modified", "deleted",
    "unchanged", "payload_sha256",
)


class DeltaError(Exception):
    """A delta package is invalid, the baseline does not match, or applying
    it failed before the mirror reached a verifiable state."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _fsync_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str, data: bytes) -> None:
    """Durable temp-file + atomic rename write; fsyncs file and directory."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f".{os.path.basename(path)}.tmp-{os.getpid()}")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(d)


def _dump_manifest_bytes(manifest: dict) -> bytes:
    """Byte-for-byte identical to what ``core.export_version`` writes, so an
    applied delta produces a directory indistinguishable from a full export."""
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def build_delta(from_dir: str, to_dir: str, out_dir: str) -> dict:
    """Generate a verifiable delta package from two full export directories.

    Both exports must pass the offline verifier; the output directory must
    not already contain a delta. The start and target manifests are embedded
    in full, which binds the package to exactly those two releases.
    """
    from_errors = verifier.verify_export(from_dir)
    if from_errors:
        raise DeltaError(
            f"start export {from_dir!r} is not valid; refusing to build delta:"
            + "".join(f"\n  - {e}" for e in from_errors[:10]))
    to_errors = verifier.verify_export(to_dir)
    if to_errors:
        raise DeltaError(
            f"target export {to_dir!r} is not valid; refusing to build delta:"
            + "".join(f"\n  - {e}" for e in to_errors[:10]))

    from_manifest, _ = verifier.load_manifest(from_dir)
    to_manifest, _ = verifier.load_manifest(to_dir)
    if from_manifest["version"] == to_manifest["version"]:
        raise DeltaError(
            f"start and target are the same release "
            f"(version {from_manifest['version']}); nothing to delta")
    if from_manifest["hash_algo"] != to_manifest["hash_algo"]:
        raise DeltaError("start and target use different hash algorithms")
    if from_manifest["prefix_len"] != to_manifest["prefix_len"]:
        raise DeltaError("start and target use different prefix lengths")

    a, b = from_manifest["files"], to_manifest["files"]
    added = {p: b[p] for p in sorted(set(b) - set(a))}
    deleted = {p: a[p] for p in sorted(set(a) - set(b))}
    modified = {p: b[p] for p in sorted(set(a) & set(b)) if a[p] != b[p]}
    unchanged = sorted(p for p in set(a) & set(b) if a[p] == b[p])

    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise DeltaError(f"output directory {out_dir!r} exists and is not empty")
    pdir_added = os.path.join(out_dir, "payloads", "added")
    pdir_mod = os.path.join(out_dir, "payloads", "modified")
    os.makedirs(pdir_added, exist_ok=True)
    os.makedirs(pdir_mod, exist_ok=True)

    payload_sha: dict[str, str] = {}

    def carry(prefix: str, kind: str, src_dir: str):
        rel = f"{kind}/{prefix}.txt"
        src = os.path.join(src_dir, "buckets", f"{prefix}.txt")
        dst = os.path.join(out_dir, "payloads", kind, f"{prefix}.txt")
        shutil.copyfile(src, dst)
        payload_sha[rel] = _sha256_file(dst)

    for p in added:
        carry(p, "added", to_dir)
    for p in modified:
        carry(p, "modified", to_dir)

    meta = {
        "format": DELTA_FORMAT,
        "from_version": from_manifest["version"],
        "to_version": to_manifest["version"],
        "hash_algo": to_manifest["hash_algo"],
        "prefix_len": to_manifest["prefix_len"],
        "from_manifest_sha256": from_manifest["manifest_sha256"],
        "to_manifest_sha256": to_manifest["manifest_sha256"],
        "created_at": _utcnow(),
        "from_manifest": from_manifest,
        "to_manifest": to_manifest,
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "unchanged": unchanged,
        "payload_sha256": dict(sorted(payload_sha.items())),
    }
    meta["delta_sha256"] = _delta_self_hash(meta)
    atomic_write(os.path.join(out_dir, DELTA_FILE),
                 _dump_manifest_bytes(meta))
    return meta


def _delta_self_hash(meta: dict) -> str:
    payload = {f: meta[f] for f in _DELTA_FIELDS}
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()


# --------------------------------------------------------------------------
# Validation / inspection
# --------------------------------------------------------------------------

def _load_delta(delta_dir: str):
    path = os.path.join(delta_dir, DELTA_FILE)
    if not os.path.isfile(path):
        raise DeltaError(f"missing delta descriptor: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaError(f"unreadable delta descriptor: {exc}") from exc
    if not isinstance(meta, dict):
        raise DeltaError("delta descriptor is not a JSON object")
    return meta


def validate_delta(delta_dir: str) -> dict:
    """Fully validate a delta package on its own (no baseline needed).

    Returns the descriptor. Raises DeltaError with a clear, aggregated message
    on the first class of problems found.
    """
    meta = _load_delta(delta_dir)
    problems: list[str] = []

    missing = [f for f in _DELTA_FIELDS + ("delta_sha256",) if f not in meta]
    if missing:
        raise DeltaError("delta descriptor missing fields: " + ", ".join(missing))
    if meta["format"] != DELTA_FORMAT:
        problems.append(f"unsupported format: {meta['format']!r}")
    if meta["from_version"] == meta["to_version"]:
        problems.append("from_version and to_version must differ")

    # 1. self-integrity of the descriptor
    if _delta_self_hash(meta) != meta["delta_sha256"]:
        problems.append("delta_sha256 does not match recomputed hash "
                        "(package metadata was altered)")

    # 2. embedded manifests must be structurally sound and self-consistent
    emb: dict[str, dict] = {}
    for side in ("from_manifest", "to_manifest"):
        m = meta[side]
        errs = verifier.check_manifest_fields(m)
        if errs:
            problems.extend(f"{side}: {e}" for e in errs)
            continue
        if verifier.manifest_self_hash(m) != m["manifest_sha256"]:
            problems.append(f"{side}: manifest_sha256 does not match recomputed hash")
        emb[side] = m
    if problems:
        raise DeltaError("; ".join(problems))

    fm, tm = emb["from_manifest"], emb["to_manifest"]
    if fm["version"] != meta["from_version"]:
        problems.append("from_manifest.version does not match from_version")
    if tm["version"] != meta["to_version"]:
        problems.append("to_manifest.version does not match to_version")
    if fm["manifest_sha256"] != meta["from_manifest_sha256"]:
        problems.append("from_manifest_sha256 binding does not match embedded manifest")
    if tm["manifest_sha256"] != meta["to_manifest_sha256"]:
        problems.append("to_manifest_sha256 binding does not match embedded manifest")
    if fm["hash_algo"] != tm["hash_algo"] or fm["hash_algo"] != meta["hash_algo"]:
        problems.append("hash_algo mismatch across delta and manifests")
    if fm["prefix_len"] != tm["prefix_len"] or fm["prefix_len"] != meta["prefix_len"]:
        problems.append("prefix_len mismatch across delta and manifests")

    added, modified, deleted = meta["added"], meta["modified"], meta["deleted"]
    unchanged = meta["unchanged"]
    for name, obj in (("added", added), ("modified", modified),
                      ("deleted", deleted)):
        if not isinstance(obj, dict):
            problems.append(f"'{name}' must be an object")
    if not isinstance(unchanged, list):
        problems.append("'unchanged' must be a list")
    if not isinstance(meta["payload_sha256"], dict):
        problems.append("'payload_sha256' must be an object")
    if problems:
        raise DeltaError("; ".join(problems))

    # 3. the recorded partition must be exactly derivable from the two
    #    embedded manifests, and every recorded file hash must match the
    #    release manifest it refers to.
    a, b = fm["files"], tm["files"]
    expect_added = {p: b[p] for p in sorted(set(b) - set(a))}
    expect_deleted = {p: a[p] for p in sorted(set(a) - set(b))}
    expect_modified = {p: b[p] for p in sorted(set(a) & set(b)) if a[p] != b[p]}
    expect_unchanged = sorted(p for p in set(a) & set(b) if a[p] == b[p])
    if added != expect_added:
        problems.append("'added' bucket partition does not match the embedded manifests")
    if modified != expect_modified:
        problems.append("'modified' bucket partition does not match the embedded manifests")
    if deleted != expect_deleted:
        problems.append("'deleted' bucket partition does not match the embedded manifests")
    if sorted(unchanged) != expect_unchanged:
        problems.append("'unchanged' bucket list does not match the embedded manifests")
    overlap = ((set(added) & set(modified))
               | (set(added) & set(deleted))
               | (set(modified) & set(deleted)))
    if overlap:
        problems.append(f"bucket partition is not disjoint: {sorted(overlap)}")
    if set(unchanged) & (set(added) | set(modified) | set(deleted)):
        problems.append("an 'unchanged' bucket is also listed as changed")
    for p in added:
        if added[p] != b.get(p):
            problems.append(f"added {p}: recorded hash does not match target manifest")
    for p in modified:
        if modified[p] != b.get(p):
            problems.append(f"modified {p}: recorded hash does not match target manifest")
    for p in deleted:
        if deleted[p] != a.get(p):
            problems.append(f"deleted {p}: recorded hash does not match start manifest")
    if problems:
        raise DeltaError("; ".join(problems))

    # 4. payload files: expected set, hash bindings and on-disk content
    expect_payloads = {f"added/{p}.txt": h for p, h in added.items()}
    expect_payloads.update({f"modified/{p}.txt": h for p, h in modified.items()})
    if meta["payload_sha256"] != dict(sorted(expect_payloads.items())):
        problems.append("'payload_sha256' does not match the derived payload set")
    if problems:
        raise DeltaError("; ".join(problems))

    pl = tm["prefix_len"]
    algo = tm["hash_algo"]
    k_to = tm["threshold_k"]
    for kind, entries in (("added", added), ("modified", modified)):
        for prefix, expected_sha in entries.items():
            rel = f"{kind}/{prefix}.txt"
            fpath = os.path.join(delta_dir, "payloads", kind, f"{prefix}.txt")
            if not os.path.isfile(fpath):
                problems.append(f"missing payload content: payloads/{rel}")
                continue
            with open(fpath, "rb") as fh:
                raw = fh.read()
            actual = _sha256_bytes(raw)
            if actual != expected_sha:
                problems.append(
                    f"payload {rel}: sha256 mismatch (content altered or missing)")
            elif meta["payload_sha256"].get(rel) != expected_sha:
                problems.append(f"payload {rel}: payload_sha256 binding mismatch")
            # carried buckets must satisfy the TARGET release's rules
            problems.extend(
                f"payload {rel}: {e}" for e in
                verifier.check_bucket_bytes(raw, prefix, pl, algo, k_to))

    # no stray payload files
    proot = os.path.join(delta_dir, "payloads")
    for kind in ("added", "modified"):
        kdir = os.path.join(proot, kind)
        if not os.path.isdir(kdir):
            if (kind == "added" and added) or (kind == "modified" and modified):
                problems.append(f"missing payload directory: payloads/{kind}/")
            continue
        for name in sorted(os.listdir(kdir)):
            rel = f"{kind}/{name}"
            if rel not in expect_payloads:
                problems.append(f"unexpected payload file: payloads/{rel}")
    if os.path.isdir(proot):
        for name in sorted(os.listdir(proot)):
            if name not in ("added", "modified"):
                problems.append(f"unexpected entry in payloads/: {name}")

    if problems:
        raise DeltaError("; ".join(problems))
    return meta


def delta_summary(meta: dict) -> dict:
    return {
        "format": meta["format"],
        "from_version": meta["from_version"],
        "to_version": meta["to_version"],
        "from_manifest_sha256": meta["from_manifest_sha256"],
        "to_manifest_sha256": meta["to_manifest_sha256"],
        "buckets_added": len(meta["added"]),
        "buckets_modified": len(meta["modified"]),
        "buckets_deleted": len(meta["deleted"]),
        "buckets_unchanged": len(meta["unchanged"]),
        "delta_sha256": meta["delta_sha256"],
    }


def check_delta(delta_dir: str, baseline_dir: str | None = None) -> dict:
    """Validate a delta package and, when ``baseline_dir`` is given, verify
    that the local mirror is exactly the bound start release. Returns the
    descriptor; raises DeltaError otherwise."""
    meta = validate_delta(delta_dir)
    if baseline_dir is not None:
        errors = verifier.verify_export(baseline_dir)
        if errors:
            raise DeltaError(
                "local baseline is not a valid export, cannot apply this delta:"
                + "".join(f"\n  - {e}" for e in errors[:10]))
        base_manifest, _ = verifier.load_manifest(baseline_dir)
        _require_baseline_match(base_manifest, meta)
    return meta


def _require_baseline_match(base_manifest: dict, meta: dict) -> None:
    """The local mirror must be byte-bound to the delta's start release:
    matching self hash and identical signed manifest content (every recorded
    bucket hash, version, threshold, ... )."""
    if base_manifest["manifest_sha256"] != meta["from_manifest_sha256"]:
        raise DeltaError(
            f"local baseline is release {base_manifest.get('version')} "
            f"(manifest {base_manifest.get('manifest_sha256', '')[:16]}...), "
            f"but this delta requires version {meta['from_version']} "
            f"(manifest {meta['from_manifest_sha256'][:16]}...); "
            "refusing to apply")
    if _canonical(verifier.manifest_payload(base_manifest)) != \
            _canonical(verifier.manifest_payload(meta["from_manifest"])):
        raise DeltaError(
            "local baseline manifest content differs from the start release "
            "bound in this delta, despite matching hash label; refusing to apply")


# --------------------------------------------------------------------------
# Application (journaled, crash-safe, idempotent)
# --------------------------------------------------------------------------

def _link_or_copy(src: str, dst: str) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        os.link(src, dst)
    except (OSError, AttributeError):
        shutil.copyfile(src, dst)


def _write_journal(stage: dict) -> None:
    atomic_write(stage["journal_path"],
                 (_canonical(stage["journal"]) + "\n").encode("utf-8"))


def _read_journal(mirror_dir: str):
    path = os.path.join(mirror_dir, JOURNAL_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise DeltaError(
            f"found unreadable application journal {path!r}; a previous apply"
            f" was interrupted and its state cannot be inspected: {exc}") from exc


def _remove_orphan_stage(stage_path: str) -> bool:
    """Drop a staging area that was never registered in a journal -- the
    crash window between staging and the journal write. Returns True when
    something was removed.

    Only called once the mirror itself has been verified as a valid release,
    so the staged payloads and backups it holds are known to be redundant,
    re-derivable data."""
    if os.path.islink(stage_path) or os.path.isfile(stage_path):
        os.unlink(stage_path)
        return True
    if os.path.isdir(stage_path):
        shutil.rmtree(stage_path, ignore_errors=True)
        return True
    return False


def apply_delta(delta_dir: str, mirror_dir: str, rollback: bool = False,
                progress=None) -> dict:
    """Apply a delta package to a local full-export mirror.

    Preconditions (all checked before the mirror is modified):
      * the delta package is complete and untampered (``validate_delta``);
      * the mirror passes the original offline verifier;
      * the mirror is exactly the delta's bound start release
        (or, for an idempotent re-run, its target release).

    The switch is journaled. Interrupting it at any point leaves the mirror
    recoverable: a further ``apply_delta`` call resumes forward to the target;
    ``apply_delta(..., rollback=True)`` restores the exact start release. Both
    outcomes pass ``verifier.verify_export``.
    """
    def note(event):
        if progress is not None:
            progress(event)

    meta = validate_delta(delta_dir)
    fm, tm = meta["from_manifest"], meta["to_manifest"]
    bdir = os.path.join(mirror_dir, "buckets")

    journal = _read_journal(mirror_dir)
    stage_path = os.path.join(mirror_dir, STAGE_NAME)

    if journal is not None:
        # Resuming an interrupted switch -- never silently mix it with a
        # different package.
        if journal.get("to_manifest_sha256") != meta["to_manifest_sha256"] \
                or journal.get("from_manifest_sha256") != meta["from_manifest_sha256"]:
            raise DeltaError(
                "an interrupted application of a DIFFERENT delta is present in"
                f" {mirror_dir!r} (journal {JOURNAL_NAME}); resume it with the"
                " matching package or use --rollback before applying another one")
        ctx = _resume_context(mirror_dir, meta)
        if rollback:
            return _rollback(ctx, note)
        return _switch(ctx, note)

    # No interrupted switch: this must be a clean start release...
    errors = verifier.verify_export(mirror_dir)
    if errors:
        raise DeltaError(
            "local baseline failed verification, refusing to apply delta:"
            + "".join(f"\n  - {e}" for e in errors[:10]))
    base_manifest, _ = verifier.load_manifest(mirror_dir)

    # ...unless the same delta was already completed: then re-applying is a
    # safe, verified no-op.
    if base_manifest["manifest_sha256"] == meta["to_manifest_sha256"]:
        if _canonical(verifier.manifest_payload(base_manifest)) == \
                _canonical(verifier.manifest_payload(tm)):
            return {
                "from_version": meta["from_version"],
                "to_version": meta["to_version"],
                "already_applied": True,
                "buckets_added": len(meta["added"]),
                "buckets_modified": len(meta["modified"]),
                "buckets_deleted": len(meta["deleted"]),
            }
        raise DeltaError(
            "mirror claims the target manifest hash but its content differs"
            " from the release bound in this delta; refusing to apply")

    _require_baseline_match(base_manifest, meta)

    if rollback:
        # No journal was ever registered: the switch never began, so there is
        # nothing to roll back -- the mirror verified above is still the exact
        # start release. A crash between staging and the journal write may
        # have orphaned the staging area; remove it rather than leaving it
        # behind, and report truthfully that nothing was rolled back.
        removed = _remove_orphan_stage(stage_path)
        if removed:
            _fsync_dir(mirror_dir)
        return {"from_version": meta["from_version"],
                "to_version": meta["to_version"],
                "rolled_back": False,
                "nothing_to_roll_back": True,
                "orphan_stage_removed": removed,
                "note": "no interrupted application found; mirror is unchanged"}

    # A crash between staging and the journal write leaves an orphaned
    # staging area beside the untouched mirror. It is entirely re-derivable,
    # and re-staging over it could trip on its hard-linked backups, so drop
    # it before staging fresh.
    _remove_orphan_stage(stage_path)

    # ---- prepare: stage everything new and back up everything replaced ----
    new_dir = os.path.join(stage_path, "new")
    old_dir = os.path.join(stage_path, "old")
    os.makedirs(new_dir, exist_ok=True)
    os.makedirs(old_dir, exist_ok=True)
    try:
        for prefix in sorted(meta["added"]) + sorted(meta["modified"]):
            kind = "added" if prefix in meta["added"] else "modified"
            src = os.path.join(delta_dir, "payloads", kind, f"{prefix}.txt")
            with open(src, "rb") as fh:
                raw = fh.read()
            if _sha256_bytes(raw) != meta[kind][prefix]:
                raise DeltaError(
                    f"payload {kind}/{prefix}.txt failed integrity check while"
                    " staging; package content is missing or altered")
            dst = os.path.join(new_dir, f"{prefix}.txt")
            with open(dst, "wb") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
        for prefix in sorted(meta["modified"]) + sorted(meta["deleted"]):
            src = os.path.join(bdir, f"{prefix}.txt")
            if not os.path.isfile(src):
                raise DeltaError(
                    f"baseline bucket {prefix}.txt disappeared during prepare;"
                    " mirror left untouched")
            _link_or_copy(src, os.path.join(old_dir, f"{prefix}.txt"))
        # back up the exact start manifest bytes for an eventual rollback
        old_manifest_bytes = _read_bytes(os.path.join(mirror_dir, "manifest.json"))
        atomic_write(os.path.join(stage_path, "manifest.old.json"), old_manifest_bytes)
        _fsync_dir(stage_path)
    except DeltaError:
        # staging happens entirely beside the mirror; on failure remove the
        # partial stage so the untouched baseline stays clean and verifiable
        shutil.rmtree(stage_path, ignore_errors=True)
        raise
    note("stage-ready")

    ctx = {
        "mirror_dir": mirror_dir,
        "bdir": bdir,
        "stage_path": stage_path,
        "new_dir": new_dir,
        "old_dir": old_dir,
        "journal_path": os.path.join(mirror_dir, JOURNAL_NAME),
        "meta": meta,
        "journal": {
            "format": DELTA_FORMAT,
            "from_version": meta["from_version"],
            "to_version": meta["to_version"],
            "from_manifest_sha256": meta["from_manifest_sha256"],
            "to_manifest_sha256": meta["to_manifest_sha256"],
            "state": "prepared",
        },
    }
    _write_journal(ctx)
    note("prepared")

    return _switch(ctx, note)


def _resume_context(mirror_dir: str, meta: dict) -> dict:
    stage_path = os.path.join(mirror_dir, STAGE_NAME)
    journal = _read_journal(mirror_dir)
    if not os.path.isdir(stage_path):
        raise DeltaError(
            f"application journal exists but {STAGE_NAME}/ is missing; cannot"
            " resume or roll back automatically")
    return {
        "mirror_dir": mirror_dir,
        "bdir": os.path.join(mirror_dir, "buckets"),
        "stage_path": stage_path,
        "new_dir": os.path.join(stage_path, "new"),
        "old_dir": os.path.join(stage_path, "old"),
        "journal_path": os.path.join(mirror_dir, JOURNAL_NAME),
        "meta": meta,
        "journal": journal,
    }


def _switch(ctx, note) -> dict:
    """Idempotent: drive a prepared switch to 'target fully installed'.

    Every step is safe to repeat after a crash even if the journal state did
    not reach 'switched': deletes are conditional, and a bucket rename whose
    staged source is gone but whose destination already holds the target
    content counts as done instead of failing.
    """
    meta = ctx["meta"]
    tm = meta["to_manifest"]
    bdir, new_dir = ctx["bdir"], ctx["new_dir"]
    os.makedirs(bdir, exist_ok=True)
    target_hash = {**meta["added"], **meta["modified"]}

    # delete buckets removed by the target
    for prefix in sorted(meta["deleted"]):
        p = os.path.join(bdir, f"{prefix}.txt")
        if os.path.isfile(p):
            os.unlink(p)
    # install added/modified buckets (rename is atomic on the same filesystem;
    # repeating it after an interruption is harmless)
    for prefix in sorted(meta["added"]) + sorted(meta["modified"]):
        dst = os.path.join(bdir, f"{prefix}.txt")
        src = os.path.join(new_dir, f"{prefix}.txt")
        if os.path.isfile(src):
            os.replace(src, dst)
        elif not (os.path.isfile(dst)
                  and _sha256_file(dst) == target_hash[prefix]):
            raise DeltaError(
                f"staged content for bucket {prefix} is missing and the"
                " installed bucket is not the target content; use --rollback"
                " to restore the start release")
    _fsync_dir(bdir)
    note("buckets-switched")

    # publish the target manifest (exact bytes of a full target export)
    atomic_write(os.path.join(ctx["mirror_dir"], "manifest.json"),
                 _dump_manifest_bytes(tm))
    note("manifest-written")

    ctx["journal"]["state"] = "switched"
    _write_journal(ctx)
    note("switched")

    # terminal verification: the resulting directory must be a valid target
    # release -- indistinguishable from a full export of the target version.
    errors = verifier.verify_export(ctx["mirror_dir"])
    if errors:
        raise DeltaError(
            "post-apply verification FAILED; mirror is not a valid target"
            " release (use --rollback to restore the start release):"
            + "".join(f"\n  - {e}" for e in errors[:10]))
    final_manifest, _ = verifier.load_manifest(ctx["mirror_dir"])
    if final_manifest["manifest_sha256"] != meta["to_manifest_sha256"] \
            or _canonical(verifier.manifest_payload(final_manifest)) \
            != _canonical(verifier.manifest_payload(tm)):
        raise DeltaError(
            "post-apply manifest does not match the bound target release;"
            " use --rollback to restore the start release")

    _cleanup(ctx)
    return {
        "from_version": meta["from_version"],
        "to_version": meta["to_version"],
        "already_applied": False,
        "buckets_added": len(meta["added"]),
        "buckets_modified": len(meta["modified"]),
        "buckets_deleted": len(meta["deleted"]),
    }


def _rollback(ctx, note) -> dict:
    """Restore the exact start release from a prepared/switched journal.

    The journal state flag is deliberately NOT trusted: a crash can happen
    between moving the buckets and recording 'switched'. Restoration is
    therefore unconditional -- remove every added bucket, restore every
    modified or deleted bucket from the stage backup, restore the exact start
    manifest bytes -- and is safe to repeat.
    """
    meta = ctx["meta"]
    bdir, old_dir = ctx["bdir"], ctx["old_dir"]
    os.makedirs(bdir, exist_ok=True)

    for prefix in sorted(meta["added"]):
        p = os.path.join(bdir, f"{prefix}.txt")
        if os.path.isfile(p):
            os.unlink(p)
    for prefix in sorted(meta["modified"]) + sorted(meta["deleted"]):
        dst = os.path.join(bdir, f"{prefix}.txt")
        src = os.path.join(old_dir, f"{prefix}.txt")
        if os.path.isfile(src):
            os.replace(src, dst)
        elif not (os.path.isfile(dst)
                  and _sha256_file(dst) == meta["from_manifest"]["files"].get(prefix)):
            raise DeltaError(
                f"backup of baseline bucket {prefix} is missing from"
                f" {STAGE_NAME}/; cannot roll back safely")
    _fsync_dir(bdir)

    old_manifest = os.path.join(ctx["stage_path"], "manifest.old.json")
    if not os.path.isfile(old_manifest):
        raise DeltaError("backup of baseline manifest is missing;"
                         " cannot roll back safely")
    atomic_write(os.path.join(ctx["mirror_dir"], "manifest.json"),
                 _read_bytes(old_manifest))

    errors = verifier.verify_export(ctx["mirror_dir"])
    if errors:
        raise DeltaError("rollback did not produce a valid start release:"
                         + "".join(f"\n  - {e}" for e in errors[:10]))
    base_manifest, _ = verifier.load_manifest(ctx["mirror_dir"])
    _require_baseline_match(base_manifest, meta)
    note("rolled-back")
    _cleanup(ctx)
    return {"from_version": meta["from_version"],
            "to_version": meta["to_version"], "rolled_back": True}


def _cleanup(ctx) -> None:
    journal = ctx["journal_path"]
    if os.path.isfile(journal):
        os.unlink(journal)
    if os.path.isdir(ctx["stage_path"]):
        shutil.rmtree(ctx["stage_path"], ignore_errors=True)
    _fsync_dir(ctx["mirror_dir"])


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="pwncorpus-delta",
        description="generate, check and apply verifiable incremental packages")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("build",
                       help="build a delta package from two full export dirs")
    p.add_argument("from_export", help="baseline (start) release export directory")
    p.add_argument("to_export", help="target release export directory")
    p.add_argument("out_dir", help="output delta package directory")

    p = sub.add_parser("check",
                       help="validate a delta package (and optionally a baseline)")
    p.add_argument("delta_dir")
    p.add_argument("--baseline", default=None,
                   help="local mirror that must match the bound start release")

    p = sub.add_parser("apply", help="apply a delta package to a local mirror")
    p.add_argument("delta_dir")
    p.add_argument("mirror_dir")
    p.add_argument("--rollback", action="store_true",
                   help="restore an interrupted application to the start release")

    args = ap.parse_args(argv)

    try:
        if args.cmd == "build":
            meta = build_delta(args.from_export, args.to_export, args.out_dir)
            s = delta_summary(meta)
            print(f"built delta v{s['from_version']} -> v{s['to_version']} "
                  f"in {args.out_dir}")
            print(f"  added {s['buckets_added']}, modified "
                  f"{s['buckets_modified']}, deleted {s['buckets_deleted']}, "
                  f"unchanged {s['buckets_unchanged']} buckets")
            print(f"  delta {s['delta_sha256'][:16]}...")
            return 0
        if args.cmd == "check":
            meta = check_delta(args.delta_dir, args.baseline)
            s = delta_summary(meta)
            print(f"OK: delta v{s['from_version']} -> v{s['to_version']}, "
                  f"delta {s['delta_sha256'][:16]}...")
            print(f"    added {s['buckets_added']}, modified "
                  f"{s['buckets_modified']}, deleted {s['buckets_deleted']}, "
                  f"unchanged {s['buckets_unchanged']} buckets")
            if args.baseline:
                print(f"    baseline matches bound start release "
                      f"({s['from_manifest_sha256'][:16]}...)")
            return 0
        if args.cmd == "apply":
            result = apply_delta(args.delta_dir, args.mirror_dir,
                                 rollback=args.rollback)
            if result.get("already_applied"):
                print(f"OK: mirror already at v{result['to_version']}; "
                      "re-application changed nothing")
            elif result.get("rolled_back"):
                print(f"OK: mirror rolled back to v{result['from_version']}")
            elif result.get("nothing_to_roll_back"):
                msg = (f"OK: nothing to roll back; mirror never left "
                       f"v{result['from_version']}")
                if result.get("orphan_stage_removed"):
                    msg += "; removed leftover staging data"
                print(msg)
            else:
                print(f"OK: applied v{result['from_version']} -> "
                      f"v{result['to_version']} "
                      f"(added {result['buckets_added']}, modified "
                      f"{result['buckets_modified']}, deleted "
                      f"{result['buckets_deleted']})")
            return 0
    except DeltaError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
