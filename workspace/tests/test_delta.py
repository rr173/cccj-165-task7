"""Tests for verifiable incremental packages (pwncorpus.delta).

Exercises generation, standalone/baseline checks, application equivalence with
a full target export, baseline-mismatch and tampering rejection, journaled
crash recovery (forward resume + rollback), idempotent re-application and the
CLI entry points. PREFIX_LEN is shrunk to 2 like the main suite.
"""
from __future__ import annotations

import filecmp
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from pwncorpus import core, db, delta, verifier

core.PREFIX_LEN = 2  # test-only: 256 buckets instead of 1M


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest().upper()


def pw_with_prefix(prefix: str, n: int, start: int = 0, tag: str = "pw"):
    out, i = [], start
    while len(out) < n:
        cand = f"{tag}-{i}"
        if sha1(cand).startswith(prefix):
            out.append(cand)
        i += 1
    return out


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


class DeltaCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwncorpus-delta-test-")
        self.db_path = os.path.join(self.tmp, "corpus.db")
        db.init(self.db_path)
        self.conn = db.connect(self.db_path)
        self.addCleanup(self.conn.close)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def publish(self, k=1):
        info = core.build_candidate(self.conn, k)
        core.activate(self.conn, info["version"])
        return info["version"]

    def export(self, version):
        d = os.path.join(self.tmp, f"export-v{version}")
        core.export_version(self.conn, version, d)
        self.assertEqual(verifier.verify_export(d), [])
        return d

    def build_versions(self):
        """v1 -> v2 spans every change kind:
           A1 bucket content, B1 unchanged, C1 deleted in v2, D1 added in v2."""
        a1 = pw_with_prefix("A1", 3, tag="a1")
        b1 = pw_with_prefix("B1", 2, tag="b1")
        c1 = pw_with_prefix("C1", 2, tag="c1")
        core.ingest_batch(self.conn, "base", a1 + b1 + c1)
        v1 = self.publish(k=1)

        extra = pw_with_prefix("A1", 2, start=500, tag="a1more")
        d1 = pw_with_prefix("D1", 2, tag="d1")
        core.ingest_batch(self.conn, "growth", extra + d1)
        c1_batch = self.conn.execute(
            "SELECT batch_id FROM batches WHERE source='base'").fetchone()["batch_id"]
        core.add_corrections(self.conn, c1_batch, c1)
        v2 = self.publish(k=1)
        return v1, v2, a1, b1, c1, extra, d1

    # ------------------------------------------------------------------ gen
    def test_delta_package_partition_and_bindings(self):
        v1, v2, a1, b1, c1, extra, d1 = self.build_versions()
        d1_dir, d2_dir = self.export(v1), self.export(v2)
        out = os.path.join(self.tmp, "delta-1-2")
        meta = delta.build_delta(d1_dir, d2_dir, out)

        self.assertEqual(meta["from_version"], v1)
        self.assertEqual(meta["to_version"], v2)
        self.assertEqual(set(meta["added"]), {"D1"})
        self.assertEqual(set(meta["modified"]), {"A1"})
        self.assertEqual(set(meta["deleted"]), {"C1"})
        self.assertEqual(meta["unchanged"], ["B1"])
        # the package binds both releases by their manifest self hashes
        self.assertEqual(meta["from_manifest_sha256"],
                         read_json(os.path.join(d1_dir, "manifest.json"))["manifest_sha256"])
        self.assertEqual(meta["to_manifest_sha256"],
                         read_json(os.path.join(d2_dir, "manifest.json"))["manifest_sha256"])
        # payloads on disk, nothing for deleted buckets
        self.assertTrue(os.path.isfile(os.path.join(out, "payloads", "added", "D1.txt")))
        self.assertTrue(os.path.isfile(os.path.join(out, "payloads", "modified", "A1.txt")))
        self.assertEqual(sorted(os.listdir(os.path.join(out, "payloads"))),
                         ["added", "modified"])
        # self hash is stable / verifiable
        again = read_json(os.path.join(out, "delta.json"))
        self.assertEqual(again["delta_sha256"],
                         delta._delta_self_hash(again))

    def test_delta_check_standalone_and_against_baseline(self):
        v1, v2, *_ = self.build_versions()
        d1_dir, d2_dir = self.export(v1), self.export(v2)
        out = os.path.join(self.tmp, "delta")
        delta.build_delta(d1_dir, d2_dir, out)
        meta = delta.check_delta(out)
        self.assertEqual(meta["to_version"], v2)
        # matching baseline accepted
        self.assertIs(delta.check_delta(out, d1_dir) is meta or True, True)
        # wrong baseline (target release instead of start) rejected
        with self.assertRaises(delta.DeltaError) as cx:
            delta.check_delta(out, d2_dir)
        self.assertIn("requires version", str(cx.exception))

    def test_build_refuses_invalid_or_same_exports(self):
        v1, v2, *_ = self.build_versions()
        d1_dir, d2_dir = self.export(v1), self.export(v2)
        with self.assertRaises(delta.DeltaError):
            delta.build_delta(d1_dir, d1_dir, os.path.join(self.tmp, "x"))
        bogus = os.path.join(self.tmp, "bogus")
        os.makedirs(bogus)
        with open(os.path.join(bogus, "manifest.json"), "w") as fh:
            fh.write("{not json")
        with self.assertRaises(delta.DeltaError):
            delta.build_delta(bogus, d2_dir, os.path.join(self.tmp, "y"))

    # ---------------------------------------------------------------- apply
    def test_apply_produces_directory_equal_to_full_export(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        pkg = os.path.join(self.tmp, "delta")
        delta.build_delta(full_v1, full_v2, pkg)

        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)
        result = delta.apply_delta(pkg, mirror)
        self.assertEqual((result["from_version"], result["to_version"]), (v1, v2))
        # passes the ORIGINAL full-export verifier
        self.assertEqual(verifier.verify_export(mirror), [])
        # and is byte-identical to a full export of the target
        self._assert_dirs_equal(mirror, full_v2)
        cmp = filecmp.dircmp(mirror, full_v2)
        self.assertEqual(cmp.diff_files, [])

    def _assert_dirs_equal(self, a, b):
        da, db = set(), set()
        for root, _, files in os.walk(a):
            for f in files:
                da.add(os.path.relpath(os.path.join(root, f), a))
        for root, _, files in os.walk(b):
            for f in files:
                db.add(os.path.relpath(os.path.join(root, f), b))
        self.assertEqual(da, db)
        for rel in da:
            self.assertTrue(filecmp.cmp(os.path.join(a, rel),
                                        os.path.join(b, rel), shallow=False),
                            f"content differs: {rel}")

    def test_reapply_completed_delta_is_idempotent(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        pkg = os.path.join(self.tmp, "delta")
        delta.build_delta(full_v1, full_v2, pkg)

        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v2, mirror)  # already at target
        result = delta.apply_delta(pkg, mirror)
        self.assertTrue(result["already_applied"])
        self._assert_dirs_equal(mirror, full_v2)

        # corrupt a bucket after completion: re-apply must NOT silently repair
        # it -- the mirror fails verification and the error is clear
        p = os.path.join(mirror, "buckets", "B1.txt")
        with open(p, "rb") as fh:
            raw = fh.read()
        with open(p, "wb") as fh:
            fh.write(raw.replace(b":1\n", b":9\n", 1))
        with self.assertRaises(delta.DeltaError) as cx:
            delta.apply_delta(pkg, mirror)
        self.assertIn("verification", str(cx.exception))
        # restore, idempotent apply works again
        with open(p, "wb") as fh:
            fh.write(raw)
        self.assertTrue(delta.apply_delta(pkg, mirror)["already_applied"])

    def test_wrong_baseline_blocks_application_before_any_change(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        # build a genuinely different third release as the wrong mirror
        core.ingest_batch(self.conn, "third", pw_with_prefix("E1", 1, tag="e"))
        v3 = self.publish(k=1)
        full_v3 = self.export(v3)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v3, mirror)
        mp = os.path.join(mirror, "manifest.json")
        with open(mp, "rb") as fh:
            before = fh.read()
        with self.assertRaises(delta.DeltaError) as cx:
            delta.apply_delta(pkg, mirror)
        self.assertIn(str(v1), str(cx.exception))
        # mirror untouched: still the valid v3 release
        self.assertEqual(verifier.verify_export(mirror), [])
        with open(mp, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))

    def test_corrupt_baseline_mirror_rejected(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)
        # tamper with a baseline bucket without touching the manifest
        p = os.path.join(mirror, "buckets", "B1.txt")
        with open(p, "a") as fh:
            fh.write("F" * 38 + ":7\n")
        with self.assertRaises(delta.DeltaError) as cx:
            delta.apply_delta(pkg, mirror)
        self.assertIn("verification", str(cx.exception))
        # still the (corrupt) original, not upgraded
        self.assertEqual(read_json(os.path.join(mirror, "manifest.json"))["version"], v1)

    def test_tampered_delta_is_rejected(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        def expect_rejected():
            with self.assertRaises(delta.DeltaError):
                delta.check_delta(pkg)
            with self.assertRaises(delta.DeltaError):
                delta.apply_delta(pkg, mirror)

        # 1. alter a carried payload
        p = os.path.join(pkg, "payloads", "modified", "A1.txt")
        with open(p, "rb") as fh:
            raw = fh.read()
        with open(p, "wb") as fh:
            fh.write(raw.replace(b":1\n", b":8\n", 1))
        expect_rejected()
        with open(p, "wb") as fh:
            fh.write(raw)
        self.assertEqual(delta.check_delta(pkg)["to_version"], v2)

        # 2. remove a payload (missing content)
        os.unlink(os.path.join(pkg, "payloads", "added", "D1.txt"))
        expect_rejected()

        # rebuild, then tamper with metadata (deleted-list forgery):
        # the descriptor self-hash is the first line of defense
        pkg2 = os.path.join(self.tmp, "d2")
        delta.build_delta(full_v1, full_v2, pkg2)
        dj = os.path.join(pkg2, "delta.json")
        forged = read_json(dj)
        forged["deleted"]["B1"] = forged["deleted"].get("C1")  # claim B1 deleted
        with open(dj, "w") as fh:
            json.dump(forged, fh, indent=2, sort_keys=True)
        with self.assertRaises(delta.DeltaError) as cx:
            delta.check_delta(pkg2)
        self.assertIn("delta_sha256", str(cx.exception))

        # defense in depth: even a mis-partitioned descriptor with a valid
        # self hash (e.g. produced by a buggy generator) must be rejected
        meta = read_json(os.path.join(pkg, "delta.json"))
        del meta["deleted"]["C1"]
        meta["delta_sha256"] = delta._delta_self_hash(meta)
        bogus = os.path.join(self.tmp, "d-bogus")
        shutil.copytree(pkg, bogus)
        with open(os.path.join(bogus, "delta.json"), "w") as fh:
            json.dump(meta, fh, indent=2, sort_keys=True)
        with self.assertRaises(delta.DeltaError) as cx:
            delta.check_delta(bogus)
        self.assertIn("partition", str(cx.exception))

        # 3. flip the target manifest hash binding but keep self hash stale
        pkg3 = os.path.join(self.tmp, "d3")
        delta.build_delta(full_v1, full_v2, pkg3)
        dj = os.path.join(pkg3, "delta.json")
        forged = read_json(dj)
        forged["to_manifest_sha256"] = "0" * 64
        with open(dj, "w") as fh:
            json.dump(forged, fh, indent=2, sort_keys=True)
        with self.assertRaises(delta.DeltaError) as cx:
            delta.check_delta(pkg3)
        self.assertIn("delta_sha256", str(cx.exception))

    # ------------------------------------------------------- crash recovery
    def test_interrupted_apply_resumes_forward(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        events = []

        def boom(event):
            events.append(event)
            if event == "buckets-switched":
                raise KeyboardInterrupt("simulated power loss mid-switch")

        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        # journal + stage survive; mirror is in the middle of the switch
        self.assertTrue(os.path.isfile(os.path.join(mirror, delta.JOURNAL_NAME)))
        journal = read_json(os.path.join(mirror, delta.JOURNAL_NAME))
        self.assertEqual(journal["state"], "prepared")

        # resume forward: ends exactly at the full target export
        result = delta.apply_delta(pkg, mirror)
        self.assertFalse(result.get("already_applied"))
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v2)
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))
        self.assertFalse(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))

    def test_interrupted_after_target_installed_rolls_back(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        # crash in the window AFTER the target manifest was published but
        # BEFORE the journal records 'switched' -- it still says 'prepared'
        def boom(event):
            if event == "manifest-written":
                raise KeyboardInterrupt("simulated crash after switch")

        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        journal = read_json(os.path.join(mirror, delta.JOURNAL_NAME))
        self.assertEqual(journal["state"], "prepared")
        # the mirror is nevertheless already a valid target export...
        self.assertEqual(verifier.verify_export(mirror), [])
        # ...a plain re-run resumes forward and finishes
        result = delta.apply_delta(pkg, mirror)
        self._assert_dirs_equal(mirror, full_v2)

        # redo: this time crash at the same window and roll back instead
        shutil.rmtree(mirror)
        shutil.copytree(full_v1, mirror)
        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        result = delta.apply_delta(pkg, mirror, rollback=True)
        self.assertTrue(result["rolled_back"])
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v1)
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))
        self.assertFalse(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))

    def test_rollback_before_switch_restores_baseline(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        def boom(event):
            if event == "prepared":
                raise KeyboardInterrupt("crashed before touching buckets")

        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        # buckets never moved in 'prepared': rollback just removes bookkeeping
        result = delta.apply_delta(pkg, mirror, rollback=True)
        self.assertTrue(result["rolled_back"])
        self._assert_dirs_equal(mirror, full_v1)
        self.assertEqual(verifier.verify_export(mirror), [])

    # ---------------- crash after staging, before the journal is registered
    def test_unjournaled_stage_resumes_forward(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        def boom(event):
            if event == "stage-ready":
                raise KeyboardInterrupt("power lost before journal registration")

        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        # staged but never registered: orphan stage, no journal, mirror intact
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))
        self.assertTrue(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))
        self.assertEqual(verifier.verify_export(mirror), [])
        self.assertEqual(
            read_json(os.path.join(mirror, "manifest.json"))["manifest_sha256"],
            read_json(os.path.join(full_v1, "manifest.json"))["manifest_sha256"])

        # a plain re-run discards the orphan and completes the same switch
        result = delta.apply_delta(pkg, mirror)
        self.assertFalse(result.get("already_applied"))
        self.assertEqual((result["from_version"], result["to_version"]), (v1, v2))
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v2)
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))
        self.assertFalse(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))

    def test_unjournaled_stage_rollback_cleans_up_without_misreporting(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        def boom(event):
            if event == "stage-ready":
                raise KeyboardInterrupt("power lost before journal registration")

        with self.assertRaises(KeyboardInterrupt):
            delta.apply_delta(pkg, mirror, progress=boom)
        self.assertTrue(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))

        result = delta.apply_delta(pkg, mirror, rollback=True)
        # the switch never began: nothing was rolled back...
        self.assertFalse(result["rolled_back"])
        self.assertTrue(result["nothing_to_roll_back"])
        self.assertTrue(result["orphan_stage_removed"])
        # ...and no orphaned staging directory is left behind
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.STAGE_NAME)))
        self.assertFalse(os.path.exists(os.path.join(mirror, delta.JOURNAL_NAME)))
        # the mirror is still exactly the valid start release
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v1)

    def test_unjournaled_partial_stage_with_hardlinks_resumes_forward(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        # emulate an orphaned stage exactly as staging leaves it: baseline
        # backups hard-linked to the live buckets, a partial staged payload
        stage = os.path.join(mirror, delta.STAGE_NAME)
        os.makedirs(os.path.join(stage, "new"))
        os.makedirs(os.path.join(stage, "old"))
        try:
            os.link(os.path.join(mirror, "buckets", "A1.txt"),
                    os.path.join(stage, "old", "A1.txt"))
        except OSError:  # filesystem without hard links
            shutil.copyfile(os.path.join(mirror, "buckets", "A1.txt"),
                            os.path.join(stage, "old", "A1.txt"))
        with open(os.path.join(stage, "new", "A1.txt"), "wb") as fh:
            fh.write(b"partial garbage")

        result = delta.apply_delta(pkg, mirror)
        self.assertEqual((result["from_version"], result["to_version"]), (v1, v2))
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v2)
        self.assertFalse(os.path.isdir(os.path.join(mirror, delta.STAGE_NAME)))

    def test_rollback_on_clean_mirror_reports_nothing_to_do(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        result = delta.apply_delta(pkg, mirror, rollback=True)
        self.assertFalse(result["rolled_back"])
        self.assertTrue(result["nothing_to_roll_back"])
        self.assertFalse(result["orphan_stage_removed"])
        self.assertEqual(verifier.verify_export(mirror), [])
        self._assert_dirs_equal(mirror, full_v1)

        # the CLI says the same and still exits 0
        env = dict(os.environ, PYTHONPATH="/workspace")
        r = subprocess.run(
            [sys.executable, "-m", "pwncorpus.delta", "apply", pkg, mirror,
             "--rollback"],
            capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nothing to roll back", r.stdout)
        self.assertNotIn("rolled back to", r.stdout)

    def test_foreign_journal_rejected(self):
        v1, v2, *_ = self.build_versions()
        # a third release for a different delta
        more = pw_with_prefix("E1", 1, tag="e1")
        core.ingest_batch(self.conn, "third", more)
        v3 = self.publish(k=1)
        d1, d2, d3 = self.export(v1), self.export(v2), self.export(v3)
        pkg12 = os.path.join(self.tmp, "p12")
        pkg13 = os.path.join(self.tmp, "p13")
        delta.build_delta(d1, d2, pkg12)
        delta.build_delta(d1, d3, pkg13)
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(d1, mirror)

        def boom(event):
            if event == "prepared":
                raise RuntimeError("stop")

        with self.assertRaises(RuntimeError):
            delta.apply_delta(pkg12, mirror, progress=boom)
        # resuming with a different package is a clear error
        with self.assertRaises(delta.DeltaError) as cx:
            delta.apply_delta(pkg13, mirror)
        self.assertIn("DIFFERENT delta", str(cx.exception))
        # the original package still resumes correctly
        delta.apply_delta(pkg12, mirror)
        self._assert_dirs_equal(mirror, d2)

    def test_missing_payload_detected_at_apply_time(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)
        # check_delta is already expected to catch this; emulate payload loss
        # after validation by deleting the staged-new file mid-run is not
        # reachable, so simply assert validate reports the missing payload.
        os.unlink(os.path.join(pkg, "payloads", "modified", "A1.txt"))
        with self.assertRaises(delta.DeltaError) as cx:
            delta.apply_delta(pkg, mirror)
        self.assertIn("missing payload", str(cx.exception))
        self.assertEqual(verifier.verify_export(mirror), [])  # untouched

    # ----------------------------------------------------------------- cli
    def test_cli_delta_module_build_check_apply(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        pkg = os.path.join(self.tmp, "pkg")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)
        env = dict(os.environ, PYTHONPATH="/workspace")

        def run(*args):
            return subprocess.run(
                [sys.executable, "-m", "pwncorpus.delta", *args],
                capture_output=True, text=True, env=env)

        r = run("build", full_v1, full_v2, pkg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("added 1", r.stdout)

        r = run("check", pkg, "--baseline", mirror)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("baseline matches", r.stdout)

        r = run("apply", pkg, mirror)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("applied", r.stdout)
        self._assert_dirs_equal(mirror, full_v2)

        r = run("apply", pkg, mirror)  # idempotent
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already at", r.stdout)

        # tamper -> non-zero exit, clear message
        os.unlink(os.path.join(pkg, "payloads", "added", "D1.txt"))
        r = run("check", pkg)
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL", r.stderr)

    def test_cli_delta_generate_from_db(self):
        v1, v2, *_ = self.build_versions()
        full_v2 = self.export(v2)
        pkg = os.path.join(self.tmp, "pkg-db")
        env = dict(os.environ, PYTHONPATH="/workspace")
        r = subprocess.run(
            [sys.executable, "-m", "pwncorpus.cli", "--db", self.db_path,
             "delta-generate", "--from-version", str(v1),
             "--to-version", str(v2), "--out", pkg],
            capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        meta = delta.check_delta(pkg)
        self.assertEqual((meta["from_version"], meta["to_version"]), (v1, v2))

        # apply to a v1 export mirror, reach byte-identical v2
        full_v1 = self.export(v1)
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)
        delta.apply_delta(pkg, mirror)
        self._assert_dirs_equal(mirror, full_v2)

    # ----------------------------------------------- deleted bucket rollback
    def test_rollback_restores_deleted_buckets(self):
        v1, v2, *_ = self.build_versions()
        full_v1, full_v2 = self.export(v1), self.export(v2)
        delta.build_delta(full_v1, full_v2, os.path.join(self.tmp, "d"))
        pkg = os.path.join(self.tmp, "d")
        mirror = os.path.join(self.tmp, "mirror")
        shutil.copytree(full_v1, mirror)

        def boom(event):
            if event == "manifest-written":
                raise RuntimeError("x")

        with self.assertRaises(RuntimeError):
            delta.apply_delta(pkg, mirror, progress=boom)
        self.assertFalse(os.path.isfile(
            os.path.join(mirror, "buckets", "C1.txt")))  # deleted during switch
        delta.apply_delta(pkg, mirror, rollback=True)
        self.assertTrue(os.path.isfile(
            os.path.join(mirror, "buckets", "C1.txt")))
        self._assert_dirs_equal(mirror, full_v1)


if __name__ == "__main__":
    unittest.main()
