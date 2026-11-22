import json
import os
import tempfile
import unittest
import jsonschema
from pathlib import Path
from unittest.mock import patch

import posix_containment as containment


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.root.mkdir()
        containment.initialize_sandbox(self.root)
        self.target = self.root / "sample.txt"
        self.target.write_bytes(b"controlled test fixture\n")

    def tearDown(self):
        self.temp.cleanup()

    def approve(self, plan):
        loaded = containment.read_json(plan)
        response = "APPROVE " + loaded["plan_sha256"]
        with patch("builtins.input", return_value=response):
            result = containment.approve_plan(plan)
        self.assertEqual(result["status"], "approved")

    def test_inspect_is_read_only_and_reports_regular_file_digest(self):
        before = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*"))
        result = containment.inspect_root(self.root)
        after = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*"))
        self.assertEqual(before, after)
        self.assertFalse(result["host_mutations_performed"])
        self.assertEqual(result["regular_files_observed"], 2)
        self.assertIn("sample.txt", [item["path"] for item in result["entries"]])

    def test_prepare_creates_plan_and_snapshot_without_moving_target(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.assertTrue(self.target.exists())
        loaded = containment.read_json(plan)
        snapshot = self.root / loaded["snapshot_relative"]
        self.assertTrue(snapshot.exists())
        self.assertEqual(snapshot.read_bytes(), self.target.read_bytes())
        self.assertEqual(containment._validate_plan(loaded)["operation"], "quarantine")

    def test_apply_requires_explicit_plan_bound_approval(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertTrue(self.target.exists())

    def test_wrong_approval_does_not_authorize_mutation(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        with self.assertRaises(containment.ContainmentError):
            containment.approve_plan(plan, response="APPROVE wrong-hash")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertTrue(self.target.exists())

    def test_tampered_plan_is_rejected(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        value = containment.read_json(plan)
        value["destination_relative"] = "other.txt"
        plan.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(containment.ContainmentError):
            containment.show_plan(plan)

    def test_changed_source_after_prepare_is_not_moved(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        self.target.write_bytes(b"changed after plan")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertEqual(self.target.read_bytes(), b"changed after plan")

    def test_symlink_target_is_rejected(self):
        link = self.root / "link.txt"
        link.symlink_to(self.target)
        with self.assertRaises(containment.ContainmentError):
            containment.prepare_quarantine(self.root, "link.txt")

    def test_path_traversal_is_rejected(self):
        with self.assertRaises(containment.ContainmentError):
            containment.prepare_quarantine(self.root, "../outside.txt")

    def test_hard_link_target_is_rejected(self):
        linked = self.root / "linked.txt"
        os.link(self.target, linked)
        with self.assertRaises(containment.ContainmentError):
            containment.prepare_quarantine(self.root, "sample.txt")

    def test_full_quarantine_and_separately_approved_rollback(self):
        original = self.target.read_bytes()
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        applied = containment.apply_plan(plan)
        self.assertEqual(applied["status"], "applied_unverified")
        self.assertFalse(self.target.exists())
        verified = containment.verify_plan(plan)
        self.assertEqual(verified["status"], "verified")
        recorded = containment.record_outcome(plan)
        self.assertEqual(recorded["status"], "recorded")

        restore_plan = containment.prepare_rollback(plan)
        self.approve(restore_plan)
        restore_applied = containment.apply_plan(restore_plan)
        self.assertEqual(restore_applied["status"], "applied_unverified")
        restore_verified = containment.verify_plan(restore_plan)
        self.assertEqual(restore_verified["status"], "verified")
        containment.record_outcome(restore_plan)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.target.read_bytes(), original)

    def test_record_is_blocked_before_verified_apply(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        with self.assertRaises(containment.ContainmentError):
            containment.record_outcome(plan)
        self.assertTrue(self.target.exists())

    def test_restore_plan_refuses_occupied_original_path(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        containment.apply_plan(plan)
        containment.verify_plan(plan)
        containment.record_outcome(plan)
        self.target.write_bytes(b"operator-created file")
        with self.assertRaises(containment.ContainmentError):
            containment.prepare_rollback(plan)
        self.assertEqual(self.target.read_bytes(), b"operator-created file")


    def test_unmarked_root_cannot_be_used_for_containment(self):
        unmarked = self.root.parent / "unmarked"
        unmarked.mkdir()
        (unmarked / "sample.txt").write_text("not opted in", encoding="utf-8")
        with self.assertRaises(containment.ContainmentError):
            containment.prepare_quarantine(unmarked, "sample.txt")

    def test_sandbox_initialization_requires_empty_directory(self):
        nonempty = self.root.parent / "nonempty"
        nonempty.mkdir()
        (nonempty / "keep.txt").write_text("keep", encoding="utf-8")
        with self.assertRaises(containment.ContainmentError):
            containment.initialize_sandbox(nonempty)

    def test_system_directory_cannot_be_initialized(self):
        with self.assertRaises(containment.ContainmentError):
            containment.initialize_sandbox(Path("/etc"))


    def test_existing_quarantine_destination_is_never_overwritten(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        loaded = containment.read_json(plan)
        destination = self.root / loaded["destination_relative"]
        destination.write_bytes(b"pre-existing destination")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertTrue(self.target.exists())
        self.assertEqual(destination.read_bytes(), b"pre-existing destination")

    def test_tampered_rollback_snapshot_blocks_apply(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        loaded = containment.read_json(plan)
        snapshot = self.root / loaded["snapshot_relative"]
        snapshot.write_bytes(b"tampered snapshot")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertTrue(self.target.exists())


    def test_rollback_restores_from_prechange_snapshot_not_quarantine_copy(self):
        original = self.target.read_bytes()
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        containment.apply_plan(plan)
        containment.verify_plan(plan)
        containment.record_outcome(plan)
        loaded = containment.read_json(plan)
        quarantined = self.root / loaded["destination_relative"]
        quarantined.write_bytes(b"quarantine copy altered")
        restore_plan = containment.prepare_rollback(plan)
        self.approve(restore_plan)
        containment.apply_plan(restore_plan)
        self.assertEqual(containment.verify_plan(restore_plan)["status"], "verified")
        containment.record_outcome(restore_plan)
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual(quarantined.read_bytes(), b"quarantine copy altered")


    def test_generated_plan_approval_and_record_match_versioned_schemas(self):
        schemas_dir = Path(__file__).resolve().parents[1] / "schemas"

        def validate(schema_name, instance):
            schema = json.loads((schemas_dir / schema_name).read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            )
            validator.validate(instance)

        plan_path = containment.prepare_quarantine(self.root, "sample.txt")
        plan = containment.read_json(plan_path)
        validate("containment-plan.schema.json", plan)

        self.approve(plan_path)
        approval_path = self.root / containment.STATE_DIR / "approvals" / (plan["operation_id"] + ".json")
        validate("containment-approval.schema.json", containment.read_json(approval_path))

        containment.apply_plan(plan_path)
        record_result = containment.record_outcome(plan_path)
        record_path = self.root / record_result["record"]
        validate("containment-record.schema.json", containment.read_json(record_path))


    def test_type_confused_plan_operation_is_rejected(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        value = containment.read_json(plan)
        value["operation"] = []
        plan.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(containment.ContainmentError):
            containment.show_plan(plan)

    def test_modified_approval_cannot_authorize_plan(self):
        plan = containment.prepare_quarantine(self.root, "sample.txt")
        self.approve(plan)
        loaded = containment.read_json(plan)
        approval_path = self.root / containment.STATE_DIR / "approvals" / (loaded["operation_id"] + ".json")
        approval = containment.read_json(approval_path)
        approval["plan_sha256"] = "0" * 64
        approval_path.write_text(json.dumps(approval), encoding="utf-8")
        with self.assertRaises(containment.ContainmentError):
            containment.apply_plan(plan)
        self.assertTrue(self.target.exists())


if __name__ == "__main__":
    unittest.main()
