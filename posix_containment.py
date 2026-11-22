#!/usr/bin/env python3
"""Sandbox-scoped POSIX file containment with an explicit approval gate.

The prototype is local and offline. It does not kill processes, alter firewall
or routing state, escalate privileges, or operate outside a configured root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"
STATE_DIR = ".cas-xdp-state"
PLAN_KEYS = {
    "schema_version", "operation_id", "operation", "root",
    "source_relative", "destination_relative", "target_relative",
    "artifact_sha256", "size_bytes", "source_identity",
    "snapshot_relative", "snapshot_sha256", "prepared_at",
    "related_operation_id", "plan_sha256",
}


class ContainmentError(ValueError):
    """Raised when a local containment stage cannot safely proceed."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _unique_object(pairs: List[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContainmentError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContainmentError("cannot read JSON file " + str(path) + ": " + str(exc))


def write_json_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ContainmentError("state directory must not be a symlink")
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise ContainmentError("refusing to overwrite existing state file: " + str(path))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise ContainmentError("cannot read file " + str(path) + ": " + str(exc))
    return digest.hexdigest()


def _root_path(value: Path) -> Path:
    if value.is_symlink():
        raise ContainmentError("configured root must not be a symlink")
    try:
        root = value.resolve(strict=True)
    except OSError as exc:
        raise ContainmentError("configured root is unavailable: " + str(exc))
    if not root.is_dir():
        raise ContainmentError("configured root must be an existing directory")
    return root


def _relative_path(value: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ContainmentError("target must be a non-empty relative path without '.' or '..' components")
    return path


def _safe_path(root: Path, relative: str, allow_missing: bool = False) -> Path:
    rel = _relative_path(relative)
    current = root
    for index, part in enumerate(rel.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing and index == len(rel.parts) - 1:
                break
            raise ContainmentError("path component does not exist: " + str(current))
        except OSError as exc:
            raise ContainmentError("cannot inspect path component " + str(current) + ": " + str(exc))
        if stat.S_ISLNK(info.st_mode):
            raise ContainmentError("symlinks are not accepted: " + str(current))
    try:
        resolved_parent = current.parent.resolve(strict=True)
    except OSError as exc:
        raise ContainmentError("path parent is unavailable: " + str(exc))
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ContainmentError("path escapes the configured root")
    if current.exists() and (current.resolve(strict=True) != root and root not in current.resolve(strict=True).parents):
        raise ContainmentError("path escapes the configured root")
    return current


def _file_identity(info: os.stat_result) -> Dict[str, int]:
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size_bytes": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mode": int(stat.S_IMODE(info.st_mode)),
        "link_count": int(info.st_nlink),
    }


def _require_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ContainmentError("cannot inspect target: " + str(exc))
    if not stat.S_ISREG(info.st_mode):
        raise ContainmentError("only regular files can be quarantined")
    if info.st_nlink != 1:
        raise ContainmentError("files with multiple hard links are not accepted")
    return info


def _state_paths(root: Path, create: bool = False) -> Dict[str, Path]:
    state = root / STATE_DIR
    if state.is_symlink():
        raise ContainmentError("state directory must not be a symlink")
    paths = {
        "state": state,
        "plans": state / "plans",
        "snapshots": state / "snapshots",
        "rollback_snapshots": state / "rollback-snapshots",
        "quarantine": state / "quarantine",
        "approvals": state / "approvals",
        "records": state / "records",
    }
    if create:
        for directory in paths.values():
            if directory == state or directory.parent == state:
                directory.mkdir(mode=0o700, exist_ok=True)
                if directory.is_symlink() or not directory.is_dir():
                    raise ContainmentError("unsafe state directory: " + str(directory))
    return paths


def _copy_snapshot(source: Path, destination: Path, expected_identity: Dict[str, int]) -> tuple[str, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(source), flags)
    except OSError as exc:
        raise ContainmentError("cannot open source without following symlinks: " + str(exc))
    digest = hashlib.sha256()
    size = 0
    try:
        opened_info = os.fstat(descriptor)
        if _file_identity(opened_info) != expected_identity:
            raise ContainmentError("source changed before rollback snapshot could be prepared")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with os.fdopen(descriptor, "rb") as source_handle:
            descriptor = -1
            with destination.open("xb") as snapshot_handle:
                while True:
                    chunk = source_handle.read(1024 * 1024)
                    if not chunk:
                        break
                    snapshot_handle.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                snapshot_handle.flush()
                os.fsync(snapshot_handle.fileno())
            after_info = os.fstat(source_handle.fileno())
            if _file_identity(after_info) != expected_identity:
                destination.unlink(missing_ok=True)
                raise ContainmentError("source changed while rollback snapshot was being prepared")
        os.chmod(destination, stat.S_IMODE(opened_info.st_mode))
        os.utime(destination, ns=(opened_info.st_atime_ns, opened_info.st_mtime_ns))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest(), size


def _plan_hash(plan: Dict[str, Any]) -> str:
    unsigned = {key: value for key, value in plan.items() if key != "plan_sha256"}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def _seal_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    plan["plan_sha256"] = _plan_hash(plan)
    return plan


def _validate_plan(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PLAN_KEYS:
        raise ContainmentError("plan has an invalid shape")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ContainmentError("unsupported plan schema version")
    if value["operation"] not in {"quarantine", "restore"}:
        raise ContainmentError("unsupported plan operation")
    if value["plan_sha256"] != _plan_hash(value):
        raise ContainmentError("plan integrity check failed")
    if not isinstance(value["source_identity"], dict):
        raise ContainmentError("plan source identity is invalid")
    if not isinstance(value["artifact_sha256"], str) or len(value["artifact_sha256"]) != 64:
        raise ContainmentError("plan digest is invalid")
    if isinstance(value["size_bytes"], bool) or not isinstance(value["size_bytes"], int) or value["size_bytes"] < 0:
        raise ContainmentError("plan size is invalid")
    return value


def _load_plan(path: Path) -> tuple[Dict[str, Any], Path, Dict[str, Path]]:
    raw = read_json(path)
    plan = _validate_plan(raw)
    root = _root_path(Path(plan["root"]))
    state = _state_paths(root)
    expected_path = state["plans"] / (plan["operation_id"] + ".json")
    if path.resolve(strict=True) != expected_path.resolve(strict=True):
        raise ContainmentError("plan must be loaded from its configured state directory")
    return plan, root, state


def _snapshot_path(root: Path, relative: str) -> Path:
    path = _safe_path(root, relative)
    if not path.is_file() or path.is_symlink():
        raise ContainmentError("rollback snapshot is unavailable or unsafe")
    return path


def _create_plan(
    root: Path,
    operation: str,
    source_relative: str,
    destination_relative: str,
    target_relative: str,
    snapshot_directory: str,
    related_operation_id: str,
) -> Path:
    source = _safe_path(root, source_relative)
    info = _require_regular_file(source)
    identity = _file_identity(info)
    source_digest = sha256_file(source)
    operation_id = str(uuid.uuid4())
    state = _state_paths(root, create=True)
    snapshot_relative = (Path(STATE_DIR) / snapshot_directory / (operation_id + ".snapshot")).as_posix()
    snapshot = _safe_path(root, snapshot_relative, allow_missing=True)
    snapshot_digest, snapshot_size = _copy_snapshot(source, snapshot, identity)
    if snapshot_digest != source_digest or snapshot_size != info.st_size:
        snapshot.unlink(missing_ok=True)
        raise ContainmentError("rollback snapshot does not match source bytes")

    plan = {
        "schema_version": SCHEMA_VERSION,
        "operation_id": operation_id,
        "operation": operation,
        "root": str(root),
        "source_relative": source_relative,
        "destination_relative": destination_relative,
        "target_relative": target_relative,
        "artifact_sha256": source_digest,
        "size_bytes": int(info.st_size),
        "source_identity": identity,
        "snapshot_relative": snapshot_relative,
        "snapshot_sha256": snapshot_digest,
        "prepared_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "related_operation_id": related_operation_id,
    }
    _seal_plan(plan)
    plan_path = state["plans"] / (operation_id + ".json")
    write_json_exclusive(plan_path, plan)
    return plan_path


def inspect_root(root_value: Path) -> Dict[str, Any]:
    """Inspect regular files without following symlinks or writing state."""
    root = _root_path(root_value)
    entries: List[Dict[str, Any]] = []
    skipped_symlinks = 0
    skipped_special = 0
    for current, directories, filenames in os.walk(str(root), followlinks=False):
        current_path = Path(current)
        kept_directories = []
        for name in directories:
            candidate = current_path / name
            if name == STATE_DIR and current_path == root:
                continue
            try:
                mode = candidate.lstat().st_mode
            except OSError:
                skipped_special += 1
                continue
            if stat.S_ISLNK(mode):
                skipped_symlinks += 1
            elif stat.S_ISDIR(mode):
                kept_directories.append(name)
            else:
                skipped_special += 1
        directories[:] = kept_directories
        for name in filenames:
            candidate = current_path / name
            try:
                info = candidate.lstat()
            except OSError:
                skipped_special += 1
                continue
            if stat.S_ISLNK(info.st_mode):
                skipped_symlinks += 1
                continue
            if not stat.S_ISREG(info.st_mode):
                skipped_special += 1
                continue
            try:
                digest = sha256_file(candidate)
                status = "observed"
            except ContainmentError:
                digest = None
                status = "unavailable"
            entries.append({
                "path": candidate.relative_to(root).as_posix(),
                "status": status,
                "size_bytes": int(info.st_size),
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "sha256": digest,
            })
    entries.sort(key=lambda item: item["path"])
    return {
        "mode": "read_only",
        "root": str(root),
        "host_mutations_performed": False,
        "regular_files_observed": len(entries),
        "symlinks_skipped": skipped_symlinks,
        "special_files_skipped": skipped_special,
        "entries": entries,
    }


def prepare_quarantine(root_value: Path, target_relative: str) -> Path:
    root = _root_path(root_value)
    target = _relative_path(target_relative)
    if STATE_DIR in target.parts:
        raise ContainmentError("the reserved containment state directory cannot be a target")
    source = _safe_path(root, target.as_posix())
    _require_regular_file(source)
    quarantine_relative = (Path(STATE_DIR) / "quarantine" / (str(uuid.uuid4()) + "-" + source.name)).as_posix()
    return _create_plan(
        root, "quarantine", target.as_posix(), quarantine_relative,
        target.as_posix(), "snapshots", "",
    )


def prepare_rollback(plan_path: Path) -> Path:
    original, root, state = _load_plan(plan_path)
    if original["operation"] != "quarantine":
        raise ContainmentError("rollback preparation requires an original quarantine plan")
    original_record_path = state["records"] / (original["operation_id"] + ".json")
    if not original_record_path.exists():
        raise ContainmentError("record the verified quarantine outcome before preparing rollback")
    original_record = read_json(original_record_path)
    if original_record.get("status") != "verified":
        raise ContainmentError("rollback preparation requires a verified quarantine outcome")

    target_path = _safe_path(root, original["target_relative"], allow_missing=True)
    if target_path.exists():
        raise ContainmentError("original target path is occupied; refusing to overwrite it")
    quarantine_path = _safe_path(root, original["destination_relative"])
    info = _require_regular_file(quarantine_path)
    if sha256_file(quarantine_path) != original["artifact_sha256"]:
        raise ContainmentError("quarantined file no longer matches the original plan")
    return _create_plan(
        root, "restore", original["destination_relative"], original["target_relative"],
        original["target_relative"], "rollback-snapshots", original["operation_id"],
    )


def show_plan(plan_path: Path) -> Dict[str, Any]:
    plan, root, _ = _load_plan(plan_path)
    if plan["operation"] == "quarantine":
        impact = "Move one regular file from the configured root into the local quarantine directory."
        rollback = "Restore the original bytes from the prepared snapshot through a separately approved restore plan."
    else:
        impact = "Move one quarantined regular file back to its original relative path."
        rollback = "A pre-restore snapshot of the quarantined bytes is stored before approval."
    return {
        "stage": "impact_review",
        "operation": plan["operation"],
        "operation_id": plan["operation_id"],
        "plan_sha256": plan["plan_sha256"],
        "root": str(root),
        "source": plan["source_relative"],
        "destination": plan["destination_relative"],
        "size_bytes": plan["size_bytes"],
        "sha256": plan["artifact_sha256"],
        "rollback_snapshot": plan["snapshot_relative"],
        "impact": impact,
        "rollback": rollback,
        "approval_required": "Type APPROVE " + plan["plan_sha256"] + " when prompted.",
        "no_mutation_performed": True,
    }


def approve_plan(plan_path: Path, response: Optional[str] = None) -> Dict[str, Any]:
    plan, root, state = _load_plan(plan_path)
    _print_json(show_plan(plan_path))
    expected = "APPROVE " + plan["plan_sha256"]
    if response is None:
        response = input("Enter exactly '" + expected + "' to authorize this one operation: ")
    if response.strip() != expected:
        raise ContainmentError("operator approval did not match the displayed plan hash")
    approval = {
        "schema_version": SCHEMA_VERSION,
        "operation_id": plan["operation_id"],
        "plan_sha256": plan["plan_sha256"],
        "approved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    approval_path = state["approvals"] / (plan["operation_id"] + ".json")
    write_json_exclusive(approval_path, approval)
    return {"status": "approved", "operation_id": plan["operation_id"], "plan_sha256": plan["plan_sha256"]}


def _require_approval(plan: Dict[str, Any], state: Dict[str, Path]) -> None:
    approval_path = state["approvals"] / (plan["operation_id"] + ".json")
    if not approval_path.exists():
        raise ContainmentError("explicit operator approval is required before apply")
    approval = read_json(approval_path)
    if (
        approval.get("operation_id") != plan["operation_id"]
        or approval.get("plan_sha256") != plan["plan_sha256"]
    ):
        raise ContainmentError("approval does not match this exact plan")


def apply_plan(plan_path: Path) -> Dict[str, Any]:
    plan, root, state = _load_plan(plan_path)
    _require_approval(plan, state)
    source = _safe_path(root, plan["source_relative"])
    destination = _safe_path(root, plan["destination_relative"], allow_missing=True)
    snapshot = _snapshot_path(root, plan["snapshot_relative"])
    source_info = _require_regular_file(source)
    if _file_identity(source_info) != plan["source_identity"]:
        raise ContainmentError("source file identity changed after plan preparation")
    if sha256_file(source) != plan["artifact_sha256"]:
        raise ContainmentError("source file bytes changed after plan preparation")
    if sha256_file(snapshot) != plan["snapshot_sha256"] or snapshot.stat().st_size != plan["size_bytes"]:
        raise ContainmentError("prepared rollback snapshot failed integrity verification")
    if destination.exists():
        raise ContainmentError("destination already exists; refusing to overwrite")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ContainmentError("destination parent must not be a symlink")
    if destination.parent.resolve(strict=True) != root and root not in destination.parent.resolve(strict=True).parents:
        raise ContainmentError("destination escapes configured root")
    os.replace(str(source), str(destination))
    if sha256_file(destination) != plan["artifact_sha256"]:
        raise ContainmentError("partial apply: moved file digest mismatch; retain plan and snapshot for recovery")
    return {
        "status": "applied_unverified",
        "operation_id": plan["operation_id"],
        "source": plan["source_relative"],
        "destination": plan["destination_relative"],
        "verification_required": True,
    }


def verify_plan(plan_path: Path) -> Dict[str, Any]:
    plan, root, _ = _load_plan(plan_path)
    source = _safe_path(root, plan["source_relative"], allow_missing=True)
    destination = _safe_path(root, plan["destination_relative"])
    snapshot = _snapshot_path(root, plan["snapshot_relative"])
    if source.exists():
        raise ContainmentError("verification failed: source path still exists")
    if not destination.is_file() or destination.is_symlink():
        raise ContainmentError("verification failed: destination is missing or not a regular file")
    if sha256_file(destination) != plan["artifact_sha256"]:
        raise ContainmentError("verification failed: destination digest mismatch")
    if sha256_file(snapshot) != plan["snapshot_sha256"]:
        raise ContainmentError("verification failed: rollback snapshot digest mismatch")
    return {
        "status": "verified",
        "operation_id": plan["operation_id"],
        "operation": plan["operation"],
        "artifact_sha256": plan["artifact_sha256"],
        "rollback_snapshot": plan["snapshot_relative"],
    }


def record_outcome(plan_path: Path) -> Dict[str, Any]:
    plan, root, state = _load_plan(plan_path)
    verification = verify_plan(plan_path)
    record = {
        "schema_version": SCHEMA_VERSION,
        "operation_id": plan["operation_id"],
        "operation": plan["operation"],
        "plan_sha256": plan["plan_sha256"],
        "status": verification["status"],
        "artifact_sha256": plan["artifact_sha256"],
        "target_relative": plan["target_relative"],
        "rollback_reference": plan["snapshot_relative"],
        "related_operation_id": plan["related_operation_id"],
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    record_path = state["records"] / (plan["operation_id"] + ".json")
    write_json_exclusive(record_path, record)
    return {"status": "recorded", "record": str(record_path.relative_to(root)), "verification": verification}


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="posix-containment-kit",
        description="Local sandbox-scoped POSIX file quarantine with staged approval and rollback.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect", help="read-only inventory of regular files under a root")
    inspect.add_argument("root", type=Path)

    prepare = commands.add_parser("prepare", help="prepare a quarantine plan and rollback snapshot")
    prepare.add_argument("root", type=Path)
    prepare.add_argument("target", help="target path relative to the configured root")

    show = commands.add_parser("show", help="display plan impact and rollback details")
    show.add_argument("plan", type=Path)

    approve = commands.add_parser("approve", help="display plan and request exact typed approval")
    approve.add_argument("plan", type=Path)

    apply = commands.add_parser("apply", help="apply an approved plan")
    apply.add_argument("plan", type=Path)

    verify = commands.add_parser("verify", help="verify the applied operation")
    verify.add_argument("plan", type=Path)

    record = commands.add_parser("record", help="record a verified outcome")
    record.add_argument("plan", type=Path)

    rollback = commands.add_parser("prepare-rollback", help="prepare a separately approved restore plan")
    rollback.add_argument("plan", type=Path)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            _print_json(inspect_root(args.root))
            return 0
        if args.command == "prepare":
            plan = prepare_quarantine(args.root, args.target)
            _print_json({"status": "prepared", "plan": str(plan), "impact": show_plan(plan)})
            return 0
        if args.command == "show":
            _print_json(show_plan(args.plan))
            return 0
        if args.command == "approve":
            _print_json(approve_plan(args.plan))
            return 0
        if args.command == "apply":
            _print_json(apply_plan(args.plan))
            return 0
        if args.command == "verify":
            _print_json(verify_plan(args.plan))
            return 0
        if args.command == "record":
            _print_json(record_outcome(args.plan))
            return 0
        if args.command == "prepare-rollback":
            plan = prepare_rollback(args.plan)
            _print_json({"status": "prepared", "plan": str(plan), "impact": show_plan(plan)})
            return 0
    except (ContainmentError, OSError) as exc:
        _print_json({"status": "blocked", "error": str(exc), "mutation_claim": "none unless apply reported partial apply"})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
