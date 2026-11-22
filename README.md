# posix-containment-kit

Local POSIX inspection and sandbox-scoped, reversible file containment with explicit operator approval.

## Current prototype

The current implementation is deliberately narrow:

- Read-only inventory of regular files and SHA-256 digests.
- Explicit sandbox initialization. The root must be an empty directory and cannot be a protected system path.
- File quarantine restricted to regular files inside the initialized sandbox.
- Symlinks, special files, hard-linked files, path traversal, and pre-existing destinations are rejected.
- A pre-change snapshot and immutable plan are prepared before approval.
- Approval requires typing the exact plan SHA-256.
- Apply, verify, and outcome recording are separate stages.
- Rollback is a new separately approved plan that restores from the original pre-change snapshot. The quarantined copy is retained as evidence.

The engine is local and offline. It does not kill processes, change firewall or routing state, control system services, escalate privileges, or operate on unmarked directories.

## Quick start

Create a dedicated empty test directory. Do not point this at a system directory or a directory containing unrelated files.

```sh
mkdir -p /tmp/cas-xdp-lab
python3 posix_containment.py init-root /tmp/cas-xdp-lab
printf 'controlled sample\n' > /tmp/cas-xdp-lab/sample.txt
python3 posix_containment.py inspect /tmp/cas-xdp-lab
```

## Seven-stage quarantine

```sh
# 1. Inspect current state
python3 posix_containment.py inspect /tmp/cas-xdp-lab

# 2. Generate plan and prepare rollback snapshot
python3 posix_containment.py prepare /tmp/cas-xdp-lab sample.txt
# Copy the plan path printed by the command into PLAN below.

# 3. Display the proposed impact
python3 posix_containment.py show PLAN

# 4. Explicitly approve the exact displayed plan
python3 posix_containment.py approve PLAN
# Type the full APPROVE <plan_sha256> phrase when prompted.

# 5. Apply only the approved plan
python3 posix_containment.py apply PLAN

# 6. Verify the result
python3 posix_containment.py verify PLAN

# 7. Record the verified outcome and rollback reference
python3 posix_containment.py record PLAN
```

## Separately approved rollback

```sh
python3 posix_containment.py prepare-rollback PLAN
# Use the new restore plan path printed by the command.
python3 posix_containment.py show RESTORE_PLAN
python3 posix_containment.py approve RESTORE_PLAN
python3 posix_containment.py apply RESTORE_PLAN
python3 posix_containment.py verify RESTORE_PLAN
python3 posix_containment.py record RESTORE_PLAN
```

Rollback restores bytes from the pre-change snapshot and leaves the quarantined copy in place as retained evidence. The operator can inspect and manage that retained copy separately. The tool does not delete it automatically.

## State and schemas

The sandbox-local `.cas-xdp-state/` directory stores plans, snapshots, quarantine files, approvals, and outcome records. It is created with restrictive directory permissions.

- `schemas/containment-plan.schema.json`
- `schemas/containment-approval.schema.json`
- `schemas/containment-record.schema.json`
- `schemas/compatibility.schema.json`

## Tests

```sh
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
```

## Limitations

This is a prototype, not a production endpoint security product. Approval files and plan hashes protect against accidental plan drift, not a privileged local attacker who can alter the sandbox state. Filesystem races with a concurrent hostile writer are not fully eliminated on every POSIX filesystem. Snapshot metadata preservation is limited to file mode and timestamps; ownership, ACLs, extended attributes, and filesystem-specific metadata are not guaranteed. A no-replace hard-link move is required; if the filesystem does not support it, the operation is blocked without a fallback.

See [SECURITY.md](SECURITY.md) and [CONTRACT.md](CONTRACT.md).
