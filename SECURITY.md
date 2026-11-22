# Security Model

## Scope

The prototype supports read-only local inventory and a reversible regular-file quarantine workflow inside an explicitly initialized empty sandbox root. It is not designed for production host containment.

## Mutation gate

Every quarantine and restore operation follows the contract's seven stages:

1. Inspect the current state.
2. Prepare a versioned plan and verified pre-change snapshot.
3. Display impact and rollback details.
4. Require exact typed approval bound to the plan SHA-256.
5. Apply only the approved plan.
6. Verify the source, destination, and snapshot state.
7. Record the verified outcome and rollback reference.

Restore is a separate plan and requires separate approval. No `--confirm` bypass exists.

## Guardrails

- Mutations require the explicit `.cas-xdp-sandbox` marker created in an empty, non-system directory.
- Paths are relative to the root. Traversal, symlinks, special files, and files with multiple hard links are rejected.
- Only regular files are supported.
- Existing destinations are never overwritten. Apply uses a no-replace hard-link move and blocks if the filesystem does not support it.
- The source identity and digest are rechecked before apply.
- The pre-change snapshot is prepared and verified before approval.
- Rollback restores from the original snapshot and retains the quarantined copy as evidence.
- The tool performs no network access, privilege escalation, process termination, firewall/routing change, or system-service control.

## Limitations

- The approval record is a local workflow guard, not a cryptographic authorization token. A privileged local attacker can alter files in the sandbox state directory.
- Plan SHA-256 detects accidental plan drift but does not authenticate the plan author.
- Concurrent hostile filesystem writers can still create race conditions between path validation and filesystem operations. The prototype does not claim race-free confinement against a same-host adversary.
- File mode and timestamps are preserved in snapshots; ownership, ACLs, extended attributes, alternate data streams, and filesystem-specific metadata are not guaranteed.
- Hard-link based no-replace moves are filesystem-dependent. Unsupported behavior blocks; there is no silent fallback.
- Crash recovery and partial-operation recovery are operator-guided. Inspect both source and destination paths if an apply reports a partial move.
- No process, service, firewall, route, socket, or interface containment is implemented.
