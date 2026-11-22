# posix-containment-kit

Local POSIX host inspection and operator-authorized reversible containment toolkit.

## Responsibility

The kit is intended to inspect the local host, generate transparent containment plans, prepare rollback state before changes, and support apply, verify, and rollback stages only after explicit operator approval.

## Safety boundary

- Read-only inspection must not mutate host state.
- No remote host operations or network scanning.
- Every mutation must follow all seven stages in [CONTRACT.md](CONTRACT.md).
- Rollback data is prepared before mutation. Approval is tied to the exact plan.
- Unsupported platform operations must fail with clear diagnostics, not silently substitute behavior.

## Current status

**Lifecycle: planned.** No inspection engine, containment adapter, rollback implementation, or tests have yet been verified. See [COMPATIBILITY.json](COMPATIBILITY.json).

## Development

Prefer standard-library core behavior. Platform-specific commands and privilege requirements must be explicit and tested.
