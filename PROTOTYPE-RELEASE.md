# Prototype Release Record

**Release stage:** Prototype candidate documentation complete  
**Lifecycle:** Prototype  
**Verified source commit:** `f8c29a6ed58528bc7863c852090f7c31f78246f3`  
**Evidence ceiling:** TIER-2  
**GitHub Release/tag:** Not published by this record

## Purpose

A local POSIX inspection and sandbox-scoped file containment prototype. Its narrow scope is intentional: regular files inside an explicitly initialized, operator-owned empty sandbox.

## Included capabilities

- Read-only inventory of regular files and SHA-256 digests.
- Empty sandbox initialization with protected-path checks.
- Reversible quarantine of eligible regular files within that sandbox.
- Pre-change snapshot and immutable plan.
- Exact plan-hash-bound operator approval.
- Separate apply, verify, outcome-record, and separately approved restore stages.
- Symlinks, special files, hard links, traversal, and pre-existing destinations rejected.

## Verify locally

```sh
python3 -m pip install -r requirements-test.txt
python3 -m unittest discover -v
```

For a controlled walkthrough, follow the seven-stage quarantine and separately approved rollback procedures in [README.md](README.md). Use only a disposable test directory.

## Evidence

The recorded CI run passed 23 deterministic tests and schema checks across Python 3.9 through 3.13 on Ubuntu 24.04: [workflow run](https://github.com/HuffmanMainNode/posix-containment-kit/actions/runs/44976874176).

## Explicit limitations

This is not an endpoint security product or system-wide containment tool. It does not terminate processes, control services, alter firewall/routing state, elevate privileges, or operate outside the initialized sandbox. Filesystem races with hostile concurrent writers are not fully eliminated on all POSIX filesystems; ownership, ACLs, extended attributes, and filesystem-specific metadata are not guaranteed. Other operating systems and filesystems are untested.

## Next milestone

Obtain independent security review of filesystem race handling and snapshot semantics, add platform-specific filesystem tests, and retain explicit operator approval and pre-change rollback preparation.

## Ecosystem context

Related public components:
- [cas-xdp-supervisor](https://github.com/HuffmanMainNode/cas-xdp-supervisor)
- [cas-threat-index](https://github.com/HuffmanMainNode/cas-threat-index)
- [xdp-ingress-primitives](https://github.com/HuffmanMainNode/xdp-ingress-primitives)
- [canary-labyrinth-httpd](https://github.com/HuffmanMainNode/canary-labyrinth-httpd)

No system-wide containment or integrated orchestration claim is made.
