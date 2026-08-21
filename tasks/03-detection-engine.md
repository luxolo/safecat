# Task 03: Detection and redaction engine

## Objective

Implement detector registration, match resolution, and configurable redaction independent of input/output plumbing.

## Dependencies

Task 01 core interfaces.

## Scope

- Define a detector registry and detector result format.
- Implement match confidence, detector priority, and overlapping-match resolution.
- Implement streaming-compatible plain-text scanning.
- Add detectors for password-like fields, JWTs, PEM private keys, and common token patterns.
- Implement replacement strategies: literal replacement, masking, and stable short hash.
- Ensure replacement cannot expose the original value through diagnostics.
- Make detector rules configurable without requiring code changes where practical.

## Out of scope

- YAML/JSON AST traversal.
- Kubernetes-specific path semantics.
- CLI argument parsing.

## Acceptance criteria

- Multiple detectors can report matches for the same input.
- Resolution is deterministic and tested for overlaps.
- Multiline secrets are redacted correctly.
- Default output uses an obvious marker such as `REDACTED`.
- The engine can operate incrementally on chunks.
