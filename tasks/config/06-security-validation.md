# Config 06: File permissions, validation, and fail-closed behavior

## Objective

Make configuration handling safe against accidental disclosure, permissive file access, malformed policy content, and ambiguous policy selection.

## Dependencies

Config 01–03. Coordinate error/exit-code behavior with Config 04 and existing `ErrInvalidPolicy` handling in `policy.go`.

## Files or areas likely to change

- Policy/config loader and validation code near `policy.go`.
- Command error reporting in `cmd/safecat/main.go`.
- Security-focused unit and integration tests.

## Scope

- Define required directory/file modes, ownership checks where portable, and behavior for symlinks, special files, unreadable files, and permission errors.
- Reuse bounded reads such as the existing `MaxPolicyBytes` concept and reject trailing data, unknown fields, invalid regexes, unsupported versions, and invalid paths.
- Distinguish absent optional configuration from malformed configuration that was selected for use.
- Fail closed: never process input with an unexpectedly ignored selected policy, and never print policy contents or secret values in errors/explain output.
- Define safe handling for partial writes and concurrent readers.

## Out of scope

- Cryptographic signing or encryption of policies.
- Operating-system MAC policy configuration.
- Broad redesign of detector validation unrelated to persisted policies.

## Acceptance criteria

- Malformed, oversized, invalid-version, unreadable, and unsafe-permission cases have explicit outcomes and exit codes.
- No failure path emits raw policy data or input secrets.
- Writes use restrictive permissions and an atomic replacement strategy where files are created or updated.
- Security decisions and portability limitations are documented in code/task notes.

## Notes for parallel Codex sessions

- Preserve current `LoadPolicyFile` bounded-read and `DisallowUnknownFields` guarantees unless a compatibility decision says otherwise.
- Test mode bits without assuming one umask; assert the resulting minimum safety property.
- Treat symlink behavior as an explicit decision, not an incidental `os.Open` result.
