# Config 07: Configuration and policy test coverage

## Objective

Provide focused regression and integration coverage for discovery, persistence, precedence, commands, upgrades, and fail-closed policy handling.

## Dependencies

Config 01–06 interfaces and behavior. Tests can be added alongside implementation tasks, with final end-to-end coverage after command integration.

## Files or areas likely to change

- New config/loader tests.
- `policy_test.go` for schema, validation, and merge behavior.
- `cmd/safecat/main_test.go` for subcommands and CLI precedence.
- Test fixtures under a clearly named config/policy fixture directory, if needed.

## Scope

- Test `XDG_CONFIG_HOME`, `os.UserConfigDir()` behavior, missing directories, and isolated temporary homes/config roots.
- Test built-in/user/project/explicit policy precedence, field merge behavior, duplicate names, and deterministic listing.
- Test `init`, `config path`, `config show`, and `policy list` output and exit codes.
- Test persistent policies across an upgrade simulation and verify installers do not overwrite them.
- Test malformed JSON/schema, unknown fields, invalid regex, unsupported version, oversized files, bad permissions, symlinks, and fail-closed behavior.
- Assert that secret values do not appear in errors or diagnostics.

## Out of scope

- Performance benchmarking beyond bounded-size or basic regression checks.
- Testing external package managers that cannot be represented in this repository.
- Re-testing unrelated detector behavior already covered by existing suites.

## Acceptance criteria

- Required scenarios run with the repository's normal Go test command.
- Tests are hermetic and do not read or write the developer's real config directory.
- Both missing optional configuration and invalid selected configuration are covered.
- At least one end-to-end test proves the effective policy changes redaction as intended without exposing the original secret.

## Notes for parallel Codex sessions

- Prefer dependency injection for config roots and working directories over global environment mutation.
- If environment mutation is unavoidable, use test cleanup and avoid parallel tests that share process state.
- Record platform-specific skips or limitations explicitly.
