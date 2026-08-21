# Config 01: Configuration directory discovery and platform behavior

## Objective

Define and implement the single source of truth for safecat's user configuration directory, using `os.UserConfigDir()` and honoring `XDG_CONFIG_HOME` on platforms where Go does so.

## Dependencies

None for the discovery contract. Coordinate the returned path shape with Config 02 and the loader in Config 03.

## Files or areas likely to change

- New configuration/path package or files near `policy.go` (ownership to be agreed before implementation).
- `cmd/safecat/main.go` for command integration only after the API exists.
- Path-focused tests, likely a new `config_test.go`.

## Scope

- Define the base directory as the path returned by `os.UserConfigDir()` joined with `safecat`.
- Specify Linux/macOS behavior, `XDG_CONFIG_HOME` handling, and behavior when the environment or home/config directory cannot be resolved.
- Define paths for the main config file and `policies/` without creating directories during read-only operations.
- Keep path construction platform-aware with `filepath`, and prevent relative/path traversal policy names.

## Out of scope

- Policy contents or merge semantics.
- Creating files or directories except where called by `safecat init`.
- Windows-specific product requirements beyond documenting the behavior inherited from `os.UserConfigDir()`.

## Acceptance criteria

- A documented API returns the same base path for all commands in one invocation.
- Tests cover Linux/macOS-compatible `XDG_CONFIG_HOME`, unset variables, missing directories, and path joining.
- Read-only commands do not create or modify the configuration directory.
- Errors are actionable but do not expose sensitive file contents.

## Notes for parallel Codex sessions

- Treat the path API and environment injection strategy as a small stable interface for other sessions.
- Do not add policy parsing here; use temporary directories and test-only environment control.
- Report any platform behavior that cannot be tested directly rather than adding platform-specific assumptions.
