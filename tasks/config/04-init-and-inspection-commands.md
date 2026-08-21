# Config 04: Initialization and inspection commands

## Objective

Add user-facing commands for creating a starter configuration and inspecting effective configuration and persistent policies.

## Dependencies

Config 01, Config 02, and Config 03. Requires a deliberate extension of the current single-command `flag` parsing in `cmd/safecat/main.go`.

## Files or areas likely to change

- `cmd/safecat/main.go` or new command files under `cmd/safecat`.
- New command-level tests beside `cmd/safecat/main_test.go`.
- Starter config/policy templates, if templates are kept as Go constants or embedded assets.

## Scope

- Implement `safecat init` with safe directory/file creation and no destructive overwrite by default.
- Implement `safecat config path` to print the resolved base directory.
- Implement `safecat config show` to print effective, non-secret configuration and policy origins.
- Implement `safecat policy list` to list valid persistent policies and report invalid entries safely.
- Define stdout/stderr, exit codes, help, `--json` or equivalent machine-readable output if needed, and behavior when directories are absent.

## Out of scope

- Interactive editor or prompt UI.
- Network or repository policy synchronization.
- Exporting secret values or raw sensitive policy content in diagnostics.

## Acceptance criteria

- All four command forms have stable help and documented output contracts.
- `init` is idempotent and refuses accidental overwrite unless an explicit, documented option is provided.
- `config show` reflects the same precedence used for redaction.
- `policy list` handles empty, missing, valid, and invalid policy directories without leaking file contents.

## Notes for parallel Codex sessions

- Coordinate command dispatch before editing the existing flag parser.
- Keep redaction stdin/file workflows backward compatible.
- Use temporary config roots in tests; never exercise the real user's configuration directory.
