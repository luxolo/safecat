# Config 08: Documentation and release/package-manager guidance

## Objective

Document persistent configuration, policy precedence, security guarantees, upgrade behavior, and release/package-manager requirements for users and maintainers.

## Dependencies

Config 01–07, especially the final schema, command output, precedence, permissions, and failure behavior.

## Files or areas likely to change

- `README.md` and CLI help text.
- New configuration/policy reference document, if appropriate.
- Release checklist or packaging documentation if present.
- Examples and fixtures referenced by documentation.

## Scope

- Document `~/.config/safecat`, `os.UserConfigDir()`, `XDG_CONFIG_HOME`, platform differences, and how to inspect the resolved path.
- Document schema/versioning, persistent policy file layout, precedence, project policy discovery, and explicit `--policy-file` behavior.
- Document `safecat init`, `config path`, `config show`, and `policy list` with safe examples.
- Explain permissions, fail-closed behavior, malformed files, upgrade preservation, backup/recovery, and how to disable optional policies.
- Add maintainer guidance that installers and package managers must not overwrite user configuration, plus release tests/checklist items.

## Out of scope

- Implementing commands or changing policy behavior.
- Promising package-manager integration not supported by this repository.
- Publishing a full security certification or cryptographic threat model.

## Acceptance criteria

- A new user can locate, initialize, inspect, and safely customize configuration from the docs.
- Documentation matches actual command names, defaults, precedence, exit codes, and schema examples.
- Upgrade guidance explicitly states that mutable user configuration is outside the install prefix and must survive upgrades.
- Release/package-manager notes include a test or review gate preventing user-file overwrite.

## Notes for parallel Codex sessions

- Treat implementation behavior and tests as authoritative; flag documentation mismatches instead of silently inventing semantics.
- Keep examples non-secret and suitable for copy/paste.
- Coordinate README edits to avoid conflicts with other ongoing CLI documentation work.
