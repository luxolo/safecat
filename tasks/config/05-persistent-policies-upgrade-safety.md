# Config 05: Persistent policies and upgrade-safe installation

## Objective

Support user-managed policies under `~/.config/safecat/policies/` (or the discovered equivalent) and ensure package installation/upgrades never overwrite them.

## Dependencies

Config 01 path contract, Config 02 schema, and Config 03 loader/precedence. Coordinate with Config 08 for package-manager guidance.

## Files or areas likely to change

- New persistent policy directory loader.
- `cmd/safecat/main.go` integration and `policy list` support.
- Installer, release, Homebrew/package-manager, or documentation configuration only if such files exist; inspect first.
- Integration tests using isolated config roots.

## Scope

- Define which files in `policies/` are loaded, how names map to files, and how non-policy files are ignored or rejected.
- Ensure user policies survive replacement of the safecat binary and package upgrades.
- Keep packaged defaults/templates separate from mutable user files.
- Define atomic writes and preservation behavior for `init` and future managed updates.
- Document administrator/system policy boundaries if system-wide configuration is considered later.

## Out of scope

- Implementing a remote policy registry.
- Automatically migrating or rewriting user policies during upgrade.
- Changing package-manager metadata that is not present in this repository.

## Acceptance criteria

- An upgrade simulation replaces the binary while user config and policies remain byte-for-byte intact.
- `init` never overwrites existing user policies.
- Persistent policy discovery is deterministic and honors the documented filename rules.
- No installer step places mutable user files inside the installation prefix.

## Notes for parallel Codex sessions

- First inspect release/package files before claiming code changes are required; this repository may only need guidance.
- Use explicit temporary paths and fixture copies for upgrade tests.
- Escalate any need to modify packaging artifacts to Config 08 rather than inventing package behavior.
