# Persistent configuration and policy task plan

## Objective

Add persistent, upgrade-safe user configuration and policy support to safecat without coupling configuration to the installed binary. The preferred Unix location is `~/.config/safecat`, discovered through Go's `os.UserConfigDir()` so Linux/macOS behavior and `XDG_CONFIG_HOME` are respected.

This is a documentation-only plan. It does not implement configuration, policy discovery, or new CLI commands.

## Current repository seams

- `policy.go` defines `Policy`, `PolicyRegex`, `DefaultPolicyConfig`, `LoadPolicyFile`, and `Policy.Validate`.
- `cmd/safecat/main.go` currently uses a single `flag.FlagSet`; it loads one explicit JSON policy file and applies replacement/literal flags afterward.
- Existing policy errors map to CLI exit code 5, while malformed structured input maps to processing failure. Future config loading should preserve safe, non-secret diagnostics and make precedence explicit.
- Existing tests are in `policy_test.go`, `engine_test.go`, `structured_test.go`, and `cmd/safecat/main_test.go`.

## Recommended execution order

`config-01` and `config-02` can start in parallel. `config-03` depends on the discovery and schema contracts from both. `config-04` and `config-05` can proceed in parallel after the loader/precedence contract is agreed. `config-06` should track each implementation task and finish before release documentation in `config-07`.

## Task files

- [Config 01 - Directory discovery and platform behavior](tasks/config/01-directory-discovery.md)
- [Config 02 - Schema and versioning](tasks/config/02-schema-versioning.md)
- [Config 03 - Loading and precedence](tasks/config/03-loading-precedence.md)
- [Config 04 - Initialization and inspection commands](tasks/config/04-init-and-inspection-commands.md)
- [Config 05 - Persistent policies and upgrade safety](tasks/config/05-persistent-policies-upgrade-safety.md)
- [Config 06 - Security, validation, and fail-closed behavior](tasks/config/06-security-validation.md)
- [Config 07 - Test coverage](tasks/config/07-tests.md)
- [Config 08 - Documentation and packaging guidance](tasks/config/08-documentation-release.md)

## Cross-task constraints

- Keep user configuration outside the executable and never overwrite it during installation or upgrade.
- Use `os.UserConfigDir()` as the primary discovery API; do not hard-code a home directory or ignore `XDG_CONFIG_HOME`.
- Preserve explicit CLI policy behavior and document how built-in, user, project, and explicit policies compose.
- Fail closed when a policy that is selected for use is malformed, unreadable, ambiguous, or unsafe; diagnostics must not include policy contents or secret values.
- Keep task changes independently reviewable. Coordinate shared types and command dispatch before editing overlapping files.
- Do not change existing implementation as part of this planning task.
