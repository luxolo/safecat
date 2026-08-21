# Config 02: Config and policy schema versioning

## Objective

Define a versioned, forward-compatible schema for the user config and persistent policy files while preserving the existing `Policy` fields and JSON behavior.

## Dependencies

Current `Policy` and `LoadPolicyFile` APIs in `policy.go`. Coordinate with Config 03 on decoding and with Config 06 on unknown fields and invalid versions.

## Files or areas likely to change

- `policy.go` or a new config schema/codec package.
- Existing policy tests in `policy_test.go` plus schema fixtures.
- CLI help text and examples only after the schema is settled.

## Scope

- Decide whether the top-level config is JSON, YAML, or another format; document the choice and why it fits the existing JSON policy API.
- Define an explicit schema/version field, defaults, naming, and whether files can contain one policy or named policy metadata.
- Map schema data to the existing `Policy` fields: replacement, literal, sensitive keys/paths, regex rules, and detector priorities.
- Define compatibility rules for missing version, supported versions, unknown fields, and future versions.
- Define stable policy names and file extension conventions under `policies/`.

## Out of scope

- Loading order or precedence.
- CLI command implementation.
- Migration tooling beyond documenting future migration requirements.

## Acceptance criteria

- Example valid config and policy documents are included in the task or test fixtures.
- Every field has documented type, default, and validation behavior.
- A version mismatch cannot silently change redaction behavior.
- Existing explicit JSON policy files either remain valid or have a documented compatibility/migration path.

## Notes for parallel Codex sessions

- Avoid changing `Policy` semantics merely to make persistence convenient; introduce an adapter if needed.
- Coordinate the exact version representation before Config 03 implements discovery.
- Include a short security review of fields that could affect diagnostics or replacement output.
