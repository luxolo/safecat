# Config 03: Policy loading and precedence

## Objective

Define deterministic composition of built-in defaults, user configuration, project policy, and explicitly selected CLI policy, including how scalar and list/map fields merge.

## Dependencies

Config 01 directory API and Config 02 schema/version contract. Existing `DefaultPolicyConfig`, `LoadPolicyFile`, and CLI flag behavior are the compatibility baseline.

## Files or areas likely to change

- `policy.go` or a new policy loader/merge package.
- `cmd/safecat/main.go` command setup and option processing.
- `policy_test.go` and CLI tests.

## Scope

- Specify the precedence order: built-in, user, project, then explicit CLI policy, with command-line scalar flags applied at their documented level.
- Define whether policies replace or merge lists, maps, regex rules, and detector priorities, and how duplicate rule names/paths are handled.
- Define project discovery boundaries and the exact project policy filename, without walking into unrelated parent directories unexpectedly.
- Define opt-out/disable controls for user or project policy and behavior when no optional file exists.
- Preserve deterministic results and explain effective origins in safe diagnostics where appropriate.

## Out of scope

- Writing config files.
- Implementing `safecat init` or inspection commands.
- Remote policy distribution.

## Acceptance criteria

- A written precedence table covers every policy field and CLI override.
- Equivalent inputs produce deterministic effective policies regardless of filesystem iteration order.
- Missing optional files are distinguishable from malformed selected files.
- Explicit `--policy-file` remains supported and its precedence is tested.

## Notes for parallel Codex sessions

- Start with a pure merge function so it can be tested without environment or filesystem setup.
- Do not silently fall back to built-ins after a selected policy fails validation.
- Coordinate project discovery with Config 01 and avoid broad repository changes.
