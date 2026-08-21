# Task 05: CLI integration and policy configuration

## Objective

Expose a stable, composable command-line interface and user-defined redaction policies.

## Dependencies

Tasks 01–04, or coordinate on their public interfaces.

## Scope

- Implement stdin-first usage:

  ```sh
  cat kubeconfig | safecat
  kubectl get secret -o yaml | safecat
  safecat kubeconfig
  ```

- Add options for format, replacement strategy, policy file, strict mode, explanation, and color control.
- Add a policy format for sensitive keys, paths, regular expressions, detector priority, and replacement behavior.
- Ensure `--explain` reports rule names and locations without exposing values.
- Define fail-closed behavior and useful exit codes.
- Provide shell-friendly help and examples.

## Out of scope

- GUI or terminal UI features.
- Remote policy distribution.

## Acceptance criteria

- The common pipe workflow is simple and documented.
- A custom policy can redact a user-defined field.
- Strict mode detects unresolved suspicious content or processing uncertainty.
- CLI errors go to stderr and never echo secret input.
- Backward compatibility expectations are documented before release.
