# Task 06: Tests, security review, and documentation

## Objective

Validate the complete tool against realistic use cases and document its guarantees and limitations.

## Dependencies

Tasks 01–05.

## Scope

- Add end-to-end tests for stdin, files, pipelines, malformed input, large input, and broken pipes.
- Add fixture-based tests for kubeconfig, Kubernetes Secrets, YAML streams, JSON, PEM, JWT, dotenv, and plain text.
- Add regression tests for false negatives, overlapping matches, Unicode, line endings, and secrets split across chunks.
- Review logs, errors, panic paths, temporary files, and memory limits for accidental disclosure.
- Document that safecat reduces display risk but is not a cryptographic security boundary.
- Document supported formats, detection rules, known limitations, and safe examples.
- Add release checklist and, if applicable, CI checks.

## Acceptance criteria

- Tests demonstrate that known fixture secrets never appear in redacted output.
- Failure paths are covered and fail closed.
- Documentation explains streaming versus structured mode.
- A security review records remaining risks and mitigations.
- The project has a repeatable build/test command suitable for CI.
