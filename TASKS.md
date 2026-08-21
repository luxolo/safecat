# Safecat Task Plan

Safecat is a streaming Unix filter that redacts secrets from arbitrary text while supporting richer detection for structured YAML/JSON and Kubernetes manifests.

## Recommended execution order

Tasks 01, 02, and 03 can begin in parallel. Task 04 depends on 02 and 03. Task 05 depends on 01–04. Task 06 can begin after the CLI shape is agreed and should be completed before release.

## Task files

- [01 - Project foundation](tasks/01-project-foundation.md)
- [02 - Streaming input and output](tasks/02-streaming-io.md)
- [03 - Detection and redaction engine](tasks/03-detection-engine.md)
- [04 - Structured formats and Kubernetes](tasks/04-structured-kubernetes.md)
- [05 - CLI integration and policies](tasks/05-cli-and-policies.md)
- [06 - Tests, security review, and documentation](tasks/06-tests-security-docs.md)

## Parallel-session guidance

Each session should read its assigned task file first. Avoid changing files owned by another task unless the task explicitly permits it. If an interface is needed before its implementation exists, define a small documented interface and leave integration to Task 05.

Every task should preserve existing user changes, include focused tests where practical, and report assumptions or unresolved interface decisions in its final handoff.
