# Task 01: Project foundation

## Objective

Set up the project structure, language/tooling conventions, and core domain interfaces for safecat.

## Dependencies

None.

## Scope

- Inspect the repository and choose conventions consistent with the existing project.
- Establish the executable/library layout and build configuration.
- Define small interfaces for input chunks, detectors, matches, redaction policies, and output events.
- Define common error types and diagnostic behavior.
- Add a minimal executable that can compile and display help, if the repository does not already have one.

## Out of scope

- Implementing concrete secret detectors.
- Full YAML/JSON parsing.
- Production-grade CLI behavior.

## Acceptance criteria

- The project builds using documented commands.
- Core interfaces are documented and have no unnecessary coupling to a specific detector.
- A later task can add detectors without changing the reader abstraction.
- Basic unit tests cover match spans/confidence or equivalent core value objects.
