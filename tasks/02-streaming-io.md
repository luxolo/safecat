# Task 02: Streaming input and output

## Objective

Implement a bounded-memory reader/writer pipeline suitable for Unix pipes and long-running producers.

## Dependencies

Task 01 interfaces, or coordinate with that session before changing shared interfaces.

## Scope

- Read stdin by default and support explicit file inputs if the project shape allows it.
- Process input incrementally without waiting for EOF in plain-text mode.
- Support bounded lookahead/state for multiline patterns such as PEM blocks.
- Write transformed content to stdout and diagnostics only to stderr.
- Preserve bytes, line endings, and formatting as much as possible.
- Handle broken pipes, read errors, write errors, and binary/invalid UTF-8 input safely.
- Add configurable size limits for structured buffering and multiline state.

## Out of scope

- Concrete secret detection rules.
- Reformatting YAML or JSON.

## Acceptance criteria

- `producer | safecat` emits output incrementally.
- Memory usage does not grow with an unbounded stdin stream in plain-text mode.
- Input is never printed unredacted because of a processing error.
- Exit status and stderr behavior are documented and tested.
