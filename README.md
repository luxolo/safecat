# safecat

Safecat is a byte-preserving streaming filter that redacts common secret forms.
This repository currently implements the configuration work and tasks 01–05: project interfaces, bounded
streaming I/O, independent detection/redaction, conservative structured
YAML/JSON plus Kubernetes-aware redaction, and the composable CLI/policy layer.
Release/security work remains for task 06.

## Toolchain

The project uses Go 1.22 or newer and only the Go standard library.

```sh
go test ./...
go build ./...
printf 'password: hunter2\n' | go run ./cmd/safecat
go run ./cmd/safecat --help
```

The filter reads stdin when no file is named and writes transformed bytes to
stdout. File arguments are processed in order. `--help` writes a short help
message to stdout. Diagnostics are written to stderr and never include input
values or match snippets. A broken pipe or other read/write failure exits
non-zero; the filter does not fall back to printing the original input.

The library API is in the root package. `Chunk`, `Detector`, `Match`,
`RedactionPolicy`, and `OutputEvent` are intentionally detector-neutral. The
streaming `Engine` retains only a bounded pending window and delays its tail so
matches split across reads can be detected.

Structured use is explicit through `RedactStructured`. JSON is validated and
reserialized with the standard library; YAML streams use a conservative
line-preserving transformer for common mappings, lists, comments, and document
boundaries. Structured input is capped at 8 MiB and 128 YAML documents by
default. Malformed or ambiguous YAML/JSON candidates return an error and no
partial output. Unknown input falls back to the ordinary byte scanner. Secret
`data`/`stringData`, kubeconfig credential fields, private-key material, and
known sensitive paths are replaced without decoding or printing base64 content.
The YAML support intentionally does not claim full YAML 1.2 coverage; anchors,
complex keys, and unusual flow syntax are rejected or treated conservatively.

The CLI reads stdin when no positional file is supplied, accepts `-` explicitly,
and processes file/kubeconfig paths in order. `--format auto|plain|yaml|json`,
`--replacement literal|mask|hash`, `--policy-file`, `--policy NAME`, `--strict`,
`--explain`, and `--color auto|always|never` are supported. Explanation output goes only to
stderr and contains rule names plus byte/line locations, never values.

## Persistent configuration

User configuration is stored outside the installation directory. The default
location is Go's user configuration directory joined with `safecat`; an
absolute `XDG_CONFIG_HOME` is honored when supplied. On Linux this is normally
`~/.config/safecat`. Use these commands to inspect and initialize it:

```sh
safecat init
safecat config path
safecat config show
safecat policy list
```

`init` creates restrictive `config.json` and `policies/` entries and does not
overwrite existing user policies. Persistent policies are versioned JSON files
under `policies/`, for example:

```json
{
  "version": 1,
  "name": "company",
  "policy": {
    "sensitive_keys": ["customerSecret"],
    "sensitive_paths": ["spec.credentials.password"]
  }
}
```

By default safecat combines built-in defaults, `config.json`, persistent
policies in deterministic filename order, a project-local `.safecat.json`, and
an explicitly selected `--policy-file`. `--policy NAME` selects one persistent
policy instead of loading all of them. Lists are merged uniquely, named regex
rules are replaced by later definitions, and scalar/map values use the later
layer. Missing optional files are ignored; malformed selected policies fail
closed. User configuration is not part of the binary and survives normal
upgrades.

Policy files are JSON and intentionally local/static. Example:

```json
{
  "replacement": "literal",
  "literal": "MASKED",
  "sensitive_keys": ["customerSecret"],
  "sensitive_paths": ["spec.credentials.password"],
  "regex": [{"name": "internal-id", "pattern": "INT-[0-9]+", "priority": 90}],
  "detector_priority": {"jwt": 100}
}
```

Unknown policy fields, invalid regular expressions, malformed structured input,
and bounded-buffer failures fail closed. Exit status 0 means success, 2 usage
error, 3 input/output error, 4 processing or strict-mode failure, and 5 policy
error. Errors are short, stderr-only, and secret-free. Before release, scripts
may rely on these options, exit classes, stdin/file behavior, and the literal
default marker `REDACTED`; diagnostic wording and JSON reserialization details
are not compatibility contracts.
