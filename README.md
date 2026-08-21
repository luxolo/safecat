# safecat

Safecat is a lightweight Unix filter that redacts secrets and other sensitive
values before you print or share command output.

It reads stdin by default, preserves ordinary text, and writes sanitized output
to stdout:

```sh
kubectl get secret my-secret -o yaml | safecat
cat ~/.kube/config | safecat
terraform output | safecat
```

Safecat is a display-safety tool, not a security boundary. Review output before
sharing it.

## Install

### Homebrew

```sh
brew tap luxolo/tap
brew install safecat
```

### Go

```sh
go install github.com/luxolo/safecat/cmd/safecat@latest
```

Make sure the Go binary directory is on your `PATH`:

```sh
export PATH="$(go env GOPATH)/bin:$PATH"
```

### From source

```sh
git clone https://github.com/luxolo/safecat.git
cd safecat
go build -o safecat ./cmd/safecat
sudo install safecat /usr/local/bin/safecat
```

Installing the binary does not create user configuration. Initialize it only
if you want persistent custom policies:

```sh
safecat init
```

## Usage

Safecat accepts stdin or file arguments. Multiple files are processed in order.

```sh
safecat config.yaml
cat config.yaml | safecat
safecat file1.yaml file2.json
```

Useful options:

```text
--format auto|plain|yaml|json  Select the input format
--replacement literal|mask|hash Replacement strategy
--literal TEXT                 Replacement text for literal mode
--policy NAME                  Load one persistent policy
--policy-file FILE             Load an explicit policy file
--strict                       Fail if suspicious content remains
--explain                      Report safe rule/location diagnostics to stderr
--color auto|always|never      Color explanation output
```

Examples:

```sh
kubectl config view --raw | safecat
kubectl get secret my-secret -o yaml | safecat --strict
cat app.yaml | safecat --replacement mask
cat output.json | safecat --format json
```

Diagnostics go to stderr. Safecat never includes input values in errors or
explanation output, and processing errors fail closed instead of printing the
original input.

## What is redacted

Built-in detection covers common password fields, JWTs, private PEM keys,
common cloud/source-control tokens, Kubernetes kubeconfig credentials, and
Kubernetes Secret data. YAML and JSON also support sensitive key and path rules.

Unknown text is handled by the streaming scanner. Structured YAML and JSON are
buffered up to 8 MiB and validated before output. JSON may be reserialized;
comments and formatting are not guaranteed to survive JSON mode. YAML support is
conservative and rejects unsupported or ambiguous syntax rather than emitting
potentially unsafe output.

## Persistent policies

Safecat keeps user configuration outside the installation directory, so package
upgrades do not replace it. The default location is the platform user config
directory plus `safecat`; an absolute `XDG_CONFIG_HOME` is honored when set.
On most Linux systems this is:

```text
~/.config/safecat/
├── config.json
└── policies/
```

Manage the configuration with:

```sh
safecat init
safecat config path
safecat config show
safecat policy list
```

Create a persistent policy in `policies/company.json`:

```json
{
  "version": 1,
  "name": "company",
  "policy": {
    "sensitive_keys": ["customerSecret", "connectionString"],
    "sensitive_paths": ["spec.credentials.password"],
    "regex": [
      {"name": "internal-id", "pattern": "INT-[0-9]+", "priority": 90}
    ]
  }
}
```

Use it explicitly:

```sh
cat manifest.yaml | safecat --policy company
```

Policy precedence is built-in defaults, user configuration, persistent
policies, a project-local `.safecat.json`, and finally `--policy-file`. Lists
are merged uniquely; later scalar, map, and same-named regex values win.
Malformed, unsupported, oversized, or unsafe policy files fail closed.

## Exit codes

```text
0  Success
2  Usage error
3  Input/output error
4  Processing or strict-mode failure
5  Policy/configuration error
```

## Development

```sh
go test ./...
go vet ./...
go build ./...
```

Safecat is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
