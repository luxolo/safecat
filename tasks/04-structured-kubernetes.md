# Task 04: Structured formats and Kubernetes support

## Objective

Add structured YAML/JSON handling and Kubernetes-aware redaction while preserving safe behavior for arbitrary manifests.

## Dependencies

Tasks 02 and 03.

## Scope

- Add format detection as an advisory hint with safe fallback to plain-text scanning.
- Support YAML streams/multiple documents and JSON.
- Traverse structured values by key and path.
- Add Kubernetes rules for kubeconfig fields, Secret `data`, Secret `stringData`, and private credential material.
- Redact base64-encoded secret values without attempting to print decoded content.
- Preserve comments, ordering, document boundaries, and formatting where the chosen parser permits it.
- Make full structured buffering bounded and explicit when necessary.

## Out of scope

- Supporting every Kubernetes resource type semantically.
- Network access or contacting a Kubernetes cluster.

## Acceptance criteria

- Kubeconfig examples redact tokens and client private key material.
- Kubernetes Secret manifests redact sensitive values in both `data` and `stringData`.
- Multi-document YAML is handled safely.
- Malformed or ambiguous structured input does not fall through to unredacted output.
- Structured and streaming behavior are documented.
