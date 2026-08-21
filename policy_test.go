package safecat

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestPolicyCustomKeyPathAndRegex(t *testing.T) {
	p := Policy{Replacement: string(StrategyLiteral), Literal: "MASKED", SensitiveKeys: []string{"custom"}, SensitivePaths: []string{"spec.credentials"}, Regex: []PolicyRegex{{Name: "internal-id", Pattern: `INT-[0-9]+`, Priority: 90}}}
	in := []byte("kind: ConfigMap\ncustom: value\nspec:\n  credentials: secret\nidentifier: INT-123\n")
	out, err := RedactStructuredWithPolicy(in, StructuredOptions{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("value")) || bytes.Contains(out, []byte("secret")) || bytes.Contains(out, []byte("INT-123")) {
		t.Fatalf("policy leak: %q", out)
	}
	jsonOut, err := RedactStructuredWithPolicy([]byte(`{"custom":"value"}`), StructuredOptions{}, p)
	if err != nil || bytes.Contains(jsonOut, []byte("value")) || !bytes.Contains(jsonOut, []byte("MASKED")) {
		t.Fatalf("JSON custom policy: %q %v", jsonOut, err)
	}
}

func TestPolicyRejectsUnknownFieldsAndInvalidRegex(t *testing.T) {
	p := Policy{Replacement: "unsupported"}
	if !errors.Is(p.Validate(), ErrInvalidPolicy) {
		t.Fatal("unsupported replacement accepted")
	}
	p = Policy{Regex: []PolicyRegex{{Name: "bad", Pattern: "["}}}
	if !errors.Is(p.Validate(), ErrInvalidPolicy) {
		t.Fatal("invalid regex accepted")
	}
}

func TestPolicyFileSizeBoundAndExplainCoverage(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "oversized-policy-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxPolicyBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := LoadPolicyFile(file.Name()); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized policy: %v", err)
	}
	p := Policy{SensitiveKeys: []string{"custom"}, SensitivePaths: []string{"spec.credentials"}, Regex: []PolicyRegex{{Name: "custom-regex", Pattern: `SECRET-[0-9]+`}}}
	input := []byte(`{"custom":"SECRET-123","spec":{"credentials":"hidden"}}`)
	explanation := p.Explain(input)
	names := ""
	for _, item := range explanation {
		names += item.Rule + " " + item.Location + " "
	}
	for _, name := range []string{"policy-key:custom", "policy-path:spec.credentials", "custom-regex"} {
		if !bytes.Contains([]byte(names), []byte(name)) {
			t.Fatalf("missing explanation %q: %s", name, names)
		}
	}
	if bytes.Contains([]byte(names), []byte("SECRET-123")) || bytes.Contains([]byte(names), []byte("hidden")) {
		t.Fatalf("explanation leaked value: %s", names)
	}
}
