package safecat

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestStructuredKubernetesSecretYAML(t *testing.T) {
	in := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: demo\ndata:\n  password: c2VjcmV0\nstringData:\n  token: plain-secret\n# keep this comment\n"
	out, err := RedactStructured([]byte(in), StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "c2VjcmV0") || strings.Contains(s, "plain-secret") {
		t.Fatalf("secret leaked: %q", s)
	}
	if !strings.Contains(s, "name: demo") || !strings.Contains(s, "# keep this comment") {
		t.Fatalf("format lost: %q", s)
	}
}

func TestStructuredSecretClassificationIsOrderIndependent(t *testing.T) {
	in := "data:\n  password: c2VjcmV0\nstringData:\n  token: plain-secret\nkind: Secret\n"
	out, err := RedactStructured([]byte(in), StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("c2VjcmV0")) || bytes.Contains(out, []byte("plain-secret")) {
		t.Fatalf("secret leaked when kind followed data: %q", out)
	}
}

func TestStructuredYAMLRejectsTabIndentWithoutOutput(t *testing.T) {
	in := []byte("kind: Secret\n\tdata:\n\t  password: leaked\n")
	out, err := RedactStructured(in, StructuredOptions{})
	if !errors.Is(err, ErrStructuredMalformed) || out != nil {
		t.Fatalf("tab-indented YAML: output=%q err=%v", out, err)
	}
}

func TestStructuredYAMLPreservesInlineComments(t *testing.T) {
	in := "kind: Secret # resource type\ndata:\n  opaque: c2VjcmV0 # keep explanation\n"
	out, err := RedactStructured([]byte(in), StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "c2VjcmV0") || !strings.Contains(s, "# keep explanation") || !strings.Contains(s, "# resource type") {
		t.Fatalf("inline comment/value handling: %q", s)
	}
}

func TestStructuredKubeconfigAndYAMLStream(t *testing.T) {
	in := "apiVersion: v1\nclusters:\n- name: c\n  cluster:\n    certificate-authority-data: Q0E=\nusers:\n- name: u\n  user:\n    token: abc-token\n    client-key-data: S0VZ\n---\nkind: ConfigMap\ndata:\n  note: retain\n"
	out, err := RedactStructured([]byte(in), StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range []string{"Q0E=", "abc-token", "S0VZ"} {
		if strings.Contains(s, secret) {
			t.Fatalf("secret leaked: %q", s)
		}
	}
	if !strings.Contains(s, "note: retain") || strings.Count(s, "---") != 1 {
		t.Fatalf("stream damaged: %q", s)
	}
}

func TestStructuredJSONAndMalformedFailClosed(t *testing.T) {
	in := []byte(`{"kind":"Secret","data":{"password":"c2VjcmV0"},"stringData":{"token":"plain"},"metadata":{"name":"demo"}}`)
	out, err := RedactStructured(in, StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("c2VjcmV0")) || bytes.Contains(out, []byte("plain")) {
		t.Fatalf("secret leaked: %q", out)
	}
	if !bytes.Contains(out, []byte(`"data":{"password":"REDACTED"}`)) {
		t.Fatalf("secret shape lost: %q", out)
	}
	if !bytes.Contains(out, []byte(`"name":"demo"`)) {
		t.Fatalf("safe field lost: %q", out)
	}
	if _, err = RedactStructured([]byte(`{"kind":"Secret","data":`), StructuredOptions{}); !errors.Is(err, ErrStructuredMalformed) {
		t.Fatalf("got %v", err)
	}
	if _, err = RedactStructured([]byte(`{"a":"x","a":"y"}`), StructuredOptions{}); !errors.Is(err, ErrStructuredMalformed) {
		t.Fatalf("duplicate key got %v", err)
	}
	arrayInput := []byte(`[{"kind":"Secret","data":{"password":"encoded-secret"}},{"kind":"ConfigMap","data":{"note":"retain"}}]`)
	arrayOut, err := RedactStructured(arrayInput, StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(arrayOut, []byte("encoded-secret")) || !bytes.Contains(arrayOut, []byte(`"note":"retain"`)) {
		t.Fatalf("array Secret traversal: %q", arrayOut)
	}
}

func TestStructuredLimitsAndUnknownFallback(t *testing.T) {
	if got := DetectFormat([]byte("ordinary text")); got != FormatUnknown {
		t.Fatal(got)
	}
	out, err := RedactStructured([]byte("ordinary password: hidden"), StructuredOptions{})
	if err != nil || !bytes.Contains(out, []byte("REDACTED")) || bytes.Contains(out, []byte("hidden")) {
		t.Fatalf("fallback failed: %q %v", out, err)
	}
	if _, err = RedactStructured([]byte("kind: Secret\ndata:\n  x: y\n"), StructuredOptions{MaxBytes: 4}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("got %v", err)
	}
	if _, err = RedactStructured([]byte("a: b\n---\nc: d\n"), StructuredOptions{MaxDocuments: 1}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("got %v", err)
	}
	if out, err := RedactStructured([]byte("---\na: b\n---\nc: d\n"), StructuredOptions{MaxDocuments: 1}); !errors.Is(err, ErrLimitExceeded) || out != nil {
		t.Fatalf("explicit document limit: output=%q err=%v", out, err)
	}
	if _, err = RedactStructured([]byte("- ambiguous scalar\n"), StructuredOptions{}); !errors.Is(err, ErrStructuredMalformed) {
		t.Fatalf("ambiguous YAML got %v", err)
	}
	if out, err := RedactStructured([]byte("kind: Secret\ndata: [unterminated\n"), StructuredOptions{}); !errors.Is(err, ErrStructuredMalformed) || out != nil {
		t.Fatalf("flow YAML got %v", err)
	}
}

func TestStructuredExplicitFormatRejectsMismatch(t *testing.T) {
	if out, err := RedactStructuredAs([]byte("password: hidden\n"), StructuredOptions{}, FormatJSON, DefaultPolicyConfig()); !errors.Is(err, ErrStructuredMalformed) || out != nil {
		t.Fatalf("JSON mismatch: output=%q err=%v", out, err)
	}
	if out, err := RedactStructuredAs([]byte(`{"password":"hidden"}`), StructuredOptions{}, FormatYAML, DefaultPolicyConfig()); !errors.Is(err, ErrStructuredMalformed) || out != nil {
		t.Fatalf("YAML mismatch: output=%q err=%v", out, err)
	}
}
