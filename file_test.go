package safecat

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixtureKubeconfigRedactsCredentialValues(t *testing.T) {
	input := readFixture(t, "kubeconfig.yaml")
	output, err := RedactStructured(input, StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ZmFrZS1jZXJ0aWZpY2F0ZQ==", "fake-token-value", "ZmFrZS1wcml2YXRlLWtleQ=="} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("fixture secret leaked: %q", secret)
		}
	}
	for _, safe := range []string{"fake-cluster", "https://kubernetes.example.test", "current-context: fake-context"} {
		if !bytes.Contains(output, []byte(safe)) {
			t.Fatalf("safe fixture value missing: %q\noutput=%s", safe, output)
		}
	}
}

func TestFixtureSecretPreservesMetadataAndRedactsData(t *testing.T) {
	input := readFixture(t, "secret.yaml")
	output, err := RedactStructured(input, StructuredOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ZmFrZS1zZWNyZXQ=", "ZmFrZS1uYW1l", "ZmFrZS1zZXJ2ZXI="} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("fixture secret leaked: %q", secret)
		}
	}
	for _, safe := range []string{"data-hash: fake-public-hash", "secret-type: cluster", "name: fake-secret", "namespace: fake-namespace"} {
		if !bytes.Contains(output, []byte(safe)) {
			t.Fatalf("safe metadata missing: %q\noutput=%s", safe, output)
		}
	}
}

func TestFixturePlainFileThroughStreamingReader(t *testing.T) {
	file, err := os.Open(filepath.Join("testdata", "plain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var output bytes.Buffer
	policy := DefaultPolicyConfig()
	if err := Stream(file, &output, NewEngine(policy.Registry(), policy.Redaction()), 3); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "fake-password-value") || !strings.Contains(output.String(), "keep-this-public-text") {
		t.Fatalf("unexpected plain fixture output: %q", output.String())
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
