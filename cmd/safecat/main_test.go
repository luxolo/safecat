package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIBlackBoxStdinAndHelp(t *testing.T) {
	bin := buildCLI(t)
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader("password: hunter2\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "password: REDACTED\n" || strings.Contains(stderr.String(), "hunter2") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	help := exec.Command(bin, "--help")
	data, err := help.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("Usage: safecat")) {
		t.Fatalf("help=%q", data)
	}
}

func TestCLIBlackBoxPolicyFileAndStrictFailure(t *testing.T) {
	dir := t.TempDir()
	bin := buildCLI(t)
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"replacement":"literal","literal":"MASKED","sensitive_keys":["custom"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--format", "yaml", "--policy-file", policyPath, "-")
	cmd.Stdin = strings.NewReader("custom: secret-value\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "custom: MASKED\n" || strings.Contains(stdout.String(), "secret-value") {
		t.Fatalf("stdout=%q", stdout.String())
	}
	bad := exec.Command(bin, "--format", "yaml", "--strict")
	bad.Stdin = strings.NewReader("kind: Secret\n\tdata:\n\t  x: leak\n")
	if err := bad.Run(); err == nil {
		t.Fatal("strict malformed input unexpectedly succeeded")
	} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 4 {
		t.Fatalf("strict exit=%v", err)
	}
	invalid := exec.Command(bin, "--policy-file", filepath.Join(dir, "missing-policy.json"))
	if err := invalid.Run(); err == nil {
		t.Fatal("missing policy unexpectedly succeeded")
	} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 5 {
		t.Fatalf("policy exit=%v", err)
	}
	mismatch := exec.Command(bin, "--format", "json")
	mismatch.Stdin = strings.NewReader("kind: Secret\n")
	if err := mismatch.Run(); err == nil {
		t.Fatal("explicit format mismatch unexpectedly succeeded")
	} else if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 4 {
		t.Fatalf("mismatch exit=%v", err)
	}
}

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "safecat")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	return bin
}
