package safecat

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathsAndPolicyName(t *testing.T) {
	paths := ConfigPathsForRoot(filepath.Join(t.TempDir(), "safecat"))
	if paths.ConfigFile != filepath.Join(paths.Base, "config.json") || paths.PoliciesDir != filepath.Join(paths.Base, "policies") {
		t.Fatalf("unexpected paths: %#v", paths)
	}
	for _, name := range []string{"company", "my-policy.v1", "a_b-2"} {
		if !ValidatePolicyName(name) {
			t.Fatalf("valid name rejected: %q", name)
		}
	}
	for _, name := range []string{"", ".", "..", "../secret", "a/b", "a\\b"} {
		if ValidatePolicyName(name) {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
}

func TestVersionedPolicyAndMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`{"version":1,"name":"team","policy":{"sensitive_keys":["teamSecret"],"regex":[{"name":"team-id","pattern":"TEAM-[0-9]+"}]}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicyFile(path)
	if err != nil || !p.matchesKey("teamSecret") {
		t.Fatalf("load versioned policy: %#v %v", p, err)
	}
	merged := MergePolicies(Policy{SensitiveKeys: []string{"one"}, Regex: []PolicyRegex{{Name: "x", Pattern: "x"}}}, Policy{SensitiveKeys: []string{"one", "two"}, Regex: []PolicyRegex{{Name: "x", Pattern: "new"}}})
	if len(merged.SensitiveKeys) != 2 || len(merged.Regex) != 1 || merged.Regex[0].Pattern != "new" {
		t.Fatalf("merge: %#v", merged)
	}
}

func TestPersistentPoliciesAreSortedAndMalformedIsReported(t *testing.T) {
	paths := ConfigPathsForRoot(t.TempDir())
	if err := os.MkdirAll(paths.PoliciesDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.PoliciesDir, "z.json"), []byte(`{"version":1,"policy":{"sensitive_keys":["z"]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.PoliciesDir, "a.json"), []byte(`{"version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	items, err := LoadPersistentPolicies(paths, "")
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if items[0].Name != "a" || !errors.Is(items[0].Err, ErrConfigVersion) || items[1].Name != "z" {
		t.Fatalf("items=%#v", items)
	}
}

func TestInitConfigIsIdempotentAndRestrictive(t *testing.T) {
	paths := ConfigPathsForRoot(filepath.Join(t.TempDir(), "safecat"))
	if err := InitConfig(paths, false); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(paths.ConfigFile); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config mode: %v %v", info, err)
	}
	if err := InitConfig(paths, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second init: %v", err)
	}
}
