package safecat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ConfigVersion = 1

var (
	ErrConfigUnavailable = errors.New("safecat: user configuration unavailable")
	ErrConfigMalformed   = errors.New("safecat: malformed configuration")
	ErrConfigVersion     = errors.New("safecat: unsupported configuration version")
	ErrUnsafeConfig      = errors.New("safecat: unsafe configuration permissions or path")
)

type ConfigPaths struct{ Base, ConfigFile, PoliciesDir string }

func UserConfigPaths() (ConfigPaths, error) {
	root := ""
	// Go's os.UserConfigDir honors XDG_CONFIG_HOME on Linux, but not on
	// every Unix platform. Respect it explicitly when supplied so safecat is
	// predictable for portable shells and hermetic tests.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		root = xdg
	}
	var err error
	if root == "" {
		root, err = os.UserConfigDir()
	}
	if err != nil || root == "" {
		return ConfigPaths{}, ErrConfigUnavailable
	}
	return ConfigPathsForRoot(filepath.Join(root, "safecat")), nil
}

func ConfigPathsForRoot(base string) ConfigPaths {
	return ConfigPaths{Base: base, ConfigFile: filepath.Join(base, "config.json"), PoliciesDir: filepath.Join(base, "policies")}
}

// ProjectPolicy returns the policy in the current working directory, if one
// exists. Project discovery is deliberately non-recursive and never walks
// into unrelated parent directories.
func ProjectPolicy() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".safecat.json")
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return path, nil
}

func ValidatePolicyName(name string) bool {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

type ConfigDocument struct {
	Version int    `json:"version"`
	Name    string `json:"name,omitempty"`
	Policy  Policy `json:"policy"`
}

func decodePolicyDocument(data []byte, path string) (Policy, string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return Policy{}, "", ErrConfigMalformed
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Policy{}, "", ErrConfigMalformed
	}
	if v, ok := raw["version"]; ok {
		var version int
		if json.Unmarshal(v, &version) != nil || version != ConfigVersion {
			return Policy{}, "", ErrConfigVersion
		}
		var doc ConfigDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return Policy{}, "", ErrConfigMalformed
		}
		if doc.Name != "" && !ValidatePolicyName(doc.Name) {
			return Policy{}, "", ErrConfigMalformed
		}
		if err := doc.Policy.Validate(); err != nil {
			return Policy{}, "", err
		}
		return doc.Policy, doc.Name, nil
	}
	// Preserve compatibility with existing explicit, unversioned policy files.
	var p Policy
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, "", ErrConfigMalformed
	}
	if err := p.Validate(); err != nil {
		return Policy{}, "", err
	}
	return p, "", nil
}

func LoadPolicyFile(path string) (Policy, error) {
	p, _, err := loadPolicyDocument(path)
	if err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			return Policy{}, err
		}
		return Policy{}, ErrInvalidPolicy
	}
	return p, nil
}

func loadPolicyDocument(path string) (Policy, string, error) {
	data, err := readConfigFile(path, MaxPolicyBytes)
	if err != nil {
		return Policy{}, "", err
	}
	return decodePolicyDocument(data, path)
}

func readConfigFile(path string, max int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, ErrUnsafeConfig
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, ErrUnsafeConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafeConfig
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(data) > max {
		return nil, ErrConfigMalformed
	}
	return data, nil
}

func MergePolicies(base, overlay Policy) Policy {
	out := base
	if overlay.Replacement != "" {
		out.Replacement = overlay.Replacement
	}
	if overlay.Literal != "" {
		out.Literal = overlay.Literal
	}
	out.SensitiveKeys = appendUnique(out.SensitiveKeys, overlay.SensitiveKeys...)
	out.SensitivePaths = appendUnique(out.SensitivePaths, overlay.SensitivePaths...)
	out.Regex = mergeRegex(out.Regex, overlay.Regex)
	if out.DetectorPriority == nil {
		out.DetectorPriority = map[string]int{}
	}
	for k, v := range overlay.DetectorPriority {
		out.DetectorPriority[k] = v
	}
	return out
}

func appendUnique(base []string, values ...string) []string {
	seen := map[string]bool{}
	for _, v := range base {
		seen[v] = true
	}
	for _, v := range values {
		if v != "" && !seen[v] {
			base = append(base, v)
			seen[v] = true
		}
	}
	return base
}
func mergeRegex(base, values []PolicyRegex) []PolicyRegex {
	result := append([]PolicyRegex(nil), base...)
	indexes := map[string]int{}
	for i, r := range result {
		if r.Name != "" {
			indexes[r.Name] = i
		}
	}
	for _, r := range values {
		if i, ok := indexes[r.Name]; ok {
			result[i] = r
		} else {
			indexes[r.Name] = len(result)
			result = append(result, r)
		}
	}
	return result
}

type LoadedPolicy struct {
	Name, Path string
	Policy     Policy
	Err        error
}

func LoadPersistentPolicies(paths ConfigPaths, selected string) ([]LoadedPolicy, error) {
	var loaded []LoadedPolicy
	if selected != "" && !ValidatePolicyName(selected) {
		return nil, ErrInvalidPolicy
	}
	entries, err := os.ReadDir(paths.PoliciesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return loaded, nil
		}
		return nil, ErrUnsafeConfig
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidatePolicyName(name) {
			continue
		}
		if selected != "" && name != selected {
			continue
		}
		p, docName, e := loadPolicyDocument(filepath.Join(paths.PoliciesDir, entry.Name()))
		if docName != "" && docName != name {
			e = ErrConfigMalformed
		}
		loaded = append(loaded, LoadedPolicy{Name: name, Path: filepath.Join(paths.PoliciesDir, entry.Name()), Policy: p, Err: e})
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Name < loaded[j].Name })
	return loaded, nil
}

func LoadEffectivePolicy(paths ConfigPaths, project string, selected string, explicit string) (Policy, []LoadedPolicy, error) {
	policy := DefaultPolicyConfig()
	var origins []LoadedPolicy
	if data, err := readConfigFile(paths.ConfigFile, MaxPolicyBytes); err == nil {
		p, name, e := decodePolicyDocument(data, paths.ConfigFile)
		if e != nil {
			return Policy{}, nil, e
		}
		policy = MergePolicies(policy, p)
		origins = append(origins, LoadedPolicy{Name: nameOr(name, "user"), Path: paths.ConfigFile, Policy: p})
	} else if !errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil, err
	}
	policies, err := LoadPersistentPolicies(paths, selected)
	if err != nil {
		return Policy{}, nil, err
	}
	for _, item := range policies {
		if item.Err != nil {
			return Policy{}, nil, fmt.Errorf("%s: %w", item.Name, item.Err)
		}
		policy = MergePolicies(policy, item.Policy)
		origins = append(origins, item)
	}
	if project != "" {
		if p, _, err := loadPolicyDocument(project); err == nil {
			policy = MergePolicies(policy, p)
			origins = append(origins, LoadedPolicy{Name: "project", Path: project, Policy: p})
		} else if !errors.Is(err, os.ErrNotExist) {
			return Policy{}, nil, err
		}
	}
	if explicit != "" {
		p, err := LoadPolicyFile(explicit)
		if err != nil {
			return Policy{}, nil, err
		}
		policy = MergePolicies(policy, p)
		origins = append(origins, LoadedPolicy{Name: "explicit", Path: explicit, Policy: p})
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, nil, err
	}
	return policy, origins, nil
}
func nameOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func InitConfig(paths ConfigPaths, force bool) error {
	if err := os.MkdirAll(paths.Base, 0700); err != nil {
		return err
	}
	if err := os.Chmod(paths.Base, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(paths.PoliciesDir, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(paths.ConfigFile); err == nil && !force {
		return os.ErrExist
	} else if err != nil && !os.IsNotExist(err) {
		return ErrUnsafeConfig
	}
	if !force {
		if entries, _ := os.ReadDir(paths.PoliciesDir); len(entries) > 0 {
			return os.ErrExist
		}
	}
	doc := ConfigDocument{Version: ConfigVersion, Policy: DefaultPolicyConfig()}
	data, _ := json.MarshalIndent(doc, "", "  ")
	data = append(data, '\n')
	tmp, err := os.CreateTemp(paths.Base, ".config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, paths.ConfigFile)
}
