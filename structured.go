package safecat

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// StructuredFormat is an advisory format hint. Unknown input uses the
// ordinary byte engine; JSON/YAML candidates are parsed and fail closed.
type StructuredFormat string

const (
	FormatUnknown StructuredFormat = "unknown"
	FormatAuto    StructuredFormat = "auto"
	FormatPlain   StructuredFormat = "plain"
	FormatJSON    StructuredFormat = "json"
	FormatYAML    StructuredFormat = "yaml"
)

type StructuredOptions struct {
	MaxBytes     int
	MaxDocuments int
}

func DefaultStructuredOptions() StructuredOptions {
	return StructuredOptions{MaxBytes: 8 << 20, MaxDocuments: 128}
}

var ErrStructuredMalformed = errors.New("safecat: malformed or ambiguous structured input")

func DetectFormat(input []byte) StructuredFormat {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return FormatUnknown
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return FormatJSON
	}
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "---" || line == "..." || yamlLinePattern.MatchString(line) || strings.HasPrefix(line, "- ") {
			return FormatYAML
		}
	}
	return FormatUnknown
}

func DetectStructuredFormat(input []byte) StructuredFormat { return DetectFormat(input) }

// RedactStructured returns no partial output on error. Base64 values are
// treated as opaque strings and are never decoded or printed.
func RedactStructured(input []byte, options StructuredOptions) ([]byte, error) {
	return RedactStructuredWithPolicy(input, options, DefaultPolicyConfig())
}

func RedactStructuredWithPolicy(input []byte, options StructuredOptions, policy Policy) ([]byte, error) {
	return RedactStructuredAs(input, options, FormatAuto, policy)
}

// RedactStructuredAs applies an explicit format contract. Auto retains the
// advisory fallback behavior; plain bypasses structured parsing; yaml/json
// reject input whose detected format does not match.
func RedactStructuredAs(input []byte, options StructuredOptions, format StructuredFormat, policy Policy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	options = normalizeStructuredOptions(options)
	if len(input) > options.MaxBytes {
		return nil, ErrLimitExceeded
	}
	detected := DetectFormat(input)
	if format == FormatPlain {
		e := NewEngine(policy.Registry(), policy.Redaction())
		ev, err := e.Process(Chunk{Data: input, Final: true})
		if err != nil {
			return nil, err
		}
		return ev.Data, nil
	}
	if format != FormatAuto && format != FormatUnknown && format != detected {
		return nil, ErrStructuredMalformed
	}
	switch detected {
	case FormatJSON:
		out, err := redactJSON(input, options, policy)
		if err != nil {
			return nil, err
		}
		return redactPolicyText(out, policy)
	case FormatYAML:
		out, err := redactYAML(input, options, policy)
		if err != nil {
			return nil, err
		}
		return redactPolicyText(out, policy)
	default:
		e := NewEngine(policy.Registry(), policy.Redaction())
		ev, err := e.Process(Chunk{Data: input, Final: true})
		if err != nil {
			return nil, err
		}
		return ev.Data, nil
	}
}

func redactPolicyText(input []byte, policy Policy) ([]byte, error) {
	e := NewEngine(policy.CustomRegistry(), policy.Redaction())
	ev, err := e.Process(Chunk{Data: input, Final: true})
	if err != nil {
		return nil, err
	}
	return ev.Data, nil
}

func normalizeStructuredOptions(o StructuredOptions) StructuredOptions {
	d := DefaultStructuredOptions()
	if o.MaxBytes > 0 {
		d.MaxBytes = o.MaxBytes
	}
	if o.MaxDocuments > 0 {
		d.MaxDocuments = o.MaxDocuments
	}
	return d
}

func redactJSON(input []byte, options StructuredOptions, policy Policy) ([]byte, error) {
	if err := validateJSONKeys(input); err != nil {
		return nil, ErrStructuredMalformed
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, ErrStructuredMalformed
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrStructuredMalformed
	}
	if err := redactJSONValue(value, nil, value, policy); err != nil {
		return nil, err
	}
	out, err := json.Marshal(value)
	if err != nil || len(out) > options.MaxBytes {
		if len(out) > options.MaxBytes {
			return nil, ErrLimitExceeded
		}
		return nil, ErrStructuredMalformed
	}
	return out, nil
}

func validateJSONKeys(input []byte) error {
	dec := json.NewDecoder(bytes.NewReader(input))
	first, err := dec.Token()
	if err != nil {
		return err
	}
	if err = validateJSONToken(dec, first); err != nil {
		return err
	}
	if _, err = dec.Token(); err != io.EOF {
		return ErrStructuredMalformed
	}
	return nil
}

func validateJSONToken(dec *json.Decoder, token json.Token) error {
	switch d := token.(type) {
	case json.Delim:
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return ErrStructuredMalformed
				}
				seen[key] = true
				value, err := dec.Token()
				if err != nil {
					return err
				}
				if err := validateJSONToken(dec, value); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return ErrStructuredMalformed
			}
		case '[':
			for dec.More() {
				value, err := dec.Token()
				if err != nil {
					return err
				}
				if err := validateJSONToken(dec, value); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return ErrStructuredMalformed
			}
		default:
			return ErrStructuredMalformed
		}
	}
	return nil
}

func redactJSONValue(value any, path []string, root any, policy Policy) error {
	switch v := value.(type) {
	case map[string]any:
		if isSecretRoot(v) {
			root = v
		}
		for key, child := range v {
			childPath := append(append([]string(nil), path...), key)
			if (strings.EqualFold(key, "data") || strings.EqualFold(key, "stringData")) && isSecretRoot(root) {
				switch child.(type) {
				case map[string]any, []any:
				default:
					v[key] = jsonReplacement(child, policy)
					continue
				}
			}
			if shouldRedactPath(childPath, root, policy) {
				v[key] = jsonReplacement(child, policy)
				continue
			}
			if err := redactJSONValue(child, childPath, root, policy); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range v {
			if err := redactJSONValue(child, append(path, fmt.Sprint(i)), root, policy); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonReplacement(value any, policy Policy) string {
	text := "value"
	if original, ok := value.(string); ok {
		text = original
	}
	return string(Redact([]byte(text), []Match{{Start: 0, End: len(text)}}, policy.Redaction()))
}

func isSecretRoot(root any) bool {
	obj, ok := root.(map[string]any)
	if !ok {
		return false
	}
	kind, ok := obj["kind"].(string)
	return ok && strings.EqualFold(kind, "secret")
}

func shouldRedactPath(path []string, root any, policy Policy) bool {
	if len(path) == 0 {
		return false
	}
	key := strings.ToLower(path[len(path)-1])
	rootObject, _ := root.(map[string]any)
	for _, p := range path[:len(path)-1] {
		if strings.EqualFold(p, "data") || strings.EqualFold(p, "stringData") {
			if kind, ok := rootObject["kind"].(string); ok && strings.EqualFold(kind, "secret") {
				return true
			}
		}
	}
	return sensitiveField(key) || policy.matchesKey(key) || policy.matchesPath(path)
}

func sensitiveField(key string) bool {
	key = strings.ToLower(key)
	if slash := strings.LastIndexByte(key, '/'); slash >= 0 {
		key = key[slash+1:]
	}
	return strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "passwd") || key == "secret" || strings.HasSuffix(key, "-secret") || strings.HasSuffix(key, "_secret") || (strings.Contains(key, "private") && strings.Contains(key, "key")) || key == "client-key" || key == "client-key-data" || key == "client-certificate" || key == "client-certificate-data" || key == "certificate-authority-data" || key == "private-key"
}

var yamlLinePattern = regexp.MustCompile(`^(?:[- ]*[A-Za-z_][A-Za-z0-9_./-]*\s*:|kind\s*:)`)
var yamlKeyPattern = regexp.MustCompile(`^(\s*)(?:-\s*)?(?:["']?([A-Za-z_][A-Za-z0-9_./-]*)["']?)\s*:\s*(.*)$`)

type yamlStackEntry struct {
	indent int
	key    string
}

func redactYAML(input []byte, options StructuredOptions, policy Policy) ([]byte, error) {
	lines := splitKeepEndings(input)
	for _, line := range lines {
		content, _ := stripEnding(line)
		if hasTabIndent(content) {
			return nil, ErrStructuredMalformed
		}
	}
	docForLine, secretDocs, documentCount := yamlDocumentInfo(lines)
	if documentCount > options.MaxDocuments {
		return nil, ErrLimitExceeded
	}
	var out bytes.Buffer
	var stack []yamlStackEntry
	blockIndent := -1
	block := false
	for lineIndex, line := range lines {
		content, ending := stripEnding(line)
		trimmed := strings.TrimSpace(content)
		if trimmed == "---" {
			stack = nil
			block = false
			blockIndent = -1
			out.WriteString(line)
			continue
		}
		if trimmed == "..." {
			stack = nil
			block = false
			blockIndent = -1
			out.WriteString(line)
			continue
		}
		indent := leadingSpaces(content)
		if block {
			if trimmed == "" || indent > blockIndent {
				out.WriteString(indentString(indent) + policyMarker(policy) + ending)
				continue
			}
			block = false
			blockIndent = -1
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			continue
		}
		match := yamlKeyPattern.FindStringSubmatch(content)
		if match == nil {
			if strings.HasPrefix(trimmed, "-") {
				return nil, ErrStructuredMalformed
			}
			return nil, ErrStructuredMalformed
		}
		if strings.ContainsAny(match[3], "{}[]") || strings.ContainsAny(match[3], "&*") {
			return nil, ErrStructuredMalformed
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		key, rest := match[2], match[3]
		path := make([]string, 0, len(stack)+1)
		for _, entry := range stack {
			path = append(path, entry.key)
		}
		path = append(path, key)
		secretDoc := secretDocs[docForLine[lineIndex]]
		if rest == "" || rest == "|" || rest == ">" || strings.HasPrefix(rest, "|-") || strings.HasPrefix(rest, ">-") {
			if rest != "" && shouldRedactYAMLPath(path, secretDoc, policy) {
				block = true
				blockIndent = indent
				out.WriteString(match[1] + match[2] + ": " + rest + ending)
				continue
			}
			out.WriteString(line)
			stack = append(stack, yamlStackEntry{indent, key})
			continue
		}
		if shouldRedactYAMLPath(path, secretDoc, policy) || strings.Contains(rest, "-----BEGIN") {
			out.WriteString(match[1] + match[2] + ": " + quoteLike(rest, yamlReplacement(rest, policy)) + ending)
		} else {
			out.WriteString(line)
		}
		stack = append(stack, yamlStackEntry{indent, key})
	}
	return out.Bytes(), nil
}

func yamlReplacement(value string, policy Policy) string {
	scalar, _ := splitInlineComment(strings.TrimSpace(value))
	if scalar == "" {
		scalar = "value"
	}
	return string(Redact([]byte(scalar), []Match{{Start: 0, End: len(scalar)}}, policy.Redaction()))
}

func policyMarker(policy Policy) string { return yamlReplacement("value", policy) }

// yamlDocumentInfo classifies each document before redaction, making Secret
// handling independent of field order. Content before a first explicit --- is
// counted as an implicit document.
func yamlDocumentInfo(lines []string) ([]int, []bool, int) {
	docForLine := make([]int, len(lines))
	secretDocs := []bool{false}
	doc, seenContent := 0, false
	hadExplicitMarker, documentEnded := false, false
	for i, line := range lines {
		content, _ := stripEnding(line)
		trimmed := strings.TrimSpace(content)
		if trimmed == "---" {
			if seenContent {
				doc++
				secretDocs = append(secretDocs, false)
			} else if !hadExplicitMarker {
				doc = 0
			}
			hadExplicitMarker, seenContent, documentEnded = true, false, false
			docForLine[i] = doc
			continue
		}
		if documentEnded && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			doc++
			secretDocs = append(secretDocs, false)
			documentEnded, seenContent = false, false
		}
		docForLine[i] = doc
		if trimmed == "..." {
			documentEnded = true
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		seenContent = true
		if match := yamlKeyPattern.FindStringSubmatch(content); match != nil && strings.EqualFold(match[2], "kind") {
			kindValue, _ := splitInlineComment(strings.TrimSpace(match[3]))
			if strings.EqualFold(kindValue, "Secret") {
				secretDocs[doc] = true
			}
		}
	}
	return docForLine, secretDocs, doc + 1
}

func shouldRedactYAMLPath(path []string, secretDoc bool, policy Policy) bool {
	for _, p := range path {
		if secretDoc && (strings.EqualFold(p, "data") || strings.EqualFold(p, "stringData")) {
			return true
		}
	}
	return len(path) > 0 && (sensitiveField(path[len(path)-1]) || policy.matchesKey(path[len(path)-1]) || policy.matchesPath(path))
}
func quoteLike(value, replacement string) string {
	v, comment := splitInlineComment(strings.TrimSpace(value))
	result := replacement
	if strings.HasPrefix(v, "\"") {
		result = `"` + replacement + `"`
	} else if strings.HasPrefix(v, "'") {
		result = `'` + replacement + `'`
	}
	if comment != "" {
		return result + " " + comment
	}
	return result
}

func splitInlineComment(value string) (string, string) {
	quote := byte(0)
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\'', '"':
			if quote == 0 {
				quote = value[i]
			} else if quote == value[i] {
				quote = 0
			}
		case '#':
			if quote == 0 && i > 0 && (value[i-1] == ' ' || value[i-1] == '\t') {
				return strings.TrimSpace(value[:i]), strings.TrimSpace(value[i:])
			}
		}
	}
	return value, ""
}
func splitKeepEndings(input []byte) []string {
	var lines []string
	start := 0
	for i, b := range input {
		if b == '\n' {
			lines = append(lines, string(input[start:i+1]))
			start = i + 1
		}
	}
	if start < len(input) {
		lines = append(lines, string(input[start:]))
	}
	return lines
}
func stripEnding(line string) (string, string) {
	if strings.HasSuffix(line, "\r\n") {
		return strings.TrimSuffix(line, "\r\n"), "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return strings.TrimSuffix(line, "\n"), "\n"
	}
	return line, ""
}
func leadingSpaces(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }
func indentString(n int) string  { return strings.Repeat(" ", n) }

func hasTabIndent(s string) bool {
	for _, r := range s {
		if r == '\t' {
			return true
		}
		if r != ' ' {
			return false
		}
	}
	return false
}
