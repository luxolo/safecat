package safecat

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
)

const MaxPolicyBytes = 1 << 20

type Policy struct {
	Replacement      string         `json:"replacement"`
	Literal          string         `json:"literal"`
	SensitiveKeys    []string       `json:"sensitive_keys"`
	SensitivePaths   []string       `json:"sensitive_paths"`
	Regex            []PolicyRegex  `json:"regex"`
	DetectorPriority map[string]int `json:"detector_priority"`
}

type PolicyRegex struct {
	Name       string  `json:"name"`
	Pattern    string  `json:"pattern"`
	Priority   int     `json:"priority"`
	Confidence float64 `json:"confidence"`
}

var ErrInvalidPolicy = errors.New("safecat: invalid policy")

func DefaultPolicyConfig() Policy {
	return Policy{Replacement: string(StrategyLiteral), Literal: "REDACTED"}
}

func (p Policy) Validate() error {
	if p.Replacement == "" {
		p.Replacement = string(StrategyLiteral)
	}
	if p.Replacement != string(StrategyLiteral) && p.Replacement != string(StrategyMask) && p.Replacement != string(StrategyHash) {
		return ErrInvalidPolicy
	}
	if p.Literal == "" {
		p.Literal = "REDACTED"
	}
	for _, key := range append(append([]string{}, p.SensitiveKeys...), p.SensitivePaths...) {
		if key == "" || len(key) > 256 {
			return ErrInvalidPolicy
		}
	}
	for _, rule := range p.Regex {
		if rule.Name == "" || rule.Pattern == "" || len(rule.Pattern) > 4096 {
			return ErrInvalidPolicy
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return ErrInvalidPolicy
		}
		if rule.Confidence < 0 || rule.Confidence > 1 {
			return ErrInvalidPolicy
		}
	}
	return nil
}

func (p Policy) Redaction() RedactionPolicy {
	strategy := Strategy(p.Replacement)
	if strategy == "" {
		strategy = StrategyLiteral
	}
	literal := p.Literal
	if literal == "" {
		literal = "REDACTED"
	}
	return RedactionPolicy{Strategy: strategy, Literal: literal}
}

func (p Policy) Registry() *Registry {
	r := NewRegistry()
	base := DefaultRegistry().Detectors()
	for _, d := range base {
		priority := p.DetectorPriority[d.Name()]
		if priority == 0 {
			r.Register(d)
		} else {
			r.Register(priorityDetector{Detector: d, Priority: priority})
		}
	}
	for _, rule := range p.Regex {
		r.Register(makeCustomDetector(rule))
	}
	return r
}

func (p Policy) CustomRegistry() *Registry {
	r := NewRegistry()
	for _, rule := range p.Regex {
		r.Register(makeCustomDetector(rule))
	}
	return r
}

func makeCustomDetector(rule PolicyRegex) Detector {
	re := regexp.MustCompile(rule.Pattern)
	confidence := rule.Confidence
	if confidence == 0 {
		confidence = .9
	}
	return customRegexDetector{name: rule.Name, re: re, priority: rule.Priority, confidence: confidence}
}

func (p Policy) matchesKey(key string) bool {
	for _, candidate := range p.SensitiveKeys {
		if candidate == key || equalFold(candidate, key) {
			return true
		}
	}
	return false
}
func (p Policy) matchesPath(path []string) bool {
	parts := make([]string, 0, len(path))
	for _, part := range path {
		if part != "" && allDigits(part) {
			continue
		}
		parts = append(parts, part)
	}
	joined := stringsJoin(parts, ".")
	for _, candidate := range p.SensitivePaths {
		last := ""
		if len(parts) > 0 {
			last = parts[len(parts)-1]
		}
		if candidate == joined || candidate == "*."+last || equalFold(candidate, joined) {
			return true
		}
	}
	return false
}
func equalFold(a, b string) bool { return len(a) == len(b) && bytes.EqualFold([]byte(a), []byte(b)) }
func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}
func stringsJoin(parts []string, separator string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += separator
		}
		result += part
	}
	return result
}

type priorityDetector struct {
	Detector
	Priority int
}

func (d priorityDetector) Detect(data []byte) []Match {
	matches := d.Detector.Detect(data)
	for i := range matches {
		matches[i].Priority = d.Priority
	}
	return matches
}

type customRegexDetector struct {
	name       string
	re         *regexp.Regexp
	priority   int
	confidence float64
}

func (d customRegexDetector) Name() string { return d.name }
func (d customRegexDetector) Detect(data []byte) []Match {
	var out []Match
	for _, loc := range d.re.FindAllIndex(data, -1) {
		out = append(out, Match{Start: loc[0], End: loc[1], Detector: d.name, Priority: d.priority, Confidence: d.confidence})
	}
	return out
}

type RuleExplanation struct {
	Rule     string
	Location string
}

func (p Policy) Explain(input []byte) []RuleExplanation {
	matches, _ := p.Registry().Detect(input)
	out := make([]RuleExplanation, 0, len(matches)+len(p.SensitiveKeys)+len(p.SensitivePaths))
	for _, m := range matches {
		out = append(out, RuleExplanation{Rule: m.Detector, Location: "byte:" + itoa(m.Start) + "-" + itoa(m.End)})
	}
	if DetectFormat(input) == FormatJSON {
		out = append(out, p.explainJSON(input)...)
	} else {
		out = append(out, p.explainYAML(input)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Location < out[j].Location })
	return out
}

func (p Policy) explainJSON(input []byte) []RuleExplanation {
	var root any
	if json.Unmarshal(input, &root) != nil {
		return nil
	}
	var out []RuleExplanation
	var walk func(any, []string)
	walk = func(value any, path []string) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				childPath := append(append([]string(nil), path...), key)
				location := "line:" + itoa(lineForKey(input, key))
				if p.matchesKey(key) {
					out = append(out, RuleExplanation{Rule: "policy-key:" + key, Location: location})
				}
				for _, candidate := range p.SensitivePaths {
					if candidate == normalizedPath(childPath) || candidate == "*."+key {
						if p.matchesPath(childPath) {
							out = append(out, RuleExplanation{Rule: "policy-path:" + candidate, Location: location})
						}
					}
				}
				walk(child, childPath)
			}
		case []any:
			for i, child := range v {
				walk(child, append(path, itoa(i)))
			}
		}
	}
	walk(root, nil)
	return out
}

func (p Policy) explainYAML(input []byte) []RuleExplanation {
	var out []RuleExplanation
	for lineNumber, line := range bytes.Split(input, []byte("\n")) {
		for _, key := range p.SensitiveKeys {
			if bytes.Contains(line, []byte(key+":")) {
				out = append(out, RuleExplanation{Rule: "policy-key:" + key, Location: "line:" + itoa(lineNumber+1)})
			}
		}
		for _, path := range p.SensitivePaths {
			parts := stringsSplit(path, ".")
			if len(parts) > 0 && bytes.Contains(line, []byte(parts[len(parts)-1]+":")) {
				out = append(out, RuleExplanation{Rule: "policy-path:" + path, Location: "line:" + itoa(lineNumber+1)})
			}
		}
	}
	return out
}

func lineForKey(input []byte, key string) int {
	index := bytes.Index(input, []byte(`"`+key+`"`))
	if index < 0 {
		index = bytes.Index(input, []byte(key+":"))
	}
	if index < 0 {
		return 1
	}
	return 1 + bytes.Count(input[:index], []byte("\n"))
}
func normalizedPath(parts []string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if !allDigits(part) {
			filtered = append(filtered, part)
		}
	}
	return stringsJoin(filtered, ".")
}
func stringsSplit(value, separator string) []string {
	var out []string
	for value != "" {
		index := bytes.Index([]byte(value), []byte(separator))
		if index < 0 {
			return append(out, value)
		}
		out = append(out, value[:index])
		value = value[index+len(separator):]
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
