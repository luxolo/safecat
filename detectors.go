package safecat

import (
	"bytes"
	"regexp"
)

type regexpDetector struct {
	name       string
	priority   int
	confidence float64
	re         *regexp.Regexp
	group      int
}

func (d regexpDetector) Name() string { return d.name }

func (d regexpDetector) PendingPrefix(data []byte) bool {
	switch d.name {
	case "jwt":
		return regexp.MustCompile(`(?i)(?:\beyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){0,2})$`).Match(data)
	case "pem-private-key":
		start := bytes.LastIndex(data, []byte("-----BEGIN"))
		if start >= 0 {
			return !d.re.Match(data[start:])
		}
		for i := 1; i < len("-----BEGIN"); i++ {
			if bytes.HasSuffix(data, []byte("-----BEGIN"[:i])) {
				return true
			}
		}
		return false
	case "password-field":
		return regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*["']?[^\s"',;}\]]*$`).Match(data)
	case "common-token":
		return regexp.MustCompile(`(?:gh[pousr]_?|github_pat_|sk-|xox[baprs]-|AKIA)[A-Za-z0-9_-]*$`).Match(data)
	default:
		return false
	}
}
func (d regexpDetector) Detect(data []byte) []Match {
	var out []Match
	for _, loc := range d.re.FindAllSubmatchIndex(data, -1) {
		s, e := loc[2*d.group], loc[2*d.group+1]
		out = append(out, Match{Start: s, End: e, Confidence: d.confidence, Priority: d.priority, Detector: d.name})
	}
	return out
}

func PasswordFields() Detector {
	return regexpDetector{"password-field", 80, .96, regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*["']?([^\s"',;}\]]+)`), 1}
}
func JWTs() Detector {
	return regexpDetector{"jwt", 70, .93, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), 0}
}
func PEMPrivateKeys() Detector {
	return regexpDetector{"pem-private-key", 100, 1, regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), 0}
}
func CommonTokens() Detector {
	return regexpDetector{"common-token", 60, .90, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AKIA[0-9A-Z]{16})\b`), 0}
}

func DefaultRegistry() *Registry {
	return NewRegistry(PasswordFields(), JWTs(), PEMPrivateKeys(), CommonTokens())
}
