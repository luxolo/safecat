package safecat

import (
	"crypto/sha256"
	"encoding/hex"
)

func (p RedactionPolicy) replacement(original []byte) []byte {
	switch p.Strategy {
	case StrategyMask:
		out := make([]byte, len(original))
		for i := range out {
			out[i] = '*'
		}
		return out
	case StrategyHash:
		h := sha256.Sum256(original)
		return []byte("HASH[" + hex.EncodeToString(h[:])[:8] + "]")
	default:
		literal := p.Literal
		if literal == "" {
			literal = "REDACTED"
		}
		return []byte(literal)
	}
}

func Redact(data []byte, matches []Match, policy RedactionPolicy) []byte {
	if len(matches) == 0 {
		return append([]byte(nil), data...)
	}
	out := make([]byte, 0, len(data))
	pos := 0
	for _, m := range matches {
		out = append(out, data[pos:m.Start]...)
		out = append(out, policy.replacement(data[m.Start:m.End])...)
		pos = m.End
	}
	return append(out, data[pos:]...)
}
