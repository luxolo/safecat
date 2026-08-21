package safecat

// Chunk is one input fragment. Offset is the absolute byte offset in the
// source; Final is true only for the last fragment.
type Chunk struct {
	Data   []byte
	Offset int64
	Final  bool
}

// OutputEvent describes transformed bytes without retaining the whole stream.
// Diagnostic is safe metadata only; implementations must not put source data
// or match snippets in it.
type OutputEvent struct {
	Data       []byte
	Offset     int64
	Diagnostic string
}

// Match is a half-open byte span [Start, End). Spans refer to the input passed
// to Detector.Detect. Confidence is in [0,1]; Priority breaks equal-confidence
// overlaps deterministically. Detector is an identifying, non-secret name.
type Match struct {
	Start      int
	End        int
	Confidence float64
	Priority   int
	Detector   string
}

// Detector finds secret spans in a byte slice. It must not mutate the input or
// include secret values in errors/diagnostics. A detector may return matches
// that overlap results from other detectors.
type Detector interface {
	Name() string
	Detect([]byte) []Match
}

type Strategy string

const (
	StrategyLiteral Strategy = "literal"
	StrategyMask    Strategy = "mask"
	StrategyHash    Strategy = "hash"
)

// RedactionPolicy controls replacement independently of detection.
type RedactionPolicy struct {
	Strategy Strategy
	Literal  string
}

func DefaultPolicy() RedactionPolicy {
	return RedactionPolicy{Strategy: StrategyLiteral, Literal: "REDACTED"}
}
