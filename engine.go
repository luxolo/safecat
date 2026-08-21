package safecat

// Engine incrementally transforms data while retaining at most MaxPending
// bytes. TailLookahead is retained between calls so boundary-spanning tokens
// and multiline secrets are not emitted before detection can see them.
type Engine struct {
	registry                  *Registry
	policy                    RedactionPolicy
	pending                   []byte
	offset                    int64
	MaxPending, TailLookahead int
}

type pendingPrefixDetector interface {
	PendingPrefix([]byte) bool
}

func NewEngine(registry *Registry, policy RedactionPolicy) *Engine {
	if registry == nil {
		registry = NewRegistry()
	}
	return &Engine{registry: registry, policy: policy, MaxPending: 1 << 20, TailLookahead: 64 << 10}
}

func (e *Engine) Process(c Chunk) (OutputEvent, error) {
	if len(e.pending)+len(c.Data) > e.MaxPending {
		return OutputEvent{}, ErrLimitExceeded
	}
	buf := make([]byte, 0, len(e.pending)+len(c.Data))
	buf = append(buf, e.pending...)
	buf = append(buf, c.Data...)
	matches, err := e.registry.Detect(buf)
	if err != nil {
		return OutputEvent{}, err
	}
	emit := len(buf)
	if !c.Final {
		if len(matches) == 0 && !e.registry.hasPendingPrefix(buf) {
			// Plain text with no possible partial secret need not wait for
			// EOF. Detectors opt into retaining their own partial prefixes.
			emit = len(buf)
		} else {
			emit -= e.TailLookahead
			if emit < 0 {
				emit = 0
			}
			for _, m := range matches {
				if m.Start < emit && m.End > emit {
					emit = m.Start
				}
			}
		}
	}
	if emit == 0 && !c.Final {
		e.pending = buf
		return OutputEvent{Offset: e.offset}, nil
	}
	var visible, hold []byte
	visible, hold = buf[:emit], buf[emit:]
	var visibleMatches []Match
	for _, m := range matches {
		if m.End <= emit {
			visibleMatches = append(visibleMatches, m)
		}
	}
	out := Redact(visible, visibleMatches, e.policy)
	e.pending = append([]byte(nil), hold...)
	ev := OutputEvent{Data: out, Offset: e.offset}
	// Offset is an input offset, so replacement length must not affect it.
	e.offset += int64(len(visible))
	if c.Final {
		e.pending = nil
	}
	return ev, nil
}

func (e *Engine) Finish() (OutputEvent, error) { return e.Process(Chunk{Final: true}) }
