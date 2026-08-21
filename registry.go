package safecat

import "sort"

// Registry holds detectors in registration order. Registration order is only
// the final tie breaker; resolution is otherwise confidence, priority, span,
// and detector name, making output deterministic.
type Registry struct{ detectors []Detector }

func NewRegistry(detectors ...Detector) *Registry {
	r := &Registry{}
	for _, d := range detectors {
		r.Register(d)
	}
	return r
}

func (r *Registry) Register(d Detector) {
	if d != nil {
		r.detectors = append(r.detectors, d)
	}
}
func (r *Registry) Detectors() []Detector { return append([]Detector(nil), r.detectors...) }

func (r *Registry) Detect(data []byte) ([]Match, error) {
	var all []Match
	for _, d := range r.detectors {
		for _, m := range d.Detect(data) {
			if m.Start < 0 || m.End <= m.Start || m.End > len(data) || m.Confidence < 0 || m.Confidence > 1 {
				return nil, ErrInvalidMatch
			}
			if m.Detector == "" {
				m.Detector = d.Name()
			}
			all = append(all, m)
		}
	}
	return resolveMatches(all), nil
}

func (r *Registry) hasPendingPrefix(data []byte) bool {
	for _, d := range r.detectors {
		if p, ok := d.(pendingPrefixDetector); ok && p.PendingPrefix(data) {
			return true
		}
	}
	return false
}

func resolveMatches(matches []Match) []Match {
	// Select by strength first, so a high-confidence match can displace a
	// weaker match that starts later inside it. Sort the result by source order.
	sort.SliceStable(matches, func(i, j int) bool { return stronger(matches[i], matches[j]) })
	selected := make([]Match, 0, len(matches))
	for _, m := range matches {
		overlap := false
		for _, chosen := range selected {
			if m.Start < chosen.End && chosen.Start < m.End {
				overlap = true
				break
			}
		}
		if !overlap {
			selected = append(selected, m)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })
	return selected
}

func stronger(a, b Match) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.End != b.End {
		return a.End > b.End
	}
	if a.Start != b.Start {
		return a.Start < b.Start
	}
	return a.Detector < b.Detector
}
