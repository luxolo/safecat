package safecat

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type fixedDetector struct {
	name    string
	matches []Match
}

func (d fixedDetector) Name() string          { return d.name }
func (d fixedDetector) Detect([]byte) []Match { return d.matches }

func TestRegistryResolvesOverlapByConfidenceAndPriority(t *testing.T) {
	r := NewRegistry(fixedDetector{"weak", []Match{{Start: 2, End: 8, Confidence: .5, Priority: 100}}}, fixedDetector{"strong", []Match{{Start: 0, End: 5, Confidence: .9, Priority: 1}}})
	got, err := r.Detect([]byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Detector != "strong" {
		t.Fatalf("unexpected matches: %#v", got)
	}
}

func TestStreamingDetectsSplitJWTAndPreservesBytes(t *testing.T) {
	e := NewEngine(NewRegistry(JWTs()), DefaultPolicy())
	var out []byte
	for i, c := range []Chunk{{Data: []byte("before eyJabc.def")}, {Data: []byte(".ghi after\r\n")}, {Final: true}} {
		ev, err := e.Process(c)
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && len(out) > 7 {
			t.Fatalf("split secret emitted before detection: %q", out)
		}
		out = append(out, ev.Data...)
	}
	if string(out) != "before REDACTED after\r\n" {
		t.Fatalf("got %q", out)
	}
}

func TestStreamingDetectsSplitPasswordField(t *testing.T) {
	e := NewEngine(NewRegistry(PasswordFields()), DefaultPolicy())
	var out []byte
	input := []byte("password=fake-password-value\n")
	for i := 0; i < len(input); i += 3 {
		end := i + 3
		if end > len(input) {
			end = len(input)
		}
		ev, err := e.Process(Chunk{Data: input[i:end]})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev.Data...)
	}
	ev, err := e.Finish()
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, ev.Data...)
	if string(out) != "password=REDACTED\n" {
		t.Fatalf("got %q", out)
	}
}

func TestPlainTextEmitsBeforeEOF(t *testing.T) {
	e := NewEngine(DefaultRegistry(), DefaultPolicy())
	ev, err := e.Process(Chunk{Data: []byte("safe")})
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.Data) != "safe" {
		t.Fatalf("got pre-EOF output %q", ev.Data)
	}
}

func TestPEMIsRedactedAcrossChunks(t *testing.T) {
	e := NewEngine(NewRegistry(PEMPrivateKeys()), DefaultPolicy())
	input := "x\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\ny"
	var out []byte
	for i := 0; i < len(input); i += 7 {
		end := i + 7
		if end > len(input) {
			end = len(input)
		}
		ev, err := e.Process(Chunk{Data: []byte(input[i:end])})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev.Data...)
	}
	ev, err := e.Finish()
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, ev.Data...)
	if string(out) != "x\nREDACTED\ny" {
		t.Fatalf("got %q", out)
	}
}

func TestRedactionStrategies(t *testing.T) {
	m := []Match{{Start: 0, End: 6}}
	if got := string(Redact([]byte("secret"), m, RedactionPolicy{Strategy: StrategyMask})); got != "******" {
		t.Fatal(got)
	}
	if got := string(Redact([]byte("secret"), m, RedactionPolicy{Strategy: StrategyHash})); got != "HASH[2bb80d53]" {
		t.Fatal(got)
	}
}

func TestStreamHandlesInvalidUTF8AndWriteError(t *testing.T) {
	input := bytes.NewReader([]byte{'x', 0xff, '\n'})
	var output bytes.Buffer
	if err := Stream(input, &output, NewEngine(NewRegistry(), DefaultPolicy()), 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), []byte{'x', 0xff, '\n'}) {
		t.Fatalf("bytes changed: %v", output.Bytes())
	}
	_, err := io.Copy(io.Discard, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("write failed")
	if err := Stream(bytes.NewReader([]byte("x")), errorWriter{writeErr}, NewEngine(NewRegistry(), DefaultPolicy()), 1); !errors.Is(err, writeErr) {
		t.Fatalf("got %v", err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestStreamRejectsShortWrite(t *testing.T) {
	err := Stream(bytes.NewReader([]byte("safe")), shortWriter{}, NewEngine(NewRegistry(), DefaultPolicy()), 4)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v", err)
	}
}

func TestPendingLimitNeverEmitsUnredactedTail(t *testing.T) {
	e := NewEngine(DefaultRegistry(), DefaultPolicy())
	e.MaxPending = 8
	e.TailLookahead = 8
	ev, err := e.Process(Chunk{Data: []byte("-----BE")})
	if err != nil || len(ev.Data) != 0 {
		t.Fatalf("event=%#v err=%v", ev, err)
	}
	if _, err = e.Process(Chunk{Data: []byte("xx")}); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("got %v", err)
	}
}
