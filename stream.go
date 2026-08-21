package safecat

import (
	"io"
)

// Stream copies src to dst in fixed-size chunks. Errors are returned without
// writing diagnostics or source data; callers decide how to report them.
func Stream(src io.Reader, dst io.Writer, engine *Engine, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = 32 << 10
	}
	buf := make([]byte, chunkSize)
	var offset int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			ev, e := engine.Process(Chunk{Data: buf[:n], Offset: offset})
			if e != nil {
				return e
			}
			if e = writeAll(dst, ev.Data); e != nil {
				return e
			}
			offset += int64(n)
		}
		if err == io.EOF {
			ev, e := engine.Finish()
			if e != nil {
				return e
			}
			if len(ev.Data) > 0 {
				e = writeAll(dst, ev.Data)
			}
			return e
		}
		if err != nil {
			return err
		}
	}
}

func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
