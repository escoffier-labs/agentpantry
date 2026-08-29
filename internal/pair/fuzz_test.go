package pair

import (
	"io"
	"testing"
)

func FuzzNormalizeCode(f *testing.F) {
	f.Add("ABCD-EFGH")
	f.Add("abcdefgh")
	f.Add("OI1L-0000")
	f.Add("")
	f.Add("not a code!!")
	f.Fuzz(func(t *testing.T, s string) {
		got, err := NormalizeCode(s)
		if err != nil {
			return
		}
		again, err := NormalizeCode(got)
		if err != nil {
			t.Fatalf("canonical %q failed re-normalize: %v", got, err)
		}
		if again != got {
			t.Fatalf("normalize not idempotent: %q -> %q", got, again)
		}
	})
}

func FuzzReadMsg(f *testing.F) {
	var buf []byte
	_ = writeMsg(&sliceWriter{&buf}, msgShare, []byte("share"))
	f.Add(buf)
	f.Add([]byte{0, 0, 0, 2, 1, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = readMsg(&sliceReader{b}) // must not panic
	})
}

type sliceWriter struct{ dst *[]byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w.dst = append(*w.dst, p...)
	return len(p), nil
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
