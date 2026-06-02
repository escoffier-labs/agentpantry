package surface

import "testing"

func FuzzParseNetscapeLine(f *testing.F) {
	f.Add("a.com\tFALSE\t/\tFALSE\t0\tn\tv")
	f.Add("# comment")
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseNetscapeLine(line) // must not panic
	})
}
