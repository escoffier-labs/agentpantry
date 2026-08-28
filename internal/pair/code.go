package pair

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"
)

// Crockford base32 without I, L, O, U to cut transcription errors.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeBytes is the entropy of a pairing code (40 bits).
const CodeBytes = 5

// GenerateCode returns a one-time XXXX-XXXX Crockford code.
func GenerateCode() (string, error) {
	raw := make([]byte, CodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	enc := encodeCrockford(raw)
	return formatCode(enc), nil
}

// NormalizeCode accepts hyphenated or bare Crockford input, folds case, and
// maps I/L→1 and O→0. The returned value is the canonical XXXX-XXXX form used
// as the SPAKE2 password so both ends hash the same bytes.
func NormalizeCode(s string) (string, error) {
	var b strings.Builder
	b.Grow(8)
	for _, r := range s {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		r = unicode.ToUpper(r)
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if strings.IndexByte(crockfordAlphabet, byte(r)) < 0 {
			return "", errInvalidCode
		}
		b.WriteByte(byte(r))
	}
	if b.Len() != 8 {
		return "", errInvalidCode
	}
	return formatCode(b.String()), nil
}

func formatCode(enc string) string {
	return enc[:4] + "-" + enc[4:]
}

func encodeCrockford(raw []byte) string {
	var n uint64
	for _, v := range raw {
		n = (n << 8) | uint64(v)
	}
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = crockfordAlphabet[n&31]
		n >>= 5
	}
	return string(out)
}

var errInvalidCode = fmt.Errorf("invalid pairing code")
