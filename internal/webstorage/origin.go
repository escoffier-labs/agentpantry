package webstorage

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ValidateOrigin rejects storage origins that Chrome would canonicalize before
// exact-origin matching or that contain URL components beyond an origin. Only
// an exact canonical HTTP(S) origin is accepted; unsafe input is never
// normalized and passed onward. Canonical dotted-decimal IPv4 and compressed
// lowercase IPv6 literals are allowed (including non-loopback). Errors are
// generic and never echo the raw origin.
func ValidateOrigin(raw string) error {
	invalid := fmt.Errorf("invalid storage origin")
	if raw == "" || !isASCII(raw) {
		return invalid
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalid
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalid
	}
	if u.Opaque != "" || u.User != nil {
		return invalid
	}
	if u.Host == "" || u.Hostname() == "" {
		return invalid
	}
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return invalid
	}

	host := u.Hostname()
	if !isASCII(host) {
		return invalid
	}

	var canonicalHost string
	switch {
	case strings.HasPrefix(u.Host, "["):
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return invalid
		}
		// IPv4-mapped IPv6 (::ffff:...) is rejected: Chrome serializes these
		// differently from netip, so accepting them would let a row pass
		// preflight and then fail exact target-origin ownership checks.
		if addr.Is4In6() {
			return invalid
		}
		if host != addr.String() {
			return invalid
		}
		canonicalHost = "[" + addr.String() + "]"
	case isLegacyIPv4Candidate(host):
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is4() || addr.String() != host {
			return invalid
		}
		canonicalHost = host
	default:
		if !isCanonicalASCIIHostname(host) {
			return invalid
		}
		canonicalHost = host
	}

	canonical := u.Scheme + "://" + canonicalHost
	if port := u.Port(); port != "" {
		if !isCanonicalOriginPort(u.Scheme, port) {
			return invalid
		}
		canonical += ":" + port
	}
	if raw != canonical {
		return invalid
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// isLegacyIPv4NumberCandidate reports whether label is a WHATWG-style IPv4
// number candidate: all ASCII decimal digits, or 0x/0X followed by one or
// more ASCII hex digits.
func isLegacyIPv4NumberCandidate(label string) bool {
	if label == "" {
		return false
	}
	if len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
		for i := 2; i < len(label); i++ {
			c := label[i]
			isDigit := c >= '0' && c <= '9'
			isLower := c >= 'a' && c <= 'f'
			isUpper := c >= 'A' && c <= 'F'
			if !isDigit && !isLower && !isUpper {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// isLegacyIPv4Candidate reports hostnames Chrome may reinterpret as IPv4
// because the final dotted label is a WHATWG-style IPv4 number candidate.
func isLegacyIPv4Candidate(host string) bool {
	if host == "" {
		return false
	}
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return isLegacyIPv4NumberCandidate(parts[len(parts)-1])
}

func isCanonicalASCIIHostname(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isLetter := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLetter && !isDigit && c != '-' {
				return false
			}
		}
	}
	return true
}

func isCanonicalOriginPort(scheme, port string) bool {
	if port == "" {
		return false
	}
	if len(port) > 1 && port[0] == '0' {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
		return false
	}
	return strconv.Itoa(n) == port
}
