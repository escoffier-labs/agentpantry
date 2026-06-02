package surface

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cookie"
)

type netscapeRow struct {
	domain     string
	includeSub bool
	path       string
	secure     bool
	expiry     int64 // unix seconds, 0=session
	name       string
	value      string
}

// Netscape writes a Netscape-format cookies.txt (curl/wget/yt-dlp).
type Netscape struct {
	path string
	rows map[string]netscapeRow // keyed by cookie.Key
}

func NewNetscape(path string) (*Netscape, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	n := &Netscape{path: path, rows: map[string]netscapeRow{}}
	if err := n.seed(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *Netscape) seed() error {
	f, err := os.Open(n.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 7 {
			continue
		}
		exp, _ := strconv.ParseInt(parts[4], 10, 64)
		r := netscapeRow{
			domain:     parts[0],
			includeSub: parts[1] == "TRUE",
			path:       parts[2],
			secure:     parts[3] == "TRUE",
			expiry:     exp,
			name:       parts[5],
			value:      parts[6],
		}
		n.rows[cookie.Key(cookie.Cookie{Host: r.domain, Name: r.name, Path: r.path})] = r
	}
	return sc.Err()
}

func (n *Netscape) Apply(d cookie.Diff) error {
	for _, c := range d.Upserts {
		n.rows[cookie.Key(c)] = netscapeRow{
			domain:     c.Host,
			includeSub: strings.HasPrefix(c.Host, "."),
			path:       c.Path,
			secure:     c.IsSecure,
			expiry:     cookie.ExpiresUnix(c.ExpiresUTC),
			name:       c.Name,
			value:      c.Value,
		}
	}
	for _, k := range d.Deletes {
		delete(n.rows, k)
	}
	return n.write()
}

func (n *Netscape) write() error {
	keys := make([]string, 0, len(n.rows))
	for k := range n.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	for _, k := range keys {
		r := n.rows[k]
		b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.domain, boolTF(r.includeSub), r.path, boolTF(r.secure), r.expiry, r.name, r.value))
	}
	return os.WriteFile(n.path, []byte(b.String()), 0o600)
}

func boolTF(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}
