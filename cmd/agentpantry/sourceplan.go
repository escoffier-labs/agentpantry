package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/escoffier-labs/agentpantry/internal/cdpvault"
	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/receipt"
)

// Values the source plan reports. capture_coverage and website_authentication
// are fixed: a plan reads config and file metadata only, so it cannot know how
// many cookies a capture would carry, whose account they belong to, or whether
// any of them still log in.
const (
	planReady            = "ready"
	planNotReady         = "not_ready"
	planNotMeasured      = "not_measured"
	planNotVerified      = "not_verified"
	planAccountIdentity  = "unknown"
	planStorePresent     = "present"
	planStoreMissing     = "missing"
	planStoreNotChecked  = "not_checked"
	planStoreInvalid     = "invalid"
	planRouteStdio       = "stdio"
	planRouteTCP         = "tcp"
	planRoutePeerless    = "peerless"
	planModeOnce         = "once"
	planModeWatch        = "watch"
	planDomainPolicyRule = "deny wins; a host must equal or be a subdomain of an allow entry; empty allow permits nothing"
	planNamePolicyRule   = "deny wins; exact secret names; empty allow permits every name"
)

// sourcePlan is the read-only disclosure plan printed by `source -dry-run`. It
// describes what a real source run with the same config and flags would read
// and where it would send it. It is built from the parsed config plus
// os.Stat metadata only: no key, cookie, localStorage, or secret value is read,
// no keyring or browser is queried, no CDP endpoint or peer is contacted, no
// salt or frame is written, and no state or receipt file is touched.
type sourcePlan struct {
	DryRun        bool                `json:"dry_run"`
	Config        string              `json:"config"`
	Role          string              `json:"role"`
	Mode          string              `json:"mode"`
	ResyncSeconds int                 `json:"resync_seconds"`
	Route         sourcePlanRoute     `json:"route"`
	Key           sourcePlanFile      `json:"key"`
	Browsers      []sourcePlanBrowser `json:"browsers"`
	DomainPolicy  sourcePlanPolicy    `json:"domain_policy"`
	SecretPolicy  sourcePlanPolicy    `json:"secret_name_policy"`
	SecretSources sourcePlanSecrets   `json:"secret_sources"`
	LocalWrites   []sourcePlanWrite   `json:"local_writes"`
	Status        sourcePlanStatus    `json:"status"`
	Problems      []string            `json:"problems"`
	Notes         []string            `json:"notes"`
}

type sourcePlanRoute struct {
	Kind   string `json:"kind"`
	Peer   string `json:"peer"`
	Detail string `json:"detail"`
}

type sourcePlanFile struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    string `json:"mode"`
}

type sourcePlanBrowser struct {
	Kind                string `json:"kind"`
	Profile             string `json:"profile"`
	Mechanism           string `json:"mechanism"`
	Store               string `json:"store"`
	StoreCheck          string `json:"store_check"`
	CaptureLocalStorage bool   `json:"capture_localstorage"`
	AccountIdentity     string `json:"account_identity"`
}

type sourcePlanPolicy struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	Rule  string   `json:"rule"`
}

type sourcePlanSecrets struct {
	SecretsDir sourcePlanSecretsDir `json:"secrets_dir"`
	Keepass    sourcePlanKeepass    `json:"keepass"`
}

type sourcePlanSecretsDir struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	Present bool   `json:"present"`
}

type sourcePlanKeepass struct {
	Enabled  bool           `json:"enabled"`
	Path     string         `json:"path"`
	Present  bool           `json:"present"`
	Tag      string         `json:"tag"`
	Keyfile  sourcePlanFile `json:"keyfile"`
	PassFile sourcePlanFile `json:"pass_file"`
}

type sourcePlanWrite struct {
	Purpose string `json:"purpose"`
	Path    string `json:"path"`
}

type sourcePlanStatus struct {
	ConfigReadiness       string `json:"config_readiness"`
	CaptureCoverage       string `json:"capture_coverage"`
	WebsiteAuthentication string `json:"website_authentication"`
}

// statFile reports path metadata without opening the file. An empty path is
// reported as absent.
func statFile(path string) sourcePlanFile {
	f := sourcePlanFile{Path: path}
	if path == "" {
		return f
	}
	info, err := os.Stat(path)
	if err != nil {
		return f
	}
	f.Present = true
	f.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	return f
}

// statCredFile stats a KeePass credential file (keepass_keyfile or
// keepass_pass_file) and returns the first problem the real reader's
// loadCredFile would raise that metadata alone can show: a missing path, a
// path that is not a regular file, group or other permission bits (off
// Windows), or an empty file. The file is never opened. An empty problem
// means the metadata checks passed.
func statCredFile(field, path string) (sourcePlanFile, string) {
	f := sourcePlanFile{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		return f, fmt.Sprintf("%s not found at %s", field, path)
	}
	f.Present = true
	f.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	switch {
	case !info.Mode().IsRegular():
		return f, fmt.Sprintf("%s %s is not a regular file", field, path)
	case runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0:
		return f, fmt.Sprintf("%s perms %04o are too open, want 0600", field, info.Mode().Perm())
	case info.Size() == 0:
		return f, fmt.Sprintf("%s %s is empty", field, path)
	}
	return f, ""
}

func chromiumMechanism() string {
	if runtime.GOOS == "windows" {
		return "copy the Chromium Cookies DB, decrypt values with the DPAPI key from Local State"
	}
	return "copy the Chromium Cookies DB, decrypt values with the Chrome Safe Storage key from the Secret Service"
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// buildSourcePlan derives the plan from config and file metadata. It applies
// the startup checks cmdSource and buildVaults run, plus the presence checks
// doctor runs on configured stores, so a plan with no problems describes a
// config the real source would accept.
func buildSourcePlan(cfgPath string, c config.Config, stdio, once bool, unknownKeys []string) sourcePlan {
	p := sourcePlan{
		DryRun:   true,
		Config:   cfgPath,
		Role:     c.Role,
		Mode:     planModeWatch,
		Browsers: []sourcePlanBrowser{},
		DomainPolicy: sourcePlanPolicy{
			Allow: nonNil(c.Domains.Allow),
			Deny:  nonNil(c.Domains.Deny),
			Rule:  planDomainPolicyRule,
		},
		SecretPolicy: sourcePlanPolicy{
			Allow: nonNil(c.SecretNames.Allow),
			Deny:  nonNil(c.SecretNames.Deny),
			Rule:  planNamePolicyRule,
		},
		LocalWrites: []sourcePlanWrite{},
		Status: sourcePlanStatus{
			CaptureCoverage:       planNotMeasured,
			WebsiteAuthentication: planNotVerified,
		},
		Problems: []string{},
		Notes:    []string{},
	}
	if once {
		p.Mode = planModeOnce
	}
	problem := func(format string, a ...any) { p.Problems = append(p.Problems, fmt.Sprintf(format, a...)) }
	note := func(format string, a ...any) { p.Notes = append(p.Notes, fmt.Sprintf(format, a...)) }

	for _, k := range unknownKeys {
		note("unknown config key %q is ignored", k)
	}
	if c.Role != "source" {
		problem("role is %q, want \"source\"", c.Role)
	}

	// Route. A peerless config is reported, not rejected: it exists so an
	// external scheduler can drive explicit capture pairs.
	switch {
	case c.Peerless():
		p.Route = sourcePlanRoute{
			Kind:   planRoutePeerless,
			Peer:   c.Peer,
			Detail: "no network peer; an external scheduler drives capture, and `agentpantry source` refuses to run this config",
		}
	case stdio:
		p.Route = sourcePlanRoute{
			Kind:   planRouteStdio,
			Peer:   c.Peer,
			Detail: "issue the session salt and stream sealed frames to stdout; the peer is not dialed",
		}
	default:
		p.Route = sourcePlanRoute{
			Kind:   planRouteTCP,
			Peer:   c.Peer,
			Detail: "dial the peer over TCP, receive the sink's session salt, push sealed frames",
		}
		if _, _, err := net.SplitHostPort(c.Peer); err != nil {
			problem("peer %q is not host:port", c.Peer)
		}
	}

	// Key: metadata only. The real run loads it with keyfile.Load, which needs
	// a regular file and, off Windows, no group or other permission bits.
	p.Key = sourcePlanFile{Path: c.KeyPath}
	if c.KeyPath == "" {
		problem("key_path is not set")
	} else if info, err := os.Stat(c.KeyPath); err != nil {
		problem("key file not found at %s", c.KeyPath)
	} else {
		p.Key.Present = true
		p.Key.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
		if !info.Mode().IsRegular() {
			problem("key path %s is not a regular file", c.KeyPath)
		} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			problem("key perms %04o are too open, want 0600", info.Mode().Perm())
		}
	}

	hasCDP := false
	for _, b := range c.Browsers {
		row := sourcePlanBrowser{
			Kind:                b.Kind,
			Profile:             b.Profile,
			CaptureLocalStorage: b.CaptureLocalStorage,
			AccountIdentity:     planAccountIdentity,
		}
		switch b.Kind {
		case "chromium", "firefox":
			if b.Kind == "chromium" {
				row.Mechanism = chromiumMechanism()
			} else {
				row.Mechanism = "copy the Firefox cookies.sqlite DB; values are stored in plaintext"
			}
			row.Store = b.CookiePath
			switch {
			case b.CookiePath == "":
				row.StoreCheck = planStoreMissing
				problem("%s browser %q has no cookie_path", b.Kind, b.Profile)
			case statFile(b.CookiePath).Present:
				row.StoreCheck = planStorePresent
			default:
				row.StoreCheck = planStoreMissing
				problem("cookie store for %s browser %q not found at %s", b.Kind, b.Profile, b.CookiePath)
			}
		case "cdp":
			hasCDP = true
			row.Mechanism = "read cookies over the loopback DevTools endpoint (Storage.getCookies)"
			if b.CaptureLocalStorage {
				row.Mechanism += " and localStorage for permitted origins"
			}
			row.Store = b.URL
			if err := cdpvault.ValidateLoopbackURL(b.URL, "http", "https"); err != nil {
				row.StoreCheck = planStoreInvalid
				problem("cdp browser %q must use a loopback URL: %v", b.Profile, err)
			} else {
				row.StoreCheck = planStoreNotChecked
			}
		default:
			row.Mechanism = "unsupported"
			row.Store = b.CookiePath
			row.StoreCheck = planStoreInvalid
			problem("unsupported browser kind %q (supported: chromium, firefox, cdp)", b.Kind)
		}
		if b.CaptureLocalStorage && b.Kind != "cdp" {
			problem("capture_localstorage is only supported for kind = \"cdp\" browsers, not %q", b.Kind)
		}
		p.Browsers = append(p.Browsers, row)
	}

	// Secret sources: metadata only. File contents and vault entries are
	// never opened. KeePass credential files get the stat-level checks the
	// real reader applies before it opens them.
	if c.SecretsDir != "" {
		p.SecretSources.SecretsDir = sourcePlanSecretsDir{
			Enabled: true,
			Path:    c.SecretsDir,
			Present: statFile(c.SecretsDir).Present,
		}
		if !p.SecretSources.SecretsDir.Present {
			problem("secrets_dir not found at %s", c.SecretsDir)
		}
	}
	if c.KeepassPath != "" {
		kp := sourcePlanKeepass{
			Enabled: true,
			Path:    c.KeepassPath,
			Present: statFile(c.KeepassPath).Present,
			Tag:     c.KeepassTagOrDefault(),
		}
		if c.KeepassKeyfile == "" {
			problem("keepass_keyfile is required when keepass_path is set")
		} else {
			var msg string
			if kp.Keyfile, msg = statCredFile("keepass_keyfile", c.KeepassKeyfile); msg != "" {
				problem("%s", msg)
			}
		}
		if c.KeepassPassFile != "" {
			var msg string
			if kp.PassFile, msg = statCredFile("keepass_pass_file", c.KeepassPassFile); msg != "" {
				problem("%s", msg)
			}
		}
		if !kp.Present {
			problem("keepass_path not found at %s", c.KeepassPath)
		}
		p.SecretSources.Keepass = kp
	}

	// Mode and resync, matching cmdSource's cdp default.
	p.ResyncSeconds = c.ResyncSeconds
	if hasCDP && c.ResyncSeconds == 0 && !once {
		p.ResyncSeconds = int(defaultCDPResync.Seconds())
		note("cdp source detected: resync defaults to %ds", p.ResyncSeconds)
	}

	// Local files a real run would write.
	p.LocalWrites = append(p.LocalWrites, sourcePlanWrite{Purpose: "state", Path: statePath(cfgPath)})
	if c.Receipts.Enabled {
		logPath := receipt.ResolvePath(c, cfgPath)
		p.LocalWrites = append(p.LocalWrites,
			sourcePlanWrite{Purpose: "receipts", Path: logPath},
			sourcePlanWrite{Purpose: "receipts_head", Path: receipt.HeadPath(logPath)},
		)
	}

	if len(c.Browsers) == 0 && c.SecretsDir == "" && c.KeepassPath == "" {
		note("no browsers or secret sources are configured: a real run would capture nothing")
	}
	if len(c.Browsers) > 0 && len(c.Domains.Allow) == 0 {
		note("domains.allow is empty: no cookies or localStorage would sync")
	}
	if c.WarnExpiryDays > 0 && len(c.Browsers) > 0 {
		note("warn_expiry_days is set: a real run reads cookies once at startup for the near-expiry warning; this plan did not")
	}
	note("account identity cannot be established from config or file metadata; a successful capture of one profile does not cover another")

	if len(p.Problems) == 0 {
		p.Status.ConfigReadiness = planReady
	} else {
		p.Status.ConfigReadiness = planNotReady
	}
	return p
}

// printSourcePlan writes the plan as indented JSON or as a readable listing.
func printSourcePlan(w io.Writer, p sourcePlan, jsonOut bool) error {
	if jsonOut {
		b, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	var sb strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&sb, format+"\n", a...) }
	list := func(items []string, empty string) string {
		if len(items) == 0 {
			return empty
		}
		return strings.Join(items, ", ")
	}

	line("source plan (dry run): config and file metadata only; no values read, nothing dialed or written")
	line("config: %s", p.Config)
	line("role: %s", p.Role)
	if p.ResyncSeconds > 0 {
		line("mode: %s (resync %ds)", p.Mode, p.ResyncSeconds)
	} else {
		line("mode: %s", p.Mode)
	}
	if p.Route.Peer != "" {
		line("route: %s, peer %s: %s", p.Route.Kind, p.Route.Peer, p.Route.Detail)
	} else {
		line("route: %s: %s", p.Route.Kind, p.Route.Detail)
	}
	if p.Key.Present {
		line("key: %s (present, mode %s; contents not read)", p.Key.Path, p.Key.Mode)
	} else {
		line("key: %s (missing)", p.Key.Path)
	}
	line("browsers:")
	if len(p.Browsers) == 0 {
		line("  none")
	}
	for _, b := range p.Browsers {
		line("  - %s profile %q", b.Kind, b.Profile)
		line("    mechanism: %s", b.Mechanism)
		line("    store: %s (%s)", b.Store, b.StoreCheck)
		line("    capture_localstorage: %t", b.CaptureLocalStorage)
		line("    account identity: %s", b.AccountIdentity)
	}
	line("domain policy (%s):", p.DomainPolicy.Rule)
	line("  allow: %s", list(p.DomainPolicy.Allow, "none"))
	line("  deny: %s", list(p.DomainPolicy.Deny, "none"))
	line("secret name policy (%s):", p.SecretPolicy.Rule)
	line("  allow: %s", list(p.SecretPolicy.Allow, "all"))
	line("  deny: %s", list(p.SecretPolicy.Deny, "none"))
	line("secret sources (values not read):")
	if sd := p.SecretSources.SecretsDir; sd.Enabled {
		line("  secrets_dir: %s (present: %t)", sd.Path, sd.Present)
	} else {
		line("  secrets_dir: disabled")
	}
	if kp := p.SecretSources.Keepass; kp.Enabled {
		line("  keepass: %s (present: %t, tag %q)", kp.Path, kp.Present, kp.Tag)
	} else {
		line("  keepass: disabled")
	}
	line("local writes on a real run:")
	for _, lw := range p.LocalWrites {
		line("  %s: %s", lw.Purpose, lw.Path)
	}
	line("status:")
	line("  config_readiness: %s", p.Status.ConfigReadiness)
	line("  capture_coverage: %s", p.Status.CaptureCoverage)
	line("  website_authentication: %s", p.Status.WebsiteAuthentication)
	line("problems:")
	if len(p.Problems) == 0 {
		line("  none")
	}
	for _, pr := range p.Problems {
		line("  - %s", pr)
	}
	line("notes:")
	for _, n := range p.Notes {
		line("  - %s", n)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// runSourcePlan prints the plan and fails when the config would not start a
// real source, so a wrapper can gate execution on the exit status as well as on
// status.config_readiness.
func runSourcePlan(w io.Writer, cfgPath string, c config.Config, stdio, once, jsonOut bool, unknownKeys []string) error {
	p := buildSourcePlan(cfgPath, c, stdio, once, unknownKeys)
	if err := printSourcePlan(w, p, jsonOut); err != nil {
		return err
	}
	if p.Status.ConfigReadiness != planReady {
		return fmt.Errorf("source plan found %d problem(s)", len(p.Problems))
	}
	return nil
}
