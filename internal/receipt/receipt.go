// Package receipt writes and verifies local hash-chained sync receipts.
//
// Each record is one JSON line: timestamp, source/sink identity, event type,
// a value-free content digest of the synced payload, the previous record's
// hash, and an HMAC. Cookie, secret, and localStorage values are never
// written — only counts and identifiers used to form the digest.
package receipt

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/escoffier-labs/agentpantry/internal/config"
	"github.com/escoffier-labs/agentpantry/internal/cookie"
	"github.com/escoffier-labs/agentpantry/internal/privfile"
	"github.com/escoffier-labs/agentpantry/internal/secret"
	"github.com/escoffier-labs/agentpantry/internal/webstorage"
	"github.com/escoffier-labs/agentpantry/internal/wire"
	"golang.org/x/crypto/hkdf"
)

const (
	// SchemaVersion is the current receipt record version.
	SchemaVersion = 1

	// EventSend is written by a source after a non-empty frame is sent.
	EventSend = "sync.send"
	// EventApply is written by a sink after a non-empty frame is applied.
	EventApply = "sync.apply"

	// GenesisPrev is prev_hash for the first record in a log.
	GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

	maxLine    = 256 * 1024
	macInfo    = "agentpantry/v1 receipt mac"
	hashHexLen = 64
	filePerm   = 0o600
	dirPerm    = 0o700
)

// Record is one append-only JSON line. It never carries cookie, secret, or
// localStorage values — only identities, event metadata, and digests.
type Record struct {
	V           int    `json:"v"`
	Seq         int    `json:"seq"`
	TS          string `json:"ts"`
	Role        string `json:"role"`
	SourceID    string `json:"source_id"`
	SinkID      string `json:"sink_id"`
	Event       string `json:"event"`
	PayloadHash string `json:"payload_hash"`
	PrevHash    string `json:"prev_hash"`
	Sig         string `json:"sig"`
}

// signBody is the canonical encoding covered by Sig. Field order is load-bearing.
type signBody struct {
	V           int    `json:"v"`
	Seq         int    `json:"seq"`
	TS          string `json:"ts"`
	Role        string `json:"role"`
	SourceID    string `json:"source_id"`
	SinkID      string `json:"sink_id"`
	Event       string `json:"event"`
	PayloadHash string `json:"payload_hash"`
	PrevHash    string `json:"prev_hash"`
}

// tipFile is the 0600 pointer stored beside the log so a deleted or truncated
// chain cannot verify as intact.
type tipFile struct {
	Seq  int    `json:"seq"`
	Hash string `json:"hash"`
	Sig  string `json:"sig"`
}

type tipBody struct {
	Seq  int    `json:"seq"`
	Hash string `json:"hash"`
}

// summary is the canonical, value-free description hashed into payload_hash.
type summary struct {
	CookieUpserts  int      `json:"cookie_upserts"`
	CookieDeletes  int      `json:"cookie_deletes"`
	CookieSlots    []string `json:"cookie_slots"`
	SecretUpserts  int      `json:"secret_upserts"`
	SecretDeletes  int      `json:"secret_deletes"`
	SecretNames    []string `json:"secret_names"`
	StorageUpserts int      `json:"storage_upserts"`
	StorageDeletes int      `json:"storage_deletes"`
	StorageSlots   []string `json:"storage_slots"`
}

// Log is an append-only receipt file bound to a MAC key.
type Log struct {
	Path     string
	Key      []byte
	Role     string
	SourceID string
	SinkID   string
	Now      func() time.Time

	mu sync.Mutex
}

// ResolvePath returns the receipt file path: an explicit config path, or
// receipts.jsonl beside cfgPath, or receipts.jsonl in the default config dir.
func ResolvePath(c config.Config, cfgPath string) string {
	if c.Receipts.Path != "" {
		return c.Receipts.Path
	}
	if cfgPath != "" {
		return filepath.Join(filepath.Dir(cfgPath), "receipts.jsonl")
	}
	return filepath.Join(config.Dir(), "receipts.jsonl")
}

// HeadPath returns the tip-pointer path beside the log (`receipts.jsonl` →
// `receipts.head`).
func HeadPath(logPath string) string {
	if strings.HasSuffix(logPath, ".jsonl") {
		return strings.TrimSuffix(logPath, ".jsonl") + ".head"
	}
	return logPath + ".head"
}

// Identity returns the configured per-node identity, or the hostname when
// unset. The transport is PSK-only, so this string is asserted, not proven.
func Identity(c config.Config) string {
	if s := strings.TrimSpace(c.Receipts.Identity); s != "" {
		return s
	}
	h, err := os.Hostname()
	if err != nil {
		return "agentpantry"
	}
	h = strings.TrimSpace(h)
	if h == "" {
		return "agentpantry"
	}
	return h
}

// DeriveMACKey returns a 32-byte HMAC key from the 32-byte transport PSK.
func DeriveMACKey(psk []byte) ([]byte, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("receipt key must be 32 bytes, got %d", len(psk))
	}
	r := hkdf.New(sha256.New, psk, nil, []byte(macInfo))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// PayloadHash returns the hex SHA-256 of a canonical value-free summary of p.
func PayloadHash(p wire.Payload) (string, error) {
	s := summarize(p)
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func summarize(p wire.Payload) summary {
	s := summary{
		CookieUpserts:  len(p.Cookies.Upserts),
		CookieDeletes:  len(p.Cookies.Deletes),
		SecretUpserts:  len(p.Secrets.Upserts),
		SecretDeletes:  len(p.Secrets.Deletes),
		StorageUpserts: len(p.Storage.Upserts),
		StorageDeletes: len(p.Storage.Deletes),
	}
	slots := make([]string, 0, len(p.Cookies.Upserts)+len(p.Cookies.Deletes))
	for _, c := range p.Cookies.Upserts {
		slots = append(slots, cookie.Key(c))
	}
	slots = append(slots, p.Cookies.Deletes...)
	sort.Strings(slots)
	s.CookieSlots = slots

	names := make([]string, 0, len(p.Secrets.Upserts)+len(p.Secrets.Deletes))
	for _, sec := range p.Secrets.Upserts {
		names = append(names, secret.Key(sec))
	}
	names = append(names, p.Secrets.Deletes...)
	sort.Strings(names)
	s.SecretNames = names

	stSlots := make([]string, 0, len(p.Storage.Upserts)+len(p.Storage.Deletes))
	for _, it := range p.Storage.Upserts {
		stSlots = append(stSlots, webstorage.Key(it))
	}
	stSlots = append(stSlots, p.Storage.Deletes...)
	sort.Strings(stSlots)
	s.StorageSlots = stSlots
	return s
}

func (l *Log) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now().UTC()
}

// Append writes one receipt for a successful non-empty sync event.
func (l *Log) Append(event string, p wire.Payload) error {
	if l.Path == "" {
		return errors.New("receipt path is empty")
	}
	if event == "" {
		return errors.New("receipt event is empty")
	}
	payloadHash, err := PayloadHash(p)
	if err != nil {
		return err
	}
	macKey, err := DeriveMACKey(l.Key)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.Path), dirPerm); err != nil {
		return err
	}
	prev, lastSeq, tip, hasTip, err := lastState(l.Path)
	if err != nil {
		return err
	}
	if hasTip && tip.Seq > lastSeq {
		return fmt.Errorf("receipt tip seq %d is ahead of log seq %d (log truncated?)", tip.Seq, lastSeq)
	}
	if !hasTip && lastSeq == 0 {
		if err := writeTip(HeadPath(l.Path), macKey, 0, GenesisPrev); err != nil {
			return err
		}
	}
	rec := Record{
		V:           SchemaVersion,
		Seq:         lastSeq + 1,
		TS:          l.now().UTC().Format(time.RFC3339),
		Role:        l.Role,
		SourceID:    l.SourceID,
		SinkID:      l.SinkID,
		Event:       event,
		PayloadHash: payloadHash,
		PrevHash:    prev,
	}
	sig, err := sign(macKey, rec)
	if err != nil {
		return err
	}
	rec.Sig = sig
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(line) > maxLine {
		return fmt.Errorf("receipt line exceeds %d bytes", maxLine)
	}
	if err := appendLine(l.Path, line); err != nil {
		return err
	}
	return writeTip(HeadPath(l.Path), macKey, rec.Seq, recordHash(line))
}

func sign(macKey []byte, rec Record) (string, error) {
	body := signBody{
		V:           rec.V,
		Seq:         rec.Seq,
		TS:          rec.TS,
		Role:        rec.Role,
		SourceID:    rec.SourceID,
		SinkID:      rec.SinkID,
		Event:       rec.Event,
		PayloadHash: rec.PayloadHash,
		PrevHash:    rec.PrevHash,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func verifySig(keys [][]byte, rec Record) error {
	var last error
	for _, key := range keys {
		macKey, err := DeriveMACKey(key)
		if err != nil {
			last = err
			continue
		}
		want, err := sign(macKey, rec)
		if err != nil {
			last = err
			continue
		}
		if hmac.Equal([]byte(rec.Sig), []byte(want)) {
			return nil
		}
		last = errors.New("signature mismatch")
	}
	if last == nil {
		return errors.New("signature mismatch")
	}
	return last
}

func recordHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

func lastState(path string) (string, int, tipFile, bool, error) {
	var tip tipFile
	line, err := lastLine(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", 0, tip, false, err
	}
	prev := GenesisPrev
	logSeq := 0
	if err == nil && len(line) > 0 {
		rec, perr := parseRecord(line)
		if perr != nil {
			return "", 0, tip, false, perr
		}
		prev = recordHash(line)
		logSeq = rec.Seq
	}
	tip, tipErr := readTip(HeadPath(path))
	if errors.Is(tipErr, os.ErrNotExist) {
		return prev, logSeq, tip, false, nil
	}
	if tipErr != nil {
		return prev, logSeq, tip, false, tipErr
	}
	return prev, logSeq, tip, true, nil
}

func lastLine(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked receipt path %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("receipt path %s is not a regular file", path)
	}
	if info.Size() == 0 {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- receipt path is operator-selected.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// A well-formed log ends with newline. Refuse a truncated trailing line
	// so the next append cannot chain off incomplete bytes.
	if _, err := f.Seek(-1, io.SeekEnd); err != nil {
		return nil, err
	}
	tail := make([]byte, 1)
	if _, err := io.ReadFull(f, tail); err != nil {
		return nil, err
	}
	if tail[0] != '\n' {
		return nil, fmt.Errorf("receipt log %s does not end with a newline", path)
	}

	readN := info.Size()
	if readN > int64(maxLine)+1 {
		readN = int64(maxLine) + 1
	}
	if _, err := f.Seek(-readN, io.SeekEnd); err != nil {
		return nil, err
	}
	buf := make([]byte, readN)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	buf = bytes.TrimSuffix(buf, []byte("\n"))
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	if len(buf) > maxLine {
		return nil, fmt.Errorf("receipt line exceeds %d bytes", maxLine)
	}
	return buf, nil
}

func appendLine(path string, line []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked receipt path %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("receipt path %s is not a regular file", path)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("receipt perms %v are too open, want 0600", info.Mode().Perm())
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, filePerm) // #nosec G304 -- receipt path is operator-selected.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("receipt perms %v are too open, want 0600", info.Mode().Perm())
		}
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Verify walks path and checks schema, seq, prev_hash links, HMAC, and the
// external tip pointer. A missing log with no tip is an empty chain. A missing
// or truncated log that still has a tip fails.
func Verify(path string, keys ...[]byte) (int, error) {
	if len(keys) == 0 {
		return 0, errors.New("receipt verify requires at least one key")
	}
	headPath := HeadPath(path)
	f, err := os.Open(path) // #nosec G304 -- receipt path is operator-selected.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, tipErr := os.Lstat(headPath); tipErr == nil {
				return 0, errors.New("receipt log missing but tip is present")
			}
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = f.Close() }()
	if runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("receipt path %s is not a regular file", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return 0, fmt.Errorf("receipt perms %v are too open, want 0600", info.Mode().Perm())
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	prev := GenesisPrev
	n := 0
	lastHash := ""
	lastSeq := 0
	prevHash := GenesisPrev
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return n, fmt.Errorf("receipt %d: empty line", n+1)
		}
		rec, err := parseRecord(line)
		if err != nil {
			return n, fmt.Errorf("receipt %d: %w", n+1, err)
		}
		if rec.Seq != n+1 {
			return n, fmt.Errorf("receipt %d: seq %d, want %d", n+1, rec.Seq, n+1)
		}
		if rec.PrevHash != prev {
			return n, fmt.Errorf("receipt %d: prev_hash mismatch", n+1)
		}
		if err := verifySig(keys, rec); err != nil {
			return n, fmt.Errorf("receipt %d: %w", n+1, err)
		}
		prevHash = prev
		lastHash = recordHash(line)
		lastSeq = rec.Seq
		prev = lastHash
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, checkTip(headPath, keys, n, lastSeq, lastHash, prevHash)
}

func parseRecord(line []byte) (Record, error) {
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return Record{}, err
	}
	if rec.V != SchemaVersion {
		return Record{}, fmt.Errorf("unsupported schema version %d", rec.V)
	}
	if rec.Seq < 1 {
		return Record{}, errors.New("seq must be >= 1")
	}
	if rec.TS == "" || rec.Role == "" || rec.Event == "" {
		return Record{}, errors.New("missing required fields")
	}
	if rec.SourceID == "" || rec.SinkID == "" {
		return Record{}, errors.New("missing source or sink identity")
	}
	if err := checkHex("payload_hash", rec.PayloadHash); err != nil {
		return Record{}, err
	}
	if err := checkHex("prev_hash", rec.PrevHash); err != nil {
		return Record{}, err
	}
	if err := checkHex("sig", rec.Sig); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func checkHex(name, s string) error {
	if len(s) != hashHexLen {
		return fmt.Errorf("%s must be %d hex chars", name, hashHexLen)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("%s is not valid hex", name)
	}
	return nil
}

// ReadAll returns every well-formed record in path. It does not verify the
// chain; use Verify for integrity.
func ReadAll(path string) ([]Record, error) {
	f, err := os.Open(path) // #nosec G304 -- receipt path is operator-selected.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	var out []Record
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return out, fmt.Errorf("receipt %d: empty line", len(out)+1)
		}
		rec, err := parseRecord(line)
		if err != nil {
			return out, fmt.Errorf("receipt %d: %w", len(out)+1, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// ContainsSensitive reports whether raw receipt bytes include any of the
// provided secret material. Used by tests to pin the no-values invariant.
func ContainsSensitive(raw []byte, values ...string) bool {
	for _, v := range values {
		if v == "" {
			continue
		}
		if bytes.Contains(raw, []byte(v)) {
			return true
		}
	}
	return false
}

// FormatLine renders one record for human show output (metadata only).
func FormatLine(rec Record) string {
	return fmt.Sprintf("%s  %s  %s  source=%s sink=%s  payload=%s  prev=%s",
		rec.TS, rec.Role, rec.Event, rec.SourceID, rec.SinkID,
		shortHash(rec.PayloadHash), shortHash(rec.PrevHash))
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16] + "…"
}

func writeTip(path string, macKey []byte, seq int, hash string) error {
	sig, err := signTip(macKey, seq, hash)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(tipFile{Seq: seq, Hash: hash, Sig: sig})
	if err != nil {
		return err
	}
	return privfile.Write(path, append(raw, '\n'))
}

func signTip(macKey []byte, seq int, hash string) (string, error) {
	raw, err := json.Marshal(tipBody{Seq: seq, Hash: hash})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func readTip(path string) (tipFile, error) {
	var tip tipFile
	info, err := os.Lstat(path)
	if err != nil {
		return tip, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return tip, fmt.Errorf("refusing symlinked receipt tip %s", path)
	}
	if !info.Mode().IsRegular() {
		return tip, fmt.Errorf("receipt tip %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return tip, fmt.Errorf("receipt tip perms %v are too open, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- tip path is derived from the operator-selected receipt path.
	if err != nil {
		return tip, err
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tip); err != nil {
		return tip, fmt.Errorf("receipt tip: %w", err)
	}
	if err := checkHex("tip.hash", tip.Hash); err != nil {
		return tip, err
	}
	if err := checkHex("tip.sig", tip.Sig); err != nil {
		return tip, err
	}
	if tip.Seq < 0 {
		return tip, errors.New("receipt tip seq must be >= 0")
	}
	return tip, nil
}

func verifyTipSig(keys [][]byte, tip tipFile) error {
	var last error
	for _, key := range keys {
		macKey, err := DeriveMACKey(key)
		if err != nil {
			last = err
			continue
		}
		want, err := signTip(macKey, tip.Seq, tip.Hash)
		if err != nil {
			last = err
			continue
		}
		if hmac.Equal([]byte(tip.Sig), []byte(want)) {
			return nil
		}
		last = errors.New("receipt tip signature mismatch")
	}
	if last == nil {
		return errors.New("receipt tip signature mismatch")
	}
	return last
}

func checkTip(headPath string, keys [][]byte, n, lastSeq int, lastHash, prevHash string) error {
	tip, err := readTip(headPath)
	if n == 0 {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := verifyTipSig(keys, tip); err != nil {
			return err
		}
		if tip.Seq == 0 && tip.Hash == GenesisPrev {
			return nil
		}
		return errors.New("receipt tip present but log is empty")
	}
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("receipt tip missing")
	}
	if err != nil {
		return err
	}
	if err := verifyTipSig(keys, tip); err != nil {
		return err
	}
	if tip.Seq == lastSeq && tip.Hash == lastHash {
		return nil
	}
	// One-record crash window: appendLine fsynced, writeTip did not.
	// An attacker without the MAC key cannot manufacture this state.
	if tip.Seq == lastSeq-1 && tip.Hash == prevHash {
		return nil
	}
	return errors.New("receipt tip mismatch")
}

// CheckPath is the doctor helper: when receipts are enabled, the target
// directory must be writable or creatable and an existing file must be a
// regular 0600 path (not a symlink).
func CheckPath(path string, writable func(dir string) bool) error {
	if path == "" {
		return errors.New("receipts.enabled is set but path is empty")
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked receipt path %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("receipt path %s is not a regular file", path)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("receipt perms %v are too open, want 0600", info.Mode().Perm())
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if writable != nil && !writable(filepath.Dir(path)) {
		return fmt.Errorf("receipt dir not writable: %s", filepath.Dir(path))
	}
	return nil
}
