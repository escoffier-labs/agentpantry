// Package pair bootstraps a long-lived PSK with a one-time SPAKE2 short code.
//
// Pairing is additive setup only. After both ends write psk.key, every sync
// connection still performs the session-salt handshake in
// internal/transport/handshake.go (sink issues the salt over TCP; source issues
// it over --stdio) and still derives per-session keys via
// HKDF-SHA256(PSK, salt, info "agentpantry/v1 session"). Pairing never replaces
// that handshake and never pins a static session key.
package pair

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	gospake2 "github.com/ValiantChip/gospake2" // v0.1.5 pinned in go.mod
	"golang.org/x/crypto/hkdf"
)

const (
	// DefaultTimeout is the sink pairing window.
	DefaultTimeout = 2 * time.Minute
	// MaxAttempts is the number of failed SPAKE2 *code* tries before lockout.
	MaxAttempts = 3
	// MaxInFlight is a secondary DoS limit on concurrent pairing exchanges.
	// The attempt cap is the hard bound: Serve will not start an exchange
	// when failures+inFlight is already at MaxAttempts.
	MaxInFlight = 4
	// ConnTimeout bounds one pairing TCP exchange after the first byte.
	ConnTimeout = 30 * time.Second
	// FirstReadTimeout bounds the wait for the initiator's first frame so an
	// idle connect cannot occupy the pairing window.
	FirstReadTimeout = 2 * time.Second

	idA     = "agentpantry/v1 pair-source"
	idB     = "agentpantry/v1 pair-sink"
	pskInfo = "agentpantry/v1 pair-psk"
)

var errPairFailed = fmt.Errorf("pairing confirmation failed")

// Fingerprint is a short SHA-256(PSK) prefix for operator compare.
// It is not a secret and is not enough to recover the key.
func Fingerprint(psk []byte) string {
	sum := sha256.Sum256(psk)
	h := hex.EncodeToString(sum[:8])
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16]
}

func derivePSK(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte(pskInfo))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExchangeSource is SPAKE2 party A (the source). rw is a single pairing stream.
func ExchangeSource(rw io.ReadWriter, code string) ([]byte, error) {
	code, err := NormalizeCode(code)
	if err != nil {
		return nil, err
	}
	a, err := gospake2.NewA([]byte(code), idA, idB, rand.Reader, gospake2.DEFAULT_SUITE)
	if err != nil {
		return nil, err
	}
	share, err := a.Start()
	if err != nil {
		return nil, err
	}
	if err := writeMsg(rw, msgShare, share); err != nil {
		return nil, err
	}
	typ, peerShare, err := readMsg(rw)
	if err != nil {
		return nil, err
	}
	if typ != msgShare {
		return nil, errPairFailed
	}
	key, confirm, err := a.Finish(peerShare)
	if err != nil {
		return nil, errPairFailed
	}
	// RFC 9382: A sends cA first. B verifies cA before sending cB.
	if err := writeMsg(rw, msgConfirm, confirm); err != nil {
		return nil, err
	}
	typ, peerConfirm, err := readMsg(rw)
	if err != nil {
		return nil, err
	}
	if typ != msgConfirm {
		return nil, errPairFailed
	}
	if err := a.Verify(peerConfirm); err != nil {
		return nil, errPairFailed
	}
	return derivePSK(key)
}

// ExchangeSink is SPAKE2 party B (the sink). rw is a single pairing stream.
func ExchangeSink(rw io.ReadWriter, code string) ([]byte, error) {
	code, err := NormalizeCode(code)
	if err != nil {
		return nil, err
	}
	b, err := gospake2.NewB([]byte(code), idA, idB, rand.Reader, gospake2.DEFAULT_SUITE)
	if err != nil {
		return nil, err
	}
	share, err := b.Start()
	if err != nil {
		return nil, err
	}
	typ, peerShare, err := readMsg(rw)
	if err != nil {
		return nil, err
	}
	if typ != msgShare {
		return nil, errPairFailed
	}
	if err := writeMsg(rw, msgShare, share); err != nil {
		return nil, err
	}
	key, confirm, err := b.Finish(peerShare)
	if err != nil {
		return nil, errPairFailed
	}
	typ, peerConfirm, err := readMsg(rw)
	if err != nil {
		return nil, err
	}
	if typ != msgConfirm {
		return nil, errPairFailed
	}
	if err := b.Verify(peerConfirm); err != nil {
		return nil, errPairFailed
	}
	if err := writeMsg(rw, msgConfirm, confirm); err != nil {
		return nil, err
	}
	return derivePSK(key)
}
