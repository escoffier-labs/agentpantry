package pair

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func TestNormalizeCodeRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 9 || code[4] != '-' {
		t.Fatalf("canonical form XXXX-XXXX, got %q", code)
	}
	got, err := NormalizeCode(strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if err != nil {
		t.Fatal(err)
	}
	if got != code {
		t.Fatalf("normalize(%q) = %q, want %q", code, got, code)
	}
}

func TestNormalizeCodeMapsHomoglyphs(t *testing.T) {
	got, err := NormalizeCode("OI1L-abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0111-ABCD" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeCodeRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "ABC", "ABCD-EFGH-I", "XXXX-XXXU", "!!!!-!!!!"} {
		if _, err := NormalizeCode(s); err == nil {
			t.Fatalf("NormalizeCode(%q) must fail", s)
		}
	}
}

func TestExchangeRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	src, snk := net.Pipe()
	defer src.Close()
	defer snk.Close()
	_ = src.SetDeadline(time.Now().Add(5 * time.Second))
	_ = snk.SetDeadline(time.Now().Add(5 * time.Second))

	errc := make(chan error, 2)
	var srcKey, snkKey []byte
	go func() {
		defer src.Close()
		k, err := ExchangeSource(src, code)
		srcKey = k
		errc <- err
	}()
	go func() {
		defer snk.Close()
		k, err := ExchangeSink(snk, code)
		snkKey = k
		errc <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(srcKey, snkKey) {
		t.Fatal("derived PSKs must match")
	}
	if len(srcKey) != 32 {
		t.Fatalf("PSK must be 32 bytes, got %d", len(srcKey))
	}
	if Fingerprint(srcKey) != Fingerprint(snkKey) {
		t.Fatal("fingerprints must match")
	}
}

func TestExchangeWrongCodeFails(t *testing.T) {
	src, snk := net.Pipe()
	defer src.Close()
	defer snk.Close()
	_ = src.SetDeadline(time.Now().Add(5 * time.Second))
	_ = snk.SetDeadline(time.Now().Add(5 * time.Second))

	type outcome struct {
		key []byte
		err error
	}
	errc := make(chan outcome, 2)
	go func() {
		defer src.Close()
		k, err := ExchangeSource(src, "AAAA-AAAA")
		errc <- outcome{k, err}
	}()
	go func() {
		defer snk.Close()
		k, err := ExchangeSink(snk, "BBBB-BBBB")
		errc <- outcome{k, err}
	}()
	for i := 0; i < 2; i++ {
		o := <-errc
		if o.err == nil {
			t.Fatal("mismatched codes must fail confirmation")
		}
		if o.key != nil {
			t.Fatal("neither side may return a key on a code mismatch")
		}
	}
}

func TestDialServeRoundTrip(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrCh := make(chan string, 1)
	errc := make(chan error, 1)
	var sinkKey []byte
	go func() {
		k, err := Serve(ctx, ServeConfig{
			Addr: "127.0.0.1:0",
			Code: code,
			OnListening: func(addr string) {
				addrCh <- addr
			},
		})
		sinkKey = k
		errc <- err
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errc:
		t.Fatalf("serve exited before listen: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for listen")
	}

	srcKey, err := Dial(ctx, addr, code)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srcKey, sinkKey) {
		t.Fatal("dial/serve PSKs must match")
	}
}

func TestServeLocksAfterFailedAttempts(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrCh := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		_, err := Serve(ctx, ServeConfig{
			Addr:     "127.0.0.1:0",
			Code:     code,
			Attempts: 2,
			OnListening: func(addr string) {
				addrCh <- addr
			},
		})
		errc <- err
	}()
	addr := <-addrCh
	for i := 0; i < 2; i++ {
		if _, err := Dial(ctx, addr, "FFFF-FFFF"); err == nil {
			t.Fatal("wrong code must fail")
		}
	}
	err = <-errc
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("want lockout, got %v", err)
	}
}

func TestServeBurstWrongCodeRespectsCap(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const attempts, flight, burst = 2, 2, 12
	addrCh := make(chan string, 1)
	errc := make(chan error, 1)
	var started atomic.Int64
	go func() {
		_, err := Serve(ctx, ServeConfig{
			Addr:     "127.0.0.1:0",
			Code:     code,
			Attempts: attempts,
			InFlight: flight,
			OnListening: func(addr string) {
				addrCh <- addr
			},
			OnExchange: func() { started.Add(1) },
		})
		errc <- err
	}()
	addr := <-addrCh

	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = Dial(ctx, addr, "FFFF-FFFF")
		}()
	}
	err = <-errc
	wg.Wait()
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("want lockout, got %v", err)
	}
	if n := started.Load(); n > int64(attempts) {
		t.Fatalf("SPAKE2 exchanges %d exceed attempt cap %d", n, attempts)
	}
	if n := started.Load(); n > int64(flight) {
		t.Fatalf("SPAKE2 exchanges %d exceed in-flight cap %d", n, flight)
	}
	if n := started.Load(); n == 0 {
		t.Fatal("expected at least one code exchange")
	}
}

func TestServeIgnoresIdleAndStrayConnects(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrCh := make(chan string, 1)
	errc := make(chan error, 1)
	var sinkKey []byte
	go func() {
		k, err := Serve(ctx, ServeConfig{
			Addr:     "127.0.0.1:0",
			Code:     code,
			Attempts: 1,
			OnListening: func(addr string) {
				addrCh <- addr
			},
		})
		sinkKey = k
		errc <- err
	}()
	addr := <-addrCh

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = idle.SetDeadline(time.Now().Add(FirstReadTimeout + time.Second))
	if _, rerr := idle.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("idle connect must be dropped before the SPAKE2 phase")
	}
	_ = idle.Close()

	// Length 2, version 9: a stray frame, not a SPAKE2 share. Must not
	// increment the code-attempt counter (Attempts is 1).
	junk, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = junk.Write([]byte{0, 0, 0, 2, 9, 9})
	_ = junk.Close()

	srcKey, err := Dial(ctx, addr, code)
	if err != nil {
		t.Fatalf("idle/stray connects must not consume the code-attempt budget: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srcKey, sinkKey) {
		t.Fatal("successful pair after stray connects must still match")
	}
}

func TestDerivePSKInfoSeparation(t *testing.T) {
	shared := bytes.Repeat([]byte{0x11}, 32)
	got, err := derivePSK(shared)
	if err != nil {
		t.Fatal(err)
	}
	pairKey := hkdfOnce(t, shared, pskInfo)
	sessionKey := hkdfOnce(t, shared, "agentpantry/v1 session")
	if !bytes.Equal(got, pairKey) {
		t.Fatal("derivePSK must use agentpantry/v1 pair-psk")
	}
	if bytes.Equal(got, sessionKey) {
		t.Fatal("pair-psk HKDF must not match the session info string")
	}
}

func hkdfOnce(t *testing.T, secret []byte, info string) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReadMsgRejectsOversizeAndBadVersion(t *testing.T) {
	var buf bytes.Buffer
	_ = writeFrame(&buf, bytes.Repeat([]byte{1}, maxFrame+1))
	if _, err := readFrame(&buf); err == nil {
		t.Fatal("oversize frame must be rejected")
	}
	buf.Reset()
	_ = writeFrame(&buf, []byte{2, msgShare})
	if _, _, err := readMsg(&buf); err == nil {
		t.Fatal("unknown version must be rejected")
	}
	buf.Reset()
	_ = writeFrame(&buf, []byte{protocolVersion, 9})
	if _, _, err := readMsg(&buf); err == nil {
		t.Fatal("unknown type must be rejected")
	}
}

func TestFingerprintStableAndShort(t *testing.T) {
	psk, _ := hex.DecodeString(strings.Repeat("ab", 32))
	fp := Fingerprint(psk)
	if fp != Fingerprint(psk) {
		t.Fatal("fingerprint must be deterministic")
	}
	if len(fp) != 19 {
		t.Fatalf("want abcd-ef01-style, got %q", fp)
	}
}

func TestExchangeDoesNotWriteOnShortRead(t *testing.T) {
	src, snk := net.Pipe()
	defer src.Close()
	errc := make(chan error, 1)
	go func() { _, err := ExchangeSink(snk, "AAAA-AAAA"); errc <- err }()
	_ = src.Close()
	if err := <-errc; err == nil {
		t.Fatal("closed pipe must fail")
	}
}

func TestWriteMsgRejectsHugePayload(t *testing.T) {
	if err := writeMsg(io.Discard, msgShare, bytes.Repeat([]byte{1}, maxFrame)); err == nil {
		t.Fatal("huge pairing payload must be rejected")
	}
}
