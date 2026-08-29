package pair

import (
	"bytes"
	"encoding/hex"
	"testing"

	gospake2 "github.com/ValiantChip/gospake2" // v0.1.5 pinned in go.mod
)

// TestGospake2V015TranscriptPin pins github.com/ValiantChip/gospake2 v0.1.5's
// Ed25519 SPAKE2 transcript so an upstream Finish/Verify or transcript change
// fails the test.
//
// This is a library pin, not an RFC 9382 appendix vector. Appendix B publishes
// P-256 values that cannot be fed to DEFAULT_SUITE.
func TestGospake2V015TranscriptPin(t *testing.T) {
	rng := bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))
	const (
		pw  = "rfc9382-kat"
		idA = "agentpantry/v1 pair-source"
		idB = "agentpantry/v1 pair-sink"
	)
	A, err := gospake2.NewA([]byte(pw), idA, idB, rng, gospake2.DEFAULT_SUITE)
	if err != nil {
		t.Fatal(err)
	}
	B, err := gospake2.NewB([]byte(pw), idA, idB, rng, gospake2.DEFAULT_SUITE)
	if err != nil {
		t.Fatal(err)
	}
	pA, err := A.Start()
	if err != nil {
		t.Fatal(err)
	}
	pB, err := B.Start()
	if err != nil {
		t.Fatal(err)
	}
	keA, cA, err := A.Finish(pB)
	if err != nil {
		t.Fatal(err)
	}
	keB, cB, err := B.Finish(pA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keA, keB) {
		t.Fatal("Ke must match on both sides")
	}
	if err := B.Verify(cA); err != nil {
		t.Fatalf("B must verify initiator cA first: %v", err)
	}
	if err := A.Verify(cB); err != nil {
		t.Fatalf("A must verify responder cB: %v", err)
	}

	// Recorded against github.com/ValiantChip/gospake2 v0.1.5.
	const (
		wantPA = "7635114990b7cbf9ba1ae5e6f66f46339f08f4fa2bc1d765a5ade137df39055c"
		wantPB = "d7b60e16c4f19627a19074dc374ec16fbd2159921e668156c65e7c3161c8a853"
		wantKe = "a351f7d9b3eef1463d396d930d01489e"
		wantCA = "ea9cad4e8f8844b46081b3e24a2eeb6d7719d9c52af09d90f4781f16d6f949f4"
		wantCB = "699a6bec64ae4c64d8db72eaa57bef5aa655d74b605c8b1ec9ce3f879953c410"
	)
	got := map[string]string{
		"pA": hex.EncodeToString(pA),
		"pB": hex.EncodeToString(pB),
		"Ke": hex.EncodeToString(keA),
		"cA": hex.EncodeToString(cA),
		"cB": hex.EncodeToString(cB),
	}
	want := map[string]string{"pA": wantPA, "pB": wantPB, "Ke": wantKe, "cA": wantCA, "cB": wantCB}
	for name, exp := range want {
		if got[name] != exp {
			t.Errorf("%s=%s want %s (gospake2 v0.1.5 transcript changed)", name, got[name], exp)
		}
	}
}
