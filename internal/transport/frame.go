package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrame caps a single frame to guard against malicious length prefixes.
const maxFrame = 64 << 20 // 64 MiB

// WriteFrame writes a uint32 big-endian length prefix then the payload.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("frame size %d exceeds max %d", len(payload), maxFrame)
	}
	n := uint32(len(payload)) // #nosec G115 -- len is bounded by maxFrame well below uint32 max.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], n)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("frame size %d exceeds max %d", n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
