package pair

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxFrame bounds an unauthenticated pairing frame. SPAKE2 shares and
// confirmations are tens of bytes; 1 KiB leaves room without letting a
// pre-auth peer force an 8 MiB transport-sized allocation.
const maxFrame = 1024

const (
	protocolVersion byte = 1
	msgShare        byte = 1
	msgConfirm      byte = 2
)

func writeMsg(w io.Writer, typ byte, payload []byte) error {
	if typ != msgShare && typ != msgConfirm {
		return fmt.Errorf("unknown pairing message type")
	}
	if len(payload)+2 > maxFrame {
		return fmt.Errorf("pairing frame too large")
	}
	body := make([]byte, 0, 2+len(payload))
	body = append(body, protocolVersion, typ)
	body = append(body, payload...)
	return writeFrame(w, body)
}

func readMsg(r io.Reader) (byte, []byte, error) {
	body, err := readFrame(r)
	if err != nil {
		return 0, nil, err
	}
	if len(body) < 2 {
		return 0, nil, fmt.Errorf("pairing frame too short")
	}
	if body[0] != protocolVersion {
		return 0, nil, fmt.Errorf("unsupported pairing version")
	}
	typ := body[1]
	if typ != msgShare && typ != msgConfirm {
		return 0, nil, fmt.Errorf("unknown pairing message type")
	}
	return typ, body[2:], nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("pairing frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload))) // #nosec G115 -- len is bounded by maxFrame.
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("pairing frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
