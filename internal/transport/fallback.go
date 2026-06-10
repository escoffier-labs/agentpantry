package transport

// FallbackOpener opens frames with a primary key, falling back to a previous
// key during a rotation grace window. The first frame that authenticates pins
// its key for the rest of the session, so per-session replay protection is
// exactly the single-Opener behavior and a session can never switch keys
// mid-stream.
type FallbackOpener struct {
	primary  *Opener
	fallback *Opener
	pinned   *Opener

	// OnFallback is called once, when a session's first authenticated frame
	// used the fallback (pre-rotation) key.
	OnFallback func()
}

// NewFallbackOpener derives per-session openers for both keys from the same
// session salt.
func NewFallbackOpener(primaryKey, fallbackKey, salt []byte) (*FallbackOpener, error) {
	p, err := NewOpener(primaryKey, salt)
	if err != nil {
		return nil, err
	}
	f, err := NewOpener(fallbackKey, salt)
	if err != nil {
		return nil, err
	}
	return &FallbackOpener{primary: p, fallback: f}, nil
}

// Open decrypts frame under the pinned key, or probes primary then fallback
// on the session's first frames. A failed AEAD open does not advance the
// probed opener's replay counter, so probing leaves its state untouched.
func (o *FallbackOpener) Open(frame []byte) ([]byte, error) {
	if o.pinned != nil {
		return o.pinned.Open(frame)
	}
	pt, primaryErr := o.primary.Open(frame)
	if primaryErr == nil {
		o.pinned = o.primary
		return pt, nil
	}
	pt, err := o.fallback.Open(frame)
	if err == nil {
		o.pinned = o.fallback
		if o.OnFallback != nil {
			o.OnFallback()
		}
		return pt, nil
	}
	return nil, primaryErr
}
