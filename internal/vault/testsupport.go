package vault

// EncryptForTest mirrors Chromium's Linux scheme so other packages' tests can
// build fixtures. It delegates the crypto to EncryptValue and only swaps the
// 3-byte prefix; v10 fixtures derive their key from the fixed "peanuts" pass.
func EncryptForTest(prefix, passphrase, value string) []byte {
	pass := passphrase
	if prefix == "v10" {
		pass = "peanuts"
	}
	enc, err := EncryptValue(value, pass)
	if err != nil {
		panic(err)
	}
	out := append([]byte(prefix), enc[3:]...)
	return out
}
