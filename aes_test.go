package cryptoutils

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveAESKey(t *testing.T) {
	want := []byte{0x46, 0xc7, 0x44, 0x94, 0x1b, 0xf5, 0x6e, 0x42,
		0x40, 0x1b, 0xdd, 0xed, 0x61, 0x11, 0x9c, 0x2b,
		0x1c, 0x29, 0xd6, 0x56, 0x56, 0x54, 0xf6, 0xf0,
		0x94, 0xcd, 0x84, 0xc8, 0xec, 0x8d, 0xfa, 0x3f}

	hash := DeriveAESKey([]byte("Password1"))
	if !bytes.Equal(hash, want) {
		t.Errorf("hash does not match: got: %s, want: %s", hex.EncodeToString(hash), hex.EncodeToString(want))
	}
}

func TestEncryptAesGcm(t *testing.T) {
	plaintext := "Test message"
	data := "Additional Data"
	passphrase := "Password1"

	key := DeriveAESKey([]byte(passphrase))

	enc, nonce, err := EncryptAesGcm(key, []byte(plaintext), []byte(data))
	if err != nil {
		t.Errorf("encrypt error: %s", err)
		return
	}

	_, err = DecryptAesGcm(key, nonce, enc, []byte(data))
	if err != nil {
		t.Errorf("decrypt error: %s", err)
		return
	}
}
