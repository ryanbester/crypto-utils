package cryptoutils

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestArgon2IDKey(t *testing.T) {
	want := []byte{0x5f, 0x70, 0xf2, 0xea, 0x3b, 0xe4, 0xb7, 0x21,
		0x38, 0x21, 0xfc, 0xa4, 0x2, 0x45, 0x5d, 0x1a,
		0xbb, 0x13, 0x27, 0xb7, 0x54, 0x50, 0x81, 0x11,
		0x7a, 0xab, 0x1c, 0x84, 0xb2, 0x48, 0xee, 0x38}
	password := []byte("Password 1")
	salt := []byte("salt")

	hash := Argon2IDKey(password, salt)
	if !bytes.Equal(hash, want) {
		t.Errorf("hash does not match: got: %s, want: %s", hex.EncodeToString(hash), hex.EncodeToString(want))
	}
}

func TestArgon2Verify(t *testing.T) {
	password := []byte("Password 1")
	salt := []byte("salt")
	hash := Argon2IDKey(password, salt)

	encoded := Argon2EncodeHash(salt, hash, &Argon2AppParams)

	valid, err := Argon2Verify(password, encoded)
	if err != nil {
		t.Errorf("verify error: %s", err)
	} else if !valid {
		t.Errorf("verify result false")
	}
}

func TestArgon2EncodeHash(t *testing.T) {
	want := "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$X3Dy6jvktyE4IfykAkVdGrsTJ7dUUIEReqschLJI7jg"

	password := []byte("Password 1")
	salt := []byte("salt")
	hash := Argon2IDKey(password, salt)

	encoded := Argon2EncodeHash(salt, hash, &Argon2AppParams)
	if encoded != want {
		t.Errorf("encoded does not match: got %s, want: %s", encoded, want)
	}
}

func TestArgon2DecodeHash(t *testing.T) {
	encodedHash := "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$X3Dy6jvktyE4IfykAkVdGrsTJ7dUUIEReqschLJI7jg"

	params, _, _, err := Argon2DecodeHash(encodedHash)
	if err != nil {
		t.Errorf("decode hash error: %s", err)
		return
	}

	if params.Memory != Argon2AppParams.Memory ||
		params.Iterations != Argon2AppParams.Iterations ||
		params.Parallelism != Argon2AppParams.Parallelism ||
		params.KeyLength != Argon2AppParams.KeyLength {
		t.Errorf("invalid values decoding hash: got: %x, want: %x", params, Argon2AppParams)
	}
}
