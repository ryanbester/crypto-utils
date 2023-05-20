package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// DeriveAESKey derives a key from a passphrase with argon2 for use in with AES algorithms.
func DeriveAESKey(passphrase []byte) []byte {
	return Argon2IDKey(passphrase, []byte(""))
}

// EncryptAesGcm encrypts plaintext with key, adds data for authentication, and returns the ciphertext and nonce.
func EncryptAesGcm(key, plaintext, data []byte) (ciphertext, nonce []byte, error error) {
	if len(key) != 32 {
		return nil, nil, errors.New("invalid key length")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	enc := gcm.Seal(nil, nonce, plaintext, data)
	return enc, nonce, nil
}

// DecryptAesGcm decrypts ciphertext with key and nonce, authenticates data, and returns the plaintext.
func DecryptAesGcm(key, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, data)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
