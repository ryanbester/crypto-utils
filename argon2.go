package cryptoutils

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"math"
	"strings"
)

// Argon2Params contains configuration parameters for argon2 functions.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
}

// Argon2DefaultParams contains the default recommended argon2 parameters.
var Argon2DefaultParams = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 4,
	KeyLength:   32,
}

// Argon2AppParams contains the parameters defined in user config, or the default parameters if not set.
var Argon2AppParams = Argon2DefaultParams

// InitialiseArgon2Params sets Argon2AppParams to user defined values, or the default if not set.
func InitialiseArgon2Params(config *Argon2Params) {
	Argon2AppParams = Argon2Params{
		Memory:      uint32(math.Max(float64(config.Memory), float64(Argon2DefaultParams.Memory))),
		Iterations:  uint32(math.Max(float64(config.Iterations), float64(Argon2DefaultParams.Iterations))),
		Parallelism: uint8(math.Max(float64(config.Parallelism), float64(Argon2DefaultParams.Parallelism))),
		KeyLength:   uint32(math.Max(float64(config.KeyLength), float64(Argon2DefaultParams.KeyLength))),
	}
}

// Argon2IDKey generates a hash for password with salt, using Argon2AppParams.
func Argon2IDKey(password, salt []byte) []byte {
	return Argon2IDKeyParams(password, salt, &Argon2AppParams)
}

// Argon2IDKeyParams generates a hash for password with salt, using p.
func Argon2IDKeyParams(password, salt []byte, p *Argon2Params) []byte {
	return argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, 32)
}

// Argon2Verify verifies password is the same used in encodedHash.
func Argon2Verify(password []byte, encodedHash string) (bool, error) {
	p, hash, salt, err := Argon2DecodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	newHash := Argon2IDKeyParams(password, salt, p)

	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	}
	return false, nil
}

// Argon2EncodeHash serializes the hash, salt, and params to a string for storage.
func Argon2EncodeHash(salt, hash []byte, p *Argon2Params) string {
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)
}

// Argon2DecodeHash deserializes the string generated from Argon2EncodeHash.
func Argon2DecodeHash(encodedHash string) (p *Argon2Params, passwdHash, salt []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash")
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible argon2 version")
	}

	p = &Argon2Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}

	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, hash, salt, nil
}
