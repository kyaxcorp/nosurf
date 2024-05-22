package nosurf

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
)

const (
	keyLength = 32 // Length of the derived key from the password
)

var MaskPassword = []byte("yoursuperpasswordhere!")

// DeriveKeyFromPassword derives a key from the provided password.
func deriveKeyFromPassword(password []byte) []byte {
	hashed := sha256.Sum256(password)
	return hashed[:]
}

// oneTimePad encrypts/decrypts the data using the given key.
func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

// Masks/unmasks the given data *in place*
// with the given key
// Slices must be of the same length, or oneTimePad will panic
func maskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	key := deriveKeyFromPassword(MaskPassword)
	result := make([]byte, 2*tokenLength)
	copy(result[tokenLength:], data)

	if _, err := io.ReadFull(rand.Reader, result[:tokenLength]); err != nil {
		panic(err)
	}

	oneTimePad(result[tokenLength:], key)
	return result
}

// unmaskToken unmasks a token using a password.
func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	key := deriveKeyFromPassword(MaskPassword)
	token := data[tokenLength:]
	oneTimePad(token, key)

	return token
}
