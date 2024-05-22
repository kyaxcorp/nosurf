package nosurf

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"
)

const (
	tokenLength = 32
)

/*
There are two types of tokens.

* The unmasked "real" token consists of 32 random bytes.
  It is stored in a cookie (base64-encoded) and it's the
  "reference" value that sent tokens get compared to.

* The masked "sent" token consists of 64 bytes:
  32 byte key used for one-time pad masking and
  32 byte "real" token masked with the said key.
  It is used as a value (base64-encoded as well)
  in forms and/or headers.

Upon processing, both tokens are base64-decoded
and then treated as 32/64 byte slices.
*/

// A token is generated by returning tokenLength bytes
// from crypto/rand
func generateToken() []byte {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}

	return bytes
}

func EncodeData(data []byte) string {
	//return base64.StdEncoding.EncodeToString(data)
	// Removed because symbols like "+" make problems?!
	return encodeToBase62(data)
}

func encodeToBase62(data []byte) string {
	var bigInt big.Int
	bigInt.SetBytes(data)
	return bigInt.Text(62)
}

func decodeFromBase62(encoded string) ([]byte, error) {
	var bigInt big.Int
	_, ok := bigInt.SetString(encoded, 62)
	if !ok {
		return nil, fmt.Errorf("invalid base62 string: %s", encoded)
	}
	return bigInt.Bytes(), nil
}

func DecodeData(data string) []byte {
	decoded, err := decodeFromBase62(data)
	//decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return decoded
}

// VerifyToken verifies the sent token equals the real one
// and returns a bool value indicating if tokens are equal.
// Supports masked tokens. realToken comes from Token(r) and
// sentToken is token sent unusual way.
func VerifyToken(realToken, sentToken string) bool {
	//r, err := base64.StdEncoding.DecodeString(realToken)
	r, err := decodeFromBase62(realToken)
	if err != nil {
		return false
	}
	//if len(r) == 2*tokenLength {
	r = unmaskToken(r)
	//}
	//s, err := base64.StdEncoding.DecodeString(sentToken)
	s, err := decodeFromBase62(sentToken)
	if err != nil {
		return false
	}
	//if len(s) == 2*tokenLength {
	s = unmaskToken(s)
	//}
	return tokensEqual(r, s)

}

// VerifyTokenDebug verifies the sent token equals the real one
// and returns a bool value indicating if tokens are equal.
// Supports masked tokens. realToken comes from Token(r) and
// sentToken is token sent unusual way.
func VerifyTokenDebug(realToken, sentToken string) bool {
	//log.Println("realToken", realToken)
	//log.Println("sentToken", sentToken)
	//r, err := base64.StdEncoding.DecodeString(realToken)
	r, err := decodeFromBase62(realToken)
	if err != nil {
		return false
	}
	//log.Println("decoded realToken", realToken, len(r), r, err)

	//if len(r) == 2*tokenLength {
	r = unmaskToken(r)
	//log.Println("unmasked realToken", len(r), r)
	//}
	//s, err := base64.StdEncoding.DecodeString(sentToken)
	s, err := decodeFromBase62(sentToken)
	if err != nil {
		return false
	}
	//log.Println("decoded sentToken", sentToken, len(s), s, err)

	//if len(s) == 2*tokenLength {
	s = unmaskToken(s)
	//log.Println("unmasked sentToken", len(s), s)
	//}
	return tokensEqual(r, s)

}

// verifyToken expects the realToken to be unmasked and the sentToken to be masked
func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)

	// sentN == tokenLength means the token is unmasked
	// sentN == 2*tokenLength means the token is masked.

	if realN == tokenLength && sentN == 2*tokenLength {
		return tokensEqual(realToken, unmaskToken(sentToken))
	}
	return false
}

// tokensEqual expects both tokens to be unmasked
func tokensEqual(realToken, sentToken []byte) bool {
	return len(realToken) == tokenLength &&
		len(sentToken) == tokenLength &&
		subtle.ConstantTimeCompare(realToken, sentToken) == 1
}

func checkForPRNG() {
	// Check that cryptographically secure PRNG is available
	// In case it's not, panic.
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)

	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

func init() {
	checkForPRNG()
}
