package pbkdf2_sha256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
	"strings"
)

func Encode(password string, salt string, iterations int) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, sha256.Size, sha256.New)
	b64Hash := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("%s$%d$%s$%s", "pbkdf2_sha256", iterations, salt, b64Hash)
}

func VerifyPassword(password, encoded string) (bool, error) {
	s := strings.Split(encoded, "$")
	if len(s) != 4 {
		return false, errors.New("pbkdf2: unreadable component in hashed password")
	}
	if s[0] != "pbkdf2_sha256" {
		return false, errors.New("pbkdf2: algorithm mismatch")
	}
	i, err := strconv.Atoi(s[1])
	if err != nil {
		return false, errors.New("pbkdf2: unreadable component in hashed password")
	}
	return hmac.Equal([]byte(Encode(password, s[2], i)), []byte(encoded)), nil
}
