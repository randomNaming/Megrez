package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// 一次性配对码：12 个 base64url 字符（约 72 位熵），人为分成三组便于转写。
func NewPairCode() (pretty, canonical string, err error) {
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	code := base64.RawURLEncoding.EncodeToString(buf)[:12]
	return code[0:4] + "-" + code[4:8] + "-" + code[8:12], code, nil
}

func NormalizePairCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func PairCodeHash(pretty string) string {
	sum := sha256.Sum256([]byte(NormalizePairCode(pretty)))
	return hex.EncodeToString(sum[:])
}
