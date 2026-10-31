package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数：32MB 内存 / 3 轮 / 2 线程。
// 单人生态、登录频率极低，配合强密码 + 动态码 + 锁定已足够；
// 不用 64MB 是为了压住登录瞬间的内存峰值（服务器余量只有 900MB）。
const (
	argonMemory  = 32 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
)

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	m, t, p, err := parseArgonParams(parts[2])
	if err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseArgonParams(s string) (m, t uint32, p uint8, err error) {
	for _, kv := range strings.Split(s, ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("参数不合法")
		}
		switch key {
		case "m":
			v, e := strconv.ParseUint(val, 10, 32)
			if e != nil {
				return 0, 0, 0, e
			}
			m = uint32(v)
		case "t":
			v, e := strconv.ParseUint(val, 10, 32)
			if e != nil {
				return 0, 0, 0, e
			}
			t = uint32(v)
		case "p":
			v, e := strconv.ParseUint(val, 10, 8)
			if e != nil {
				return 0, 0, 0, e
			}
			p = uint8(v)
		}
	}
	if m == 0 || t == 0 || p == 0 {
		return 0, 0, 0, fmt.Errorf("参数不合法")
	}
	return m, t, p, nil
}
