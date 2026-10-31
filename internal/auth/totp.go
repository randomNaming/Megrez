package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// RFC 6238 TOTP：SHA1 / 6 位 / 30 秒，兼容所有主流验证器 App。
const totpPeriod = 30

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32NoPad.EncodeToString(buf), nil
}

func totpCode(secret string, counter uint64) (string, error) {
	key, err := b32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// TOTPCode 给出某一时刻的动态码，供本地初始化校验与测试使用。
func TOTPCode(secret string, at time.Time) (string, error) {
	return totpCode(secret, uint64(at.Unix()/totpPeriod))
}

// VerifyTOTP 允许前后各一个时间窗（时钟漂移容忍 30 秒）。
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	counter := uint64(now.Unix() / totpPeriod)
	for _, delta := range []int64{0, -1, 1} {
		c := counter
		if delta < 0 {
			if counter == 0 {
				continue
			}
			c = counter - 1
		} else if delta > 0 {
			c = counter + 1
		}
		want, err := totpCode(secret, c)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
