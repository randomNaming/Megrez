package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 最小 JWT（EdDSA）。不引第三方库，格式遵守 RFC 7519，
// 业务侧（Node/Go/Python）都能用各自标准库验签。

var (
	ErrTokenMalformed = errors.New("令牌格式不正确")
	ErrTokenSignature = errors.New("令牌签名无效")
	ErrTokenExpired   = errors.New("令牌已过期")
)

var b64 = base64.RawURLEncoding

type Claims struct {
	Sub string `json:"sub"` // 设备 ID；SSO 票据为 owner
	Aud string `json:"aud,omitempty"`
	Typ string `json:"typ"`           // access
	Dev string `json:"dev,omitempty"` // 公钥指纹，便于业务侧按设备排查
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func ClaimsToJSON(c Claims) []byte {
	b, _ := json.Marshal(c)
	return b
}

func SignJWT(key *SigningKey, c Claims) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": key.Kid}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(key.Private, []byte(signing))
	return signing + "." + b64.EncodeToString(sig), nil
}

func VerifyJWT(token string, pub ed25519.PublicKey) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}
	signing := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if !ed25519.Verify(pub, []byte(signing), sig) {
		return nil, ErrTokenSignature
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrTokenMalformed
	}
	return &c, nil
}

// VerifyAccess 供业务侧参考实现：验签 + 过期 + 令牌类型。
func VerifyAccess(token string, pub ed25519.PublicKey, now int64, deviceID string) (*Claims, error) {
	c, err := VerifyJWT(token, pub)
	if err != nil {
		return nil, err
	}
	if c.Typ != "access" {
		return nil, fmt.Errorf("令牌类型不是 access")
	}
	if c.Exp <= now {
		return nil, ErrTokenExpired
	}
	if deviceID != "" && c.Sub != deviceID {
		return nil, fmt.Errorf("令牌不属于该设备")
	}
	return c, nil
}
