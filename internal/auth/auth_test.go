package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"megrez/internal/auth"
)

func TestPasswordRoundTrip(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	h, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("哈希失败: %v", err)
	}
	if !auth.VerifyPassword(h, pw) {
		t.Fatalf("正确密码应通过校验，哈希串 %q", h)
	}
	if auth.VerifyPassword(h, "wrong") {
		t.Fatal("错误密码不应通过校验")
	}
	if auth.VerifyPassword("", pw) || auth.VerifyPassword("garbage", pw) {
		t.Fatal("非法哈希串不应通过校验")
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	now := time.Now()
	code, err := auth.TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("生成动态码失败: %v", err)
	}
	if !auth.VerifyTOTP(secret, code, now) {
		t.Fatal("当前动态码应通过校验")
	}
	if !auth.VerifyTOTP(secret, code, now.Add(30*time.Second)) {
		t.Fatal("允许一个时间窗的漂移")
	}
	if auth.VerifyTOTP(secret, code, now.Add(2*time.Minute)) {
		t.Fatal("过期动态码不应通过校验")
	}
	if auth.VerifyTOTP(secret, "12345", now) {
		t.Fatal("位数不足不应通过校验")
	}
}

func TestJWTSignAndVerify(t *testing.T) {
	key, err := auth.LoadOrCreateSigningKey(t.TempDir() + "/k.pem")
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	now := time.Now().Unix()
	tok, err := auth.SignJWT(key, auth.Claims{Sub: "dev_1", Typ: "access", Dev: "FP", Jti: "j1", Iat: now, Exp: now + 60})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	claims, err := auth.VerifyAccess(tok, key.Public(), now, "dev_1")
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	if claims.Sub != "dev_1" || claims.Typ != "access" {
		t.Fatalf("claims 不正确: %+v", claims)
	}
	if _, err := auth.VerifyAccess(tok, key.Public(), now, "dev_2"); err == nil {
		t.Fatal("凭证不应归属另一台设备")
	}
	if _, err := auth.VerifyAccess(tok, key.Public(), now+120, "dev_1"); err == nil {
		t.Fatal("过期凭证应被拒绝")
	}
	// 换一把公钥（模拟伪造签名）必须失败。
	other, err := auth.LoadOrCreateSigningKey(t.TempDir() + "/other.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.VerifyJWT(tok, other.Public()); err == nil {
		t.Fatal("另一把公钥不应验过")
	}
}

func TestPairCodeNormalize(t *testing.T) {
	a := auth.PairCodeHash("ABCD-EFGH-IJKL")
	b := auth.PairCodeHash("abcdefghijkl")
	c := auth.PairCodeHash("  abcd efgh ijkl  ")
	if a != b || b != c {
		t.Fatal("配对码规范化后哈希应一致")
	}
}

func TestSigningPayloadStable(t *testing.T) {
	p := string(auth.SigningPayload("c1", "n1", "d1"))
	if p != "megrez-device-auth-v1|c1|n1|d1" {
		t.Fatalf("签名原文格式被改动，客户端会验不过: %q", p)
	}
}

func TestEd25519PublicKeySize(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatal("公钥长度不符合预期")
	}
}
