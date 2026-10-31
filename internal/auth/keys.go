package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// SigningKey 是天权自己的令牌签发密钥。它只用于签访问凭证，与设备密钥无关。
// 私钥落在本机文件（0600），绝不进仓库、不进日志。
type SigningKey struct {
	Private ed25519.PrivateKey
	Kid     string
}

func LoadOrCreateSigningKey(path string) (*SigningKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("签名密钥文件格式不正确: %s", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析签名密钥失败: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("签名密钥不是 Ed25519")
		}
		return &SigningKey{Private: priv, Kid: "megrez-1"}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return nil, err
	}
	return &SigningKey{Private: priv, Kid: "megrez-1"}, nil
}

func (k *SigningKey) Public() ed25519.PublicKey {
	return k.Private.Public().(ed25519.PublicKey)
}

// PublicJWK 给业务项目本地验签用（/api/.well-known/keys）。
func (k *SigningKey) PublicJWK() map[string]string {
	pub := k.Public()
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": k.Kid,
		"alg": "EdDSA",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}
