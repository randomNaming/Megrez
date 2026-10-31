package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

var stateEntropy = []byte("megrez-client-state-v1")

// State 是这台设备上唯一的一份本地状态：私钥种子 + 短期/长期凭证。
// 整份文件用 DPAPI 加密，明文不落盘。
type State struct {
	Server           string `json:"server"`
	DeviceID         string `json:"device_id"`
	Name             string `json:"name"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	SeedB64          string `json:"seed"`
	AccessToken      string `json:"access_token"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresAt int64  `json:"refresh_expires_at"`
}

func DefaultStatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "megrez", "device.state"), nil
}

func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := unprotectSecret(raw, stateEntropy)
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, fmt.Errorf("本地状态损坏: %w", err)
	}
	return &st, nil
}

func SaveState(path string, st *State) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return err
	}
	cipher, err := protectSecret(plain, stateEntropy)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, cipher, 0o600)
}

func DeleteState(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (s *State) PrivateKey() (ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(s.SeedB64)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("私钥种子长度不正确")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
