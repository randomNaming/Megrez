package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 20 * time.Second},
	}
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("请求失败（HTTP %d）", e.Status)
	}
	return e.Message
}

func (c *Client) post(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var e map[string]string
		_ = json.Unmarshal(raw, &e)
		return &APIError{Status: res.StatusCode, Message: e["error"]}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

type RegisterResult struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

func (c *Client) Register(pairCode, name, platform string, pub ed25519.PublicKey) (*RegisterResult, error) {
	var out RegisterResult
	err := c.post("/api/device/register", map[string]string{
		"pair_code":  pairCode,
		"name":       name,
		"platform":   platform,
		"public_key": base64.RawURLEncoding.EncodeToString(pub),
	}, &out)
	return &out, err
}

type ChallengeResult struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *Client) Challenge(deviceID string) (*ChallengeResult, error) {
	var out ChallengeResult
	err := c.post("/api/device/challenge", map[string]string{"device_id": deviceID}, &out)
	return &out, err
}

type TokenResult struct {
	DeviceID         string `json:"device_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int    `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func (c *Client) Verify(deviceID, challengeID string, sig []byte) (*TokenResult, error) {
	var out TokenResult
	err := c.post("/api/device/verify", map[string]string{
		"device_id":    deviceID,
		"challenge_id": challengeID,
		"signature":    base64.RawURLEncoding.EncodeToString(sig),
	}, &out)
	return &out, err
}

func (c *Client) Refresh(deviceID, refreshToken string) (*TokenResult, error) {
	var out TokenResult
	err := c.post("/api/token/refresh", map[string]string{
		"device_id":     deviceID,
		"refresh_token": refreshToken,
	}, &out)
	return &out, err
}

func (c *Client) Revoke(deviceID, refreshToken string) error {
	return c.post("/api/token/revoke", map[string]string{
		"device_id":     deviceID,
		"refresh_token": refreshToken,
	}, nil)
}
