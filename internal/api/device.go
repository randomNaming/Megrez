package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"megrez/internal/auth"
	"megrez/internal/store"
)

var allowedPlatforms = map[string]bool{
	"ios": true, "android": true, "windows": true, "macos": true, "linux": true,
}

type registerReq struct {
	PairCode  string `json:"pair_code"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	PublicKey string `json:"public_key"`
}

type registerResp struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("register", ip, s.Cfg.RateRegisterPerHr, time.Hour) {
		writeErr(w, http.StatusTooManyRequests, "注册请求过于频繁")
		return
	}
	var req registerReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) == 0 || len(name) > 64 {
		writeErr(w, http.StatusBadRequest, "设备名长度必须在 1-64 字符之间")
		return
	}
	if !allowedPlatforms[req.Platform] {
		writeErr(w, http.StatusBadRequest, "平台必须是 ios/android/windows/macos/linux 之一")
		return
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "公钥必须是 Ed25519 原始公钥的 base64url 编码")
		return
	}
	if req.PairCode == "" {
		writeErr(w, http.StatusForbidden, "缺少配对码")
		return
	}
	pubCanonical := base64.RawURLEncoding.EncodeToString(pubRaw)
	if existing, err := s.Store.DeviceByPublicKey(pubCanonical); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	} else if existing != nil {
		writeErr(w, http.StatusConflict, "该公钥已注册")
		return
	}

	ok, err := s.Store.ConsumePairCode(auth.PairCodeHash(req.PairCode), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if !ok {
		_ = s.Store.Audit(s.now(), "register_denied", "", ip, "配对码无效或已使用")
		writeErr(w, http.StatusForbidden, "配对码无效或已使用")
		return
	}

	id, err := randomToken(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	d := &store.Device{
		ID:          "dev_" + id,
		Name:        name,
		Platform:    req.Platform,
		PublicKey:   pubCanonical,
		Fingerprint: fingerprint(pubRaw),
		Status:      "pending",
		CreatedAt:   s.now(),
	}
	if err := s.Store.InsertDevice(d); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(s.now(), "register", d.ID, ip, d.Name+" / "+d.Platform+" / "+d.Fingerprint)
	writeJSON(w, http.StatusCreated, registerResp{DeviceID: d.ID, Fingerprint: d.Fingerprint, Status: d.Status})
}

type challengeReq struct {
	DeviceID string `json:"device_id"`
}

type challengeResp struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresIn   int    `json:"expires_in"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("challenge", ip, 20, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req challengeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	dev, err := s.Store.DeviceByID(req.DeviceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if dev == nil {
		writeErr(w, http.StatusNotFound, "设备不存在")
		return
	}
	if dev.Status != "approved" {
		// 默认拒绝：未审批、被拒绝、被吊销的设备一律拿不到挑战。
		writeErr(w, http.StatusForbidden, "设备未获批准")
		return
	}
	id, nonce, err := s.Challenges.Create(dev.ID, s.Cfg.ChallengeTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	writeJSON(w, http.StatusOK, challengeResp{
		ChallengeID: id,
		Nonce:       nonce,
		ExpiresIn:   int(s.Cfg.ChallengeTTL.Seconds()),
	})
}

type verifyReq struct {
	DeviceID    string `json:"device_id"`
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

type tokenResp struct {
	DeviceID         string `json:"device_id"`
	AccessToken      string `json:"access_token"`
	AccessExpiresIn  int    `json:"access_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("verify", ip, 30, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req verifyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	dev, err := s.Store.DeviceByID(req.DeviceID)
	if err != nil || dev == nil {
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	if dev.Status != "approved" {
		_ = s.Store.Audit(s.now(), "login_denied", dev.ID, ip, "设备未获批准")
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	nonce, err := s.Challenges.Consume(req.ChallengeID, req.DeviceID, time.Now())
	if err != nil {
		_ = s.Store.Audit(s.now(), "login_denied", dev.ID, ip, "挑战无效或已使用")
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(dev.PublicKey)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), auth.SigningPayload(req.ChallengeID, nonce, dev.ID), sig) {
		_ = s.Store.Audit(s.now(), "login_denied", dev.ID, ip, "签名无效")
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}

	resp, err := s.issueTokens(dev, ip, "login")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) issueTokens(dev *store.Device, ip, event string) (*tokenResp, error) {
	now := s.now()
	jti, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	access, err := auth.SignJWT(s.Key, auth.Claims{
		Sub: dev.ID,
		Typ: "access",
		Dev: dev.Fingerprint,
		Jti: jti,
		Iat: now,
		Exp: now + int64(s.Cfg.AccessTTL.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	tid, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	if err := s.Store.InsertToken(&store.Token{
		ID:          tid,
		DeviceID:    dev.ID,
		RefreshHash: sha256Hex(refresh),
		ExpiresAt:   now + int64(s.Cfg.RefreshTTL.Seconds()),
		CreatedAt:   now,
	}); err != nil {
		return nil, err
	}
	_ = s.Store.TouchDevice(dev.ID, now, ip)
	_ = s.Store.Audit(now, event, dev.ID, ip, "")
	return &tokenResp{
		DeviceID:         dev.ID,
		AccessToken:      access,
		AccessExpiresIn:  int(s.Cfg.AccessTTL.Seconds()),
		RefreshToken:     refresh,
		RefreshExpiresIn: int(s.Cfg.RefreshTTL.Seconds()),
	}, nil
}

type refreshReq struct {
	DeviceID     string `json:"device_id"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("refresh", ip, 60, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req refreshReq
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.Store.TokenByRefreshHash(sha256Hex(req.RefreshToken))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if t == nil || t.RevokedAt != nil || t.ExpiresAt <= s.now() || t.DeviceID != req.DeviceID {
		_ = s.Store.Audit(s.now(), "refresh_denied", req.DeviceID, ip, "凭证无效")
		writeErr(w, http.StatusUnauthorized, "续期失败")
		return
	}
	dev, err := s.Store.DeviceByID(req.DeviceID)
	if err != nil || dev == nil || dev.Status != "approved" {
		writeErr(w, http.StatusUnauthorized, "续期失败")
		return
	}
	// 轮换：旧凭证立即失效。并发的两个续期请求只有一个能成功。
	rotated, err := s.Store.RevokeToken(t.ID, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if !rotated {
		writeErr(w, http.StatusUnauthorized, "续期失败")
		return
	}
	resp, err := s.issueTokens(dev, ip, "refresh")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type revokeReq struct {
	DeviceID     string `json:"device_id"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("revoke", ip, 20, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req revokeReq
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.Store.TokenByRefreshHash(sha256Hex(req.RefreshToken))
	if err != nil || t == nil || t.DeviceID != req.DeviceID {
		writeErr(w, http.StatusUnauthorized, "注销失败")
		return
	}
	now := s.now()
	if err := s.Store.RevokeDeviceTokens(req.DeviceID, now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if err := s.Store.SetDeviceStatus(req.DeviceID, "revoked", "设备自行注销", now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "self_revoke", req.DeviceID, ip, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleWellKnownKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{s.Key.PublicJWK()}})
}
