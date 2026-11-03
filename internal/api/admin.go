package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"megrez/internal/auth"
	"megrez/internal/store"
	"megrez/internal/ui"
)

type deviceDTO struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Platform    string  `json:"platform"`
	Fingerprint string  `json:"fingerprint"`
	PublicKey   string  `json:"public_key"`
	Status      string  `json:"status"`
	CreatedAt   int64   `json:"created_at"`
	ApprovedAt  *int64  `json:"approved_at,omitempty"`
	LastSeenAt  *int64  `json:"last_seen_at,omitempty"`
	LastIP      *string `json:"last_ip,omitempty"`
	Note        *string `json:"note,omitempty"`
}

func toDTO(d *store.Device) deviceDTO {
	return deviceDTO{
		ID: d.ID, Name: d.Name, Platform: d.Platform, Fingerprint: d.Fingerprint,
		PublicKey: d.PublicKey, Status: d.Status, CreatedAt: d.CreatedAt,
		ApprovedAt: d.ApprovedAt, LastSeenAt: d.LastSeenAt, LastIP: d.LastIP, Note: d.Note,
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(ui.AdminHTML)
}

func (s *Server) sessionHashFrom(r *http.Request) string {
	if c, err := r.Cookie(s.Cfg.AdminCookieName); err == nil && c.Value != "" {
		return sha256Hex(c.Value)
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return sha256Hex(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
	}
	return ""
}

func (s *Server) sessionInfo(r *http.Request) (hash, scope string, ok bool, err error) {
	hash = s.sessionHashFrom(r)
	if hash == "" {
		return "", "", false, nil
	}
	scope, valid, err := s.Store.SessionInfo(hash, s.now())
	if err != nil || !valid {
		return hash, "", false, err
	}
	return hash, scope, true, nil
}

// requireSession 校验会话。allowPending=false 时只认已绑定动态码的完整会话。
func (s *Server) requireSession(allowPending bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, scope, ok, err := s.sessionInfo(r)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "服务内部错误")
			return
		}
		if !ok {
			writeErr(w, http.StatusUnauthorized, "会话已失效，请重新登录")
			return
		}
		if scope != "full" && !allowPending {
			writeErr(w, http.StatusForbidden, "请先用手机验证器完成动态码绑定")
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireSession(false, next)
}

func (s *Server) clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.Cfg.AdminCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

type adminLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleAdminLogin 只校验账号密码。
// 页面上不出现动态码，非首次登录由前端跳到第二步（只填动态码），
// 目的是不让随便扫一眼登录页就能读出「密码 + 动态码」这套模型。
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if until, locked := s.Limiter.LockedOut("adminlogin", ip); locked {
		writeErr(w, http.StatusTooManyRequests,
			"登录已锁定，请 "+strconv.Itoa(int(time.Until(until).Minutes())+1)+" 分钟后再试")
		return
	}
	if !s.Limiter.Allow("adminlogin-rate", ip, 10, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req adminLoginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	admin, err := s.Store.Admin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if admin == nil {
		writeErr(w, http.StatusServiceUnavailable, "后台尚未初始化")
		return
	}
	if !auth.VerifyPassword(admin.PasswordHash, req.Password) || strings.TrimSpace(req.Username) != admin.Username {
		s.Limiter.FailLogin("adminlogin", ip, 5, 15*time.Minute)
		_ = s.Store.Audit(s.now(), "admin_login_failed", "", ip, "")
		writeErr(w, http.StatusUnauthorized, "账号或密码不正确")
		return
	}
	s.Limiter.ResetLogin("adminlogin", ip)
	now := s.now()

	if admin.OTPSecret == "" {
		// 首次：只发临时会话，进去也只能看到扫码绑定页。
		if admin.PendingOTPSecret == "" {
			secret, err := auth.NewTOTPSecret()
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "服务内部错误")
				return
			}
			if err := s.Store.SetPendingOTPSecret(secret); err != nil {
				writeErr(w, http.StatusInternalServerError, "服务内部错误")
				return
			}
		}
		token, err := randomToken(32)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "服务内部错误")
			return
		}
		exp := now + int64(s.Cfg.AdminSessionTTL.Seconds())
		if err := s.Store.InsertSession(sha256Hex(token), "pending_enroll", exp, now, ip); err != nil {
			writeErr(w, http.StatusInternalServerError, "服务内部错误")
			return
		}
		s.setAdminCookie(w, r, token, exp)
		_ = s.Store.Audit(now, "admin_password_ok", "", ip, "首次登录")
		writeJSON(w, http.StatusOK, map[string]any{"step": "enroll"})
		return
	}

	// 已绑定：不直接发会话，只发一张 5 分钟的一次性票，用来完成第二步。
	pre, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	exp := now + 300
	if err := s.Store.InsertSession(sha256Hex(pre), "pending_otp", exp, now, ip); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "admin_password_ok", "", ip, "")
	writeJSON(w, http.StatusOK, map[string]any{"step": "otp", "otp_token": pre, "expires_in": 300})
}

type adminOTPReq struct {
	OTPToken string `json:"otp_token"`
	Code     string `json:"code"`
}

func (s *Server) handleAdminLoginOTP(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if until, locked := s.Limiter.LockedOut("adminlogin", ip); locked {
		writeErr(w, http.StatusTooManyRequests,
			"验证已锁定，请 "+strconv.Itoa(int(time.Until(until).Minutes())+1)+" 分钟后再试")
		return
	}
	if !s.Limiter.Allow("adminlogin-rate", ip, 10, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req adminOTPReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.OTPToken == "" {
		writeErr(w, http.StatusUnauthorized, "验证已失效，请重新登录")
		return
	}
	hash := sha256Hex(req.OTPToken)
	scope, ok, err := s.Store.SessionInfo(hash, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if !ok || scope != "pending_otp" {
		writeErr(w, http.StatusUnauthorized, "验证已失效，请重新登录")
		return
	}
	admin, err := s.Store.Admin()
	if err != nil || admin == nil || admin.OTPSecret == "" {
		writeErr(w, http.StatusUnauthorized, "验证失败")
		return
	}
	if !auth.VerifyTOTP(admin.OTPSecret, req.Code, time.Now()) {
		s.Limiter.FailLogin("adminlogin", ip, 5, 15*time.Minute)
		_ = s.Store.Audit(s.now(), "admin_otp_failed", "", ip, "")
		writeErr(w, http.StatusUnauthorized, "验证码不正确")
		return
	}
	s.Limiter.ResetLogin("adminlogin", ip)

	// 一次性票用完即删，再签发完整会话。
	_ = s.Store.DeleteSession(hash)
	now := s.now()
	token, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	exp := now + int64(s.Cfg.AdminSessionTTL.Seconds())
	if err := s.Store.InsertSession(sha256Hex(token), "full", exp, now, ip); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	s.setAdminCookie(w, r, token, exp)
	_ = s.Store.Audit(now, "admin_login", "", ip, "")
	writeJSON(w, http.StatusOK, map[string]any{"step": "done", "username": admin.Username})
}

func (s *Server) setAdminCookie(w http.ResponseWriter, r *http.Request, token string, exp int64) {
	// 前置 nginx 终止 TLS 时 r.TLS 为空，要靠 X-Forwarded-Proto 判断，否则 Cookie 不会带 Secure。
	secure := r.TLS != nil
	if !secure && s.Cfg.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		secure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.Cfg.AdminCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  time.Unix(exp, 0),
		MaxAge:   int(time.Until(time.Unix(exp, 0)).Seconds()),
	})
}

type changePasswordReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if len([]rune(req.New)) < 14 {
		writeErr(w, http.StatusBadRequest, "新密码至少 14 个字符")
		return
	}
	admin, err := s.Store.Admin()
	if err != nil || admin == nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if !auth.VerifyPassword(admin.PasswordHash, req.Current) {
		_ = s.Store.Audit(s.now(), "admin_password_change_failed", "", requestIP(r), "")
		writeErr(w, http.StatusUnauthorized, "当前密码不正确")
		return
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if err := s.Store.UpdatePassword(hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	// 改密码后全部会话作废，必须用新密码重新走两步登录。
	_ = s.Store.DeleteAllSessions()
	s.clearAdminCookie(w)
	_ = s.Store.Audit(s.now(), "admin_password_changed", "", requestIP(r), "")
	writeJSON(w, http.StatusOK, map[string]any{"changed": true})
}

func (s *Server) handleAdminMe(w http.ResponseWriter, r *http.Request) {
	admin, err := s.Store.Admin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if admin == nil {
		writeErr(w, http.StatusServiceUnavailable, "后台尚未初始化")
		return
	}
	_, scope, _, _ := s.sessionInfo(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": admin.Username,
		"enrolled": admin.OTPSecret != "",
		"scope":    scope,
	})
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	hash := s.sessionHashFrom(r)
	if hash != "" {
		_ = s.Store.DeleteSession(hash)
	}
	s.clearAdminCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleLogoutPage 供业务项目跳转退出：GET 不能带 CSRF 校验，但这里的副作用只是
// 「把自己踢下线」，最坏情况是被诱骗退出一次，可接受。
//
// 支持 ?next=：退出后直接回到发起退出的业务项目，而不是掉进后台首页 ——
// 业务项目那边再发起登录，用户看到的就是「登录 → 授权 → 回业务」这条路。
func (s *Server) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	hash := s.sessionHashFrom(r)
	if hash != "" {
		_ = s.Store.DeleteSession(hash)
	}
	s.clearAdminCookie(w)

	if target := s.allowedNext(r.URL.Query().Get("next")); target != "" {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// allowedNext 只允许站内路径或以已登记项目域名开头的地址，避免开放重定向。
func (s *Server) allowedNext(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	target, err := url.Parse(raw)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") {
		return ""
	}
	clients, err := s.Store.ListClients()
	if err != nil {
		return ""
	}
	for _, c := range clients {
		if c.RevokedAt != nil {
			continue
		}
		cu, err := url.Parse(c.RedirectURI)
		if err != nil {
			continue
		}
		if strings.EqualFold(cu.Host, target.Host) {
			return raw
		}
	}
	return ""
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.Store.ListDevices(200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	out := make([]deviceDTO, 0, len(devices))
	for _, d := range devices {
		out = append(out, toDTO(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out, "server_time": s.now()})
}

type noteReq struct {
	Note string `json:"note"`
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求体读取失败")
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 解析失败")
		return false
	}
	return true
}

func (s *Server) loadDevice(w http.ResponseWriter, r *http.Request) (*store.Device, bool) {
	id := r.PathValue("id")
	dev, err := s.Store.DeviceByID(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return nil, false
	}
	if dev == nil {
		writeErr(w, http.StatusNotFound, "设备不存在")
		return nil, false
	}
	return dev, true
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	if dev.Status == "revoked" {
		writeErr(w, http.StatusConflict, "已吊销的设备不能恢复，请重新注册")
		return
	}
	var req noteReq
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	if err := s.Store.SetDeviceStatus(dev.ID, "approved", strings.TrimSpace(req.Note), s.now()); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(s.now(), "approve", dev.ID, requestIP(r), strings.TrimSpace(req.Note))
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	var req noteReq
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	now := s.now()
	if err := s.Store.SetDeviceStatus(dev.ID, "rejected", strings.TrimSpace(req.Note), now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.RevokeDeviceTokens(dev.ID, now)
	_ = s.Store.Audit(now, "reject", dev.ID, requestIP(r), strings.TrimSpace(req.Note))
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.loadDevice(w, r)
	if !ok {
		return
	}
	var req noteReq
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	now := s.now()
	if err := s.Store.SetDeviceStatus(dev.ID, "revoked", strings.TrimSpace(req.Note), now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.RevokeDeviceTokens(dev.ID, now)
	_ = s.Store.Audit(now, "revoke", dev.ID, requestIP(r), strings.TrimSpace(req.Note))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

type pairCodeReq struct {
	TTLMinutes int `json:"ttl_minutes"`
}

func (s *Server) handleCreatePairCode(w http.ResponseWriter, r *http.Request) {
	var req pairCodeReq
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	ttl := req.TTLMinutes
	if ttl == 0 {
		ttl = 10
	}
	if ttl < 1 || ttl > 1440 {
		writeErr(w, http.StatusBadRequest, "有效期必须在 1-1440 分钟之间")
		return
	}
	pretty, canonical, err := auth.NewPairCode()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	now := s.now()
	exp := now + int64(ttl*60)
	if err := s.Store.CreatePairCode(auth.PairCodeHash(canonical), exp, now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "pair_code_created", "", requestIP(r), "")
	// 二维码内容就是配对码本身：移动端扫码即得，扫不了还能照着下面的文字手动输。
	qrPNG, err := qrcode.Encode(pretty, qrcode.Medium, 480)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "生成二维码失败")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":        pretty,
		"expires_at":  exp,
		"expires_in":  ttl * 60,
		"qr_data_uri": "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG),
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := s.Store.ListAudit(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
