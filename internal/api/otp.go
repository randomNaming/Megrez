package api

import (
	"net/http"
	"time"

	"github.com/skip2/go-qrcode"

	"megrez/internal/auth"
)

const otpIssuer = "Megrez"

// handleOTPQR 只对「尚未绑定动态码」的临时会话开放，返回验证器可扫的二维码。
func (s *Server) handleOTPQR(w http.ResponseWriter, r *http.Request) {
	admin, err := s.Store.Admin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if admin == nil {
		writeErr(w, http.StatusServiceUnavailable, "后台尚未初始化")
		return
	}
	if admin.OTPSecret != "" {
		writeErr(w, http.StatusConflict, "动态码已绑定")
		return
	}
	secret := admin.PendingOTPSecret
	if secret == "" {
		secret, err = auth.NewTOTPSecret()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "服务内部错误")
			return
		}
		if err := s.Store.SetPendingOTPSecret(secret); err != nil {
			writeErr(w, http.StatusInternalServerError, "服务内部错误")
			return
		}
	}
	png, err := qrcode.Encode(auth.OTPAuthURL(otpIssuer, admin.Username, secret), qrcode.Medium, 640)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

type otpConfirmReq struct {
	Code string `json:"code"`
}

func (s *Server) handleOTPConfirm(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("otpconfirm", ip, 10, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
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
	if admin.OTPSecret != "" {
		writeErr(w, http.StatusConflict, "动态码已绑定")
		return
	}
	if admin.PendingOTPSecret == "" {
		writeErr(w, http.StatusConflict, "二维码已失效，请刷新页面重试")
		return
	}
	var req otpConfirmReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !auth.VerifyTOTP(admin.PendingOTPSecret, req.Code, time.Now()) {
		_ = s.Store.Audit(s.now(), "admin_otp_bind_failed", "", ip, "")
		writeErr(w, http.StatusUnauthorized, "动态码不正确，确认验证器里显示的是当前这一组")
		return
	}
	if err := s.Store.EnrollOTP(admin.PendingOTPSecret); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	// 绑定成功：全站会话作废，强制用「密码 + 动态码」重新登录。
	if err := s.Store.DeleteAllSessions(); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	s.clearAdminCookie(w)
	_ = s.Store.Audit(s.now(), "admin_otp_enrolled", "", ip, "")
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": true})
}
