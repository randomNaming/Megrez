package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"megrez/internal/auth"
	"megrez/internal/store"
)

const maxBodyBytes = 64 << 10

type Config struct {
	ChallengeTTL      time.Duration
	AccessTTL         time.Duration
	RefreshTTL        time.Duration
	AdminSessionTTL   time.Duration
	SSOTTL            time.Duration
	TrustProxy        bool
	AdminCookieName   string
	RateRegisterPerHr int
}

func DefaultConfig() Config {
	return Config{
		ChallengeTTL:      auth.ChallengeTTL,
		AccessTTL:         15 * time.Minute,
		RefreshTTL:        30 * 24 * time.Hour,
		AdminSessionTTL:   12 * time.Hour,
		SSOTTL:            8 * time.Hour,
		TrustProxy:        false,
		AdminCookieName:   "megrez_admin",
		RateRegisterPerHr: 5,
	}
}

type Server struct {
	Store      *store.Store
	Key        *auth.SigningKey
	Challenges *auth.ChallengeStore
	Limiter    *auth.RateLimiter
	Cfg        Config
	now        func() int64
	mux        *http.ServeMux
}

func New(st *store.Store, key *auth.SigningKey, cfg Config) *Server {
	s := &Server{
		Store:      st,
		Key:        key,
		Challenges: auth.NewChallengeStore(),
		Limiter:    auth.NewRateLimiter(),
		Cfg:        cfg,
		now:        func() int64 { return time.Now().Unix() },
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.middleware(s.mux)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("POST /api/device/register", s.handleRegister)
	m.HandleFunc("POST /api/device/challenge", s.handleChallenge)
	m.HandleFunc("POST /api/device/verify", s.handleVerify)
	m.HandleFunc("POST /api/token/refresh", s.handleRefresh)
	m.HandleFunc("POST /api/token/revoke", s.handleRevoke)

	m.HandleFunc("GET /api/admin/status", s.handleAdminStatus)
	m.HandleFunc("POST /api/admin/setup", s.handleAdminSetup)
	m.HandleFunc("POST /api/admin/login", s.handleAdminLogin)
	m.HandleFunc("POST /api/admin/login/otp", s.handleAdminLoginOTP)
	m.HandleFunc("POST /api/admin/logout", s.handleAdminLogout)
	m.HandleFunc("GET /api/admin/me", s.requireSession(true, s.handleAdminMe))
	m.HandleFunc("GET /api/admin/otp/qr.png", s.requireSession(true, s.handleOTPQR))
	m.HandleFunc("POST /api/admin/otp/confirm", s.requireSession(true, s.handleOTPConfirm))
	m.HandleFunc("POST /api/admin/password", s.requireAdmin(s.handleChangePassword))
	m.HandleFunc("GET /api/admin/clients", s.requireAdmin(s.handleListClients))
	m.HandleFunc("POST /api/admin/clients", s.requireAdmin(s.handleCreateClient))
	m.HandleFunc("POST /api/admin/clients/{id}/revoke", s.requireAdmin(s.handleRevokeClient))
	m.HandleFunc("GET /api/admin/devices", s.requireAdmin(s.handleListDevices))
	m.HandleFunc("POST /api/admin/devices/{id}/approve", s.requireAdmin(s.handleApprove))
	m.HandleFunc("POST /api/admin/devices/{id}/reject", s.requireAdmin(s.handleReject))
	m.HandleFunc("POST /api/admin/devices/{id}/revoke", s.requireAdmin(s.handleRevokeDevice))
	m.HandleFunc("POST /api/admin/pair-codes", s.requireAdmin(s.handleCreatePairCode))
	m.HandleFunc("GET /api/admin/audit", s.requireAdmin(s.handleAudit))

	m.HandleFunc("GET /api/.well-known/keys", s.handleWellKnownKeys)

	// 单点登录：授权码流程
	m.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	m.HandleFunc("POST /oauth/authorize/decision", s.handleAuthorizeDecision)
	m.HandleFunc("POST /oauth/token", s.handleOAuthToken)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /admin", s.handleAdminPage)
	// 业务项目只能发起 GET 跳转，因此单独给一个退出入口：清后台会话后回登录页。
	m.HandleFunc("GET /logout", s.handleLogoutPage)
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
}

type ctxKey int

const ctxIP ctxKey = 0

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		r = r.WithContext(contextWithIP(r, ip))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic %s %s: %v", r.Method, r.URL.Path, rec)
				writeErr(w, http.StatusInternalServerError, "服务内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.Cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requestIP(r *http.Request) string {
	if v, ok := r.Context().Value(ctxIP).(string); ok {
		return v
	}
	return ""
}

func contextWithIP(r *http.Request, ip string) context.Context {
	return context.WithValue(r.Context(), ctxIP, ip)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "请求体必须是 application/json")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求体读取失败")
		return false
	}
	if len(body) == 0 {
		writeErr(w, http.StatusBadRequest, "请求体为空")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON 解析失败")
		return false
	}
	return true
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var b32Upper = base32.StdEncoding.WithPadding(base32.NoPadding)

// fingerprint 给审批页看的公钥指纹，不是密钥本身。
func fingerprint(pubRaw []byte) string {
	sum := sha256.Sum256(pubRaw)
	s := b32Upper.EncodeToString(sum[:])[:16]
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
