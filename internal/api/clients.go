package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"megrez/internal/auth"
	"megrez/internal/store"
)

// handleAdminStatus 让网页判断是「首次设置」还是「正常登录」。不泄露任何账号信息。
func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	admin, err := s.Store.Admin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"initialized": admin != nil})
}

type setupReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleAdminSetup 网页端首次设置管理员密码。库和密钥在服务启动时已经自动建好，这里只写管理员。
func (s *Server) handleAdminSetup(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("admin_setup", ip, 5, 15*time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	admin, err := s.Store.Admin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if admin != nil {
		writeErr(w, http.StatusConflict, "已经初始化过了，请直接登录")
		return
	}
	var req setupReq
	if !decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	if len([]rune(username)) == 0 || len([]rune(username)) > 64 {
		writeErr(w, http.StatusBadRequest, "账号必须 1-64 个字符")
		return
	}
	if len([]rune(req.Password)) < 14 {
		writeErr(w, http.StatusBadRequest, "密码至少 14 个字符")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	now := s.now()
	if err := s.Store.SetAdminPassword(username, hash, now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "admin_created", "", ip, "web")
	writeJSON(w, http.StatusCreated, map[string]string{"username": username})
}

type clientDTO struct {
	ClientID        string `json:"client_id"`
	Name            string `json:"name"`
	RedirectURI     string `json:"redirect_uri"`
	TokenTTLSeconds int64  `json:"token_ttl_seconds"`
	CreatedAt       int64  `json:"created_at"`
	Revoked         bool   `json:"revoked"`
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.Store.ListClients()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	out := make([]clientDTO, 0, len(clients))
	for _, c := range clients {
		out = append(out, clientDTO{
			ClientID: c.ID, Name: c.Name, RedirectURI: c.RedirectURI,
			TokenTTLSeconds: c.TokenTTL, CreatedAt: c.CreatedAt, Revoked: c.RevokedAt != nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out, "default_ttl_seconds": int(s.Cfg.SSOTTL.Seconds())})
}

type createClientReq struct {
	Name            string `json:"name"`
	RedirectURI     string `json:"redirect_uri"`
	TokenTTLMinutes int    `json:"token_ttl_minutes"`
}

// normalizeRedirectURI 只接受带 host 的 http/https 绝对地址，且不允许 # 片段。
func normalizeRedirectURI(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
		return "", false
	}
	return u.String(), true
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if len([]rune(name)) == 0 || len([]rune(name)) > 64 {
		writeErr(w, http.StatusBadRequest, "项目名必须 1-64 个字符")
		return
	}
	redirectURI, ok := normalizeRedirectURI(req.RedirectURI)
	if !ok {
		writeErr(w, http.StatusBadRequest, "回调地址必须是完整的 http/https 地址且不带 # 片段")
		return
	}
	ttlMin := req.TokenTTLMinutes
	if ttlMin == 0 {
		ttlMin = int(s.Cfg.SSOTTL.Minutes())
	}
	if ttlMin < 5 || ttlMin > 525600 {
		writeErr(w, http.StatusBadRequest, "票据有效期必须在 5 分钟到 365 天之间")
		return
	}

	idRaw, err := randomToken(8)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	clientID := "app_" + idRaw
	now := s.now()
	if err := s.Store.CreateClient(&store.Client{
		ID: clientID, Name: name, RedirectURI: redirectURI,
		TokenTTL: int64(ttlMin) * 60, CreatedAt: now,
	}, sha256Hex(secret)); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "client_created", "", requestIP(r), clientID+" "+name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":         clientID,
		"client_secret":     secret,
		"name":              name,
		"redirect_uri":      redirectURI,
		"token_ttl_seconds": ttlMin * 60,
	})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, _, err := s.Store.ClientByID(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "项目不存在")
		return
	}
	if err := s.Store.RevokeClient(id, s.now()); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(s.now(), "client_revoked", "", requestIP(r), id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

type updateRedirectReq struct {
	RedirectURI string `json:"redirect_uri"`
}

// handleUpdateClientRedirect 只改回调地址；client_id 和 secret 不动。
func (s *Server) handleUpdateClientRedirect(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, _, err := s.Store.ClientByID(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if c == nil {
		writeErr(w, http.StatusNotFound, "项目不存在")
		return
	}
	if c.RevokedAt != nil {
		writeErr(w, http.StatusConflict, "项目已吊销，不能再改回调地址")
		return
	}
	var req updateRedirectReq
	if !decodeJSON(w, r, &req) {
		return
	}
	redirectURI, ok := normalizeRedirectURI(req.RedirectURI)
	if !ok {
		writeErr(w, http.StatusBadRequest, "回调地址必须是完整的 http/https 地址且不带 # 片段")
		return
	}
	if redirectURI == c.RedirectURI {
		writeJSON(w, http.StatusOK, map[string]string{"client_id": id, "redirect_uri": redirectURI})
		return
	}
	if err := s.Store.UpdateClientRedirect(id, redirectURI); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(s.now(), "client_redirect_changed", "", requestIP(r),
		id+" "+c.RedirectURI+" -> "+redirectURI)
	writeJSON(w, http.StatusOK, map[string]string{"client_id": id, "redirect_uri": redirectURI})
}
