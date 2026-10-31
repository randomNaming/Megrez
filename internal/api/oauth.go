package api

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"megrez/internal/auth"
	"megrez/internal/store"
)

// 单点登录用的授权码流程：
//   GET  /oauth/authorize          → 没登录先跳登录页，登录后回到这里出「同意」页
//   POST /oauth/authorize/decision → 同意后带一次性 code 跳回业务项目
//   POST /oauth/token              → 业务后端用 client_secret + code 换票据（服务端到服务端）

const authCodeTTL = 60 * time.Second

var consentTmpl = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权登录</title>
<style>
  :root{--ink:#1b1b1b;--soft:#5a5a5a;--faint:#8c8c8c;--line:#e6e6e6;--bg-soft:#fafafa}
  *{box-sizing:border-box}
  body{margin:0;background:#fff;color:var(--soft);font:14px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .card{width:360px;border:1px solid var(--line);border-radius:10px;padding:28px}
  h1{margin:0 0 6px;font-size:18px;color:var(--ink);font-weight:600}
  .sub{margin:0 0 22px;font-size:13px;color:var(--faint)}
  .app{border:1px solid var(--line);border-radius:8px;background:var(--bg-soft);padding:14px;margin-bottom:22px}
  .app .name{color:var(--ink);font-weight:600;font-size:15px}
  .app .host{color:var(--faint);font-size:12px;word-break:break-all}
  .meta{font-size:13px;margin-bottom:22px}
  .meta b{color:var(--ink);font-weight:600}
  form{display:flex;gap:10px}
  button{font:inherit;cursor:pointer;border-radius:7px;padding:9px 16px;border:1px solid var(--line);background:#fff;color:var(--ink);flex:1}
  button.primary{background:var(--ink);border-color:var(--ink);color:#fff}
  button.primary:hover{background:#000}
  button:hover{background:var(--bg-soft)}
</style></head><body>
<div class="card">
  <h1>授权登录</h1>
  <p class="sub">确认是否以你的身份登录下面的项目</p>
  <div class="app">
    <div class="name">{{.Name}}</div>
    <div class="host">{{.Host}}</div>
  </div>
  <div class="meta">将以 <b>{{.User}}</b> 的身份登录，本次票据有效期 <b>{{.TTL}}</b>，项目拿不到你的密码。</div>
  <form method="post" action="/oauth/authorize/decision">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <button type="submit" name="decision" value="deny">取消</button>
    <button type="submit" name="decision" value="allow" class="primary">允许</button>
  </form>
</div>
</body></html>`))

type consentData struct {
	Name        string
	Host        string
	User        string
	TTL         string
	ClientID    string
	RedirectURI string
	State       string
}

// resolveClient 只认已登记且未吊销的项目，redirect_uri 必须与登记值完全一致。
func (s *Server) resolveClient(clientID, redirectURI string) (*store.Client, bool) {
	c, _, err := s.Store.ClientByID(clientID)
	if err != nil || c == nil || c.RevokedAt != nil {
		return nil, false
	}
	if redirectURI != "" && redirectURI != c.RedirectURI {
		return nil, false
	}
	return c, true
}

// tokenTTL 决定这个项目的票据活多久：项目自己登记的优先，否则用服务端默认。
func (s *Server) tokenTTL(c *store.Client) time.Duration {
	if c.TokenTTL > 0 {
		return time.Duration(c.TokenTTL) * time.Second
	}
	return s.Cfg.SSOTTL
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0f 天", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f 小时", d.Hours())
	default:
		return fmt.Sprintf("%.0f 分钟", d.Minutes())
	}
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	client, ok := s.resolveClient(clientID, redirectURI)
	if !ok {
		writeErr(w, http.StatusBadRequest, "未知的应用或回调地址不匹配")
		return
	}
	_, scope, logged, err := s.sessionInfo(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if !logged || scope != "full" {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/admin?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	host := client.RedirectURI
	if u, err := url.Parse(client.RedirectURI); err == nil {
		host = u.Host
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = consentTmpl.Execute(w, consentData{
		Name: client.Name, Host: host, User: "owner",
		TTL:         humanDuration(s.tokenTTL(client)),
		ClientID:    clientID,
		RedirectURI: client.RedirectURI,
		State:       state,
	})
}

func (s *Server) handleAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式不正确")
		return
	}
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")

	_, scope, logged, err := s.sessionInfo(r)
	if err != nil || !logged || scope != "full" {
		next := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
			"&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + url.QueryEscape(state)
		http.Redirect(w, r, "/admin?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	registered, ok := s.resolveClient(clientID, redirectURI)
	if !ok {
		writeErr(w, http.StatusBadRequest, "未知的应用或回调地址不匹配")
		return
	}
	target, err := url.Parse(registered.RedirectURI)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "回调地址不合法")
		return
	}
	q := target.Query()

	if r.FormValue("decision") != "allow" {
		q.Set("error", "access_denied")
		if state != "" {
			q.Set("state", state)
		}
		target.RawQuery = q.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}

	code, err := randomToken(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	now := s.now()
	if err := s.Store.CreateAuthCode(sha256Hex(code), clientID, registered.RedirectURI, now+int64(authCodeTTL.Seconds()), now); err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "sso_authorize", "", requestIP(r), clientID)
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

type tokenReq struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	ip := requestIP(r)
	if !s.Limiter.Allow("oauth_token", ip, 30, time.Minute) {
		writeErr(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	var req tokenReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.GrantType != "authorization_code" || req.Code == "" {
		writeErr(w, http.StatusBadRequest, "grant_type 不支持")
		return
	}
	client, secretHash, err := s.Store.ClientByID(req.ClientID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if client == nil || client.RevokedAt != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(req.ClientSecret)), []byte(secretHash)) != 1 {
		writeErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	ac, err := s.Store.ConsumeAuthCode(sha256Hex(req.Code), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	if ac == nil || ac.ClientID != req.ClientID || ac.RedirectURI != client.RedirectURI {
		_ = s.Store.Audit(s.now(), "sso_token_failed", "", ip, req.ClientID)
		writeErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	now := s.now()
	ttl := s.tokenTTL(client)
	jti, err := randomToken(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	token, err := auth.SignJWT(s.Key, auth.Claims{
		Sub: "owner",
		Aud: req.ClientID,
		Typ: "access",
		Jti: jti,
		Iat: now,
		Exp: now + int64(ttl.Seconds()),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "服务内部错误")
		return
	}
	_ = s.Store.Audit(now, "sso_token", "", ip, req.ClientID+" ttl="+ttl.String())
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"sub":          "owner",
	})
}
