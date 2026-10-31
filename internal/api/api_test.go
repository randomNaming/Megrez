package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"megrez/internal/api"
	"megrez/internal/auth"
	"megrez/internal/store"
)

type testEnv struct {
	t         *testing.T
	srv       *api.Server
	ts        *httptest.Server
	st        *store.Store
	key       *auth.SigningKey
	admin     string
	pw        string
	otpSecret string
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnvWithOTP(t, true)
}

// newBareEnv 建好服务和空库，但没有管理员——用来测首次设置流程。
func newBareEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	key, err := auth.LoadOrCreateSigningKey(filepath.Join(dir, "signing.key"))
	if err != nil {
		t.Fatalf("生成测试签名密钥失败: %v", err)
	}
	srv := api.New(st, key, api.DefaultConfig())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		st.Close()
	})
	return &testEnv{t: t, srv: srv, ts: ts, st: st, key: key}
}

func newEnvWithOTP(t *testing.T, enrolled bool) *testEnv {
	t.Helper()
	e := newBareEnv(t)
	pw := "test-password-1234" // 测试夹具，非真实凭据
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("哈希测试密码失败: %v", err)
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatalf("生成测试动态码密钥失败: %v", err)
	}
	now := time.Now().Unix()
	if err := e.st.SetAdminPassword("admin", hash, now); err != nil {
		t.Fatalf("写入测试管理员失败: %v", err)
	}
	if enrolled {
		if err := e.st.EnrollOTP(secret); err != nil {
			t.Fatalf("绑定测试动态码失败: %v", err)
		}
	}
	e.admin, e.pw, e.otpSecret = "admin", pw, secret
	return e
}

func (e *testEnv) call(method, path string, body any, client *http.Client, bearer string) (int, map[string]any) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("序列化请求失败: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rdr)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	c := client
	if c == nil {
		c = e.ts.Client()
	}
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("请求失败: %v", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return res.StatusCode, out
}

func (e *testEnv) pairCode() string {
	e.t.Helper()
	pretty, canonical, err := auth.NewPairCode()
	if err != nil {
		e.t.Fatalf("生成配对码失败: %v", err)
	}
	now := time.Now().Unix()
	if err := e.st.CreatePairCode(auth.PairCodeHash(canonical), now+600, now); err != nil {
		e.t.Fatalf("写入配对码失败: %v", err)
	}
	return pretty
}

func (e *testEnv) adminClient() *http.Client {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	code, out := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": e.pw}, c, "")
	if code != http.StatusOK {
		e.t.Fatalf("管理员第一步登录失败，状态码 %d: %v", code, out)
	}
	token, _ := out["otp_token"].(string)
	if token == "" {
		e.t.Fatalf("已绑定动态码时应返回第二步票据，实际 %v", out)
	}
	otp, err := auth.TOTPCode(e.otpSecret, time.Now())
	if err != nil {
		e.t.Fatalf("生成动态码失败: %v", err)
	}
	code, out = e.call(http.MethodPost, "/api/admin/login/otp",
		map[string]string{"otp_token": token, "code": otp}, c, "")
	if code != http.StatusOK {
		e.t.Fatalf("管理员第二步验证失败，状态码 %d: %v", code, out)
	}
	return c
}

// enroll 注册并返回设备 ID、密钥对；不自动审批。
func (e *testEnv) enroll(name string) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	e.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.t.Fatalf("生成设备密钥失败: %v", err)
	}
	code, out := e.call(http.MethodPost, "/api/device/register", map[string]string{
		"pair_code":  e.pairCode(),
		"name":       name,
		"platform":   "windows",
		"public_key": b64(pub),
	}, nil, "")
	if code != http.StatusCreated {
		e.t.Fatalf("注册失败，状态码 %d: %v", code, out)
	}
	return out["device_id"].(string), pub, priv
}

func (e *testEnv) login(deviceID string, priv ed25519.PrivateKey) (int, map[string]any) {
	e.t.Helper()
	chCode, ch := e.call(http.MethodPost, "/api/device/challenge", map[string]string{"device_id": deviceID}, nil, "")
	if chCode != http.StatusOK {
		return chCode, ch
	}
	sig := ed25519.Sign(priv, auth.SigningPayload(ch["challenge_id"].(string), ch["nonce"].(string), deviceID))
	return e.call(http.MethodPost, "/api/device/verify", map[string]string{
		"device_id":    deviceID,
		"challenge_id": ch["challenge_id"].(string),
		"signature":    b64(sig),
	}, nil, "")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestP0_RegistrationWithoutApprovalCannotLogin(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")

	// 未审批：连挑战都拿不到。
	code, out := e.call(http.MethodPost, "/api/device/challenge",
		map[string]string{"device_id": deviceID}, nil, "")
	if code != http.StatusForbidden {
		t.Fatalf("未审批设备应被拒绝挑战，实际 %d: %v", code, out)
	}
	// 即使伪造一次验证请求也拿不到凭证。
	code, _ = e.call(http.MethodPost, "/api/device/verify", map[string]string{
		"device_id": deviceID, "challenge_id": "fake", "signature": b64([]byte{1, 2, 3}),
	}, nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("未审批设备的验证应失败，实际 %d", code)
	}
	_ = priv
}

func TestP0_ApprovedDeviceCanLoginAndTokensVerifyLocally(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")
	admin := e.adminClient()
	code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{"note": "自用机"}, admin, "")
	if code != http.StatusOK {
		t.Fatalf("审批失败，状态码 %d", code)
	}

	code, tok := e.login(deviceID, priv)
	if code != http.StatusOK {
		t.Fatalf("已审批设备应能登录，实际 %d: %v", code, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("没有拿到访问凭证")
	}

	// 业务侧本地验签（不回调天权），这就是 P1 中间件要做的事。
	claims, err := auth.VerifyAccess(access, e.key.Public(), time.Now().Unix(), deviceID)
	if err != nil {
		t.Fatalf("业务侧验签失败: %v", err)
	}
	if claims.Sub != deviceID || claims.Typ != "access" {
		t.Fatalf("凭证内容不正确: %+v", claims)
	}
	// JWKS 端点必须能给出可验签的公钥。
	code, jwks := e.call(http.MethodGet, "/api/.well-known/keys", nil, nil, "")
	if code != http.StatusOK {
		t.Fatalf("JWKS 端点异常，状态码 %d", code)
	}
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("JWKS 应只包含一把签发公钥，实际 %v", jwks)
	}

	// 后台必须能看到这台设备及其审批状态。
	code, list := e.call(http.MethodGet, "/api/admin/devices", nil, admin, "")
	if code != http.StatusOK {
		t.Fatalf("设备列表异常，状态码 %d", code)
	}
	devs, _ := list["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("应只有一台设备，实际 %v", list)
	}
	if first, ok := devs[0].(map[string]any); !ok || first["status"] != "approved" {
		t.Fatalf("审批后设备状态应为 approved，实际 %v", devs[0])
	}
}

func TestP0_RevokeKillsAccessImmediately(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatalf("审批失败")
	}
	code, tok := e.login(deviceID, priv)
	if code != http.StatusOK {
		t.Fatalf("登录失败: %d", code)
	}
	refresh := tok["refresh_token"].(string)

	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/revoke",
		map[string]string{"note": "设备丢失"}, admin, ""); code != http.StatusOK {
		t.Fatalf("吊销失败")
	}
	// 吊销后：续期立即失败，挑战也拿不到。
	code, _ = e.call(http.MethodPost, "/api/token/refresh",
		map[string]string{"device_id": deviceID, "refresh_token": refresh}, nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("吊销后续期应失败，实际 %d", code)
	}
	code, _ = e.call(http.MethodPost, "/api/device/challenge",
		map[string]string{"device_id": deviceID}, nil, "")
	if code != http.StatusForbidden {
		t.Fatalf("吊销后不应再发挑战，实际 %d", code)
	}
}

func TestReplayChallengeRejected(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatal("审批失败")
	}
	_, ch := e.call(http.MethodPost, "/api/device/challenge", map[string]string{"device_id": deviceID}, nil, "")
	cid := ch["challenge_id"].(string)
	sig := ed25519.Sign(priv, auth.SigningPayload(cid, ch["nonce"].(string), deviceID))
	payload := map[string]string{"device_id": deviceID, "challenge_id": cid, "signature": b64(sig)}

	if code, _ := e.call(http.MethodPost, "/api/device/verify", payload, nil, ""); code != http.StatusOK {
		t.Fatal("首次验证应成功")
	}
	if code, out := e.call(http.MethodPost, "/api/device/verify", payload, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("同一挑战第二次使用应被拒绝，实际 %d: %v", code, out)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	e := newEnv(t)
	deviceID, _, _ := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatal("审批失败")
	}
	// 用另一把私钥签名同一段原文：签名验不过。
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, ch := e.call(http.MethodPost, "/api/device/challenge", map[string]string{"device_id": deviceID}, nil, "")
	sig := ed25519.Sign(wrongPriv, auth.SigningPayload(ch["challenge_id"].(string), ch["nonce"].(string), deviceID))
	code, _ := e.call(http.MethodPost, "/api/device/verify", map[string]string{
		"device_id": deviceID, "challenge_id": ch["challenge_id"].(string), "signature": b64(sig),
	}, nil, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("篡改签名应被拒绝，实际 %d", code)
	}
}

func TestPairCodeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	code := e.pairCode()
	body := map[string]string{"pair_code": code, "name": "机 A", "platform": "windows", "public_key": b64(pub)}
	if c, _ := e.call(http.MethodPost, "/api/device/register", body, nil, ""); c != http.StatusCreated {
		t.Fatalf("首次注册应成功，实际 %d", c)
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	body["public_key"] = b64(pub2)
	if c, _ := e.call(http.MethodPost, "/api/device/register", body, nil, ""); c != http.StatusForbidden {
		t.Fatalf("同一配对码第二次应被拒绝，实际 %d", c)
	}
}

func TestRefreshRotationInvalidatesOldToken(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatal("审批失败")
	}
	_, tok := e.login(deviceID, priv)
	old := tok["refresh_token"].(string)
	if code, _ := e.call(http.MethodPost, "/api/token/refresh",
		map[string]string{"device_id": deviceID, "refresh_token": old}, nil, ""); code != http.StatusOK {
		t.Fatal("首次续期应成功")
	}
	if code, _ := e.call(http.MethodPost, "/api/token/refresh",
		map[string]string{"device_id": deviceID, "refresh_token": old}, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("旧长期凭证应已失效，实际 %d", code)
	}
}

func TestSelfRevokeDisablesDevice(t *testing.T) {
	e := newEnv(t)
	deviceID, _, priv := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatal("审批失败")
	}
	_, tok := e.login(deviceID, priv)
	if code, _ := e.call(http.MethodPost, "/api/token/revoke", map[string]string{
		"device_id": deviceID, "refresh_token": tok["refresh_token"].(string),
	}, nil, ""); code != http.StatusOK {
		t.Fatalf("自注销失败，实际 %d", code)
	}
	if code, _ := e.call(http.MethodPost, "/api/device/challenge",
		map[string]string{"device_id": deviceID}, nil, ""); code != http.StatusForbidden {
		t.Fatalf("自注销后不应再发挑战，实际 %d", code)
	}
}

func TestRevokedDeviceCannotBeApprovedAgain(t *testing.T) {
	e := newEnv(t)
	deviceID, _, _ := e.enroll("测试机")
	admin := e.adminClient()
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/revoke",
		map[string]string{}, admin, ""); code != http.StatusOK {
		t.Fatal("吊销失败")
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/devices/"+deviceID+"/approve",
		map[string]string{}, admin, ""); code != http.StatusConflict {
		t.Fatalf("已吊销设备不应能恢复，实际 %d", code)
	}
}

func TestAdminEndpointsRequireSession(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.call(http.MethodGet, "/api/admin/devices", nil, nil, ""); code != http.StatusUnauthorized {
		t.Fatalf("未登录访问设备列表应被拒绝，实际 %d", code)
	}
	if code, _ := e.call(http.MethodGet, "/api/admin/audit", nil, nil, "random-token"); code != http.StatusUnauthorized {
		t.Fatalf("无效会话应被拒绝，实际 %d", code)
	}
}

func TestAdminLoginLockoutAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.call(http.MethodPost, "/api/admin/login",
			map[string]string{"username": e.admin, "password": "wrong-password", "otp": "000000"}, nil, "")
	}
	otp, _ := auth.TOTPCode(e.otpSecret, time.Now())
	code, out := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": e.pw, "otp": otp}, nil, "")
	if code != http.StatusTooManyRequests {
		t.Fatalf("连续失败后应被锁定，实际 %d: %v", code, out)
	}
}

func TestRegisterRateLimit(t *testing.T) {
	e := newEnv(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	lastCode := 0
	for i := 0; i < 6; i++ {
		code, _ := e.call(http.MethodPost, "/api/device/register", map[string]string{
			"pair_code":  "AAAA-AAAA-AAAA",
			"name":       "机",
			"platform":   "windows",
			"public_key": b64(pub),
		}, nil, "")
		lastCode = code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("第 6 次注册应被限流，实际 %d", lastCode)
	}
}

// P0 的管理员首次绑定流程：密码登录 → 网页二维码 → 输一次动态码确认 → 强制退出 → 之后必须密码 + 动态码。
func TestFirstLoginBindsOTPAndForcesRelogin(t *testing.T) {
	e := newEnvWithOTP(t, false)

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	code, out := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": e.pw}, c, "")
	if code != http.StatusOK {
		t.Fatalf("首次登录只需密码，实际 %d: %v", code, out)
	}
	if step, _ := out["step"].(string); step != "enroll" {
		t.Fatalf("尚未绑定动态码时应进入绑定流程，实际 %v", out)
	}

	// 临时会话只能看到绑定页，碰不到设备数据。
	if code, _ := e.call(http.MethodGet, "/api/admin/devices", nil, c, ""); code != http.StatusForbidden {
		t.Fatalf("未绑定动态码的会话不应能读设备列表，实际 %d", code)
	}

	// 二维码必须在登录后的会话里可取到。
	res, err := c.Get(e.ts.URL + "/api/admin/otp/qr.png")
	if err != nil {
		t.Fatalf("取二维码失败: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("二维码接口异常，状态码 %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
		t.Fatalf("二维码应返回 PNG，实际 %q", ct)
	}

	adminRow, err := e.st.Admin()
	if err != nil || adminRow == nil {
		t.Fatalf("读取管理员失败: %v", err)
	}
	if adminRow.PendingOTPSecret == "" {
		t.Fatal("二维码接口应生成待绑定的动态码密钥")
	}
	correct, err := auth.TOTPCode(adminRow.PendingOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("计算测试动态码失败: %v", err)
	}
	wrong := "000000"
	if wrong == correct {
		wrong = "111111"
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/otp/confirm",
		map[string]string{"code": wrong}, c, ""); code != http.StatusUnauthorized {
		t.Fatalf("错误动态码应被拒绝，实际 %d", code)
	}

	if code, _ := e.call(http.MethodPost, "/api/admin/otp/confirm",
		map[string]string{"code": correct}, c, ""); code != http.StatusOK {
		t.Fatalf("正确动态码应绑定成功，实际 %d", code)
	}

	// 绑定成功后：旧会话作废，必须重新登录。
	if code, _ := e.call(http.MethodGet, "/api/admin/me", nil, c, ""); code != http.StatusUnauthorized {
		t.Fatalf("绑定后旧会话应失效，实际 %d", code)
	}
	jar2, _ := cookiejar.New(nil)
	c2 := &http.Client{Jar: jar2}
	code, out = e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": e.pw}, c2, "")
	if code != http.StatusOK {
		t.Fatalf("密码正确时应进入第二步，实际 %d: %v", code, out)
	}
	if step, _ := out["step"].(string); step != "otp" {
		t.Fatalf("已绑定动态码时应要求第二步，实际 %v", out)
	}
	token, _ := out["otp_token"].(string)
	if token == "" {
		t.Fatalf("第二步票据缺失: %v", out)
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/login/otp",
		map[string]string{"otp_token": token, "code": wrong}, c2, ""); code != http.StatusUnauthorized {
		t.Fatalf("错误验证码应被拒绝，实际 %d", code)
	}
	enrolledCode, err := auth.TOTPCode(adminRow.PendingOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("计算已绑定动态码失败: %v", err)
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/login/otp",
		map[string]string{"otp_token": token, "code": enrolledCode}, c2, ""); code != http.StatusOK {
		t.Fatalf("密码 + 验证码应登录成功，实际 %d", code)
	}
	if code, _ := e.call(http.MethodGet, "/api/admin/devices", nil, c2, ""); code != http.StatusOK {
		t.Fatalf("完整会话应能读设备列表，实际 %d", code)
	}
}

func TestChangePasswordKicksSessions(t *testing.T) {
	e := newEnv(t)
	admin := e.adminClient()

	if code, _ := e.call(http.MethodPost, "/api/admin/password",
		map[string]string{"current_password": "wrong", "new_password": "a-new-password-1234"}, admin, ""); code != http.StatusUnauthorized {
		t.Fatalf("当前密码错误应被拒绝，实际 %d", code)
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/password",
		map[string]string{"current_password": e.pw, "new_password": "short-pass"}, admin, ""); code != http.StatusBadRequest {
		t.Fatalf("不足 14 位的新密码应被拒绝，实际 %d", code)
	}
	const newPW = "a-new-password-5678"
	if code, _ := e.call(http.MethodPost, "/api/admin/password",
		map[string]string{"current_password": e.pw, "new_password": newPW}, admin, ""); code != http.StatusOK {
		t.Fatalf("改密码应成功，实际 %d", code)
	}
	// 改完所有会话作废。
	if code, _ := e.call(http.MethodGet, "/api/admin/devices", nil, admin, ""); code != http.StatusUnauthorized {
		t.Fatalf("改密码后旧会话应失效，实际 %d", code)
	}
	// 旧密码不再可用，新密码可走两步登录。
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if code, _ := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": e.pw}, c, ""); code != http.StatusUnauthorized {
		t.Fatalf("旧密码应登录失败，实际 %d", code)
	}
	code, out := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": e.admin, "password": newPW}, c, "")
	if code != http.StatusOK {
		t.Fatalf("新密码应能进入第二步，实际 %d: %v", code, out)
	}
	otp, err := auth.TOTPCode(e.otpSecret, time.Now())
	if err != nil {
		t.Fatalf("生成动态码失败: %v", err)
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/login/otp",
		map[string]string{"otp_token": out["otp_token"].(string), "code": otp}, c, ""); code != http.StatusOK {
		t.Fatalf("新密码 + 验证码应登录成功，实际 %d", code)
	}
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (e *testEnv) registerClient(name, redirect string) (clientID, secret string) {
	e.t.Helper()
	return e.registerClientWithTTL(name, redirect, 0)
}

func (e *testEnv) registerClientWithTTL(name, redirect string, ttl time.Duration) (clientID, secret string) {
	e.t.Helper()
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		e.t.Fatalf("生成 client_id 失败: %v", err)
	}
	clientID = "app_" + b64(buf)
	secret = "test-secret-" + clientID
	if err := e.st.CreateClient(&store.Client{
		ID: clientID, Name: name, RedirectURI: redirect,
		TokenTTL: int64(ttl.Seconds()), CreatedAt: time.Now().Unix(),
	}, hashHex(secret)); err != nil {
		e.t.Fatalf("写入测试 client 失败: %v", err)
	}
	return clientID, secret
}

func noFollow(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (e *testEnv) postForm(c *http.Client, path string, v url.Values) (*http.Response, error) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(req)
}

// 单点登录全链路：未登录跳转 → 登录后授权 → 带 code 回跳 → 后端换票 → 业务侧本地验签。
func TestSSOAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t)
	admin := e.adminClient()
	nf := noFollow(admin.Jar)
	anonymousJar, _ := cookiejar.New(nil)
	anon := noFollow(anonymousJar)

	const redirect = "https://crm.example.com/auth/callback"
	const state = "state-1"
	clientID, secret := e.registerClient("crm-mini", redirect)

	authz := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) + "&state=" + url.QueryEscape(state)

	// 1) 未登录访问授权端点：必须回登录页，且带上原始地址。
	res, err := anon.Get(e.ts.URL + authz)
	if err != nil {
		t.Fatalf("请求授权端点失败: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("未登录应跳登录页，实际 %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/admin?next=") {
		t.Fatalf("回跳地址不正确: %q", loc)
	}

	// 2) 已登录：出授权确认页。
	res, err = nf.Get(e.ts.URL + authz)
	if err != nil {
		t.Fatalf("请求授权端点失败: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), "crm-mini") {
		t.Fatalf("已登录应显示授权页，实际 %d", res.StatusCode)
	}

	// 3) 取消授权：带 error 回到业务项目。
	resp, err := e.postForm(nf, "/oauth/authorize/decision", url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "state": {state}, "decision": {"deny"},
	})
	if err != nil {
		t.Fatalf("拒绝授权请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("拒绝后应跳回业务项目，实际 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=access_denied") || !strings.Contains(loc, "state="+state) {
		t.Fatalf("拒绝回跳参数不正确: %q", loc)
	}

	// 4) 同意授权：拿到一次性 code。
	resp, err = e.postForm(nf, "/oauth/authorize/decision", url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "state": {state}, "decision": {"allow"},
	})
	if err != nil {
		t.Fatalf("授权请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("授权后应跳回业务项目，实际 %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("回跳地址不合法: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != state {
		t.Fatalf("回跳缺少 code 或 state: %q", resp.Header.Get("Location"))
	}

	// 5) 业务后端换票。
	code2, tok := e.call(http.MethodPost, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": code,
		"client_id": clientID, "client_secret": secret, "redirect_uri": redirect,
	}, nil, "")
	if code2 != http.StatusOK {
		t.Fatalf("换票失败，状态码 %d: %v", code2, tok)
	}
	access, _ := tok["access_token"].(string)
	if exp, _ := tok["expires_in"].(float64); exp != 28800 {
		t.Fatalf("默认 SSO 票据应为 8 小时，实际 %v", tok["expires_in"])
	}
	claims, err := auth.VerifyJWT(access, e.key.Public())
	if err != nil {
		t.Fatalf("业务侧验签失败: %v", err)
	}
	if claims.Sub != "owner" || claims.Aud != clientID || claims.Typ != "access" {
		t.Fatalf("票据内容不正确: %+v", claims)
	}

	// 6) code 只能用一次。
	if c, _ := e.call(http.MethodPost, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": code,
		"client_id": clientID, "client_secret": secret,
	}, nil, ""); c != http.StatusBadRequest {
		t.Fatalf("授权码重放应失败，实际 %d", c)
	}

	// 7) 错误 secret、未登记的回调地址都要被拒。
	if c, _ := e.call(http.MethodPost, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": "whatever",
		"client_id": clientID, "client_secret": "wrong-secret",
	}, nil, ""); c != http.StatusUnauthorized {
		t.Fatalf("错误 secret 应被拒，实际 %d", c)
	}
	res, err = anon.Get(e.ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://evil.example.com/cb"))
	if err != nil {
		t.Fatalf("请求授权端点失败: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("未登记的回调地址应被拒，实际 %d", res.StatusCode)
	}
}

func (e *testEnv) authorizeCode(c *http.Client, clientID, redirect, state string) string {
	e.t.Helper()
	resp, err := e.postForm(c, "/oauth/authorize/decision", url.Values{
		"client_id": {clientID}, "redirect_uri": {redirect}, "state": {state}, "decision": {"allow"},
	})
	if err != nil {
		e.t.Fatalf("授权请求失败: %v", err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		e.t.Fatalf("授权回跳缺少 code: %q", resp.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

// 每个项目可以单独设票据有效期，不能一刀切。
func TestSSOTokenTTLIsPerClient(t *testing.T) {
	e := newEnv(t)
	admin := e.adminClient()
	nf := noFollow(admin.Jar)

	const redirect = "https://short.example.com/cb"
	clientID, secret := e.registerClientWithTTL("short-lived", redirect, 30*time.Minute)
	code := e.authorizeCode(nf, clientID, redirect, "s1")

	status, out := e.call(http.MethodPost, "/oauth/token", map[string]string{
		"grant_type": "authorization_code", "code": code,
		"client_id": clientID, "client_secret": secret,
	}, nil, "")
	if status != http.StatusOK {
		t.Fatalf("换票失败，状态码 %d: %v", status, out)
	}
	if exp, _ := out["expires_in"].(float64); exp != 1800 {
		t.Fatalf("该项目应拿到 30 分钟票据，实际 %v 秒", out["expires_in"])
	}
	claims, err := auth.VerifyJWT(out["access_token"].(string), e.key.Public())
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	if claims.Exp-claims.Iat != 1800 {
		t.Fatalf("票据实际有效期应为 1800 秒，实际 %d", claims.Exp-claims.Iat)
	}
}

// 首次设置完全走网页接口，不依赖命令行。
func TestWebSetupFlow(t *testing.T) {
	e := newBareEnv(t)

	code, st := e.call(http.MethodGet, "/api/admin/status", nil, nil, "")
	if code != http.StatusOK {
		t.Fatalf("状态接口异常，状态码 %d", code)
	}
	if init, _ := st["initialized"].(bool); init {
		t.Fatal("空库应报告未初始化")
	}

	if code, _ := e.call(http.MethodPost, "/api/admin/setup",
		map[string]string{"username": "owner", "password": "short"}, nil, ""); code != http.StatusBadRequest {
		t.Fatalf("不足 14 位的密码应被拒绝，实际 %d", code)
	}

	const pw = "web-setup-password-1"
	if code, out := e.call(http.MethodPost, "/api/admin/setup",
		map[string]string{"username": "owner", "password": pw}, nil, ""); code != http.StatusCreated {
		t.Fatalf("首次设置应成功，实际 %d: %v", code, out)
	}
	if code, _ := e.call(http.MethodPost, "/api/admin/setup",
		map[string]string{"username": "owner", "password": pw}, nil, ""); code != http.StatusConflict {
		t.Fatalf("重复设置应被拒绝，实际 %d", code)
	}

	code, st = e.call(http.MethodGet, "/api/admin/status", nil, nil, "")
	if code != http.StatusOK {
		t.Fatalf("状态接口异常，状态码 %d", code)
	}
	if init, _ := st["initialized"].(bool); !init {
		t.Fatal("设置后应报告已初始化")
	}

	code, out := e.call(http.MethodPost, "/api/admin/login",
		map[string]string{"username": "owner", "password": pw}, nil, "")
	if code != http.StatusOK {
		t.Fatalf("设置后登录失败，实际 %d: %v", code, out)
	}
	if step, _ := out["step"].(string); step != "enroll" {
		t.Fatalf("新管理员登录后应进入扫码绑定，实际 %v", out)
	}
}

// 业务项目在网页后台登记，不需要命令行。
func TestClientsManageViaAPI(t *testing.T) {
	e := newEnv(t)
	admin := e.adminClient()

	if code, _ := e.call(http.MethodPost, "/api/admin/clients",
		map[string]string{"name": "x", "redirect_uri": "http://x/cb#frag"}, admin, ""); code != http.StatusBadRequest {
		t.Fatalf("带 # 的回调地址应被拒绝，实际 %d", code)
	}

	code, out := e.call(http.MethodPost, "/api/admin/clients", map[string]any{
		"name": "crm-mini", "redirect_uri": "https://crm.example.com/cb", "token_ttl_minutes": 30,
	}, admin, "")
	if code != http.StatusCreated {
		t.Fatalf("登记项目应成功，实际 %d: %v", code, out)
	}
	clientID, _ := out["client_id"].(string)
	secret, _ := out["client_secret"].(string)
	if clientID == "" || secret == "" {
		t.Fatalf("登记返回应包含 client_id 与 secret: %v", out)
	}
	if exp, _ := out["token_ttl_seconds"].(float64); exp != 1800 {
		t.Fatalf("票据有效期应为 1800 秒，实际 %v", out["token_ttl_seconds"])
	}

	// 列表里绝不能回显 secret。
	_, list := e.call(http.MethodGet, "/api/admin/clients", nil, admin, "")
	clients, _ := list["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("应只有 1 个项目，实际 %v", list["clients"])
	}
	if first, ok := clients[0].(map[string]any); !ok || first["client_secret"] != nil {
		t.Fatalf("列表不应包含 secret，实际 %v", clients[0])
	}

	if code, _ := e.call(http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/revoke",
		nil, admin, ""); code != http.StatusOK {
		t.Fatalf("吊销项目失败，实际 %d", code)
	}
	nf := noFollow(admin.Jar)
	res, err := nf.Get(e.ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape("https://crm.example.com/cb"))
	if err != nil {
		t.Fatalf("请求授权端点失败: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("已吊销的项目不应能发起授权，实际 %d", res.StatusCode)
	}
}
