package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"megrez/internal/auth"
	"megrez/internal/client"
)

const usage = `megrez-client · 天权设备代理

用法:
  megrez-client enroll  -server <URL> -pair-code-file <文件> [-name <设备名>] [-platform windows]
  megrez-client login   -server <URL>
  megrez-client refresh -server <URL>
  megrez-client status
  megrez-client revoke  -server <URL>

本地状态: %s（DPAPI 加密，换机/换用户解不开）
`

func main() {
	log.SetFlags(0)
	def, err := client.DefaultStatePath()
	if err != nil {
		log.Fatalf("定位本地状态目录失败: %v", err)
	}
	if len(os.Args) < 2 {
		fmt.Printf(usage, def)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enroll":
		runEnroll(os.Args[2:], def)
	case "login":
		runLogin(os.Args[2:], def)
	case "refresh":
		runRefresh(os.Args[2:], def)
	case "status":
		runStatus(os.Args[2:], def)
	case "revoke":
		runRevoke(os.Args[2:], def)
	default:
		fmt.Printf(usage, def)
		os.Exit(2)
	}
}

func runEnroll(args []string, defState string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "http://127.0.0.1:8787", "天权地址")
	codeFile := fs.String("pair-code-file", "", "配对码文件（必填）")
	name := fs.String("name", defaultDeviceName(), "设备名")
	platform := fs.String("platform", defaultPlatform(), "平台标识")
	statePath := fs.String("state", defState, "本地状态文件")
	_ = fs.Parse(args)

	if *codeFile == "" {
		log.Fatalf("必须提供 -pair-code-file")
	}
	if st, err := client.LoadState(*statePath); err != nil {
		log.Fatalf("读取本地状态失败: %v", err)
	} else if st != nil {
		log.Fatalf("本机已注册为 %s（%s）。如需重新注册，请先 revoke。", st.Name, st.DeviceID)
	}
	raw, err := os.ReadFile(*codeFile)
	if err != nil {
		log.Fatalf("读取配对码失败: %v", err)
	}
	pairCode := strings.TrimSpace(strings.TrimPrefix(string(raw), "\xef\xbb\xbf"))
	if pairCode == "" {
		log.Fatalf("配对码文件为空")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("生成设备密钥失败: %v", err)
	}
	res, err := client.New(*server).Register(pairCode, *name, *platform, pub)
	if err != nil {
		log.Fatalf("注册失败: %v", err)
	}
	st := &client.State{
		Server:      strings.TrimRight(*server, "/"),
		DeviceID:    res.DeviceID,
		Name:        *name,
		Platform:    *platform,
		Fingerprint: res.Fingerprint,
		SeedB64:     base64.RawURLEncoding.EncodeToString(priv.Seed()),
	}
	if err := client.SaveState(*statePath, st); err != nil {
		log.Fatalf("保存本地状态失败: %v", err)
	}
	fmt.Printf("已注册：%s\n  设备 ID   %s\n  公钥指纹  %s\n  状态      %s（等待管理员批准后才能登录）\n",
		*name, res.DeviceID, res.Fingerprint, res.Status)
}

func runLogin(args []string, defState string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "天权地址（留空则用注册时记录的值）")
	statePath := fs.String("state", defState, "本地状态文件")
	_ = fs.Parse(args)

	st, err := client.LoadState(*statePath)
	if err != nil {
		log.Fatalf("读取本地状态失败: %v", err)
	}
	if st == nil {
		log.Fatalf("本机尚未注册，先运行 enroll")
	}
	srv := st.Server
	if *server != "" {
		srv = strings.TrimRight(*server, "/")
	}
	priv, err := st.PrivateKey()
	if err != nil {
		log.Fatalf("读取设备私钥失败: %v", err)
	}
	c := client.New(srv)
	ch, err := c.Challenge(st.DeviceID)
	if err != nil {
		log.Fatalf("获取挑战失败: %v", err)
	}
	sig := ed25519.Sign(priv, auth.SigningPayload(ch.ChallengeID, ch.Nonce, st.DeviceID))
	tok, err := c.Verify(st.DeviceID, ch.ChallengeID, sig)
	if err != nil {
		log.Fatalf("签名验证失败: %v", err)
	}
	now := time.Now().Unix()
	st.Server = srv
	st.AccessToken = tok.AccessToken
	st.AccessExpiresAt = now + int64(tok.AccessExpiresIn)
	st.RefreshToken = tok.RefreshToken
	st.RefreshExpiresAt = now + int64(tok.RefreshExpiresIn)
	if err := client.SaveState(*statePath, st); err != nil {
		log.Fatalf("保存凭证失败: %v", err)
	}
	fmt.Printf("登录成功：%s\n  访问凭证  有效期 %s（已加密保存，不打印）\n  长期凭证  有效期 %s\n",
		st.DeviceID, humanDur(tok.AccessExpiresIn), humanDur(tok.RefreshExpiresIn))
}

func runRefresh(args []string, defState string) {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	statePath := fs.String("state", defState, "本地状态文件")
	_ = fs.Parse(args)

	st, err := client.LoadState(*statePath)
	if err != nil || st == nil {
		log.Fatalf("没有可用的本地凭证")
	}
	tok, err := client.New(st.Server).Refresh(st.DeviceID, st.RefreshToken)
	if err != nil {
		log.Fatalf("续期失败: %v", err)
	}
	now := time.Now().Unix()
	st.AccessToken = tok.AccessToken
	st.AccessExpiresAt = now + int64(tok.AccessExpiresIn)
	st.RefreshToken = tok.RefreshToken
	st.RefreshExpiresAt = now + int64(tok.RefreshExpiresIn)
	if err := client.SaveState(*statePath, st); err != nil {
		log.Fatalf("保存凭证失败: %v", err)
	}
	fmt.Printf("续期成功：新的访问凭证有效期 %s，长期凭证已轮换\n", humanDur(tok.AccessExpiresIn))
}

func runStatus(args []string, defState string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statePath := fs.String("state", defState, "本地状态文件")
	_ = fs.Parse(args)

	st, err := client.LoadState(*statePath)
	if err != nil {
		log.Fatalf("读取本地状态失败: %v", err)
	}
	if st == nil {
		fmt.Println("本机尚未注册。")
		return
	}
	now := time.Now().Unix()
	fmt.Printf("设备 %s（%s）\n  ID        %s\n  指纹      %s\n  服务器    %s\n  访问凭证  %s\n  长期凭证  %s\n  状态文件  %s\n",
		st.Name, st.Platform, st.DeviceID, st.Fingerprint, st.Server,
		expiryText(now, st.AccessExpiresAt), expiryText(now, st.RefreshExpiresAt), *statePath)
}

func runRevoke(args []string, defState string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	statePath := fs.String("state", defState, "本地状态文件")
	_ = fs.Parse(args)

	st, err := client.LoadState(*statePath)
	if err != nil || st == nil {
		log.Fatalf("没有可用的本地凭证")
	}
	if err := client.New(st.Server).Revoke(st.DeviceID, st.RefreshToken); err != nil {
		log.Fatalf("注销失败: %v", err)
	}
	if err := client.DeleteState(*statePath); err != nil {
		log.Fatalf("删除本地状态失败: %v", err)
	}
	fmt.Printf("已注销并删除本地状态：%s\n", st.DeviceID)
}

func expiryText(now, at int64) string {
	if at == 0 {
		return "无"
	}
	left := at - now
	if left <= 0 {
		return "已过期"
	}
	return "剩余 " + humanDur(int(left))
}

func humanDur(sec int) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0f 天", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0f 小时", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.0f 分钟", d.Minutes())
	default:
		return fmt.Sprintf("%d 秒", sec)
	}
}

func defaultPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	default:
		return runtime.GOOS
	}
}

func defaultDeviceName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "未命名设备"
	}
	if len([]rune(host)) > 64 {
		return string([]rune(host)[:64])
	}
	return host
}
