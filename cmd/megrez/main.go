package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"megrez/internal/api"
	"megrez/internal/auth"
	"megrez/internal/store"
)

const usage = `天权 · Megrez

用法:
  megrez serve        [-addr 127.0.0.1:8787] [-db data/megrez.db] [-key data/signing.key] [-trust-proxy]
  megrez init-admin   [-db data/megrez.db] -username <名字> -password-file <文件> [-force]
  megrez paircode     [-db data/megrez.db] -out <文件> [-ttl 10]
  megrez client       add -name <项目名> -redirect <回调地址> -out <secret文件>
  megrez client       list
  megrez client       revoke -client-id <id>
  megrez backup       [-db data/megrez.db] -out <快照文件>
  megrez version

说明:
  - init-admin 只设置账号密码；动态码在网页端首次登录后扫码绑定。
  - 密码与配对码都不通过命令行参数传递，避免落进 shell 历史。
  - -force 会解绑动态码并使所有后台会话失效，需要重新扫码。
`

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "init-admin":
		runInitAdmin(os.Args[2:])
	case "paircode":
		runPairCode(os.Args[2:])
	case "backup":
		runBackup(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "version":
		fmt.Println("megrez 0.1.0")
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "监听地址")
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	keyPath := fs.String("key", "data/signing.key", "令牌签发私钥路径")
	trustProxy := fs.Bool("trust-proxy", false, "是否信任 X-Forwarded-For（前置 nginx 时开启）")
	accessTTL := fs.Duration("access-ttl", 15*time.Minute, "设备访问票据有效期")
	refreshTTL := fs.Duration("refresh-ttl", 30*24*time.Hour, "设备长期票据有效期")
	adminTTL := fs.Duration("admin-session-ttl", 12*time.Hour, "后台登录会话有效期（多久要重新输密码）")
	ssoTTL := fs.Duration("sso-ttl", 8*time.Hour, "项目未单独配置时的 SSO 票据有效期")
	_ = fs.Parse(args)

	for _, d := range []time.Duration{*accessTTL, *refreshTTL, *adminTTL, *ssoTTL} {
		if d <= 0 {
			log.Fatalf("有效期必须大于 0")
		}
	}

	key, err := auth.LoadOrCreateSigningKey(*keyPath)
	if err != nil {
		log.Fatalf("加载签名密钥失败: %v", err)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	cfg := api.DefaultConfig()
	cfg.TrustProxy = *trustProxy
	cfg.AccessTTL = *accessTTL
	cfg.RefreshTTL = *refreshTTL
	cfg.AdminSessionTTL = *adminTTL
	cfg.SSOTTL = *ssoTTL
	srv := api.New(st, key, cfg)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if admin, _ := st.Admin(); admin == nil {
		log.Print("提示：后台尚未初始化，只有 /api/device/register 会工作；先运行 megrez init-admin")
	}
	log.Printf("天权已启动：http://%s/admin （数据库 %s，密钥 kid=%s）", *addr, *dbPath, key.Kid)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("监听失败: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("正在关闭…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func runInitAdmin(args []string) {
	fs := flag.NewFlagSet("init-admin", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	username := fs.String("username", "", "管理员账号")
	pwFile := fs.String("password-file", "", "存放密码的文件（读取后请删除）")
	force := fs.Bool("force", false, "已存在管理员时覆盖（会同时解绑动态码，需重新扫码）")
	_ = fs.Parse(args)

	if strings.TrimSpace(*username) == "" || *pwFile == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -username 和 -password-file")
		os.Exit(2)
	}
	pw, err := readSecretFile(*pwFile)
	if err != nil {
		log.Fatalf("读取密码文件失败: %v", err)
	}
	if len([]rune(pw)) < 14 {
		log.Fatalf("密码至少 14 个字符（当前 %d）", len([]rune(pw)))
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	if existing, _ := st.Admin(); existing != nil && !*force {
		log.Fatalf("管理员已存在（%s），需要覆盖请加 -force", existing.Username)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		log.Fatalf("密码哈希失败: %v", err)
	}
	if err := st.SetAdminPassword(strings.TrimSpace(*username), hash, time.Now().Unix()); err != nil {
		log.Fatalf("写入管理员失败: %v", err)
	}
	// 重置密码同时作废所有后台会话，避免旧会话带着旧权限继续用。
	if err := st.DeleteAllSessions(); err != nil {
		log.Fatalf("清理旧会话失败: %v", err)
	}
	log.Printf("管理员 %s 已创建（动态码未绑定）", strings.TrimSpace(*username))
	log.Print("打开 /admin，用密码登录后按提示扫码绑定动态码；绑定前后台只能看到绑定页。")
}

func runPairCode(args []string) {
	fs := flag.NewFlagSet("paircode", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	out := fs.String("out", "", "配对码输出文件（必填，不打印到终端）")
	ttl := fs.Int("ttl", 10, "有效期（分钟）")
	_ = fs.Parse(args)

	if *out == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -out，配对码只写入文件，不打印")
		os.Exit(2)
	}
	if *ttl < 1 || *ttl > 1440 {
		log.Fatalf("有效期必须在 1-1440 分钟之间")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	pretty, canonical, err := auth.NewPairCode()
	if err != nil {
		log.Fatalf("生成配对码失败: %v", err)
	}
	now := time.Now().Unix()
	if err := st.CreatePairCode(auth.PairCodeHash(canonical), now+int64(*ttl*60), now); err != nil {
		log.Fatalf("写入配对码失败: %v", err)
	}
	if err := writeSecretFile(*out, pretty+"\n"); err != nil {
		log.Fatalf("写入配对码文件失败: %v", err)
	}
	_ = st.Audit(now, "pair_code_created", "", "localhost", "CLI")
	log.Printf("配对码已写入 %s，%d 分钟内有效，使用一次即失效", *out, *ttl)
}

func runBackup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	out := fs.String("out", "", "快照输出路径（必填，目标文件不能已存在）")
	_ = fs.Parse(args)

	if *out == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -out")
		os.Exit(2)
	}
	if _, err := os.Stat(*out); err == nil {
		log.Fatalf("目标文件已存在: %s", *out)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()
	if err := st.Backup(*out); err != nil {
		log.Fatalf("生成快照失败: %v", err)
	}
	if err := os.Chmod(*out, 0o600); err != nil {
		log.Printf("警告：无法收紧快照文件权限: %v", err)
	}
	log.Printf("快照已写入 %s（服务运行中也安全）", *out)
}

func runClient(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: megrez client add|list|revoke")
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		runClientAdd(args[1:])
	case "list":
		runClientList(args[1:])
	case "revoke":
		runClientRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: client %s\n", args[0])
		os.Exit(2)
	}
}

func runClientAdd(args []string) {
	fs := flag.NewFlagSet("client add", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	name := fs.String("name", "", "项目名（授权页会显示）")
	redirect := fs.String("redirect", "", "回调地址，例如 https://crm.example.com/auth/callback")
	tokenTTL := fs.Duration("token-ttl", 8*time.Hour, "签发给该项目的票据有效期，例如 30m / 8h / 168h")
	out := fs.String("out", "", "secret 输出文件（必填，不打印到终端）")
	_ = fs.Parse(args)

	if strings.TrimSpace(*name) == "" || *redirect == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -name、-redirect 和 -out")
		os.Exit(2)
	}
	if *tokenTTL < 5*time.Minute || *tokenTTL > 365*24*time.Hour {
		log.Fatalf("票据有效期必须在 5 分钟到 365 天之间")
	}
	u, err := url.Parse(*redirect)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
		log.Fatalf("回调地址必须是完整的 http/https 地址且不带 # 片段")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	idBuf := make([]byte, 10)
	if _, err := rand.Read(idBuf); err != nil {
		log.Fatalf("生成 client_id 失败: %v", err)
	}
	clientID := "app_" + base64.RawURLEncoding.EncodeToString(idBuf)
	secretBuf := make([]byte, 32)
	if _, err := rand.Read(secretBuf); err != nil {
		log.Fatalf("生成 secret 失败: %v", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBuf)

	now := time.Now().Unix()
	if err := st.CreateClient(&store.Client{
		ID: clientID, Name: strings.TrimSpace(*name), RedirectURI: *redirect,
		TokenTTL: int64((*tokenTTL).Seconds()), CreatedAt: now,
	}, sha256Hex(secret)); err != nil {
		log.Fatalf("写入项目失败: %v", err)
	}
	if err := writeSecretFile(*out, "client_id: "+clientID+"\nclient_secret: "+secret+"\n"); err != nil {
		log.Fatalf("写入 secret 文件失败: %v", err)
	}
	_ = st.Audit(now, "client_created", "", "localhost", clientID+" "+*name)
	log.Printf("项目 %s 已登记：%s", *name, clientID)
	log.Printf("client_id=%s，secret 已写入 %s（放进业务项目环境变量后删除该文件）", clientID, *out)
}

func runClientList(args []string) {
	fs := flag.NewFlagSet("client list", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	_ = fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()
	clients, err := st.ListClients()
	if err != nil {
		log.Fatalf("读取项目失败: %v", err)
	}
	if len(clients) == 0 {
		fmt.Println("还没有登记任何业务项目。")
		return
	}
	for _, c := range clients {
		state := "正常"
		if c.RevokedAt != nil {
			state = "已吊销"
		}
		fmt.Printf("%s  %s  %s  票据 %s  %s\n", c.ID, c.Name, c.RedirectURI,
			(time.Duration(c.TokenTTL) * time.Second).String(), state)
	}
}

func runClientRevoke(args []string) {
	fs := flag.NewFlagSet("client revoke", flag.ExitOnError)
	dbPath := fs.String("db", "data/megrez.db", "SQLite 文件路径")
	clientID := fs.String("client-id", "", "要吊销的 client_id")
	_ = fs.Parse(args)

	if *clientID == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -client-id")
		os.Exit(2)
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()
	c, _, err := st.ClientByID(*clientID)
	if err != nil || c == nil {
		log.Fatalf("找不到项目 %s", *clientID)
	}
	now := time.Now().Unix()
	if err := st.RevokeClient(*clientID, now); err != nil {
		log.Fatalf("吊销失败: %v", err)
	}
	_ = st.Audit(now, "client_revoked", "", "localhost", *clientID)
	log.Printf("项目 %s（%s）已吊销，之后无法再换票", *clientID, c.Name)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// PowerShell 等工具写文件时可能带 UTF-8 BOM，不剥掉会让密码/配对码整体错位。
	s := strings.TrimPrefix(string(raw), "\xef\xbb\xbf")
	return strings.TrimSpace(s), nil
}

func writeSecretFile(path, content string) error {
	return writeSecretBytes(path, []byte(content))
}

func writeSecretBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
