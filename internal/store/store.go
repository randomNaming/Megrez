package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db *sql.DB
}

type Device struct {
	ID          string
	Name        string
	Platform    string
	PublicKey   string
	Fingerprint string
	Status      string
	CreatedAt   int64
	ApprovedAt  *int64
	LastSeenAt  *int64
	LastIP      *string
	Note        *string
}

type Token struct {
	ID          string
	DeviceID    string
	RefreshHash string
	ExpiresAt   int64
	RevokedAt   *int64
	CreatedAt   int64
}

type AuditEntry struct {
	At       int64  `json:"at"`
	Event    string `json:"event"`
	DeviceID string `json:"device_id,omitempty"`
	IP       string `json:"ip,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

type Admin struct {
	Username         string
	PasswordHash     string
	OTPSecret        string
	PendingOTPSecret string
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	raw, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(string(raw)); err != nil {
		db.Close()
		return nil, err
	}
	// 老库升级：CREATE TABLE IF NOT EXISTS 不会给已有表补列，这里按需补。
	for _, m := range []struct{ table, column, decl string }{
		{"admin", "pending_otp_secret", "TEXT NOT NULL DEFAULT ''"},
		{"admin_sessions", "scope", "TEXT NOT NULL DEFAULT 'full'"},
		{"clients", "token_ttl", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := ensureColumn(db, m.table, m.column, m.decl); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ensureColumn(db *sql.DB, table, column, decl string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if strings.EqualFold(name, column) {
			exists = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if exists {
		return nil
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl)
	return err
}

func (s *Store) InsertDevice(d *Device) error {
	_, err := s.db.Exec(`INSERT INTO devices
		(id, name, platform, public_key, fingerprint, status, created_at, note)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.Name, d.Platform, d.PublicKey, d.Fingerprint, d.Status, d.CreatedAt, d.Note)
	return err
}

func scanDevice(sc interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var approved, seen sql.NullInt64
	var ip, note sql.NullString
	if err := sc.Scan(&d.ID, &d.Name, &d.Platform, &d.PublicKey, &d.Fingerprint, &d.Status,
		&d.CreatedAt, &approved, &seen, &ip, &note); err != nil {
		return nil, err
	}
	if approved.Valid {
		v := approved.Int64
		d.ApprovedAt = &v
	}
	if seen.Valid {
		v := seen.Int64
		d.LastSeenAt = &v
	}
	if ip.Valid {
		v := ip.String
		d.LastIP = &v
	}
	if note.Valid {
		v := note.String
		d.Note = &v
	}
	return &d, nil
}

const deviceCols = `id, name, platform, public_key, fingerprint, status, created_at, approved_at, last_seen_at, last_ip, note`

func (s *Store) DeviceByID(id string) (*Device, error) {
	row := s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return d, err
}

func (s *Store) DeviceByPublicKey(pub string) (*Device, error) {
	row := s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE public_key = ?`, pub)
	d, err := scanDevice(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return d, err
}

func (s *Store) ListDevices(limit int) ([]*Device, error) {
	rows, err := s.db.Query(`SELECT `+deviceCols+` FROM devices ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDevices(rows)
}

func collectDevices(rows *sql.Rows) ([]*Device, error) {
	out := []*Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SetDeviceStatus(id, status, note string, now int64) error {
	var approvedAt any
	if status == "approved" {
		approvedAt = now
	}
	_, err := s.db.Exec(`UPDATE devices
		SET status = ?, note = ?, approved_at = COALESCE(?, approved_at)
		WHERE id = ?`, status, note, approvedAt, id)
	return err
}

func (s *Store) TouchDevice(id string, now int64, ip string) error {
	_, err := s.db.Exec(`UPDATE devices SET last_seen_at = ?, last_ip = ? WHERE id = ?`, now, ip, id)
	return err
}

func (s *Store) CreatePairCode(hash string, expiresAt, now int64) error {
	_, err := s.db.Exec(`INSERT INTO pair_codes (code_hash, expires_at, created_at) VALUES (?, ?, ?)`,
		hash, expiresAt, now)
	return err
}

// ConsumePairCode 原子占用：只有未使用且未过期的一次性码才会被消费成功。
func (s *Store) ConsumePairCode(hash string, now int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE pair_codes SET used_at = ?
		WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`, now, hash, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) InsertToken(t *Token) error {
	_, err := s.db.Exec(`INSERT INTO tokens (id, device_id, refresh_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`, t.ID, t.DeviceID, t.RefreshHash, t.ExpiresAt, t.CreatedAt)
	return err
}

func (s *Store) TokenByRefreshHash(hash string) (*Token, error) {
	var t Token
	var revoked sql.NullInt64
	err := s.db.QueryRow(`SELECT id, device_id, refresh_hash, expires_at, revoked_at, created_at
		FROM tokens WHERE refresh_hash = ?`, hash).
		Scan(&t.ID, &t.DeviceID, &t.RefreshHash, &t.ExpiresAt, &revoked, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		v := revoked.Int64
		t.RevokedAt = &v
	}
	return &t, nil
}

func (s *Store) RevokeToken(id string, now int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) RevokeDeviceTokens(deviceID string, now int64) error {
	_, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL`,
		now, deviceID)
	return err
}

func (s *Store) Audit(at int64, event, deviceID, ip, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit (at, event, device_id, ip, detail) VALUES (?, ?, ?, ?, ?)`,
		at, event, deviceID, ip, detail)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT at, event, COALESCE(device_id, ''), COALESCE(ip, ''), COALESCE(detail, '')
		FROM audit ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.Event, &e.DeviceID, &e.IP, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Admin() (*Admin, error) {
	var a Admin
	err := s.db.QueryRow(`SELECT username, password_hash, otp_secret, pending_otp_secret
		FROM admin WHERE id = 1`).
		Scan(&a.Username, &a.PasswordHash, &a.OTPSecret, &a.PendingOTPSecret)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// SetAdminPassword 初始化/重置管理员密码，并把动态码打回未绑定状态，逼着重新扫码绑定。
func (s *Store) SetAdminPassword(username, passwordHash string, now int64) error {
	_, err := s.db.Exec(`INSERT INTO admin (id, username, password_hash, otp_secret, pending_otp_secret, created_at)
		VALUES (1, ?, ?, '', '', ?)
		ON CONFLICT(id) DO UPDATE SET username = excluded.username,
			password_hash = excluded.password_hash, otp_secret = '', pending_otp_secret = ''`,
		username, passwordHash, now)
	return err
}

func (s *Store) SetPendingOTPSecret(secret string) error {
	_, err := s.db.Exec(`UPDATE admin SET pending_otp_secret = ? WHERE id = 1`, secret)
	return err
}

// UpdatePassword 只改密码哈希，不动动态码绑定。
func (s *Store) UpdatePassword(passwordHash string) error {
	_, err := s.db.Exec(`UPDATE admin SET password_hash = ? WHERE id = 1`, passwordHash)
	return err
}

// EnrollOTP 把待绑定的动态码密钥转正，并清空待绑定副本。
func (s *Store) EnrollOTP(secret string) error {
	_, err := s.db.Exec(`UPDATE admin SET otp_secret = ?, pending_otp_secret = '' WHERE id = 1`, secret)
	return err
}

func (s *Store) InsertSession(hash, scope string, expiresAt, now int64, ip string) error {
	_, err := s.db.Exec(`INSERT INTO admin_sessions (token_hash, expires_at, created_at, ip, scope)
		VALUES (?, ?, ?, ?, ?)`, hash, expiresAt, now, ip, scope)
	return err
}

func (s *Store) SessionInfo(hash string, now int64) (scope string, ok bool, err error) {
	var exp int64
	err = s.db.QueryRow(`SELECT expires_at, scope FROM admin_sessions WHERE token_hash = ?`, hash).
		Scan(&exp, &scope)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return scope, exp > now, nil
}

func (s *Store) DeleteSession(hash string) error {
	_, err := s.db.Exec(`DELETE FROM admin_sessions WHERE token_hash = ?`, hash)
	return err
}

// DeleteAllSessions 绑定动态码成功后整站踢出，强制用「密码 + 动态码」重新登录。
func (s *Store) DeleteAllSessions() error {
	_, err := s.db.Exec(`DELETE FROM admin_sessions`)
	return err
}

// Backup 用 VACUUM INTO 生成一份一致的快照，服务运行中也能安全执行。
func (s *Store) Backup(dest string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, dest)
	return err
}

type Client struct {
	ID          string
	Name        string
	RedirectURI string
	TokenTTL    int64 // 秒；0 表示用服务端默认
	CreatedAt   int64
	RevokedAt   *int64
}

func (s *Store) CreateClient(c *Client, secretHash string) error {
	_, err := s.db.Exec(`INSERT INTO clients (client_id, name, redirect_uri, secret_hash, token_ttl, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, c.ID, c.Name, c.RedirectURI, secretHash, c.TokenTTL, c.CreatedAt)
	return err
}

func (s *Store) ClientByID(id string) (*Client, string, error) {
	var c Client
	var secretHash string
	var revoked sql.NullInt64
	err := s.db.QueryRow(`SELECT client_id, name, redirect_uri, secret_hash, token_ttl, created_at, revoked_at
		FROM clients WHERE client_id = ?`, id).
		Scan(&c.ID, &c.Name, &c.RedirectURI, &secretHash, &c.TokenTTL, &c.CreatedAt, &revoked)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if revoked.Valid {
		v := revoked.Int64
		c.RevokedAt = &v
	}
	return &c, secretHash, nil
}

func (s *Store) ListClients() ([]*Client, error) {
	rows, err := s.db.Query(`SELECT client_id, name, redirect_uri, token_ttl, created_at, revoked_at
		FROM clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Client{}
	for rows.Next() {
		var c Client
		var revoked sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Name, &c.RedirectURI, &c.TokenTTL, &c.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		if revoked.Valid {
			v := revoked.Int64
			c.RevokedAt = &v
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (s *Store) RevokeClient(id string, now int64) error {
	_, err := s.db.Exec(`UPDATE clients SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL`, now, id)
	return err
}

func (s *Store) UpdateClientRedirect(id, uri string) error {
	_, err := s.db.Exec(`UPDATE clients SET redirect_uri = ? WHERE client_id = ? AND revoked_at IS NULL`, uri, id)
	return err
}

type AuthCode struct {
	ClientID    string
	RedirectURI string
	ExpiresAt   int64
}

func (s *Store) CreateAuthCode(hash, clientID, redirectURI string, expiresAt, now int64) error {
	_, err := s.db.Exec(`INSERT INTO auth_codes (code_hash, client_id, redirect_uri, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`, hash, clientID, redirectURI, expiresAt, now)
	return err
}

// ConsumeAuthCode 原子占用：一次性，过期或已用都拿不到。
func (s *Store) ConsumeAuthCode(hash string, now int64) (*AuthCode, error) {
	res, err := s.db.Exec(`UPDATE auth_codes SET used_at = ?
		WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`, now, hash, now)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, nil
	}
	var ac AuthCode
	err = s.db.QueryRow(`SELECT client_id, redirect_uri, expires_at FROM auth_codes WHERE code_hash = ?`, hash).
		Scan(&ac.ClientID, &ac.RedirectURI, &ac.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &ac, nil
}
