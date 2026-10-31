-- 天权 P0 数据模型。时间一律用 Unix 秒（INTEGER）。
-- 不存任何明文密钥：设备只存公钥，长期凭证只存哈希，配对码只存哈希。

CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    public_key   TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending / approved / rejected / revoked
    created_at   INTEGER NOT NULL,
    approved_at  INTEGER,
    last_seen_at INTEGER,
    last_ip      TEXT,
    note         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_public_key ON devices (public_key);

CREATE TABLE IF NOT EXISTS pair_codes (
    code_hash  TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id           TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    refresh_hash TEXT NOT NULL UNIQUE,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_device ON tokens (device_id);

CREATE TABLE IF NOT EXISTS audit (
    at        INTEGER NOT NULL,
    event     TEXT NOT NULL,
    device_id TEXT,
    ip        TEXT,
    detail    TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit (at);

-- 单人生态：管理员表恒为一行（id = 1）。
-- otp_secret 为空 = 尚未绑定动态码，首次登录走网页扫码绑定流程。
CREATE TABLE IF NOT EXISTS admin (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    username           TEXT NOT NULL,
    password_hash      TEXT NOT NULL,
    otp_secret         TEXT NOT NULL DEFAULT '',
    pending_otp_secret TEXT NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL
);

-- scope: full = 已绑定动态码的完整会话；pending_enroll = 只够绑定动态码的临时会话。
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    ip         TEXT,
    scope      TEXT NOT NULL DEFAULT 'full'
);

-- 接入的业务项目。每个项目一个 client_id，secret 只存哈希。
CREATE TABLE IF NOT EXISTS clients (
    client_id    TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    token_ttl    INTEGER NOT NULL DEFAULT 0,  -- 签发给该项目的票据有效期（秒），0 用服务端默认
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER
);

-- 授权码：一次性、60 秒、绑定 client 与 redirect_uri，只存哈希。
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash    TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    used_at      INTEGER,
    created_at   INTEGER NOT NULL
);
