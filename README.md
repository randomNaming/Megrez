# 天权 · Megrez

> 北斗第四星，居斗魁与斗柄之间；权者，衡也，准入之权。
> 北辰生态的**准入与授权器官**：谁是主人、哪台设备被允许、进门之后能拿走什么。

## 一、星位

| 项 | 值 |
|---|---|
| 中文 | 天权 |
| 星名 | Megrez（北斗七星第四星） |
| 目录 | `local_github/megrez` |
| 定位 | 身份与准入：设备登记、审批、发证、吊销、审计 |
| 不叫 SSO | SSO 只描述「一次登录多处通行」，这个器官真正管的是「谁能进」 |

北斗七星的编制（见 `Polaris/北辰-总体规划与上下文.md` §3）：北辰（总纲）/ 天枢（记忆）/ 天璇（客户枢纽）/ 天玑（数据矿）/ **天权（本仓库）** / 玉衡（评测）/ 开阳（语音）/ 摇光（内容雷达）。

## 二、它为什么存在

生态里已经有多个项目（crm-mini、titleforge、Saydra、OpenBiliClaw…），每个都在各自造登录。这带来三个问题：

1. 改一次凭证要改 N 处；
2. 每个项目都要自己保证安全细节，漏一个就是缺口；
3. 以后做手机 App 时，要为每个后端各做一套登录。

天权的存在就是把这部分**收归一处**：生态内所有项目不再做账号，只做「验票」。

## 三、明确的边界

**做：**

- 唯一用户的身份：设备密钥登记、管理员审批、签发访问凭证
- 设备生命周期：待审批 / 已批准 / 已吊销，可单独吊销一台
- 审计：谁、何时、哪台设备、来自哪里
- 管理后台：审批设备、生成一次性配对码、查看审计

**不做：**

- 多用户、角色、组织、租户（生态只有一个人）
- 邮箱/短信找回（不做账号体系，就没有找回）
- 第三方登录（GitHub/Google）——以后真要再说
- 业务逻辑、业务数据（天权不碰任何业务表）

## 四、技术基线

| 项 | 决定 | 理由 |
|---|---|---|
| 存储 | SQLite 单文件 | 服务器余量只有 900MB，不能为了身份再养一个数据库 |
| 常驻内存 | ≤ 100MB | 目标 30–60MB；不做 Java、不引 Redis |
| 依赖 | 尽量零外部服务 | 与天枢（Neo4j 只在笔记本）的策略一致 |
| 凭证 | 设备密钥对 + 挑战签名 | 私钥不出设备；服务器只存公钥 |
| 管理员登录 | 账号 + 强密码 + 动态码 | 新设备尚未批准时，只能靠这条兜底路径 |

> 红线：任何密码、私钥、配对码明文都不写进本仓库、不进任何 AI 可见文档。

## 五、当前状态

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 骨架：SQLite schema、设备注册/审批、挑战签名登录、管理后台 | **已完成** |
| P1 | 令牌签发 + 业务侧验签中间件（先拿 crm-mini 做样本） | **SSO 授权码流程已完成**，crm-mini 接入待做 |
| P2 | 审计、吊销、多设备管理、异常告警 | 未开始 |
| P3 | 网页端接入 | **已并入 P1**：浏览器走重定向 SSO，不再需要通行密钥 |
| P4 | 手机 App 接入约定（设备密钥 + 首次配对） | 未开始 |

P0–P1 实测数据（本机 Windows，2026-10-31）：空载常驻 13.9MB，登录后 48–81MB；
`go test ./...` 覆盖 17 项（含默认拒绝、批准后可登录、吊销即时失效、挑战重放、签名篡改、配对码一次性、续期轮换、后台锁定、注册限流、首次扫码绑定并强制重登、两步登录、改密码踢会话、完整 SSO 授权码链路、按项目配置票据有效期、网页首次设置、后台登记/吊销项目）。

### 怎么跑起来

**本地开发**：

```powershell
go build -o bin\megrez.exe ./cmd/megrez
go build -o bin\megrez-client.exe ./cmd/megrez-client
bin\megrez.exe serve        # 打开 http://127.0.0.1:8787/admin
```

数据库和签名私钥在首次启动时自动生成，**不需要任何初始化命令**。

打开页面后全在网页里做：

1. 「首次设置」设管理员账号 + 密码（至少 14 位）
2. 登录 → 页面出二维码 → 手机验证器扫码 → 填 6 位数字 → 强制退出
3. 重新登录（账号密码 + 验证码）
4. 设备：后台点「一次性配对码」，把码给设备端：

```powershell
bin\megrez-client.exe enroll -server http://127.0.0.1:8787 -pair-code-file <配对码文件>
bin\megrez-client.exe login  -server http://127.0.0.1:8787
bin\megrez-client.exe status
```

5. 回到后台点「批准」；「接入项目」里登记要接入的业务项目

> 设备私钥与凭证用 Windows DPAPI 加密保存在 `%AppData%\megrez\device.state`，换机或换用户解不开。

**上线**：见 [docs/deploy.md](docs/deploy.md)——一个压缩包，解压后跑 `install.sh`，其余同样在浏览器里完成。

详细流程、数据模型、接口草案见 [docs/plan.md](docs/plan.md)。

## 六、业务项目怎么接入

一句话：**业务项目没有身份 → 跳转天权 → 你在天权登录 → 带一次性 code 跳回 → 业务后端换票 → 本地验签。** 跟微信 / GitHub 授权登录一个路子。

### 6.1 在后台登记这个项目（不用命令行）

登录天权后台，找到「接入项目」卡片，只填三项：

| 字段 | 例子 | 说明 |
|---|---|---|
| 项目名 | crm-mini | 授权确认页会显示这个名字 |
| 回调地址 | https://crm.example.com/auth/callback | 必须和代码里跳转时用的完全一致 |
| 票据有效期 | 480（分钟） | 5 分钟～365 天，按项目自己定 |

点「登记」后，页面会显示一次 `client_id` 和 `client_secret`，**只显示这一次**：

- `client_id` → 放进项目的公开配置
- `client_secret` → **只放后端环境变量**，绝不能出现前端

填错或要换 secret，就在列表里「吊销」，再登记一个新的（旧 secret 不会重发）。

### 6.2 登录流程

```
浏览器（未登录）
   │  GET https://auth.example.com/oauth/authorize
   │      ?client_id=app_xxx
   │      &redirect_uri=https://crm.example.com/auth/callback
   │      &state=<业务自己生成的随机串>
   ▼
天权：没登录 → 登录页（账号 + 密码；已登录过则只需验证码）
      登录后 → 授权确认页（显示项目名和回调域名）
   │  302 https://crm.example.com/auth/callback?code=<一次性>&state=<原样带回>
   ▼
业务后端（服务端到服务端）
   POST https://auth.example.com/oauth/token
   {grant_type:"authorization_code", code, client_id, client_secret}
   ← {access_token: EdDSA JWT, token_type:"Bearer", expires_in:28800}
   │
   ▼
业务后端把 JWT 放进自己的 HttpOnly Cookie（或服务端 session），
每个请求本地验签，不回调天权。
```

关键约束：

- `code` **60 秒有效、只能用一次**，且绑定到 client 与登记的回调地址
- `client_secret` 只在两个后端之间传，**永远不下发浏览器**
- `state` 由业务项目自己生成并校验，防 CSRF

### 6.3 业务项目要写的三段代码（Nitro 示例）

**① 没登录时发起跳转** `server/routes/auth/login.ts`

```ts
export default defineEventHandler((event) => {
  const state = crypto.randomUUID()
  setCookie(event, 'sso_state', state, { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 600 })

  const q = new URLSearchParams({
    client_id: process.env.MEGREZ_CLIENT_ID!,
    redirect_uri: process.env.MEGREZ_REDIRECT_URI!,
    state: state
  })
  return sendRedirect(event, `${process.env.MEGREZ_BASE}/oauth/authorize?${q}`)
})
```

**② 回调换票、写自己的会话** `server/routes/auth/callback.ts`

```ts
export default defineEventHandler(async (event) => {
  const q = getQuery(event)
  if (q.state !== getCookie(event, 'sso_state')) throw createError({ statusCode: 400, statusMessage: 'bad state' })
  deleteCookie(event, 'sso_state')

  const res = await fetch(`${process.env.MEGREZ_BASE}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code: q.code,
      client_id: process.env.MEGREZ_CLIENT_ID,
      client_secret: process.env.MEGREZ_CLIENT_SECRET
    })
  })
  if (!res.ok) throw createError({ statusCode: 401, statusMessage: 'sso failed' })
  const { access_token } = await res.json()

  setCookie(event, 'session', access_token, {
    httpOnly: true, sameSite: 'lax', secure: true, path: '/', maxAge: 8 * 3600
  })
  return sendRedirect(event, '/')
})
```

**③ 每个请求本地验签** `server/middleware/megrez-auth.ts`

这个中间件同时要能读 Cookie（浏览器）和 `Authorization: Bearer`（设备/客户端），两条路都只做本地验签：

```ts
import { createPublicKey, verify, type KeyObject } from 'node:crypto'

const AUTH_BASE = process.env.MEGREZ_BASE!
const TTL = 5 * 60 * 1000
let cache: { at: number; keys: Record<string, KeyObject> } = { at: 0, keys: {} }

async function publicKey(kid: string) {
  if (Date.now() - cache.at > TTL) {
    const body = await (await fetch(`${AUTH_BASE}/api/.well-known/keys`)).json()
    cache = {
      at: Date.now(),
      keys: Object.fromEntries(
        body.keys.map((k: any) => [k.kid, createPublicKey({ key: k, format: 'jwk' })])
      )
    }
  }
  return cache.keys[kid]
}

const b64url = (s: string) => Buffer.from(s, 'base64url')

export default defineEventHandler(async (event) => {
  if (!event.path.startsWith('/api/') || event.path === '/api/health') return

  const raw = getCookie(event, 'session') ||
    (getRequestHeader(event, 'authorization') || '').replace(/^Bearer /, '')
  const parts = raw.split('.')
  if (parts.length !== 3) throw createError({ statusCode: 401, statusMessage: 'missing token' })

  const [h, p, s] = parts
  const header = JSON.parse(b64url(h).toString())
  const claims = JSON.parse(b64url(p).toString())
  if (header.alg !== 'EdDSA') throw createError({ statusCode: 401, statusMessage: 'bad alg' })

  const key = await publicKey(header.kid)
  const sigOK = key && verify(null, Buffer.from(`${h}.${p}`), key, b64url(s))
  const timeOK = claims.typ === 'access' && claims.exp > Date.now() / 1000
  if (!sigOK || !timeOK) throw createError({ statusCode: 401, statusMessage: 'invalid token' })

  event.context.deviceId = claims.sub      // SSO 票据里是 owner，设备票据里是 dev_xxx
})
```

Go 项目可以直接照抄本仓库 [internal/auth/jwt.go](internal/auth/jwt.go) 的 `VerifyAccess`（约 35 行，零依赖）；Python 用 `cryptography` 的 `Ed25519PublicKey.verify`，流程完全一样。

### 6.4 非浏览器客户端（设备那条路）

桌面端 / 未来的原生 App 不走重定向，走设备密钥登记：

```bash
megrez-client enroll -server https://auth.example.com -pair-code-file pair.txt
megrez-client login  -server https://auth.example.com
megrez-client refresh -server https://auth.example.com
```

| 票 | 有效期 | 用法 |
|---|---|---|
| access_token（设备） | 15 分钟 | `Authorization: Bearer`，业务后端同一套本地验签 |
| refresh_token | 30 天，换一次作废一次 | 只有设备自己用，业务后端不管 |

浏览器拿到的是 SSO 票（`sub=owner`，8 小时）；设备拿到的是设备票（`sub=dev_xxx`，15 分钟）。业务侧只看 `typ=access` 和签名，`sub` 用来区分「是哪台设备 / 还是网页本人」。

### 6.5 必须知道的限制

| 限制 | 说明 | 想改怎么办 |
|---|---|---|
| 票据不能即时吊销 | 已签发的 JWT 是自包含的。吊销 client 只挡住「以后换票」，已发出的票最长还能活到它自己的过期时间 | 业务侧清自己的 Cookie；或把该项目 `-token-ttl` 调短 |
| 天权挂了不能新登录 | 已发出的票仍能本地验签，业务照常可用；只是没法再发起 SSO | 这是故意设计（天权不做单点故障） |
| 公钥轮换 | P0 固定一把 `kid=megrez-1` | 需要两边同时支持，放 P2 |
| 单人生态 | 一张票永远属于 owner，没有多用户 | 按设计如此 |

### 6.6 有效期归谁管

分两层：**天权定「票最长能活多久」，业务项目定「自己的会话撑多久」**。两边都能配，但只有天权能设上限。

| 项 | 谁决定 | 默认 | 怎么改 |
|---|---|---|---|
| 在天权登录一次能免密码多久 | 天权（全局） | 12 小时 | `serve -admin-session-ttl 72h` |
| 发给某个项目的 SSO 票据 | 天权（按项目） | 8 小时 | 后台「接入项目」里填有效期 |
| 业务项目自己的 Cookie / session | 业务项目 | 自己定 | 必须 ≤ 票据有效期；过期就回天权重新授权 |
| 设备访问票（Bearer） | 天权（全局） | 15 分钟 | `serve -access-ttl 1h` |
| 设备长期票（续期用） | 天权（全局） | 30 天 | `serve -refresh-ttl 720h` |

为什么不能只放一处：

- 全放业务项目 → 票据没有上限，等于永不过期，天权管不住
- 全放天权 → 业务项目自己的 Cookie 活多久它说了算，天权管不到

推荐组合：

| 场景 | 后台会话 | SSO 票据 | 业务 Cookie | 结果 |
|---|---|---|---|---|
| 只自己用的内部工具 | 7 天 | 7 天 | 7 天 | 一周输一次密码 |
| 给别人看/对外 | 12 小时 | 2 小时 | 2 小时 | 过期自动回天权，会话还在时点一下就回 |
| 桌面客户端 | 不适用 | 不适用 | 15 分钟 + 30 天续期 | 客户端自动续，不用人管 |

> 调这些都不需要改代码，`serve` 和 `client add` 都支持传参；改完重启服务即可，已发出的票不受影响（它们各带各的过期时间）。

## 七、部署

部署步骤、systemd、nginx、备份、升级和自动化选项见 [docs/deploy.md](docs/deploy.md)。摘要：

1. 交叉编译出一个 Linux 二进制（服务器上不需要装 Go）
2. 放到 `/opt/megrez/bin`，数据放 `/opt/megrez/data`（0700）
3. systemd 拉起，只监听 `127.0.0.1:8787`
4. nginx 做 TLS 反代，开 `-trust-proxy`
5. `init-admin` 设密码 → 浏览器登录扫码绑定 → 生成第一个配对码

自动化可以做到「打 tag → 自动出二进制 → 一条命令部署」，但不建议把服务器 SSH 私钥放进 GitHub，除非你愿意承担这个风险；理由和配置见 deploy.md。
