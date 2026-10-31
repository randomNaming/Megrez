# 天权 · 部署手册

一句话：**上传一个压缩包 → 解压 → 跑一条 `install.sh` → 剩下的全部在浏览器里点。**
数据库和签名私钥在服务第一次启动时自动生成，没有任何"初始化命令"要执行。

## 一、发布包里有什么

```
megrez              Linux 二进制（静态，约 15MB，服务器不需要装 Go）
install.sh          一键安装脚本（建账号/目录、装二进制、写 systemd、启动）
megrez.service      systemd 单元（含内存上限）
```

nginx 怎么配写在下面第二、三节，包里不再放示例文件。

拿包：

- **GitHub Release**：推一个 `v*` tag，Actions 自动出包
- **本地**：`powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Version v1.0.0`

## 二、宝塔面板（项目放在 /www/wwwroot）

宝塔里 Go 程序不是 PHP 站点，所以分两件事：**程序由 systemd 跑，站点只负责域名 + SSL + 反向代理**。

### 1. 上传并安装

```bash
mkdir -p /www/wwwroot/megrez
# 把压缩包传到服务器 /tmp/ 后，直接解压到目标目录
tar xzf /tmp/megrez-v1.0.0-linux-amd64.tar.gz -C /www/wwwroot/megrez --strip-components=1
cd /www/wwwroot/megrez
sudo MEGREZ_PREFIX=/www/wwwroot/megrez bash install.sh
```

> `tar -C` 不会自动建目录，所以第一行的 `mkdir -p` 不能省。

装完目录长这样，全部在宝塔文件管理器里看得见、能手动改：

```
/www/wwwroot/megrez/
├── bin/megrez        二进制
├── data/megrez.db    数据库（自动生成）
├── data/signing.key  令牌签名私钥（自动生成）
├── backup/           快照目录
├── install.sh        安装脚本
├── megrez.service
├── nginx.conf
└── nginx-baota.conf
```

脚本是幂等的，升级就是把新包解压覆盖、再跑一遍同一行命令，`data/` 不动。

### 2. 宝塔里建站点

1. 「网站」→ 添加站点：域名填你的域名，**根目录随便给个空目录**（不要指向 `/www/wwwroot/megrez`，它是程序目录，不是网站目录）
2. 「SSL」→ Let's Encrypt 申请证书，强制 HTTPS
3. 「反向代理」→ 添加反向代理：
   - 代理名称：megrez
   - 目标 URL：`http://127.0.0.1:8787`
   - 缓存：关

   或者在「配置文件」里手工加下面这段（关键是 `X-Forwarded-Proto`，别删；缺了后台登录会被踢回登录页，审计 IP 也会变成 127.0.0.1）：

   ```nginx
   location / {
       proxy_pass http://127.0.0.1:8787;
       proxy_http_version 1.1;
       proxy_set_header Host              $host;
       proxy_set_header X-Real-IP         $remote_addr;
       proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;
       proxy_read_timeout 30s;
   }
   ```

4. 防火墙：**不用放行 8787**，服务只监听本机；只放行 443（宝塔「安全」里加）。

### 3. 打开页面做首次设置

`https://你的域名/admin`，后面见第四节。

> 提示：宝塔的计划任务可以调用 `/www/wwwroot/megrez/bin/megrez backup` 做每日快照，见第五节。

## 三、普通 Linux（默认 /opt）

没有宝塔的机器：

```bash
scp dist/megrez-v1.0.0-linux-amd64.tar.gz root@服务器:/tmp/
mkdir -p /tmp/megrez-pkg
tar xzf /tmp/megrez-v1.0.0-linux-amd64.tar.gz -C /tmp/megrez-pkg --strip-components=1
sudo bash /tmp/megrez-pkg/install.sh        # 默认装到 /opt/megrez
```

然后自己配 nginx（域名和证书路径换成你的）：

```nginx
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
}
```

服务只监听 `127.0.0.1:8787`，公网必须走 nginx。

## 四、浏览器首次设置（两种装法都一样）

打开 `https://你的域名/admin`：

| 步骤 | 页面位置 | 说明 |
|---|---|---|
| 1 | 首次设置卡片 | 设管理员账号 + 密码（至少 14 位） |
| 2 | 登录 | 只用账号密码 |
| 3 | 绑定验证器 | 页面显示二维码 → 手机扫 → 填 6 位数字 → 自动退出 |
| 4 | 重新登录 | 账号密码 → 再填一次验证码 |
| 5 | 设备 | 「一次性配对码」生成 → 设备端 `megrez-client enroll` → 回来点「批准」 |
| 6 | 接入项目 | 填项目名 / 回调地址 / 票据有效期 → 记下 `client_id` 与 `client_secret`（只显示一次） |

## 五、日常运维

**升级**：新包解压覆盖 → 重跑 `install.sh`（`data/` 保留，表结构启动时自动补列）。

**备份**（运行中安全，不用停机）：

```bash
sudo -u megrez /www/wwwroot/megrez/bin/megrez backup \
  -db /www/wwwroot/megrez/data/megrez.db \
  -out /www/wwwroot/megrez/backup/megrez-$(date +%F).db
```

宝塔用户可以直接在「计划任务」里加一条 Shell 脚本，每天跑上面这行；普通 Linux 用 cron。

**记得单独备份 `data/signing.key`**：丢了不影响设备身份，但已签发的票全部失效，要重新登录。

**看状态**：

```bash
systemctl status megrez
curl -s http://127.0.0.1:8787/healthz
journalctl -u megrez -n 100 --no-pager
```

## 六、自动化

`.github/workflows/release.yml`：推 `v*` tag → 跑测试 → 编 Linux/Windows → 打 tar.gz/zip → 挂 Release。服务器不参与，没有服务器密钥进仓库。

想全自动上线需要把 SSH 私钥放进 Secrets，我的建议是**出包自动、上线手动**（天权管全生态准入，CI 里那把私钥等于侧门）。配置片段见旧版说明或直接 `ssh` 手动。

## 七、命令行（应急才用）

平时不需要，网页进不去时兜底：

| 场景 | 命令 |
|---|---|
| 忘记密码 / 换手机（会解绑动态码） | `megrez init-admin -username owner -password-file /tmp/pw -force` |
| 网页坏了但急着发配对码 | `megrez paircode -db ... -out /tmp/pair.txt -ttl 10` |
| 想用命令行登记项目 | `megrez client add -name ... -redirect ... -out /tmp/secret.txt` |
| 看/吊销项目 | `megrez client list`、`megrez client revoke -client-id app_xxx` |
| 打快照 | `megrez backup -db ... -out ...` |

## 八、排查

| 现象 | 先查 |
|---|---|
| 登录后立刻退回登录页 | 反代有没有传 `X-Forwarded-Proto`；systemd 里是否带 `-trust-proxy` |
| 审计里 IP 全是 127.0.0.1 | 同上 |
| `/healthz` 正常但页面 502 | 反代目标写成 `https://127.0.0.1:8787`（应为本机 http） |
| 内存被 systemd 杀掉 | `journalctl -u megrez`，看是否同时大量登录触发 Argon2 |
| 业务项目验签失败 | 业务侧拉的 `/api/.well-known/keys` 地址不对，或机器时钟偏差过大 |
