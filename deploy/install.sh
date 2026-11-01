#!/usr/bin/env bash
# 天权首次安装：建账号/目录、装二进制、写 systemd、启动。
# 升级请用 update.sh（只换二进制、不碰数据库），不要重跑本脚本到新目录。
set -euo pipefail

PREFIX="${MEGREZ_PREFIX:-/www/wwwroot/megrez}"
PORT="${MEGREZ_PORT:-8787}"
# 数据目录与程序目录分开：以后换程序目录也不会换库。
DATA="${MEGREZ_DATA:-/www/wwwroot/megrez-data}"

# 已经装过：直接沿用现有服务里的路径，不用再传任何参数
if EXIST_BIN="$(systemctl cat megrez 2>/dev/null | grep -m1 'ExecStart=' | sed 's/^ExecStart=//' | awk '{print $1}')" && [ -n "$EXIST_BIN" ]; then
  [ -n "${MEGREZ_PREFIX:-}" ] || PREFIX="$(dirname "$(dirname "$EXIST_BIN")")"
fi
if EXIST_DB="$(systemctl cat megrez 2>/dev/null | grep -o -- '-db [^ ]*' | head -n1 | cut -d' ' -f2)"; then
  [ -n "${MEGREZ_DATA:-}" ] || DATA="$(dirname "$EXIST_DB")"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo ./install.sh" >&2
  exit 1
fi
if [ ! -f "$DIR/megrez" ]; then
  echo "安装包里缺少 megrez 二进制" >&2
  exit 1
fi

# 防呆：目标库里没有数据库时，先看机器上别处是不是已经有库了。
# 有的话直接继续会静默建一个空库，后台就会重新要求「首次设置」。
if [ ! -f "$DATA/megrez.db" ]; then
  EXISTING="$(find /www/wwwroot /opt /root -maxdepth 5 -name megrez.db 2>/dev/null | head -n 1 || true)"
  if [ -n "$EXISTING" ] && [ "${MEGREZ_FRESH:-0}" != "1" ]; then
    echo "" >&2
    echo "发现已有的数据库：$EXISTING" >&2
    echo "但目标数据目录 $DATA 里没有库；继续安装会建一个空库，后台会重新要求首次设置。" >&2
    echo "" >&2
    echo "二选一：" >&2
    echo "  a) 继续用旧库：MEGREZ_DATA=$(dirname "$EXISTING") sudo -E bash install.sh" >&2
    echo "  b) 把旧库搬过来：sudo cp -a $(dirname "$EXISTING")/. $DATA/ 然后重跑" >&2
    echo "" >&2
    echo "确认就是要全新开始（旧库不要了），加 MEGREZ_FRESH=1 重跑。" >&2
    exit 1
  fi
fi

id -u megrez >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin megrez

mkdir -p "$PREFIX/bin" "$DATA" "$PREFIX/backup"
chown -R megrez:megrez "$PREFIX" "$DATA"
chmod 700 "$DATA" "$PREFIX/backup"
install -m 0755 "$DIR/megrez" "$PREFIX/bin/megrez"

sed -e "s|__PREFIX__|$PREFIX|g" -e "s|__DATA__|$DATA|g" -e "s|__PORT__|$PORT|g" \
  "$DIR/megrez.service" > /etc/systemd/system/megrez.service

systemctl daemon-reload
systemctl unmask megrez >/dev/null 2>&1 || true
systemctl enable megrez >/dev/null 2>&1 || true
systemctl restart megrez

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "已启动"
    echo "  程序目录：$PREFIX"
    echo "  数据目录：$DATA（升级时不要动这里）"
    echo "  监听：127.0.0.1:$PORT"
    echo "下一步：配置 nginx HTTPS 后，用浏览器打开 https://你的域名/admin 完成首次设置"
    exit 0
  fi
  sleep 0.5
done

echo "启动失败，查看日志：journalctl -u megrez -n 50 --no-pager" >&2
exit 1
