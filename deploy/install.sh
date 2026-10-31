#!/usr/bin/env bash
# 天权一键安装：建账号/目录、装二进制、写 systemd、启动。
# 只做这一件事，重复执行也安全（升级就是再跑一遍）。
set -euo pipefail

PREFIX="${MEGREZ_PREFIX:-/opt/megrez}"
PORT="${MEGREZ_PORT:-8787}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo ./install.sh" >&2
  exit 1
fi
if [ ! -f "$DIR/megrez" ]; then
  echo "安装包里缺少 megrez 二进制" >&2
  exit 1
fi

id -u megrez >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin megrez

mkdir -p "$PREFIX/bin" "$PREFIX/data" "$PREFIX/backup"
chown -R megrez:megrez "$PREFIX"
chmod 700 "$PREFIX/data" "$PREFIX/backup"
install -m 0755 "$DIR/megrez" "$PREFIX/bin/megrez"

sed -e "s|__PREFIX__|$PREFIX|g" -e "s|__PORT__|$PORT|g" \
  "$DIR/megrez.service" > /etc/systemd/system/megrez.service

systemctl daemon-reload
systemctl enable megrez >/dev/null 2>&1
systemctl restart megrez

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "已启动，内部监听 127.0.0.1:$PORT（数据目录 $PREFIX/data）"
    echo "下一步：配置 nginx HTTPS 后，用浏览器打开 https://你的域名/admin 完成首次设置"
    exit 0
  fi
  sleep 0.5
done

echo "启动失败，查看日志：journalctl -u megrez -n 50 --no-pager" >&2
exit 1
