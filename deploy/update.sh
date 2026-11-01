#!/usr/bin/env bash
# 天权升级：一条命令。只换二进制，先备份数据库，绝不碰 data。
#
#   sudo bash update.sh <发布包.tar.gz | 下载地址 | megrez 二进制>
#   例：sudo bash update.sh https://github.com/…/megrez-linux-amd64.tar.gz
#
# 路径（二进制、数据库、端口）从现有 systemd 单元里自动读出，不用记。
set -euo pipefail

SRC="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/megrez}"
TMP=""
trap '[ -n "$TMP" ] && rm -rf "$TMP"' EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo bash update.sh <发布包|地址|二进制>" >&2
  exit 1
fi
systemctl cat megrez >/dev/null 2>&1 || { echo "还没装过，请先跑 install.sh" >&2; exit 1; }

# ---- 解析入参：tar.gz / URL / 现成二进制 ----
case "$SRC" in
  http://*|https://*)
    TMP="$(mktemp -d)"
    echo "下载 $SRC"
    curl -fsSL "$SRC" -o "$TMP/pkg.tar.gz"
    SRC="$TMP/pkg.tar.gz"
    ;;
esac

if [ -f "$SRC" ] && [[ "$SRC" == *.tar.gz || "$SRC" == *.tgz ]]; then
  [ -n "$TMP" ] || TMP="$(mktemp -d)"
  mkdir -p "$TMP/pkg"
  tar xzf "$SRC" -C "$TMP/pkg" --strip-components=1 2>/dev/null || tar xzf "$SRC" -C "$TMP/pkg"
  NEW_BIN="$(find "$TMP/pkg" -type f -name megrez | head -n1)"
else
  NEW_BIN="$SRC"
fi

[ -n "${NEW_BIN:-}" ] && [ -f "$NEW_BIN" ] || { echo "包里找不到 megrez 二进制：$SRC" >&2; exit 1; }

# ---- 从现有单元读路径 ----
BIN_PATH="$(systemctl cat megrez | grep -m1 'ExecStart=' | sed 's/^ExecStart=//' | awk '{print $1}')"
DB_PATH="$(systemctl cat megrez | grep -o -- '-db [^ ]*' | head -n1 | cut -d' ' -f2)"
ADDR="$(systemctl cat megrez | grep -o -- '-addr [^ ]*' | head -n1 | cut -d' ' -f2)"
PORT="${ADDR##*:}"; PORT="${PORT:-8787}"

[ -f "$BIN_PATH" ] || { echo "当前二进制不存在：$BIN_PATH" >&2; exit 1; }
[ -f "$DB_PATH" ] || { echo "数据库不存在：$DB_PATH（拒绝继续，避免建空库）" >&2; exit 1; }

BACKUP_DIR="${MEGREZ_BACKUP:-$(dirname "$(dirname "$DB_PATH")")/backup}"
mkdir -p "$BACKUP_DIR"
chown megrez:megrez "$BACKUP_DIR" 2>/dev/null || true

echo "备份数据库……"
sudo -u megrez "$BIN_PATH" backup -db "$DB_PATH" -out "$BACKUP_DIR/megrez-$(date +%F-%H%M%S).db"

echo "替换二进制并重启……"
systemctl stop megrez
install -m 0755 "$NEW_BIN" "$BIN_PATH"
systemctl start megrez

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "升级完成，数据库未动：$DB_PATH"
    exit 0
  fi
  sleep 1
done

echo "服务没起来，二进制已替换、数据库未动。排查：journalctl -u megrez -n 60 --no-pager" >&2
exit 1
