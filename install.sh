#!/usr/bin/env bash
# ============================================================
#  Hermes 红队插件 —— 一键安装
#
#  用法：
#     bash install.sh                  # 装到 ~/.hermes/plugins/purge/
#     HERMES_HOME=/opt/hermes bash install.sh
#
#  已存在时会先备份成 purge.bak_<时间戳>，不会覆盖你的数据。
# ============================================================
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DST="$HERMES_HOME/plugins/purge"

echo "==> Hermes 红队插件 · 安装"
echo "    源目录  : $SRC"
echo "    目标    : $DST"

# --- 0. 检查 ---
command -v python3 >/dev/null 2>&1 || { echo "!! 需要 python3"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
echo "    python3 : $PYV"

# --- 1. 备份已有 ---
mkdir -p "$HERMES_HOME/plugins"
if [ -d "$DST" ]; then
  BAK="${DST}.bak_$(date +%Y%m%d-%H%M%S)"
  echo "==> 已存在，备份到 $BAK"
  mv "$DST" "$BAK"
fi

# --- 2. 拷贝 ---
mkdir -p "$DST"
for f in "$SRC"/*.py "$SRC"/*.yaml; do
  [ -e "$f" ] && cp "$f" "$DST/"
done
# roles.d（角色提示词自填目录）
if [ -d "$SRC/roles.d" ]; then
  mkdir -p "$DST/roles.d"
  cp -r "$SRC"/roles.d/. "$DST/roles.d/" 2>/dev/null || true
fi

# --- 3. 清掉不该带的 ---
rm -rf "$DST/__pycache__"
find "$DST" -name '*.bak*' -delete 2>/dev/null || true

# --- 4. 自检 ---
echo "==> 文件清单"
ls -1 "$DST" | sed 's/^/    /'

echo
echo "==> 装好了。接下来两步："
echo "    1) 重启网关让插件生效：   hermes gateway restart"
echo "    2) 对 bot 说：            purge_status"
echo
echo "  角色提示词是空的（roles.d/ 里没有 .md）——这是设计如此。"
echo "  写你自己的角色稿：$DST/roles.d/<role>.md"
echo "  详见 roles.d/README.md"
