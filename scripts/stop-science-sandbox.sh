#!/usr/bin/env bash
# 停止隔离沙箱 Science（只停沙箱 data-dir 的守护进程，绝不影响真实实例 8765）。
# Windows 移植：原 zsh 版的 :A/:h 修饰符改为 bash 等价实现；绝对路径判断适配盘符。
set -euo pipefail
umask 077

# 相对/裸路径判断：接受 /xxx（unix）与 C:/ 或 C:\（windows 盘符）
is_abs() {
  case "$1" in
    /* | [A-Za-z]:[\\/]* | [A-Za-z]:) return 0 ;;
    *) return 1 ;;
  esac
}

# 等价 zsh ${VAR:A}：输出绝对路径（不改写符号链接，够用于碰撞比较）
abspath() {
  local p="$1"
  if [ -d "$p" ]; then
    (cd -- "$p" >/dev/null 2>&1 && pwd -P)
  else
    local d b
    d="$(dirname -- "$p")"
    b="$(basename -- "$p")"
    (cd -- "$d" >/dev/null 2>&1 && printf '%s/%s\n' "$(pwd -P)" "$b")
  fi
}

PROJ="$(cd -- "$(dirname -- "$(dirname -- "$0")")" && pwd -P)"
SANDBOX_HOME="${SANDBOX_HOME:-$PROJ/.sandbox/home}"
DATA_DIR="$SANDBOX_HOME/.claude-science"
# Host home is explicit (CSSWITCH_HOST_HOME from Desktop allowlist). Required for
# the real-data-dir collision guard under set -u when ambient HOME is cleared.
if [[ -n "${CSSWITCH_HOST_HOME:-}" ]]; then
  REAL_HOME="$CSSWITCH_HOST_HOME"
elif [[ -n "${HOME:-}" ]]; then
  # Manual/dev fallback only; production Desktop always sets CSSWITCH_HOST_HOME.
  REAL_HOME="$HOME"
else
  echo "拒绝：缺少 CSSWITCH_HOST_HOME（或 HOME）以解析主机侧路径" >&2
  exit 1
fi
REAL_DATA_DIR="$REAL_HOME/.claude-science"
APP_BIN="${CSSWITCH_SCIENCE_APP_BIN:-}"
BIN="${SCIENCE_BIN:-}"

is_safe_science_bin() {
  local probe="$1"
  is_abs "$probe" || return 1
  while :; do
    [[ -L "$probe" ]] && return 1
    case "$probe" in
      / | [A-Za-z]: | [A-Za-z]:[\\/]) break ;;
    esac
    local parent
    parent="$(dirname -- "$probe")"
    [[ "$parent" == "$probe" ]] && break
    probe="$parent"
  done
  [[ -f "$1" && -x "$1" ]]
}
path_contains_symlink() {
  local probe="$1"
  is_abs "$probe" || return 0
  while :; do
    [[ -L "$probe" ]] && return 0
    case "$probe" in
      / | [A-Za-z]: | [A-Za-z]:[\\/]) break ;;
    esac
    local parent
    parent="$(dirname -- "$probe")"
    [[ "$parent" == "$probe" ]] && break
    probe="$parent"
  done
  return 1
}
if [[ -n "${SCIENCE_BIN:-}" ]] && ! is_safe_science_bin "$BIN"; then
  echo "拒绝：显式 SCIENCE_BIN 路径含符号链接或不是绝对可执行文件"
  exit 1
fi

_dd="$(abspath "$DATA_DIR")"; _rd="$(abspath "$REAL_DATA_DIR")"
if [[ "$_dd" == "$_rd" ]]; then echo "拒绝：data-dir 的真实路径指向真实目录"; exit 1; fi
if path_contains_symlink "$DATA_DIR"; then
  echo "拒绝：Science data-dir 路径包含符号链接"
  exit 1
fi

if [[ ! -d "$DATA_DIR" ]]; then echo "沙箱不存在，无需停止。"; exit 0; fi

# Match launch identity. CSSwitch passes the exact runtime recorded at launch;
# without it, manual stop may use only the installed App and never an implicit
# data-dir fallback.
if [[ -z "$BIN" ]]; then
  if [[ -n "$APP_BIN" ]] && is_safe_science_bin "$APP_BIN" && HOME="$SANDBOX_HOME" "$APP_BIN" --version >/dev/null 2>&1; then
    BIN="$APP_BIN"
  fi
fi
if ! is_safe_science_bin "$BIN"; then
  echo "找不到可用于停止沙箱的已验证 Science binary" >&2
  exit 1
fi

if path_contains_symlink "$DATA_DIR"; then
  echo "拒绝：Science data-dir 路径在停止前发生符号链接变化" >&2
  exit 1
fi
rc=0
HOME="$SANDBOX_HOME" "$BIN" stop --data-dir "$DATA_DIR" 2>&1 | tail -2 || rc=$?
if [[ $rc -eq 0 ]]; then
  echo "沙箱已停。真实实例 8765 未受影响。"
else
  echo "停止失败（退出码 $rc）。真实实例 8765 未受影响。" >&2
  exit "$rc"
fi
