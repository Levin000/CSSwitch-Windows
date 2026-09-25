#!/usr/bin/env bash
# 启动 CSSwitch 管理的隔离运行环境。
# Windows 移植：原 zsh 版的 :A/:h 修饰符、${(z)}/${(s:;:)} 切分、BSD stat -f
# 均改为 bash 等价实现；macOS 专属命令（sandbox-exec/security）在缺失时 fail-closed。
# Safety boundaries:
#   - 独立 HOME + 独立 data-dir + 独立端口，绝不修改/删除真实 ~/.claude-science，绝不用端口 8765
#   - data-dir 只承载持久化状态；不从真实 Science HOME 读取或复制 runtime 或用户数据
#   - 系统 SSH 配置仅在用户显式授权时读取具体 Host alias；不复制 Host block、密钥或整个 ~/.ssh
#   - 只使用应用在隔离目录中生成的本地状态，与真实账号无关
#   - 使用独立的本地钥匙串
#
# 用法:
#   代理由 CSSwitch 桌面端启动并管理；本脚本只负责虚拟 Science 沙箱。
#   再起沙箱: scripts/launch-virtual-sandbox.sh [--port 8990] [--proxy-url http://127.0.0.1:18991]
#   CSSwitch 桌面端通过 CSSWITCH_PROXY_URL 环境变量传递含 secret 的 URL，避免进入 argv。
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

# Windows 移植：把承载本脚本的控制台切到 UTF-8（65001）。守护进程与脚本
# 自身都输出 UTF-8，中文 Windows 控制台默认 GBK(936) 会把标点误解码成
# 鈥?/路 之类的乱码。无控制台（隐藏窗口）时静默失败，不影响流程。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    cmd //c "chcp 65001" >/dev/null 2>&1 || true
    ;;
esac

PROJ="$(cd -- "$(dirname -- "$(dirname -- "$0")")" && pwd -P)"
SANDBOX_HOME="${SANDBOX_HOME:-$PROJ/.sandbox/home}"
DATA_DIR="$SANDBOX_HOME/.claude-science"   # = auth_dir（Science 按 HOME 推导）
# Host home is explicit (CSSWITCH_HOST_HOME from Desktop allowlist). Do not treat
# ambient $HOME as the trusted host path when Desktop injects the control env.
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
REUSE_SYSTEM_SSH="${CSSWITCH_REUSE_SYSTEM_SSH:-0}"
SYSTEM_SSH_HOSTS="${CSSWITCH_SYSTEM_SSH_HOSTS:-}"
SYSTEM_SSH_CONFIG="$REAL_HOME/.ssh/config"
SSH_BRIDGE_DIR="$PROJ/scripts/ssh-bridge"
SSH_BRIDGE_BIN="$SSH_BRIDGE_DIR/ssh"
SSH_BRIDGE_SHA256="0828acbda9f296983c127149879526e92a3eb915cbc9874747e8cecbeab87c5c"
SSH_RUNTIME_BRIDGE_DIR="$SANDBOX_HOME/.csswitch-ssh-bridge"
SSH_RUNTIME_BRIDGE_BIN="$SSH_RUNTIME_BRIDGE_DIR/ssh"
SANDBOX_SSH_DIR="$SANDBOX_HOME/.ssh"
SANDBOX_SSH_CONFIG="$SANDBOX_SSH_DIR/config"
SSH_STUB_MARKER_V1="# CSSwitch managed system SSH config bridge v1"
SSH_STUB_MARKER="# CSSwitch managed system SSH config bridge v2"
PORT=8990
PROXY_URL="${CSSWITCH_PROXY_URL:-http://127.0.0.1:18991}"
EMAIL="virtual@localhost.invalid"
DRY_RUN=0
SKIP_FORGE=0
SCIENCE_OPAQUE_BINDINGS="${CSSWITCH_SCIENCE_OPAQUE_BINDINGS:-}"
ACCEPTANCE_OUTER_SANDBOX="${CSSWITCH_ACCEPTANCE_OUTER_SANDBOX:-0}"

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

# GNU/BSD stat 兼容：优先 GNU stat -c，回退 BSD stat -f
_stat_gnu() { stat -c "$1" "$2" 2>/dev/null; }

validate_ssh_wrapper_identity() {
  local candidate="$1"
  local metadata digest owner mode nlink
  is_safe_science_bin "$candidate" || return 1
  metadata="$(_stat_gnu '%u %a %h' "$candidate")" || return 1
  read -r owner mode nlink <<< "$metadata"
  [[ "$owner" == "$(id -u)" && "$nlink" == "1" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#22) == 0 )) || return 1
  digest="$(sha256sum "$candidate" 2>/dev/null | awk '{print $1}')" || return 1
  [[ "$digest" == "$SSH_BRIDGE_SHA256" ]]
}

materialize_system_ssh_wrapper_snapshot() {
  local owner mode temporary
  if [[ -e "$SSH_RUNTIME_BRIDGE_DIR" || -L "$SSH_RUNTIME_BRIDGE_DIR" ]]; then
    [[ -d "$SSH_RUNTIME_BRIDGE_DIR" && ! -L "$SSH_RUNTIME_BRIDGE_DIR" ]] || return 1
    owner="$(_stat_gnu '%u' "$SSH_RUNTIME_BRIDGE_DIR" 2>/dev/null)" || return 1
    mode="$(_stat_gnu '%a' "$SSH_RUNTIME_BRIDGE_DIR" 2>/dev/null)" || return 1
    [[ "$owner" == "$(id -u)" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 8#22) == 0 )) || return 1
    validate_ssh_wrapper_identity "$SSH_RUNTIME_BRIDGE_BIN" || return 1
    chmod 700 "$SSH_RUNTIME_BRIDGE_DIR" || return 1
    return 0
  fi

  mkdir -m 700 -p "$SSH_RUNTIME_BRIDGE_DIR" || return 1
  temporary="$SSH_RUNTIME_BRIDGE_DIR/.ssh.$PPID.$$"
  [[ ! -e "$temporary" && ! -L "$temporary" && ! -e "$SSH_RUNTIME_BRIDGE_BIN" ]] || return 1
  if ! install -m 500 "$SSH_BRIDGE_BIN" "$temporary" \
      || ! validate_ssh_wrapper_identity "$temporary" \
      || ! mv -f "$temporary" "$SSH_RUNTIME_BRIDGE_BIN" \
      || ! chmod 700 "$SSH_RUNTIME_BRIDGE_DIR" \
      || ! validate_ssh_wrapper_identity "$SSH_RUNTIME_BRIDGE_BIN"; then
    rm -f "$temporary"
    return 1
  fi
}

validate_science_opaque_bindings() {
  local binding name expected target actual owner mode
  if [[ -z "$SCIENCE_OPAQUE_BINDINGS" ]]; then
    [[ "${CSSWITCH_RUNTIME_VERSION_PRECHECKED:-0}" != "1" ]] && return 0
    echo "拒绝：缺少 Science opaque-root 启动绑定" >&2
    return 1
  fi
  for binding in ${SCIENCE_OPAQUE_BINDINGS//;/ }; do
    name="${binding%%=*}"
    expected="${binding#*=}"
    case "$name" in
      conda|runtime|seed-assets|r-libs|sbx-bind-src) ;;
      *)
        echo "拒绝：Science opaque-root 启动绑定名称非法" >&2
        return 1
        ;;
    esac
    target="$DATA_DIR/$name"
    if [[ "$expected" == "absent" ]]; then
      if [[ -e "$target" || -L "$target" ]]; then
        echo "拒绝：Science opaque root 在启动前出现" >&2
        return 1
      fi
      continue
    fi
    [[ "$expected" =~ ^[0-9]+:[0-9]+$ ]] || {
      echo "拒绝：Science opaque-root 启动绑定格式非法" >&2
      return 1
    }
    if [[ ! -d "$target" || -L "$target" ]]; then
      echo "拒绝：Science opaque root 在启动前被替换" >&2
      return 1
    fi
    actual="$(_stat_gnu '%d:%i' "$target" 2>/dev/null || true)"
    owner="$(_stat_gnu '%u' "$target" 2>/dev/null || true)"
    mode="$(_stat_gnu '%a' "$target" 2>/dev/null || true)"
    if [[ "$actual" != "$expected" || "$owner" != "$(id -u)" || ! "$mode" =~ ^[0-7]{3,4}$ ]] \
        || (( (8#$mode & 8#22) != 0 )); then
      echo "拒绝：Science opaque root 启动绑定已变化" >&2
      return 1
    fi
  done
}

is_managed_ssh_stub() {
  local target="$1" escaped first second third fourth host
  [[ -f "$target" && ! -L "$target" ]] || return 1
  [[ "$(_stat_gnu '%u' "$target" 2>/dev/null)" == "$(id -u)" ]] || return 1
  escaped="$(printf '%s' "$SYSTEM_SSH_CONFIG" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  {
    IFS= read -r first || return 1
    IFS= read -r second || return 1
    IFS= read -r third || third=""
    IFS= read -r fourth || fourth=""
  } < "$target"
  if [[ "$first" == "$SSH_STUB_MARKER_V1" && "$second" == "Include \"$escaped\"" && -z "$third" && -z "$fourth" ]]; then
    return 0
  fi
  [[ "$first" == "$SSH_STUB_MARKER" && "$second" == "Host "* && "$third" == "Include \"$escaped\"" && -z "$fourth" ]] || return 1
  for host in ${second#"Host "}; do
    [[ "$host" =~ '^[A-Za-z0-9._:@%+-]{1,255}$' && "$host" != -* ]] || return 1
  done
}

prepare_sandbox_ssh_config() {
  if path_contains_symlink "$SANDBOX_SSH_DIR"; then
    echo "拒绝：隔离 SSH 配置目录包含符号链接"
    return 1
  fi
  if [[ -e "$SANDBOX_SSH_DIR" && ! -d "$SANDBOX_SSH_DIR" ]]; then
    echo "拒绝：隔离 SSH 配置目录不是普通目录"
    return 1
  fi
  mkdir -m 700 -p "$SANDBOX_SSH_DIR" 2>/dev/null || {
    echo "拒绝：无法创建隔离 SSH 配置目录"
    return 1
  }
  chmod 700 "$SANDBOX_SSH_DIR" 2>/dev/null || {
    echo "拒绝：无法收紧隔离 SSH 配置目录权限"
    return 1
  }
  if [[ -e "$SANDBOX_SSH_CONFIG" || -L "$SANDBOX_SSH_CONFIG" ]]; then
    if ! is_managed_ssh_stub "$SANDBOX_SSH_CONFIG"; then
      echo "拒绝：隔离 SSH config 不是 CSSwitch 管理的安全入口"
      return 1
    fi
  fi
  local escaped tmp
  escaped="$(printf '%s' "$SYSTEM_SSH_CONFIG" | /usr/bin/sed 's/\\/\\\\/g; s/"/\\"/g')"
  tmp="$(mktemp "$SANDBOX_SSH_DIR/.csswitch-config.XXXXXX" 2>/dev/null)" || {
    echo "拒绝：无法创建隔离 SSH 临时配置"
    return 1
  }
  chmod 600 "$tmp" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
    echo "拒绝：无法收紧隔离 SSH 临时配置权限"
    return 1
  }
  printf '%s\nHost %s\nInclude "%s"\n' "$SSH_STUB_MARKER" "$SYSTEM_SSH_HOSTS" "$escaped" > "$tmp" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
    echo "拒绝：无法写入隔离 SSH 配置"
    return 1
  }
  mv -f "$tmp" "$SANDBOX_SSH_CONFIG" 2>/dev/null || {
    rm -f "$tmp" 2>/dev/null || true
    echo "拒绝：无法提交隔离 SSH 配置"
    return 1
  }
  chmod 600 "$SANDBOX_SSH_CONFIG" 2>/dev/null || {
    echo "拒绝：无法收紧隔离 SSH config 权限"
    return 1
  }
}

remove_sandbox_ssh_config() {
  if [[ ! -e "$SANDBOX_SSH_DIR" && ! -L "$SANDBOX_SSH_DIR" ]]; then
    return 0
  fi
  if path_contains_symlink "$SANDBOX_SSH_DIR" || [[ ! -d "$SANDBOX_SSH_DIR" ]]; then
    echo "拒绝：未授权状态下的隔离 SSH 配置目录不安全"
    return 1
  fi
  if [[ -e "$SANDBOX_SSH_CONFIG" || -L "$SANDBOX_SSH_CONFIG" ]]; then
    if ! is_managed_ssh_stub "$SANDBOX_SSH_CONFIG"; then
      echo "拒绝：未授权状态下存在非 CSSwitch 管理的隔离 SSH config"
      return 1
    fi
    rm -f "$SANDBOX_SSH_CONFIG" 2>/dev/null || {
      echo "拒绝：无法撤销隔离 SSH config"
      return 1
    }
  fi
  /bin/rmdir "$SANDBOX_SSH_DIR" 2>/dev/null || true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --proxy-url) PROXY_URL="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    --skip-oauth-forge) SKIP_FORGE=1; shift;;
    *) echo "未知参数: $1"; exit 1;;
  esac
done

# —— 铁律断言：绝不使用真实目录 / 真实端口 ——
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "拒绝：端口不是合法整数（$PORT）"; exit 1; }
if (( 10#${PORT} == 8765 )); then echo "拒绝：端口 8765 是真实实例保留端口"; exit 1; fi
if (( 10#${PORT} >= 65535 )); then echo "拒绝：Science 端口必须小于 65535，才能分配隔离预览端口"; exit 1; fi
PREVIEW_PORT=$(( 10#${PORT} + 1 ))
if (( PREVIEW_PORT == 8765 )); then echo "拒绝：预览端口会命中真实实例保留端口 8765"; exit 1; fi
_PROXY_HOSTPORT="$(printf '%s' "$PROXY_URL" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]+).*#\1#')"
_PROXY_PORT="${_PROXY_HOSTPORT##*:}"
if [[ "$_PROXY_PORT" =~ ^[0-9]+$ ]] && (( 10#${_PROXY_PORT} == PREVIEW_PORT )); then
  echo "拒绝：预览端口 $PREVIEW_PORT 与 CSSwitch Gateway 端口冲突"
  exit 1
fi
if [[ "$REUSE_SYSTEM_SSH" != "0" && "$REUSE_SYSTEM_SSH" != "1" ]]; then
  echo "拒绝：系统 SSH 授权值无效"
  exit 1
fi
if [[ "$REUSE_SYSTEM_SSH" == "1" ]]; then
  if [[ ! -f "$SYSTEM_SSH_CONFIG" ]]; then
    echo "拒绝：未找到系统 ~/.ssh/config，不能启用系统 SSH 配置"
    exit 1
  fi
  if ! validate_ssh_wrapper_identity "$SSH_BRIDGE_BIN"; then
    echo "拒绝：CSSwitch SSH bridge 内容身份或文件权限不匹配"
    exit 1
  fi
  if [[ -z "$SYSTEM_SSH_HOSTS" ]]; then
    echo "拒绝：未准备可供 Science 校验的具体 SSH Host alias"
    exit 1
  fi
  for _ssh_host in $SYSTEM_SSH_HOSTS; do
    if [[ ! "$_ssh_host" =~ '^[A-Za-z0-9._:@%+-]{1,255}$' || "$_ssh_host" == -* ]]; then
      echo "拒绝：SSH Host alias 不符合安全格式"
      exit 1
    fi
  done
fi
_dd_real="$(abspath "$DATA_DIR")"; _real_real="$(abspath "$REAL_DATA_DIR")"
if [[ "$_dd_real" == "$_real_real" ]]; then echo "拒绝：data-dir 的真实路径指向真实目录"; exit 1; fi
if path_contains_symlink "$DATA_DIR"; then
  echo "拒绝：Science data-dir 路径包含符号链接"
  exit 1
fi
if [[ "$DRY_RUN" == "1" ]]; then echo "DRY-RUN OK：护栏通过，未启动沙箱。"; exit 0; fi

# The selected runtime owns initialization and migration inside the isolated
# data-dir. Never seed it from the user's real Science data. The backend passes
# SCIENCE_BIN for the installed App or a user-authorized one-shot cache. Without
# that identity, this script may use only the installed App and never an implicit
# data-dir fallback.
mkdir -p "$DATA_DIR"
if path_contains_symlink "$DATA_DIR"; then
  echo "拒绝：Science data-dir 路径在初始化期间发生符号链接变化"
  exit 1
fi
if [[ "$REUSE_SYSTEM_SSH" == "1" ]]; then
  prepare_sandbox_ssh_config
else
  remove_sandbox_ssh_config
fi
BIN_SOURCE="backend-selected runtime"
if [[ -z "$BIN" ]]; then
  BIN="$APP_BIN"
  BIN_SOURCE="official local app"
fi
if ! is_safe_science_bin "$BIN"; then
  echo "拒绝：Science binary 必须是无符号链接的绝对可执行文件"
  exit 1
fi
if [[ "${CSSWITCH_RUNTIME_VERSION_PRECHECKED:-0}" != "1" ]] && ! HOME="$SANDBOX_HOME" "$BIN" --version >/dev/null 2>&1; then
  echo "拒绝：Science binary 未通过非写入版本预检"
  exit 1
fi
unset CSSWITCH_RUNTIME_VERSION_PRECHECKED

if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$PREVIEW_PORT" -sTCP:LISTEN -t 2>/dev/null | grep -q .; then
    echo "拒绝：隔离预览端口 $PREVIEW_PORT 已被占用"
    exit 1
  fi
elif netstat -an 2>/dev/null | grep -Eq "[.:]$PREVIEW_PORT[[:space:]].*LISTEN"; then
  echo "拒绝：隔离预览端口 $PREVIEW_PORT 已被占用"
  exit 1
fi

# Use a keychain scoped to the isolated HOME (macOS only; other platforms skip).
SANDBOX_KC="$SANDBOX_HOME/Library/Keychains/login.keychain-db"
if command -v security >/dev/null 2>&1; then
  if [[ ! -f "$SANDBOX_KC" ]]; then
    echo "创建沙箱专属钥匙串（隔离，空密码，不自动锁）…"
    mkdir -p "$SANDBOX_HOME/Library/Keychains"
    if ! HOME="$SANDBOX_HOME" security create-keychain -p "" "$SANDBOX_KC" >/dev/null 2>&1; then
      echo "警告：沙箱专属钥匙串初始化未完成；原始输出因可能含路径而未记录。" >&2
    fi
  fi
  # 每次启动都确保：加入沙箱搜索表、设为默认、解锁、关自动锁（全部仅作用于沙箱 HOME）
  HOME="$SANDBOX_HOME" security list-keychains -d user -s "$SANDBOX_KC" >/dev/null 2>&1 || true
  HOME="$SANDBOX_HOME" security default-keychain -d user -s "$SANDBOX_KC" >/dev/null 2>&1 || true
  HOME="$SANDBOX_HOME" security unlock-keychain -p "" "$SANDBOX_KC" >/dev/null 2>&1 || true
  HOME="$SANDBOX_HOME" security set-keychain-settings "$SANDBOX_KC" >/dev/null 2>&1 || true
fi

# 应用必须先在隔离目录中准备本地状态。
if [[ "$SKIP_FORGE" == "1" ]]; then
  echo "隔离运行状态已由 CSSwitch 准备（路径已隐藏）"
else
  echo "拒绝：请通过 CSSwitch 启动此隔离环境"
  exit 1
fi

echo
echo "启动隔离沙箱 Science（虚拟登录）"
echo "  HOME     = [CSSwitch isolated]"
echo "  data-dir = [CSSwitch isolated Science data]"
echo "  端口     = $PORT   （真实实例 8765 不受影响）"
echo "  预览端口 = $PREVIEW_PORT   （显式固定，供本机 Science 预览使用）"
echo "  二进制   = $BIN_SOURCE"
if [[ "$REUSE_SYSTEM_SSH" == "1" ]]; then
  echo "  系统 SSH = 已显式授权（Science 校验具体 alias；OpenSSH 读取 ~/.ssh/config）"
else
  echo "  系统 SSH = 未授权"
fi
# 掩掉 proxy-url 里的 path secret（一次性鉴权令牌不入日志）
_masked_proxy="$(printf '%s' "$PROXY_URL" | sed -E 's#(://[^/]+/).+#\1****#')"
echo "  推理指向 = $_masked_proxy"
echo "  账号     = $EMAIL （本地假账号，不用真实凭证）"

# Keep local inference traffic on loopback and fail closed for blocked upstreams.
_FASTFAIL_PROXY="http://$_PROXY_HOSTPORT"
_NO_PROXY="127.0.0.1,localhost,::1"
echo "  外联防卡 = Anthropic HTTPS fast-fail（经 $_FASTFAIL_PROXY，no_proxy=$_NO_PROXY）"
echo

if path_contains_symlink "$DATA_DIR"; then
  echo "拒绝：Science data-dir 路径在启动前发生符号链接变化"
  exit 1
fi
validate_science_opaque_bindings
# Empty environment + explicit allowlist only. Never inherit ambient parent vars.
_SAFE_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
_SCIENCE_PATH="$_SAFE_PATH"
if [[ "$REUSE_SYSTEM_SSH" == "1" ]]; then
  if ! validate_ssh_wrapper_identity "$SSH_BRIDGE_BIN" \
      || ! materialize_system_ssh_wrapper_snapshot; then
    echo "拒绝：CSSwitch SSH bridge 无法固定为隔离的内容身份 snapshot" >&2
    exit 1
  fi
  _SCIENCE_PATH="$SSH_RUNTIME_BRIDGE_DIR:$_SAFE_PATH"
fi
_SCIENCE_TMPDIR="${TMPDIR:-/tmp}"
_SCIENCE_LANG="${LANG:-en_US.UTF-8}"
_SCIENCE_USER="$(id -un 2>/dev/null || echo csswitch)"
typeset -a _SCIENCE_ENV
_SCIENCE_ENV=(
  "HOME=$SANDBOX_HOME"
  "PATH=$_SCIENCE_PATH"
  "TMPDIR=$_SCIENCE_TMPDIR"
  "LANG=$_SCIENCE_LANG"
  "LC_ALL=$_SCIENCE_LANG"
  "USER=$_SCIENCE_USER"
  "LOGNAME=$_SCIENCE_USER"
  "ANTHROPIC_BASE_URL=$PROXY_URL"
  "https_proxy=$_FASTFAIL_PROXY"
  "HTTPS_PROXY=$_FASTFAIL_PROXY"
  "no_proxy=$_NO_PROXY"
  "NO_PROXY=$_NO_PROXY"
  # Anthropic CLI 官方退避开关：虚拟登录不上官方云，关掉守护进程的
  # 遥测/非必要流量轮询，消除周期性 401 重试噪音。
  "DO_NOT_TRACK=1"
  "OPERON_DISABLE_TELEMETRY=1"
  "OPERON_DISABLE_NONESSENTIAL_TRAFFIC=1"
)
# Windows 移植：已知目录解析（SHGetKnownFolderPath 回退链）与 CRT 初始化
# 需要这些系统变量，env -i 后必须补回；USERPROFILE/APPDATA 指向隔离 HOME
# 保持隔离，系统级变量从宿主透传（非隐私）。
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    mkdir -p "$SANDBOX_HOME/AppData/Roaming" "$SANDBOX_HOME/AppData/Local"
    _SCIENCE_ENV+=(
      "USERPROFILE=$SANDBOX_HOME"
      "APPDATA=$SANDBOX_HOME/AppData/Roaming"
      "LOCALAPPDATA=$SANDBOX_HOME/AppData/Local"
      "SystemRoot=${SystemRoot:-C:\Windows}"
      "SystemDrive=${SystemDrive:-C:}"
      "windir=${windir:-C:\Windows}"
      "ProgramData=${ProgramData:-C:\ProgramData}"
      "ALLUSERSPROFILE=${ALLUSERSPROFILE:-C:\ProgramData}"
      "TEMP=${TEMP:-C:\Windows\Temp}"
      "TMP=${TMP:-C:\Windows\Temp}"
      "PATHEXT=${PATHEXT:-.COM;.EXE;.BAT;.CMD}"
      "ComSpec=${ComSpec:-C:\Windows\System32\cmd.exe}"
    )
    ;;
esac
typeset -a _SCIENCE_EXTRA_ARGS
_SCIENCE_EXTRA_ARGS=()
if [[ "$ACCEPTANCE_OUTER_SANDBOX" == "1" ]]; then
  _sandbox_real="$(abspath "$SANDBOX_HOME")"
  _host_real="$(abspath "$REAL_HOME")"
  case "$_sandbox_real/$_host_real" in
    /private/tmp/*|/tmp/*) ;;
    *)
      echo "拒绝：isolated-live 外层 sandbox 只允许临时 HOME" >&2
      exit 1
      ;;
  esac
  # A successful nested sandbox probe means no outer sandbox is active, so the
  # acceptance-only opt-out must fail closed instead of weakening production.
  if sandbox-exec -p '(version 1)(allow default)' true >/dev/null 2>&1; then
    echo "拒绝：isolated-live 外层 sandbox 未生效" >&2
    exit 1
  fi
  _SCIENCE_EXTRA_ARGS+=("--dangerously-no-sandbox")
  echo "  Science sandbox = 由外层 isolated-live deny-egress sandbox 接管"
elif [[ "$ACCEPTANCE_OUTER_SANDBOX" != "0" ]]; then
  echo "拒绝：isolated-live 外层 sandbox 标志非法" >&2
  exit 1
fi
if [[ "$REUSE_SYSTEM_SSH" == "1" ]]; then
  if ! validate_ssh_wrapper_identity "$SSH_RUNTIME_BRIDGE_BIN"; then
    echo "拒绝：隔离的 CSSwitch SSH bridge snapshot 在 Science 启动前发生变化" >&2
    exit 1
  fi
  _SCIENCE_ENV+=(
    "CSSWITCH_SYSTEM_SSH_CONFIG=$SYSTEM_SSH_CONFIG"
  )
fi
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # Windows 移植：claude-science 的 --detached 守护进程化在本平台故障
    #（daemon child spawn 失败）。改用前台模式 + bash 后台挂起：脚本退出
    # 后服务进程继续存活，健康探活/停止脚本语义不变。
    env -i "${_SCIENCE_ENV[@]}" "$BIN" serve \
        --data-dir "$DATA_DIR" \
        --host 127.0.0.1 \
        --port "$PORT" \
        --sandbox-port "$PREVIEW_PORT" \
        --no-browser --no-auto-update "${_SCIENCE_EXTRA_ARGS[@]}" \
        >/dev/null 2>&1 &
    _SERVE_PID=$!
    sleep 2
    if ! kill -0 "$_SERVE_PID" 2>/dev/null; then
      wait "$_SERVE_PID" 2>/dev/null
      _rc=$?
      echo "Science 启动命令失败（退出码 $_rc；原始输出可能含临时链接或路径，未写入 CSSwitch 日志）" >&2
      # Contract with the desktop transaction: this distinct code proves that
      # Science was invoked and may have mutated its opaque environment roots.
      exit 70
    fi
    ;;
  *)
    if ! /usr/bin/env -i "${_SCIENCE_ENV[@]}" "$BIN" serve \
        --data-dir "$DATA_DIR" \
        --host 127.0.0.1 \
        --port "$PORT" \
        --sandbox-port "$PREVIEW_PORT" \
        --no-browser --no-auto-update --detached "${_SCIENCE_EXTRA_ARGS[@]}" \
        >/dev/null 2>&1; then
      echo "Science 启动命令失败（原始输出可能含临时链接或路径，未写入 CSSwitch 日志）" >&2
      # Contract with the desktop transaction: this distinct code proves that
      # Science was invoked and may have mutated its opaque environment roots.
      exit 70
    fi
    ;;
esac

echo
echo "已后台启动。验证:"
echo "  健康:   curl -s http://127.0.0.1:$PORT/health || true"
echo "  状态:   请使用 CSSwitch 状态灯确认"
echo "停止:     请使用 CSSwitch「停止全部」"
