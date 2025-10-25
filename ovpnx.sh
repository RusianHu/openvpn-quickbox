#!/usr/bin/env bash
# ovpnx.sh — 一键交互式 OpenVPN 管理/安装/卸载 脚本
# 适配：Ubuntu 22.04/24.04（systemd）
# 资产/PKI/备份/客户端文件集中在 WORKDIR（默认 /opt/ovpnx）

set -Eeuo pipefail

# ======================= 全局默认 =======================
WORKDIR="${OVPNX_WORKDIR:-/opt/ovpnx}"
EASYRSA_DIR="$WORKDIR/easy-rsa"
SERVER_DIR="/etc/openvpn/server"
SERVER_NAME="server"
SERVICE_NAME="openvpn-server@${SERVER_NAME}.service"
UFW_BEFORE_RULES="/etc/ufw/before.rules"
SYSCTL_FILE="/etc/sysctl.d/99-openvpn.conf"

# 默认网络/端口/协议/DNS
VPN_NET="10.8.0.0/24"
PORT="1194"
PROTO="udp"   # 可改 tcp
DNS1="1.1.1.1"
DNS2="8.8.8.8"
ECDH_CURVE="prime256v1"  # ECC 曲线

# OpenVPN 2.6 推荐数据通道加密套件
DATACIPHERS="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

# TLS 控制通道密码套件（含 RSA/ECDSA，保持单行 <256 兼容 OpenVPN 限制）
TLSCIPHERS="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"

# UFW NAT 标记，便于卸载回滚
NAT_TAG_BEGIN="# OVPNX-START"
NAT_TAG_END="# OVPNX-END"
TLS_CIPHER_NOTICE=""

# ======================= 小工具函数 =======================
color() { local c="$1"; shift; echo -e "\033[${c}m$*\033[0m"; }
ok()    { color 32 "$*"; }
warn()  { color 33 "$*"; }
err()   { color 31 "$*"; }
info()  { color 36 "$*"; }

pause() { read -r -p "按回车键继续..." _; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "请以 root 运行。比如：sudo bash $0"
    exit 1
  fi
}

check_system() {
  # 检查系统版本
  if [[ ! -f /etc/os-release ]]; then
    err "无法检测系统版本，请确保运行在 Ubuntu 系统上。"
    exit 1
  fi

  source /etc/os-release
  if [[ "$ID" != "ubuntu" ]]; then
    err "此脚本仅支持 Ubuntu 系统，当前系统: $ID"
    exit 1
  fi

  local ver_major="${VERSION_ID%%.*}"
  if [[ "$ver_major" -lt 22 ]]; then
    err "此脚本需要 Ubuntu 22.04 或更高版本，当前版本: $VERSION_ID"
    exit 1
  fi

  ok "系统检查通过: Ubuntu $VERSION_ID"
}

check_openvpn_version() {
  # 检查 OpenVPN 版本（安装后调用）
  if ! command -v openvpn &>/dev/null; then
    warn "OpenVPN 未安装，跳过版本检查。"
    return 0
  fi

  local ovpn_ver ovpn_full_info
  ovpn_full_info=$(openvpn --version 2>&1 | head -n1)
  ovpn_ver=$(echo "$ovpn_full_info" | grep -oP 'OpenVPN \K[0-9.]+' || echo "unknown")

  if [[ "$ovpn_ver" == "unknown" ]]; then
    warn "无法检测 OpenVPN 版本，继续执行..."
    return 0
  fi

  ok "检测到 OpenVPN 版本: $ovpn_ver"

  # 解析版本号
  local ver_major ver_minor
  ver_major="${ovpn_ver%%.*}"
  ver_minor=$(echo "$ovpn_ver" | cut -d. -f2)

  # 版本兼容性检查
  if [[ "$ver_major" -lt 2 ]]; then
    err "OpenVPN 版本过低 ($ovpn_ver)，需要 2.4 或更高版本。"
    return 1
  fi

  if [[ "$ver_major" -eq 2 && "$ver_minor" -lt 4 ]]; then
    warn "OpenVPN 版本 $ovpn_ver 较旧，建议升级到 2.5+ 以获得更好的安全性和性能。"
    warn "当前配置的加密套件可能不完全支持。"
  fi

  # 检查是否支持 tls-crypt（2.4+ 支持）
  if [[ "$ver_major" -eq 2 && "$ver_minor" -ge 4 ]] || [[ "$ver_major" -gt 2 ]]; then
    ok "版本支持 tls-crypt 和现代加密套件。"
  fi

  # 检查是否支持 data-ciphers（2.5+ 推荐）
  if [[ "$ver_major" -eq 2 && "$ver_minor" -ge 5 ]] || [[ "$ver_major" -gt 2 ]]; then
    ok "版本支持 data-ciphers 配置（推荐）。"
  elif [[ "$ver_major" -eq 2 && "$ver_minor" -eq 4 ]]; then
    info "OpenVPN 2.4 使用 ncp-ciphers，配置已兼容。"
  fi

  return 0
}

ensure_dirs() {
  install -d "$WORKDIR" "$WORKDIR/backups" "$WORKDIR/clients"
}

default_iface() {
  local iface
  iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')

  if [[ -z "$iface" ]]; then
    # 如果没有默认路由，尝试获取第一个非 lo 的活动网卡
    iface=$(ip -o -4 addr show | awk '$2!="lo" {print $2; exit}')
  fi

  if [[ -z "$iface" ]]; then
    err "无法检测到网络接口，请手动指定。"
    return 1
  fi

  echo "$iface"
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0

  # 使用纳秒级时间戳避免冲突
  local ts; ts=$(date +%Y%m%d-%H%M%S-%N)
  local backup_path="$WORKDIR/backups/$(basename "$f").$ts.bak"

  # 如果仍然存在同名文件（极小概率），添加随机后缀
  if [[ -f "$backup_path" ]]; then
    backup_path="${backup_path}.${RANDOM}"
  fi

  cp -a "$f" "$backup_path"
  info "已备份: $backup_path"
}

get_client_cert_state() {
  local name="$1"
  local idx="$EASYRSA_DIR/pki/index.txt"
  if [[ ! -f "$idx" ]]; then
    echo "missing -"
    return 0
  fi

  local record code serial
  record=$(awk -v target="$name" '
    /^[A-Z]/ && match($0, /CN=([^\/]+)/, arr) && arr[1] == target {
      state = substr($0, 1, 1)
      serial = $4
    }
    END {
      if (state == "")
        print "missing -"
      else
        print state " " serial
    }
  ' "$idx")

  read -r code serial <<<"$record"
  case "$code" in
    V) echo "valid ${serial:- -}" ;;
    R) echo "revoked ${serial:- -}" ;;
    E) echo "expired ${serial:- -}" ;;
    missing) echo "missing -" ;;
    *) echo "unknown ${serial:- -}" ;;
  esac
}

archive_easyrsa_client_files() {
  local name="$1"
  local base="$EASYRSA_DIR/pki"
  local ts dest moved=0
  ts=$(date +%Y%m%d-%H%M%S)
  dest="$WORKDIR/backups/revoked-${name}-${ts}"

  local rel
  for rel in "private/${name}.key" "issued/${name}.crt" "reqs/${name}.req"; do
    if [[ -e "$base/$rel" ]]; then
      if (( moved == 0 )); then
        install -d "$dest"
      fi
      mv "$base/$rel" "$dest/"
      moved=1
    fi
  done

  if (( moved > 0 )); then
    ok "已将 ${name} 的 Easy-RSA 资料归档到 $dest"
    return 0
  fi

  return 1
}

ensure_tls_cipher_consistency() {
  local conf="$SERVER_DIR/${SERVER_NAME}.conf"
  [[ -f "$conf" ]] || return 0

  local current=""
  current=$(grep -E '^tls-cipher' "$conf" | head -n1 | sed 's/^tls-cipher[[:space:]]*//') || true

  if [[ -n "$current" ]]; then
    if [[ "$current" == "$TLSCIPHERS" ]]; then
      return 0
    fi
    backup_file "$conf"
    sed -i "s|^tls-cipher .*|tls-cipher ${TLSCIPHERS}|" "$conf"
    TLS_CIPHER_NOTICE="检测到服务端 tls-cipher 列表已被更新为最新兼容配置，记得在菜单选择“重启服务”让其生效。"
    return 0
  fi

  backup_file "$conf"
  awk -v newline="tls-cipher ${TLSCIPHERS}" '
    {print}
    $0 ~ /^tls-version-min/ && !inserted {print newline; inserted=1}
    END {
      if (!inserted) print newline
    }
  ' "$conf" > "${conf}.tmp"
  mv "${conf}.tmp" "$conf"
  TLS_CIPHER_NOTICE="检测到服务端缺少 tls-cipher 指令，已自动补充。请在菜单选择“重启服务”让其生效。"
}

normalize_cidr() {
  local cidr="${1:-}"
  [[ -n "$cidr" ]] || return 1

  local normalized
  if ! normalized=$(
    python3 - "$cidr" <<'PY' 2>/dev/null
import sys, ipaddress
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except Exception:
    sys.exit(1)
if net.version != 4:
    sys.exit(1)
print(net.with_prefixlen)
PY
  ); then
    return 1
  fi

  [[ -n "${normalized:-}" ]] || return 1
  echo "$normalized"
}

cidr_prefix_to_netmask() {
  local prefix="${1:-}"
  [[ -n "$prefix" ]] || return 1

  local netmask
  if ! netmask=$(
    python3 - "$prefix" <<'PY' 2>/dev/null
import sys, ipaddress
try:
    prefix = int(sys.argv[1])
except Exception:
    sys.exit(1)
if not 0 <= prefix <= 32:
    sys.exit(1)
net = ipaddress.ip_network(f"0.0.0.0/{prefix}", strict=False)
print(net.netmask)
PY
  ); then
    return 1
  fi

  [[ -n "${netmask:-}" ]] || return 1
  echo "$netmask"
}
# ======================= 步骤函数 =======================
install_packages() {
  info "更新 apt 并安装 openvpn / easy-rsa / ufw..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa ufw

  # 安装后检查 OpenVPN 版本
  check_openvpn_version
}

init_pki() {
  info "初始化 Easy-RSA PKI... (工作区：$EASYRSA_DIR)"
  install -d "$EASYRSA_DIR"
  if [[ ! -d "$EASYRSA_DIR/.git" && ! -f "$EASYRSA_DIR/easyrsa" ]]; then
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
  fi
  pushd "$EASYRSA_DIR" >/dev/null

  # 配置使用 ECC
  if ! grep -q "EASYRSA_ALGO" vars 2>/dev/null; then
cat >> vars <<EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE ${ECDH_CURVE}
EOF
  fi

  ok "将使用 ECC（${ECDH_CURVE}）生成证书。"

  if [[ ! -d pki ]]; then
    ./easyrsa --batch init-pki
  fi

  if [[ ! -f pki/ca.crt ]]; then
    warn "将生成 CA（无口令）。如需手动设口令，请中止后自行运行：./easyrsa build-ca"
    ./easyrsa --batch build-ca nopass
  else
    ok "已存在 CA，跳过。"
  fi

  if [[ ! -f "pki/private/${SERVER_NAME}.key" ]]; then
    info "生成服务器证书请求..."
    ./easyrsa --batch gen-req "${SERVER_NAME}" nopass
    info "签发服务器证书..."
    ./easyrsa --batch sign-req server "${SERVER_NAME}" <<< "yes"
  else
    ok "已存在服务器证书，跳过。"
  fi
  popd >/dev/null
}

stage_server_files() {
  info "整理服务端证书/密钥到 ${SERVER_DIR} ..."
  install -d "$SERVER_DIR"
  install -m 600 "$EASYRSA_DIR/pki/private/${SERVER_NAME}.key" "$SERVER_DIR/${SERVER_NAME}.key"
  install -m 644 "$EASYRSA_DIR/pki/issued/${SERVER_NAME}.crt" "$SERVER_DIR/${SERVER_NAME}.crt"
  install -m 644 "$EASYRSA_DIR/pki/ca.crt" "$SERVER_DIR/ca.crt"

  # 生成 tls-crypt 密钥
  if [[ ! -f "$SERVER_DIR/ta.key" ]]; then
    # OpenVPN 2.6+ 推荐使用 tls-crypt-v2，但为了兼容性使用 secret
    openvpn --genkey secret "$SERVER_DIR/ta.key"
  fi

  # 生成 DH 参数（即使使用 ECC 证书，某些 OpenVPN 版本仍需要）
  if [[ ! -f "$SERVER_DIR/dh.pem" ]]; then
    info "生成 Diffie-Hellman 参数（2048位，需要1-2分钟）..."
    openssl dhparam -out "$SERVER_DIR/dh.pem" 2048
  fi
}

write_server_conf() {
  local srv="$1" port="$2" proto="$3" net="$4" dns1="$5" dns2="$6"
  info "写入服务端配置 /etc/openvpn/server/${SERVER_NAME}.conf ..."
  backup_file "$SERVER_DIR/${SERVER_NAME}.conf"

  local normalized_net net_addr prefix netmask
  if ! normalized_net=$(normalize_cidr "$net"); then
    err "VPN 网段 ${net} 非法，请重新指定 (示例: 10.8.0.0/24)。"
    return 1
  fi
  net_addr="${normalized_net%/*}"
  prefix="${normalized_net#*/}"
  if ! netmask=$(cidr_prefix_to_netmask "$prefix"); then
    err "无法从前缀 ${prefix} 计算掩码，请检查输入。"
    return 1
  fi

  cat >"$SERVER_DIR/${SERVER_NAME}.conf" <<EOF
port ${port}
proto ${proto}
dev tun

user nobody
group nogroup
persist-key
persist-tun
topology subnet

server ${net_addr} ${netmask}
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS ${dns1}"
push "dhcp-option DNS ${dns2}"

data-ciphers ${DATACIPHERS}
data-ciphers-fallback AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher ${TLSCIPHERS}
# 使用 tls-groups 替代 ecdh-curve（OpenVPN 2.6+ 推荐）
tls-groups ${ECDH_CURVE}

ca ${SERVER_DIR}/ca.crt
cert ${SERVER_DIR}/${SERVER_NAME}.crt
key ${SERVER_DIR}/${SERVER_NAME}.key
dh ${SERVER_DIR}/dh.pem

tls-crypt ${SERVER_DIR}/ta.key

keepalive 10 120
status /var/log/openvpn-status.log
verb 3

# 如需启用 CRL，请取消下一行注释,并在吊销客户端后生成 CRL：
# crl-verify ${SERVER_DIR}/crl.pem
EOF
}

enable_ip_forward() {
  info "开启 IPv4 转发..."
  backup_file "$SYSCTL_FILE"
  echo 'net.ipv4.ip_forward=1' > "$SYSCTL_FILE"
  sysctl --system >/dev/null
}

setup_ufw_nat() {
  local net="$1" iface="$2" port="$3" proto="$4"
  info "配置 UFW 端口放行与 NAT (出口网卡: ${iface})..."

  # 放行端口与 SSH
  ufw allow OpenSSH >/dev/null 2>&1 || true
  ufw allow ${port}/${proto} >/dev/null 2>&1 || true

  # 写 NAT 规则（带标记，方便卸载）
  backup_file "$UFW_BEFORE_RULES"
  if ! grep -q "$NAT_TAG_BEGIN" "$UFW_BEFORE_RULES" 2>/dev/null; then
    # 创建临时文件存储 NAT 规则
    local nat_rules=$(cat <<'NATRULES'
# OVPNX-START
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s NET_PLACEHOLDER -o IFACE_PLACEHOLDER -j MASQUERADE
COMMIT
# OVPNX-END

NATRULES
)
    # 替换占位符
    nat_rules="${nat_rules//NET_PLACEHOLDER/$net}"
    nat_rules="${nat_rules//IFACE_PLACEHOLDER/$iface}"

    # 在 *filter 表之前插入 NAT 规则
    if grep -q '^\*filter' "$UFW_BEFORE_RULES"; then
      # 在 *filter 行之前插入
      awk -v rules="$nat_rules" '/^\*filter/ {print rules} {print}' "$UFW_BEFORE_RULES" > "$UFW_BEFORE_RULES.tmp"
      mv "$UFW_BEFORE_RULES.tmp" "$UFW_BEFORE_RULES"
    else
      # 如果没有 *filter 标记，插入到文件开头（跳过 shebang 和注释）
      awk -v rules="$nat_rules" 'NR==1 {print; print rules; next} {print}' "$UFW_BEFORE_RULES" > "$UFW_BEFORE_RULES.tmp"
      mv "$UFW_BEFORE_RULES.tmp" "$UFW_BEFORE_RULES"
    fi
  fi

  # 转发策略
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

  # 启用 UFW（若未启用）
  if ! ufw status | grep -q "Status: active"; then
    ufw --force enable
  else
    ufw reload
  fi
}

start_service() {
  info "启用并启动服务 ${SERVICE_NAME} ..."
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  # 等待服务启动并检查状态
  local max_wait=10
  local count=0
  while [[ $count -lt $max_wait ]]; do
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      ok "服务启动成功！"
      systemctl --no-pager --full status "$SERVICE_NAME" | sed -n '1,50p'
      return 0
    fi
    ((count++))
  done

  # 启动失败，显示详细错误信息
  err "服务启动失败！请查看以下日志："
  systemctl --no-pager --full status "$SERVICE_NAME" || true
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
  return 1
}

make_client() {
  local NAME="$1"
  [[ -n "$NAME" ]] || { err "用法: make_client <name>"; return 1; }

  local status_info status serial need_new=0
  status_info=$(get_client_cert_state "$NAME")
  read -r status serial <<<"$status_info"

  case "$status" in
    revoked|expired)
      warn "检测到 ${NAME} 的证书状态为 ${status}（序列号: ${serial}），将归档旧文件后重新签发。"
      archive_easyrsa_client_files "$NAME" || true
      need_new=1
      ;;
    missing|unknown)
      need_new=1
      ;;
    valid)
      if [[ ! -f "$EASYRSA_DIR/pki/private/${NAME}.key" || ! -f "$EASYRSA_DIR/pki/issued/${NAME}.crt" ]]; then
        warn "索引记录 ${NAME} 为有效，但证书文件缺失，将重新签发。"
        archive_easyrsa_client_files "$NAME" || true
        need_new=1
      fi
      ;;
  esac

  pushd "$EASYRSA_DIR" >/dev/null
  if (( need_new )) || [[ ! -f "pki/private/${NAME}.key" || ! -f "pki/issued/${NAME}.crt" ]]; then
    info "生成客户端证书 ${NAME} ..."
    ./easyrsa --batch gen-req "$NAME" nopass
    ./easyrsa --batch sign-req client "$NAME" <<< "yes"
  else
    ok "已存在客户端证书 $NAME ，保持当前证书。"
  fi
  popd >/dev/null

  local C_DIR="$WORKDIR/clients/$NAME"
  install -d "$C_DIR"
  cp "$EASYRSA_DIR/pki/ca.crt" "$C_DIR/"
  cp "$EASYRSA_DIR/pki/issued/${NAME}.crt" "$C_DIR/"
  cp "$EASYRSA_DIR/pki/private/${NAME}.key" "$C_DIR/"
  cp "$SERVER_DIR/ta.key" "$C_DIR/"

  local SRV_HOST=""
  while [[ -z "${SRV_HOST// }" ]]; do
    read -r -p "请输入服务器 公网IP或域名(留空默认自动检测)：" SRV_HOST || true

    if [[ -n "${SRV_HOST// }" ]]; then
      SRV_HOST="${SRV_HOST//[[:space:]]/}"
      break
    fi

    info "正在自动检测服务器地址..."

    SRV_HOST=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || \
               curl -s -4 --max-time 5 icanhazip.com 2>/dev/null || \
               curl -s -4 --max-time 5 ipinfo.io/ip 2>/dev/null || true)

    if [[ -z "${SRV_HOST// }" ]]; then
      local def_if=""
      def_if=$(default_iface 2>/dev/null || true)
      warn "无法通过公网接口获取地址，尝试使用本地网络接口 IP。"
      if [[ -n "${def_if// }" ]]; then
        SRV_HOST=$(ip -4 addr show "$def_if" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
      fi
    fi

    if [[ -z "${SRV_HOST// }" ]]; then
      SRV_HOST=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^[0-9.]+$/) {print $i; exit}}')
    fi

    if [[ -z "${SRV_HOST// }" ]]; then
      err "自动检测服务器地址失败，请手动输入有效的公网 IP 或域名。"
    else
      info "检测到服务器地址: $SRV_HOST"
    fi
  done

  SRV_HOST="${SRV_HOST//[[:space:]]/}"

  local OVPN="$C_DIR/${NAME}.ovpn"
  cat >"$OVPN" <<EOF
client
dev tun
proto ${PROTO}
remote ${SRV_HOST} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
data-ciphers ${DATACIPHERS}
tls-version-min 1.2
tls-cipher ${TLSCIPHERS}
verb 3
setenv opt block-outside-dns
<ca>
$(cat "$C_DIR/ca.crt")
</ca>
<cert>
$(cat "$C_DIR/${NAME}.crt")
</cert>
<key>
$(cat "$C_DIR/${NAME}.key")
</key>
<tls-crypt>
$(cat "$C_DIR/ta.key")
</tls-crypt>
EOF
  ok "已生成客户端：$OVPN"
  echo "可下载命令示例（在本地电脑执行）："
  echo "scp -P 22 root@${SRV_HOST}:$OVPN ./"
}

remove_client_files() {
  local name="$1"
  [[ -n "${name:-}" ]] || return 1

  local clients_base="$WORKDIR/clients"
  local client_dir="$clients_base/$name"
  local removed=0

  if [[ -d "$client_dir" ]]; then
    rm -rf "$client_dir"
    ok "已删除目录: ${client_dir}"
    removed=1
  fi

  local legacy_file
  for legacy_file in "${clients_base}/${name}.ovpn" "${clients_base}/${name}.crt" "${clients_base}/${name}.key"; do
    if [[ -e "$legacy_file" ]]; then
      rm -f "$legacy_file"
      removed=1
    fi
  done

  if (( removed > 0 )); then
    return 0
  fi
  return 1
}

list_clients() {
  local idx="$EASYRSA_DIR/pki/index.txt"
  [[ -f "$idx" ]] || { warn "未找到 $idx"; return 0; }
  echo
  ok "当前证书状态 (仅显示最新记录)："

  local -a status_lines=()
  mapfile -t status_lines < <(
    awk '
      /^[VR]/ {
        if (match($0, /CN=([^\/]+)/, arr)) {
          name = arr[1]
          status = substr($0, 1, 1)
          order[name] = NR
          state[name] = status
        }
      }
      END {
        for (name in state) {
          printf "%09d\t%s\t%s\n", order[name], state[name], name
        }
      }
    ' "$idx" | sort -n
  )

  if ((${#status_lines[@]} == 0)); then
    info "未找到任何证书记录。"
  else
    local line order status name
    for line in "${status_lines[@]}"; do
      IFS=$'\t' read -r order status name <<<"$line"
      case "$status" in
        V) printf "有效\t%s\n" "$name" ;;
        R) printf "吊销\t%s\n" "$name" ;;
        *) printf "%s\t%s\n" "$status" "$name" ;;
      esac
    done
  fi
  echo
}

revoke_client() {
  local NAME
  read -r -p "输入要吊销的客户端名称：" NAME || true
  [[ -n "${NAME:-}" ]] || { warn "未输入名称"; return 0; }

  if [[ ! -d "$EASYRSA_DIR" ]]; then
    warn "未找到 Easy-RSA 目录 (${EASYRSA_DIR})，请先执行安装/初始化。"
    return 0
  fi

  if ! pushd "$EASYRSA_DIR" >/dev/null; then
    warn "无法进入 Easy-RSA 目录 (${EASYRSA_DIR})。"
    return 0
  fi

  if ! ./easyrsa --batch revoke "$NAME" <<< "yes"; then
    warn "吊销 ${NAME} 失败，可能不存在对应的证书。"
    popd >/dev/null || true
    return 0
  fi

  if ! ./easyrsa --batch gen-crl; then
    warn "生成吊销列表失败，请检查 Easy-RSA 状态。"
    popd >/dev/null || true
    return 0
  fi

  popd >/dev/null || true

  if ! install -m 644 "$EASYRSA_DIR/pki/crl.pem" "$SERVER_DIR/crl.pem"; then
    warn "无法更新服务器端 CRL 文件，请手动检查。"
    return 0
  fi

  # 确保 server.conf 启用 crl-verify
  if ! grep -q '^crl-verify ' "$SERVER_DIR/${SERVER_NAME}.conf"; then
    echo "crl-verify ${SERVER_DIR}/crl.pem" >> "$SERVER_DIR/${SERVER_NAME}.conf"
  fi
  if ! systemctl reload "$SERVICE_NAME"; then
    warn "服务不支持 reload，执行 restart..."
    systemctl restart "$SERVICE_NAME"
  fi
  ok "已吊销 ${NAME} 并生成/应用 CRL。"

  # 询问是否删除已吊销证书的文件
  read -r -p "是否删除已吊销证书 ${NAME} 的相关文件？[y/N]: " del_files
  if [[ "${del_files,,}" == "y" ]]; then
    local cleaned=0
    if remove_client_files "$NAME"; then
      cleaned=1
    fi
    if archive_easyrsa_client_files "$NAME"; then
      cleaned=1
    fi

    if (( cleaned > 0 )); then
      ok "已清理 ${NAME} 的客户端资料。"
    else
      info "未发现 ${NAME} 的客户端资料可清理。"
    fi
  fi
}

clean_revoked_certs() {
  local idx="$EASYRSA_DIR/pki/index.txt"
  [[ -f "$idx" ]] || { warn "证书索引文件不存在"; return 0; }

  echo
  info "扫描已吊销的证书..."
  local revoked_list=$(awk '/^R/ {match($0, /CN=([^\/]+)/, arr); print arr[1]}' "$idx" | sort -u)

  if [[ -z "$revoked_list" ]]; then
    ok "没有已吊销的证书。"
    return 0
  fi

  echo "已吊销的证书："
  echo "$revoked_list" | nl
  echo

  read -r -p "是否删除所有已吊销证书的客户端文件？[y/N]: " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    info "已取消。"
    return 0
  fi

  local count=0 skipped=0
  while IFS= read -r name; do
    if [[ -n "$name" ]]; then
      local status_info status _
      status_info=$(get_client_cert_state "$name")
      read -r status _ <<<"$status_info"
      if [[ "$status" == "valid" ]]; then
        info "跳过 ${name} （当前存在有效证书）。"
        ((skipped++))
        continue
      fi

      local cleaned=0
      if remove_client_files "$name"; then
        cleaned=1
      fi
      if archive_easyrsa_client_files "$name"; then
        cleaned=1
      fi
      if (( cleaned > 0 )); then
        ((count++))
      fi
    fi
  done <<< "$revoked_list"

  ok "共清理 ${count} 个已吊销证书的相关文件。"
  if (( skipped > 0 )); then
    info "另有 ${skipped} 个名称因已存在新证书而跳过清理。"
  fi
}

show_status() {
  echo
  if ! systemctl --no-pager --full status "$SERVICE_NAME" 2>&1 | sed -n '1,70p'; then
    warn "无法获取服务状态，可能未安装或权限不足。"
  fi
  echo
  echo "最近日志："
  journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
}

uninstall_keep_backup() {
  warn "卸载 OpenVPN（保留 $WORKDIR 与备份）..."
  systemctl stop "$SERVICE_NAME" || true
  systemctl disable "$SERVICE_NAME" || true

  # 还原 sysctl
  if [[ -f "$SYSCTL_FILE" ]]; then
    backup_file "$SYSCTL_FILE"; rm -f "$SYSCTL_FILE"; sysctl --system >/dev/null || true
  fi

  # 移除 UFW NAT 段与端口规则
  if [[ -f "$UFW_BEFORE_RULES" ]]; then
    backup_file "$UFW_BEFORE_RULES"

    # 改进的 AWK 删除逻辑：删除标记行及其之间的所有内容
    awk -v b="$NAT_TAG_BEGIN" -v e="$NAT_TAG_END" '
      BEGIN { skip=0 }
      {
        if (index($0, b)) {
          skip=1
          next
        }
        if (index($0, e)) {
          skip=0
          next
        }
        if (!skip) print
      }
    ' "$UFW_BEFORE_RULES" > "$UFW_BEFORE_RULES.tmp" && mv "$UFW_BEFORE_RULES.tmp" "$UFW_BEFORE_RULES"

    ufw delete allow ${PORT}/${PROTO} >/dev/null 2>&1 || true
    ufw reload || true
  fi

  # 保留 WORKDIR，仅移除 /etc/openvpn/server
  if [[ -d "$SERVER_DIR" ]]; then
    backup_file "$SERVER_DIR/${SERVER_NAME}.conf" || true
    rm -f "$SERVER_DIR/${SERVER_NAME}.conf" "$SERVER_DIR/ta.key" "$SERVER_DIR/${SERVER_NAME}.crt" "$SERVER_DIR/${SERVER_NAME}.key" "$SERVER_DIR/ca.crt" "$SERVER_DIR/crl.pem" "$SERVER_DIR/dh.pem" || true
    rmdir "$SERVER_DIR" 2>/dev/null || true
  fi

  ok "服务卸载完成（已保留 $WORKDIR）。如需彻底清除，请选择菜单：彻底清除。"
}

purge_all() {
  warn "将彻底清除 OpenVPN 与工作区，且不可恢复！"
  read -r -p "确认继续? [y/N] " x
  if [[ "${x,,}" != "y" ]]; then
    warn "已取消。"; return 0
  fi

  uninstall_keep_backup
  apt-get purge -y openvpn easy-rsa || true
  apt-get autoremove -y || true
  rm -rf "$WORKDIR"
  ok "已彻底清除 OpenVPN 与工作区。"
}

# ======================= 一键安装流程 =======================
wizard_install() {
  require_root
  check_system
  ensure_dirs

  local t="" input_net="" normalized_net=""
  while true; do
    read -r -p "设置 VPN 网段 (默认 ${VPN_NET}): " t || true
    input_net=${t:-$VPN_NET}
    if normalized_net=$(normalize_cidr "$input_net"); then
      VPN_NET="$normalized_net"
      break
    fi
    err "输入 \"${input_net}\" 不是合法的 IPv4 CIDR 网段 (示例: 10.8.0.0/24)，请重试。"
  done

  read -r -p "监听端口 (默认 ${PORT}): " t || true
  PORT=${t:-$PORT}

  read -r -p "协议 udp/tcp (默认 ${PROTO}): " t || true
  PROTO=${t:-$PROTO}

  read -r -p "DNS1 (默认 ${DNS1}): " t || true
  DNS1=${t:-$DNS1}
  read -r -p "DNS2 (默认 ${DNS2}): " t || true
  DNS2=${t:-$DNS2}

  local IFACE; IFACE=$(default_iface)
  read -r -p "出口网卡 (默认 ${IFACE}): " t || true
  IFACE=${t:-$IFACE}

  install_packages
  init_pki
  stage_server_files
  write_server_conf "${SERVER_NAME}" "$PORT" "$PROTO" "$VPN_NET" "$DNS1" "$DNS2"
  enable_ip_forward
  setup_ufw_nat "$VPN_NET" "$IFACE" "$PORT" "$PROTO"

  if start_service; then
    ok "安装完成！下一步可在菜单中生成客户端配置。"
  else
    err "服务启动失败，请检查配置和日志。"
    warn "可以尝试手动运行: systemctl status $SERVICE_NAME"
    return 1
  fi
}

# ======================= 主菜单 =======================
menu() {
  clear

  # 获取系统和 OpenVPN 版本信息
  local sys_info="" ovpn_info=""
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    sys_info="Ubuntu $VERSION_ID"
  fi

  if command -v openvpn &>/dev/null; then
    local ovpn_ver
    ovpn_ver=$(openvpn --version 2>&1 | head -n1 | grep -oP 'OpenVPN \K[0-9.]+' || echo "unknown")
    ovpn_info="OpenVPN $ovpn_ver"
  else
    ovpn_info="未安装"
  fi

 cat <<EOF
$(ok "OpenVPN 管理脚本 ovpnx.sh")
系统: $sys_info | $ovpn_info
工作区: $WORKDIR
服务端配置: $SERVER_DIR/${SERVER_NAME}.conf
服务名: $SERVICE_NAME

1) 安装 / 初始化（向导）
2) 生成客户端 .ovpn（内联证书）
3) 列出证书 (有效/吊销)
4) 吊销客户端证书
5) 清理已吊销证书的文件
6) 查看服务状态与日志
7) 重启服务
8) 卸载（保留工作区与备份）
9) 彻底清除（含工作区与包）
0) 退出
EOF
  if [[ -n "$TLS_CIPHER_NOTICE" ]]; then
    warn "$TLS_CIPHER_NOTICE"
    echo
    TLS_CIPHER_NOTICE=""
  fi
  read -r -p "请选择 [0-9]: " ans || true
  case "${ans:-}" in
    1) wizard_install; pause ;;
    2) read -r -p "输入客户端名称: " cname; [[ -n "${cname:-}" ]] && make_client "$cname"; pause ;;
    3) list_clients; pause ;;
    4) revoke_client; pause ;;
    5) clean_revoked_certs; pause ;;
    6) show_status; pause ;;
    7) if systemctl restart "$SERVICE_NAME"; then ok "已重启。"; else warn "重启失败，请确认服务是否已安装。"; fi; pause ;;
    8) uninstall_keep_backup; pause ;;
    9) purge_all; pause ;;
    0) exit 0 ;;
    *) ;;
  esac
}

# ======================= 入口 =======================
require_root
ensure_dirs
ensure_tls_cipher_consistency
while true; do menu; done
