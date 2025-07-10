#!/bin/bash

# 自用 sing-box 服务端配置脚本

# --- 安全设置 ---
# set -e: 如果命令失败，立即退出
# set -u: 将未设置的变量视为错误
# set -o pipefail: 管道中任何命令失败，整个管道都失败
set -euo pipefail

# --- 配置 ---
SINGBOX_EXEC="/usr/bin/sing-box"
CONFIG_FILE="/etc/sing-box/config.json"
LOG_FILE="/var/log/sing-box.log"
CERT_DIR="/etc/sing-box/cert"

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 基础函数 ---

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 此操作需要root权限。请使用 'sudo' 运行。${NC}"
        exit 1
    fi
}

validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${RED}错误: 端口必须是1-65535之间的数字。${NC}"
        return 1
    fi
    return 0
}

check_port() {
    local port=$1
    if ! validate_port "$port"; then
        return 1
    fi
    if ss -tlnp | grep -q ":${port}\b"; then
        echo -e "${RED}错误: 端口 ${port} 已被占用。${NC}"
        return 1
    fi
    return 0
}

get_server_ip() {
    local ip
    ip=$(curl -s4 --connect-timeout 10 https://api.ipify.org || curl -s6 --connect-timeout 10 https://api64.ipify.org)
    if [ -z "${ip}" ]; then
        echo -e "${RED}错误: 无法获取公网 IP 地址。请检查网络连接。${NC}" >&2
        return 1
    fi
    echo "${ip}"
}

backup_config() {
    if [ -f "$CONFIG_FILE" ]; then
        local backup_file="${CONFIG_FILE}.backup.$(date +%s)"
        cp "$CONFIG_FILE" "$backup_file"
        echo -e "${GREEN}配置已备份到: $backup_file${NC}"
    fi
}

check_singbox_status() {
    if command -v "$SINGBOX_EXEC" &> /dev/null; then
        local version=$(${SINGBOX_EXEC} version 2>/dev/null | head -1)
        echo -e "${GREEN}✓ sing-box 已安装${NC} - 版本: ${version}"
        
        if systemctl is-active --quiet sing-box; then
            echo -e "${GREEN}✓ sing-box 服务运行中${NC}"
            local uptime=$(systemctl show sing-box --property=ActiveEnterTimestamp --value)
            if [ -n "$uptime" ]; then
                echo -e "${CYAN}  启动时间: ${uptime}${NC}"
            fi
        else
            echo -e "${YELLOW}✗ sing-box 服务未运行${NC}"
        fi
    else
        echo -e "${RED}✗ sing-box 未安装${NC}"
    fi
    echo
}

show_error_log() {
    echo -e "${YELLOW}服务可能启动失败，请检查日志。${NC}"
    journalctl -u sing-box --no-pager -l | tail -n 20
}

# --- 核心功能 ---

install_singbox() {
    check_root
    echo -e "${YELLOW}正在安装 sing-box...${NC}"
    
    # 先安装基础依赖
    local packages_to_install=()
    for dep in jq curl openssl; do
        if ! command -v "$dep" &> /dev/null; then
            packages_to_install+=("$dep")
        fi
    done
    
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        echo -e "${YELLOW}正在安装基础依赖: ${packages_to_install[*]}...${NC}"
        apt-get update
        apt-get install -y "${packages_to_install[@]}"
    fi

    # 添加 sing-box 仓库
    if [ ! -f "/etc/apt/sources.list.d/sagernet.sources" ]; then
        echo -e "${YELLOW}正在添加 sing-box 仓库...${NC}"
        mkdir -p /etc/apt/keyrings
        if ! curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc; then
            echo -e "${RED}下载GPG密钥失败${NC}"
            return 1
        fi
        chmod a+r /etc/apt/keyrings/sagernet.asc
        cat > /etc/apt/sources.list.d/sagernet.sources << 'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
    fi
    
    # 安装 sing-box
    echo -e "${YELLOW}正在安装 sing-box...${NC}"
    apt-get update
    apt-get install -y sing-box-beta

    if ! command -v "$SINGBOX_EXEC" &> /dev/null; then
        echo -e "${RED}sing-box 安装失败! 未在 ${SINGBOX_EXEC} 找到。${NC}"
        return 1
    fi

    # 创建初始配置
    mkdir -p /etc/sing-box
    mkdir -p "$CERT_DIR"
    chown sing-box:sing-box "$CERT_DIR" 2>/dev/null || true
    # --- 配置文件处理 ---
    # 安装时，无条件覆盖配置文件，确保使用的是脚本定义的默认配置。
    echo -e "${YELLOW}正在创建/覆盖初始配置文件...${NC}"
    backup_config
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}jq 未安装，无法创建配置文件${NC}"; return 1
    fi
    
    # 直接覆盖或创建文件，不备份
    jq -n '{
        "log": { "disabled": false, "level": "warn", "output": "/var/log/sing-box.log", "timestamp": true },
        "dns": {},
        "inbounds": [],
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "route": {
            "rules": [
                { "ip_is_private": true, "action": "reject" },
                { "rule_set": ["geoip-cn"], "action": "reject" }
            ],
            "rule_set": [
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                    "download_detour": "direct"
                }
            ],
            "final": "direct"
        }
    }' > "$CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}创建配置文件失败${NC}"; return 1
    fi
    echo -e "${GREEN}配置文件创建/覆盖成功。${NC}"

    # 创建日志文件
    touch "$LOG_FILE"
    chown sing-box:sing-box "$LOG_FILE" 2>/dev/null || true
    
    # 启用服务
    systemctl enable sing-box
    systemctl start sing-box
    
    sleep 2  # 等待服务启动
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}sing-box 安装并启动成功! 版本: $(${SINGBOX_EXEC} version)${NC}"
    else
        echo -e "${YELLOW}sing-box 已安装，但服务启动可能有问题。${NC}"
        echo -e "${YELLOW}请检查配置文件: $CONFIG_FILE${NC}"
        show_error_log
    fi
}

update_singbox() {
    check_root
    if ! command -v "$SINGBOX_EXEC" &> /dev/null; then
        echo -e "${RED}sing-box 未安装，请先安装。${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}正在更新 sing-box...${NC}"
    echo -e "${CYAN}当前版本: $(${SINGBOX_EXEC} version)${NC}"
    
    apt-get update
    apt-get install -y --only-upgrade sing-box-beta
    
    echo -e "${YELLOW}正在重新加载 systemd 配置...${NC}"
    systemctl daemon-reload
    
    echo -e "${YELLOW}正在重启 sing-box 服务...${NC}"
    systemctl restart sing-box
    
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}更新成功! 新版本: $(${SINGBOX_EXEC} version)${NC}"
    else
        echo -e "${RED}服务重启失败，请检查日志。${NC}"
        show_error_log
    fi
}

update_config_and_restart() {
    check_root
    local new_config_json=$1
    local temp_file=""
    
    # Set trap to clean up temp file on exit, works with set -e
    trap 'rm -f "${temp_file}"' EXIT

    temp_file=$(mktemp) || { echo -e "${RED}无法创建临时文件。${NC}"; return 1; }

    echo "${new_config_json}" > "${temp_file}"

    echo -e "${YELLOW}正在检查配置...${NC}"
    if ! ${SINGBOX_EXEC} check -c "${temp_file}"; then
        echo -e "${RED}新配置无效，配置未应用。${NC}"
        # The trap will clean up the temp file on exit
        return 1
    fi

    echo -e "${GREEN}配置检查通过。${NC}"
    backup_config
    mv "${temp_file}" "$CONFIG_FILE"
    
    # After moving, clear the var so the trap on exit does nothing to a non-existent file
    temp_file=""
    trap - EXIT # Disable the trap

    echo -e "${YELLOW}正在重启 sing-box...${NC}"
    systemctl restart sing-box
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}服务重启成功。${NC}"
    else
        echo -e "${RED}服务重启失败! 请检查日志。${NC}"
        show_error_log
    fi
}

# 简化版：确保自签名证书存在。如果不存在，则创建。
generate_self_signed_cert() {
    check_root
    local key_path=$1
    local crt_path=$2
    local server_name=$3

    # 如果证书文件已存在，直接返回路径，不再询问
    if [ -f "${key_path}" ] && [ -f "${crt_path}" ]; then
        echo -e "${GREEN}检测到现有自签名证书，将直接使用: ${crt_path}${NC}" >&2
        echo "${key_path}|${crt_path}"
        return 0
    fi
    
    # 确保证书目录存在
    mkdir -p "$(dirname "${key_path}")"
    
    echo -e "${YELLOW}为 ${server_name} 生成新的自签名证书...${NC}" >&2
    echo -e "${CYAN}密钥文件: ${key_path}${NC}" >&2
    echo -e "${CYAN}证书文件: ${crt_path}${NC}" >&2
    
    openssl ecparam -genkey -name prime256v1 -out "${key_path}"
    openssl req -new -x509 -days 3650 -key "${key_path}" -out "${crt_path}" -subj "/CN=${server_name}"
    echo -e "${GREEN}证书已生成。${NC}" >&2
    
    # 返回文件路径
    echo "${key_path}|${crt_path}"
}

_handle_tls_setup() {
    local protocol_name=$1
    local alpn_json=$2
    local cert_choice

    # Reset global variables
    TLS_CONFIG_JSON=""
    CLASH_SERVER=""
    CLASH_SKIP_CERT_VERIFY=""
    CERT_DOMAIN=""

    echo "请选择证书类型:"
    echo "  1) 自签名证书 (默认)"
    echo "  2) ACME 自动申请"
    read -p "请选择 [1-2]: " cert_choice
    cert_choice=${cert_choice:-1}

    if [ "$cert_choice" = "2" ]; then
        echo -e "\n${YELLOW}警告: ACME申请需要80和443端口，请确保它们未被Caddy/Nginx等服务占用。${NC}"
        read -r -p "确认端口可用后，按 Enter键 继续..."
        
        read -r -p "请输入证书域名 (必须解析到本机IP): " cert_domain_input
        if [ -z "$cert_domain_input" ]; then echo -e "${RED}证书域名不能为空。${NC}"; return 1; fi
        CERT_DOMAIN="$cert_domain_input"

        echo -e "${YELLOW}正在检查并设置证书目录权限...${NC}"
        mkdir -p "$CERT_DIR"
        if ! chown -R sing-box:sing-box "$CERT_DIR" 2>/dev/null; then
            echo -e "${YELLOW}警告: 无法将证书目录所有者更改为 sing-box。如果 ACME 失败，请手动执行 'sudo chown -R sing-box:sing-box ${CERT_DIR}'。${NC}"
        fi

        local cert_file="${CERT_DIR}/certificates/${CERT_DOMAIN}.crt"
        local key_file="${CERT_DIR}/certificates/${CERT_DOMAIN}.key"

        if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
            echo -e "${GREEN}检测到域名 ${CERT_DOMAIN} 的现有ACME证书，将直接使用。${NC}"
            TLS_CONFIG_JSON=$(jq -n --arg server_name "$CERT_DOMAIN" --arg key_path "$key_file" --arg crt_path "$cert_file" '{
                "enabled": true, "server_name": $server_name,
                "key_path": $key_path, "certificate_path": $crt_path
            }')
        else
            echo -e "${YELLOW}未找到现有证书，将为 ${CERT_DOMAIN} 申请新的ACME证书。${NC}"
            read -p "请输入用于 ACME 的邮箱 (默认 admin@gmail.com): " acme_email
            acme_email=${acme_email:-admin@gmail.com}
            TLS_CONFIG_JSON=$(jq -n --arg server_name "$CERT_DOMAIN" --arg acme_email "$acme_email" --arg cert_dir "$CERT_DIR" '{
                "enabled": true, "server_name": $server_name,
                "acme": { "domain": $server_name, "email": $acme_email, "disable_http_challenge": true, "data_directory": $cert_dir }
            }')
        fi
        CLASH_SERVER="$CERT_DOMAIN"
        CLASH_SKIP_CERT_VERIFY=false
    else
        # 对于自签名证书，使用固定的域名，不再询问用户
        CERT_DOMAIN="www.swift.com"
        echo -e "${CYAN}正在为自签名证书准备环境，使用默认域名: ${CERT_DOMAIN}${NC}" >&2
        
        local cert_paths
        cert_paths=$(generate_self_signed_cert "${CERT_DIR}/${protocol_name}.key" "${CERT_DIR}/${protocol_name}.crt" "${CERT_DOMAIN}")
        local key_path=$(echo "$cert_paths" | cut -d'|' -f1)
        local crt_path=$(echo "$cert_paths" | cut -d'|' -f2)
        
        TLS_CONFIG_JSON=$(jq -n --arg server_name "$CERT_DOMAIN" --arg key_path "$key_path" --arg crt_path "$crt_path" '{
            "enabled": true, "server_name": $server_name,
            "key_path": $key_path, "certificate_path": $crt_path
        }')
        
        local server_ip
        server_ip=$(get_server_ip) || return 1
        CLASH_SERVER="$server_ip"
        CLASH_SKIP_CERT_VERIFY=true
    fi

    if [ "$alpn_json" != "null" ]; then
        TLS_CONFIG_JSON=$(echo "$TLS_CONFIG_JSON" | jq --argjson alpn "$alpn_json" '. + {alpn: $alpn}')
    fi
    
    return 0
}

# --- 节点配置函数 ---

add_inbound_config() {
    local inbound_json=$1
    if [ -z "${inbound_json}" ]; then
        echo -e "${RED}错误: 传入的配置为空。${NC}" >&2
        return 1
    fi
    
    local new_json
    new_json=$(jq --argjson inbound "${inbound_json}" '.inbounds += [$inbound]' "$CONFIG_FILE")
    
    update_config_and_restart "${new_json}"
}

setup_ss() {
    check_root
    echo -e "${BLUE}=== 配置 Shadowsocks (aes-128-gcm) ===${NC}"
    read -p "请输入端口 (默认 10000): " port
    port=${port:-10000}
    ! check_port "${port}" && return 1
    
    local password=$(${SINGBOX_EXEC} generate rand --base64 16)
    local server_ip
    server_ip=$(get_server_ip) || return 1

    local ss_config=$(jq -n \
        --argjson port "$port" \
        --arg password "$password" \
        '{
            "type": "shadowsocks",
            "tag": ("ss-" + ($port|tostring)),
            "listen": "::",
            "listen_port": $port,
            "method": "aes-128-gcm",
            "password": $password,
            "multiplex": {
                "enabled": true,
                "padding": true
            }
        }')
    
    if add_inbound_config "${ss_config}"; then
        echo -e "\n${GREEN}Shadowsocks (aes-128-gcm) 入站添加成功。${NC}"
        echo -e "${YELLOW}--- Clash YAML 配置 ---${NC}"
        cat <<EOF
proxies:
  - name: "ss-${server_ip}"
    type: ss
    server: ${server_ip}
    port: ${port}
    cipher: aes-128-gcm
    password: ${password}
    smux:
      enabled: true
      padding: true
EOF
    fi
}

setup_ss2022() {
    check_root
    echo -e "${BLUE}=== 配置 Shadowsocks 2022 ===${NC}"
    read -p "请输入端口 (默认 10001): " port
    port=${port:-10001}
    ! check_port "${port}" && return 1
    
    local password=$(${SINGBOX_EXEC} generate rand --base64 16)
    local server_ip
    server_ip=$(get_server_ip) || return 1

    local ss_config=$(jq -n \
        --argjson port "$port" \
        --arg password "$password" \
        '{
            "type": "shadowsocks",
            "tag": ("ss2022-" + ($port|tostring)),
            "listen": "::",
            "listen_port": $port,
            "network": "tcp",
            "method": "2022-blake3-aes-128-gcm",
            "password": $password,
            "multiplex": {
                "enabled": true,
                "padding": true
            }
        }')
    
    if add_inbound_config "${ss_config}"; then
        echo -e "\n${GREEN}Shadowsocks 2022 入站添加成功。${NC}"
        echo -e "${YELLOW}--- Clash YAML 配置 ---${NC}"
        cat <<EOF
proxies:
  - name: "ss2022-${server_ip}"
    type: ss
    server: ${server_ip}
    port: ${port}
    cipher: 2022-blake3-aes-128-gcm
    password: ${password}
    udp-over-tcp: true
    smux:
      enabled: true
      padding: true
EOF
    fi
}

setup_vless() {
    check_root
    echo -e "${BLUE}=== 配置 VLESS+Vision+Reality ===${NC}"
    read -p "请输入端口 (默认 4443): " port
    port=${port:-4443}
    ! check_port "${port}" && return 1

    read -p "请输入伪装域名 (默认 www.swift.com): " server_name
    server_name=${server_name:-www.swift.com}
    
    local uuid=$(${SINGBOX_EXEC} generate uuid)
    local keypair=$(${SINGBOX_EXEC} generate reality-keypair)
    local private_key=$(echo "$keypair" | grep "PrivateKey" | awk '{print $2}')
    local public_key=$(echo "$keypair" | grep "PublicKey" | awk '{print $2}')
    local short_id=$(${SINGBOX_EXEC} generate rand --hex 8)
    local server_ip
    server_ip=$(get_server_ip) || return 1

    local new_tag="vless-${port}"
    local vless_config=$(jq -n \
        --arg tag "$new_tag" \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg server_name "$server_name" \
        --arg private_key "$private_key" \
        --arg short_id "$short_id" \
        '{
            "type": "vless",
            "tag": $tag,
            "listen": "::",
            "listen_port": $port,
            "users": [ { "uuid": $uuid, "flow": "xtls-rprx-vision" } ],
            "tls": {
                "enabled": true,
                "server_name": $server_name,
                "reality": {
                    "enabled": true,
                    "handshake": { "server": $server_name, "server_port": 443 },
                    "private_key": $private_key,
                    "short_id": $short_id
                }
            }
        }')
    
    if add_inbound_config "${vless_config}"; then
        echo -e "\n${GREEN}VLESS 入站添加成功。${NC}"
        echo -e "${YELLOW}--- Clash YAML 配置 ---${NC}"
        cat <<EOF
proxies:
  - name: "vless-${server_ip}"
    type: vless
    server: ${server_ip}
    port: ${port}
    uuid: ${uuid}
    tls: true
    flow: xtls-rprx-vision
    skip-cert-verify: false
    servername: ${server_name}
    reality-opts:
      public-key: ${public_key}
      short-id: ${short_id}
    client-fingerprint: "chrome"
EOF
    fi
}

setup_hysteria2() {
    check_root
    echo -e "${BLUE}=== 配置 Hysteria2 ===${NC}"
    read -p "请输入端口 (默认 10443): " port
    port=${port:-10443}
    ! check_port "${port}" && return 1

    local password
    password=$(${SINGBOX_EXEC} generate rand --base64 16)
    
    # Call the new TLS handler
    if ! _handle_tls_setup "hy2" '["h3"]'; then
        return 1
    fi
    # The helper sets: TLS_CONFIG_JSON, CLASH_SERVER, CLASH_SKIP_CERT_VERIFY, CERT_DOMAIN

    read -p "请输入伪装域名 (默认 www.swift.com): " masquerade_domain
    masquerade_domain=${masquerade_domain:-www.swift.com}

    local hy2_config
    hy2_config=$(jq -n \
        --argjson port "$port" \
        --arg password "$password" \
        --arg masquerade_domain "$masquerade_domain" \
        --argjson tls_config "$TLS_CONFIG_JSON" \
        '{
            "type": "hysteria2",
            "tag": ("hy2-" + ($port|tostring)),
            "listen": "::",
            "listen_port": $port,
            "users": [ { "password": $password } ],
            "masquerade": ("https://" + $masquerade_domain),
            "tls": $tls_config
        }')

    if add_inbound_config "${hy2_config}"; then
        echo -e "\n${GREEN}Hysteria2 入站添加成功。${NC}"
        echo -e "${YELLOW}--- Clash YAML 配置 ---${NC}"
        cat <<EOF
proxies:
  - name: "hy2-${CLASH_SERVER}"
    type: hysteria2
    server: ${CLASH_SERVER}
    port: ${port}
    password: ${password}
    skip-cert-verify: ${CLASH_SKIP_CERT_VERIFY}
    sni: ${CERT_DOMAIN}
    alpn:
      - h3
EOF
    fi
}

setup_anytls() {
    check_root
    echo -e "${BLUE}=== 配置 AnyTLS ===${NC}"
    read -p "请输入端口 (默认 8443): " port
    port=${port:-8443}
    ! check_port "${port}" && return 1

    local password
    password=$(${SINGBOX_EXEC} generate rand --base64 16)

    # Call the new TLS handler, no ALPN for AnyTLS
    if ! _handle_tls_setup "anytls" "null"; then
        return 1
    fi
    # The helper sets: TLS_CONFIG_JSON, CLASH_SERVER, CLASH_SKIP_CERT_VERIFY, CERT_DOMAIN

    local anytls_config
    anytls_config=$(jq -n \
        --argjson port "$port" \
        --arg password "$password" \
        --argjson tls_config "$TLS_CONFIG_JSON" \
        '{
            "type": "anytls",
            "tag": ("anytls-" + ($port|tostring)),
            "listen": "::",
            "listen_port": $port,
            "users": [ { "password": $password } ],
            "tls": $tls_config
        }')
    
    if add_inbound_config "${anytls_config}"; then
        echo -e "\n${GREEN}AnyTLS 入站添加成功。${NC}"
        echo -e "${YELLOW}--- Clash YAML 配置 ---${NC}"
        cat <<EOF
proxies:
  - name: "anytls-${CLASH_SERVER}"
    type: anytls
    server: ${CLASH_SERVER}
    port: ${port}
    password: "${password}"
    tls: true
    skip-cert-verify: ${CLASH_SKIP_CERT_VERIFY}
    sni: ${CERT_DOMAIN}
    client-fingerprint: "chrome"
EOF
    fi
}

setup_port_forward() {
    check_root
    echo -e "${BLUE}=== 配置端口转发 ===${NC}"
    
    read -p "请输入监听端口 (例如 1081): " listen_port
    if [ -z "$listen_port" ]; then
        echo -e "${RED}错误: 监听端口不能为空。${NC}"
        return 1
    fi
    ! check_port "${listen_port}" && return 1

    read -p "请输入目标地址 (IP或域名): " override_address
    if [ -z "$override_address" ]; then
        echo -e "${RED}错误: 目标地址不能为空。${NC}"
        return 1
    fi

    read -p "请输入目标端口: " override_port
    ! validate_port "${override_port}" && return 1

    local new_tag="forward-${listen_port}"
    local forward_config=$(jq -n \
        --arg tag "$new_tag" \
        --argjson listen_port "$listen_port" \
        --arg override_address "$override_address" \
        --argjson override_port "$override_port" \
        '{
            "type": "direct",
            "tag": $tag,
            "listen": "::",
            "listen_port": $listen_port,
            "override_address": $override_address,
            "override_port": $override_port
        }')

    if add_inbound_config "${forward_config}"; then
        echo -e "\n${GREEN}端口转发添加入站成功。${NC}"
        echo -e "${YELLOW}--- 详情 ---${NC}"
        echo "  监听端口: ${listen_port}"
        echo "  目标地址: ${override_address}"
        echo "  目标端口: ${override_port}"
    fi
}

# --- 管理功能 ---

list_inbounds() {
    check_root
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}配置文件不存在。${NC}"
        return 1
    fi
    
    echo -e "${BLUE}=== 当前入站列表 ===${NC}"
    
    local inbounds_info
    inbounds_info=$(jq -r '.inbounds[] | "\(.tag) \(.type) \(.listen_port)"' "$CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$inbounds_info" ]; then
        echo -e "${YELLOW}暂无配置的入站。${NC}"
        return 0
    fi
    
    local i=1
    while read -r tag type port; do
        if [ -n "$tag" ]; then # 确保行不为空
            echo "  $i) $tag - $type - 端口:$port"
            i=$((i+1))
        fi
    done <<< "$inbounds_info"
}

remove_inbound() {
    check_root
    
    # 先显示入站列表
    if ! list_inbounds; then
        return 1
    fi
    
    # 获取入站总数
    local total_inbounds
    total_inbounds=$(jq '.inbounds | length' "$CONFIG_FILE" 2>/dev/null)
    
    if [ "$total_inbounds" -eq 0 ]; then
        echo -e "${YELLOW}暂无可删除的入站。${NC}"
        return 0
    fi
    
    echo
    read -p "请输入要删除的入站序号 [1-${total_inbounds}]: " choice
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "$total_inbounds" ]; then
        echo -e "${RED}无效的序号。${NC}"
        return 1
    fi
    
    # 获取要删除的入站标签 (数组索引从0开始，所以减1)
    local tag_to_remove
    tag_to_remove=$(jq -r ".inbounds[$((choice-1))].tag" "$CONFIG_FILE")
    
    if [ -z "$tag_to_remove" ] || [ "$tag_to_remove" = "null" ]; then
        echo -e "${RED}无法获取入站信息。${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}即将删除入站: $tag_to_remove${NC}"
    read -p "确定要删除吗？(y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消。"
        return 0
    fi
    
    local new_json
    new_json=$(jq "del(.inbounds[$((choice-1))])" "$CONFIG_FILE")
    if update_config_and_restart "${new_json}"; then
        echo -e "${GREEN}入站 '$tag_to_remove' 已删除。${NC}"
    fi
}

view_config() {
    check_root
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}配置文件不存在。${NC}"
        return 1
    fi
    
    echo -e "${BLUE}=== 当前配置文件 ===${NC}"
    if command -v jq &> /dev/null; then
        jq . "$CONFIG_FILE"
    else
        cat "$CONFIG_FILE"
    fi
}

view_status() {
    check_root
    echo -e "${BLUE}=== sing-box 服务状态 ===${NC}"
    systemctl status sing-box --no-pager -l
    echo
    echo -e "${BLUE}=== 最近日志 ===${NC}"
    journalctl -u sing-box --no-pager -l | tail -10
}

view_realtime_log() {
    check_root
    if [ ! -f "$LOG_FILE" ]; then
        echo -e "${RED}日志文件 ${LOG_FILE} 不存在。${NC}"
        return 1
    fi
    echo -e "${YELLOW}正在实时显示应用日志: ${LOG_FILE}... 按 Ctrl+C 退出。${NC}"
    tail -f "$LOG_FILE"
}

start_service() {
    check_root
    echo -e "${YELLOW}正在启动 sing-box 服务...${NC}"
    systemctl start sing-box
    sleep 1
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}服务启动成功。${NC}"
    else
        echo -e "${RED}服务启动失败，请检查日志。${NC}"
        show_error_log
    fi
}

stop_service() {
    check_root
    echo -e "${YELLOW}正在停止 sing-box 服务...${NC}"
    systemctl stop sing-box
    echo -e "${GREEN}服务已停止。${NC}"
}

restart_service() {
    check_root
    echo -e "${YELLOW}正在重启 sing-box 服务...${NC}"
    systemctl restart sing-box
    sleep 1
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}服务重启成功。${NC}"
    else
        echo -e "${RED}服务重启失败，请检查日志。${NC}"
        show_error_log
    fi
}

uninstall_singbox() {
    check_root
    echo -e "${YELLOW}此操作将:${NC}"
    echo "- 停止并禁用 sing-box 服务"
    echo "- 卸载 sing-box"
    echo -e "- ${RED}删除整个 /etc/sing-box 目录 (包含所有配置和证书)${NC}"
    read -p "您确定要继续吗？(y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "操作已取消。"
        return 0
    fi
    
    echo "正在停止并禁用 sing-box 服务..."
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    
    echo "正在卸载 sing-box..."
    apt-get purge -y sing-box sing-box-beta 2>/dev/null || true
    
    echo "正在删除配置文件和证书..."
    rm -rf /etc/sing-box
    
    echo -e "${GREEN}卸载完成。${NC}"
}

# --- 菜单功能 ---

show_add_inbound_menu() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}    添加入站${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
    echo "  1) Shadowsocks"
    echo "  2) Shadowsocks 2022"
    echo "  3) VLESS+Vision+Reality"
    echo "  4) Hysteria2"
    echo "  5) AnyTLS"
    echo "  6) 端口转发 (Direct)"
    echo
    read -p "请选择协议类型 [1-6]: " choice

    case "$choice" in
        1) setup_ss ;;
        2) setup_ss2022 ;;
        3) setup_vless ;;
        4) setup_hysteria2 ;;
        5) setup_anytls ;;
        6) setup_port_forward ;;
        *) echo -e "${RED}无效选择。${NC}"; exit 1 ;;
    esac
}

show_service_menu() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}    服务控制${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
    check_singbox_status
    echo "  1) 启动服务"
    echo "  2) 停止服务"
    echo "  3) 重启服务"
    echo "  4) 查看服务状态"
    echo
    read -p "请选择操作 [1-4]: " choice
    
    case "$choice" in
        1) start_service ;;
        2) stop_service ;;
        3) restart_service ;;
        4) view_status ;;
        *) echo -e "${RED}无效选择。${NC}"; exit 1 ;;
    esac
}

# --- 主菜单 ---

show_menu() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}    sing-box 管理脚本${NC}"
    echo -e "${GREEN}================================${NC}"
    echo
    check_singbox_status
    echo -e "${BLUE}安装管理:${NC}"
    echo "  1) 安装 sing-box"
    echo "  2) 更新 sing-box"
    echo "  3) 卸载 sing-box"
    echo
    echo -e "${BLUE}入站管理:${NC}"
    echo "  4) 添加入站"
    echo "  5) 列出所有入站"
    echo "  6) 删除入站"
    echo
    echo -e "${BLUE}系统管理:${NC}"
    echo "  7) 服务控制"
    echo "  8) 查看配置文件"
    echo "  9) 实时查看日志"
    echo
    read -p "请选择操作 [1-9]: " choice
    
    case "$choice" in
        1) install_singbox ;;
        2) update_singbox ;;
        3) uninstall_singbox ;;
        4) show_add_inbound_menu ;;
        5) list_inbounds ;;
        6) remove_inbound ;;
        7) show_service_menu ;;
        8) view_config ;;
        9) view_realtime_log ;;
        *) echo -e "${RED}无效选择。${NC}"; exit 1 ;;
    esac
}

# --- 脚本入口 ---
show_menu