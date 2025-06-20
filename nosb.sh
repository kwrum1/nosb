#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 恢复默认颜色

# 全局变量
export PORT=${PORT:-$(shuf -i 2000-65000 -n 1)}
export UUID=${UUID:-$(cat /proc/sys/kernel/random/uuid)}
CONFIG_FILE="/root/proxy-config"

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}此脚本必须以root权限运行!${NC}"
        exit 1
    fi
}

# 获取公网IP和ISP信息
get_network_info() {
    public_ip=$(curl -s --max-time 2 ip.sb || curl -s --max-time 1 ipv6.ip.sb)
    if [[ -z "${public_ip}" ]]; then
        echo -e "${RED}无法获取到你的服务器IP${NC}"
        return 1
    fi
    
    isp=$(curl -s https://speed.cloudflare.com/meta | jq -r '[.asn, .asOrganization, .country] | map(tostring) | join("-")' 2>/dev/null || echo "unknown-isp")
    echo "$public_ip,$isp"
}

# 安装依赖包
install_dependencies() {
    echo -e "${YELLOW}[+] 正在安装依赖包...${NC}"
    local packages="unzip jq uuid-runtime openssl wget curl qrencode gawk"
    
    if command -v apt &>/dev/null; then
        apt update -y
        apt install -y -q $packages
    elif command -v yum &>/dev/null; then
        yum install -y $packages
    elif command -v dnf &>/dev/null; then
        dnf install -y $packages
    elif command -v apk &>/dev/null; then
        apk add $packages
    else
        echo -e "${RED}暂不支持的系统!${NC}"
        return 1
    fi
    echo -e "${GREEN}[√] 依赖包安装完成${NC}"
}

# 安装Xray Reality
install_xray_reality() {
    echo -e "${YELLOW}[+] 开始安装 Xray Reality...${NC}"
    
    # 如果已安装则跳过
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${YELLOW}Xray 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 安装Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # 生成密钥
    reX25519Key=$(/usr/local/bin/xray x25519)
    rePrivateKey=$(echo "${reX25519Key}" | head -1 | awk '{print $3}')
    rePublicKey=$(echo "${reX25519Key}" | tail -n 1 | awk '{print $3}')
    shortId=$(openssl rand -hex 8)

    # 配置Xray
    cat >/usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": $PORT, 
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "target": "www.nazhumi.com:443",
          "xver": 0,
          "serverNames": [
            "www.nazhumi.com"
          ],
          "privateKey": "$rePrivateKey",
          "shortIds": [
            "$shortId"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
      {
        "protocol": "freedom",
        "tag": "direct"
        },
      {
        "protocol": "blackhole",
        "tag": "blocked"
      }
    ]    
}
EOF

    # 启动服务
    systemctl enable xray.service && systemctl restart xray.service
    
    # 保存配置
    echo "XRAY_PORT=$PORT" >> $CONFIG_FILE
    echo "XRAY_UUID=$UUID" >> $CONFIG_FILE
    echo "XRAY_PUBLIC_KEY=$rePublicKey" >> $CONFIG_FILE
    echo "XRAY_SHORT_ID=$shortId" >> $CONFIG_FILE
    
    echo -e "${GREEN}[√] Xray Reality 安装完成!${NC}"
}

# 安装Juicity
install_juicity() {
    echo -e "${YELLOW}[+] 开始安装 Juicity...${NC}"
    
    # 定义变量
    local INSTALL_DIR="/root/juicity"
    local CONFIG_FILE="$INSTALL_DIR/config.json"
    local SERVICE_FILE="/etc/systemd/system/juicity.service"
    local JUICITY_SERVER="$INSTALL_DIR/juicity-server"
    
    # 如果已安装则跳过
    if [[ -d $INSTALL_DIR && -f $SERVICE_FILE ]]; then
        echo -e "${YELLOW}Juicity 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 检测架构
    local ARCH=$(uname -m)
    local BINARY_NAME="juicity-linux"
    
    case "$ARCH" in
        "x86_64") BINARY_NAME+="-x86_64.zip" ;;
        "arm64") BINARY_NAME+="-arm64.zip" ;;
        "armv7") BINARY_NAME+="-armv7.zip" ;;
        "mips32") BINARY_NAME+="-mips32.zip" ;;
        "mips64") BINARY_NAME+="-mips64.zip" ;;
        "riscv64") BINARY_NAME+="-riscv64.zip" ;;
        "i686") BINARY_NAME+="-x86_32.zip" ;;
        *)
            echo -e "${RED}不支持的架构: $ARCH${NC}"
            return
            ;;
    esac
    
    # 下载最新版本
    local LATEST_RELEASE_URL=$(curl --silent "https://api.github.com/repos/juicity/juicity/releases" | jq -r ".[0].assets[] | select(.name == \"$BINARY_NAME\") | .browser_download_url")
    
    # 创建安装目录
    mkdir -p $INSTALL_DIR
    curl -sL $LATEST_RELEASE_URL -o "$INSTALL_DIR/juicity.zip"
    unzip -q "$INSTALL_DIR/juicity.zip" -d $INSTALL_DIR
    
    # 删除除juicity-server外的所有文件
    find $INSTALL_DIR ! -name 'juicity-server' -type f -exec rm -f {} +
    chmod +x $JUICITY_SERVER
    
    # 获取配置信息
    local PORT=$((RANDOM % 55536 + 10000))
    local PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 8 | head -n 1)
    local UUID=$(uuidgen)
    
    # 生成密钥
    openssl ecparam -genkey -name prime256v1 -out "$INSTALL_DIR/private.key"
    openssl req -new -x509 -days 36500 -key "$INSTALL_DIR/private.key" -out "$INSTALL_DIR/fullchain.cer" -subj "/CN=www.speedtest.net"
    
    # 创建配置文件
    cat > $CONFIG_FILE <<EOL
{
  "listen": ":$PORT",
  "users": {
    "$UUID": "$PASSWORD"
  },
  "certificate": "$INSTALL_DIR/fullchain.cer",
  "private_key": "$INSTALL_DIR/private.key",
  "congestion_control": "bbr",
  "log_level": "info"
}
EOL
    
    # 创建系统服务
    cat > $SERVICE_FILE <<EOL
[Unit]
Description=juicity-server Service
Documentation=https://github.com/juicity/juicity
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=$JUICITY_SERVER run -c $CONFIG_FILE
StandardOutput=file:$INSTALL_DIR/juicity-server.log
StandardError=file:$INSTALL_DIR/juicity-server.log
Restart=on-failure
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable juicity > /dev/null 2>&1
    systemctl start juicity
    
    # 生成分享链接
    local SHARE_LINK=$($JUICITY_SERVER generate-sharelink -c $CONFIG_FILE)
    
    # 保存配置信息
    echo "JUICITY_PORT=$PORT" >> $CONFIG_FILE
    echo "JUICITY_UUID=$UUID" >> $CONFIG_FILE
    echo "JUICITY_PASSWORD=$PASSWORD" >> $CONFIG_FILE
    echo "JUICITY_SHARE_LINK=\"$SHARE_LINK\"" >> $CONFIG_FILE
    
    echo -e "${GREEN}[√] Juicity 安装完成!${NC}"
}

# 安装Tuic-V5
install_tuic() {
    echo -e "${YELLOW}[+] 开始安装 Tuic-V5...${NC}"
    
    # 定义变量
    local INSTALL_DIR="/root/tuic"
    local SERVICE_FILE="/etc/systemd/system/tuic.service"
    
    # 如果已安装则跳过
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}Tuic 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 检测架构
    detect_arch() {
        local arch=$(uname -m)
        case $arch in
            x86_64) echo "x86_64-unknown-linux-gnu" ;;
            i686) echo "i686-unknown-linux-gnu" ;;
            armv7l) echo "armv7-unknown-linux-gnueabi" ;;
            aarch64) echo "aarch64-unknown-linux-gnu" ;;
            *)
                echo -e "${RED}不支持的架构: $arch${NC}"
                return
                ;;
        esac
    }
    
    local server_arch=$(detect_arch)
    local latest_release_version=$(curl -s "https://api.github.com/repos/etjec4/tuic/releases/latest" | jq -r ".tag_name")
    local download_url="https://github.com/etjec4/tuic/releases/download/$latest_release_version/$latest_release_version-$server_arch"
    
    # 创建安装目录
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    wget -O tuic-server -q "$download_url" || { echo -e "${RED}下载失败!${NC}"; return; }
    chmod 755 tuic-server
    
    # 生成证书
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout $INSTALL_DIR/server.key -out $INSTALL_DIR/server.crt -subj "/CN=bing.com" -days 36500
    
    # 获取配置信息
    local port=$(shuf -i 10000-65000 -n 1)
    local password=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 8 | head -n 1)
    local UUID=$(openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)/\1-\2-\3-\4-/')
    
    # 创建配置文件
    cat > $INSTALL_DIR/config.json <<EOL
{
  "server": "[::]:$port",
  "users": {
    "$UUID": "$password"
  },
  "certificate": "$INSTALL_DIR/server.crt",
  "private_key": "$INSTALL_DIR/server.key",
  "congestion_control": "bbr",
  "alpn": ["h3", "spdy/3.1"],
  "udp_relay_ipv6": true,
  "zero_rtt_handshake": false,
  "dual_stack": true,
  "auth_timeout": "3s",
  "task_negotiation_timeout": "3s",
  "max_idle_time": "10s",
  "max_external_packet_size": 1500,
  "gc_interval": "3s",
  "gc_lifetime": "15s",
  "log_level": "warn"
}
EOL
    
    # 创建系统服务
    cat > $SERVICE_FILE <<EOL
[Unit]
Description=tuic service
Documentation=TUIC v5
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=$INSTALL_DIR/tuic-server -c $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable tuic > /dev/null 2>&1
    systemctl start tuic
    
    # 保存配置信息
    echo "TUIC_PORT=$port" >> $CONFIG_FILE
    echo "TUIC_UUID=$UUID" >> $CONFIG_FILE
    echo "TUIC_PASSWORD=$password" >> $CONFIG_FILE
    
    echo -e "${GREEN}[√] Tuic-V5 安装完成!${NC}"
}

# 安装Hysteria2
install_hysteria2() {
    echo -e "${YELLOW}[+] 开始安装 Hysteria2...${NC}"
    
    # 定义变量
    local HY2_PORT=$(shuf -i 2000-65000 -n 1)
    local PASSWD=$(cat /proc/sys/kernel/random/uuid)
    
    # 如果已安装则跳过
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        echo -e "${YELLOW}Hysteria2 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 安装官方脚本
    bash <(curl -fsSL https://get.hy2.sh/)
    
    # 创建证书目录
    mkdir -p /etc/hysteria
    
    # 生成证书
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=bing.com" -days 36500
    chown hysteria /etc/hysteria/server.key
    chown hysteria /etc/hysteria/server.crt
    
    # 创建配置文件
    cat << EOF > /etc/hysteria/config.yaml
listen: :$HY2_PORT

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: "$PASSWD"

fastOpen: true

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

transport:
  udp:
    hopInterval: 30s
EOF
    
    # 启动服务
    systemctl start hysteria-server.service
    systemctl enable hysteria-server.service > /dev/null 2>&1
    
    # 保存配置信息
    echo "HYSTERIA_PORT=$HY2_PORT" >> $CONFIG_FILE
    echo "HYSTERIA_PASSWORD=$PASSWD" >> $CONFIG_FILE
    
    echo -e "${GREEN}[√] Hysteria2 安装完成!${NC}"
}

# 安装AnyTLS-Go
install_anytls() {
    echo -e "${YELLOW}[+] 开始安装 AnyTLS-Go...${NC}"
    
    # 定义变量
    local ANYTLS_VERSION="v0.0.8"
    local ANYTLS_PORT=$(shuf -i 10000-65000 -n 1)
    local ANYTLS_PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 16 | head -n 1)
    local INSTALL_DIR="/usr/local/bin"
    local SERVICE_FILE="/etc/systemd/system/anytls-server.service"
    local BINARY_NAME="anytls-server"
    local BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
    
    # 如果已安装则跳过
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${YELLOW}AnyTLS 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 检测架构
    local ARCH=$(uname -m)
    case $ARCH in
        x86_64 | amd64) ANYTLS_ARCH="amd64" ;;
        aarch64 | arm64) ANYTLS_ARCH="arm64" ;;
        *)
            echo -e "${RED}不支持的架构: $ARCH${NC}"
            return
            ;;
    esac
    
    # 下载最新版本
    local VERSION_FOR_FILENAME=${ANYTLS_VERSION#v}
    local FILENAME="anytls_${VERSION_FOR_FILENAME}_linux_${ANYTLS_ARCH}.zip"
    local DOWNLOAD_URL="https://github.com/anytls/anytls-go/releases/download/$ANYTLS_VERSION/$FILENAME"
    
    # 下载并解压
    wget -O /tmp/$FILENAME -q "$DOWNLOAD_URL" || { echo -e "${RED}下载失败!${NC}"; return; }
    unzip -q -o "/tmp/$FILENAME" -d /tmp/anytls
    mv "/tmp/anytls/$BINARY_NAME" $BINARY_PATH
    chmod +x $BINARY_PATH
    rm -rf /tmp/anytls "/tmp/$FILENAME"
    
    # 创建系统服务
    cat > $SERVICE_FILE <<EOL
[Unit]
Description=AnyTLS Server Service
Documentation=https://github.com/anytls/anytls-go
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$BINARY_PATH -l 0.0.0.0:$ANYTLS_PORT -p "$ANYTLS_PASSWORD"
Restart=on-failure
RestartSec=10s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable anytls-server > /dev/null 2>&1
    systemctl start anytls-server
    
    # 保存配置信息
    echo "ANYTLS_PORT=$ANYTLS_PORT" >> $CONFIG_FILE
    echo "ANYTLS_PASSWORD=$ANYTLS_PASSWORD" >> $CONFIG_FILE
    
    echo -e "${GREEN}[√] AnyTLS-Go 安装完成!${NC}"
}

# 安装XanMod内核并优化
install_kernel_and_optimize() {
    echo -e "${YELLOW}[+] 开始安装XanMod内核并优化系统...${NC}"
    
    # 检查是否已安装XanMod内核
    if uname -r | grep -q "xanmod"; then
        echo -e "${YELLOW}XanMod内核已安装，跳过安装步骤${NC}"
    else
        echo -e "${CYAN}[1/3] 安装XanMod内核...${NC}"
        
        # 注册PGP密钥
        wget -qO - https://dl.xanmod.org/archive.key | sudo gpg --dearmor -vo /etc/apt/keyrings/xanmod-archive-keyring.gpg
        
        # 添加仓库
        echo 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
        
        # 更新并安装
        apt update && apt install linux-xanmod-edge-x64v3 -y
        
        echo -e "${GREEN}[√] XanMod内核安装完成，需要重启生效${NC}"
    fi
    
    echo -e "${CYAN}[2/3] 应用系统优化配置...${NC}"
    
    # 基础系统参数
    cat >/etc/sysctl.d/99-custom-gateway.conf <<EOF
# 系统基础
kernel.pid_max = 65535
vm.swappiness = 10
vm.overcommit_memory = 1
vm.dirty_ratio = 8
vm.dirty_background_ratio = 2
vm.min_free_kbytes = 65536
kernel.numa_balancing = 0

# TCP 网络优化
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096
net.core.optmem_max = 65536

net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 65536 4194304
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_ecn = 1

# 安全与稳定性
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_tw_buckets = 8192
net.ipv4.tcp_max_orphans = 32768
net.ipv4.route.gc_timeout = 100
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

    # 应用sysctl配置
    sysctl --system >/dev/null 2>&1
    
    echo -e "${CYAN}[3/3] 设置文件句柄限制和systemd参数...${NC}"
    
    # 设置文件句柄限制
    cat >/etc/security/limits.d/99-custom-nofile.conf <<EOF
* soft nofile 100000
* hard nofile 100000
root soft nofile 100000
root hard nofile 100000
EOF

    grep -q "ulimit -SHn" /etc/profile || echo "ulimit -SHn 100000" >> /etc/profile

    # 设置systemd参数
    sed -i '/^DefaultTasksMax/d' /etc/systemd/system.conf
    echo "DefaultTasksMax=infinity" >> /etc/systemd/system.conf
    systemctl daemon-reexec
    
    echo -e "${GREEN}[√] 内核安装和系统优化完成! 建议重启系统使所有更改生效${NC}"
}

# 显示所有链接
show_links() {
    # 读取配置变量
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi

    local network_info=($(get_network_info | tr ',' ' '))
    local public_ip=${network_info[0]}
    local isp=${network_info[1]}
    
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议连接信息                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
    # Xray Reality 链接
    if [ -n "$XRAY_UUID" ]; then
        echo -e "${CYAN}Xray Reality 链接:${NC}"
        echo -e "${GREEN}vless://${XRAY_UUID}@${public_ip}:${XRAY_PORT}?encryption=none&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${XRAY_PUBLIC_KEY}&sid=${XRAY_SHORT_ID}&allowInsecure=1&type=xhttp&mode=auto#${isp}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Juicity 链接
    if [ -n "$JUICITY_SHARE_LINK" ]; then
        echo -e "${CYAN}Juicity 链接:${NC}"
        echo -e "${GREEN}$JUICITY_SHARE_LINK${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Tuic 链接
    if [ -n "$TUIC_PORT" ]; then
        echo -e "${CYAN}Tuic 链接:${NC}"
        echo -e "${GREEN}tuic://$TUIC_UUID:$TUIC_PASSWORD@$public_ip:$TUIC_PORT?congestion_control=bbr&alpn=h3&sni=www.bing.com&udp_relay_mode=native&allow_insecure=1#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Hysteria2 链接
    if [ -n "$HYSTERIA_PORT" ]; then
        echo -e "${CYAN}Hysteria2 链接:${NC}"
        echo -e "${GREEN}hysteria2://$HYSTERIA_PASSWORD@$public_ip:$HYSTERIA_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # AnyTLS 链接
    if [ -n "$ANYTLS_PORT" ]; then
        echo -e "${CYAN}AnyTLS 链接:${NC}"
        echo -e "${GREEN}anytls://$ANYTLS_PASSWORD@$public_ip:$ANYTLS_PORT?allowInsecure=true#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    echo -e "${GREEN}所有链接已显示完毕${NC}"
    echo -e "${YELLOW}================================================${NC}"
}

# 更新所有服务
update_services() {
    echo -e "${YELLOW}[+] 正在更新所有协议服务...${NC}"
    
    # 更新 Xray
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${CYAN}更新 Xray...${NC}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        systemctl restart xray
        echo -e "${GREEN}Xray 更新完成!${NC}"
    fi
    
    # 更新 Juicity
    if [ -d "/root/juicity" ]; then
        echo -e "${CYAN}更新 Juicity...${NC}"
        systemctl stop juicity
        
        local INSTALL_DIR="/root/juicity"
        local ARCH=$(uname -m)
        local BINARY_NAME="juicity-linux"
        
        case "$ARCH" in
            "x86_64") BINARY_NAME+="-x86_64.zip" ;;
            "arm64") BINARY_NAME+="-arm64.zip" ;;
            "armv7") BINARY_NAME+="-armv7.zip" ;;
            "mips32") BINARY_NAME+="-mips32.zip" ;;
            "mips64") BINARY_NAME+="-mips64.zip" ;;
            "riscv64") BINARY_NAME+="-riscv64.zip" ;;
            "i686") BINARY_NAME+="-x86_32.zip" ;;
            *) ;;
        esac
        
        local LATEST_RELEASE_URL=$(curl --silent "https://api.github.com/repos/juicity/juicity/releases" | jq -r ".[0].assets[] | select(.name == \"$BINARY_NAME\") | .browser_download_url")
        
        curl -sL $LATEST_RELEASE_URL -o "$INSTALL_DIR/juicity.zip"
        unzip -q "$INSTALL_DIR/juicity.zip" -d $INSTALL_DIR
        find $INSTALL_DIR ! -name 'juicity-server' -type f -exec rm -f {} +
        chmod +x $INSTALL_DIR/juicity-server
        
        systemctl start juicity
        echo -e "${GREEN}Juicity 更新完成!${NC}"
    fi
    
    # 更新 Tuic
    if [ -d "/root/tuic" ]; then
        echo -e "${CYAN}更新 Tuic...${NC}"
        systemctl stop tuic
        
        local INSTALL_DIR="/root/tuic"
        detect_arch() {
            local arch=$(uname -m)
            case $arch in
                x86_64) echo "x86_64-unknown-linux-gnu" ;;
                i686) echo "i686-unknown-linux-gnu" ;;
                armv7l) echo "armv7-unknown-linux-gnueabi" ;;
                aarch64) echo "aarch64-unknown-linux-gnu" ;;
                *) ;;
            esac
        }
        
        local server_arch=$(detect_arch)
        local latest_release_version=$(curl -s "https://api.github.com/repos/etjec4/tuic/releases/latest" | jq -r ".tag_name")
        local download_url="https://github.com/etjec4/tuic/releases/download/$latest_release_version/$latest_release_version-$server_arch"
        
        wget -O tuic-server -q "$download_url"
        chmod 755 tuic-server
        
        systemctl start tuic
        echo -e "${GREEN}Tuic 更新完成!${NC}"
    fi
    
    # 更新 Hysteria2
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        echo -e "${CYAN}更新 Hysteria2...${NC}"
        systemctl stop hysteria-server.service
        
        # 重新安装官方脚本
        bash <(curl -fsSL https://get.hy2.sh/)
        
        systemctl start hysteria-server.service
        echo -e "${GREEN}Hysteria2 更新完成!${NC}"
    fi
    
    # 更新 AnyTLS
    if [ -f "/etc/systemd/system/anytls-server.service" ]; then
        echo -e "${CYAN}更新 AnyTLS...${NC}"
        systemctl stop anytls-server
        
        local ANYTLS_VERSION="v0.0.8"
        local INSTALL_DIR="/usr/local/bin"
        local BINARY_NAME="anytls-server"
        local BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
        
        # 检测架构
        local ARCH=$(uname -m)
        case $ARCH in
            x86_64 | amd64) ANYTLS_ARCH="amd64" ;;
            aarch64 | arm64) ANYTLS_ARCH="arm64" ;;
            *) ;;
        esac
        
        # 下载最新版本
        local VERSION_FOR_FILENAME=${ANYTLS_VERSION#v}
        local FILENAME="anytls_${VERSION_FOR_FILENAME}_linux_${ANYTLS_ARCH}.zip"
        local DOWNLOAD_URL="https://github.com/anytls/anytls-go/releases/download/$ANYTLS_VERSION/$FILENAME"
        
        # 下载并解压
        wget -O /tmp/$FILENAME -q "$DOWNLOAD_URL"
        unzip -q -o "/tmp/$FILENAME" -d /tmp/anytls
        mv "/tmp/anytls/$BINARY_NAME" $BINARY_PATH
        chmod +x $BINARY_PATH
        rm -rf /tmp/anytls "/tmp/$FILENAME"
        
        systemctl start anytls-server
        echo -e "${GREEN}AnyTLS 更新完成!${NC}"
    fi
    
    echo -e "${GREEN}[√] 所有协议更新完成!${NC}"
}

# 卸载所有服务
uninstall_services() {
    echo -e "${YELLOW}[+] 正在卸载所有协议服务...${NC}"
    
    # 卸载 Xray
    if [ -f "/usr/local/bin/xray" ]; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
        echo -e "${CYAN}Xray 已卸载${NC}"
    fi
    
    # 卸载 Juicity
    if [ -d "/root/juicity" ]; then
        systemctl stop juicity
        systemctl disable juicity > /dev/null 2>&1
        rm -rf /root/juicity
        rm -f /etc/systemd/system/juicity.service
        echo -e "${CYAN}Juicity 已卸载${NC}"
    fi
    
    # 卸载 Tuic
    if [ -d "/root/tuic" ]; then
        systemctl stop tuic
        systemctl disable tuic > /dev/null 2>&1
        rm -rf /root/tuic
        rm -f /etc/systemd/system/tuic.service
        echo -e "${CYAN}Tuic 已卸载${NC}"
    fi
    
    # 卸载 Hysteria2
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        systemctl stop hysteria-server.service
        systemctl disable hysteria-server.service > /dev/null 2>&1
        rm -rf /etc/hysteria
        rm -f /etc/systemd/system/hysteria-server.service
        echo -e "${CYAN}Hysteria2 已卸载${NC}"
    fi
    
    # 卸载 AnyTLS
    if [ -f "/etc/systemd/system/anytls-server.service" ]; then
        systemctl stop anytls-server
        systemctl disable anytls-server > /dev/null 2>&1
        rm -f /etc/systemd/system/anytls-server.service
        rm -f /usr/local/bin/anytls-server
        echo -e "${CYAN}AnyTLS 已卸载${NC}"
    fi
    
    # 清理配置文件
    rm -f /root/proxy-config
    
    echo -e "${GREEN}[√] 所有协议已卸载!${NC}"
}

# 显示菜单
show_menu() {
    clear
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议管理菜单                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}1. 安装/更新所有协议服务${NC}"
    echo -e "${GREEN}2. 查看所有协议链接${NC}"
    echo -e "${GREEN}3. 更新所有服务端程序${NC}"
    echo -e "${BLUE}4. 安装XanMod内核并优化系统${NC}"
    echo -e "${RED}5. 卸载所有协议${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo -e "输入 ${CYAN}x${NC} 即可打开此菜单"
    echo -e "${YELLOW}================================================${NC}"
    
    read -p "请输入选项 (1-5): " choice
    
    case $choice in
        1) 
            install_dependencies
            install_xray_reality
            install_juicity
            install_tuic
            install_hysteria2
            install_anytls
            read -p "按回车键返回主菜单..." input
            ;;
        2) 
            show_links
            read -p "按回车键返回主菜单..." input
            ;;
        3) 
            update_services
            read -p "按回车键返回主菜单..." input
            ;;
        4) 
            install_kernel_and_optimize
            read -p "按回车键返回主菜单..." input
            ;;
        5) 
            uninstall_services
            read -p "按回车键返回主菜单..." input
            ;;
        *) 
            echo -e "${RED}无效选项!${NC}"
            sleep 1
            ;;
    esac
}

# 主函数
main() {
    check_root
    
    # 创建管理命令
    if [ ! -f "/usr/local/bin/x" ]; then
        create_management_script
    fi
    
    while true; do
        show_menu
    done
}

# 启动主函数
main
