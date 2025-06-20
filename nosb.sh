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
JUICITY_CONFIG_FILE="/root/juicity-config"

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 此脚本必须以root权限运行!${NC}"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${YELLOW}[+] 安装必要依赖...${NC}"
    apt update > /dev/null 2>&1
    apt install -y jq curl wget unzip openssl > /dev/null 2>&1
    echo -e "${GREEN}[√] 依赖安装完成!${NC}"
}

# Xray Reality 安装
install_xray_reality() {
    echo -e "${YELLOW}[+] 开始安装 Xray Reality...${NC}"
    
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${YELLOW}Xray 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 安装 Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # 生成配置
    local UUID=$(uuidgen)
    local PRIVATE_KEY=$(xray x25519 -i "$(head -c 32 /dev/urandom | base64)" | awk '/Private key:/ {print $3}')
    local PUBLIC_KEY=$(xray x25519 -i "$PRIVATE_KEY" | awk '/Public key:/ {print $3}')
    local SHORT_ID=$(openssl rand -hex 8)
    
    # 保存配置到全局变量
    XRAY_UUID="$UUID"
    XRAY_PORT="443"
    XRAY_PUBLIC_KEY="$PUBLIC_KEY"
    XRAY_SHORT_ID="$SHORT_ID"
    
    # 保存到配置文件
    cat > "$CONFIG_FILE" <<EOL
XRAY_UUID="$UUID"
XRAY_PORT="443"
XRAY_PUBLIC_KEY="$PUBLIC_KEY"
XRAY_SHORT_ID="$SHORT_ID"
EOL
    
    # 创建 Xray 配置文件
    cat > /usr/local/etc/xray/config.json <<EOL
{
  "inbounds": [
    {
      "port": 443,
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
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.nazhumi.com:443",
          "xver": 0,
          "serverNames": ["www.nazhumi.com"],
          "privateKey": "$PRIVATE_KEY",
          "minClient": "",
          "maxClient": "",
          "maxTimediff": 0,
          "shortIds": ["$SHORT_ID"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOL
    
    systemctl restart xray
    echo -e "${GREEN}[√] Xray Reality 安装完成!${NC}"
}

# Juicity 安装
install_juicity() {
    echo -e "${YELLOW}[+] 开始安装 Juicity...${NC}"
    
    local INSTALL_DIR="/root/juicity"
    local CONFIG_FILE="$INSTALL_DIR/config.json"
    local SERVICE_FILE="/etc/systemd/system/juicity.service"
    local JUICITY_SERVER="$INSTALL_DIR/juicity-server"
    
    if [[ -d $INSTALL_DIR && -f $SERVICE_FILE ]]; then
        echo -e "${YELLOW}Juicity 已安装，跳过安装步骤${NC}"
        return
    fi
    
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
    
    local LATEST_RELEASE_URL=$(curl --silent "https://api.github.com/repos/juicity/juicity/releases" | jq -r ".[0].assets[] | select(.name == \"$BINARY_NAME\") | .browser_download_url")
    
    mkdir -p $INSTALL_DIR
    curl -sL $LATEST_RELEASE_URL -o "$INSTALL_DIR/juicity.zip"
    unzip -q "$INSTALL_DIR/juicity.zip" -d $INSTALL_DIR
    
    find $INSTALL_DIR ! -name 'juicity-server' -type f -exec rm -f {} +
    chmod +x $JUICITY_SERVER
    
    local PORT=$((RANDOM % 55536 + 10000))
    local PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 8 | head -n 1)
    local UUID=$(uuidgen)
    
    openssl ecparam -genkey -name prime256v1 -out "$INSTALL_DIR/private.key"
    openssl req -new -x509 -days 36500 -key "$INSTALL_DIR/private.key" -out "$INSTALL_DIR/fullchain.cer" -subj "/CN=www.speedtest.net"
    
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
    
    systemctl daemon-reload
    systemctl enable juicity > /dev/null 2>&1
    systemctl start juicity
    
    local SHARE_LINK=$($JUICITY_SERVER generate-sharelink -c $CONFIG_FILE)
    
    # 保存配置到单独文件
    cat > "$JUICITY_CONFIG_FILE" <<EOL
JUICITY_PORT=$PORT
JUICITY_UUID=$UUID
JUICITY_PASSWORD=$PASSWORD
JUICITY_SHARE_LINK="$SHARE_LINK"
EOL
    
    echo -e "${GREEN}[√] Juicity 安装完成!${NC}"
}

# Tuic 安装
install_tuic() {
    echo -e "${YELLOW}[+] 开始安装 Tuic...${NC}"
    
    local INSTALL_DIR="/root/tuic"
    local CONFIG_FILE="$INSTALL_DIR/config.json"
    local SERVICE_FILE="/etc/systemd/system/tuic.service"
    
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}Tuic 已安装，跳过安装步骤${NC}"
        return
    fi
    
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    
    # 检测架构
    detect_arch() {
        local arch=$(uname -m)
        case $arch in
            x86_64) echo "x86_64-unknown-linux-gnu" ;;
            i686) echo "i686-unknown-linux-gnu" ;;
            armv7l) echo "armv7-unknown-linux-gnueabi" ;;
            aarch64) echo "aarch64-unknown-linux-gnu" ;;
            *) echo "" ;;
        esac
    }
    
    local server_arch=$(detect_arch)
    if [ -z "$server_arch" ]; then
        echo -e "${RED}不支持的架构: $(uname -m)${NC}"
        return
    fi
    
    local latest_release_version=$(curl -s "https://api.github.com/repos/etjec4/tuic/releases/latest" | jq -r ".tag_name")
    local download_url="https://github.com/etjec4/tuic/releases/download/$latest_release_version/$latest_release_version-$server_arch"
    
    wget -O tuic-server -q "$download_url"
    chmod 755 tuic-server
    
    local PORT=$((RANDOM % 55536 + 10000))
    local UUID=$(uuidgen)
    local PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 16 | head -n 1)
    
    cat > $CONFIG_FILE <<EOL
{
  "server": "[::]:$PORT",
  "users": {
    "$UUID": "$PASSWORD"
  },
  "certificate": "/root/tuic/fullchain.cer",
  "private_key": "/root/tuic/private.key",
  "congestion_controller": "bbr",
  "alpn": ["h3"],
  "log_level": "info"
}
EOL
    
    openssl ecparam -genkey -name prime256v1 -out "$INSTALL_DIR/private.key"
    openssl req -new -x509 -days 36500 -key "$INSTALL_DIR/private.key" -out "$INSTALL_DIR/fullchain.cer" -subj "/CN=www.bing.com"
    
    cat > $SERVICE_FILE <<EOL
[Unit]
Description=tuic-server
After=network.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/tuic-server -c $CONFIG_FILE
Restart=on-failure
RestartSec=3
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL
    
    systemctl daemon-reload
    systemctl enable tuic > /dev/null 2>&1
    systemctl start tuic
    
    # 保存到主配置文件
    echo "TUIC_UUID=\"$UUID\"" >> "$CONFIG_FILE"
    echo "TUIC_PASSWORD=\"$PASSWORD\"" >> "$CONFIG_FILE"
    echo "TUIC_PORT=\"$PORT\"" >> "$CONFIG_FILE"
    
    echo -e "${GREEN}[√] Tuic 安装完成!${NC}"
}

# Hysteria2 安装
install_hysteria2() {
    echo -e "${YELLOW}[+] 开始安装 Hysteria2...${NC}"
    
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        echo -e "${YELLOW}Hysteria2 已安装，跳过安装步骤${NC}"
        return
    fi
    
    # 安装 Hysteria2
    bash <(curl -fsSL https://get.hy2.sh/)
    
    # 生成配置
    local PORT=$((RANDOM % 55536 + 10000))
    local PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 16 | head -n 1)
    
    # 创建配置目录
    mkdir -p /etc/hysteria2
    cat > /etc/hysteria2/config.yaml <<EOL
listen: :$PORT

tls:
  cert: /etc/hysteria2/fullchain.cer
  key: /etc/hysteria2/private.key

auth:
  type: password
  password: $PASSWORD

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
EOL
    
    # 生成自签名证书
    openssl ecparam -genkey -name prime256v1 -out /etc/hysteria2/private.key
    openssl req -new -x509 -days 36500 -key /etc/hysteria2/private.key -out /etc/hysteria2/fullchain.cer -subj "/CN=www.bing.com"
    
    systemctl restart hysteria-server.service
    
    # 保存配置
    echo "HYSTERIA_PASSWORD=\"$PASSWORD\"" >> "$CONFIG_FILE"
    echo "HYSTERIA_PORT=\"$PORT\"" >> "$CONFIG_FILE"
    
    echo -e "${GREEN}[√] Hysteria2 安装完成!${NC}"
}

# AnyTLS 安装
install_anytls() {
    echo -e "${YELLOW}[+] 开始安装 AnyTLS...${NC}"
    
    if [ -f "/etc/systemd/system/anytls-server.service" ]; then
        echo -e "${YELLOW}AnyTLS 已安装，跳过安装步骤${NC}"
        return
    fi
    
    local ANYTLS_VERSION="v0.0.8"
    local INSTALL_DIR="/usr/local/bin"
    local BINARY_NAME="anytls-server"
    local BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
    local CONFIG_DIR="/etc/anytls"
    local SERVICE_FILE="/etc/systemd/system/anytls-server.service"
    
    # 创建配置目录
    mkdir -p $CONFIG_DIR
    
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
    
    # 下载并安装
    local VERSION_FOR_FILENAME=${ANYTLS_VERSION#v}
    local FILENAME="anytls_${VERSION_FOR_FILENAME}_linux_${ANYTLS_ARCH}.zip"
    local DOWNLOAD_URL="https://github.com/anytls/anytls-go/releases/download/$ANYTLS_VERSION/$FILENAME"
    
    wget -O /tmp/$FILENAME -q "$DOWNLOAD_URL"
    unzip -q -o "/tmp/$FILENAME" -d /tmp/anytls
    mv "/tmp/anytls/$BINARY_NAME" $BINARY_PATH
    chmod +x $BINARY_PATH
    rm -rf /tmp/anytls "/tmp/$FILENAME"
    
    # 生成配置
    local PORT=$((RANDOM % 55536 + 10000))
    local PASSWORD=$(tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 16 | head -n 1)
    
    cat > $CONFIG_DIR/config.json <<EOL
{
    "server": ":$PORT",
    "password": "$PASSWORD"
}
EOL
    
    # 创建服务文件
    cat > $SERVICE_FILE <<EOL
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$BINARY_PATH -c $CONFIG_DIR/config.json
Restart=always
RestartSec=3
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL
    
    systemctl daemon-reload
    systemctl enable anytls-server > /dev/null 2>&1
    systemctl start anytls-server
    
    # 保存配置
    echo "ANYTLS_PASSWORD=\"$PASSWORD\"" >> "$CONFIG_FILE"
    echo "ANYTLS_PORT=\"$PORT\"" >> "$CONFIG_FILE"
    
    echo -e "${GREEN}[√] AnyTLS 安装完成!${NC}"
}

# 安装/更新所有协议服务
install_or_update_all() {
    install_dependencies
    
    # Xray
    if [ -f "/usr/local/bin/xray" ]; then
        echo -e "${YELLOW}检测到已安装 Xray，执行更新...${NC}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        systemctl restart xray
        echo -e "${GREEN}Xray 更新完成!${NC}"
    else
        install_xray_reality
    fi
    
    # Juicity
    if [ -d "/root/juicity" ]; then
        echo -e "${YELLOW}检测到已安装 Juicity，执行更新...${NC}"
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
    else
        install_juicity
    fi

    # Tuic
    if [ -d "/root/tuic" ]; then
        echo -e "${YELLOW}检测到已安装 Tuic，执行更新...${NC}"
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
        
        echo "TUIC_UUID=\"$UUID\"" >> "$CONFIG_FILE"
        echo "TUIC_PASSWORD=\"$PASSWORD\"" >> "$CONFIG_FILE"
        echo "TUIC_PORT=\"$PORT\"" >> "$CONFIG_FILE"

        echo -e "${GREEN}Tuic 更新完成!${NC}"
    else
        install_tuic
    fi
    
    # Hysteria2
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        echo -e "${YELLOW}检测到已安装 Hysteria2，执行更新...${NC}"
        systemctl stop hysteria-server.service
        
        bash <(curl -fsSL https://get.hy2.sh/)
        
        systemctl start hysteria-server.service
        echo -e "${GREEN}Hysteria2 更新完成!${NC}"
    else
        install_hysteria2
    fi
    
    # AnyTLS
    if [ -f "/etc/systemd/system/anytls-server.service" ]; then
        echo -e "${YELLOW}检测到已安装 AnyTLS，执行更新...${NC}"
        systemctl stop anytls-server
        
        local ANYTLS_VERSION="v0.0.8"
        local INSTALL_DIR="/usr/local/bin"
        local BINARY_NAME="anytls-server"
        local BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
        
        local ARCH=$(uname -m)
        case $ARCH in
            x86_64 | amd64) ANYTLS_ARCH="amd64" ;;
            aarch64 | arm64) ANYTLS_ARCH="arm64" ;;
            *) ;;
        esac
        
        local VERSION_FOR_FILENAME=${ANYTLS_VERSION#v}
        local FILENAME="anytls_${VERSION_FOR_FILENAME}_linux_${ANYTLS_ARCH}.zip"
        local DOWNLOAD_URL="https://github.com/anytls/anytls-go/releases/download/$ANYTLS_VERSION/$FILENAME"
        
        wget -O /tmp/$FILENAME -q "$DOWNLOAD_URL"
        unzip -q -o "/tmp/$FILENAME" -d /tmp/anytls
        mv "/tmp/anytls/$BINARY_NAME" $BINARY_PATH
        chmod +x $BINARY_PATH
        rm -rf /tmp/anytls "/tmp/$FILENAME"
        
        systemctl start anytls-server
        echo -e "${GREEN}AnyTLS 更新完成!${NC}"
    else
        install_anytls
    fi
    
    echo -e "${GREEN}[√] 所有协议服务已安装或更新完成!${NC}"
}

# 安装XanMod内核并优化系统
install_kernel_and_optimize() {
    echo -e "${YELLOW}[+] 开始安装XanMod内核并优化系统...${NC}"
    
    # 安装XanMod内核
    wget -qO - https://dl.xanmod.org/archive.key | sudo gpg --dearmor -vo /etc/apt/keyrings/xanmod-archive-keyring.gpg
    echo 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list
    apt update
    apt install -y 	linux-xanmod-edge-x64v3
    
    # 系统优化
    cat > /etc/sysctl.d/99-optimization.conf <<EOL
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
EOL
    
    sysctl --system
    
    echo -e "${GREEN}[√] XanMod内核安装及系统优化完成!${NC}"
}

# 卸载所有服务
uninstall_services() {
    echo -e "${YELLOW}[+] 开始卸载所有协议服务...${NC}"
    
    # Xray
    if [ -f "/usr/local/bin/xray" ]; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
        echo -e "${GREEN}Xray 已卸载${NC}"
    fi
    
    # Juicity
    if [ -f "/etc/systemd/system/juicity.service" ]; then
        systemctl stop juicity
        systemctl disable juicity
        rm -f /etc/systemd/system/juicity.service
        rm -rf /root/juicity
        echo -e "${GREEN}Juicity 已卸载${NC}"
    fi
    
    # Tuic
    if [ -f "/etc/systemd/system/tuic.service" ]; then
        systemctl stop tuic
        systemctl disable tuic
        rm -f /etc/systemd/system/tuic.service
        rm -rf /root/tuic
        echo -e "${GREEN}Tuic 已卸载${NC}"
    fi
    
    # Hysteria2
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        systemctl stop hysteria-server.service
        systemctl disable hysteria-server.service
        rm -f /etc/systemd/system/hysteria-server.service
        rm -rf /etc/hysteria2
        rm -f /usr/local/bin/hysteria
        echo -e "${GREEN}Hysteria2 已卸载${NC}"
    fi
    
    # AnyTLS
    if [ -f "/etc/systemd/system/anytls-server.service" ]; then
        systemctl stop anytls-server
        systemctl disable anytls-server
        rm -f /etc/systemd/system/anytls-server.service
        rm -rf /etc/anytls
        rm -f /usr/local/bin/anytls-server
        echo -e "${GREEN}AnyTLS 已卸载${NC}"
    fi
    
    # 删除配置文件
    rm -f "$CONFIG_FILE"
    rm -f "$JUICITY_CONFIG_FILE"
    
    echo -e "${GREEN}[√] 所有协议服务已卸载!${NC}"
}

# 显示协议链接
show_links() {
    # 确保加载所有配置文件
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
    
    if [ -f "$JUICITY_CONFIG_FILE" ]; then
        source "$JUICITY_CONFIG_FILE"
    fi
    
    # 安全获取公网IP
    public_ip=$(curl -s --max-time 2 ip.sb)
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s --max-time 2 ipv6.ip.sb)
    fi
    [ -z "$public_ip" ] && public_ip="无法获取公网IP"

    # 获取ISP信息
    isp_info=$(curl -s --max-time 2 https://speed.cloudflare.com/meta)
    if [ -n "$isp_info" ]; then
        asn=$(echo "$isp_info" | jq -r '.asn // empty')
        org=$(echo "$isp_info" | jq -r '.asOrganization // empty')
        country=$(echo "$isp_info" | jq -r '.country // empty')
        isp="${asn}-${org}-${country}"
    else
        isp="未知ISP"
    fi

    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议连接信息                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
    # Xray Reality 链接
    if [[ -n "$XRAY_UUID" && -n "$XRAY_PORT" && -n "$XRAY_PUBLIC_KEY" && -n "$XRAY_SHORT_ID" ]]; then
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
    if [[ -n "$TUIC_UUID" && -n "$TUIC_PASSWORD" && -n "$TUIC_PORT" ]]; then
        echo -e "${CYAN}Tuic 链接:${NC}"
        echo -e "${GREEN}tuic://$TUIC_UUID:$TUIC_PASSWORD@$public_ip:$TUIC_PORT?congestion_control=bbr&alpn=h3&sni=www.bing.com&udp_relay_mode=native&allow_insecure=1#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Hysteria2 链接
    if [[ -n "$HYSTERIA_PASSWORD" && -n "$HYSTERIA_PORT" ]]; then
        echo -e "${CYAN}Hysteria2 链接:${NC}"
        echo -e "${GREEN}hysteria2://$HYSTERIA_PASSWORD@$public_ip:$HYSTERIA_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # AnyTLS 链接
    if [[ -n "$ANYTLS_PASSWORD" && -n "$ANYTLS_PORT" ]]; then
        echo -e "${CYAN}AnyTLS 链接:${NC}"
        echo -e "${GREEN}anytls://$ANYTLS_PASSWORD@$public_ip:$ANYTLS_PORT?allowInsecure=true#$isp${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    echo -e "${GREEN}所有链接已显示完毕${NC}"
    echo -e "${YELLOW}================================================${NC}"
}

# 显示菜单
show_menu() {
    clear
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议管理菜单                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}1. 安装或更新所有协议服务${NC}"
    echo -e "${GREEN}2. 安装XanMod内核并优化系统${NC}"
    echo -e "${GREEN}3. 查看所有协议链接${NC}"
    echo -e "${RED}4. 卸载所有协议${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
    read -p "请输入选项 (1-4): " choice
    
    case $choice in
        1) 
            install_or_update_all
            ;;
        2) 
            install_kernel_and_optimize
            ;;
        3) 
            show_links
            ;;
        4) 
            uninstall_services
            ;;
        *)
            echo -e "${RED}无效选项!${NC}"
            sleep 1
            ;;
    esac
    
    read -p "按回车键返回主菜单..." input
}

# 主函数
main() {
    check_root
    
    # 确保配置文件存在
    touch "$CONFIG_FILE"
    touch "$JUICITY_CONFIG_FILE"
    
    # 加载现有配置
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
    
    if [ -f "$JUICITY_CONFIG_FILE" ]; then
        source "$JUICITY_CONFIG_FILE"
    fi
    
    while true; do
        show_menu
    done
}

# 启动脚本
main
