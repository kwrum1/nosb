#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 恢复默认颜色

# 获取公网IP和ISP信息
get_network_info() {
    public_ip=$(curl -s https://api.ipify.org)
    isp=$(curl -s https://speed.cloudflare.com/meta | jq -r '[.asn, .asOrganization, .country] | map(tostring) | join("-")')
    echo "$public_ip,$isp"
}

# 安装依赖包
install_dependencies() {
    echo -e "${YELLOW}[+] 正在安装依赖包...${NC}"
    local packages="unzip jq uuid-runtime openssl wget curl"
    
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
        exit 1
    fi
    echo -e "${GREEN}[√] 依赖包安装完成${NC}"
}

# 安装Juicity
install_juicity() {
    echo -e "${YELLOW}[+] 开始安装 Juicity...${NC}"
    
    # 定义变量
    local INSTALL_DIR="/root/juicity"
    local CONFIG_FILE="$INSTALL_DIR/config.json"
    local SERVICE_FILE="/etc/systemd/system/juicity.service"
    local JUICITY_SERVER="$INSTALL_DIR/juicity-server"
    
    # 如果已安装则卸载
    if [[ -d $INSTALL_DIR && -f $SERVICE_FILE ]]; then
        systemctl stop juicity
        systemctl disable juicity > /dev/null 2>&1
        rm -rf $INSTALL_DIR
        rm -f $SERVICE_FILE
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
    echo "JUICITY_PORT=$PORT" >> /root/proxy-config
    echo "JUICITY_UUID=$UUID" >> /root/proxy-config
    echo "JUICITY_PASSWORD=$PASSWORD" >> /root/proxy-config
    echo "JUICITY_SHARE_LINK=\"$SHARE_LINK\"" >> /root/proxy-config
    
    echo -e "${GREEN}[√] Juicity 安装完成!${NC}"
}

# 安装Tuic-V5
install_tuic() {
    echo -e "${YELLOW}[+] 开始安装 Tuic-V5...${NC}"
    
    # 定义变量
    local INSTALL_DIR="/root/tuic"
    local SERVICE_FILE="/etc/systemd/system/tuic.service"
    
    # 如果已安装则卸载
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf $INSTALL_DIR
        systemctl stop tuic
        pkill -f tuic-server
        systemctl disable tuic > /dev/null 2>&1
        rm -f $SERVICE_FILE
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
    echo "TUIC_PORT=$port" >> /root/proxy-config
    echo "TUIC_UUID=$UUID" >> /root/proxy-config
    echo "TUIC_PASSWORD=$password" >> /root/proxy-config
    
    echo -e "${GREEN}[√] Tuic-V5 安装完成!${NC}"
}

# 安装Hysteria2
install_hysteria2() {
    echo -e "${YELLOW}[+] 开始安装 Hysteria2...${NC}"
    
    # 定义变量
    local HY2_PORT=$(shuf -i 2000-65000 -n 1)
    local PASSWD=$(cat /proc/sys/kernel/random/uuid)
    
    # 如果已安装则卸载
    if [ -f "/etc/systemd/system/hysteria-server.service" ]; then
        systemctl stop hysteria-server.service
        systemctl disable hysteria-server.service > /dev/null 2>&1
        rm -rf /etc/hysteria
        rm -f /etc/systemd/system/hysteria-server.service
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
    echo "HYSTERIA_PORT=$HY2_PORT" >> /root/proxy-config
    echo "HYSTERIA_PASSWORD=$PASSWD" >> /root/proxy-config
    
    echo -e "${GREEN}[√] Hysteria2 安装完成!${NC}"
}

# 创建管理脚本
create_management_script() {
    cat > /usr/local/bin/x << 'EOF'
#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 恢复默认颜色

# 加载配置
if [ -f "/root/proxy-config" ]; then
    source /root/proxy-config
else
    echo -e "${RED}未找到配置文件，请先安装协议${NC}"
    exit 1
fi

# 获取公网IP和ISP信息
get_network_info() {
    public_ip=$(curl -s https://api.ipify.org)
    isp=$(curl -s https://speed.cloudflare.com/meta | jq -r '[.asn, .asOrganization, .country] | map(tostring) | join("-")')
    echo "$public_ip,$isp"
}

# 显示所有链接
show_links() {
    local network_info=($(get_network_info | tr ',' ' '))
    local public_ip=${network_info[0]}
    local isp=${network_info[1]}
    
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议连接信息                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
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
    
    echo -e "${GREEN}所有链接已显示完毕${NC}"
    echo -e "${YELLOW}================================================${NC}"
}

# 更新所有服务
update_services() {
    echo -e "${YELLOW}[+] 正在更新所有协议服务...${NC}"
    
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
    
    echo -e "${GREEN}[√] 所有协议更新完成!${NC}"
}

# 卸载所有服务
uninstall_services() {
    echo -e "${YELLOW}[+] 正在卸载所有协议服务...${NC}"
    
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
    echo -e "${GREEN}1. 更新所有服务端程序${NC}"
    echo -e "${GREEN}2. 查看所有协议链接${NC}"
    echo -e "${RED}3. 卸载所有协议${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo -e "输入 ${CYAN}x${NC} 即可打开此菜单"
    echo -e "${YELLOW}================================================${NC}"
    
    read -p "请输入选项 (1-3): " choice
    
    case $choice in
        1) update_services ;;
        2) show_links ;;
        3) uninstall_services ;;
        *) echo -e "${RED}无效选项!${NC}" ;;
    esac
    
    echo ""
    read -p "按回车键返回主菜单..." input
}

# 主函数
main() {
    while true; do
        show_menu
    done
}

# 启动主函数
main
EOF

    chmod +x /usr/local/bin/x
    echo -e "${GREEN}[√] 管理命令 'x' 已创建!${NC}"
    echo -e "${YELLOW}您可以在终端输入 ${CYAN}x${YELLOW} 来管理协议${NC}"
}

# 主安装函数
install_all_protocols() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}此脚本必须以root权限运行!${NC}"
        exit 1
    fi
    
    # 清空旧配置
    rm -f /root/proxy-config
    
    # 安装依赖
    install_dependencies
    
    # 安装三个协议
    install_juicity
    install_tuic
    install_hysteria2
    
    # 创建管理脚本
    create_management_script
    
    # 显示安装完成信息
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}         所有协议已成功安装!          ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    echo -e "使用 ${CYAN}x${NC} 命令管理协议:"
    echo -e "  ${GREEN}1. 更新所有服务端程序${NC}"
    echo -e "  ${GREEN}2. 查看所有协议链接${NC}"
    echo -e "  ${RED}3. 卸载所有协议${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
    # 立即显示所有链接
    echo -e "${GREEN}正在显示所有协议链接...${NC}"
    /usr/local/bin/x 2
}

# 启动安装
install_all_protocols
