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
JUICITY_CONFIG_FILE="/root/juicity-config"  # 新增单独保存Juicity配置文件路径

# check_root() 及其他函数保持不变

# 安装/更新所有协议服务合并函数
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

# 1. 补全 get_network_info 函数（放在脚本顶部或合适位置）
get_network_info() {
    # 返回公网IP和ISP名称，用逗号分隔
    local ip isp
    ip=$(curl -s https://ip.gs || curl -s https://api.ip.sb/ip)
    isp=$(curl -s https://ip.gs/isp || echo "Unknown ISP")
    echo "$ip,$isp"
}

# 2. 修正 show_links 函数开头，source配置文件时加判断，并保证定义了必需变量

show_links() {
    # 先清空之前可能的变量
    unset XRAY_UUID XRAY_PORT XRAY_PUBLIC_KEY XRAY_SHORT_ID
    unset JUICITY_SHARE_LINK
    unset TUIC_UUID TUIC_PASSWORD TUIC_PORT
    unset HYSTERIA_PASSWORD HYSTERIA_PORT
    unset ANYTLS_PASSWORD ANYTLS_PORT

    # 读取主配置
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
    # 读取 Juicity 配置
    if [[ -f "$JUICITY_CONFIG_FILE" ]]; then
        source "$JUICITY_CONFIG_FILE"
    fi

    # 调用网络信息
    local network_info=($(get_network_info | tr ',' ' '))
    local public_ip=${network_info[0]}
    local isp=${network_info[1]}
    
    echo -e "${YELLOW}================================================${NC}"
    echo -e "${GREEN}                 协议连接信息                  ${NC}"
    echo -e "${YELLOW}================================================${NC}"
    
    # Xray Reality 链接示例（假设你配置里变量名）
    if [[ -n "$XRAY_UUID" && -n "$XRAY_PORT" && -n "$XRAY_PUBLIC_KEY" && -n "$XRAY_SHORT_ID" ]]; then
        echo -e "${CYAN}Xray Reality 链接:${NC}"
        echo -e "${GREEN}vless://${XRAY_UUID}@${public_ip}:${XRAY_PORT}?encryption=none&security=reality&sni=www.nazhumi.com&fp=chrome&pbk=${XRAY_PUBLIC_KEY}&sid=${XRAY_SHORT_ID}&allowInsecure=1&type=xhttp&mode=auto#${isp}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Juicity 链接
    if [[ -n "$JUICITY_SHARE_LINK" ]]; then
        echo -e "${CYAN}Juicity 链接:${NC}"
        echo -e "${GREEN}${JUICITY_SHARE_LINK}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Tuic 链接示例
    if [[ -n "$TUIC_UUID" && -n "$TUIC_PASSWORD" && -n "$TUIC_PORT" ]]; then
        echo -e "${CYAN}Tuic 链接:${NC}"
        echo -e "${GREEN}tuic://${TUIC_UUID}:${TUIC_PASSWORD}@${public_ip}:${TUIC_PORT}?congestion_control=bbr&alpn=h3&sni=www.bing.com&udp_relay_mode=native&allow_insecure=1#${isp}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # Hysteria2 链接示例
    if [[ -n "$HYSTERIA_PASSWORD" && -n "$HYSTERIA_PORT" ]]; then
        echo -e "${CYAN}Hysteria2 链接:${NC}"
        echo -e "${GREEN}hysteria2://${HYSTERIA_PASSWORD}@${public_ip}:${HYSTERIA_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#${isp}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi
    
    # AnyTLS 链接示例
    if [[ -n "$ANYTLS_PASSWORD" && -n "$ANYTLS_PORT" ]]; then
        echo -e "${CYAN}AnyTLS 链接:${NC}"
        echo -e "${GREEN}anytls://${ANYTLS_PASSWORD}@${public_ip}:${ANYTLS_PORT}?allowInsecure=true#${isp}${NC}"
        echo -e "${YELLOW}------------------------------------------------${NC}"
    fi

    echo -e "${GREEN}所有链接已显示完毕${NC}"
    echo -e "${YELLOW}================================================${NC}"
}

# install_juicity 函数修改保存配置到单独文件，方便读取
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
    
    # 保存配置到单独文件，避免覆盖主配置
    echo "JUICITY_PORT=$PORT" > $JUICITY_CONFIG_FILE
    echo "JUICITY_UUID=$UUID" >> $JUICITY_CONFIG_FILE
    echo "JUICITY_PASSWORD=$PASSWORD" >> $JUICITY_CONFIG_FILE
    echo "JUICITY_SHARE_LINK=\"$SHARE_LINK\"" >> $JUICITY_CONFIG_FILE
    
    echo -e "${GREEN}[√] Juicity 安装完成!${NC}"
}

# show_menu 修改，去掉快捷命令提示，合并1和4选项
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

# main函数改去掉create_shortcut相关调用
main() {
    check_root
    
    # 创建配置文件
    touch $CONFIG_FILE
    
    while true; do
        show_menu
    done
}

# 启动脚本
main
