#!/bin/bash

CONFIG_FILE="/etc/slowdns.conf"
DOMAIN=""
EMAIL=""

# Create configuration file if it doesn't exist
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "LISTEN_IP=0.0.0.0" > "$CONFIG_FILE"
    echo "DNS_PORT=5300" >> "$CONFIG_FILE"
    echo "SSH_HOST=127.0.0.1" >> "$CONFIG_FILE"
    echo "SSH_PORT=22" >> "$CONFIG_FILE"
fi

# Generate a new DNSTT Public Key if not exists
if ! grep -q "DNSTT_PUBLIC_KEY" "$CONFIG_FILE"; then
    PUBKEY=$(openssl rand -hex 32)
    echo "DNSTT_PUBLIC_KEY=$PUBKEY" >> "$CONFIG_FILE"
fi

# Update system and install required packages
echo "[+] Updating system and installing dependencies..."
apt update && apt install -y openssh-server cmake make gcc git nginx dropbear certbot python3-certbot-nginx curl

# Configure SSH
echo "[+] Configuring SSH..."
sed -i '/^#\?PasswordAuthentication /c\PasswordAuthentication yes' /etc/ssh/sshd_config
sed -i '/^#\?PermitRootLogin /c\PermitRootLogin yes' /etc/ssh/sshd_config
sed -i '/^#\?AllowTcpForwarding /c\AllowTcpForwarding yes' /etc/ssh/sshd_config
sed -i '/^#\?GatewayPorts /c\GatewayPorts yes' /etc/ssh/sshd_config
systemctl restart ssh

# Configure Dropbear
echo "[+] Configuring Dropbear..."
cat <<EOF > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 444"
EOF
systemctl restart dropbear

# Install BadVPN
echo "[+] Installing BadVPN..."
cd /root
git clone https://github.com/ambrop72/badvpn.git
cd badvpn
cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)
make install

# Create systemd service for BadVPN
echo "[+] Creating BadVPN systemd service..."
cat <<EOF > /etc/systemd/system/badvpn.service
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start BadVPN service
systemctl daemon-reload
systemctl enable badvpn
systemctl restart badvpn

# Function to setup WebSocket SSL VPN
setup_ws_ssl() {
    echo "========================================="
    echo " WS Proxy SSL VPN Installer"
    echo "========================================="
    read -p "Enter your domain (e.g., vpn.example.com or IP): " DOMAIN
    read -p "Enter your email (for Let's Encrypt SSL): " EMAIL

    if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
        echo "❌ Domain and email are required!"
        return
    fi

    # Configure Nginx WebSocket proxy
    echo "[+] Configuring Nginx WebSocket proxy..."
    cat <<EOF > /etc/nginx/sites-available/ws-proxy
server {
    listen 80;
    server_name $DOMAIN;

    location /ws {
        proxy_pass http://127.0.0.1:2086/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
    ln -s /etc/nginx/sites-available/ws-proxy /etc/nginx/sites-enabled/ 2>/dev/null || echo "⚠️ Warning: Nginx config link exists!"
    systemctl restart nginx || { echo "❌ Failed to restart Nginx!"; return; }

    # Obtain SSL certificate
    echo "[+] Obtaining SSL certificate..."
    certbot --nginx --email $EMAIL --agree-tos --no-eff-email -d $DOMAIN || { echo "❌ SSL certificate setup failed!"; return; }

    # Update Nginx configuration for SSL
    cat <<EOF > /etc/nginx/sites-available/ws-proxy
server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    location /ws {
        proxy_pass http://127.0.0.1:2086/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
    systemctl restart nginx || { echo "❌ Failed to restart Nginx after SSL setup!"; return; }

    # Install Websocat
    echo "[+] Installing Websocat..."
    pkill websocat 2>/dev/null
    sleep 2
    rm -f /usr/local/bin/websocat 2>/dev/null

    curl -s https://api.github.com/repos/vi/websocat/releases/latest | grep browser_download_url | grep linux | cut -d '"' -f 4 | wget -O /usr/local/bin/websocat -i - || { echo "❌ Failed to download Websocat!"; return; }
    chmod +x /usr/local/bin/websocat

    # Create WebSocket Proxy service
    echo "[+] Creating WebSocket Proxy service..."
    cat <<EOF > /usr/local/bin/ws-proxy
#!/bin/bash
while true; do
    websocat -s 2086 --binary --exit-on-eof --tcp-listen 127.0.0.1:2086
done
EOF
    chmod +x /usr/local/bin/ws-proxy

    cat <<EOF > /etc/systemd/system/ws-proxy.service
[Unit]
Description=WebSocket Proxy Service
After=network.target

[Service]
ExecStart=/usr/local/bin/ws-proxy
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ws-proxy
    systemctl restart ws-proxy || { echo "❌ Failed to start WS Proxy service!"; return; }

    echo "========================================="
    echo " ✅ WebSocket SSL VPN Setup Complete!"
    echo " Use SSH over WebSocket with:"
    echo " - Host: $DOMAIN"
    echo " - Port: 443 (SSL)"
    echo " - Payload: GET /ws HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]"
    echo "========================================="
}

# SlowDNS & SSH Manager
while true; do
    clear
    source "$CONFIG_FILE"

    echo "============================"
    echo "  SlowDNS & SSH Manager  "
    echo "============================"
    echo "[+] DNSTT Public Key: $DNSTT_PUBLIC_KEY"
    echo "============================"
    echo "1. Create SSH User"
    echo "2. Delete SSH User"
    echo "3. List SSH Users"
    echo "4. Set Listen IP"
    echo "5. Set SSH Host"
    echo "6. Restart SlowDNS"
    echo "7. Setup WS SSL"
    echo "8. Exit"
    echo "============================"
    read -p "Choose an option: " option

    case $option in
        1)
            read -p "Enter username: " username
            read -p "Enter password: " password
            useradd -m -s /bin/bash $username
            echo "$username:$password" | chpasswd
            echo "[+] User $username created!"
            echo "============================"
            echo "Account Details:"
            echo "Username: $username"
            echo "Password: $password"
            echo "IP Address: $(curl -s ifconfig.me)"
            echo "WebSocket SSL: $DOMAIN"
            echo "Port: 443"
            echo "WebSocket Payload: GET /ws HTTP/1.1[crlf]Host: $DOMAIN[crlf]Upgrade: websocket[crlf][crlf]"
            echo "============================"
            read -p "Press Enter to continue..."
            ;;
        2)
            read -p "Enter username to delete: " username
            userdel -r $username
            echo "[+] User $username deleted!"
            read -p "Press Enter to continue..."
            ;;
        3)
            echo "[+] Listing users..."
            awk -F':' '$3 >= 1000 {print $1}' /etc/passwd
            read -p "Press Enter to continue..."
            ;;
        4)
            read -p "Enter new Listen IP: " new_listen_ip
            sed -i "s/^LISTEN_IP=.*/LISTEN_IP=$new_listen_ip/" $CONFIG_FILE
            echo "[+] Listen IP updated to $new_listen_ip!"
            systemctl restart slowdns
            read -p "Press Enter to continue..."
            ;;
        5)
            read -p "Enter new SSH Host: " new_ssh_host
            sed -i "s/^SSH_HOST=.*/SSH_HOST=$new_ssh_host/" $CONFIG_FILE
            echo "[+] SSH Host updated to $new_ssh_host!"
            systemctl restart slowdns
            read -p "Press Enter to continue..."
            ;;
        6)
            systemctl restart slowdns
            echo "[+] SlowDNS restarted!"
            read -p "Press Enter to continue..."
            ;;
        7)
            setup_ws_ssl
            read -p "Press Enter to continue..."
            ;;
        8)
            exit 0
            ;;
        *)
            echo "Invalid option!"
            sleep 1
            ;;
    esac
done
