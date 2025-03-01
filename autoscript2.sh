#!/bin/bash

CONFIG_FILE="/etc/slowdns.conf"
DOMAIN=""
EMAIL=""

### DEFAULT CONFIGURATION ###
DEFAULT_LISTEN_IP="0.0.0.0"
DEFAULT_SSH_HOST="13.215.153.241"
DNS_PORT="5300"
SSHD_PORT="22"

### INSTALLATION ###
install_packages() {
    echo "[+] Installing dependencies..."
    apt update && apt install -y python3 screen openssh-server nginx dropbear certbot python3-certbot-nginx curl cmake make gcc git
}

setup_config() {
    echo "[+] Setting up configuration..."
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "LISTEN_IP=$DEFAULT_LISTEN_IP" > "$CONFIG_FILE"
        echo "SSH_HOST=$DEFAULT_SSH_HOST" >> "$CONFIG_FILE"
        echo "DNS_PORT=$DNS_PORT" >> "$CONFIG_FILE"
        echo "SSH_PORT=$SSHD_PORT" >> "$CONFIG_FILE"
    fi
    source "$CONFIG_FILE"
}

create_slowdns_script() {
    echo "[+] Creating SlowDNS server..."
    source "$CONFIG_FILE"
    cat <<EOF > /usr/local/bin/slowdns.py
#!/usr/bin/env python3
import socket
import base64
import subprocess

LISTEN_IP = "$LISTEN_IP"
DNS_PORT = $DNS_PORT
SSH_HOST = "$SSH_HOST"
SSH_PORT = $SSHD_PORT

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((LISTEN_IP, DNS_PORT))

print(f"[*] SlowDNS Server Running on {LISTEN_IP}:{DNS_PORT}")

def handle_dns_request(data, addr):
    try:
        domain = data[12:-4].decode(errors="ignore")
        encoded_data = domain.split(".")[0]
        decoded_data = base64.urlsafe_b64decode(encoded_data + "==").decode(errors="ignore")
        response = subprocess.getoutput(f"echo {decoded_data} | nc {SSH_HOST} {SSH_PORT}")
        encoded_response = base64.urlsafe_b64encode(response.encode()).decode().rstrip("=")
        response_packet = data[:2] + b"\\x81\\x80" + data[4:6] + data[4:6] + b"\\x00\\x00\\x00\\x00" + data[12:] + b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04" + socket.inet_aton("127.0.0.1")
        server.sendto(response_packet, addr)
    except Exception as e:
        print(f"[!] Error: {e}")

while True:
    data, addr = server.recvfrom(512)
    handle_dns_request(data, addr)
EOF
    chmod +x /usr/local/bin/slowdns.py
}

create_start_script() {
    echo "[+] Creating SlowDNS start script..."
    cat <<EOF > /usr/local/bin/start-slowdns.sh
#!/bin/bash
source "$CONFIG_FILE"
screen -dmS slowdns python3 /usr/local/bin/slowdns.py
EOF
    chmod +x /usr/local/bin/start-slowdns.sh
}

create_service() {
    echo "[+] Creating SlowDNS service..."
    cat <<EOF > /etc/systemd/system/slowdns.service
[Unit]
Description=SlowDNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/start-slowdns.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable slowdns
    systemctl start slowdns
}

setup_firewall() {
    echo "[+] Configuring firewall..."
    ufw allow $DNS_PORT/udp
    ufw allow $SSHD_PORT/tcp
    ufw reload
}

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
