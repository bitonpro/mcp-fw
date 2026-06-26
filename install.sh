#!/bin/bash
# Quick install on target server
set -e

INSTALL_DIR="/opt/mcp-fw"
REPO="https://github.com/bitonpro/mcp-fw.git"

echo "=== mcp-fw install ==="

if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing..."
    cd "$INSTALL_DIR"
    git pull
else
    echo "Cloning..."
    git clone "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cat > /etc/systemd/system/mcp-fw.service << 'EOF'
[Unit]
Description=MCP Firewall Manager
After=network.target

[Service]
Type=simple
ExecStart=/opt/mcp-fw/venv/bin/python /opt/mcp-fw/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mcp-fw

echo "=== Done ==="
systemctl status mcp-fw --no-pager
