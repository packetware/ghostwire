#!/usr/bin/env bash

# Ghostwire install script
# Currently, only tested on Ubuntu

set -eu

repo="https://github.com/packetware/ghostwire"
arch=$(uname -m)
os=$(uname -s)

echo "🤗 Finding the right binary for your platform..."

if [ "$os" == "Linux" ]; then
    if [ "$arch" == "x86_64" ]; then
        target="linux-x86"
    elif [ "$arch" == "aarch64" | "$arch" == "arm64" ]; then
        target="linux-arm4"
    else
        echo "😩 Sorry, we don't have binaries for your platform: '$os $arch'"
        echo "   You can build from source or submit an issue at $repo/issues"
        exit 1
    fi
else
    echo "😩 Sorry, we don't have binaries for your platform: '$os $arch'. Currently, only Linux is supported."
    exit 1
fi

# Download the server
echo "📦 Downloading latest ghostwire server to /opt/ghostwire"
mkdir -p /opt/ghostwire
sudo curl --fail --location --progress-bar $repo/releases/latest/download/ghostwire-server-$target -o /opt/ghostwire/ghostwire
chmod +x /opt/ghostwire/ghostwire

# Start the systemd service
echo "🛠️  Creating systemd service for Ghostwire server"
sudo tee /etc/systemd/system/ghostwire.service > /dev/null <<EOL
[Unit]
Description=Ghostwire Server
After=network.target

[Service]
ExecStart=/opt/ghostwire/ghostwire
Restart=always
User=nobody
WorkingDirectory=/opt/ghostwire

[Install]
WantedBy=multi-user.target
EOL

echo "🚀 Starting Ghostwire server"
sudo systemctl daemon-reload
sudo systemctl enable ghostwire
sudo systemctl start ghostwire

# Download the CLI
echo "📦 Downloading latest ghostwire CLI to /usr/local/bin"
sudo curl --fail --location --progress-bar $repo/releases/latest/download/ghostwire-cli-$target -o /usr/local/bin/gw
sudo chmod +x /usr/local/bin/gw

echo "🎉 Installed Ghostwire! Run 'gw' to configure Ghostwire."
