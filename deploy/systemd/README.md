# Systemd Service Installation

## Quick Installation

```bash
# Create prism user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin prism

# Create directories
sudo mkdir -p /etc/prism /var/lib/prism /var/log/prism
sudo chown prism:prism /var/lib/prism /var/log/prism

# Copy binary
sudo cp target/release/prism /usr/local/bin/
sudo chmod +x /usr/local/bin/prism

# Copy configuration
sudo cp examples/basic.yaml /etc/prism/prism.yaml
sudo cp deploy/systemd/prism.env /etc/prism/
sudo chown -R root:prism /etc/prism
sudo chmod 640 /etc/prism/prism.yaml /etc/prism/prism.env

# Install service
sudo cp deploy/systemd/prism.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable prism
sudo systemctl start prism

# Check status
sudo systemctl status prism
sudo journalctl -u prism -f
```

## Configuration

Edit `/etc/prism/prism.yaml` for your needs, then reload:

```bash
sudo systemctl reload prism
```

## Logs

```bash
# View logs
sudo journalctl -u prism

# Follow logs
sudo journalctl -u prism -f

# Last 100 lines
sudo journalctl -u prism -n 100

# Since last boot
sudo journalctl -u prism -b
```

## Troubleshooting

```bash
# Check service status
sudo systemctl status prism

# Validate configuration
sudo -u prism /usr/local/bin/prism --config /etc/prism/prism.yaml --validate

# Run in foreground for debugging
sudo -u prism RUST_LOG=debug /usr/local/bin/prism --config /etc/prism/prism.yaml
```
