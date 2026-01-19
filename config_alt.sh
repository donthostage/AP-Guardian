# Просто создай правильный config.json в папке проекта
cd ~/qwe/AP-Guardian
cat > config.json << 'EOF'
{
  "general": {
    "log_level": "INFO",
    "check_interval": 3
  },
  "arp_spoofing": {
    "enabled": true,
    "check_interval": 3
  },
  "ddos": {
    "enabled": true
  },
  "network_scan": {
    "enabled": true
  },
  "bruteforce": {
    "enabled": true
  },
  "firewall": {
    "enabled": true,
    "auto_block": true
  },
  "notifications": {
    "enabled": false
  }
}
EOF

# И запусти
sudo python3 -m src.main
