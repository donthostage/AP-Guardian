#!/bin/bash
# Конвертация UCI конфига в JSON и запуск AP-Guardian

cd ~/qwe/AP-Guardian || exit 1

# Создаём JSON конфиг из твоего UCI
cat > /tmp/apg_config.json << 'EOF'
{
    "general": {
        "enabled": true,
        "log_level": "INFO",
        "log_file": "/var/log/ap-guardian.log",
        "check_interval": 3
    },
    "arp_spoofing": {
        "enabled": true,
        "check_interval": 3,
        "threshold": 3,
        "block_duration": 3600,
        "monitor_gateway": true,
        "trusted_devices": []
    },
    "ddos": {
        "enabled": true,
        "adaptive_thresholds": true,
        "syn_flood": {
            "enabled": true,
            "syn_per_second_threshold": 100,
            "syn_ack_ratio_threshold": 0.1,
            "incomplete_connections_threshold": 50
        },
        "udp_flood": {
            "enabled": true,
            "packets_per_second_threshold": 1000,
            "anomaly_detection": true
        },
        "icmp_flood": {
            "enabled": true,
            "packets_per_second_threshold": 500,
            "anomaly_detection": true
        }
    },
    "network_scan": {
        "enabled": true,
        "horizontal_scan": {
            "enabled": true,
            "hosts_threshold": 10,
            "time_window": 60
        },
        "vertical_scan": {
            "enabled": true,
            "ports_threshold": 20,
            "time_window": 60
        }
    },
    "firewall": {
        "enabled": true,
        "auto_block": true,
        "rate_limit": true,
        "rate_limit_packets": 100,
        "rate_limit_seconds": 1,
        "whitelist": [],
        "blacklist": []
    },
    "notifications": {
        "enabled": false
    },
    "bruteforce": {
        "enabled": true,
        "attempts_threshold": 5,
        "time_window": 300
    }
}
EOF

echo "Конфиг создан. Запускаю AP-Guardian..."
sudo python3 -m src.main --config /tmp/apg_config.json
