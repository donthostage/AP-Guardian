#!/bin/bash
# Быстрая установка AP-Guardian на Ubuntu

set -e

echo "=== Быстрая установка AP-Guardian ==="

# Проверка прав root
if [ "$EUID" -ne 0 ]; then 
    echo "Ошибка: Запустите скрипт с правами root (sudo)"
    exit 1
fi

# Обновление системы
echo "[1/7] Обновление списка пакетов..."
apt-get update -qq

# Установка зависимостей
echo "[2/7] Установка зависимостей..."
apt-get install -y python3 python3-pip python3-dev \
    iptables arptables \
    build-essential libpcap-dev \
    git curl wget

# Установка Python пакетов
echo "[3/7] Установка Python пакетов..."
pip3 install --upgrade pip
pip3 install scapy requests

# Создание директорий
echo "[4/7] Создание директорий..."
mkdir -p /etc/ap-guardian
mkdir -p /var/log/ap-guardian
mkdir -p /var/run/ap-guardian
mkdir -p /usr/lib/ap-guardian

# Копирование файлов (предполагается, что мы в директории проекта)
echo "[5/7] Копирование файлов..."
if [ -d "src" ]; then
    cp -r src/* /usr/lib/ap-guardian/
    chmod +x /usr/lib/ap-guardian/main.py
else
    echo "Ошибка: директория src не найдена. Убедитесь, что вы в корне проекта."
    exit 1
fi

# Создание символической ссылки
ln -sf /usr/lib/ap-guardian/main.py /usr/bin/ap-guardian
chmod +x /usr/bin/ap-guardian

# Копирование конфигурации
if [ -f "files/etc/ap-guardian/config.json" ]; then
    cp files/etc/ap-guardian/config.json /etc/ap-guardian/
else
    echo "Предупреждение: файл конфигурации не найден, создается базовый..."
    cat > /etc/ap-guardian/config.json << 'EOF'
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
    "trusted_devices": [],
    "monitor_gateway": true
  },
  "ddos": {
    "enabled": true,
    "syn_flood": {
      "enabled": true,
      "syn_per_second_threshold": 50,
      "syn_ack_ratio_threshold": 0.1,
      "incomplete_connections_threshold": 30
    },
    "udp_flood": {
      "enabled": true,
      "packets_per_second_threshold": 200,
      "anomaly_detection": true
    },
    "icmp_flood": {
      "enabled": true,
      "packets_per_second_threshold": 100,
      "anomaly_detection": true
    },
    "adaptive_thresholds": true
  },
  "network_scan": {
    "enabled": true,
    "horizontal_scan": {
      "enabled": true,
      "hosts_threshold": 5,
      "time_window": 60
    },
    "vertical_scan": {
      "enabled": true,
      "ports_threshold": 10,
      "time_window": 60
    }
  },
  "bruteforce": {
    "enabled": true,
    "failed_attempts_threshold": 3,
    "time_window": 300,
    "ports_to_monitor": [22, 23, 80, 443, 3306, 5432]
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
  }
}
EOF
fi

# Установка systemd service
echo "[6/7] Установка systemd service..."
if [ -f "install/ap-guardian.service" ]; then
    cp install/ap-guardian.service /etc/systemd/system/
    systemctl daemon-reload
else
    cat > /etc/systemd/system/ap-guardian.service << 'EOF'
[Unit]
Description=AP-Guardian - Active Network Protection System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /usr/lib/ap-guardian/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

MemoryLimit=100M
CPUQuota=30%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi

# Настройка прав
echo "[7/7] Настройка прав..."
chmod 644 /etc/ap-guardian/config.json
chmod 755 /usr/lib/ap-guardian

echo ""
echo "=== Установка завершена! ==="
echo ""
echo "Следующие шаги:"
echo "1. Проверьте конфигурацию: cat /etc/ap-guardian/config.json"
echo "2. Запустите службу: sudo systemctl start ap-guardian"
echo "3. Проверьте статус: sudo systemctl status ap-guardian"
echo "4. Просмотрите логи: sudo journalctl -u ap-guardian -f"
echo ""
