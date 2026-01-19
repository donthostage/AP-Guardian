#!/bin/bash
# Установщик для Ubuntu с поддержкой PEP 668

set -e

echo "=== Установка AP-Guardian с учётом PEP 668 ==="

# Проверка root
if [ "$EUID" -ne 0 ]; then 
    echo "Запусти с sudo: sudo $0"
    exit 1
fi

# 1. Обновление
apt update -qq

# 2. Установка системных пакетов
apt install -y python3 python3-pip git iptables arptables libpcap-dev

# 3. ОБХОД PEP 668 - используем --break-system-packages
echo "Обход PEP 668..."
pip3 install --break-system-packages scapy requests

# 4. Или используем venv (лучший вариант)
echo "Создание виртуального окружения..."
python3 -m venv /opt/ap-guardian-venv
source /opt/ap-guardian-venv/bin/activate
pip install scapy requests
deactivate

# 5. Клонирование
cd /opt
git clone https://github.com/donthostage/AP-Guardian.git
cd AP-Guardian

# 6. Создаём скрипт запуска с venv
cat > /usr/local/bin/ap-guardian << 'EOF'
#!/bin/bash
# Запуск через виртуальное окружение
source /opt/ap-guardian-venv/bin/activate
cd /opt/AP-Guardian
python3 -m src.main "$@"
deactivate
EOF

chmod +x /usr/local/bin/ap-guardian

echo "Готово! Запускай: sudo ap-guardian"
