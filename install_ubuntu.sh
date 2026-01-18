#!/bin/bash
# Скрипт установки AP-Guardian на Ubuntu/Debian

set -e

echo "=== Установка AP-Guardian ==="

# Проверка прав root
if [ "$EUID" -ne 0 ]; then 
    echo "Ошибка: Запустите скрипт с правами root (sudo)"
    exit 1
fi

# Обновление системы
echo "Обновление списка пакетов..."
apt-get update

# Установка зависимостей
echo "Установка зависимостей..."
apt-get install -y python3 python3-pip python3-dev \
    iptables arptables \
    build-essential libpcap-dev \
    git

# Установка Python пакетов
echo "Установка Python пакетов..."
pip3 install scapy requests

# Создание директорий
echo "Создание директорий..."
mkdir -p /etc/ap-guardian
mkdir -p /var/log/ap-guardian
mkdir -p /var/run/ap-guardian
mkdir -p /usr/lib/ap-guardian

# Сохранение текущей директории
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Копирование исходного кода
echo "Копирование исходного кода..."
cp -r "${SCRIPT_DIR}/src" /usr/lib/ap-guardian/
# Копируем также __init__.py из корня если есть
if [ -f "${SCRIPT_DIR}/__init__.py" ]; then
    cp "${SCRIPT_DIR}/__init__.py" /usr/lib/ap-guardian/ 2>/dev/null || true
fi

# Установка через setup.py для создания entry point
echo "Установка Python пакета..."
cd "${SCRIPT_DIR}" || exit 1
pip3 install -e . 2>/dev/null || {
    echo "Предупреждение: Не удалось установить через setup.py, используем wrapper скрипт"
}

# Создание альтернативной символической ссылки (если setup.py не сработал)
if [ ! -f /usr/local/bin/ap-guardian ] && [ ! -f /usr/bin/ap-guardian ]; then
    # Создаем wrapper скрипт
    cat > /usr/local/bin/ap-guardian << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/usr/lib/ap-guardian')
os.chdir('/usr/lib/ap-guardian')
from src.main import main
if __name__ == '__main__':
    main()
EOF
    chmod +x /usr/local/bin/ap-guardian
fi

# Копирование конфигурации
if [ ! -f /etc/ap-guardian/config.json ]; then
    cp "${SCRIPT_DIR}/files/etc/ap-guardian/config.json" /etc/ap-guardian/
fi

# Установка systemd service
echo "Установка systemd service..."
cp "${SCRIPT_DIR}/install/ap-guardian.service" /etc/systemd/system/
systemctl daemon-reload

# Настройка прав (root владелец, так как требуется для работы с сетью)
chown -R root:root /etc/ap-guardian
chown -R root:root /usr/lib/ap-guardian
chmod -R 755 /usr/lib/ap-guardian
chmod 644 /etc/ap-guardian/config.json
# Директории для логов и runtime
mkdir -p /var/log/ap-guardian /var/run/ap-guardian
chmod 755 /var/log/ap-guardian /var/run/ap-guardian

# Настройка capabilities для захвата пакетов без root
setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.9 2>/dev/null || \
setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3 2>/dev/null || \
echo "Предупреждение: Не удалось установить capabilities. Запускайте с правами root."

echo ""
echo "=== Установка завершена ==="
echo ""
echo "Для запуска службы:"
echo "  sudo systemctl start ap-guardian"
echo "  sudo systemctl enable ap-guardian"
echo ""
echo "Для проверки статуса:"
echo "  sudo systemctl status ap-guardian"
echo ""
echo "Для просмотра логов:"
echo "  sudo journalctl -u ap-guardian -f"
