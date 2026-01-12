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
pip3 install scapy

# Создание пользователя для службы (опционально)
if ! id "ap-guardian" &>/dev/null; then
    echo "Создание пользователя ap-guardian..."
    useradd -r -s /bin/false ap-guardian
fi

# Создание директорий
echo "Создание директорий..."
mkdir -p /etc/ap-guardian
mkdir -p /var/log/ap-guardian
mkdir -p /var/run/ap-guardian
mkdir -p /usr/lib/ap-guardian

# Копирование файлов
echo "Копирование файлов..."
cp -r src/* /usr/lib/ap-guardian/
chmod +x /usr/lib/ap-guardian/main.py

# Создание символической ссылки
ln -sf /usr/lib/ap-guardian/main.py /usr/bin/ap-guardian
chmod +x /usr/bin/ap-guardian

# Копирование конфигурации
if [ ! -f /etc/ap-guardian/config.json ]; then
    cp files/etc/ap-guardian/config.json /etc/ap-guardian/
fi

# Установка systemd service
echo "Установка systemd service..."
cp install/ap-guardian.service /etc/systemd/system/
systemctl daemon-reload

# Настройка прав
chown -R ap-guardian:ap-guardian /etc/ap-guardian
chown -R ap-guardian:ap-guardian /var/log/ap-guardian
chown -R ap-guardian:ap-guardian /var/run/ap-guardian

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
