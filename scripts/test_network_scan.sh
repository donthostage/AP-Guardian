#!/bin/bash
# Скрипт для тестирования Network Scan
# Использование: ./test_network_scan.sh <target_ip_or_network>

TARGET=${1:-"127.0.0.1"}

echo "Тестирование Network Scan на $TARGET"
echo "ВНИМАНИЕ: Это тестовое сканирование! Используйте только на своих системах."
echo "Нажмите Ctrl+C для остановки"
sleep 3

# Проверка наличия nmap
if ! command -v nmap &> /dev/null; then
    echo "Установка nmap..."
    sudo apt-get install -y nmap
fi

# Запуск сканирования
echo "Запуск Network Scan..."
nmap -sS -p- $TARGET
