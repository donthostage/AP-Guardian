#!/bin/bash
# quick_demo.sh - Быстрая демонстрация AP-Guardian в Termux

echo "=== Быстрая демонстрация AP-Guardian ==="

# 1. Установка зависимостей в Termux
pkg update -y && pkg upgrade -y
pkg install python python-pip git -y
pip install scapy

# 2. Клонирование проекта
git clone https://github.com/ваш-репозиторий/ap-guardian.git
cd ap-guardian

# 3. Запуск симулятора атак (в одном терминале)
echo "Запуск симулятора атак..."
python demo_attack_simulator.py &

# 4. Запуск AP-Guardian (в другом терминале)
echo "Запуск системы защиты..."
echo "Откройте новый терминал (свайп слева -> '+') и выполните:"
echo "cd ap-guardian && python -m src.main"

# 5. Запуск веб-интерфейса для мониторинга
echo "Запуск веб-интерфейса мониторинга..."
python -m http.server 8080 --bind 0.0.0.0 &
sleep 2

# 6. Показ инструкций
echo ""
echo "=== ИНСТРУКЦИЯ ДЛЯ ПРЕЗЕНТАЦИИ ==="
echo "1. Симулятор атак: генерирует искусственные атаки"
echo "2. AP-Guardian: обнаруживает и блокирует атаки"
echo "3. Веб-интерфейс: http://localhost:8080"
echo ""
echo "Для остановки: Ctrl+C в обоих терминалах"
