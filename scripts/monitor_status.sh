#!/bin/bash
# Скрипт для мониторинга статуса AP-Guardian

echo "=== Статус AP-Guardian ==="
echo ""

# Проверка процесса
if pgrep -f "ap-guardian" > /dev/null; then
    echo "✓ Процесс запущен"
    echo "  PID: $(pgrep -f 'ap-guardian' | head -1)"
else
    echo "✗ Процесс не запущен"
fi

echo ""

# Проверка статуса службы (если используется systemd)
if systemctl is-active --quiet ap-guardian 2>/dev/null; then
    echo "✓ Systemd служба активна"
    systemctl status ap-guardian --no-pager -l | head -5
else
    echo "ℹ Systemd служба не используется или не активна"
fi

echo ""

# Проверка файлов статуса
if [ -f /var/run/ap-guardian-status.json ]; then
    echo "✓ Файл статуса существует"
    echo "  Статус:"
    cat /var/run/ap-guardian-status.json | python3 -m json.tool 2>/dev/null || cat /var/run/ap-guardian-status.json
else
    echo "✗ Файл статуса не найден"
fi

echo ""

# Проверка угроз
if [ -f /var/run/ap-guardian-threats.json ]; then
    THREATS_COUNT=$(cat /var/run/ap-guardian-threats.json | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    echo "Угроз обнаружено: $THREATS_COUNT"
    if [ "$THREATS_COUNT" -gt 0 ]; then
        echo "  Угрозы:"
        cat /var/run/ap-guardian-threats.json | python3 -m json.tool 2>/dev/null | head -20
    fi
else
    echo "✗ Файл угроз не найден"
fi

echo ""

# Проверка блокировок
if [ -f /var/run/ap-guardian-blocks.json ]; then
    BLOCKS_COUNT=$(cat /var/run/ap-guardian-blocks.json | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    echo "Активных блокировок: $BLOCKS_COUNT"
    if [ "$BLOCKS_COUNT" -gt 0 ]; then
        echo "  Блокировки:"
        cat /var/run/ap-guardian-blocks.json | python3 -m json.tool 2>/dev/null | head -20
    fi
else
    echo "ℹ Файл блокировок не найден"
fi

echo ""

# Проверка правил iptables
echo "Правила iptables AP_GUARDIAN_INPUT:"
iptables -L AP_GUARDIAN_INPUT -n -v 2>/dev/null | head -10 || echo "  Цепочка не найдена"

echo ""
echo "Правила arptables AP_GUARDIAN:"
arptables -L AP_GUARDIAN -n -v 2>/dev/null | head -10 || echo "  Цепочка не найдена"

echo ""

# Последние логи
echo "Последние логи (последние 10 строк):"
journalctl -u ap-guardian -n 10 --no-pager 2>/dev/null || tail -10 /var/log/ap-guardian.log 2>/dev/null || echo "  Логи не найдены"
