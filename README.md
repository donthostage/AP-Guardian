# AP-Guardian

Система активной сетевой защиты для автоматического обнаружения и блокировки кибератак уровня L2/L3 в общедоступных Wi-Fi сетях на базе маршрутизаторов с OpenWrt и обычных Linux систем.

## Возможности

### Детекторы угроз

- **ARP Spoofing Detection**: Автоматическое обнаружение ARP спуфинга и конфликтов
- **DDoS Protection**: Защита от SYN Flood, UDP/ICMP Flood атак с отслеживанием источников
- **Network Scanning Detection**: Обнаружение горизонтального и вертикального сканирования
- **Bruteforce Detection**: Обнаружение брутфорс атак на критические порты
- **Automatic Firewall Management**: Автоматическая блокировка угроз через iptables/arptables

### Дополнительные функции

- **Система статистики**: Сбор и анализ статистики по пакетам, угрозам и блокировкам
- **Система уведомлений**: Email, Webhook и скрипты для уведомлений о угрозах
- **LuCI Web Interface**: Веб-интерфейс для управления и мониторинга (OpenWrt)
- **REST API**: Экспорт статуса и статистики через JSON файлы

## Требования

- Python 3.9+
- Linux система (Ubuntu/Debian/OpenWrt)
- iptables, arptables
- scapy (для анализа пакетов)
- requests (для webhook уведомлений)

## Быстрая установка на Ubuntu

```bash
# Клонирование репозитория
git clone <repository_url>
cd ap-guardian

# Установка
sudo bash install_ubuntu.sh

# Запуск службы
sudo systemctl start ap-guardian
sudo systemctl enable ap-guardian

# Проверка статуса
sudo systemctl status ap-guardian
```

## Установка на OpenWrt

```bash
# Сборка .ipk пакета
make package/ap-guardian/compile

# Установка на OpenWrt
opkg install ap-guardian_*.ipk
```

## Конфигурация

Основной конфигурационный файл: `/etc/ap-guardian/config.json`

Пример настройки уведомлений:

```json
{
  "notifications": {
    "enabled": true,
    "min_threat_level": "HIGH",
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587,
      "username": "your-email@gmail.com",
      "password": "your-password",
      "from": "your-email@gmail.com",
      "to": ["admin@example.com"]
    }
  }
}
```

## Использование

```bash
# Запуск службы
sudo systemctl start ap-guardian

# Просмотр логов
sudo journalctl -u ap-guardian -f

# Проверка статуса
./scripts/monitor_status.sh

# Просмотр статистики
cat /var/run/ap-guardian-status.json | python3 -m json.tool
```

## Тестирование

См. [TESTING.md](TESTING.md) для подробных инструкций по тестированию системы.

## Документация

- [INSTALL.md](INSTALL.md) - Инструкция по установке
- [USAGE.md](USAGE.md) - Руководство по использованию
- [TESTING.md](TESTING.md) - Руководство по тестированию
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) - Структура проекта
- [CHANGELOG.md](CHANGELOG.md) - История изменений

## Основные компоненты

### Детекторы угроз

1. **ARP Spoofing Detector** - Обнаружение ARP спуфинга и конфликтов
2. **DDoS Detector** - Защита от SYN Flood, UDP/ICMP Flood
3. **Network Scan Detector** - Обнаружение горизонтального и вертикального сканирования
4. **Bruteforce Detector** - Обнаружение брутфорс атак

### Firewall Manager

Автоматическое управление правилами iptables/arptables для блокировки угроз.

### Packet Capture

Асинхронный захват и анализ сетевых пакетов с поддержкой scapy и raw socket.

### Statistics & Notifications

- Сбор статистики по пакетам, угрозам и блокировкам
- Email, Webhook и скрипт уведомления

## Лицензия

GPL-2.0
