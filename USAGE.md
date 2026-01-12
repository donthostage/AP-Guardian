# Руководство по использованию AP-Guardian

## Обзор

AP-Guardian - это система активной сетевой защиты, которая автоматически обнаруживает и блокирует кибератаки уровня L2/L3 в Wi-Fi сетях.

## Основные возможности

### 1. Обнаружение ARP Spoofing

Система мониторит ARP таблицу и обнаруживает:
- Конфликты IP-MAC (один IP адрес с несколькими MAC адресами)
- Частые изменения MAC адресов
- Подделку gateway IP адреса

**Настройки:**
- `check_interval`: Интервал проверки ARP таблицы (секунды)
- `threshold`: Количество изменений MAC перед предупреждением
- `block_duration`: Длительность блокировки (секунды)
- `monitor_gateway`: Мониторинг gateway IP

### 2. Защита от DDoS атак

#### SYN Flood
- Подсчет SYN пакетов в секунду
- Анализ соотношения SYN/SYN-ACK
- Отслеживание незавершенных соединений

#### UDP/ICMP Flood
- Мониторинг скорости пакетов
- Обнаружение аномалий в трафике
- Адаптивные пороги

**Настройки:**
- `syn_per_second_threshold`: Порог SYN пакетов/сек
- `udp_flood.packets_per_second_threshold`: Порог UDP пакетов/сек
- `icmp_flood.packets_per_second_threshold`: Порог ICMP пакетов/сек
- `adaptive_thresholds`: Использование адаптивных порогов

### 3. Обнаружение сканирования сети

#### Горизонтальное сканирование
Обнаруживает попытки сканирования одного порта на многих хостах.

#### Вертикальное сканирование
Обнаруживает попытки сканирования многих портов на одном хосте.

**Настройки:**
- `horizontal_scan.hosts_threshold`: Количество хостов для обнаружения
- `vertical_scan.ports_threshold`: Количество портов для обнаружения
- `time_window`: Временное окно анализа (секунды)

### 4. Управление Firewall

Автоматическая блокировка угроз через iptables и arptables:
- Блокировка IP адресов
- Блокировка ARP запросов
- Rate limiting
- Whitelist/Blacklist

## Конфигурация

### Структура конфигурации

```json
{
  "general": {
    "enabled": true,
    "log_level": "INFO",
    "check_interval": 3
  },
  "arp_spoofing": {
    "enabled": true,
    "threshold": 3,
    "block_duration": 3600
  },
  "ddos": {
    "enabled": true,
    "syn_flood": {...},
    "udp_flood": {...},
    "icmp_flood": {...}
  },
  "network_scan": {
    "enabled": true,
    "horizontal_scan": {...},
    "vertical_scan": {...}
  },
  "firewall": {
    "enabled": true,
    "auto_block": true,
    "whitelist": [],
    "blacklist": []
  }
}
```

### Примеры конфигурации

#### Высокая безопасность

```json
{
  "arp_spoofing": {
    "threshold": 2,
    "block_duration": 7200
  },
  "ddos": {
    "syn_flood": {
      "syn_per_second_threshold": 50
    }
  },
  "network_scan": {
    "horizontal_scan": {
      "hosts_threshold": 5
    }
  }
}
```

#### Сбалансированная

```json
{
  "arp_spoofing": {
    "threshold": 3,
    "block_duration": 3600
  },
  "ddos": {
    "syn_flood": {
      "syn_per_second_threshold": 100
    }
  }
}
```

#### Минимальная нагрузка

```json
{
  "general": {
    "check_interval": 5
  },
  "ddos": {
    "adaptive_thresholds": true
  },
  "network_scan": {
    "horizontal_scan": {
      "hosts_threshold": 20
    }
  }
}
```

## Мониторинг

### Просмотр статуса

```bash
# Через LuCI веб-интерфейс
# Services -> AP-Guardian -> Status

# Через командную строку
cat /var/run/ap-guardian-status.json | python3 -m json.tool
```

### Просмотр угроз

```bash
# Через LuCI
# Services -> AP-Guardian -> Threats

# Через командную строку
cat /var/run/ap-guardian-threats.json | python3 -m json.tool
```

### Просмотр блокировок

```bash
# Через LuCI
# Services -> AP-Guardian -> Firewall

# Через командную строку
iptables -L AP_GUARDIAN_INPUT -n -v
arptables -L AP_GUARDIAN -n -v

# Или через JSON
cat /var/run/ap-guardian-blocks.json | python3 -m json.tool
```

### Просмотр логов

```bash
# Все логи
logread | grep ap-guardian

# Только ошибки
logread | grep ap-guardian | grep ERROR

# Последние 100 строк
tail -n 100 /var/log/ap-guardian.log
```

## Управление блокировками

### Добавление в Whitelist

```bash
# Через UCI
uci add_list ap-guardian.firewall.management.whitelist='192.168.1.100'
uci commit ap-guardian
/etc/init.d/ap-guardian reload

# Или через JSON
# Отредактируйте /etc/ap-guardian/config.json
```

### Добавление в Blacklist

```bash
# Через UCI
uci add_list ap-guardian.firewall.management.blacklist='10.0.0.1'
uci commit ap-guardian
/etc/init.d/ap-guardian reload
```

### Ручная блокировка IP

```bash
# Блокировка через iptables
iptables -A AP_GUARDIAN_INPUT -s 192.168.1.50 -j DROP

# Разблокировка
iptables -D AP_GUARDIAN_INPUT -s 192.168.1.50 -j DROP
```

## Тестирование

### Тест ARP Spoofing

```bash
# На атакующей машине
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100
```

### Тест SYN Flood

```bash
# На атакующей машине (осторожно!)
hping3 -S -p 80 --flood 192.168.1.1
```

### Тест Network Scan

```bash
# На атакующей машине
nmap -sS 192.168.1.0/24
```

## Производительность

### Оптимизация для слабых устройств

1. Увеличьте интервалы проверки:
   ```json
   {
     "general": {"check_interval": 5},
     "arp_spoofing": {"check_interval": 5}
   }
   ```

2. Отключите ненужные детекторы

3. Уменьшите размер Count-Min Sketch:
   ```json
   {
     "ddos": {
       "count_min_sketch_width": 1024,
       "count_min_sketch_depth": 3
     }
   }
   ```

### Мониторинг ресурсов

```bash
# Использование памяти
ps aux | grep ap-guardian

# Использование CPU
top -p $(pgrep -f ap-guardian)

# Использование сети
iftop -i br-lan
```

## Интеграция

### SNMP мониторинг

AP-Guardian экспортирует статус в JSON файлы, которые можно читать через скрипты для интеграции с системами мониторинга.

### Webhook уведомления

Можно добавить скрипт для отправки уведомлений при обнаружении угроз:

```bash
#!/bin/sh
# /usr/lib/ap-guardian/notify.sh

THREAT_TYPE=$1
THREAT_IP=$2

# Отправка webhook
curl -X POST https://your-webhook-url \
  -d "{\"type\":\"$THREAT_TYPE\",\"ip\":\"$THREAT_IP\"}"
```

## Безопасность

### Рекомендации

1. Регулярно обновляйте систему
2. Используйте сильные пароли для доступа к маршрутизатору
3. Настройте whitelist для доверенных устройств
4. Мониторьте логи на предмет подозрительной активности
5. Используйте HTTPS для доступа к LuCI

### Ограничения

- Система требует root прав для захвата пакетов
- Некоторые функции могут быть недоступны на слабых устройствах
- Высокая нагрузка может влиять на производительность маршрутизатора
