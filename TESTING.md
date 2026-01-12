# Руководство по тестированию AP-Guardian

## Подготовка к тестированию

### 1. Установка на Ubuntu сервер

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

### 2. Настройка конфигурации

Отредактируйте `/etc/ap-guardian/config.json` для снижения порогов (для тестирования):

```json
{
  "ddos": {
    "syn_flood": {
      "syn_per_second_threshold": 10
    },
    "udp_flood": {
      "packets_per_second_threshold": 50
    },
    "icmp_flood": {
      "packets_per_second_threshold": 20
    }
  },
  "network_scan": {
    "horizontal_scan": {
      "hosts_threshold": 3
    },
    "vertical_scan": {
      "ports_threshold": 5
    }
  }
}
```

Перезапустите службу:
```bash
sudo systemctl restart ap-guardian
```

## Тестирование с Kali Linux или Termux

### Подготовка атакующей машины

#### На Kali Linux:
```bash
# Установка инструментов (обычно уже установлены)
sudo apt-get update
sudo apt-get install -y hping3 nmap dsniff
```

#### На Termux (Android):
```bash
pkg update
pkg install -y python nmap
pip install scapy
# hping3 может быть недоступен, используйте Python скрипты
```

### Тесты атак

#### 1. Тест SYN Flood

**На атакующей машине:**
```bash
# Используя hping3
hping3 -S -p 80 --flood <IP_СЕРВЕРА>

# Или используя скрипт
./scripts/test_attack_syn_flood.sh <IP_СЕРВЕРА> 80
```

**На сервере (мониторинг):**
```bash
# Проверка статуса
./scripts/monitor_status.sh

# Просмотр логов в реальном времени
sudo journalctl -u ap-guardian -f

# Проверка блокировок
sudo iptables -L AP_GUARDIAN_INPUT -n -v
```

**Ожидаемый результат:**
- Обнаружение SYN Flood в логах
- Блокировка IP источника в iptables
- Запись в `/var/run/ap-guardian-threats.json`

#### 2. Тест UDP Flood

**На атакующей машине:**
```bash
hping3 --udp -p 53 --flood <IP_СЕРВЕРА>
# Или
./scripts/test_attack_udp_flood.sh <IP_СЕРВЕРА> 53
```

**Ожидаемый результат:**
- Обнаружение UDP Flood
- Блокировка источника

#### 3. Тест ICMP Flood (Ping Flood)

**На атакующей машине:**
```bash
hping3 --icmp --flood <IP_СЕРВЕРА>
# Или
ping -f <IP_СЕРВЕРА>
# Или
./scripts/test_attack_icmp_flood.sh <IP_СЕРВЕРА>
```

**Ожидаемый результат:**
- Обнаружение ICMP Flood
- Блокировка источника

#### 4. Тест ARP Spoofing

**На атакующей машине (в той же сети):**
```bash
# Установка dsniff
sudo apt-get install -y dsniff

# Включение IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# ARP Spoofing атака
sudo arpspoof -i eth0 -t <TARGET_IP> <GATEWAY_IP>
# Или
./scripts/test_arp_spoofing.sh eth0 <TARGET_IP> <GATEWAY_IP>
```

**На сервере:**
```bash
# Проверка ARP таблицы
arp -a

# Проверка конфликтов
cat /proc/net/arp
```

**Ожидаемый результат:**
- Обнаружение ARP конфликта
- Блокировка через arptables
- Запись в логах

#### 5. Тест Network Scan

**На атакующей машине:**
```bash
# Горизонтальное сканирование (один порт на многих хостах)
nmap -p 80 192.168.1.0/24

# Вертикальное сканирование (много портов на одном хосте)
nmap -p- <IP_СЕРВЕРА>
# Или
./scripts/test_network_scan.sh <IP_СЕРВЕРА>
```

**Ожидаемый результат:**
- Обнаружение сканирования
- Блокировка IP источника

## Мониторинг во время тестов

### Просмотр статуса в реальном времени

```bash
# Запуск мониторинга
watch -n 1 ./scripts/monitor_status.sh

# Или отдельные проверки
./scripts/monitor_status.sh
```

### Просмотр логов

```bash
# Systemd журнал
sudo journalctl -u ap-guardian -f

# Файл логов
tail -f /var/log/ap-guardian.log

# Только ошибки
sudo journalctl -u ap-guardian -p err -f
```

### Проверка блокировок

```bash
# iptables правила
sudo iptables -L AP_GUARDIAN_INPUT -n -v
sudo iptables -L AP_GUARDIAN_FORWARD -n -v

# arptables правила
sudo arptables -L AP_GUARDIAN -n -v

# JSON файлы
cat /var/run/ap-guardian-threats.json | python3 -m json.tool
cat /var/run/ap-guardian-blocks.json | python3 -m json.tool
```

### Статистика сети

```bash
# Мониторинг трафика
sudo iftop -i eth0

# Статистика пакетов
sudo netstat -s

# Подсчет SYN пакетов
sudo tcpdump -i any 'tcp[tcpflags] & tcp-syn != 0' -c 100
```

## Проверка эффективности защиты

### До атаки
```bash
# Запись базовой статистики
./scripts/monitor_status.sh > baseline.txt
```

### Во время атаки
```bash
# Мониторинг в реальном времени
watch -n 1 './scripts/monitor_status.sh'
```

### После атаки
```bash
# Проверка блокировок
sudo iptables -L AP_GUARDIAN_INPUT -n -v | grep <ATTACKER_IP>

# Проверка логов
sudo journalctl -u ap-guardian --since "5 minutes ago" | grep -i threat
```

## Тестирование производительности

### Нагрузочное тестирование

```bash
# Множественные источники атак (с разных машин)
# На машине 1:
hping3 -S -p 80 --flood <SERVER_IP>

# На машине 2:
hping3 --udp -p 53 --flood <SERVER_IP>

# На машине 3:
hping3 --icmp --flood <SERVER_IP>
```

### Проверка использования ресурсов

```bash
# CPU и память
top -p $(pgrep -f ap-guardian)

# Детальная статистика
ps aux | grep ap-guardian
```

## Устранение проблем

### Система не обнаруживает атаки

1. Проверьте, что служба запущена:
   ```bash
   sudo systemctl status ap-guardian
   ```

2. Проверьте права доступа:
   ```bash
   sudo ls -l /usr/bin/ap-guardian
   ```

3. Проверьте конфигурацию:
   ```bash
   cat /etc/ap-guardian/config.json | python3 -m json.tool
   ```

4. Проверьте логи на ошибки:
   ```bash
   sudo journalctl -u ap-guardian -p err
   ```

### Блокировки не работают

1. Проверьте iptables:
   ```bash
   sudo iptables -L -n -v
   ```

2. Проверьте, что цепочки созданы:
   ```bash
   sudo iptables -L AP_GUARDIAN_INPUT
   ```

3. Проверьте права root:
   ```bash
   sudo -u root /usr/bin/ap-guardian
   ```

### Высокое использование ресурсов

1. Увеличьте интервалы проверки в конфигурации
2. Отключите ненужные детекторы
3. Уменьшите размер Count-Min Sketch

## Автоматизированное тестирование

Создайте скрипт для автоматического тестирования:

```bash
#!/bin/bash
# auto_test.sh

SERVER_IP="192.168.1.10"

echo "Начало автоматического тестирования..."

# Тест 1: SYN Flood
echo "Тест 1: SYN Flood"
timeout 10 hping3 -S -p 80 --flood $SERVER_IP &
sleep 15
./scripts/monitor_status.sh

# Тест 2: UDP Flood
echo "Тест 2: UDP Flood"
timeout 10 hping3 --udp -p 53 --flood $SERVER_IP &
sleep 15
./scripts/monitor_status.sh

# Тест 3: ICMP Flood
echo "Тест 3: ICMP Flood"
timeout 10 hping3 --icmp --flood $SERVER_IP &
sleep 15
./scripts/monitor_status.sh

echo "Тестирование завершено"
```

## Безопасность при тестировании

⚠️ **ВАЖНО:**
- Тестируйте только на своих системах
- Не атакуйте системы без разрешения
- Используйте изолированную тестовую сеть
- Отключайте атаки после тестирования
- Не используйте в продакшене с низкими порогами
