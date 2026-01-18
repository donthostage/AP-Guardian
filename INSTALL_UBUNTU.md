# Инструкция по установке AP-Guardian на Ubuntu/Debian

## Требования

- Ubuntu 20.04 / 22.04 LTS или Debian 11+ (или другая система на базе systemd)
- Python 3.9 или выше
- iptables и arptables
- Права root для работы службы
- Минимум 128MB RAM
- Минимум 100MB свободного места

## Быстрая установка

```bash
# Клонирование репозитория
git clone <repository_url>
cd AP-Guardian

# Запуск скрипта установки (требуются права root)
sudo bash install_ubuntu.sh

# Запуск службы
sudo systemctl start ap-guardian
sudo systemctl enable ap-guardian

# Проверка статуса
sudo systemctl status ap-guardian
```

## Установка вручную

### 1. Установка системных зависимостей

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev \
    iptables arptables \
    build-essential libpcap-dev
```

### 2. Установка Python зависимостей

```bash
pip3 install --user scapy requests
# Или глобально:
sudo pip3 install scapy requests
```

### 3. Копирование файлов

```bash
# Создание директорий
sudo mkdir -p /etc/ap-guardian
sudo mkdir -p /var/log/ap-guardian
sudo mkdir -p /var/run/ap-guardian
sudo mkdir -p /usr/lib/ap-guardian

# Копирование исходного кода
sudo cp -r src /usr/lib/ap-guardian/

# Копирование конфигурации
sudo cp files/etc/ap-guardian/config.json /etc/ap-guardian/
```

### 4. Установка через setup.py (рекомендуется)

```bash
cd AP-Guardian
sudo pip3 install -e .
```

Это создаст команду `ap-guardian` в `/usr/local/bin/`.

### 5. Или создание wrapper скрипта вручную

Если установка через setup.py не работает, создайте wrapper:

```bash
sudo cat > /usr/local/bin/ap-guardian << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, '/usr/lib/ap-guardian')
os.chdir('/usr/lib/ap-guardian')
from src.main import main
if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/ap-guardian
```

### 6. Установка systemd службы

```bash
sudo cp install/ap-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Настройка конфигурации

Основной файл конфигурации: `/etc/ap-guardian/config.json`

### Редактирование конфигурации

```bash
sudo nano /etc/ap-guardian/config.json
```

### Пример минимальной конфигурации

```json
{
  "general": {
    "enabled": true,
    "log_level": "INFO",
    "log_file": "/var/log/ap-guardian.log",
    "check_interval": 3
  },
  "arp_spoofing": {
    "enabled": true,
    "check_interval": 3,
    "threshold": 3
  },
  "ddos": {
    "enabled": true,
    "syn_flood": {
      "enabled": true,
      "syn_per_second_threshold": 100
    }
  },
  "firewall": {
    "enabled": true,
    "auto_block": true
  }
}
```

### Настройка интерфейса для мониторинга

По умолчанию используется интерфейс "any". Для указания конкретного интерфейса:

```bash
sudo systemctl edit ap-guardian
```

Добавьте:

```ini
[Service]
Environment="AP_GUARDIAN_INTERFACE=eth0"
```

Или отредактируйте `/etc/systemd/system/ap-guardian.service` напрямую:

```ini
Environment="AP_GUARDIAN_INTERFACE=eth0"
```

## Управление службой

### Запуск и остановка

```bash
# Запуск
sudo systemctl start ap-guardian

# Остановка
sudo systemctl stop ap-guardian

# Перезапуск
sudo systemctl restart ap-guardian

# Включение автозапуска
sudo systemctl enable ap-guardian

# Отключение автозапуска
sudo systemctl disable ap-guardian
```

### Проверка статуса

```bash
# Статус службы
sudo systemctl status ap-guardian

# Просмотр логов
sudo journalctl -u ap-guardian -f

# Просмотр последних логов
sudo journalctl -u ap-guardian -n 100

# Просмотр логов из файла
sudo tail -f /var/log/ap-guardian.log
```

### Просмотр статистики

```bash
# Статус в JSON формате
cat /var/run/ap-guardian-status.json | python3 -m json.tool

# Угрозы
cat /var/run/ap-guardian-threats.json | python3 -m json.tool

# Блокировки
cat /var/run/ap-guardian-blocks.json | python3 -m json.tool
```

## Проверка работы

### Проверка процессов

```bash
ps aux | grep ap-guardian
```

### Проверка правил firewall

```bash
# iptables правила
sudo iptables -L AP_GUARDIAN_INPUT -n -v
sudo iptables -L AP_GUARDIAN_FORWARD -n -v

# arptables правила
sudo arptables -L AP_GUARDIAN -n -v
```

### Проверка портов и сетевых интерфейсов

```bash
# Проверка интерфейсов
ip addr show

# Проверка что интерфейс доступен
ip link show eth0  # замените eth0 на ваш интерфейс
```

## Устранение неполадок

### Служба не запускается

1. **Проверьте логи:**
   ```bash
   sudo journalctl -u ap-guardian -n 50
   ```

2. **Проверьте права доступа:**
   ```bash
   ls -l /usr/local/bin/ap-guardian
   ls -l /usr/lib/ap-guardian/
   ```

3. **Проверьте конфигурацию:**
   ```bash
   python3 -m json.tool /etc/ap-guardian/config.json
   ```

4. **Проверьте наличие Python модулей:**
   ```bash
   python3 -c "import scapy; print('scapy OK')"
   python3 -c "import sys; sys.path.insert(0, '/usr/lib/ap-guardian'); from src.main import main; print('main OK')"
   ```

### Ошибка "Permission denied" при захвате пакетов

Служба должна запускаться от root. Проверьте service файл:

```bash
grep "^User=" /etc/systemd/system/ap-guardian.service
```

Должно быть `User=root`.

### Не обнаруживаются угрозы

1. **Проверьте что служба запущена:**
   ```bash
   sudo systemctl status ap-guardian
   ```

2. **Проверьте интерфейс:**
   ```bash
   # Проверьте какой интерфейс указан
   systemctl show ap-guardian | grep Environment
   ```

3. **Проверьте что детекторы включены в конфигурации**

4. **Проверьте логи на ошибки:**
   ```bash
   sudo journalctl -u ap-guardian | grep -i error
   ```

### Высокое использование ресурсов

1. **Увеличьте интервалы проверки в конфигурации:**
   ```json
   {
     "general": {
       "check_interval": 5
     }
   }
   ```

2. **Отключите ненужные детекторы**

3. **Уменьшите размер Count-Min Sketch для DDoS детектора**

## Обновление

```bash
# Остановка службы
sudo systemctl stop ap-guardian

# Обновление кода
cd AP-Guardian
git pull

# Переустановка
sudo bash install_ubuntu.sh

# Или вручную:
sudo cp -r src /usr/lib/ap-guardian/
sudo systemctl restart ap-guardian
```

## Удаление

```bash
# Остановка и отключение службы
sudo systemctl stop ap-guardian
sudo systemctl disable ap-guardian

# Удаление файлов службы
sudo rm /etc/systemd/system/ap-guardian.service
sudo systemctl daemon-reload

# Удаление файлов (опционально)
sudo rm -rf /usr/lib/ap-guardian
sudo rm -rf /etc/ap-guardian
sudo rm -rf /var/log/ap-guardian
sudo rm /usr/local/bin/ap-guardian

# Удаление Python пакета (если установлен через setup.py)
sudo pip3 uninstall ap-guardian
```

## Важные замечания

1. **Требуются права root:** Служба должна работать от root для работы с iptables, arptables и raw sockets.

2. **Сетевой интерфейс:** По умолчанию используется `any`, что может создать дополнительную нагрузку. Рекомендуется указать конкретный интерфейс.

3. **Firewall правила:** Система автоматически создает цепочки в iptables/arptables. При удалении службы убедитесь, что правила удалены вручную.

4. **Логи:** Логи сохраняются в `/var/log/ap-guardian.log` и journald. Регулярно проверяйте размер логов.

5. **Производительность:** На высоконагруженных сетях рекомендуется увеличить `check_interval` и отключить ненужные детекторы.

## Дополнительная информация

- [README.md](README.md) - Общая информация о проекте
- [USAGE.md](USAGE.md) - Руководство по использованию
- [TESTING.md](TESTING.md) - Руководство по тестированию
