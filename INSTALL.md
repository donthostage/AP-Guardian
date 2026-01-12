# Инструкция по установке AP-Guardian

## Требования

- OpenWrt маршрутизатор (рекомендуется версия 21.02 или новее)
- Python 3.9 или выше
- iptables и arptables
- Минимум 64MB RAM
- Минимум 16MB свободного места

## Установка из исходников

### 1. Подготовка окружения OpenWrt

```bash
# Клонирование репозитория OpenWrt SDK
git clone https://github.com/openwrt/openwrt.git
cd openwrt

# Настройка конфигурации
make menuconfig
# Выберите: Target System -> Ваша платформа
# Выберите: Target Profile -> Ваш профиль

# Установка зависимостей
./scripts/feeds update -a
./scripts/feeds install -a
```

### 2. Добавление AP-Guardian в OpenWrt

```bash
# Копирование пакета в feeds
cp -r ap-guardian package/feeds/packages/

# Добавление в конфигурацию
make menuconfig
# Network -> ap-guardian
```

### 3. Сборка пакета

```bash
# Сборка только AP-Guardian
make package/ap-guardian/compile V=s

# Или сборка всего образа
make V=s
```

### 4. Установка на маршрутизатор

```bash
# Копирование .ipk файла на маршрутизатор
scp bin/packages/*/ap-guardian_*.ipk root@192.168.1.1:/tmp/

# Установка на маршрутизатор
ssh root@192.168.1.1
opkg install /tmp/ap-guardian_*.ipk
```

## Установка LuCI интерфейса

```bash
# Сборка LuCI приложения
make package/luci-app-ap-guardian/compile V=s

# Установка
opkg install luci-app-ap-guardian_*.ipk
```

## Настройка

### Через LuCI

1. Откройте веб-интерфейс LuCI: `http://192.168.1.1`
2. Перейдите в `Services -> AP-Guardian -> Settings`
3. Настройте параметры детекторов
4. Сохраните и примените изменения

### Через UCI

```bash
# Включение системы
uci set ap-guardian.general.enabled=1
uci commit ap-guardian

# Настройка ARP Spoofing детектора
uci set ap-guardian.arp_spoofing.detection.threshold=5
uci commit ap-guardian

# Применение изменений
/etc/init.d/ap-guardian reload
```

### Через JSON конфигурацию

Отредактируйте файл `/etc/ap-guardian/config.json`:

```json
{
  "general": {
    "enabled": true,
    "log_level": "INFO"
  },
  ...
}
```

## Запуск службы

```bash
# Запуск
/etc/init.d/ap-guardian start

# Остановка
/etc/init.d/ap-guardian stop

# Перезапуск
/etc/init.d/ap-guardian restart

# Проверка статуса
/etc/init.d/ap-guardian status
```

## Проверка работы

```bash
# Просмотр логов
logread | grep ap-guardian

# Или напрямую
tail -f /var/log/ap-guardian.log

# Проверка процессов
ps | grep ap-guardian

# Проверка правил firewall
iptables -L AP_GUARDIAN_INPUT -n -v
arptables -L AP_GUARDIAN -n -v
```

## Устранение неполадок

### Система не запускается

1. Проверьте права доступа:
   ```bash
   ls -l /usr/bin/ap-guardian
   chmod +x /usr/bin/ap-guardian
   ```

2. Проверьте логи:
   ```bash
   logread | grep ap-guardian
   ```

3. Проверьте конфигурацию:
   ```bash
   python3 /usr/lib/ap-guardian/uci_to_json.py
   cat /etc/ap-guardian/config.json
   ```

### Нет обнаружения угроз

1. Убедитесь, что система запущена:
   ```bash
   /etc/init.d/ap-guardian status
   ```

2. Проверьте, что детекторы включены в конфигурации

3. Проверьте права на захват пакетов (требуются root права)

### Высокое использование ресурсов

1. Увеличьте интервалы проверки в конфигурации
2. Отключите ненужные детекторы
3. Уменьшите размер Count-Min Sketch для DDoS детектора

## Обновление

```bash
# Удаление старой версии
opkg remove ap-guardian

# Установка новой версии
opkg install ap-guardian_*.ipk
```

## Удаление

```bash
# Остановка службы
/etc/init.d/ap-guardian stop
/etc/init.d/ap-guardian disable

# Удаление пакета
opkg remove ap-guardian luci-app-ap-guardian

# Очистка конфигурации (опционально)
rm -rf /etc/ap-guardian
rm /etc/config/ap-guardian
```
