# Структура проекта AP-Guardian

```
ap-guardian/
├── README.md                    # Основная документация
├── INSTALL.md                   # Инструкция по установке
├── USAGE.md                     # Руководство по использованию
├── PROJECT_STRUCTURE.md         # Этот файл
├── Makefile                     # Makefile для сборки OpenWrt пакета
├── Makefile.local              # Локальный Makefile для разработки
├── setup.py                     # Python setup script
├── requirements.txt            # Python зависимости
├── .gitignore                  # Git ignore файл
│
├── src/                        # Исходный код Python
│   ├── __init__.py
│   ├── main.py                 # Главный модуль системы
│   ├── config.py               # Управление конфигурацией
│   ├── logger.py               # Система логирования
│   ├── api_server.py           # API сервер для экспорта данных
│   ├── packet_capture.py       # Захват и анализ пакетов
│   │
│   ├── detectors/              # Модули детекторов
│   │   ├── __init__.py
│   │   ├── arp_spoofing.py     # Детектор ARP Spoofing
│   │   ├── ddos.py             # Детектор DDoS атак
│   │   └── network_scan.py     # Детектор сканирования сети
│   │
│   └── firewall/               # Модуль управления Firewall
│       ├── __init__.py
│       └── manager.py          # Менеджер Firewall
│
├── files/                      # Файлы для установки в OpenWrt
│   ├── etc/
│   │   ├── config/
│   │   │   └── ap-guardian     # UCI конфигурация
│   │   ├── init.d/
│   │   │   └── ap-guardian     # Init скрипт
│   │   └── ap-guardian/
│   │       └── config.json     # JSON конфигурация по умолчанию
│   │
│   └── usr/
│       └── lib/
│           └── ap-guardian/
│               └── uci_to_json.py  # Конвертер UCI -> JSON
│
└── luci/                       # LuCI веб-интерфейс
    └── applications/
        └── luci-app-ap-guardian/
            ├── Makefile
            ├── luasrc/
            │   ├── controller/
            │   │   └── ap-guardian.lua    # LuCI контроллер
            │   └── model/
            │       └── cbi/
            │           └── ap-guardian/
            │               └── settings.lua # CBI модель настроек
            │
            └── root/
                ├── usr/
                │   └── share/
                │       └── luci/
                │           └── menu.d/
                │               └── luci-app-ap-guardian.json  # Меню
                │
                └── www/
                    └── luci-static/
                        └── ap-guardian/
                            ├── status.js   # JavaScript для статуса
                            └── status.css  # CSS стили
```

## Описание модулей

### Основные модули

- **main.py**: Главный модуль системы, координирует работу всех компонентов
- **config.py**: Управление конфигурацией (загрузка, сохранение, валидация)
- **logger.py**: Система логирования с поддержкой файлов и консоли
- **api_server.py**: API сервер для экспорта статуса и угроз в JSON файлы

### Детекторы

- **arp_spoofing.py**: 
  - Мониторинг ARP таблицы
  - Обнаружение конфликтов IP-MAC
  - Отслеживание изменений MAC адресов
  - Обнаружение подделки gateway

- **ddos.py**:
  - SYN Flood detection
  - UDP/ICMP Flood detection
  - Count-Min Sketch для эффективного подсчета
  - Адаптивные пороги

- **network_scan.py**:
  - Горизонтальное сканирование (один порт на многих хостах)
  - Вертикальное сканирование (много портов на одном хосте)
  - Обнаружение известных паттернов сканеров

### Firewall

- **manager.py**:
  - Интеграция с iptables/arptables
  - Автоматическая блокировка угроз
  - Rate limiting
  - Whitelist/Blacklist управление
  - Временные правила с автоматическим удалением

### Захват пакетов

- **packet_capture.py**:
  - Захват пакетов через scapy или raw socket
  - Парсинг Ethernet, IP, TCP, UDP, ICMP, ARP
  - Асинхронная обработка пакетов

## Конфигурационные файлы

### UCI конфигурация (`/etc/config/ap-guardian`)

Используется для интеграции с OpenWrt и LuCI. Конвертируется в JSON через `uci_to_json.py`.

### JSON конфигурация (`/etc/ap-guardian/config.json`)

Основной формат конфигурации, используемый системой.

## LuCI интерфейс

- **ap-guardian.lua**: Контроллер для обработки HTTP запросов
- **settings.lua**: CBI модель для настройки через веб-интерфейс
- **status.js/css**: Frontend для отображения статуса и угроз

## Файлы статуса

Система экспортирует статус в JSON файлы:
- `/var/run/ap-guardian-status.json` - статус системы
- `/var/run/ap-guardian-threats.json` - обнаруженные угрозы
- `/var/run/ap-guardian-blocks.json` - активные блокировки

Эти файлы используются LuCI интерфейсом и могут быть прочитаны внешними системами мониторинга.
