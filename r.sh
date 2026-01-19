#!/bin/bash
# Установщик AP-Guardian с GitHub

set -e

echo "=== Установка AP-Guardian ==="
echo "Репозиторий: https://github.com/donthostage/AP-Guardian"

# Проверка прав root
if [ "$EUID" -ne 0 ]; then 
    echo "Ошибка: Запустите скрипт с правами root (sudo)"
    echo "Используйте: sudo $0"
    exit 1
fi

# Обновление системы
echo "[1/6] Обновление системы..."
apt-get update -qq

# Установка зависимостей
echo "[2/6] Установка зависимостей..."
apt-get install -y python3 python3-pip git iptables arptables libpcap-dev

# Клонирование репозитория
echo "[3/6] Клонирование репозитория..."
cd /tmp
if [ -d "AP-Guardian" ]; then
    rm -rf AP-Guardian
fi

git clone https://github.com/donthostage/AP-Guardian.git
cd AP-Guardian

# Проверка структуры
echo "Проверка структуры проекта..."
ls -la
if [ -d "src" ]; then
    echo "✓ Найдена директория src"
else
    echo "✗ Директория src не найдена!"
    echo "Содержимое репозитория:"
    find . -type f -name "*.py" | head -20
    exit 1
fi

# Установка Python пакетов
echo "[4/6] Установка Python пакетов..."
pip3 install scapy requests

# Копирование файлов
echo "[5/6] Копирование файлов в систему..."
mkdir -p /opt/ap-guardian
cp -r . /opt/ap-guardian/

# Создание запускающего скрипта
echo "[6/6] Создание скрипта запуска..."
cat > /usr/local/bin/ap-guardian << 'EOF'
#!/usr/bin/env python3
import sys
import os

# Добавляем путь к проекту
sys.path.insert(0, '/opt/ap-guardian')

try:
    # Пробуем разные способы импорта
    try:
        from src.main import main
    except ImportError:
        # Пробуем как модуль
        import src.main as main_module
        main = main_module.main
    
    if __name__ == '__main__':
        main()
except Exception as e:
    print(f"Ошибка запуска AP-Guardian: {e}")
    print("\nПроверка структуры проекта:")
    project_path = '/opt/ap-guardian'
    if os.path.exists(project_path):
        for root, dirs, files in os.walk(project_path):
            level = root.replace(project_path, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f'{indent}{os.path.basename(root)}/')
            subindent = ' ' * 2 * (level + 1)
            for file in files[:10]:  # Показываем первые 10 файлов
                if file.endswith('.py'):
                    print(f'{subindent}{file}')
    sys.exit(1)
EOF

chmod +x /usr/local/bin/ap-guardian

# Создание конфига если нет
if [ ! -f "/opt/ap-guardian/config.json" ]; then
    echo "Создание базового конфига..."
    cat > /opt/ap-guardian/config.json << 'EOF'
{
  "general": {
    "log_level": "INFO",
    "check_interval": 3
  },
  "arp_spoofing": {
    "enabled": true,
    "check_interval": 3,
    "threshold": 3
  },
  "ddos": {
    "enabled": true,
    "syn_threshold": 100
  },
  "network_scan": {
    "enabled": true,
    "horizontal_scan": {
      "enabled": true,
      "hosts_threshold": 10,
      "time_window": 60
    }
  }
}
EOF
fi

echo ""
echo "=== УСТАНОВКА ЗАВЕРШЕНА! ==="
echo ""
echo "Запустите AP-Guardian командой:"
echo "  sudo ap-guardian"
echo ""
echo "Для быстрого теста сканирования портов:"
echo "  cd /opt/ap-guardian"
echo "  sudo python3 -c \""
echo "import sys"
echo "sys.path.append('.'); from src.main import main; main()"
echo "\""
echo ""
echo "Если не работает, проверьте структуру:"
echo "  ls -la /opt/ap-guardian/src/"
