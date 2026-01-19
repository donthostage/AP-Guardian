"""
Модуль управления конфигурацией системы AP-Guardian
УПРОЩЕННЫЙ
"""

import json
import os
from typing import Dict, Any, Optional


class Config:
    """Класс для управления конфигурацией системы"""
    
    DEFAULT_CONFIG = {
        "general": {
            "enabled": True,
            "log_level": "INFO",
            "log_file": "/var/log/ap-guardian.log",
            "check_interval": 3,
        },
        "arp_spoofing": {
            "enabled": True,
            "check_interval": 3,
            "threshold": 3,
            "block_duration": 3600,
            "trusted_devices": [],
            "monitor_gateway": True
        },
        "ddos": {
            "enabled": True,
            "syn_flood": {
                "enabled": True,
                "syn_per_second_threshold": 100,
            },
            "udp_flood": {
                "enabled": True,
                "packets_per_second_threshold": 1000,
            },
            "icmp_flood": {
                "enabled": True,
                "packets_per_second_threshold": 500,
            }
        },
        "network_scan": {
            "enabled": True,
            "horizontal_scan": {
                "enabled": True,
                "hosts_threshold": 10,
                "time_window": 60
            },
            "vertical_scan": {
                "enabled": True,
                "ports_threshold": 20,
                "time_window": 60
            }
        },
        "firewall": {
            "enabled": True,
            "auto_block": True,
            "rate_limit": True,
            "rate_limit_packets": 100,
            "rate_limit_seconds": 1,
            "whitelist": [],
            "blacklist": []
        },
        "bruteforce": {
            "enabled": True,
            "failed_attempts_threshold": 5,
            "time_window": 300,
            "ports_to_monitor": [22, 23, 80, 443, 3306, 5432]
        }
    }
    
    CONFIG_JSON_PATH = "/etc/ap-guardian/config.json"
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Инициализация конфигурации
        
        Args:
            config_path: Путь к файлу конфигурации (опционально)
        """
        self.config_path = config_path or self.CONFIG_JSON_PATH
        self.config = self.DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        """Загрузка конфигурации из файла"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    self._merge_config(self.config, loaded_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Ошибка загрузки конфигурации: {e}, используются значения по умолчанию")
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Рекурсивное слияние конфигураций"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Получение значения конфигурации по ключам
        
        Args:
            *keys: Путь к значению (например, 'arp_spoofing', 'threshold')
            default: Значение по умолчанию
            
        Returns:
            Значение конфигурации или default
        """
        try:
            value = self.config
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                    if value is None:
                        return default
                else:
                    return default
            return value if value is not None else default
        except (TypeError, AttributeError):
            return default
    
    def is_enabled(self, module: str) -> bool:
        """
        Проверка, включен ли модуль
        
        Args:
            module: Имя модуля
            
        Returns:
            True если модуль включен
        """
        module_config = self.get(module)
        if not isinstance(module_config, dict):
            return False
        return module_config.get("enabled", False)
