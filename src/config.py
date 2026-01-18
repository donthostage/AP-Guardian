"""
Модуль управления конфигурацией системы AP-Guardian
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Класс для управления конфигурацией системы"""
    
    DEFAULT_CONFIG = {
        "general": {
            "enabled": True,
            "log_level": "INFO",
            "log_file": "/var/log/ap-guardian.log",
            "check_interval": 3,
            "max_memory_mb": 50,
            "max_cpu_percent": 30
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
                "syn_ack_ratio_threshold": 0.1,
                "incomplete_connections_threshold": 50
            },
            "udp_flood": {
                "enabled": True,
                "packets_per_second_threshold": 1000,
                "anomaly_detection": True
            },
            "icmp_flood": {
                "enabled": True,
                "packets_per_second_threshold": 500,
                "anomaly_detection": True
            },
            "adaptive_thresholds": True,
            "count_min_sketch_depth": 4,
            "count_min_sketch_width": 2048
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
            },
            "known_scanners": ["nmap", "masscan"]
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
        },
        "notifications": {
            "enabled": False,
            "min_threat_level": "MEDIUM",
            "cooldown_seconds": 300,
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from": "",
                "to": []
            },
            "webhook": {
                "enabled": False,
                "url": "",
                "headers": {}
            },
            "telegram": {
                "enabled": False,
                "bot_token": "",
                "chat_id": ""
            },
            "script": {
                "enabled": False,
                "path": ""
            }
        }
    }
    
    CONFIG_PATH = "/etc/config/ap-guardian"
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
    
    def save_config(self) -> None:
        """Сохранение конфигурации в файл"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
    
    def get(self, *keys: str, default: Any = None) -> Any:
        """
        Получение значения конфигурации по ключам
        
        Args:
            *keys: Путь к значению (например, 'arp_spoofing', 'threshold')
            default: Значение по умолчанию
            
        Returns:
            Значение конфигурации или default
        """
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
                if value is None:
                    return default
            else:
                return default
        return value if value is not None else default
    
    def set(self, *keys: str, value: Any) -> None:
        """
        Установка значения конфигурации
        
        Args:
            *keys: Путь к значению
            value: Новое значение
        """
        config = self.config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
    
    def is_enabled(self, module: str) -> bool:
        """
        Проверка, включен ли модуль
        
        Args:
            module: Имя модуля
            
        Returns:
            True если модуль включен
        """
        return self.get(module, "enabled", default=False) and self.get("general", "enabled", default=True)
