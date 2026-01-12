"""
Модуль системы логирования для AP-Guardian
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


class Logger:
    """Класс для настройки системы логирования"""
    
    _instance: Optional['Logger'] = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.logger = None
            self._initialized = True
    
    def setup(self, log_level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
        """
        Настройка логирования
        
        Args:
            log_level: Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Путь к файлу логов (опционально)
            
        Returns:
            Настроенный объект logger
        """
        if self.logger is not None:
            return self.logger
        
        self.logger = logging.getLogger("ap-guardian")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Формат логов
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Файловый обработчик (если указан)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        
        return self.logger
    
    def get_logger(self) -> logging.Logger:
        """
        Получение объекта logger
        
        Returns:
            Объект logger
        """
        if self.logger is None:
            return self.setup()
        return self.logger


def get_logger() -> logging.Logger:
    """
    Получение глобального объекта logger
    
    Returns:
        Объект logger
    """
    logger_instance = Logger()
    return logger_instance.get_logger()
