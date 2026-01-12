"""
API сервер для экспорта статуса и угроз (для LuCI и внешних систем)
"""

import asyncio
import json
import os
from typing import Dict, List
from datetime import datetime
import logging

logger = logging.getLogger("ap-guardian.api")


class APIServer:
    """API сервер для экспорта данных"""
    
    def __init__(self, system):
        """
        Инициализация API сервера
        
        Args:
            system: Экземпляр APGuardian
        """
        self.system = system
        self.status_file = "/var/run/ap-guardian-status.json"
        self.threats_file = "/var/run/ap-guardian-threats.json"
        self.blocks_file = "/var/run/ap-guardian-blocks.json"
        self.running = False
    
    async def start(self) -> None:
        """Запуск API сервера"""
        self.running = True
        logger.info("API сервер запущен")
        asyncio.create_task(self._update_loop())
    
    async def stop(self) -> None:
        """Остановка API сервера"""
        self.running = False
        logger.info("API сервер остановлен")
    
    async def _update_loop(self) -> None:
        """Цикл обновления файлов статуса"""
        while self.running:
            try:
                await self._update_status_file()
                await self._update_threats_file()
                await self._update_blocks_file()
                await asyncio.sleep(5)  # Обновление каждые 5 секунд
            except Exception as e:
                logger.error(f"Ошибка обновления API файлов: {e}")
                await asyncio.sleep(5)
    
    async def _update_status_file(self) -> None:
        """Обновление файла статуса"""
        try:
            status = self.system.get_status()
            # Добавление статистики
            if hasattr(self.system, 'statistics'):
                status['statistics'] = self.system.statistics.get_statistics()
            os.makedirs(os.path.dirname(self.status_file), exist_ok=True)
            with open(self.status_file, 'w', encoding='utf-8') as f:
                json.dump(status, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Ошибка обновления статуса: {e}")
    
    async def _update_threats_file(self) -> None:
        """Обновление файла угроз"""
        try:
            threats = await self.system._collect_threats()
            os.makedirs(os.path.dirname(self.threats_file), exist_ok=True)
            with open(self.threats_file, 'w', encoding='utf-8') as f:
                json.dump(threats, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Ошибка обновления угроз: {e}")
    
    async def _update_blocks_file(self) -> None:
        """Обновление файла блокировок"""
        try:
            if self.system.firewall_manager:
                blocks = self.system.firewall_manager.get_active_blocks()
                os.makedirs(os.path.dirname(self.blocks_file), exist_ok=True)
                with open(self.blocks_file, 'w', encoding='utf-8') as f:
                    json.dump(blocks, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Ошибка обновления блокировок: {e}")
