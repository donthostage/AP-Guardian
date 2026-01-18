"""
Модуль детектора брутфорс атак
"""

import asyncio
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple
from datetime import datetime
import logging

logger = logging.getLogger("ap-guardian.bruteforce")


class BruteforceDetector:
    """Детектор брутфорс атак (множественные попытки подключения)"""
    
    def __init__(self, config: Dict):
        """
        Инициализация детектора
        
        Args:
            config: Конфигурация модуля
        """
        self.config = config
        self.enabled = config.get("enabled", True)
        self.failed_attempts_threshold = config.get("failed_attempts_threshold", 5)
        self.time_window = config.get("time_window", 300)  # 5 минут
        self.ports_to_monitor = set(config.get("ports_to_monitor", [22, 23, 80, 443, 3306, 5432]))
        
        # Хранилище попыток: (src_ip, dst_ip, dst_port) -> deque[timestamp]
        self.connection_attempts: Dict[Tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        
        # Неудачные попытки: (src_ip, dst_ip, dst_port) -> count
        self.failed_attempts: Dict[Tuple[str, str, int], int] = defaultdict(int)
        
        # Успешные соединения: (src_ip, dst_ip, dst_port) -> count (для правильного подсчета)
        self.successful_connections: Dict[Tuple[str, str, int], int] = defaultdict(int)
        
        # Отслеживание SYN пакетов без SYN-ACK: (src_ip, dst_ip, dst_port) -> timestamp
        self.pending_syn: Dict[Tuple[str, str, int], float] = {}
        
        # Обнаруженные брутфорс атаки
        self.detected_attacks: Dict[str, Dict] = {}
        
        self.running = False
    
    async def start(self) -> None:
        """Запуск детектора"""
        self.running = True
        logger.info("Bruteforce детектор запущен")
        asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        """Остановка детектора"""
        self.running = False
        logger.info("Bruteforce детектор остановлен")
    
    async def _monitor_loop(self) -> None:
        """Основной цикл мониторинга"""
        while self.running:
            try:
                await self._check_bruteforce()
                await asyncio.sleep(10)  # Проверка каждые 10 секунд
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга Bruteforce: {e}")
                await asyncio.sleep(10)
    
    def process_connection(self, src_ip: str, dst_ip: str, dst_port: int, 
                          success: bool = False) -> None:
        """
        Обработка попытки соединения
        
        Args:
            src_ip: IP источника (атакующего)
            dst_ip: IP назначения (цель атаки)
            dst_port: Порт назначения (целевой порт)
            success: Успешное ли соединение
        """
        if not self.running or not self.enabled:
            return
        
        # Мониторим только определенные порты
        if dst_port not in self.ports_to_monitor:
            return
        
        current_time = time.time()
        key = (src_ip, dst_ip, dst_port)
        
        if success:
            # Успешное соединение - удаляем из pending и уменьшаем счетчик неудачных
            if key in self.pending_syn:
                # Уменьшаем счетчик неудачных попыток, так как соединение успешное
                if self.failed_attempts[key] > 0:
                    self.failed_attempts[key] -= 1
                del self.pending_syn[key]
            # Увеличиваем счетчик успешных соединений
            self.successful_connections[key] += 1
        else:
            # Неудачная попытка - SYN пакет
            current_time = time.time()
            self.connection_attempts[key].append(current_time)
            
            # Если это новый SYN (еще не было SYN-ACK), добавляем в pending
            if key not in self.pending_syn:
                self.pending_syn[key] = current_time
                # Временно считаем как неудачную, будет уменьшено при получении SYN-ACK
                self.failed_attempts[key] += 1
    
    async def _check_bruteforce(self) -> None:
        """Проверка на брутфорс атаки"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Проверка старых SYN без ответа (таймаут 10 секунд для TCP timeout)
        syn_timeout = 10.0
        expired_syn = []
        for key, syn_time in self.pending_syn.items():
            if current_time - syn_time > syn_timeout:
                # SYN без ответа - определенно неудачное соединение
                # Оставляем как неудачную, не удаляем из failed_attempts
                expired_syn.append(key)
        
        for key in expired_syn:
            del self.pending_syn[key]
        
        # Проверка брутфорс атак
        for (src_ip, dst_ip, dst_port), attempts in list(self.connection_attempts.items()):
            # Фильтрация попыток в временном окне
            recent_attempts = [ts for ts in attempts if ts >= cutoff_time]
            
            if len(recent_attempts) >= self.failed_attempts_threshold:
                key = (src_ip, dst_ip, dst_port)
                
                # Получаем количество неудачных попыток
                failed_count = self.failed_attempts.get(key, 0)
                success_count = self.successful_connections.get(key, 0)
                
                # Вычисляем реальное количество неудачных попыток
                # Учитываем только попытки, которые точно не были успешными
                # (исключаем те, что еще в pending, если они не истекли)
                actual_failed = failed_count
                
                # Если соотношение неудачных к успешным высокое - это брутфорс
                if len(recent_attempts) > 0:
                    failure_ratio = actual_failed / len(recent_attempts) if len(recent_attempts) > 0 else 0
                    
                    # Обнаружение брутфорс: либо много неудачных попыток, либо высокий процент неудач
                    if actual_failed >= self.failed_attempts_threshold or (len(recent_attempts) >= self.failed_attempts_threshold and failure_ratio > 0.7):
                        # Обнаружена брутфорс атака
                        logger.warning(
                            f"Обнаружена брутфорс атака от {src_ip} к {dst_ip}:{dst_port}: "
                            f"{actual_failed} неудачных из {len(recent_attempts)} попыток "
                            f"(успешных: {success_count}) за {self.time_window} сек"
                        )
                        
                        self.detected_attacks[src_ip] = {
                            "type": "bruteforce",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "failed_attempts": actual_failed,
                            "successful_attempts": success_count,
                            "total_attempts": len(recent_attempts),
                            "failure_ratio": failure_ratio,
                            "threat_level": "HIGH",
                            "timestamp": datetime.now().isoformat()
                        }
        
        # Очистка старых данных
        self._cleanup_old_data(current_time)
    
    def _cleanup_old_data(self, current_time: float) -> None:
        """Очистка устаревших данных"""
        cutoff_time = current_time - self.time_window * 2
        
        keys_to_remove = []
        for key, attempts in self.connection_attempts.items():
            # Удаление старых попыток
            while attempts and attempts[0] < cutoff_time:
                attempts.popleft()
            
            # Удаление пустых записей
            if not attempts:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.connection_attempts[key]
            if key in self.failed_attempts:
                del self.failed_attempts[key]
    
    def get_threats(self) -> List[Dict]:
        """
        Получение списка обнаруженных угроз
        
        Returns:
            Список словарей с информацией об угрозах
        """
        return list(self.detected_attacks.values())
