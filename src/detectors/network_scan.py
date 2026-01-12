"""
Модуль детектора сканирования сети
"""

import asyncio
import time
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ap-guardian.network_scan")


class NetworkScanDetector:
    """Детектор сканирования сети"""
    
    def __init__(self, config: Dict):
        """
        Инициализация детектора
        
        Args:
            config: Конфигурация модуля
        """
        self.config = config
        
        # Горизонтальное сканирование (один порт на многих хостах)
        horizontal_config = config.get("horizontal_scan", {})
        self.horizontal_enabled = horizontal_config.get("enabled", True)
        self.horizontal_hosts_threshold = horizontal_config.get("hosts_threshold", 10)
        self.horizontal_time_window = horizontal_config.get("time_window", 60)
        
        # Вертикальное сканирование (много портов на одном хосте)
        vertical_config = config.get("vertical_scan", {})
        self.vertical_enabled = vertical_config.get("enabled", True)
        self.vertical_ports_threshold = vertical_config.get("ports_threshold", 20)
        self.vertical_time_window = vertical_config.get("time_window", 60)
        
        # Известные сканеры
        self.known_scanners = set(config.get("known_scanners", ["nmap", "masscan"]))
        
        # Хранилище для горизонтального сканирования
        # Структура: (src_ip, dst_port) -> deque[(timestamp, dst_ip)]
        self.horizontal_scan_data: Dict[Tuple[str, int], deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        
        # Хранилище для вертикального сканирования
        # Структура: (src_ip, dst_ip) -> deque[(timestamp, dst_port)]
        self.vertical_scan_data: Dict[Tuple[str, str], deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        
        # Обнаруженные сканеры: src_ip -> threat_info
        self.detected_scanners: Dict[str, Dict] = {}
        
        # Временные окна для анализа
        self.scan_windows: deque = deque(maxlen=100)
        
        self.running = False
    
    async def start(self) -> None:
        """Запуск детектора"""
        self.running = True
        logger.info("Network Scan детектор запущен")
        
        # Запуск задачи мониторинга
        asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        """Остановка детектора"""
        self.running = False
        logger.info("Network Scan детектор остановлен")
    
    async def _monitor_loop(self) -> None:
        """Основной цикл мониторинга"""
        while self.running:
            try:
                await self._check_scans()
                await asyncio.sleep(5)  # Проверка каждые 5 секунд
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга Network Scan: {e}")
                await asyncio.sleep(5)
    
    def process_connection_attempt(self, src_ip: str, dst_ip: str, dst_port: int, 
                                   connection_type: str = "tcp") -> None:
        """
        Обработка попытки соединения
        
        Args:
            src_ip: IP источника
            dst_ip: IP назначения
            dst_port: Порт назначения
            connection_type: Тип соединения (tcp, udp)
        """
        if not self.running:
            return
        
        current_time = time.time()
        
        # Горизонтальное сканирование: один порт на многих хостах
        if self.horizontal_enabled:
            key = (src_ip, dst_port)
            self.horizontal_scan_data[key].append((current_time, dst_ip))
        
        # Вертикальное сканирование: много портов на одном хосте
        if self.vertical_enabled:
            key = (src_ip, dst_ip)
            self.vertical_scan_data[key].append((current_time, dst_port))
    
    async def _check_scans(self) -> None:
        """Проверка на наличие сканирования"""
        current_time = time.time()
        
        # Проверка горизонтального сканирования
        if self.horizontal_enabled:
            await self._check_horizontal_scan(current_time)
        
        # Проверка вертикального сканирования
        if self.vertical_enabled:
            await self._check_vertical_scan(current_time)
    
    async def _check_horizontal_scan(self, current_time: float) -> None:
        """Проверка горизонтального сканирования"""
        cutoff_time = current_time - self.horizontal_time_window
        
        for (src_ip, dst_port), connections in list(self.horizontal_scan_data.items()):
            # Фильтрация соединений в временном окне
            recent_connections = [
                (ts, dst_ip) for ts, dst_ip in connections
                if ts >= cutoff_time
            ]
            
            if not recent_connections:
                continue
            
            # Подсчет уникальных хостов
            unique_hosts = set(dst_ip for _, dst_ip in recent_connections)
            
            if len(unique_hosts) >= self.horizontal_hosts_threshold:
                # Обнаружено горизонтальное сканирование
                logger.warning(
                    f"Обнаружено горизонтальное сканирование от {src_ip}: "
                    f"порт {dst_port} на {len(unique_hosts)} хостах за {self.horizontal_time_window} сек"
                )
                
                self.detected_scanners[src_ip] = {
                    "type": "horizontal_scan",
                    "src_ip": src_ip,
                    "target_port": dst_port,
                    "hosts_scanned": len(unique_hosts),
                    "time_window": self.horizontal_time_window,
                    "threat_level": "HIGH",
                    "timestamp": datetime.now().isoformat()
                }
    
    async def _check_vertical_scan(self, current_time: float) -> None:
        """Проверка вертикального сканирования"""
        cutoff_time = current_time - self.vertical_time_window
        
        for (src_ip, dst_ip), connections in list(self.vertical_scan_data.items()):
            # Фильтрация соединений в временном окне
            recent_connections = [
                (ts, dst_port) for ts, dst_port in connections
                if ts >= cutoff_time
            ]
            
            if not recent_connections:
                continue
            
            # Подсчет уникальных портов
            unique_ports = set(dst_port for _, dst_port in recent_connections)
            
            if len(unique_ports) >= self.vertical_ports_threshold:
                # Обнаружено вертикальное сканирование
                logger.warning(
                    f"Обнаружено вертикальное сканирование от {src_ip} к {dst_ip}: "
                    f"{len(unique_ports)} портов за {self.vertical_time_window} сек"
                )
                
                # Обновление или создание записи
                if src_ip in self.detected_scanners:
                    existing = self.detected_scanners[src_ip]
                    if existing.get("type") == "vertical_scan":
                        existing["ports_scanned"] = max(
                            existing.get("ports_scanned", 0),
                            len(unique_ports)
                        )
                        existing["targets"].add(dst_ip)
                    else:
                        # Комбинированное сканирование
                        existing["type"] = "combined_scan"
                        existing["ports_scanned"] = len(unique_ports)
                        existing["targets"] = {dst_ip}
                else:
                    self.detected_scanners[src_ip] = {
                        "type": "vertical_scan",
                        "src_ip": src_ip,
                        "targets": {dst_ip},
                        "ports_scanned": len(unique_ports),
                        "time_window": self.vertical_time_window,
                        "threat_level": "HIGH",
                        "timestamp": datetime.now().isoformat()
                    }
    
    def _detect_known_scanner_patterns(self, src_ip: str, behavior: Dict) -> bool:
        """
        Обнаружение известных паттернов сканеров
        
        Args:
            src_ip: IP источника
            behavior: Информация о поведении
            
        Returns:
            True если обнаружен известный паттерн
        """
        # Проверка на nmap паттерны
        if behavior.get("type") == "vertical_scan":
            ports_scanned = behavior.get("ports_scanned", 0)
            # Nmap часто сканирует много портов последовательно
            if ports_scanned > 100:
                logger.info(f"Обнаружен паттерн nmap от {src_ip}")
                return True
        
        # Проверка на masscan паттерны
        if behavior.get("type") == "horizontal_scan":
            hosts_scanned = behavior.get("hosts_scanned", 0)
            # Masscan сканирует много хостов быстро
            if hosts_scanned > 50:
                logger.info(f"Обнаружен паттерн masscan от {src_ip}")
                return True
        
        return False
    
    def _cleanup_old_data(self, current_time: float) -> None:
        """Очистка устаревших данных"""
        cutoff_time = current_time - max(self.horizontal_time_window, self.vertical_time_window) * 2
        
        # Очистка горизонтальных данных
        for key in list(self.horizontal_scan_data.keys()):
            connections = self.horizontal_scan_data[key]
            # Удаление старых записей
            while connections and connections[0][0] < cutoff_time:
                connections.popleft()
            
            # Удаление пустых записей
            if not connections:
                del self.horizontal_scan_data[key]
        
        # Очистка вертикальных данных
        for key in list(self.vertical_scan_data.keys()):
            connections = self.vertical_scan_data[key]
            # Удаление старых записей
            while connections and connections[0][0] < cutoff_time:
                connections.popleft()
            
            # Удаление пустых записей
            if not connections:
                del self.vertical_scan_data[key]
    
    def get_threats(self) -> List[Dict]:
        """
        Получение списка обнаруженных угроз
        
        Returns:
            Список словарей с информацией об угрозах
        """
        threats = []
        
        for src_ip, behavior in self.detected_scanners.items():
            threat = behavior.copy()
            
            # Проверка на известные паттерны
            if self._detect_known_scanner_patterns(src_ip, behavior):
                threat["known_scanner"] = True
            
            threats.append(threat)
        
        return threats
    
    def clear_detection(self, src_ip: str) -> None:
        """
        Очистка обнаружения для конкретного IP
        
        Args:
            src_ip: IP адрес для очистки
        """
        if src_ip in self.detected_scanners:
            del self.detected_scanners[src_ip]
        
        # Очистка данных сканирования
        keys_to_remove = [
            key for key in self.horizontal_scan_data.keys()
            if key[0] == src_ip
        ]
        for key in keys_to_remove:
            del self.horizontal_scan_data[key]
        
        keys_to_remove = [
            key for key in self.vertical_scan_data.keys()
            if key[0] == src_ip
        ]
        for key in keys_to_remove:
            del self.vertical_scan_data[key]
