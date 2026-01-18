"""
Модуль детектора DDoS атак (SYN Flood, UDP/ICMP Flood)
"""

import asyncio
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ap-guardian.ddos")


class CountMinSketch:
    """Count-Min Sketch для эффективного подсчета частоты событий"""
    
    def __init__(self, width: int = 2048, depth: int = 4):
        """
        Инициализация Count-Min Sketch
        
        Args:
            width: Ширина таблицы
            depth: Глубина (количество хеш-функций)
        """
        self.width = width
        self.depth = depth
        self.table = [[0] * width for _ in range(depth)]
        self.total = 0
    
    def _hash(self, key: str, seed: int) -> int:
        """Простая хеш-функция"""
        hash_val = 0
        for char in key:
            hash_val = (hash_val * 31 + ord(char) + seed) % self.width
        return hash_val
    
    def increment(self, key: str, count: int = 1) -> None:
        """Увеличение счетчика для ключа"""
        for i in range(self.depth):
            index = self._hash(key, i) % self.width
            self.table[i][index] += count
        self.total += count
    
    def estimate(self, key: str) -> int:
        """Оценка частоты ключа (минимум по всем хешам)"""
        min_count = float('inf')
        for i in range(self.depth):
            index = self._hash(key, i) % self.width
            min_count = min(min_count, self.table[i][index])
        return int(min_count)
    
    def reset(self) -> None:
        """Сброс всех счетчиков"""
        self.table = [[0] * self.width for _ in range(self.depth)]
        self.total = 0


class DDoSDetector:
    """Детектор DDoS атак"""
    
    def __init__(self, config: Dict):
        """
        Инициализация детектора
        
        Args:
            config: Конфигурация модуля
        """
        self.config = config
        self.adaptive_thresholds = config.get("adaptive_thresholds", True)
        
        # SYN Flood настройки
        syn_config = config.get("syn_flood", {})
        self.syn_enabled = syn_config.get("enabled", True)
        self.syn_threshold = syn_config.get("syn_per_second_threshold", 100)
        self.syn_ack_ratio_threshold = syn_config.get("syn_ack_ratio_threshold", 0.1)
        self.incomplete_threshold = syn_config.get("incomplete_connections_threshold", 50)
        
        # UDP Flood настройки
        udp_config = config.get("udp_flood", {})
        self.udp_enabled = udp_config.get("enabled", True)
        self.udp_threshold = udp_config.get("packets_per_second_threshold", 1000)
        self.udp_anomaly = udp_config.get("anomaly_detection", True)
        
        # ICMP Flood настройки
        icmp_config = config.get("icmp_flood", {})
        self.icmp_enabled = icmp_config.get("enabled", True)
        self.icmp_threshold = icmp_config.get("packets_per_second_threshold", 500)
        self.icmp_anomaly = icmp_config.get("anomaly_detection", True)
        
        # Count-Min Sketch
        sketch_width = config.get("count_min_sketch_width", 2048)
        sketch_depth = config.get("count_min_sketch_depth", 4)
        self.syn_sketch = CountMinSketch(sketch_width, sketch_depth)
        self.udp_sketch = CountMinSketch(sketch_width, sketch_depth)
        self.icmp_sketch = CountMinSketch(sketch_width, sketch_depth)
        
        # Статистика пакетов по IP: IP -> deque[(timestamp, ...)]
        self.syn_packets_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self.syn_ack_packets_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self.udp_packets_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self.icmp_packets_by_ip: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        
        # Общая статистика для быстрого подсчета
        self.syn_packets: deque = deque(maxlen=60)
        self.syn_ack_packets: deque = deque(maxlen=60)
        self.udp_packets: deque = deque(maxlen=60)
        self.icmp_packets: deque = deque(maxlen=60)
        
        # Незавершенные соединения: IP -> count
        self.incomplete_connections: Dict[str, int] = defaultdict(int)
        
        # IP источников атак для блокировки
        self.attack_sources: Dict[str, Dict] = {}  # IP -> {type, count, first_seen}
        
        # Адаптивные пороги (базовые значения)
        self.adaptive_syn_threshold = self.syn_threshold
        self.adaptive_udp_threshold = self.udp_threshold
        self.adaptive_icmp_threshold = self.icmp_threshold
        
        # История нормального трафика для адаптации
        self.normal_traffic_history: deque = deque(maxlen=300)  # 5 минут
        
        self.running = False
        self.last_reset = time.time()
    
    async def start(self) -> None:
        """Запуск детектора"""
        self.running = True
        logger.info("DDoS детектор запущен")
        
        # Запуск задач мониторинга
        asyncio.create_task(self._monitor_loop())
        if self.adaptive_thresholds:
            asyncio.create_task(self._adaptive_threshold_loop())
    
    async def stop(self) -> None:
        """Остановка детектора"""
        self.running = False
        logger.info("DDoS детектор остановлен")
    
    async def _monitor_loop(self) -> None:
        """Основной цикл мониторинга"""
        while self.running:
            try:
                await self._check_threats()
                await asyncio.sleep(1)  # Проверка каждую секунду
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга DDoS: {e}")
                await asyncio.sleep(1)
    
    async def _adaptive_threshold_loop(self) -> None:
        """Цикл адаптации порогов"""
        while self.running:
            try:
                await self._update_adaptive_thresholds()
                await asyncio.sleep(60)  # Обновление каждую минуту
            except Exception as e:
                logger.error(f"Ошибка в цикле адаптации порогов: {e}")
                await asyncio.sleep(60)
    
    def process_packet(self, packet_type: str, src_ip: str, dst_ip: str, **kwargs) -> None:
        """
        Обработка пакета
        
        Args:
            packet_type: Тип пакета (syn, syn_ack, udp, icmp)
            src_ip: IP источника
            dst_ip: IP назначения
            **kwargs: Дополнительные параметры
        """
        current_time = time.time()
        
        if packet_type == "syn" and self.syn_enabled:
            self.syn_packets.append((current_time, src_ip))
            self.syn_packets_by_ip[src_ip].append(current_time)
            self.syn_sketch.increment(src_ip)
            self.incomplete_connections[src_ip] += 1
        
        elif packet_type == "syn_ack" and self.syn_enabled:
            self.syn_ack_packets.append((current_time, dst_ip))
            self.syn_ack_packets_by_ip[dst_ip].append(current_time)
            # SYN-ACK приходит от сервера (src_ip) к клиенту (dst_ip)
            # Уменьшаем счетчик незавершенных соединений для клиента (dst_ip)
            # который отправил SYN
            if dst_ip in self.incomplete_connections:
                self.incomplete_connections[dst_ip] = max(0, self.incomplete_connections[dst_ip] - 1)
        
        elif packet_type == "udp" and self.udp_enabled:
            self.udp_packets.append((current_time, src_ip))
            self.udp_packets_by_ip[src_ip].append(current_time)
            self.udp_sketch.increment(src_ip)
        
        elif packet_type == "icmp" and self.icmp_enabled:
            self.icmp_packets.append((current_time, src_ip))
            self.icmp_packets_by_ip[src_ip].append(current_time)
            self.icmp_sketch.increment(src_ip)
        
        # Очистка старых записей
        if current_time - self.last_reset > 60:
            self._cleanup_old_data(current_time)
            self.last_reset = current_time
    
    def _cleanup_old_data(self, current_time: float) -> None:
        """Очистка устаревших данных"""
        cutoff_time = current_time - 60
        
        # Очистка очередей пакетов
        while self.syn_packets and self.syn_packets[0][0] < cutoff_time:
            self.syn_packets.popleft()
        while self.syn_ack_packets and self.syn_ack_packets[0][0] < cutoff_time:
            self.syn_ack_packets.popleft()
        while self.udp_packets and self.udp_packets[0][0] < cutoff_time:
            self.udp_packets.popleft()
        while self.icmp_packets and self.icmp_packets[0][0] < cutoff_time:
            self.icmp_packets.popleft()
        
        # Очистка незавершенных соединений (старше 5 минут)
        old_ips = [
            ip for ip, count in self.incomplete_connections.items()
            if count == 0
        ]
        for ip in old_ips:
            del self.incomplete_connections[ip]
    
    async def _check_threats(self) -> None:
        """Проверка на наличие угроз"""
        current_time = time.time()
        
        # Проверка SYN Flood
        if self.syn_enabled:
            await self._check_syn_flood(current_time)
        
        # Проверка UDP Flood
        if self.udp_enabled:
            await self._check_udp_flood(current_time)
        
        # Проверка ICMP Flood
        if self.icmp_enabled:
            await self._check_icmp_flood(current_time)
    
    async def _check_syn_flood(self, current_time: float) -> None:
        """Проверка SYN Flood атаки"""
        # Подсчет SYN пакетов за последнюю секунду
        one_second_ago = current_time - 1
        syn_count = sum(1 for ts, _ in self.syn_packets if ts >= one_second_ago)
        
        # Подсчет SYN-ACK пакетов за последнюю секунду
        syn_ack_count = sum(1 for ts, _ in self.syn_ack_packets if ts >= one_second_ago)
        
        # Расчет соотношения
        syn_ack_ratio = syn_ack_count / syn_count if syn_count > 0 else 1.0
        
        threshold = self.adaptive_syn_threshold if self.adaptive_thresholds else self.syn_threshold
        
        # Обнаружение атаки по общему трафику
        if syn_count > threshold:
            logger.warning(
                f"Обнаружена SYN Flood атака: {syn_count} SYN пакетов/сек "
                f"(порог: {threshold})"
            )
        
        if syn_count > 0 and syn_ack_ratio < self.syn_ack_ratio_threshold:
            logger.warning(
                f"Обнаружена SYN Flood атака: низкое соотношение SYN-ACK ({syn_ack_ratio:.2f})"
            )
        
        # Проверка по IP источникам - находим атакующие IP
        attacking_ips = []
        for src_ip, packets in self.syn_packets_by_ip.items():
            # Подсчет пакетов за последнюю секунду от этого IP
            ip_syn_count = sum(1 for ts in packets if ts >= one_second_ago)
            
            if ip_syn_count > threshold / 10:  # Порог для отдельного IP
                attacking_ips.append((src_ip, ip_syn_count))
                if src_ip not in self.attack_sources:
                    self.attack_sources[src_ip] = {
                        "type": "syn_flood",
                        "count": ip_syn_count,
                        "first_seen": current_time
                    }
                else:
                    self.attack_sources[src_ip]["count"] = max(
                        self.attack_sources[src_ip]["count"], ip_syn_count
                    )
        
        # Проверка незавершенных соединений
        for ip, count in list(self.incomplete_connections.items()):
            if count > self.incomplete_threshold:
                logger.warning(
                    f"Обнаружена SYN Flood атака от {ip}: {count} незавершенных соединений"
                )
                if ip not in self.attack_sources:
                    self.attack_sources[ip] = {
                        "type": "syn_flood",
                        "count": count,
                        "first_seen": current_time
                    }
    
    async def _check_udp_flood(self, current_time: float) -> None:
        """Проверка UDP Flood атаки"""
        one_second_ago = current_time - 1
        udp_count = sum(1 for ts, _ in self.udp_packets if ts >= one_second_ago)
        
        threshold = self.adaptive_udp_threshold if self.adaptive_thresholds else self.udp_threshold
        
        if udp_count > threshold:
            logger.warning(
                f"Обнаружена UDP Flood атака: {udp_count} UDP пакетов/сек "
                f"(порог: {threshold})"
            )
        
        # Проверка по IP источникам
        for src_ip, packets in self.udp_packets_by_ip.items():
            ip_udp_count = sum(1 for ts in packets if ts >= one_second_ago)
            if ip_udp_count > threshold / 10:  # Порог для отдельного IP
                if src_ip not in self.attack_sources:
                    self.attack_sources[src_ip] = {
                        "type": "udp_flood",
                        "count": ip_udp_count,
                        "first_seen": current_time
                    }
                else:
                    self.attack_sources[src_ip]["count"] = max(
                        self.attack_sources[src_ip]["count"], ip_udp_count
                    )
        
        # Аномалия детекция
        if self.udp_anomaly:
            await self._check_anomaly("udp", udp_count, threshold)
    
    async def _check_icmp_flood(self, current_time: float) -> None:
        """Проверка ICMP Flood атаки"""
        one_second_ago = current_time - 1
        icmp_count = sum(1 for ts, _ in self.icmp_packets if ts >= one_second_ago)
        
        threshold = self.adaptive_icmp_threshold if self.adaptive_thresholds else self.icmp_threshold
        
        if icmp_count > threshold:
            logger.warning(
                f"Обнаружена ICMP Flood атака: {icmp_count} ICMP пакетов/сек "
                f"(порог: {threshold})"
            )
        
        # Проверка по IP источникам
        for src_ip, packets in self.icmp_packets_by_ip.items():
            ip_icmp_count = sum(1 for ts in packets if ts >= one_second_ago)
            if ip_icmp_count > threshold / 10:  # Порог для отдельного IP
                if src_ip not in self.attack_sources:
                    self.attack_sources[src_ip] = {
                        "type": "icmp_flood",
                        "count": ip_icmp_count,
                        "first_seen": current_time
                    }
                else:
                    self.attack_sources[src_ip]["count"] = max(
                        self.attack_sources[src_ip]["count"], ip_icmp_count
                    )
        
        # Аномалия детекция
        if self.icmp_anomaly:
            await self._check_anomaly("icmp", icmp_count, threshold)
    
    async def _check_anomaly(self, packet_type: str, current_count: int, threshold: int) -> None:
        """Обнаружение аномалий в трафике"""
        if len(self.normal_traffic_history) < 10:
            return
        
        # Расчет среднего и стандартного отклонения
        recent_counts = [count for _, count in list(self.normal_traffic_history)[-60:]]
        if not recent_counts:
            return
        
        mean = sum(recent_counts) / len(recent_counts)
        variance = sum((x - mean) ** 2 for x in recent_counts) / len(recent_counts)
        std_dev = variance ** 0.5
        
        # Аномалия: значение больше среднего + 3*std_dev
        if current_count > mean + 3 * std_dev:
            logger.warning(
                f"Обнаружена аномалия в {packet_type} трафике: "
                f"{current_count} пакетов (среднее: {mean:.1f}, std: {std_dev:.1f})"
            )
    
    async def _update_adaptive_thresholds(self) -> None:
        """Обновление адаптивных порогов на основе нормального трафика"""
        if len(self.normal_traffic_history) < 10:
            return
        
        # Расчет средних значений за последние 5 минут
        recent_syn = [count for ptype, count in self.normal_traffic_history if ptype == "syn"]
        recent_udp = [count for ptype, count in self.normal_traffic_history if ptype == "udp"]
        recent_icmp = [count for ptype, count in self.normal_traffic_history if ptype == "icmp"]
        
        if recent_syn:
            mean_syn = sum(recent_syn) / len(recent_syn)
            self.adaptive_syn_threshold = max(self.syn_threshold, int(mean_syn * 2))
        
        if recent_udp:
            mean_udp = sum(recent_udp) / len(recent_udp)
            self.adaptive_udp_threshold = max(self.udp_threshold, int(mean_udp * 2))
        
        if recent_icmp:
            mean_icmp = sum(recent_icmp) / len(recent_icmp)
            self.adaptive_icmp_threshold = max(self.icmp_threshold, int(mean_icmp * 2))
    
    def get_threats(self) -> List[Dict]:
        """
        Получение списка обнаруженных угроз
        
        Returns:
            Список словарей с информацией об угрозах
        """
        threats = []
        current_time = time.time()
        one_second_ago = current_time - 1
        
        # Угрозы от конкретных IP источников
        for src_ip, attack_info in self.attack_sources.items():
            attack_type = attack_info["type"]
            count = attack_info["count"]
            
            threat_level = "HIGH" if attack_type in ["syn_flood", "udp_flood"] else "MEDIUM"
            
            threats.append({
                "type": f"ddos_{attack_type}",
                "src_ip": src_ip,
                "threat_level": threat_level,
                "description": f"{attack_type.upper()} от {src_ip}: {count} пакетов/сек",
                "packets_per_second": count,
                "timestamp": datetime.fromtimestamp(attack_info["first_seen"]).isoformat()
            })
        
        # Общие угрозы (если нет конкретных источников)
        if not threats:
            # SYN Flood угрозы
            if self.syn_enabled:
                syn_count = sum(1 for ts, _ in self.syn_packets if ts >= one_second_ago)
                threshold = self.adaptive_syn_threshold if self.adaptive_thresholds else self.syn_threshold
                
                if syn_count > threshold:
                    threats.append({
                        "type": "ddos_syn_flood",
                        "threat_level": "HIGH",
                        "description": f"SYN Flood: {syn_count} пакетов/сек",
                        "packets_per_second": syn_count,
                        "threshold": threshold,
                        "timestamp": datetime.now().isoformat()
                    })
            
            # UDP Flood угрозы
            if self.udp_enabled:
                udp_count = sum(1 for ts, _ in self.udp_packets if ts >= one_second_ago)
                threshold = self.adaptive_udp_threshold if self.adaptive_thresholds else self.udp_threshold
                
                if udp_count > threshold:
                    threats.append({
                        "type": "ddos_udp_flood",
                        "threat_level": "HIGH",
                        "description": f"UDP Flood: {udp_count} пакетов/сек",
                        "packets_per_second": udp_count,
                        "threshold": threshold,
                        "timestamp": datetime.now().isoformat()
                    })
            
            # ICMP Flood угрозы
            if self.icmp_enabled:
                icmp_count = sum(1 for ts, _ in self.icmp_packets if ts >= one_second_ago)
                threshold = self.adaptive_icmp_threshold if self.adaptive_thresholds else self.icmp_threshold
                
                if icmp_count > threshold:
                    threats.append({
                        "type": "ddos_icmp_flood",
                        "threat_level": "MEDIUM",
                        "description": f"ICMP Flood: {icmp_count} пакетов/сек",
                        "packets_per_second": icmp_count,
                        "threshold": threshold,
                        "timestamp": datetime.now().isoformat()
                    })
        
        return threats
    
    def get_attack_sources(self) -> Dict[str, Dict]:
        """
        Получение списка IP источников атак
        
        Returns:
            Словарь IP -> информация об атаке
        """
        return self.attack_sources.copy()
