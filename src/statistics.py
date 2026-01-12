"""
Модуль сбора статистики и метрик
"""

import time
from collections import defaultdict, deque
from typing import Dict, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ap-guardian.statistics")


class StatisticsCollector:
    """Сборщик статистики системы"""
    
    def __init__(self):
        """Инициализация сборщика статистики"""
        # Статистика пакетов по типам
        self.packet_stats: Dict[str, int] = defaultdict(int)
        
        # Статистика по времени: тип -> deque[(timestamp, count)]
        self.timeline_stats: Dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))
        
        # Статистика угроз
        self.threats_count: Dict[str, int] = defaultdict(int)
        self.threats_timeline: deque = deque(maxlen=1000)
        
        # Статистика блокировок
        self.blocks_count = 0
        self.blocks_timeline: deque = deque(maxlen=1000)
        
        # Топ атакующих IP
        self.top_attackers: Dict[str, int] = defaultdict(int)
        
        # Статистика по портам
        self.port_stats: Dict[int, int] = defaultdict(int)
        
        self.start_time = time.time()
    
    def record_packet(self, packet_type: str) -> None:
        """Запись статистики пакета"""
        self.packet_stats[packet_type] += 1
        current_time = time.time()
        self.timeline_stats[packet_type].append((current_time, 1))
    
    def record_threat(self, threat_type: str, src_ip: str = None) -> None:
        """Запись статистики угрозы"""
        self.threats_count[threat_type] += 1
        self.threats_timeline.append({
            "type": threat_type,
            "src_ip": src_ip,
            "timestamp": datetime.now().isoformat()
        })
        
        if src_ip:
            self.top_attackers[src_ip] += 1
    
    def record_block(self, ip: str) -> None:
        """Запись статистики блокировки"""
        self.blocks_count += 1
        self.blocks_timeline.append({
            "ip": ip,
            "timestamp": datetime.now().isoformat()
        })
    
    def record_port_activity(self, port: int) -> None:
        """Запись активности порта"""
        self.port_stats[port] += 1
    
    def get_statistics(self) -> Dict:
        """
        Получение общей статистики
        
        Returns:
            Словарь со статистикой
        """
        uptime = time.time() - self.start_time
        
        # Подсчет пакетов за последний час
        one_hour_ago = time.time() - 3600
        recent_packets = {}
        for ptype, timeline in self.timeline_stats.items():
            count = sum(1 for ts, _ in timeline if ts >= one_hour_ago)
            recent_packets[ptype] = count
        
        # Топ 10 атакующих IP
        top_attackers = sorted(
            self.top_attackers.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Топ 10 портов
        top_ports = sorted(
            self.port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "uptime_seconds": int(uptime),
            "uptime_formatted": self._format_uptime(uptime),
            "packets_total": dict(self.packet_stats),
            "packets_last_hour": recent_packets,
            "threats_total": dict(self.threats_count),
            "threats_recent": len([t for t in self.threats_timeline 
                                  if datetime.fromisoformat(t["timestamp"]) > 
                                  datetime.now() - timedelta(hours=1)]),
            "blocks_total": self.blocks_count,
            "top_attackers": [{"ip": ip, "count": count} for ip, count in top_attackers],
            "top_ports": [{"port": port, "count": count} for port, count in top_ports],
            "timestamp": datetime.now().isoformat()
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Форматирование времени работы"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
