"""
Модуль детектора ARP Spoofing атак
"""

import asyncio
import re
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ap-guardian.arp_spoofing")


class ARPSpoofingDetector:
    """Детектор ARP Spoofing атак"""
    
    ARP_TABLE_PATH = "/proc/net/arp"
    
    def __init__(self, config: Dict):
        """
        Инициализация детектора
        
        Args:
            config: Конфигурация модуля
        """
        self.config = config
        self.check_interval = config.get("check_interval", 3)
        self.threshold = config.get("threshold", 3)
        self.block_duration = config.get("block_duration", 3600)
        self.trusted_devices = set(config.get("trusted_devices", []))
        self.monitor_gateway = config.get("monitor_gateway", True)
        
        # Хранилище ARP записей: IP -> Set[MAC]
        self.arp_table: Dict[str, Set[str]] = {}
        
        # История изменений: IP -> List[(timestamp, MAC)]
        self.change_history: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        
        # Обнаруженные конфликты: IP -> Set[MAC]
        self.conflicts: Dict[str, Set[str]] = {}
        
        # Статистика изменений: IP -> count
        self.change_counts: Dict[str, int] = defaultdict(int)
        
        # Gateway IP (будет определен автоматически)
        self.gateway_ip: Optional[str] = None
        
        self.running = False
    
    async def start(self) -> None:
        """Запуск детектора"""
        self.running = True
        logger.info("ARP Spoofing детектор запущен")
        
        # Определение gateway IP
        await self._detect_gateway()
        
        # Запуск мониторинга
        asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        """Остановка детектора"""
        self.running = False
        logger.info("ARP Spoofing детектор остановлен")
    
    async def _detect_gateway(self) -> None:
        """Определение IP адреса шлюза"""
        try:
            # Чтение таблицы маршрутизации
            with open("/proc/net/route", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "00000000":  # Default route
                        # Gateway в шестнадцатеричном формате
                        gateway_hex = parts[2]
                        # Конвертация из hex в IP
                        self.gateway_ip = self._hex_to_ip(gateway_hex)
                        logger.info(f"Обнаружен gateway: {self.gateway_ip}")
                        break
        except Exception as e:
            logger.warning(f"Не удалось определить gateway: {e}")
    
    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        """Конвертация hex строки в IP адрес"""
        try:
            # Удаление ведущих нулей и конвертация
            ip_parts = []
            for i in range(0, 8, 2):
                part = hex_str[i:i+2]
                ip_parts.append(str(int(part, 16)))
            return ".".join(reversed(ip_parts))
        except Exception:
            return ""
    
    async def _monitor_loop(self) -> None:
        """Основной цикл мониторинга"""
        while self.running:
            try:
                await self._check_arp_table()
                # Используем минимальный интервал 1 секунда для более быстрого обнаружения
                sleep_time = max(1, self.check_interval)
                await asyncio.sleep(sleep_time)
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга ARP: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _check_arp_table(self) -> None:
        """Проверка ARP таблицы на конфликты"""
        try:
            current_time = datetime.now()
            
            # Чтение текущей ARP таблицы
            with open(self.ARP_TABLE_PATH, "r") as f:
                current_arp: Dict[str, Set[str]] = {}
                
                # Пропуск заголовка
                next(f)
                
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        flags = parts[2]
                        
                        # Только завершенные ARP записи (0x2)
                        if flags == "0x2" or flags == "0x6":
                            if ip not in current_arp:
                                current_arp[ip] = set()
                            current_arp[ip].add(mac)
            
            # Обнаружение изменений и конфликтов
            for ip, macs in current_arp.items():
                # Проверка на конфликт (один IP -> несколько MAC)
                if len(macs) > 1:
                    if ip not in self.conflicts:
                        logger.warning(f"Обнаружен ARP конфликт: IP {ip} имеет несколько MAC: {macs}")
                    self.conflicts[ip] = macs.copy()
                    
                    # Особое внимание к gateway
                    if self.monitor_gateway and ip == self.gateway_ip:
                        logger.critical(f"КРИТИЧЕСКОЕ: Обнаружена подделка gateway! IP {ip}, MAC адреса: {macs}")
                
                # Отслеживание изменений MAC для одного IP
                if ip in self.arp_table:
                    old_macs = self.arp_table[ip]
                    new_macs = macs - old_macs
                    
                    if new_macs:
                        for mac in new_macs:
                            self.change_history[ip].append((current_time, mac))
                            self.change_counts[ip] += 1
                            
                            # Проверка частоты изменений
                            if self.change_counts[ip] >= self.threshold:
                                if ip not in self.trusted_devices:
                                    logger.warning(
                                        f"Подозрительная активность: IP {ip} изменил MAC {self.change_counts[ip]} раз. "
                                        f"Последний MAC: {mac}"
                                    )
                
                # Обновление таблицы
                self.arp_table[ip] = macs.copy()
            
            # Очистка старых записей из истории (старше 1 часа)
            cutoff_time = current_time - timedelta(hours=1)
            for ip in list(self.change_history.keys()):
                self.change_history[ip] = [
                    (ts, mac) for ts, mac in self.change_history[ip]
                    if ts > cutoff_time
                ]
                if not self.change_history[ip]:
                    del self.change_history[ip]
                    self.change_counts[ip] = 0
        
        except FileNotFoundError:
            logger.error(f"ARP таблица не найдена: {self.ARP_TABLE_PATH}")
        except Exception as e:
            logger.error(f"Ошибка при проверке ARP таблицы: {e}")
    
    def get_conflicts(self) -> Dict[str, Set[str]]:
        """
        Получение текущих конфликтов
        
        Returns:
            Словарь IP -> Set[MAC] с конфликтами
        """
        return self.conflicts.copy()
    
    def get_threats(self) -> List[Dict]:
        """
        Получение списка обнаруженных угроз
        
        Returns:
            Список словарей с информацией об угрозах
        """
        threats = []
        
        # Конфликты ARP
        for ip, macs in self.conflicts.items():
            threat_level = "CRITICAL" if ip == self.gateway_ip else "HIGH"
            threats.append({
                "type": "arp_spoofing",
                "ip": ip,
                "macs": list(macs),
                "threat_level": threat_level,
                "description": f"ARP конфликт: IP {ip} имеет {len(macs)} MAC адреса(ов)",
                "timestamp": datetime.now().isoformat()
            })
        
        # Частые изменения MAC
        for ip, count in self.change_counts.items():
            if count >= self.threshold and ip not in self.trusted_devices:
                threats.append({
                    "type": "arp_spoofing",
                    "ip": ip,
                    "threat_level": "MEDIUM",
                    "description": f"Подозрительная активность: IP {ip} изменил MAC {count} раз",
                    "change_count": count,
                    "timestamp": datetime.now().isoformat()
                })
        
        return threats
