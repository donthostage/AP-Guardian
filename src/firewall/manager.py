"""
Модуль менеджера Firewall для автоматической блокировки угроз
"""

import asyncio
import subprocess
import time
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("ap-guardian.firewall")


class FirewallManager:
    """Менеджер Firewall для управления правилами iptables/arptables"""
    
    def __init__(self, config: Dict):
        """
        Инициализация менеджера
        
        Args:
            config: Конфигурация модуля
        """
        self.config = config
        self.auto_block = config.get("auto_block", True)
        self.rate_limit = config.get("rate_limit", True)
        self.rate_limit_packets = config.get("rate_limit_packets", 100)
        self.rate_limit_seconds = config.get("rate_limit_seconds", 1)
        
        self.whitelist = set(config.get("whitelist", []))
        self.blacklist = set(config.get("blacklist", []))
        
        # Активные блокировки: IP -> (timestamp, duration, reason)
        self.active_blocks: Dict[str, Dict] = {}
        
        # Временные правила: rule_id -> (timestamp, duration)
        self.temporary_rules: Dict[str, Dict] = {}
        
        # Цепочки iptables для AP-Guardian
        self.iptables_chain = "AP_GUARDIAN_INPUT"
        self.iptables_chain_forward = "AP_GUARDIAN_FORWARD"
        self.arptables_chain = "AP_GUARDIAN"
        
        self.running = False
    
    async def start(self) -> None:
        """Запуск менеджера и инициализация цепочек"""
        self.running = True
        logger.info("Firewall Manager запущен")
        
        # Инициализация цепочек
        await self._initialize_chains()
        
        # Запуск задачи очистки
        asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Остановка менеджера"""
        self.running = False
        logger.info("Firewall Manager остановлен")
    
    async def _initialize_chains(self) -> None:
        """Инициализация цепочек iptables и arptables"""
        try:
            # Создание цепочек iptables
            await self._run_command(
                ["iptables", "-N", self.iptables_chain],
                ignore_errors=True
            )
            await self._run_command(
                ["iptables", "-N", self.iptables_chain_forward],
                ignore_errors=True
            )
            
            # Добавление правил в INPUT и FORWARD
            await self._run_command(
                ["iptables", "-C", "INPUT", "-j", self.iptables_chain],
                ignore_errors=True
            ) or await self._run_command(
                ["iptables", "-I", "INPUT", "1", "-j", self.iptables_chain]
            )
            
            await self._run_command(
                ["iptables", "-C", "FORWARD", "-j", self.iptables_chain_forward],
                ignore_errors=True
            ) or await self._run_command(
                ["iptables", "-I", "FORWARD", "1", "-j", self.iptables_chain_forward]
            )
            
            # Создание цепочки arptables
            await self._run_command(
                ["arptables", "-N", self.arptables_chain],
                ignore_errors=True
            )
            
            await self._run_command(
                ["arptables", "-C", "INPUT", "-j", self.arptables_chain],
                ignore_errors=True
            ) or await self._run_command(
                ["arptables", "-I", "INPUT", "1", "-j", self.arptables_chain]
            )
            
            logger.info("Цепочки firewall инициализированы")
        except Exception as e:
            logger.error(f"Ошибка инициализации цепочек: {e}")
    
    async def _run_command(self, cmd: List[str], ignore_errors: bool = False) -> bool:
        """
        Выполнение команды
        
        Args:
            cmd: Команда для выполнения
            ignore_errors: Игнорировать ошибки
            
        Returns:
            True если команда выполнена успешно
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0 and not ignore_errors:
                logger.error(f"Ошибка выполнения команды {' '.join(cmd)}: {stderr.decode()}")
                return False
            
            return True
        except Exception as e:
            if not ignore_errors:
                logger.error(f"Исключение при выполнении команды {' '.join(cmd)}: {e}")
            return False
    
    async def block_ip(self, ip: str, duration: int = 3600, reason: str = "Threat detected") -> bool:
        """
        Блокировка IP адреса
        
        Args:
            ip: IP адрес для блокировки
            duration: Длительность блокировки в секундах
            reason: Причина блокировки
            
        Returns:
            True если блокировка успешна
        """
        # Проверка whitelist
        if ip in self.whitelist:
            logger.info(f"IP {ip} в whitelist, блокировка пропущена")
            return False
        
        # Проверка, не заблокирован ли уже
        if ip in self.active_blocks:
            logger.debug(f"IP {ip} уже заблокирован")
            return True
        
        try:
            # Проверка, существует ли уже правило (для предотвращения дубликатов)
            # Используем -C (check), если правило существует - пропускаем
            rule_exists = await self._run_command([
                "iptables", "-C", self.iptables_chain,
                "-s", ip,
                "-j", "DROP"
            ], ignore_errors=True)
            
            if not rule_exists:
                # Блокировка через iptables (INSERT в начало для приоритета)
                await self._run_command([
                    "iptables", "-I", self.iptables_chain, "1",
                    "-s", ip,
                    "-j", "DROP"
                ])
            
            # Аналогично для FORWARD цепочки
            rule_exists_forward = await self._run_command([
                "iptables", "-C", self.iptables_chain_forward,
                "-s", ip,
                "-j", "DROP"
            ], ignore_errors=True)
            
            if not rule_exists_forward:
                await self._run_command([
                    "iptables", "-I", self.iptables_chain_forward, "1",
                    "-s", ip,
                    "-j", "DROP"
                ])
            
            # Сохранение информации о блокировке
            self.active_blocks[ip] = {
                "timestamp": time.time(),
                "duration": duration,
                "reason": reason,
                "expires_at": time.time() + duration
            }
            
            logger.warning(f"IP {ip} заблокирован на {duration} сек. Причина: {reason}")
            return True
        
        except Exception as e:
            logger.error(f"Ошибка блокировки IP {ip}: {e}")
            return False
    
    async def block_arp(self, ip: str, mac: str, duration: int = 3600, 
                       reason: str = "ARP Spoofing") -> bool:
        """
        Блокировка ARP запросов
        
        Args:
            ip: IP адрес
            mac: MAC адрес
            duration: Длительность блокировки в секундах
            reason: Причина блокировки
            
        Returns:
            True если блокировка успешна
        """
        if ip in self.whitelist:
            return False
        
        try:
            # Блокировка через arptables
            await self._run_command([
                "arptables", "-A", self.arptables_chain,
                "--source-ip", ip,
                "--source-mac", mac,
                "-j", "DROP"
            ])
            
            block_key = f"{ip}_{mac}"
            self.active_blocks[block_key] = {
                "timestamp": time.time(),
                "duration": duration,
                "reason": reason,
                "expires_at": time.time() + duration,
                "type": "arp"
            }
            
            logger.warning(f"ARP блокировка: IP {ip}, MAC {mac}. Причина: {reason}")
            return True
        
        except Exception as e:
            logger.error(f"Ошибка ARP блокировки IP {ip}, MAC {mac}: {e}")
            return False
    
    async def unblock_ip(self, ip: str) -> bool:
        """
        Разблокировка IP адреса
        
        Args:
            ip: IP адрес для разблокировки
            
        Returns:
            True если разблокировка успешна
        """
        if ip not in self.active_blocks:
            return False
        
        try:
            # Удаление правил iptables
            await self._run_command([
                "iptables", "-D", self.iptables_chain,
                "-s", ip,
                "-j", "DROP"
            ], ignore_errors=True)
            
            await self._run_command([
                "iptables", "-D", self.iptables_chain_forward,
                "-s", ip,
                "-j", "DROP"
            ], ignore_errors=True)
            
            del self.active_blocks[ip]
            logger.info(f"IP {ip} разблокирован")
            return True
        
        except Exception as e:
            logger.error(f"Ошибка разблокировки IP {ip}: {e}")
            return False
    
    async def rate_limit_ip(self, ip: str) -> bool:
        """
        Ограничение скорости для IP
        
        Args:
            ip: IP адрес
            
        Returns:
            True если правило создано
        """
        if ip in self.whitelist:
            return False
        
        try:
            # Создание правила rate limiting
            await self._run_command([
                "iptables", "-A", self.iptables_chain,
                "-s", ip,
                "-m", "limit",
                "--limit", f"{self.rate_limit_packets}/{self.rate_limit_seconds}s",
                "-j", "ACCEPT"
            ])
            
            await self._run_command([
                "iptables", "-A", self.iptables_chain,
                "-s", ip,
                "-j", "DROP"
            ])
            
            logger.info(f"Rate limit применен к IP {ip}")
            return True
        
        except Exception as e:
            logger.error(f"Ошибка применения rate limit к IP {ip}: {e}")
            return False
    
    async def _cleanup_loop(self) -> None:
        """Цикл очистки истекших блокировок"""
        while self.running:
            try:
                await self._cleanup_expired_blocks()
                await asyncio.sleep(60)  # Проверка каждую минуту
            except Exception as e:
                logger.error(f"Ошибка в цикле очистки: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_expired_blocks(self) -> None:
        """Очистка истекших блокировок"""
        current_time = time.time()
        expired_ips = []
        
        for ip, block_info in list(self.active_blocks.items()):
            if block_info.get("expires_at", 0) < current_time:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            if "_" in ip:
                # ARP блокировка
                parts = ip.split("_")
                if len(parts) == 2:
                    await self._unblock_arp(parts[0], parts[1])
            else:
                await self.unblock_ip(ip)
    
    async def _unblock_arp(self, ip: str, mac: str) -> bool:
        """Разблокировка ARP"""
        try:
            await self._run_command([
                "arptables", "-D", self.arptables_chain,
                "--source-ip", ip,
                "--source-mac", mac,
                "-j", "DROP"
            ], ignore_errors=True)
            
            block_key = f"{ip}_{mac}"
            if block_key in self.active_blocks:
                del self.active_blocks[block_key]
            
            return True
        except Exception as e:
            logger.error(f"Ошибка разблокировки ARP: {e}")
            return False
    
    def get_active_blocks(self) -> List[Dict]:
        """
        Получение списка активных блокировок
        
        Returns:
            Список словарей с информацией о блокировках
        """
        blocks = []
        current_time = time.time()
        
        for ip, block_info in self.active_blocks.items():
            remaining = max(0, block_info.get("expires_at", 0) - current_time)
            blocks.append({
                "ip": ip,
                "reason": block_info.get("reason", "Unknown"),
                "remaining_seconds": int(remaining),
                "timestamp": datetime.fromtimestamp(
                    block_info.get("timestamp", current_time)
                ).isoformat()
            })
        
        return blocks
    
    def add_to_whitelist(self, ip: str) -> None:
        """Добавление IP в whitelist"""
        self.whitelist.add(ip)
        logger.info(f"IP {ip} добавлен в whitelist")
    
    def remove_from_whitelist(self, ip: str) -> None:
        """Удаление IP из whitelist"""
        self.whitelist.discard(ip)
        logger.info(f"IP {ip} удален из whitelist")
    
    def add_to_blacklist(self, ip: str) -> None:
        """Добавление IP в blacklist"""
        self.blacklist.add(ip)
        asyncio.create_task(self.block_ip(ip, duration=86400 * 365, reason="Blacklist"))
        logger.info(f"IP {ip} добавлен в blacklist")
