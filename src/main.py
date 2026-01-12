"""
Главный модуль системы AP-Guardian
"""

import asyncio
import signal
import sys
import os
from typing import Dict, List
import logging

from .config import Config
from .logger import get_logger, Logger
from .detectors import ARPSpoofingDetector, DDoSDetector, NetworkScanDetector, BruteforceDetector
from .firewall import FirewallManager
from .packet_capture import PacketCapture
from .api_server import APIServer
from .statistics import StatisticsCollector
from .notifications import NotificationManager

logger = get_logger()


class APGuardian:
    """Главный класс системы AP-Guardian"""
    
    def __init__(self, config_path: str = None):
        """
        Инициализация системы
        
        Args:
            config_path: Путь к файлу конфигурации
        """
        self.config = Config(config_path)
        
        # Настройка логирования
        log_level = self.config.get("general", "log_level", default="INFO")
        log_file = self.config.get("general", "log_file", default="/var/log/ap-guardian.log")
        Logger().setup(log_level, log_file)
        
        # Инициализация модулей
        self.arp_detector: ARPSpoofingDetector = None
        self.ddos_detector: DDoSDetector = None
        self.scan_detector: NetworkScanDetector = None
        self.bruteforce_detector: BruteforceDetector = None
        self.firewall_manager: FirewallManager = None
        self.packet_capture: PacketCapture = None
        self.api_server = None
        self.statistics = StatisticsCollector()
        self.notification_manager = None
        
        self.running = False
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self) -> None:
        """Настройка обработчиков сигналов"""
        def signal_handler(sig, frame):
            logger.info("Получен сигнал остановки")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def initialize(self) -> None:
        """Инициализация всех модулей"""
        logger.info("Инициализация AP-Guardian...")
        
        # Инициализация детекторов
        if self.config.is_enabled("arp_spoofing"):
            arp_config = self.config.get("arp_spoofing")
            self.arp_detector = ARPSpoofingDetector(arp_config)
            logger.info("ARP Spoofing детектор инициализирован")
        
        if self.config.is_enabled("ddos"):
            ddos_config = self.config.get("ddos")
            self.ddos_detector = DDoSDetector(ddos_config)
            logger.info("DDoS детектор инициализирован")
        
        if self.config.is_enabled("network_scan"):
            scan_config = self.config.get("network_scan")
            self.scan_detector = NetworkScanDetector(scan_config)
            logger.info("Network Scan детектор инициализирован")
        
        # Инициализация детектора брутфорса
        if self.config.is_enabled("bruteforce"):
            bruteforce_config = self.config.get("bruteforce")
            self.bruteforce_detector = BruteforceDetector(bruteforce_config)
            logger.info("Bruteforce детектор инициализирован")
        
        # Инициализация менеджера Firewall
        if self.config.is_enabled("firewall"):
            firewall_config = self.config.get("firewall")
            self.firewall_manager = FirewallManager(firewall_config)
            logger.info("Firewall Manager инициализирован")
        
        # Инициализация менеджера уведомлений
        notifications_config = self.config.get("notifications", {})
        if notifications_config.get("enabled", False):
            self.notification_manager = NotificationManager(notifications_config)
            logger.info("Notification Manager инициализирован")
        
        # Инициализация захвата пакетов
        self.packet_capture = PacketCapture(callback=self._packet_callback)
        logger.info("Packet Capture инициализирован")
        
        # Инициализация API сервера
        self.api_server = APIServer(self)
        logger.info("API Server инициализирован")
    
    async def start(self) -> None:
        """Запуск системы"""
        if self.running:
            logger.warning("Система уже запущена")
            return
        
        logger.info("Запуск AP-Guardian...")
        self.running = True
        
        # Запуск модулей
        if self.arp_detector:
            await self.arp_detector.start()
        
        if self.ddos_detector:
            await self.ddos_detector.start()
        
        if self.scan_detector:
            await self.scan_detector.start()
        
        if self.bruteforce_detector:
            await self.bruteforce_detector.start()
        
        if self.firewall_manager:
            await self.firewall_manager.start()
        
        # Запуск захвата пакетов
        interface = os.getenv("AP_GUARDIAN_INTERFACE", "any")
        await self.packet_capture.start(interface)
        
        # Запуск задачи мониторинга угроз
        asyncio.create_task(self._threat_monitoring_loop())
        
        # Запуск API сервера
        if self.api_server:
            await self.api_server.start()
        
        logger.info("AP-Guardian запущен и работает")
    
    async def _packet_callback(self, packet_type: str, **kwargs) -> None:
        """
        Обработка захваченных пакетов
        
        Args:
            packet_type: Тип пакета (syn, syn_ack, udp, icmp, arp)
            **kwargs: Параметры пакета
        """
        try:
            src_ip = kwargs.get("src_ip")
            dst_ip = kwargs.get("dst_ip")
            dst_port = kwargs.get("dst_port")
            
            # Запись статистики
            self.statistics.record_packet(packet_type)
            if dst_port:
                self.statistics.record_port_activity(dst_port)
            
            # Обработка ARP детектором
            if packet_type == "arp" and self.arp_detector:
                # ARP пакеты обрабатываются через мониторинг ARP таблицы
                pass
            
            # Обработка DDoS детектором
            if self.ddos_detector:
                if packet_type == "syn":
                    self.ddos_detector.process_packet("syn", src_ip, dst_ip)
                elif packet_type == "syn_ack":
                    self.ddos_detector.process_packet("syn_ack", src_ip, dst_ip)
                elif packet_type == "udp":
                    self.ddos_detector.process_packet("udp", src_ip, dst_ip)
                elif packet_type == "icmp":
                    self.ddos_detector.process_packet("icmp", src_ip, dst_ip)
            
            # Обработка Network Scan детектором
            if self.scan_detector and dst_port:
                if packet_type in ["syn", "udp"]:
                    self.scan_detector.process_connection_attempt(
                        src_ip, dst_ip, dst_port, connection_type=packet_type
                    )
            
            # Обработка Bruteforce детектором
            if self.bruteforce_detector and dst_port:
                if packet_type == "syn":
                    # Для SYN пакетов считаем как попытку подключения
                    # Успешность определяется по наличию SYN-ACK
                    self.bruteforce_detector.process_connection(src_ip, dst_ip, dst_port, success=False)
        
        except Exception as e:
            logger.debug(f"Ошибка обработки пакета: {e}")
    
    async def _threat_monitoring_loop(self) -> None:
        """Цикл мониторинга угроз и автоматической блокировки"""
        check_interval = self.config.get("general", "check_interval", default=3)
        
        while self.running:
            try:
                threats = await self._collect_threats()
                
                # Автоматическая блокировка угроз
                if self.firewall_manager and self.firewall_manager.auto_block:
                    await self._handle_threats(threats)
                
                await asyncio.sleep(check_interval)
            
            except Exception as e:
                logger.error(f"Ошибка в цикле мониторинга угроз: {e}")
                await asyncio.sleep(check_interval)
    
    async def _collect_threats(self) -> List[Dict]:
        """Сбор угроз от всех детекторов"""
        threats = []
        
        # Угрозы от ARP детектора
        if self.arp_detector:
            arp_threats = self.arp_detector.get_threats()
            threats.extend(arp_threats)
        
        # Угрозы от DDoS детектора
        if self.ddos_detector:
            ddos_threats = self.ddos_detector.get_threats()
            threats.extend(ddos_threats)
        
        # Угрозы от Network Scan детектора
        if self.scan_detector:
            scan_threats = self.scan_detector.get_threats()
            threats.extend(scan_threats)
        
        # Угрозы от Bruteforce детектора
        if self.bruteforce_detector:
            bruteforce_threats = self.bruteforce_detector.get_threats()
            threats.extend(bruteforce_threats)
        
        return threats
    
    async def _handle_threats(self, threats: List[Dict]) -> None:
        """Обработка угроз и автоматическая блокировка"""
        if not self.firewall_manager:
            return
        
        block_duration = self.config.get("arp_spoofing", "block_duration", default=3600)
        
        for threat in threats:
            threat_type = threat.get("type", "")
            threat_level = threat.get("threat_level", "MEDIUM")
            src_ip = threat.get("src_ip")
            
            # Запись статистики
            self.statistics.record_threat(threat_type, src_ip)
            
            # Отправка уведомлений
            if self.notification_manager:
                await self.notification_manager.send_notification(threat)
            
            # Определение IP для блокировки
            ip_to_block = None
            
            if threat_type == "arp_spoofing":
                ip_to_block = threat.get("ip")
                # Для ARP спуфинга также блокируем MAC
                macs = threat.get("macs", [])
                if ip_to_block and macs and self.firewall_manager:
                    for mac in macs:
                        await self.firewall_manager.block_arp(
                            ip_to_block, mac, duration=block_duration,
                            reason="ARP Spoofing detected"
                        )
            
            elif threat_type.startswith("ddos_"):
                # Для DDoS блокируем по IP источника
                ip_to_block = threat.get("src_ip")
                if not ip_to_block and self.ddos_detector:
                    # Получаем источники атак из детектора
                    attack_sources = self.ddos_detector.get_attack_sources()
                    if attack_sources:
                        # Блокируем самый активный источник
                        top_attacker = max(attack_sources.items(), key=lambda x: x[1]["count"])
                        ip_to_block = top_attacker[0]
            
            elif threat_type in ["horizontal_scan", "vertical_scan", "combined_scan", "bruteforce"]:
                ip_to_block = threat.get("src_ip")
            
            # Блокировка IP
            if ip_to_block and self.firewall_manager:
                success = await self.firewall_manager.block_ip(
                    ip_to_block,
                    duration=block_duration,
                    reason=f"{threat_type}: {threat.get('description', 'Threat detected')}"
                )
                if success:
                    self.statistics.record_block(ip_to_block)
    
    async def stop(self) -> None:
        """Остановка системы"""
        if not self.running:
            return
        
        logger.info("Остановка AP-Guardian...")
        self.running = False
        
        # Остановка модулей
        if self.packet_capture:
            await self.packet_capture.stop()
        
        if self.arp_detector:
            await self.arp_detector.stop()
        
        if self.ddos_detector:
            await self.ddos_detector.stop()
        
        if self.scan_detector:
            await self.scan_detector.stop()
        
        if self.bruteforce_detector:
            await self.bruteforce_detector.stop()
        
        if self.firewall_manager:
            await self.firewall_manager.stop()
        
        if self.api_server:
            await self.api_server.stop()
        
        logger.info("AP-Guardian остановлен")
    
    def get_status(self) -> Dict:
        """
        Получение статуса системы
        
        Returns:
            Словарь со статусом системы
        """
        status = {
            "running": self.running,
            "modules": {}
        }
        
        if self.arp_detector:
            status["modules"]["arp_spoofing"] = {
                "enabled": True,
                "conflicts": len(self.arp_detector.get_conflicts())
            }
        
        if self.ddos_detector:
            status["modules"]["ddos"] = {
                "enabled": True,
                "threats": len(self.ddos_detector.get_threats())
            }
        
        if self.scan_detector:
            status["modules"]["network_scan"] = {
                "enabled": True,
                "threats": len(self.scan_detector.get_threats())
            }
        
        if self.bruteforce_detector:
            status["modules"]["bruteforce"] = {
                "enabled": True,
                "threats": len(self.bruteforce_detector.get_threats())
            }
        
        if self.firewall_manager:
            status["modules"]["firewall"] = {
                "enabled": True,
                "active_blocks": len(self.firewall_manager.get_active_blocks())
            }
        
        # Добавление статистики
        status["statistics"] = self.statistics.get_statistics()
        
        return status


def main():
    """Главная функция"""
    # Проверка прав root
    if os.geteuid() != 0:
        print("Ошибка: AP-Guardian требует прав root для работы")
        sys.exit(1)
    
    # Создание и запуск системы
    system = APGuardian()
    
    async def run():
        await system.initialize()
        await system.start()
        
        # Ожидание завершения
        try:
            while system.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await system.stop()
    
    asyncio.run(run())


if __name__ == "__main__":
    main()
