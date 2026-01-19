#!/usr/bin/env python3
"""
Симулятор атак для демонстрации AP-Guardian
"""

import asyncio
import time
import random
import logging
from datetime import datetime
from typing import Dict, List
import sys

logger = logging.getLogger("ap-guardian.demo")


class AttackSimulator:
    """Симулятор различных сетевых атак"""
    
    def __init__(self, target_ip: str = "192.168.1.100"):
        self.target_ip = target_ip
        self.running = False
        self.attacks = []
        
    async def start(self) -> None:
        """Запуск симулятора"""
        self.running = True
        logger.info("🎭 Симулятор атак запущен")
        logger.info("🎯 Цель демонстрации: показать работу AP-Guardian")
        
        # Запуск всех атак
        tasks = [
            self.simulate_arp_spoofing(),
            self.simulate_port_scan(),
            self.simulate_ddos(),
            self.simulate_bruteforce(),
            self.show_status()
        ]
        
        await asyncio.gather(*tasks)
    
    async def stop(self) -> None:
        """Остановка симулятора"""
        self.running = False
        logger.info("Симулятор атак остановлен")
    
    async def simulate_arp_spoofing(self) -> None:
        """Симуляция ARP спуфинга"""
        while self.running:
            try:
                # Случайная задержка между атаками
                await asyncio.sleep(random.randint(5, 15))
                
                # Симулируем ARP конфликт
                fake_mac = ":".join([f"{random.randint(0,255):02x}" 
                                   for _ in range(6)])
                
                attack_info = {
                    "type": "arp_spoofing",
                    "description": f"Подделка ARP для шлюза (MAC: {fake_mac})",
                    "threat_level": "HIGH",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.attacks.append(attack_info)
                logger.warning(f"⚠️  Симуляция ARP спуфинга: {fake_mac}")
                
            except Exception as e:
                logger.error(f"Ошибка симуляции ARP: {e}")
                await asyncio.sleep(5)
    
    async def simulate_port_scan(self) -> None:
        """Симуляция сканирования портов"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
        
        while self.running:
            try:
                await asyncio.sleep(random.randint(8, 20))
                
                # Симулируем сканирование нескольких портов
                scanned_ports = random.sample(common_ports, 
                                            random.randint(5, 10))
                
                attack_info = {
                    "type": "network_scan",
                    "description": f"Сканирование портов: {scanned_ports}",
                    "ports": scanned_ports,
                    "threat_level": "MEDIUM",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.attacks.append(attack_info)
                logger.warning(f"🔍 Симуляция сканирования портов: {scanned_ports}")
                
            except Exception as e:
                logger.error(f"Ошибка симуляции сканирования: {e}")
                await asyncio.sleep(5)
    
    async def simulate_ddos(self) -> None:
        """Симуляция DDoS атаки"""
        attack_types = ["SYN Flood", "UDP Flood", "ICMP Flood", "HTTP Flood"]
        
        while self.running:
            try:
                await asyncio.sleep(random.randint(10, 25))
                
                attack_type = random.choice(attack_types)
                packet_count = random.randint(100, 1000)
                
                attack_info = {
                    "type": "ddos",
                    "description": f"{attack_type}: {packet_count} пакетов/сек",
                    "attack_type": attack_type,
                    "packet_rate": packet_count,
                    "threat_level": "CRITICAL",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.attacks.append(attack_info)
                logger.warning(f"🌪️  Симуляция DDoS: {attack_type}")
                
            except Exception as e:
                logger.error(f"Ошибка симуляции DDoS: {e}")
                await asyncio.sleep(5)
    
    async def simulate_bruteforce(self) -> None:
        """Симуляция брутфорс атаки"""
        services = ["SSH", "FTP", "Telnet", "HTTP", "MySQL"]
        
        while self.running:
            try:
                await asyncio.sleep(random.randint(12, 18))
                
                service = random.choice(services)
                attempts = random.randint(10, 50)
                
                attack_info = {
                    "type": "bruteforce",
                    "description": f"Брутфорс {service}: {attempts} попыток",
                    "service": service,
                    "attempts": attempts,
                    "threat_level": "HIGH",
                    "timestamp": datetime.now().isoformat()
                }
                
                self.attacks.append(attack_info)
                logger.warning(f"🔑 Симуляция брутфорса: {service}")
                
            except Exception as e:
                logger.error(f"Ошибка симуляции брутфорса: {e}")
                await asyncio.sleep(5)
    
    async def show_status(self) -> None:
        """Показ статуса демонстрации"""
        while self.running:
            try:
                await asyncio.sleep(30)
                
                recent_attacks = [a for a in self.attacks 
                                if datetime.fromisoformat(a["timestamp"]).timestamp() > 
                                time.time() - 60]
                
                if recent_attacks:
                    logger.info("=" * 50)
                    logger.info("📊 СТАТУС ДЕМО АТАК (последняя минута):")
                    
                    attacks_by_type = {}
                    for attack in recent_attacks:
                        atype = attack["type"]
                        attacks_by_type[atype] = attacks_by_type.get(atype, 0) + 1
                    
                    for atype, count in attacks_by_type.items():
                        logger.info(f"   {atype}: {count} атак")
                    
                    logger.info("=" * 50)
                
            except Exception as e:
                logger.error(f"Ошибка показа статуса: {e}")
    
    def get_recent_attacks(self, seconds: int = 60) -> List[Dict]:
        """Получение последних атак"""
        cutoff = time.time() - seconds
        return [
            a for a in self.attacks
            if datetime.fromisoformat(a["timestamp"]).timestamp() > cutoff
        ]


async def run_demo():
    """Запуск демонстрации"""
    print("\n" + "="*60)
    print("🎭 ДЕМОНСТРАЦИЯ AP-GUARDIAN")
    print("="*60)
    print("Симуляция атак для демонстрации системы защиты")
    print("="*60)
    
    simulator = AttackSimulator()
    
    try:
        # Запуск симулятора
        print("\n▶️  Запуск симулятора атак...")
        print("   • ARP Spoofing")
        print("   • Сканирование портов")
        print("   • DDoS атаки")
        print("   • Bruteforce атаки")
        print("\n⏳ Атаки будут начинаться через несколько секунд...")
        print("="*60)
        
        # Даем время для запуска основной системы
        await asyncio.sleep(3)
        
        # Запускаем симулятор
        await simulator.start()
        
    except KeyboardInterrupt:
        print("\n\n🛑 Демонстрация остановлена")
    finally:
        await simulator.stop()


def main():
    """Главная функция демо"""
    # Настройка логирования для вывода в консоль
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Запуск асинхронной демонстрации
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
