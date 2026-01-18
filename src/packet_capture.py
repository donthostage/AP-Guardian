"""
Модуль захвата и анализа сетевых пакетов
"""

import asyncio
import socket
from typing import Optional, Callable, Dict, Any
import logging

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("scapy не установлен, захват пакетов будет ограничен")

logger = logging.getLogger("ap-guardian.packet_capture")


class PacketCapture:
    """Класс для захвата и анализа сетевых пакетов"""
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Инициализация захвата пакетов
        
        Args:
            callback: Функция обратного вызова для обработки пакетов
        """
        self.callback = callback
        self.running = False
        self.socket_fd: Optional[socket.socket] = None
    
    async def start(self, interface: str = "any") -> None:
        """
        Запуск захвата пакетов
        
        Args:
            interface: Сетевой интерфейс для захвата
        """
        if not SCAPY_AVAILABLE:
            logger.warning("scapy недоступен, используем альтернативный метод")
            await self._start_raw_socket(interface)
            return
        
        self.running = True
        logger.info(f"Захват пакетов запущен на интерфейсе {interface}")
        
        # Запуск захвата в отдельном потоке
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._sniff_packets, interface)
    
    async def _start_raw_socket(self, interface: str) -> None:
        """Альтернативный метод захвата через raw socket"""
        try:
            # Создание raw socket для захвата пакетов
            self.socket_fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.socket_fd.setblocking(False)
            self.running = True
            
            logger.info(f"Raw socket захват запущен на интерфейсе {interface}")
            
            # Запуск цикла захвата
            asyncio.create_task(self._raw_socket_loop())
        except PermissionError:
            logger.error("Недостаточно прав для создания raw socket. Запустите с правами root.")
            self.running = False
        except Exception as e:
            logger.error(f"Ошибка создания raw socket: {e}")
            self.running = False
    
    async def _raw_socket_loop(self) -> None:
        """Цикл захвата через raw socket"""
        loop = asyncio.get_event_loop()
        while self.running and self.socket_fd:
            try:
                # Используем более эффективный метод чтения
                try:
                    data, addr = await loop.sock_recvfrom(self.socket_fd, 65535)
                    if self.callback and data:
                        await self._process_raw_packet(data)
                except BlockingIOError:
                    await asyncio.sleep(0.001)  # Минимальная задержка
                except OSError as e:
                    if e.errno != 11:  # EAGAIN
                        logger.error(f"Ошибка чтения из raw socket: {e}")
                    await asyncio.sleep(0.01)
            except Exception as e:
                logger.error(f"Ошибка в raw socket цикле: {e}")
                await asyncio.sleep(0.1)
    
    async def _process_raw_packet(self, data: bytes) -> None:
        """Обработка сырого пакета"""
        try:
            if len(data) < 14:  # Минимальный размер Ethernet фрейма
                return
            
            # Парсинг Ethernet заголовка
            eth_header = data[:14]
            dst_mac = eth_header[0:6]
            src_mac = eth_header[6:12]
            eth_type = int.from_bytes(eth_header[12:14], 'big')
            
            # Обработка IP пакетов
            if eth_type == 0x0800 and len(data) >= 34:  # IPv4
                ip_header = data[14:34]
                protocol = ip_header[9]
                src_ip = socket.inet_ntoa(ip_header[12:16])
                dst_ip = socket.inet_ntoa(ip_header[16:20])
                
                packet_info = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_mac": src_mac.hex(':'),
                    "dst_mac": dst_mac.hex(':')
                }
                
                # Обработка TCP
                if protocol == 6 and len(data) >= 54:
                    tcp_header = data[34:54]
                    src_port = int.from_bytes(tcp_header[0:2], 'big')
                    dst_port = int.from_bytes(tcp_header[2:4], 'big')
                    flags = tcp_header[13]
                    
                    packet_info.update({
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "tcp_flags": flags
                    })
                    
                    # SYN пакет (флаг SYN установлен, ACK не установлен)
                    # 0x02 = SYN, 0x10 = ACK, 0x12 = SYN+ACK
                    if (flags & 0x02) and not (flags & 0x10):
                        # Чистый SYN без ACK
                        if self.callback:
                            await self.callback("syn", **packet_info)
                    # SYN-ACK пакет (оба флага SYN и ACK установлены)
                    elif (flags & 0x12) == 0x12:
                        # SYN + ACK
                        if self.callback:
                            await self.callback("syn_ack", **packet_info)
                
                # Обработка UDP
                elif protocol == 17 and len(data) >= 42:
                    udp_header = data[34:42]
                    src_port = int.from_bytes(udp_header[0:2], 'big')
                    dst_port = int.from_bytes(udp_header[2:4], 'big')
                    
                    packet_info.update({
                        "src_port": src_port,
                        "dst_port": dst_port
                    })
                    
                    if self.callback:
                        await self.callback("udp", **packet_info)
                
                # Обработка ICMP
                elif protocol == 1:
                    if self.callback:
                        await self.callback("icmp", **packet_info)
            
            # Обработка ARP пакетов
            elif eth_type == 0x0806 and len(data) >= 42:  # ARP
                arp_data = data[14:42]
                src_ip = socket.inet_ntoa(arp_data[14:18])
                dst_ip = socket.inet_ntoa(arp_data[24:28])
                src_mac = arp_data[8:14].hex(':')
                dst_mac = arp_data[18:24].hex(':')
                
                if self.callback:
                    await self.callback("arp", src_ip=src_ip, dst_ip=dst_ip,
                                      src_mac=src_mac, dst_mac=dst_mac)
        
        except Exception as e:
            logger.debug(f"Ошибка обработки пакета: {e}")
    
    def _sniff_packets(self, interface: str) -> None:
        """Захват пакетов с использованием scapy"""
        if not SCAPY_AVAILABLE:
            return
        
        try:
            # Используем асинхронный захват через asyncio
            import threading
            
            def sniff_thread():
                try:
                    sniff(
                        iface=interface if interface != "any" else None,
                        prn=self._process_scapy_packet,
                        stop_filter=lambda x: not self.running,
                        store=False,
                        quiet=True
                    )
                except Exception as e:
                    logger.error(f"Ошибка захвата пакетов scapy: {e}")
            
            thread = threading.Thread(target=sniff_thread, daemon=True)
            thread.start()
        except Exception as e:
            logger.error(f"Ошибка запуска захвата пакетов: {e}")
    
    def _process_scapy_packet(self, packet) -> None:
        """Обработка пакета от scapy"""
        if not self.callback:
            return
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                packet_info = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                }
                
                # TCP пакеты
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info.update({
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "tcp_flags": tcp.flags
                    })
                    
                    # TCP флаги: 0x02 = SYN, 0x10 = ACK, 0x12 = SYN+ACK
                    # Проверяем флаги правильно
                    tcp_flags = tcp.flags
                    if (tcp_flags & 0x02) and not (tcp_flags & 0x10):  # SYN без ACK
                        asyncio.create_task(
                            self.callback("syn", **packet_info)
                        )
                    elif (tcp_flags & 0x12) == 0x12:  # SYN + ACK
                        asyncio.create_task(
                            self.callback("syn_ack", **packet_info)
                        )
                
                # UDP пакеты
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info.update({
                        "src_port": udp.sport,
                        "dst_port": udp.dport
                    })
                    asyncio.create_task(
                        self.callback("udp", **packet_info)
                    )
                
                # ICMP пакеты
                elif ICMP in packet:
                    asyncio.create_task(
                        self.callback("icmp", **packet_info)
                    )
            
            # ARP пакеты
            elif ARP in packet:
                arp = packet[ARP]
                asyncio.create_task(
                    self.callback(
                        "arp",
                        src_ip=arp.psrc,
                        dst_ip=arp.pdst,
                        src_mac=arp.hwsrc,
                        dst_mac=arp.hwdst
                    )
                )
        
        except Exception as e:
            logger.debug(f"Ошибка обработки scapy пакета: {e}")
    
    async def stop(self) -> None:
        """Остановка захвата пакетов"""
        self.running = False
        if self.socket_fd:
            self.socket_fd.close()
            self.socket_fd = None
        logger.info("Захват пакетов остановлен")
