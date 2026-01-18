"""
Модуль уведомлений о угрозах
"""

import asyncio
import smtplib
import json
import time
from collections import deque
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
import logging
import subprocess

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger("ap-guardian.notifications")


class NotificationManager:
    """Менеджер уведомлений"""
    
    def __init__(self, config: Dict):
        """
        Инициализация менеджера уведомлений
        
        Args:
            config: Конфигурация уведомлений
        """
        self.config = config
        self.enabled = config.get("enabled", False)
        
        # Email настройки
        email_config = config.get("email", {})
        self.email_enabled = email_config.get("enabled", False)
        self.email_smtp_server = email_config.get("smtp_server", "smtp.gmail.com")
        self.email_smtp_port = email_config.get("smtp_port", 587)
        self.email_username = email_config.get("username", "")
        self.email_password = email_config.get("password", "")
        self.email_from = email_config.get("from", "")
        self.email_to = email_config.get("to", [])
        
        # Webhook настройки
        webhook_config = config.get("webhook", {})
        self.webhook_enabled = webhook_config.get("enabled", False)
        self.webhook_url = webhook_config.get("url", "")
        self.webhook_headers = webhook_config.get("headers", {})
        
        # Script настройки
        script_config = config.get("script", {})
        self.script_enabled = script_config.get("enabled", False)
        self.script_path = script_config.get("path", "")
        
        # Telegram настройки
        telegram_config = config.get("telegram", {})
        self.telegram_enabled = telegram_config.get("enabled", False)
        self.telegram_bot_token = telegram_config.get("bot_token", "")
        self.telegram_chat_id = telegram_config.get("chat_id", "")  # Admin ID
        
        # Минимальный уровень угрозы для уведомления
        self.min_threat_level = config.get("min_threat_level", "MEDIUM")
        
        # История отправленных уведомлений (для предотвращения спама)
        self.notification_history: deque = deque(maxlen=100)
        self.notification_cooldown = config.get("cooldown_seconds", 300)  # 5 минут
    
    async def send_notification(self, threat: Dict) -> None:
        """
        Отправка уведомления об угрозе
        
        Args:
            threat: Информация об угрозе
        """
        if not self.enabled:
            return
        
        threat_level = threat.get("threat_level", "LOW")
        
        # Проверка минимального уровня
        levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if levels.get(threat_level, 0) < levels.get(self.min_threat_level, 0):
            return
        
        # Проверка cooldown
        threat_id = f"{threat.get('type')}_{threat.get('src_ip', 'unknown')}"
        if self._is_in_cooldown(threat_id):
            return
        
        # Отправка уведомлений
        tasks = []
        
        if self.email_enabled:
            tasks.append(self._send_email(threat))
        
        if self.webhook_enabled:
            tasks.append(self._send_webhook(threat))
        
        if self.telegram_enabled:
            tasks.append(self._send_telegram(threat))
        
        if self.script_enabled:
            tasks.append(self._run_script(threat))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            self._record_notification(threat_id)
    
    def _is_in_cooldown(self, threat_id: str) -> bool:
        """Проверка cooldown для уведомления"""
        current_time = time.time()
        for notif_time, notif_id in self.notification_history:
            if notif_id == threat_id and (current_time - notif_time) < self.notification_cooldown:
                return True
        return False
    
    def _record_notification(self, threat_id: str) -> None:
        """Запись отправленного уведомления"""
        self.notification_history.append((time.time(), threat_id))
    
    async def _send_email(self, threat: Dict) -> None:
        """Отправка email уведомления"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = ", ".join(self.email_to)
            msg['Subject'] = f"AP-Guardian: Обнаружена угроза - {threat.get('type', 'Unknown')}"
            
            body = f"""
Обнаружена угроза безопасности:

Тип: {threat.get('type', 'Unknown')}
Уровень: {threat.get('threat_level', 'Unknown')}
IP источника: {threat.get('src_ip', 'Unknown')}
Описание: {threat.get('description', 'No description')}
Время: {threat.get('timestamp', 'Unknown')}

Детали:
{json.dumps(threat, indent=2, ensure_ascii=False)}
"""
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Отправка через SMTP
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._send_smtp,
                msg
            )
            
            logger.info(f"Email уведомление отправлено о угрозе {threat.get('type')}")
        except Exception as e:
            logger.error(f"Ошибка отправки email: {e}")
    
    def _send_smtp(self, msg: MIMEMultipart) -> None:
        """Синхронная отправка SMTP"""
        server = smtplib.SMTP(self.email_smtp_server, self.email_smtp_port)
        server.starttls()
        server.login(self.email_username, self.email_password)
        server.send_message(msg)
        server.quit()
    
    async def _send_webhook(self, threat: Dict) -> None:
        """Отправка webhook уведомления"""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests не установлен, webhook уведомления недоступны")
            return
        
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: requests.post(
                    self.webhook_url,
                    json=threat,
                    headers=self.webhook_headers,
                    timeout=5
                )
            )
            logger.info(f"Webhook уведомление отправлено о угрозе {threat.get('type')}")
        except Exception as e:
            logger.error(f"Ошибка отправки webhook: {e}")
    
    async def _send_telegram(self, threat: Dict) -> None:
        """Отправка Telegram уведомления"""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests не установлен, Telegram уведомления недоступны")
            return
        
        if not self.telegram_bot_token or not self.telegram_chat_id:
            logger.warning("Telegram bot_token или chat_id не настроены")
            return
        
        try:
            threat_type = threat.get('type', 'Unknown')
            threat_level = threat.get('threat_level', 'UNKNOWN')
            src_ip = threat.get('src_ip', 'Unknown')
            description = threat.get('description', 'No description')
            timestamp = threat.get('timestamp', datetime.now().isoformat())
            
            # Эмодзи в зависимости от уровня угрозы
            emoji_map = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️',
                'MEDIUM': '🔶',
                'LOW': 'ℹ️'
            }
            emoji = emoji_map.get(threat_level, '📢')
            
            # Форматирование сообщения
            message = f"""{emoji} <b>AP-Guardian: Обнаружена угроза</b>

<b>Тип:</b> {threat_type}
<b>Уровень:</b> {threat_level}
<b>IP источника:</b> <code>{src_ip}</code>
<b>Описание:</b> {description}
<b>Время:</b> {timestamp}"""
            
            # Добавление дополнительной информации в зависимости от типа угрозы
            if threat_type == 'bruteforce':
                dst_ip = threat.get('dst_ip', 'Unknown')
                dst_port = threat.get('dst_port', 'Unknown')
                failed_attempts = threat.get('failed_attempts', 0)
                message += f"\n\n<b>Цель:</b> {dst_ip}:{dst_port}"
                message += f"\n<b>Неудачных попыток:</b> {failed_attempts}"
            elif threat_type.startswith('ddos_'):
                packets_per_sec = threat.get('packets_per_second', 0)
                message += f"\n\n<b>Пакетов/сек:</b> {packets_per_sec}"
            elif threat_type in ['horizontal_scan', 'vertical_scan']:
                if threat_type == 'horizontal_scan':
                    hosts_scanned = threat.get('hosts_scanned', 0)
                    target_port = threat.get('target_port', 'Unknown')
                    message += f"\n\n<b>Сканировано хостов:</b> {hosts_scanned}"
                    message += f"\n<b>Целевой порт:</b> {target_port}"
                else:
                    ports_scanned = threat.get('ports_scanned', 0)
                    message += f"\n\n<b>Сканировано портов:</b> {ports_scanned}"
            elif threat_type == 'arp_spoofing':
                ip = threat.get('ip', 'Unknown')
                macs = threat.get('macs', [])
                message += f"\n\n<b>IP:</b> {ip}"
                message += f"\n<b>MAC адреса:</b> {', '.join(macs[:3])}"
            
            # Отправка через Telegram Bot API
            api_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    api_url,
                    json={
                        "chat_id": self.telegram_chat_id,
                        "text": message,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True
                    },
                    timeout=10
                )
            )
            
            if response.status_code == 200:
                logger.info(f"Telegram уведомление отправлено о угрозе {threat_type}")
            else:
                logger.error(f"Ошибка отправки Telegram: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Ошибка отправки Telegram уведомления: {e}")
    
    async def send_block_notification(self, ip: str, reason: str, threat_type: str = "Unknown") -> None:
        """
        Отправка уведомления о блокировке IP
        
        Args:
            ip: Заблокированный IP
            reason: Причина блокировки
            threat_type: Тип угрозы
        """
        if not self.enabled or not self.telegram_enabled:
            return
        
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return
        
        try:
            timestamp = datetime.now().isoformat()
            
            message = f"""🛡️ <b>AP-Guardian: IP заблокирован</b>

<b>IP:</b> <code>{ip}</code>
<b>Тип угрозы:</b> {threat_type}
<b>Причина:</b> {reason}
<b>Время:</b> {timestamp}
<b>Статус:</b> ✅ Заблокирован через firewall"""
            
            api_url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    api_url,
                    json={
                        "chat_id": self.telegram_chat_id,
                        "text": message,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True
                    },
                    timeout=10
                )
            )
            
            if response.status_code == 200:
                logger.info(f"Telegram уведомление о блокировке {ip} отправлено")
            else:
                logger.error(f"Ошибка отправки Telegram блокировки: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Ошибка отправки Telegram уведомления о блокировке: {e}")
    
    async def _run_script(self, threat: Dict) -> None:
        """Запуск скрипта уведомления"""
        if not self.script_path:
            return
        
        try:
            process = await asyncio.create_subprocess_exec(
                self.script_path,
                json.dumps(threat),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            logger.info(f"Скрипт уведомления выполнен для угрозы {threat.get('type')}")
        except Exception as e:
            logger.error(f"Ошибка выполнения скрипта уведомления: {e}")
