"""
Модуль уведомлений о угрозах
"""

import asyncio
import smtplib
import json
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
        import time
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
