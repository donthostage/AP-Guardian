#!/usr/bin/env python3
"""
Веб-интерфейс для демонстрации AP-Guardian
"""

from flask import Flask, render_template_string, jsonify
import json
import time
from datetime import datetime

app = Flask(__name__)

# HTML шаблон для демо
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>AP-Guardian Demo</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                     gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .attack-log { background: white; padding: 20px; border-radius: 10px; margin-top: 20px; }
        .attack-item { padding: 10px; border-bottom: 1px solid #eee; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .blocked { color: #28a745; font-weight: bold; }
        .live-badge { background: #dc3545; color: white; padding: 3px 8px; 
                     border-radius: 12px; font-size: 12px; animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
    </style>
    <script>
        async function updateStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                // Обновляем статистику
                document.getElementById('totalAttacks').textContent = data.total_attacks;
                document.getElementById('blockedAttacks').textContent = data.blocked_attacks;
                document.getElementById('detectionRate').textContent = data.detection_rate + '%';
                document.getElementById('uptime').textContent = data.uptime;
                
                // Обновляем лог атак
                const logContainer = document.getElementById('attackLog');
                logContainer.innerHTML = '';
                
                data.recent_attacks.forEach(attack => {
                    const item = document.createElement('div');
                    item.className = 'attack-item';
                    item.innerHTML = `
                        <strong>[${attack.time}]</strong>
                        <span class="${attack.threat_level.toLowerCase()}">
                            ${attack.type.toUpperCase()}
                        </span>
                        <span>${attack.description}</span>
                        ${attack.blocked ? '<span class="blocked">✓ БЛОКИРОВАНО</span>' : ''}
                    `;
                    logContainer.prepend(item);
                });
                
            } catch (error) {
                console.error('Ошибка обновления:', error);
            }
        }
        
        // Обновляем каждые 3 секунды
        setInterval(updateStats, 3000);
        
        // Первое обновление
        document.addEventListener('DOMContentLoaded', updateStats);
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AP-Guardian Demo <span class="live-badge">LIVE</span></h1>
            <p>Система защиты публичных Wi-Fi сетей в реальном времени</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Всего атак</h3>
                <h2 id="totalAttacks">0</h2>
            </div>
            <div class="stat-card">
                <h3>Блокировано</h3>
                <h2 id="blockedAttacks">0</h2>
            </div>
            <div class="stat-card">
                <h3>Эффективность</h3>
                <h2 id="detectionRate">0%</h2>
            </div>
            <div class="stat-card">
                <h3>Время работы</h3>
                <h2 id="uptime">0:00</h2>
            </div>
        </div>
        
        <div class="attack-log">
            <h3>🎯 Обнаруженные атаки (последние 10):</h3>
            <div id="attackLog">
                <p>Ожидание данных...</p>
            </div>
        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 10px;">
            <h4>📊 Что происходит в демо:</h4>
            <ul>
                <li>Симулятор создает искусственные атаки</li>
                <li>AP-Guardian обнаруживает и классифицирует угрозы</li>
                <li>Система автоматически блокирует опасные IP</li>
                <li>В реальном времени обновляется статистика</li>
            </ul>
        </div>
    </div>
</body>
</html>
'''

# Демо данные
demo_data = {
    "start_time": time.time(),
    "attacks": [],
    "blocks": []
}

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def get_stats():
    current_time = time.time()
    
    # Генерация демо данных
    attack_types = ['arp_spoofing', 'port_scan', 'ddos', 'bruteforce']
    threat_levels = ['CRITICAL', 'HIGH', 'MEDIUM']
    
    # Добавляем новую "атаку" каждые несколько запросов
    if len(demo_data["attacks"]) < 50:
        demo_data["attacks"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": random.choice(attack_types),
            "description": random.choice([
                "ARP спуфинг шлюза",
                "Сканирование портов 80, 443, 22",
                "SYN Flood атака",
                "Брутфорс SSH"
            ]),
            "threat_level": random.choice(threat_levels),
            "blocked": random.random() > 0.3  # 70% блокируются
        })
    
    # Рассчитываем статистику
    total_attacks = len(demo_data["attacks"])
    blocked_attacks = len([a for a in demo_data["attacks"] if a["blocked"]])
    detection_rate = int((blocked_attacks / total_attacks * 100)) if total_attacks > 0 else 0
    
    uptime_seconds = int(current_time - demo_data["start_time"])
    uptime_str = f"{uptime_seconds // 60}:{uptime_seconds % 60:02d}"
    
    return jsonify({
        "total_attacks": total_attacks,
        "blocked_attacks": blocked_attacks,
        "detection_rate": detection_rate,
        "uptime": uptime_str,
        "recent_attacks": demo_data["attacks"][-10:]  # Последние 10 атак
    })

if __name__ == '__main__':
    import random
    app.run(host='0.0.0.0', port=8080, debug=True)
