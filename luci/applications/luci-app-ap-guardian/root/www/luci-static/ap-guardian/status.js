/**
 * JavaScript для страницы статуса AP-Guardian
 */

'use strict';

document.addEventListener('DOMContentLoaded', function() {
    const statusContainer = document.getElementById('status-container');
    const threatsContainer = document.getElementById('threats-container');
    const blocksContainer = document.getElementById('blocks-container');
    
    // Обновление статуса
    function updateStatus() {
        fetch('/cgi-bin/luci/admin/services/ap-guardian/status')
            .then(response => response.json())
            .then(data => {
                if (statusContainer) {
                    statusContainer.innerHTML = `
                        <div class="status-item">
                            <strong>Status:</strong> 
                            <span class="${data.running ? 'status-running' : 'status-stopped'}">
                                ${data.running ? 'Running' : 'Stopped'}
                            </span>
                        </div>
                        <div class="status-item">
                            <strong>Modules:</strong> ${Object.keys(data.modules || {}).length}
                        </div>
                    `;
                }
            })
            .catch(error => console.error('Error fetching status:', error));
    }
    
    // Обновление угроз
    function updateThreats() {
        fetch('/cgi-bin/luci/admin/services/ap-guardian/threats')
            .then(response => response.json())
            .then(data => {
                if (threatsContainer && Array.isArray(data)) {
                    if (data.length === 0) {
                        threatsContainer.innerHTML = '<p>No threats detected</p>';
                    } else {
                        const threatsHtml = data.map(threat => `
                            <div class="threat-item threat-${threat.threat_level?.toLowerCase() || 'medium'}">
                                <strong>${threat.type || 'Unknown'}</strong>
                                <p>${threat.description || 'No description'}</p>
                                <small>${threat.timestamp || ''}</small>
                            </div>
                        `).join('');
                        threatsContainer.innerHTML = threatsHtml;
                    }
                }
            })
            .catch(error => console.error('Error fetching threats:', error));
    }
    
    // Обновление блокировок
    function updateBlocks() {
        fetch('/cgi-bin/luci/admin/services/ap-guardian/firewall')
            .then(response => response.json())
            .then(data => {
                if (blocksContainer && Array.isArray(data)) {
                    if (data.length === 0) {
                        blocksContainer.innerHTML = '<p>No active blocks</p>';
                    } else {
                        const blocksHtml = data.map(block => `
                            <div class="block-item">
                                <strong>IP:</strong> ${block.ip || 'Unknown'}<br>
                                <strong>Reason:</strong> ${block.reason || 'Unknown'}<br>
                                <strong>Remaining:</strong> ${block.remaining_seconds || 0} seconds
                            </div>
                        `).join('');
                        blocksContainer.innerHTML = blocksHtml;
                    }
                }
            })
            .catch(error => console.error('Error fetching blocks:', error));
    }
    
    // Обновление каждые 5 секунд
    updateStatus();
    updateThreats();
    updateBlocks();
    
    setInterval(() => {
        updateStatus();
        updateThreats();
        updateBlocks();
    }, 5000);
});
