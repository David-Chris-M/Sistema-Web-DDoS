let totalCount = 0;
let normalCount = 0;
let ddosCount = 0;
let totalConfidenceAccumulated = 0; // MODIFICACIÓN 1: Acumulador de confianza

let currentSecondNormal = 0;
let currentSecondDDoS = 0;

// 1. Gráfica de Líneas en Tiempo Real
const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
const gradientNormal = ctxTraffic.createLinearGradient(0, 0, 0, 240);
gradientNormal.addColorStop(0, 'rgba(16, 185, 129, 0.4)');
gradientNormal.addColorStop(1, 'rgba(16, 185, 129, 0.0)');

const gradientDDoS = ctxTraffic.createLinearGradient(0, 0, 0, 240);
gradientDDoS.addColorStop(0, 'rgba(239, 68, 68, 0.4)');
gradientDDoS.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

const MAX_POINTS = 30;
const initialLabels = Array.from({ length: MAX_POINTS }, (_, i) => {
    const d = new Date(Date.now() - (MAX_POINTS - i) * 1000);
    return d.toLocaleTimeString();
});

const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: {
        labels: initialLabels,
        datasets: [
            {
                label: 'Tráfico Benigno',
                borderColor: '#10b981',
                backgroundColor: gradientNormal,
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                data: Array(MAX_POINTS).fill(0)
            },
            {
                label: 'Ataques DDoS',
                borderColor: '#ef4444',
                backgroundColor: gradientDDoS,
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                data: Array(MAX_POINTS).fill(0)
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            x: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8', maxTicksLimit: 6 } },
            y: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
        },
        plugins: { legend: { position: 'top' } }
    }
});

// 2. Gráfica de Dona (Distribución)
const ctxDist = document.getElementById('distributionChart').getContext('2d');
const distributionChart = new Chart(ctxDist, {
    type: 'doughnut',
    data: {
        labels: ['Benigno', 'DDoS'],
        datasets: [{
            data: [1, 0],
            backgroundColor: ['#10b981', '#ef4444'],
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: { legend: { position: 'bottom' } }
    }
});

// 3. Sincronización Inicial con la Base de Datos
// 3. Sincronización Inicial con la Base de Datos y Modelo
async function loadInitialData() {
    try {
        const [statsRes, modelRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/model').catch(() => null)
        ]);

        const stats = await statsRes.json();
        totalCount = stats.total || 0;
        normalCount = stats.normal || 0;
        ddosCount = stats.ddos || 0;

        // Soporte tanto para avg_confidence (backend real) como avg_accuracy
        const avgConfidence = stats.avg_confidence ?? stats.avg_accuracy;
        if (avgConfidence !== null && avgConfidence !== undefined) {
            totalConfidenceAccumulated = avgConfidence * totalCount;
            const elAcc = document.getElementById('kpiAccuracy');
            if (elAcc) elAcc.innerText = `${parseFloat(avgConfidence).toFixed(2)}%`;
        }

        if (modelRes && modelRes.ok) {
            const modelInfo = await modelRes.json();
            if (modelInfo.test_metrics) {
                // Tasa de falsos positivos experimental de la investigación (Tesis PE1 / HE1)
                const elFPR = document.getElementById('kpiFPR');
                if (elFPR && modelInfo.test_metrics.fpr !== undefined) {
                    const fprVal = (modelInfo.test_metrics.fpr * 100).toFixed(2);
                    elFPR.innerText = `${fprVal}%`;
                    const fprBar = document.getElementById('fprBar');
                    if (fprBar) fprBar.style.width = `${Math.min(Math.max(parseFloat(fprVal) * 10, 4), 100)}%`;
                }
            }
        }

        updateKPIs();
        updateDistribution();

        const historyRes = await fetch('/api/history?limit=10');
        const history = await historyRes.json();
        const tbody = document.getElementById('eventsTableBody');
        tbody.innerHTML = '';
        
        history.forEach(item => addTableRow(item, false));
    } catch (e) {
        console.error('Error sincronizando con BD:', e);
    }
}
loadInitialData();

// 4. Temporizador de Throughput (1 Hz)
setInterval(() => {
    const now = new Date().toLocaleTimeString();
    trafficChart.data.labels.shift();
    trafficChart.data.labels.push(now);

    trafficChart.data.datasets[0].data.shift();
    trafficChart.data.datasets[0].data.push(currentSecondNormal);

    trafficChart.data.datasets[1].data.shift();
    trafficChart.data.datasets[1].data.push(currentSecondDDoS);

    trafficChart.update();

    currentSecondNormal = 0;
    currentSecondDDoS = 0;
}, 1000);

// 5. Conexión WebSocket
function connectWebSocket() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${proto}//${window.location.host}/ws/traffic`);

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            processIncomingFlow(data);
        } catch (err) {
            console.error('Error parseando mensaje WebSocket:', err);
        }
    };

    socket.onclose = () => {
        setTimeout(connectWebSocket, 2000);
    };
}
connectWebSocket();

// 6. Manejo de Flujos Entrantes (Soporta individual y por lotes)
let isDistributionUpdateScheduled = false;

function processIncomingFlow(data) {
    if (!data) return;

    if (data.type === 'batch') {
        const batchTotal = data.total || 0;
        const batchDDoS = data.ddos || 0;
        const batchBenign = data.benign !== undefined ? data.benign : (batchTotal - batchDDoS);

        totalCount += batchTotal;
        ddosCount += batchDDoS;
        normalCount += batchBenign;
        currentSecondDDoS += batchDDoS;
        currentSecondNormal += batchBenign;

        if (batchDDoS > 0) {
            document.getElementById('globalStatus').className = 'status-indicator status-attack';
            document.getElementById('statusText').innerText = `ALERTA: ${batchDDoS} ATAQUES DETECTADOS`;
            document.getElementById('lastDetectionTime').innerText = `Última alerta: ${data.timestamp || '--:--:--'}`;
        } else {
            if (ddosCount === 0 || totalCount % 10 === 0) {
                document.getElementById('globalStatus').className = 'status-indicator status-safe';
                document.getElementById('statusText').innerText = 'RED SEGURA';
            }
        }

        if (Array.isArray(data.flows)) {
            data.flows.forEach(f => {
                const confVal = parseFloat(f.confidence_percentage ?? f.confidence ?? 99.0);
                totalConfidenceAccumulated += confVal;
                addTableRow(f, true);
            });
        }
    } else {
        // Flujo individual
        totalCount++;
        if (data.is_attack) {
            ddosCount++;
            currentSecondDDoS++;
            document.getElementById('globalStatus').className = 'status-indicator status-attack';
            document.getElementById('statusText').innerText = 'ALERTA: DDOS DETECTADO';
            document.getElementById('lastDetectionTime').innerText = `Última alerta: ${data.timestamp || '--:--:--'}`;
        } else {
            normalCount++;
            currentSecondNormal++;
            if (ddosCount === 0 || totalCount % 10 === 0) {
                document.getElementById('globalStatus').className = 'status-indicator status-safe';
                document.getElementById('statusText').innerText = 'RED SEGURA';
            }
        }

        const confidenceVal = parseFloat(data.confidence_percentage ?? data.confidence ?? 99.0);
        totalConfidenceAccumulated += confidenceVal;
        addTableRow(data, true);
    }

    updateKPIs();

    // Throttled Chart Update: evita congelar el navegador durante ataques masivos
    if (!isDistributionUpdateScheduled) {
        isDistributionUpdateScheduled = true;
        requestAnimationFrame(() => {
            updateDistribution();
            isDistributionUpdateScheduled = false;
        });
    }
}

// Actualización dinámica de KPIs basada en telemetría real
function updateKPIs() {
    const elTotal = document.getElementById('kpiTotal');
    const elDDoS = document.getElementById('kpiDDoS');
    const elAcc = document.getElementById('kpiAccuracy');

    if (elTotal) elTotal.innerText = totalCount.toLocaleString();
    if (elDDoS) elDDoS.innerText = ddosCount.toLocaleString();
    
    if (elAcc && totalCount > 0 && totalConfidenceAccumulated > 0) {
        const avgConf = (totalConfidenceAccumulated / totalCount).toFixed(2);
        elAcc.innerText = `${avgConf}%`;
    }
}

function updateDistribution() {
    distributionChart.data.datasets[0].data = [normalCount || 1, ddosCount];
    distributionChart.update();
}

function addTableRow(item, prepend = true) {
    if (!item) return;
    const tbody = document.getElementById('eventsTableBody');
    const row = document.createElement('tr');
    const isAttack = item.is_attack || item.prediction === 'DDoS';
    const badgeClass = isAttack ? 'badge bg-danger' : 'badge bg-success';
    const predictionText = item.prediction || (isAttack ? 'DDoS' : 'BENIGN');
    const timeFormatted = item.timestamp ? item.timestamp.split('T').pop().substring(0, 8) : '--:--:--';
    const conf = item.confidence_percentage !== undefined ? `${item.confidence_percentage}%` : '--';
    const prob = item.probability !== undefined ? item.probability : (isAttack ? 0.99 : 0.01);

    row.innerHTML = `
        <td class="fw-semibold text-secondary">${timeFormatted}</td>
        <td><span class="badge bg-light text-dark border">${item.protocol || 'TCP'}</span></td>
        <td><span class="${badgeClass}">${predictionText}</span></td>
        <td>${conf}</td>
        <td class="text-muted">${prob}</td>
        <td><span class="text-muted small"><i class="bi bi-shield-check"></i> Monitoreado</span></td>
    `;

    if (prepend) {
        tbody.prepend(row);
        if (tbody.children.length > 10) tbody.removeChild(tbody.lastChild);
    } else {
        tbody.appendChild(row);
    }
}

// 7. Simulación Directa
async function simulateTraffic(isAttack) {
    const endpoint = isAttack ? '/api/simulate/ddos' : '/api/simulate/benign';
    try {
        await fetch(endpoint, { method: 'POST' });
    } catch (e) {
        console.error('Error al simular tráfico:', e);
    }
}

// 8. Reloj
setInterval(() => {
    document.getElementById('currentTime').textContent = new Date().toLocaleTimeString('es-ES', {
        weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}, 1000);