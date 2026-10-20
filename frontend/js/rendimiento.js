const MAX_HISTORY = 20;
const timeLabels = Array.from({ length: MAX_HISTORY }, (_, i) => {
    const d = new Date(Date.now() - (MAX_HISTORY - i) * 1000);
    return d.toLocaleTimeString();
});

// 1. Gráfica de Recursos (CPU y RAM)
const ctxResource = document.getElementById('resourceChart').getContext('2d');
const resourceChart = new Chart(ctxResource, {
    type: 'line',
    data: {
        labels: [...timeLabels],
        datasets: [
            {
                label: 'CPU (%)',
                data: Array(MAX_HISTORY).fill(0),
                borderColor: '#0284c7',
                backgroundColor: 'rgba(2, 132, 199, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                yAxisID: 'y'
            },
            {
                label: 'RAM (MB)',
                data: Array(MAX_HISTORY).fill(0),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.05)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
                yAxisID: 'y1'
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            x: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8', maxTicksLimit: 6 } },
            y: {
                position: 'left',
                beginAtZero: true,
                max: 100,
                title: { display: true, text: 'CPU (%)', color: '#0284c7' },
                grid: { color: '#f1f5f9' }
            },
            y1: {
                position: 'right',
                beginAtZero: true,
                title: { display: true, text: 'RAM (MB)', color: '#10b981' },
                grid: { drawOnChartArea: false }
            }
        },
        plugins: { legend: { position: 'top' } }
    }
});

// 2. Gráfica de Latencia de Inferencia
const ctxLatency = document.getElementById('latencyChart').getContext('2d');
const latencyChart = new Chart(ctxLatency, {
    type: 'line',
    data: {
        labels: [...timeLabels],
        datasets: [{
            label: 'Latencia Conv1D (ms)',
            data: Array(MAX_HISTORY).fill(2.5),
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.15)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            x: { grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8', maxTicksLimit: 6 } },
            y: {
                beginAtZero: true,
                title: { display: true, text: 'Milisegundos (ms)', color: '#f59e0b' },
                grid: { color: '#f1f5f9' }
            }
        },
        plugins: { legend: { position: 'top' } }
    }
});

// 3. Sondeo Periódico de Telemetría (1 Hz)
async function updateTelemetry() {
    try {
        const res = await fetch('/api/performance');
        const data = await res.json();

        // Actualizar KPIs de manera resiliente (evita "null ms" si no hay tráfico reciente)
        const latVal = data.inference_latency_ms !== null && data.inference_latency_ms !== undefined ? `${data.inference_latency_ms} ms` : '0.0 ms';
        const e2eVal = data.end_to_end_ms !== null && data.end_to_end_ms !== undefined ? `${data.end_to_end_ms} ms` : 'En espera';
        
        document.getElementById('kpiLatency').innerText = latVal;
        document.getElementById('kpiEndToEnd').innerText = e2eVal;
        document.getElementById('kpiCpu').innerText = `${data.cpu_percent}%`;
        document.getElementById('cpuBar').style.width = `${Math.min(data.cpu_percent, 100)}%`;
        document.getElementById('kpiRam').innerText = `${data.ram_mb} MB`;
        document.getElementById('kpiRamTotal').innerText = `De ${data.total_ram_gb} GB disponibles`;
        document.getElementById('kpiThroughput').innerText = `${data.throughput_fps} flujos/s`;

        // Actualizar Gráficas
        const now = new Date().toLocaleTimeString();

        resourceChart.data.labels.shift();
        resourceChart.data.labels.push(now);
        resourceChart.data.datasets[0].data.shift();
        resourceChart.data.datasets[0].data.push(data.cpu_percent || 0);
        resourceChart.data.datasets[1].data.shift();
        resourceChart.data.datasets[1].data.push(data.ram_mb || 0);
        resourceChart.update();

        latencyChart.data.labels.shift();
        latencyChart.data.labels.push(now);
        latencyChart.data.datasets[0].data.shift();
        latencyChart.data.datasets[0].data.push(data.inference_latency_ms || 0);
        latencyChart.update();

    } catch (e) {
        console.error('Error obteniendo telemetría:', e);
    }
}

// Reloj
setInterval(() => {
    document.getElementById('currentTime').textContent = new Date().toLocaleTimeString('es-ES', {
        weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}, 1000);

setInterval(updateTelemetry, 1000);
updateTelemetry();