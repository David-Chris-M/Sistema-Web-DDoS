(function () {
    'use strict';

    // 1. Gráfica de Recursos de Hardware (CPU y RAM)
    const MAX_HISTORIAL = 20;
    const etiquetasTiempo = Array.from({ length: MAX_HISTORIAL }, (_, i) => {
        const fecha = new Date(Date.now() - (MAX_HISTORIAL - i) * 1000);
        return fecha.toLocaleTimeString();
    });

    const elRecursos = document.getElementById('resourceChart');
    if (!elRecursos) return;
    const ctxRecursos = elRecursos.getContext('2d');
const graficoRecursos = new Chart(ctxRecursos, {
    type: 'line',
    data: {
        labels: [...etiquetasTiempo],
        datasets: [
            {
                label: 'CPU (%)',
                data: Array(MAX_HISTORIAL).fill(0),
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
                data: Array(MAX_HISTORIAL).fill(0),
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

// 2. Gráfica de Latencia de Inferencia Conv1D
const ctxLatencia = document.getElementById('latencyChart').getContext('2d');
const graficoLatencia = new Chart(ctxLatencia, {
    type: 'line',
    data: {
        labels: [...etiquetasTiempo],
        datasets: [{
            label: 'Latencia Conv1D (ms)',
            data: Array(MAX_HISTORIAL).fill(2.5),
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
async function actualizarTelemetria() {
    try {
        const respuesta = await fetch('/api/performance');
        const datos = await respuesta.json();

        const valorLatencia = datos.inference_latency_ms !== null && datos.inference_latency_ms !== undefined ? `${datos.inference_latency_ms} ms` : '0.0 ms';
        const valorExtremoAExtremo = datos.end_to_end_ms !== null && datos.end_to_end_ms !== undefined ? `${datos.end_to_end_ms} ms` : 'En espera';

        document.getElementById('kpiLatency').innerText = valorLatencia;
        document.getElementById('kpiEndToEnd').innerText = valorExtremoAExtremo;
        document.getElementById('kpiCpu').innerText = `${datos.cpu_percent}%`;
        document.getElementById('cpuBar').style.width = `${Math.min(datos.cpu_percent, 100)}%`;
        document.getElementById('kpiRam').innerText = `${datos.ram_mb} MB`;
        document.getElementById('kpiRamTotal').innerText = `De ${datos.total_ram_gb} GB disponibles`;
        document.getElementById('kpiThroughput').innerText = `${datos.throughput_fps} flujos/s`;

        const ahora = new Date().toLocaleTimeString();

        graficoRecursos.data.labels.shift();
        graficoRecursos.data.labels.push(ahora);
        graficoRecursos.data.datasets[0].data.shift();
        graficoRecursos.data.datasets[0].data.push(datos.cpu_percent || 0);
        graficoRecursos.data.datasets[1].data.shift();
        graficoRecursos.data.datasets[1].data.push(datos.ram_mb || 0);
        graficoRecursos.update();

        graficoLatencia.data.labels.shift();
        graficoLatencia.data.labels.push(ahora);
        graficoLatencia.data.datasets[0].data.shift();
        graficoLatencia.data.datasets[0].data.push(datos.inference_latency_ms || 0);
        graficoLatencia.update();

    } catch (error) {
        console.error('Error obteniendo telemetría:', error);
    }
}

// 4. Reloj e Inicialización
setInterval(() => {
    const elReloj = document.getElementById('currentTime');
    if (elReloj) {
        elReloj.textContent = new Date().toLocaleTimeString('es-ES', {
            weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }
}, 1000);

setInterval(actualizarTelemetria, 1000);
actualizarTelemetria();

    window.actualizarTelemetria = actualizarTelemetria;
    window.updateTelemetry = actualizarTelemetria;
    window.graficoRecursos = graficoRecursos;
    window.resourceChart = graficoRecursos;
    window.graficoLatencia = graficoLatencia;
    window.latencyChart = graficoLatencia;
})();