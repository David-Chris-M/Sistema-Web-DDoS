let currentPage = 1;
const rowsPerPage = 10;
let hourlyChartInstance = null;
let protocolChartInstance = null;

async function loadAnalyticsData() {
    await Promise.all([loadHourlyChart(), loadProtocolChart(), loadFlowTable()]);
}

// 1. Cargar Gráfico de Barras Apiladas (Histórico real)
async function loadHourlyChart() {
    try {
        const res = await fetch('/api/analysis/traffic-by-hour');
        const data = await res.json();
        const ctx = document.getElementById('hourlyTrafficChart').getContext('2d');

        if (hourlyChartInstance) hourlyChartInstance.destroy();

        hourlyChartInstance = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [
                    { label: 'Benigno', data: data.benign, backgroundColor: '#10b981' },
                    { label: 'DDoS', data: data.attack, backgroundColor: '#ef4444' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { stacked: true, grid: { color: '#f1f5f9' } },
                    y: { stacked: true, beginAtZero: true, grid: { color: '#f1f5f9' } }
                }
            }
        });
    } catch (e) {
        console.error('Error cargando gráfico horario:', e);
    }
}

// 2. Cargar Distribución de Protocolos
async function loadProtocolChart() {
    try {
        const res = await fetch('/api/analysis/protocol-distribution');
        const data = await res.json();
        const ctx = document.getElementById('protocolsPieChart').getContext('2d');

        if (protocolChartInstance) protocolChartInstance.destroy();

        protocolChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.labels,
                datasets: [{
                    data: data.counts,
                    backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    } catch (e) {
        console.error('Error cargando protocolos:', e);
    }
}

// 3. Cargar Tabla de Flujos Paginada y Filtrada
async function loadFlowTable() {
    const proto = document.getElementById('filterProtocol').value;
    const pred = document.getElementById('filterPrediction').value;

    try {
        const res = await fetch(`/api/analysis/flows?page=${currentPage}&limit=${rowsPerPage}&protocol=${proto}&prediction=${pred}`);
        const result = await res.json();
        const tbody = document.getElementById('fullFlowTable');
        tbody.innerHTML = '';

            result.data.forEach(f => {
                const isAttack = f.is_attack;
                const badgeClass = isAttack ? 'badge bg-danger' : 'badge bg-success';
                const row = document.createElement('tr');
                const timeStr = f.timestamp ? f.timestamp.replace('T', ' ').substring(11, 19) : '--:--:--';

                row.innerHTML = `
                    <td class="fw-semibold text-secondary">${timeStr}</td>
                    <td><code class="text-dark">${f.src_ip || '192.168.18.10'}</code></td>
                    <td><code class="text-dark">${f.dst_ip || '10.0.0.1'}</code></td>
                    <td><span class="badge bg-light text-dark border">${f.protocol}</span></td>
                    <td><span class="${badgeClass}">${f.prediction}</span></td>
                    <td>${f.duration_ms ? f.duration_ms.toFixed(1) : '120.0'} ms</td>
                    <td>${(f.total_bytes || 1024).toLocaleString()} B</td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="progress flex-grow-1" style="height: 6px; min-width: 60px;">
                                <div class="progress-bar ${isAttack ? 'bg-danger' : 'bg-success'}" style="width: ${f.confidence_percentage}%"></div>
                            </div>
                            <span class="small fw-semibold">${f.confidence_percentage}%</span>
                        </div>
                    </td>
                `;
                tbody.appendChild(row);
            });

        const start = (currentPage - 1) * rowsPerPage + 1;
        const end = Math.min(currentPage * rowsPerPage, result.total);
        document.getElementById('pageInfo').innerText = result.total > 0 
            ? `Mostrando ${start}-${end} de ${result.total.toLocaleString()} flujos`
            : '0 registros encontrados';

        document.getElementById('prevBtn').disabled = currentPage === 1;
        document.getElementById('nextBtn').disabled = end >= result.total;
    } catch (e) {
        console.error('Error cargando tabla de flujos:', e);
    }
}

function applyFilters() {
    currentPage = 1;
    loadFlowTable();
}

function changePage(delta) {
    currentPage += delta;
    loadFlowTable();
}

// Reloj
setInterval(() => {
    document.getElementById('currentTime').textContent = new Date().toLocaleTimeString('es-ES', {
        weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}, 1000);

loadAnalyticsData();