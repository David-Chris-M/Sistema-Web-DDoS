let currentPage = 1;
let selectedIpToBlock = '';
const actionModal = new bootstrap.Modal(document.getElementById('actionModal'));

async function loadAlerts(page = 1) {
    currentPage = page;
    const severity = document.getElementById('filterSeverity').value;
    const protocol = document.getElementById('filterProtocol').value;
    const searchIp = document.getElementById('searchIp').value;

    const url = `/api/alerts?page=${page}&limit=10&severity=${severity}&protocol=${protocol}&search_ip=${encodeURIComponent(searchIp)}`;

    try {
        const res = await fetch(url);
        const data = await res.json();

        // Actualizar KPIs
        document.getElementById('kpiTotalAlerts').innerText = data.kpis.total.toLocaleString();
        document.getElementById('kpiCritical').innerText = data.kpis.critical.toLocaleString();
        document.getElementById('kpiHigh').innerText = data.kpis.high.toLocaleString();
        document.getElementById('kpiMedium').innerText = data.kpis.medium.toLocaleString();

        const tbody = document.getElementById('alertsTableBody');
        tbody.innerHTML = '';

        if (data.data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><i class="bi bi-check2-circle text-success fs-4 d-block mb-1"></i>No se registran alertas de ataques DDoS con los filtros seleccionados.</td></tr>`;
        } else {
            data.data.forEach(a => {
                const conf = a.confidence_percentage;
                let sevBadge = 'bg-info text-dark';
                let sevText = 'Media';

                if (conf >= 95.0) {
                    sevBadge = 'bg-danger';
                    sevText = 'Crítica';
                } else if (conf >= 85.0) {
                    sevBadge = 'bg-warning text-dark';
                    sevText = 'Alta';
                }

                const timeStr = a.timestamp ? a.timestamp.replace('T', ' ').substring(0, 19) : '--:--:--';
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="text-secondary small fw-semibold">${timeStr}</td>
                    <td><code class="text-danger fw-bold">${a.src_ip || '203.0.113.50'}</code></td>
                    <td><code class="text-dark">${a.dst_ip || '10.0.0.5'}</code></td>
                    <td><span class="badge bg-light text-dark border">${a.protocol || 'UDP'}</span></td>
                    <td><span class="badge ${sevBadge}">${sevText}</span></td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="progress flex-grow-1" style="height: 6px; min-width: 50px;">
                                <div class="progress-bar bg-danger" style="width: ${conf}%"></div>
                            </div>
                            <span class="small fw-semibold">${conf}%</span>
                        </div>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="openActionModal('${a.src_ip}', '${sevText}', ${conf})">
                            <i class="bi bi-shield-x"></i> Mitigar
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
        }

        // Paginación
        const start = data.total === 0 ? 0 : (data.page - 1) * data.limit + 1;
        const end = Math.min(data.page * data.limit, data.total);
        document.getElementById('paginationInfo').innerText = `Mostrando ${start}-${end} de ${data.total} alertas`;

        document.getElementById('prevPageBtn').disabled = data.page <= 1;
        document.getElementById('nextPageBtn').disabled = end >= data.total;

    } catch (e) {
        console.error('Error cargando alertas:', e);
    }
}

// Botones de paginación y filtros
document.getElementById('applyFiltersBtn').addEventListener('click', () => loadAlerts(1));
document.getElementById('prevPageBtn').addEventListener('click', () => { if (currentPage > 1) loadAlerts(currentPage - 1); });
document.getElementById('nextPageBtn').addEventListener('click', () => loadAlerts(currentPage + 1));

let selectedSeverity = 'Crítica';
let selectedConfidence = 99.0;

function openActionModal(ip, severity, conf) {
    selectedIpToBlock = ip || '203.0.113.50';
    selectedSeverity = severity || 'Crítica';
    selectedConfidence = conf || 99.0;
    document.getElementById('modalContent').innerHTML = `
        <p>Se ha detectado una anomalía clasificada como <strong>${selectedSeverity}</strong> con un nivel de confianza del <strong>${selectedConfidence}%</strong>.</p>
        <div class="alert alert-warning small">
            <strong>IP Sospechosa:</strong> <code>${selectedIpToBlock}</code><br>
            <strong>Acción Defensiva:</strong> Registrar IP en la lista de bloqueo del NIDS y generar regla perimetral.
        </div>
        <p class="small text-muted mb-0">Comando perimetral: <code>iptables -A INPUT -s ${selectedIpToBlock} -j DROP</code></p>
    `;
    actionModal.show();
}

async function executeBlockRule() {
    try {
        const res = await fetch('/api/mitigation/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip: selectedIpToBlock,
                reason: 'Ataque DDoS clasificado por Conv1D',
                severity: selectedSeverity,
                confidence: selectedConfidence
            })
        });
        const data = await res.json();
        alert(`Regla Defensiva Aplicada: ${data.message || 'IP bloqueada en sistema de mitigación'}`);
    } catch (e) {
        console.error('Error aplicando bloqueo:', e);
        alert(`Error al registrar bloqueo de la IP ${selectedIpToBlock}`);
    } finally {
        actionModal.hide();
    }
}

// Simulación de Alerta de prueba
async function simulateAlert() {
    await fetch('/api/simulate/ddos', { method: 'POST' });
    loadAlerts(1);
}

// Reloj
setInterval(() => {
    document.getElementById('currentTime').textContent = new Date().toLocaleTimeString('es-ES', {
        weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
}, 1000);

loadAlerts(1);