(function () {
    'use strict';

    // 1. Estado y Utilidades de Formateo
    let paginaActual = 1;

    const elModal = document.getElementById('actionModal');
    const modalAccion = elModal ? new bootstrap.Modal(elModal) : null;

function escaparHtml(valor) {
    return String(valor ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatearFechaHoraLocal(timestamp) {
    if (!timestamp) return '--:--:--';
    try {
        const strIso = (typeof timestamp === 'string' && timestamp.includes('T') && !timestamp.endsWith('Z') && !timestamp.includes('+'))
            ? timestamp + 'Z'
            : timestamp;
        const fecha = new Date(strIso);
        if (isNaN(fecha.getTime())) return String(timestamp).substring(0, 19);
        return fecha.toLocaleString('es-PE', { hour12: false });
    } catch {
        return String(timestamp).substring(0, 19);
    }
}

function obtenerColorHexProtocolo(protocolo) {
    const p = String(protocolo || 'TCP').trim().toUpperCase();
    if (p === 'ICMP') return '#7c3aed';
    if (p === 'UDP') return '#ea580c';
    return '#dc2626';
}

function obtenerNombrePeriodo(periodo) {
    if (periodo === 'day') return 'Hoy / Último Día (24h)';
    if (periodo === 'week') return 'Última Semana (7 días)';
    if (periodo === 'month') return 'Último Mes (30 días)';
    return 'Todo el Historial';
}

// 2. Consulta y Renderizado de Alertas
async function cargarAlertas(pagina = 1) {
    paginaActual = pagina;
    const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
    const severidad = document.getElementById('filterSeverity').value;
    const protocolo = document.getElementById('filterProtocol').value;
    const busquedaIp = document.getElementById('searchIp').value;

    const btnExportar = document.getElementById('btnExportAlertsCsv');
    if (btnExportar) {
        btnExportar.href = `/api/export/csv?prediction=DDoS&period=${encodeURIComponent(periodo)}&protocol=${encodeURIComponent(protocolo)}`;
    }

    const url = `/api/alerts?page=${pagina}&limit=10&period=${encodeURIComponent(periodo)}&severity=${encodeURIComponent(severidad)}&protocol=${encodeURIComponent(protocolo)}&search_ip=${encodeURIComponent(busquedaIp)}`;

    try {
        const respuesta = await fetch(url);
        const datos = await respuesta.json();

        document.getElementById('kpiTotalAlerts').innerText = datos.kpis.total.toLocaleString();
        document.getElementById('kpiCritical').innerText = datos.kpis.critical.toLocaleString();
        document.getElementById('kpiHigh').innerText = datos.kpis.high.toLocaleString();
        document.getElementById('kpiMedium').innerText = datos.kpis.medium.toLocaleString();

        const cuerpoTabla = document.getElementById('alertsTableBody');
        cuerpoTabla.innerHTML = '';

        if (datos.data.length === 0) {
            cuerpoTabla.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><i class="bi bi-check2-circle text-success fs-4 d-block mb-1"></i>No se registran alertas de ataques DDoS con los filtros seleccionados (${escaparHtml(obtenerNombrePeriodo(periodo))}).</td></tr>`;
        } else {
            datos.data.forEach(alerta => {
                const conf = alerta.confidence_percentage;
                let claseBadgeSev = 'bg-info text-dark';
                let textoSev = 'Media';

                if (conf >= 95.0) {
                    claseBadgeSev = 'bg-danger';
                    textoSev = 'Crítica';
                } else if (conf >= 85.0) {
                    claseBadgeSev = 'bg-warning text-dark';
                    textoSev = 'Alta';
                }

                const fechaFormateada = formatearFechaHoraLocal(alerta.timestamp);
                const ipOrigenSegura = escaparHtml(alerta.src_ip || '203.0.113.50');
                const ipDestinoSegura = escaparHtml(alerta.dst_ip || '10.0.0.5');
                const protoRaw = String(alerta.protocol || 'TCP').toUpperCase();
                const protoSeguro = escaparHtml(protoRaw);
                const colorProtocolo = obtenerColorHexProtocolo(protoRaw);
                const confNum = Number.isFinite(Number(conf)) ? Number(conf) : 0;
                const fila = document.createElement('tr');
                fila.innerHTML = `
                    <td class="text-secondary small fw-semibold">${escaparHtml(fechaFormateada)}</td>
                    <td><code class="fw-bold" style="color: ${colorProtocolo};">${ipOrigenSegura}</code></td>
                    <td><code class="text-dark">${ipDestinoSegura}</code></td>
                    <td><span class="badge px-2 py-1" style="background-color: ${colorProtocolo}; color: #ffffff;">${protoSeguro}</span></td>
                    <td><span class="badge ${claseBadgeSev}">${escaparHtml(textoSev)}</span></td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="progress flex-grow-1" style="height: 6px; min-width: 50px;">
                                <div class="progress-bar" style="width: ${Math.min(100, Math.max(0, confNum))}%; background-color: ${colorProtocolo};"></div>
                            </div>
                            <span class="small fw-semibold">${confNum}%</span>
                        </div>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-outline-secondary btn-detalle-alerta">
                            <i class="bi bi-eye"></i> Ver Detalle
                        </button>
                    </td>
                `;
                const btnDetalle = fila.querySelector('.btn-detalle-alerta');
                if (btnDetalle) {
                    btnDetalle.addEventListener('click', () => abrirModalAccion(alerta, textoSev, confNum));
                }
                cuerpoTabla.appendChild(fila);
            });
        }

        const inicio = datos.total === 0 ? 0 : (datos.page - 1) * datos.limit + 1;
        const fin = Math.min(datos.page * datos.limit, datos.total);
        document.getElementById('paginationInfo').innerText = `Mostrando ${inicio}-${fin} de ${datos.total} alertas (${obtenerNombrePeriodo(periodo)})`;

        document.getElementById('prevPageBtn').disabled = datos.page <= 1;
        document.getElementById('nextPageBtn').disabled = fin >= datos.total;

    } catch (error) {
        console.error('Error cargando alertas:', error);
    }
}

// 3. Eventos de Filtrado y Paginación
document.getElementById('applyFiltersBtn').addEventListener('click', () => cargarAlertas(1));
['filterPeriod', 'filterSeverity', 'filterProtocol'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => cargarAlertas(1));
});
const inputBusquedaIp = document.getElementById('searchIp');
if (inputBusquedaIp) {
    inputBusquedaIp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') cargarAlertas(1);
    });
}
document.getElementById('prevPageBtn').addEventListener('click', () => { if (paginaActual > 1) cargarAlertas(paginaActual - 1); });
document.getElementById('nextPageBtn').addEventListener('click', () => cargarAlertas(paginaActual + 1));

// 4. Inspección Forense y Simulación
function abrirModalAccion(alerta, severidad, confianza) {
    const objAlerta = (alerta && typeof alerta === 'object') ? alerta : { src_ip: alerta };
    const ipOrigen = objAlerta.src_ip || '203.0.113.50';
    const ipDestino = objAlerta.dst_ip || '10.0.0.5';
    const protocolo = String(objAlerta.protocol || 'TCP').toUpperCase();
    const colorProto = obtenerColorHexProtocolo(protocolo);
    const fechaHora = formatearFechaHoraLocal(objAlerta.timestamp);
    const sev = severidad || 'Crítica';
    const conf = confianza ?? 99.0;

    document.getElementById('modalContent').innerHTML = `
        <p>Se ha registrado una alerta de intrusión clasificada como <strong>${escaparHtml(sev)}</strong> por la red neuronal <strong>Conv1D</strong> con una confianza del <strong>${escaparHtml(conf)}%</strong>.</p>
        <div class="alert small mb-0" style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid ${colorProto};">
            <div><strong>Fecha y Hora:</strong> ${escaparHtml(fechaHora)}</div>
            <div><strong>IP Atacante:</strong> <code style="color: ${colorProto}; font-weight: 700;">${escaparHtml(ipOrigen)}</code></div>
            <div><strong>IP Destino:</strong> <code>${escaparHtml(ipDestino)}</code></div>
            <div><strong>Protocolo L3/L4:</strong> <span class="badge px-2 py-1" style="background-color: ${colorProto}; color: #ffffff;">${escaparHtml(protocolo)}</span></div>
            <div><strong>Clasificación NIDS:</strong> Ataque DDoS [${escaparHtml(protocolo)}] Detectado</div>
        </div>
    `;
    if (modalAccion) modalAccion.show();
}

async function simularAlerta() {
    const protoSel = (document.getElementById('filterProtocol') || {}).value || 'all';
    const urlSim = protoSel !== 'all' ? `/api/simulate/ddos?protocol=${encodeURIComponent(protoSel)}` : '/api/simulate/ddos';
    await fetch(urlSim, { method: 'POST' });
    cargarAlertas(1);
}

// 5. Reloj e Inicialización
setInterval(() => {
    const elReloj = document.getElementById('currentTime');
    if (elReloj) {
        elReloj.textContent = new Date().toLocaleTimeString('es-ES', {
            weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }
}, 1000);

cargarAlertas(1);

    window.abrirModalAccion = abrirModalAccion;
    window.openActionModal = abrirModalAccion;
    window.simularAlerta = simularAlerta;
    window.simulateAlert = simularAlerta;
    window.cargarAlertas = cargarAlertas;
    window.loadAlerts = cargarAlertas;
})();