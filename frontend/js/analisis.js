(function () {
    'use strict';

    // 0. Estado y Utilidades de Formateo
    let paginaActual = 1;
    const filasPorPagina = 10;
    let instanciaGraficoHorario = null;
    let instanciaGraficoProtocolo = null;

function escaparHtml(valor) {
    return String(valor ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatearHoraLocal(timestamp) {
    if (!timestamp) return '--:--:--';
    try {
        const strIso = (typeof timestamp === 'string' && timestamp.includes('T') && !timestamp.endsWith('Z') && !timestamp.includes('+'))
            ? timestamp + 'Z'
            : timestamp;
        const fecha = new Date(strIso);
        if (isNaN(fecha.getTime())) return String(timestamp).substring(11, 19);
        return fecha.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
        return String(timestamp).substring(11, 19);
    }
}

function obtenerNombrePeriodo(periodo) {
    if (periodo === 'day') return 'Hoy / Último Día (24h)';
    if (periodo === 'week') return 'Última Semana (7 días)';
    if (periodo === 'month') return 'Último Mes (30 días)';
    return 'Todo el Historial';
}

function obtenerColorHexProtocolo(protocolo) {
    const p = String(protocolo || 'TCP').trim().toUpperCase();
    if (p === 'ICMP') return '#7c3aed';
    if (p === 'UDP') return '#ea580c';
    return '#dc2626';
}

function actualizarEnlaceExportacionCsv() {
    const btnCsv = document.getElementById('btnExportCsv');
    if (!btnCsv) return;
    const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
    const protocolo = (document.getElementById('filterProtocol') || {}).value || 'all';
    const prediccion = (document.getElementById('filterPrediction') || {}).value || 'all';
    btnCsv.href = `/api/export/csv?period=${encodeURIComponent(periodo)}&protocol=${encodeURIComponent(protocolo)}&prediction=${encodeURIComponent(prediccion)}`;
}

async function cargarDatosAnalisis() {
    actualizarEnlaceExportacionCsv();
    await Promise.all([cargarGraficoHorario(), cargarGraficoProtocolos(), cargarTablaFlujos()]);
}

function obtenerResumenFiltroActivo(esHorario = false) {
    const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
    const protocolo = (document.getElementById('filterProtocol') || {}).value || 'all';
    const prediccion = (document.getElementById('filterPrediction') || {}).value || 'all';
    const partes = [esHorario && periodo === 'all' ? 'Últimas 12h' : obtenerNombrePeriodo(periodo)];
    if (protocolo !== 'all') partes.push(protocolo);
    if (prediccion !== 'all') partes.push(prediccion);
    return partes.join(' • ');
}

// 1. Gráfico de Barras Apiladas por Hora
async function cargarGraficoHorario() {
    try {
        const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
        const protocolo = (document.getElementById('filterProtocol') || {}).value || 'all';
        const prediccion = (document.getElementById('filterPrediction') || {}).value || 'all';

        const badgeHorario = document.getElementById('badgePeriodoHorario');
        if (badgeHorario) {
            badgeHorario.textContent = obtenerResumenFiltroActivo(true);
        }

        const respuesta = await fetch(
            `/api/analysis/traffic-by-hour?period=${encodeURIComponent(periodo)}&protocol=${encodeURIComponent(protocolo)}&prediction=${encodeURIComponent(prediccion)}`
        );
        const datos = await respuesta.json();
        const ctx = document.getElementById('hourlyTrafficChart').getContext('2d');

        if (instanciaGraficoHorario) instanciaGraficoHorario.destroy();

        const colorBarraDdos = protocolo !== 'all' ? obtenerColorHexProtocolo(protocolo) : '#ef4444';

        instanciaGraficoHorario = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: datos.labels,
                datasets: [
                    { label: 'Benigno', data: datos.benign, backgroundColor: '#10b981' },
                    { label: protocolo !== 'all' ? `DDoS (${protocolo})` : 'DDoS', data: datos.attack, backgroundColor: colorBarraDdos }
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
    } catch (error) {
        console.error('Error cargando gráfico horario:', error);
    }
}

// 2. Gráfico de Distribución de Protocolos
async function cargarGraficoProtocolos() {
    try {
        const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
        const protocolo = (document.getElementById('filterProtocol') || {}).value || 'all';
        const prediccion = (document.getElementById('filterPrediction') || {}).value || 'all';
        const badgeProto = document.getElementById('badgePeriodoProtocolos');
        if (badgeProto) {
            badgeProto.textContent = obtenerResumenFiltroActivo(false);
        }

        const respuesta = await fetch(
            `/api/analysis/protocol-distribution?period=${encodeURIComponent(periodo)}&protocol=${encodeURIComponent(protocolo)}&prediction=${encodeURIComponent(prediccion)}`
        );
        const datos = await respuesta.json();
        const ctx = document.getElementById('protocolsPieChart').getContext('2d');

        if (instanciaGraficoProtocolo) instanciaGraficoProtocolo.destroy();

        const etiquetas = Array.isArray(datos.labels) && datos.labels.length > 0 ? datos.labels : ['Sin registros'];
        const conteos = Array.isArray(datos.counts) && datos.counts.length > 0 ? datos.counts : [0];
        const colores = (Array.isArray(datos.labels) && datos.labels.length > 0)
            ? datos.labels.map(proto => obtenerColorHexProtocolo(proto))
            : ['#cbd5e1'];

        instanciaGraficoProtocolo = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: etiquetas,
                datasets: [{
                    data: conteos,
                    backgroundColor: colores,
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
    } catch (error) {
        console.error('Error cargando distribución de protocolos:', error);
    }
}

// 3. Tabla de Flujos Paginada y Filtrada
async function cargarTablaFlujos() {
    const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
    const protocolo = document.getElementById('filterProtocol').value;
    const prediccion = document.getElementById('filterPrediction').value;

    try {
        const respuesta = await fetch(
            `/api/analysis/flows?page=${paginaActual}&limit=${filasPorPagina}&protocol=${encodeURIComponent(protocolo)}&prediction=${encodeURIComponent(prediccion)}&period=${encodeURIComponent(periodo)}`
        );
        const resultado = await respuesta.json();
        const cuerpoTabla = document.getElementById('fullFlowTable');
        cuerpoTabla.innerHTML = '';

        resultado.data.forEach(flujo => {
            const esAtaque = flujo.is_attack;
            const proto = (flujo.protocol || 'TCP').toUpperCase();
            const colorAtaque = obtenerColorHexProtocolo(proto);
            const claseBadge = esAtaque ? 'badge' : 'badge bg-success';
            const estiloBadge = esAtaque ? `background-color: ${colorAtaque}; color: #ffffff;` : '';
            const fila = document.createElement('tr');
            const horaFormateada = formatearHoraLocal(flujo.timestamp);

            const textoPrediccion = esAtaque ? `DDoS • ${proto}` : 'BENIGN';
            const confNum = Number.isFinite(Number(flujo.confidence_percentage)) ? Number(flujo.confidence_percentage) : 0;

            fila.innerHTML = `
                <td class="fw-semibold text-secondary">${escaparHtml(horaFormateada)}</td>
                <td><code class="text-dark">${escaparHtml(flujo.src_ip || '192.168.18.x')}</code></td>
                <td><code class="text-dark">${escaparHtml(flujo.dst_ip || '10.0.0.x')}</code></td>
                <td><span class="badge bg-light text-dark border">${escaparHtml(proto)}</span></td>
                <td><span class="${claseBadge} px-2 py-1" style="${estiloBadge}">${escaparHtml(textoPrediccion)}</span></td>
                <td>${flujo.duration_ms ? Number(flujo.duration_ms).toFixed(1) : '120.0'} ms</td>
                <td>${(Number(flujo.total_bytes) || 1024).toLocaleString()} B</td>
                <td>
                    <div class="d-flex align-items-center gap-2">
                        <div class="progress flex-grow-1" style="height: 6px; min-width: 60px;">
                            <div class="progress-bar ${esAtaque ? '' : 'bg-success'}" style="width: ${Math.min(100, Math.max(0, confNum))}%; ${esAtaque ? `background-color: ${colorAtaque};` : ''}"></div>
                        </div>
                        <span class="small fw-semibold">${confNum}%</span>
                    </div>
                </td>
            `;
            cuerpoTabla.appendChild(fila);
        });

        const inicio = (paginaActual - 1) * filasPorPagina + 1;
        const fin = Math.min(paginaActual * filasPorPagina, resultado.total);
        document.getElementById('pageInfo').innerText = resultado.total > 0 
            ? `Mostrando ${inicio}-${fin} de ${resultado.total.toLocaleString()} flujos (${obtenerNombrePeriodo(periodo)})`
            : `0 registros encontrados (${obtenerNombrePeriodo(periodo)})`;

        document.getElementById('prevBtn').disabled = paginaActual === 1;
        document.getElementById('nextBtn').disabled = fin >= resultado.total;
    } catch (error) {
        console.error('Error cargando tabla de flujos forenses:', error);
    }
}

function aplicarFiltros() {
    paginaActual = 1;
    cargarDatosAnalisis();
}

function cambiarPagina(delta) {
    paginaActual += delta;
    cargarTablaFlujos();
}

// 4. Importación y Evaluación Pasiva de Logs CSV
async function subirLogsCsv() {
    const inputArchivo = document.getElementById('csvFileInput');
    const contenedorResultado = document.getElementById('importResult');
    const botonSubir = document.getElementById('btnUploadCsv');

    if (!inputArchivo.files || inputArchivo.files.length === 0) {
        contenedorResultado.className = 'alert alert-warning small';
        contenedorResultado.innerHTML = '<i class="bi bi-exclamation-circle me-1"></i> Por favor selecciona un archivo CSV.';
        return;
    }

    const archivo = inputArchivo.files[0];
    const datosFormulario = new FormData();
    datosFormulario.append('file', archivo);

    botonSubir.disabled = true;
    botonSubir.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Evaluando con Conv1D...';
    contenedorResultado.className = 'alert alert-info small';
    contenedorResultado.innerHTML = '<i class="bi bi-hourglass-split me-1"></i> Procesando vectores y aplicando anonimización Ley 29733...';

    try {
        const respuesta = await fetch('/api/import/csv', {
            method: 'POST',
            body: datosFormulario
        });

        const datos = await respuesta.json();
        if (respuesta.ok) {
            contenedorResultado.className = 'alert alert-success small';
            contenedorResultado.innerHTML = `
                <strong><i class="bi bi-check-circle-fill me-1"></i> Validación Pasiva Exitosa:</strong><br>
                • <strong>Archivo:</strong> ${escaparHtml(datos.filename)}<br>
                • <strong>Flujos evaluados:</strong> ${Number(datos.processed_flows || 0).toLocaleString()}<br>
                • <strong>Tráfico Benigno:</strong> <span class="text-success fw-bold">${escaparHtml(datos.benign_flows)}</span><br>
                • <strong>Ataques DDoS Detectados:</strong> <span class="text-danger fw-bold">${escaparHtml(datos.ddos_detected)}</span><br>
                • <strong>Anonimización Ley 29733:</strong> Activa (IPs enmascaradas)<br>
                • <strong>Tiempo de Inferencia:</strong> ${escaparHtml(datos.eval_time_ms)} ms
            `;
            await cargarDatosAnalisis();
        } else {
            contenedorResultado.className = 'alert alert-danger small';
            contenedorResultado.innerHTML = `<strong>Error:</strong> ${escaparHtml(datos.detail || 'Fallo al procesar el archivo CSV')}`;
        }
    } catch (error) {
        console.error('Error al subir CSV:', error);
        contenedorResultado.className = 'alert alert-danger small';
        contenedorResultado.innerHTML = '<strong>Error de conexión:</strong> No se pudo conectar con el servidor API.';
    } finally {
        botonSubir.disabled = false;
        botonSubir.innerHTML = '<i class="bi bi-cpu"></i> Evaluar con Conv1D';
    }
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

cargarDatosAnalisis();

    window.cargarDatosAnalisis = cargarDatosAnalisis;
    window.loadAnalyticsData = cargarDatosAnalisis;
    window.cargarGraficoHorario = cargarGraficoHorario;
    window.loadHourlyChart = cargarGraficoHorario;
    window.cargarGraficoProtocolos = cargarGraficoProtocolos;
    window.loadProtocolChart = cargarGraficoProtocolos;
    window.cargarTablaFlujos = cargarTablaFlujos;
    window.loadFlowTable = cargarTablaFlujos;
    window.aplicarFiltros = aplicarFiltros;
    window.applyFilters = aplicarFiltros;
    window.cambiarPagina = cambiarPagina;
    window.changePage = cambiarPagina;
    window.subirLogsCsv = subirLogsCsv;
    window.uploadCsvLogs = subirLogsCsv;
})();