(function () {
    'use strict';

    // 0. Estado y Utilidades de Formateo
    let paginaActual = 1;
    let totalPaginas = 1;
    let tablaEnVuelo = false;
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

    function verificarRespuesta(resp) {
        if (typeof window.verificarRespuestaApi === 'function') {
            return window.verificarRespuestaApi(resp);
        }
        if (resp && resp.status === 401) {
            window.location.replace('/frontend/login.html');
            return false;
        }
        return Boolean(resp && resp.ok);
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
        const p = String(protocolo || 'OTHER').trim().toUpperCase();
        if (p === 'ICMP') return '#7c3aed';
        if (p === 'UDP') return '#ea580c';
        if (p === 'TCP') return '#dc2626';
        return '#64748b';
    }

    function clasificarContextoForense(ip, fuente, protocolo) {
        const ipStr = String(ip || '').trim();
        const srcStr = String(fuente || 'sensor').trim().toLowerCase();
        const p = String(protocolo || 'OTHER').trim().toUpperCase();

        let canalEtiqueta = 'Sensor Vivo';
        let canalClase = 'bg-success bg-opacity-10 text-success border border-success border-opacity-25';
        if (srcStr === 'simulation') {
            canalEtiqueta = 'Simulador';
            canalClase = 'bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25';
        } else if (srcStr === 'csv_pyme') {
            canalEtiqueta = 'Auditoría CSV';
            canalClase = 'bg-info bg-opacity-10 text-info border border-info border-opacity-25';
        }

        const esRfc5737 = ipStr.startsWith('203.0.113.') || ipStr.startsWith('198.51.100.') || ipStr.startsWith('192.0.2.');
        const esLan192 = ipStr.startsWith('192.168.');
        const esLan10 = ipStr.startsWith('10.');
        const oct2 = ipStr.startsWith('172.') ? parseInt(ipStr.split('.')[1] || '0', 10) : 0;
        const esLan172 = ipStr.startsWith('172.') && oct2 >= 16 && oct2 <= 31;
        const esLoopback = ipStr === '127.0.0.1' || ipStr === '::1';

        let alcanceEtiqueta = 'WAN Pública';
        let alcanceClase = 'bg-dark text-white';
        if (!ipStr || ipStr === 'N/D') {
            alcanceEtiqueta = 'N/D';
            alcanceClase = 'bg-secondary text-white';
        } else if (srcStr === 'simulation' || esRfc5737) {
            alcanceEtiqueta = 'Testbed';
            alcanceClase = 'bg-secondary text-white';
        } else if (esLan192 || esLan10 || esLan172 || esLoopback) {
            alcanceEtiqueta = 'LAN Local';
            alcanceClase = 'bg-warning text-dark';
        }

        let vectorAtaque = 'Anomalía Protocolo IP (OTHER)';
        if (p === 'TCP') vectorAtaque = 'TCP SYN/ACK Flood';
        else if (p === 'UDP') vectorAtaque = 'UDP Volumetric Flood';
        else if (p === 'ICMP') vectorAtaque = 'ICMP Ping Flood';

        return { alcanceEtiqueta, alcanceClase, canalEtiqueta, canalClase, vectorAtaque };
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
            if (!verificarRespuesta(respuesta)) return;
            const datos = await respuesta.json();
            const ctx = document.getElementById('hourlyTrafficChart').getContext('2d');

            if (instanciaGraficoHorario) instanciaGraficoHorario.destroy();

            const colorBarraDdos = protocolo !== 'all' ? obtenerColorHexProtocolo(protocolo) : '#ef4444';

            instanciaGraficoHorario = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Array.isArray(datos.labels) ? datos.labels : [],
                    datasets: [
                        { label: 'Benigno', data: Array.isArray(datos.benign) ? datos.benign : [], backgroundColor: '#10b981' },
                        { label: protocolo !== 'all' ? `DDoS (${protocolo})` : 'DDoS', data: Array.isArray(datos.attack) ? datos.attack : [], backgroundColor: colorBarraDdos }
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
            if (!verificarRespuesta(respuesta)) return;
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
        if (tablaEnVuelo) return;
        tablaEnVuelo = true;
        const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
        const protocolo = document.getElementById('filterProtocol').value;
        const prediccion = document.getElementById('filterPrediction').value;
        paginaActual = Math.max(1, paginaActual);

        try {
            const respuesta = await fetch(
                `/api/analysis/flows?page=${paginaActual}&limit=${filasPorPagina}&protocol=${encodeURIComponent(protocolo)}&prediction=${encodeURIComponent(prediccion)}&period=${encodeURIComponent(periodo)}`
            );
            if (!verificarRespuesta(respuesta)) return;
            const resultado = await respuesta.json();
            const cuerpoTabla = document.getElementById('fullFlowTable');
            cuerpoTabla.innerHTML = '';

            const lista = Array.isArray(resultado.data) ? resultado.data : [];
            const totalRegistros = Number.isFinite(Number(resultado.total)) ? Number(resultado.total) : 0;
            totalPaginas = Math.max(1, Math.ceil(totalRegistros / filasPorPagina));
            if (paginaActual > totalPaginas) paginaActual = totalPaginas;

            if (lista.length === 0) {
                cuerpoTabla.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No se encontraron flujos para los filtros seleccionados (${escaparHtml(obtenerNombrePeriodo(periodo))}).</td></tr>`;
            }

            lista.forEach(flujo => {
                const esAtaque = Boolean(flujo.is_attack);
                const proto = String(flujo.protocol || 'OTHER').toUpperCase();
                const colorAtaque = obtenerColorHexProtocolo(proto);
                const claseBadge = esAtaque ? 'badge' : 'badge bg-success';
                const estiloBadge = esAtaque ? `background-color: ${colorAtaque}; color: #ffffff;` : '';
                const fila = document.createElement('tr');
                const horaFormateada = formatearHoraLocal(flujo.timestamp);

                const ipOrigenRaw = flujo.src_ip ? String(flujo.src_ip).trim() : 'N/D';
                const ipDestinoRaw = flujo.dst_ip ? String(flujo.dst_ip).trim() : 'N/D';
                const ctxForense = clasificarContextoForense(ipOrigenRaw, flujo.source, proto);
                const textoPrediccion = esAtaque ? `DDoS • ${ctxForense.vectorAtaque}` : 'BENIGN (Legítimo)';
                const tieneConf = flujo.confidence_percentage !== null && flujo.confidence_percentage !== undefined && Number.isFinite(Number(flujo.confidence_percentage));
                const confNum = tieneConf ? Number(flujo.confidence_percentage) : null;

                // Rigor métrico (P3-06): respetar valores reales 0 sin reemplazar por 1024 B ni 120 ms
                const tieneBytes = flujo.total_bytes !== null && flujo.total_bytes !== undefined && flujo.total_bytes !== '' && Number.isFinite(Number(flujo.total_bytes));
                const bytesVal = tieneBytes ? Math.max(0, Number(flujo.total_bytes)) : null;

                const tieneDur = flujo.duration_ms !== null && flujo.duration_ms !== undefined && flujo.duration_ms !== '' && Number.isFinite(Number(flujo.duration_ms));
                const durVal = tieneDur ? Math.max(0, Number(flujo.duration_ms)) : null;

                const durTexto = durVal !== null ? `${durVal.toFixed(1)} ms` : 'N/D';
                const bytesTexto = bytesVal !== null ? `${bytesVal.toLocaleString()} B` : 'N/D';
                let tasaTexto = 'N/D';
                if (bytesVal !== null && durVal !== null) {
                    if (durVal > 0) {
                        tasaTexto = `${((bytesVal / 1024) / (durVal / 1000)).toFixed(1)} KB/s`;
                    } else {
                        tasaTexto = bytesVal === 0 ? '0.0 KB/s' : 'Instantáneo';
                    }
                }

                fila.innerHTML = `
                    <td class="fw-semibold text-secondary">${escaparHtml(horaFormateada)}</td>
                    <td>
                        <div class="d-flex align-items-center gap-1 flex-wrap">
                            <code class="text-dark fw-semibold">${escaparHtml(ipOrigenRaw)}</code>
                            <span class="badge ${ctxForense.alcanceClase}" style="font-size: 0.65rem;">${escaparHtml(ctxForense.alcanceEtiqueta)}</span>
                        </div>
                    </td>
                    <td><code class="text-dark">${escaparHtml(ipDestinoRaw)}</code></td>
                    <td>
                        <span class="badge bg-light text-dark border me-1">${escaparHtml(proto)}</span>
                        <span class="badge ${ctxForense.canalClase}" style="font-size: 0.65rem;">${escaparHtml(ctxForense.canalEtiqueta)}</span>
                    </td>
                    <td><span class="${claseBadge} px-2 py-1" style="${estiloBadge}">${escaparHtml(textoPrediccion)}</span></td>
                    <td>${escaparHtml(durTexto)}</td>
                    <td>
                        <div>${escaparHtml(bytesTexto)}</div>
                        <div class="text-muted" style="font-size: 0.7rem;">${escaparHtml(tasaTexto)}</div>
                    </td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="progress flex-grow-1" style="height: 6px; min-width: 60px;">
                                <div class="progress-bar ${esAtaque ? '' : 'bg-success'}" style="width: ${confNum !== null ? Math.min(100, Math.max(0, confNum)) : 0}%; ${esAtaque ? `background-color: ${colorAtaque};` : ''}"></div>
                            </div>
                            <span class="small fw-semibold">${confNum !== null ? `${confNum}%` : 'N/D'}</span>
                        </div>
                    </td>
                `;
                cuerpoTabla.appendChild(fila);
            });

            const inicio = totalRegistros > 0 ? (paginaActual - 1) * filasPorPagina + 1 : 0;
            const fin = Math.min(paginaActual * filasPorPagina, totalRegistros);
            document.getElementById('pageInfo').innerText = totalRegistros > 0
                ? `Mostrando ${inicio}-${fin} de ${totalRegistros.toLocaleString()} flujos (${obtenerNombrePeriodo(periodo)})`
                : `0 registros encontrados (${obtenerNombrePeriodo(periodo)})`;

            document.getElementById('prevBtn').disabled = paginaActual <= 1;
            document.getElementById('nextBtn').disabled = fin >= totalRegistros;
        } catch (error) {
            console.error('Error cargando tabla de flujos forenses:', error);
        } finally {
            tablaEnVuelo = false;
        }
    }

    function aplicarFiltros() {
        paginaActual = 1;
        cargarDatosAnalisis();
    }

    function cambiarPagina(delta) {
        if (tablaEnVuelo) return;
        const nuevaPagina = Math.max(1, Math.min(totalPaginas, paginaActual + delta));
        if (nuevaPagina === paginaActual) return;
        paginaActual = nuevaPagina;
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

            if (respuesta.status === 401) {
                verificarRespuesta(respuesta);
                return;
            }

            const datos = await respuesta.json().catch(() => ({}));
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
                const detalleErr = datos.detail || `Fallo HTTP ${respuesta.status} al procesar el archivo CSV`;
                contenedorResultado.className = 'alert alert-danger small';
                contenedorResultado.innerHTML = `<strong>Error:</strong> ${escaparHtml(detalleErr)}`;
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

    // 5. Reloj, Limpieza e Inicialización
    const intervaloReloj = setInterval(() => {
        const elReloj = document.getElementById('currentTime');
        if (elReloj) {
            elReloj.textContent = new Date().toLocaleTimeString('es-ES', {
                weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }
    }, 1000);

    if (typeof window.registrarLimpiezaSesion === 'function') {
        window.registrarLimpiezaSesion(() => clearInterval(intervaloReloj));
    }

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
