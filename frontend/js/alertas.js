(function () {
    'use strict';

    // 1. Estado y Utilidades de Formateo
    let paginaActual = 1;
    let nCaracteristicasModelo = 77;
    let temporizadorAvisoSim = null;

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

    function mostrarAvisoSimulacion(mensaje) {
        const aviso = document.getElementById('alertaSimulacionAviso');
        if (!aviso) return;
        aviso.textContent = mensaje;
        aviso.classList.remove('d-none');
        if (temporizadorAvisoSim) clearTimeout(temporizadorAvisoSim);
        temporizadorAvisoSim = setTimeout(() => {
            aviso.classList.add('d-none');
            temporizadorAvisoSim = null;
        }, 5000);
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
        const p = String(protocolo || 'OTHER').trim().toUpperCase();
        if (p === 'ICMP') return '#7c3aed';
        if (p === 'UDP') return '#ea580c';
        if (p === 'TCP') return '#dc2626';
        return '#64748b';
    }

    function obtenerNombrePeriodo(periodo) {
        if (periodo === 'day') return 'Hoy / Último Día (24h)';
        if (periodo === 'week') return 'Última Semana (7 días)';
        if (periodo === 'month') return 'Último Mes (30 días)';
        return 'Todo el Historial';
    }

    // Clasificación del Origen del Atacante (RFC 1918 LAN vs RFC 5737 Testbed vs WAN Pública)
    function clasificarOrigenAtacante(ip, fuente) {
        const ipStr = String(ip || '').trim();
        const srcStr = String(fuente || 'sensor').trim().toLowerCase();

        let canalEtiqueta = 'Sensor en Vivo';
        let canalBadge = 'bg-success bg-opacity-10 text-success border border-success border-opacity-25';
        let canalIcono = 'bi-broadcast';

        if (srcStr === 'simulation') {
            canalEtiqueta = 'Simulador Testbed';
            canalBadge = 'bg-secondary bg-opacity-10 text-secondary border border-secondary border-opacity-25';
            canalIcono = 'bi-flask';
        } else if (srcStr === 'csv_pyme') {
            canalEtiqueta = 'Auditoría CSV';
            canalBadge = 'bg-info bg-opacity-10 text-info border border-info border-opacity-25';
            canalIcono = 'bi-file-earmark-spreadsheet';
        }

        if (!ipStr || ipStr === 'N/D') {
            return {
                alcanceCorto: 'Origen N/D',
                alcanceDetalle: 'Dirección IP de origen no disponible en el registro',
                tipoAmenaza: 'Registro sin dirección IP de origen declarada',
                badgeClase: 'bg-secondary text-white',
                icono: 'bi-question-circle',
                canalEtiqueta,
                canalBadge,
                canalIcono
            };
        }

        const esRfc5737 = ipStr.startsWith('203.0.113.') || ipStr.startsWith('198.51.100.') || ipStr.startsWith('192.0.2.');
        const esLan192 = ipStr.startsWith('192.168.');
        const esLan10 = ipStr.startsWith('10.');
        const octeto2 = ipStr.startsWith('172.') ? parseInt(ipStr.split('.')[1] || '0', 10) : 0;
        const esLan172 = ipStr.startsWith('172.') && octeto2 >= 16 && octeto2 <= 31;
        const esLoopback = ipStr === '127.0.0.1' || ipStr === '::1';

        if (srcStr === 'simulation' || esRfc5737) {
            return {
                alcanceCorto: 'Simulación Académica',
                alcanceDetalle: 'Red de Prueba Documentada (RFC 5737 / Testbed)',
                tipoAmenaza: 'Inyección controlada de laboratorio para validación del modelo Conv1D',
                badgeClase: 'bg-secondary text-white',
                icono: 'bi-cpu',
                canalEtiqueta,
                canalBadge,
                canalIcono
            };
        }

        if (esLan192 || esLan10 || esLan172 || esLoopback) {
            return {
                alcanceCorto: 'Atacante Interno (LAN)',
                alcanceDetalle: 'Red Privada Local (RFC 1918 / Intranet)',
                tipoAmenaza: 'Host interno comprometido, herramienta de estrés en LAN (hping3/LOIC) o movimiento lateral',
                badgeClase: 'bg-warning text-dark',
                icono: 'bi-hdd-network',
                canalEtiqueta,
                canalBadge,
                canalIcono
            };
        }

        return {
            alcanceCorto: 'Atacante Externo (WAN)',
            alcanceDetalle: 'Red Pública de Internet (Enrutamiento Global WAN)',
            tipoAmenaza: 'Nodo externo o botnet DDoS intentando saturar el borde de red desde Internet',
            badgeClase: 'bg-dark text-white',
            icono: 'bi-globe2',
            canalEtiqueta,
            canalBadge,
            canalIcono
        };
    }

    // Taxonomía Técnica del Vector DDoS (Estándares MITRE ATT&CK y NIST SP 800-94)
    function obtenerTaxonomiaVectorDDoS(protocolo, totalBytes, duracionMs) {
        const p = String(protocolo || 'OTHER').trim().toUpperCase();
        const tieneBytes = totalBytes !== null && totalBytes !== undefined && Number.isFinite(Number(totalBytes));
        const tieneDur = duracionMs !== null && duracionMs !== undefined && Number.isFinite(Number(duracionMs));
        const bytesNum = tieneBytes ? Math.max(0, Number(totalBytes)) : null;
        const durNum = tieneDur ? Math.max(0, Number(duracionMs)) : null;

        let kbpsTexto = 'N/D';
        if (bytesNum !== null && durNum !== null) {
            if (durNum > 0) {
                kbpsTexto = ((bytesNum / 1024) / (durNum / 1000)).toFixed(1);
            } else {
                kbpsTexto = bytesNum === 0 ? '0.0' : 'Instantáneo';
            }
        }

        if (p === 'UDP') {
            return {
                vectorCorto: 'UDP Volumetric Flood',
                vectorNombre: 'Inundación Volumétrica UDP (Capa 4)',
                mitreId: 'MITRE ATT&CK T1498.001 / T1498.002',
                mecanismo: 'Envío masivo de datagramas UDP sin estado para saturar el ancho de banda y colapsar los buffers de recepción de la tarjeta de red.',
                recomendacion: 'Aplicar limitación de tasa (Rate-Limiting) en datagramas UDP entrantes o aislar el host emisor mediante el Centro de Mitigación SOAR.',
                kbps: kbpsTexto
            };
        }

        if (p === 'ICMP') {
            return {
                vectorCorto: 'ICMP Ping Flood',
                vectorNombre: 'Inundación de Control ICMP Echo/Flood (Capa 3)',
                mitreId: 'MITRE ATT&CK T1498.001 (Direct Network Flood)',
                mecanismo: 'Ráfaga intensiva de paquetes de control ICMP (Echo Request) diseñada para agotar ciclos de interrupción de CPU y ancho de banda de respuesta.',
                recomendacion: 'Restringir respuestas ICMP Echo en el Firewall de Windows o bloquear temporalmente la IP emisora.',
                kbps: kbpsTexto
            };
        }

        if (p === 'TCP') {
            return {
                vectorCorto: 'TCP SYN/ACK Flood',
                vectorNombre: 'Agotamiento de Estado TCP SYN/ACK Flood (Capa 4)',
                mitreId: 'MITRE ATT&CK T1498.001 (State Exhaustion Flood)',
                mecanismo: 'Inundación de segmentos TCP de apertura/control de alta frecuencia para saturar la tabla de conexiones (Backlog Queue) del sistema operativo.',
                recomendacion: 'Verificar si el origen pertenece a un equipo en la red local (LAN) o botnet externa y aplicar cuarentena temporal de 15 minutos.',
                kbps: kbpsTexto
            };
        }

        return {
            vectorCorto: 'Anomalía Protocolo IP (OTHER)',
            vectorNombre: 'Inundación / Anomalía de Otro Protocolo IP (Capa 3)',
            mitreId: 'MITRE ATT&CK T1498.001 (Direct Network Flood)',
            mecanismo: 'Ráfaga anómala de paquetes IP fuera de TCP/UDP/ICMP (p. ej., GRE, ESP o protocolos de encapsulación) detectada por el clasificador Conv1D.',
            recomendacion: 'Inspeccionar el origen del tráfico en la interfaz de captura y restringir protocolos IP no autorizados en el firewall perimetral.',
            kbps: kbpsTexto
        };
    }

    function formatearVolumenBytes(bytes) {
        if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) return 'N/D';
        const b = Math.max(0, Number(bytes));
        if (b >= 1048576) return `${(b / 1048576).toFixed(2)} MB (${b.toLocaleString()} B)`;
        if (b >= 1024) return `${(b / 1024).toFixed(1)} KB (${b.toLocaleString()} B)`;
        return `${b.toLocaleString()} Bytes`;
    }

    async function cargarMetadatosArquitecturaModelo() {
        try {
            const resp = await fetch('/api/model');
            if (!verificarRespuesta(resp)) return;
            const datos = await resp.json();
            if (datos && Number.isFinite(Number(datos.n_features)) && Number(datos.n_features) > 0) {
                nCaracteristicasModelo = Number(datos.n_features);
            }
        } catch (_) {}
    }

    // 2. Consulta y Renderizado de Alertas
    async function cargarAlertas(pagina = 1) {
        paginaActual = Math.max(1, Number(pagina) || 1);
        const periodo = (document.getElementById('filterPeriod') || {}).value || 'all';
        const severidad = document.getElementById('filterSeverity').value;
        const protocolo = document.getElementById('filterProtocol').value;
        const busquedaIp = document.getElementById('searchIp').value;

        const btnExportar = document.getElementById('btnExportAlertsCsv');
        if (btnExportar) {
            btnExportar.href = `/api/export/csv?prediction=DDoS&period=${encodeURIComponent(periodo)}&protocol=${encodeURIComponent(protocolo)}&severity=${encodeURIComponent(severidad)}&search_ip=${encodeURIComponent(busquedaIp)}`;
        }

        const url = `/api/alerts?page=${paginaActual}&limit=10&period=${encodeURIComponent(periodo)}&severity=${encodeURIComponent(severidad)}&protocol=${encodeURIComponent(protocolo)}&search_ip=${encodeURIComponent(busquedaIp)}`;

        try {
            const respuesta = await fetch(url);
            if (!verificarRespuesta(respuesta)) return;
            const datos = await respuesta.json();
            if (!datos || !datos.kpis) return;

            document.getElementById('kpiTotalAlerts').innerText = Number(datos.kpis.total || 0).toLocaleString();
            document.getElementById('kpiCritical').innerText = Number(datos.kpis.critical || 0).toLocaleString();
            document.getElementById('kpiHigh').innerText = Number(datos.kpis.high || 0).toLocaleString();
            document.getElementById('kpiMedium').innerText = Number(datos.kpis.medium || 0).toLocaleString();

            const cuerpoTabla = document.getElementById('alertsTableBody');
            cuerpoTabla.innerHTML = '';

            const filas = Array.isArray(datos.data) ? datos.data : [];
            if (filas.length === 0) {
                cuerpoTabla.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><i class="bi bi-check2-circle text-success fs-4 d-block mb-1"></i>No se registran alertas de ataques DDoS con los filtros seleccionados (${escaparHtml(obtenerNombrePeriodo(periodo))}).</td></tr>`;
            } else {
                filas.forEach(alerta => {
                    const tieneConf = alerta.confidence_percentage !== null && alerta.confidence_percentage !== undefined && Number.isFinite(Number(alerta.confidence_percentage));
                    const confNum = tieneConf ? Number(alerta.confidence_percentage) : null;
                    let claseBadgeSev = 'bg-info text-dark';
                    let textoSev = 'Media';

                    if (confNum !== null && confNum >= 95.0) {
                        claseBadgeSev = 'bg-danger';
                        textoSev = 'Crítica';
                    } else if (confNum !== null && confNum >= 85.0) {
                        claseBadgeSev = 'bg-warning text-dark';
                        textoSev = 'Alta';
                    }

                    const fechaFormateada = formatearFechaHoraLocal(alerta.timestamp);
                    const ipOrigenRaw = alerta.src_ip ? String(alerta.src_ip).trim() : 'N/D';
                    const ipDestinoRaw = alerta.dst_ip ? String(alerta.dst_ip).trim() : 'N/D';
                    const ipOrigenSegura = escaparHtml(ipOrigenRaw);
                    const ipDestinoSegura = escaparHtml(ipDestinoRaw);
                    const protoRaw = String(alerta.protocol || 'OTHER').toUpperCase();
                    const protoSeguro = escaparHtml(protoRaw);
                    const colorProtocolo = obtenerColorHexProtocolo(protoRaw);

                    const infoOrigen = clasificarOrigenAtacante(ipOrigenRaw, alerta.source);
                    const infoVector = obtenerTaxonomiaVectorDDoS(protoRaw, alerta.total_bytes, alerta.duration_ms);
                    const tieneBytes = alerta.total_bytes !== null && alerta.total_bytes !== undefined && Number.isFinite(Number(alerta.total_bytes));
                    const bytesNum = tieneBytes ? Math.max(0, Number(alerta.total_bytes)) : null;
                    const bytesCorto = bytesNum === null
                        ? 'N/D'
                        : (bytesNum >= 1024 ? `${(bytesNum / 1024).toFixed(1)} KB` : `${bytesNum} B`);
                    const tieneDur = alerta.duration_ms !== null && alerta.duration_ms !== undefined && Number.isFinite(Number(alerta.duration_ms));
                    const durCorto = tieneDur ? `${Math.max(0, Number(alerta.duration_ms)).toFixed(0)} ms` : 'N/D';

                    const fila = document.createElement('tr');
                    fila.innerHTML = `
                        <td class="text-secondary small fw-semibold">${escaparHtml(fechaFormateada)}</td>
                        <td>
                            <div class="d-flex align-items-center gap-2 flex-wrap">
                                <code class="fw-bold" style="color: ${colorProtocolo};">${ipOrigenSegura}</code>
                                <span class="badge ${infoOrigen.badgeClase}" style="font-size: 0.68rem;">
                                    <i class="bi ${infoOrigen.icono} me-1"></i>${escaparHtml(infoOrigen.alcanceCorto)}
                                </span>
                            </div>
                            <div class="mt-1">
                                <span class="badge ${infoOrigen.canalBadge}" style="font-size: 0.65rem;">
                                    <i class="bi ${infoOrigen.canalIcono} me-1"></i>${escaparHtml(infoOrigen.canalEtiqueta)}
                                </span>
                            </div>
                        </td>
                        <td><code class="text-dark">${ipDestinoSegura}</code></td>
                        <td>
                            <div class="d-flex align-items-center gap-1 flex-wrap">
                                <span class="badge px-2 py-1" style="background-color: ${colorProtocolo}; color: #ffffff;">${protoSeguro}</span>
                                <span class="small fw-semibold text-dark">${escaparHtml(infoVector.vectorCorto)}</span>
                            </div>
                            <div class="text-muted" style="font-size: 0.72rem;">
                                Volumen: <strong>${escaparHtml(bytesCorto)}</strong> · Ventana: <strong>${escaparHtml(durCorto)}</strong>
                            </div>
                        </td>
                        <td><span class="badge ${claseBadgeSev}">${escaparHtml(textoSev)}</span></td>
                        <td>
                            <div class="d-flex align-items-center gap-2">
                                <div class="progress flex-grow-1" style="height: 6px; min-width: 50px;">
                                    <div class="progress-bar" style="width: ${confNum !== null ? Math.min(100, Math.max(0, confNum)) : 0}%; background-color: ${colorProtocolo};"></div>
                                </div>
                                <span class="small fw-semibold">${confNum !== null ? `${confNum}%` : 'N/D'}</span>
                            </div>
                        </td>
                        <td>
                            <button type="button" class="btn btn-sm btn-outline-secondary btn-detalle-alerta">
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

            const total = Number(datos.total || 0);
            const pag = Number(datos.page || 1);
            const lim = Number(datos.limit || 10);
            const inicio = total === 0 ? 0 : (pag - 1) * lim + 1;
            const fin = Math.min(pag * lim, total);
            document.getElementById('paginationInfo').innerText = `Mostrando ${inicio}-${fin} de ${total} alertas (${obtenerNombrePeriodo(periodo)})`;

            document.getElementById('prevPageBtn').disabled = pag <= 1;
            document.getElementById('nextPageBtn').disabled = fin >= total;

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

    // 4. Inspección Forense Completa y Simulación
    function abrirModalAccion(alerta, severidad, confianza) {
        const objAlerta = (alerta && typeof alerta === 'object') ? alerta : { src_ip: alerta };
        const idIncidente = objAlerta.id ? `#INC-${objAlerta.id}` : '#INC-VIVO';
        const ipOrigen = objAlerta.src_ip ? String(objAlerta.src_ip).trim() : 'N/D';
        const ipDestino = objAlerta.dst_ip ? String(objAlerta.dst_ip).trim() : 'N/D';
        const protocolo = String(objAlerta.protocol || 'OTHER').toUpperCase();
        const colorProto = obtenerColorHexProtocolo(protocolo);
        const fechaHora = formatearFechaHoraLocal(objAlerta.timestamp);
        const sev = severidad || 'Media';
        const confTexto = (confianza !== null && confianza !== undefined && Number.isFinite(Number(confianza)))
            ? `${Number(confianza)}%`
            : 'N/D';
        const tieneBytes = objAlerta.total_bytes !== null && objAlerta.total_bytes !== undefined && Number.isFinite(Number(objAlerta.total_bytes));
        const tieneDur = objAlerta.duration_ms !== null && objAlerta.duration_ms !== undefined && Number.isFinite(Number(objAlerta.duration_ms));
        const totalBytes = tieneBytes ? Math.max(0, Number(objAlerta.total_bytes)) : null;
        const duracionMs = tieneDur ? Math.max(0, Number(objAlerta.duration_ms)) : null;

        const infoOrigen = clasificarOrigenAtacante(ipOrigen, objAlerta.source);
        const infoVector = obtenerTaxonomiaVectorDDoS(protocolo, totalBytes, duracionMs);
        const tasaTexto = (infoVector.kbps === 'N/D' || infoVector.kbps === 'Instantáneo')
            ? infoVector.kbps
            : `${infoVector.kbps} KB/s`;

        document.getElementById('modalContent').innerHTML = `
            <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3 pb-2 border-bottom">
                <div>
                    <span class="badge bg-danger me-1">Severidad ${escaparHtml(sev)}</span>
                    <span class="badge ${infoOrigen.badgeClase} me-1"><i class="bi ${infoOrigen.icono} me-1"></i>${escaparHtml(infoOrigen.alcanceCorto)}</span>
                    <span class="badge ${infoOrigen.canalBadge}"><i class="bi ${infoOrigen.canalIcono} me-1"></i>${escaparHtml(infoOrigen.canalEtiqueta)}</span>
                </div>
                <div class="small text-muted fw-semibold">
                    Registro Forense: <code>${escaparHtml(idIncidente)}</code> · ${escaparHtml(fechaHora)}
                </div>
            </div>

            <div class="row g-3 mb-3">
                <!-- Columna 1: Identificación del Atacante -->
                <div class="col-md-6">
                    <div class="p-3 rounded h-100 border" style="background-color: rgba(15, 23, 42, 0.03);">
                        <div class="small fw-bold text-uppercase text-secondary mb-2">
                            <i class="bi bi-person-bounding-box me-1 text-danger"></i>1. Identificación del Atacante
                        </div>
                        <div class="small mb-1"><strong>IP Atacante (Origen):</strong> <code class="fs-6 fw-bold" style="color: ${colorProto};">${escaparHtml(ipOrigen)}</code></div>
                        <div class="small mb-1"><strong>IP Víctima (Destino):</strong> <code class="fw-semibold">${escaparHtml(ipDestino)}</code></div>
                        <div class="small mb-1"><strong>Ámbito de Red:</strong> ${escaparHtml(infoOrigen.alcanceDetalle)}</div>
                        <div class="small mb-0 text-muted"><strong>Diagnóstico de Origen:</strong> ${escaparHtml(infoOrigen.tipoAmenaza)}</div>
                    </div>
                </div>

                <!-- Columna 2: Telemetría Volumétrica y Neuronal -->
                <div class="col-md-6">
                    <div class="p-3 rounded h-100 border" style="background-color: rgba(239, 68, 68, 0.05); border-color: ${colorProto} !important;">
                        <div class="small fw-bold text-uppercase text-secondary mb-2">
                            <i class="bi bi-speedometer2 me-1 text-primary"></i>2. Evidencia Volumétrica y Neuronal
                        </div>
                        <div class="small mb-1"><strong>Volumen Capturado:</strong> <code>${escaparHtml(formatearVolumenBytes(totalBytes))}</code></div>
                        <div class="small mb-1"><strong>Duración de Ráfaga:</strong> <code>${duracionMs !== null ? `${duracionMs.toFixed(2)} ms` : 'N/D'}</code></div>
                        <div class="small mb-1"><strong>Tasa de Transferencia:</strong> <code>${escaparHtml(tasaTexto)}</code></div>
                        <div class="small mb-0"><strong>Certeza Red Conv1D:</strong> <span class="fw-bold text-danger">${escaparHtml(confTexto)}</span> (Tensor de ${escaparHtml(nCaracteristicasModelo)} características activas de 80 canónicas CICFlowMeter)</div>
                    </div>
                </div>
            </div>

            <!-- Bloque 3: Taxonomía MITRE ATT&CK y Mecanismo del Ataque -->
            <div class="p-3 rounded border mb-3" style="background-color: rgba(239, 68, 68, 0.06);">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-1 mb-1">
                    <span class="small fw-bold text-uppercase text-danger">
                        <i class="bi bi-diagram-3-fill me-1"></i>3. Clasificación del Vector DDoS: ${escaparHtml(infoVector.vectorNombre)}
                    </span>
                    <span class="badge px-2 py-1" style="background-color: ${colorProto}; color: #ffffff;">
                        Protocolo ${escaparHtml(protocolo)} · ${escaparHtml(infoVector.mitreId)}
                    </span>
                </div>
                <p class="small mb-2 text-secondary">${escaparHtml(infoVector.mecanismo)}</p>
                <div class="small mb-0">
                    <strong><i class="bi bi-shield-check text-success me-1"></i>Acción Recomendada (NIST SP 800-94):</strong>
                    ${escaparHtml(infoVector.recomendacion)}
                </div>
            </div>
        `;
        if (modalAccion) modalAccion.show();
    }

    async function simularAlerta() {
        const protoSel = (document.getElementById('filterProtocol') || {}).value || 'all';
        const protoSimulable = ['TCP', 'UDP', 'ICMP'].includes(protoSel) ? protoSel : null;
        const urlSim = protoSimulable
            ? `/api/simulate/ddos?protocol=${encodeURIComponent(protoSimulable)}`
            : '/api/simulate/ddos';

        try {
            const resp = await fetch(urlSim, { method: 'POST' });
            if (resp.status === 401) {
                verificarRespuesta(resp);
                return;
            }
            if (resp.status === 403) {
                const datos = await resp.json().catch(() => ({}));
                mostrarAvisoSimulacion(datos.detail || 'Simulación deshabilitada en este entorno (ENABLE_SIMULATION=false).');
                if (typeof window.notificarSimulacionDeshabilitada === 'function') {
                    window.notificarSimulacionDeshabilitada();
                }
                return;
            }
            if (!resp.ok) {
                const datos = await resp.json().catch(() => ({}));
                mostrarAvisoSimulacion(datos.detail || `No se pudo ejecutar la simulación (HTTP ${resp.status}).`);
                return;
            }
            await cargarAlertas(1);
        } catch (error) {
            console.error('Error al simular alerta:', error);
            mostrarAvisoSimulacion('Error de conexión con el servidor al intentar inyectar el ataque de prueba.');
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
        window.registrarLimpiezaSesion(() => {
            clearInterval(intervaloReloj);
            if (temporizadorAvisoSim) clearTimeout(temporizadorAvisoSim);
        });
    }

    cargarMetadatosArquitecturaModelo();
    cargarAlertas(1);

    window.obtenerPaginaActualAlertas = () => paginaActual;
    window.abrirModalAccion = abrirModalAccion;
    window.openActionModal = abrirModalAccion;
    window.simularAlerta = simularAlerta;
    window.simulateAlert = simularAlerta;
    window.cargarAlertas = cargarAlertas;
    window.loadAlerts = cargarAlertas;
})();
