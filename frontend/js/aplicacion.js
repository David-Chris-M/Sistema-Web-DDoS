(function () {
    'use strict';

    // 1. Estado Global y Gráfica de Throughput en Tiempo Real
    let conteoTotal = 0;
    let conteoBenigno = 0;
    let conteoDDoS = 0;
    let conteoDDoSTCP = 0;
    let conteoDDoSUDP = 0;
    let conteoDDoSICMP = 0;
    let conteoDDoSOTHER = 0;
    let confianzaTotalAcumulada = 0;
    let flujosConConfianza = 0;

    let segundoActualBenigno = 0;
    let segundoActualDDoSTCP = 0;
    let segundoActualDDoSUDP = 0;
    let segundoActualDDoSICMP = 0;
    let segundoActualDDoSOTHER = 0;

    const elTrafico = document.getElementById('trafficChart');
    if (!elTrafico) return;
    const ctxTrafico = elTrafico.getContext('2d');

    const MAX_PUNTOS = 90;
    const etiquetasIniciales = Array.from({ length: MAX_PUNTOS }, (_, i) => {
        const fecha = new Date(Date.now() - (MAX_PUNTOS - i) * 1000);
        return fecha.toLocaleTimeString();
    });

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

    const graficoTrafico = new Chart(ctxTrafico, {
        type: 'line',
        data: {
            labels: etiquetasIniciales,
            datasets: [
                {
                    label: 'Tráfico Benigno',
                    borderColor: '#0284c7',
                    backgroundColor: 'rgba(2, 132, 199, 0.42)',
                    borderWidth: 1.6,
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    data: Array(MAX_PUNTOS).fill(0)
                },
                {
                    label: 'DDoS [TCP]',
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.50)',
                    borderWidth: 1.6,
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    data: Array(MAX_PUNTOS).fill(0)
                },
                {
                    label: 'DDoS [UDP]',
                    borderColor: '#ea580c',
                    backgroundColor: 'rgba(234, 88, 12, 0.50)',
                    borderWidth: 1.6,
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    data: Array(MAX_PUNTOS).fill(0)
                },
                {
                    label: 'DDoS [ICMP]',
                    borderColor: '#7c3aed',
                    backgroundColor: 'rgba(124, 58, 237, 0.50)',
                    borderWidth: 1.6,
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    data: Array(MAX_PUNTOS).fill(0)
                },
                {
                    label: 'DDoS [OTHER]',
                    borderColor: '#64748b',
                    backgroundColor: 'rgba(100, 116, 139, 0.45)',
                    borderWidth: 1.6,
                    fill: true,
                    tension: 0,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    data: Array(MAX_PUNTOS).fill(0)
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            scales: {
                x: {
                    grid: { color: '#f1f5f9' },
                    ticks: { color: '#64748b', maxTicksLimit: 9, font: { size: 10 } }
                },
                y: {
                    grid: { color: '#f1f5f9' },
                    ticks: { color: '#64748b', font: { size: 10 } },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        boxWidth: 8,
                        boxHeight: 8,
                        padding: 14,
                        font: { size: 11, weight: '600' }
                    }
                }
            }
        }
    });

    // 2. Gráfica de Distribución Acumulada (proporciones reales sin distorsión visual)
    const ctxDistribucion = document.getElementById('distributionChart').getContext('2d');
    const graficoDistribucion = new Chart(ctxDistribucion, {
        type: 'doughnut',
        data: {
            labels: ['Tráfico Benigno', 'DDoS [TCP]', 'DDoS [UDP]', 'DDoS [ICMP]', 'DDoS [OTHER]'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#0284c7', '#dc2626', '#ea580c', '#7c3aed', '#64748b'],
                borderWidth: 1,
                borderColor: 'rgba(255, 255, 255, 0.8)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        boxWidth: 8,
                        boxHeight: 8,
                        padding: 12,
                        font: { size: 11, weight: '600' }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (contexto) {
                            const reales = [conteoBenigno, conteoDDoSTCP, conteoDDoSUDP, conteoDDoSICMP, conteoDDoSOTHER];
                            const valorReal = reales[contexto.dataIndex] ?? 0;
                            const sumaTotal = conteoBenigno + conteoDDoSTCP + conteoDDoSUDP + conteoDDoSICMP + conteoDDoSOTHER;
                            const pct = sumaTotal > 0 ? ((valorReal / sumaTotal) * 100).toFixed(2) : '0.00';
                            return ` ${contexto.label}: ${valorReal.toLocaleString()} flujos (${pct}%)`;
                        }
                    }
                }
            }
        }
    });

    // 3. Sincronización Inicial de Telemetría
    async function cargarDatosIniciales() {
        try {
            const [respuestaEstadisticas, respuestaModelo] = await Promise.all([
                fetch('/api/stats'),
                fetch('/api/model').catch(() => null)
            ]);

            if (verificarRespuesta(respuestaEstadisticas)) {
                const estadisticas = await respuestaEstadisticas.json();
                conteoTotal = Number(estadisticas.total || 0);
                conteoBenigno = Number(estadisticas.normal || 0);
                conteoDDoS = Number(estadisticas.ddos || 0);
                if (estadisticas.ddos_by_protocol && typeof estadisticas.ddos_by_protocol === 'object') {
                    conteoDDoSTCP = Number(estadisticas.ddos_by_protocol.TCP || 0);
                    conteoDDoSUDP = Number(estadisticas.ddos_by_protocol.UDP || 0);
                    conteoDDoSICMP = Number(estadisticas.ddos_by_protocol.ICMP || 0);
                    conteoDDoSOTHER = Number(estadisticas.ddos_by_protocol.OTHER || 0);
                } else {
                    conteoDDoSTCP = 0;
                    conteoDDoSUDP = 0;
                    conteoDDoSICMP = 0;
                    conteoDDoSOTHER = conteoDDoS;
                }

                const confPromRaw = estadisticas.avg_confidence;
                if (conteoTotal > 0 && confPromRaw !== null && confPromRaw !== undefined && Number.isFinite(Number(confPromRaw))) {
                    confianzaTotalAcumulada = Number(confPromRaw) * conteoTotal;
                    flujosConConfianza = conteoTotal;
                } else {
                    confianzaTotalAcumulada = 0;
                    flujosConConfianza = 0;
                }
            }

            if (respuestaModelo && verificarRespuesta(respuestaModelo)) {
                const infoModelo = await respuestaModelo.json();
                const tm = infoModelo && infoModelo.test_metrics ? infoModelo.test_metrics : null;
                const elementoFPR = document.getElementById('kpiFPR');
                const barraFPR = document.getElementById('fprBar');
                const elementoTestAcc = document.getElementById('kpiTestAccuracy');

                if (elementoFPR) {
                    if (tm && Number.isFinite(Number(tm.fpr))) {
                        const valorFPR = (Number(tm.fpr) * 100).toFixed(2);
                        elementoFPR.innerText = `${valorFPR}%`;
                        if (barraFPR) {
                            barraFPR.style.width = `${Math.min(Math.max(parseFloat(valorFPR) * 10, 0), 100)}%`;
                        }
                    } else {
                        elementoFPR.innerText = 'N/D';
                        if (barraFPR) barraFPR.style.width = '0%';
                    }
                }
                if (elementoTestAcc) {
                    if (tm && Number.isFinite(Number(tm.accuracy))) {
                        const accPct = (Number(tm.accuracy) * 100).toFixed(2);
                        elementoTestAcc.textContent = `Exactitud: ${accPct}%`;
                        const recallPct = Number.isFinite(Number(tm.recall)) ? `${(Number(tm.recall) * 100).toFixed(2)}%` : 'N/D';
                        const f1Pct = Number.isFinite(Number(tm.f1_score)) ? `${(Number(tm.f1_score) * 100).toFixed(2)}%` : 'N/D';
                        elementoTestAcc.title = `Evaluación offline Test Conv1D (77 características) — Exactitud: ${accPct}% | Recall: ${recallPct} | F1: ${f1Pct}`;
                    } else {
                        elementoTestAcc.textContent = 'Exactitud: N/D';
                    }
                }
            }

            actualizarKPIs();
            actualizarDistribucion();

            const respuestaHistorial = await fetch('/api/history?limit=10');
            if (!verificarRespuesta(respuestaHistorial)) return;
            const historial = await respuestaHistorial.json();
            const cuerpoTabla = document.getElementById('eventsTableBody');
            if (cuerpoTabla && Array.isArray(historial)) {
                cuerpoTabla.innerHTML = '';
                historial.forEach(elemento => agregarFilaTabla(elemento, false));
            }
        } catch (error) {
            console.error('Error sincronizando con la base de datos:', error);
        }
    }

    const CLAVE_CACHE_THROUGHPUT = 'cybershield_throughput_90s_v2';

    function guardarEstadoGraficoEnCache() {
        try {
            const payload = {
                savedAtMs: Date.now(),
                labels: graficoTrafico.data.labels.slice(-MAX_PUNTOS),
                benign: graficoTrafico.data.datasets[0].data.slice(-MAX_PUNTOS),
                tcp: graficoTrafico.data.datasets[1].data.slice(-MAX_PUNTOS),
                udp: graficoTrafico.data.datasets[2].data.slice(-MAX_PUNTOS),
                icmp: graficoTrafico.data.datasets[3].data.slice(-MAX_PUNTOS),
                other: graficoTrafico.data.datasets[4].data.slice(-MAX_PUNTOS)
            };
            sessionStorage.setItem(CLAVE_CACHE_THROUGHPUT, JSON.stringify(payload));
        } catch (_) {}
    }

    function restaurarEstadoGraficoDesdeCache() {
        try {
            const raw = sessionStorage.getItem(CLAVE_CACHE_THROUGHPUT);
            if (!raw) return false;
            const cache = JSON.parse(raw);
            if (!cache || !Array.isArray(cache.labels) || cache.labels.length !== MAX_PUNTOS) return false;
            if (Date.now() - (cache.savedAtMs || 0) > 120000) return false;
            graficoTrafico.data.labels = cache.labels;
            graficoTrafico.data.datasets[0].data = cache.benign;
            graficoTrafico.data.datasets[1].data = cache.tcp;
            graficoTrafico.data.datasets[2].data = cache.udp;
            graficoTrafico.data.datasets[3].data = cache.icmp;
            graficoTrafico.data.datasets[4].data = Array.isArray(cache.other) && cache.other.length === MAX_PUNTOS
                ? cache.other
                : Array(MAX_PUNTOS).fill(0);
            graficoTrafico.update();
            return true;
        } catch (_) {
            return false;
        }
    }

    async function sincronizarVentanaTiempoReal() {
        try {
            const resp = await fetch(`/api/telemetry/timeseries?seconds=${MAX_PUNTOS}`);
            if (!verificarRespuesta(resp)) return;
            const data = await resp.json();
            if (!data || !Array.isArray(data.points) || data.points.length === 0) return;

            // Normalizar siempre a exactamente MAX_PUNTOS (90) puntos rellenando por la izquierda si llegan menos (P3-09)
            let puntos = data.points.slice(-MAX_PUNTOS);
            if (puntos.length < MAX_PUNTOS) {
                const faltantes = MAX_PUNTOS - puntos.length;
                const primerEpoch = Number(puntos[0]?.epoch || Math.floor(Date.now() / 1000));
                const relleno = Array.from({ length: faltantes }, (_, idx) => ({
                    epoch: primerEpoch - (faltantes - idx),
                    benign: 0,
                    tcp: 0,
                    udp: 0,
                    icmp: 0,
                    other: 0
                }));
                puntos = relleno.concat(puntos);
            }

            graficoTrafico.data.labels = puntos.map(p => new Date(p.epoch * 1000).toLocaleTimeString());
            graficoTrafico.data.datasets[0].data = puntos.map(p => Number(p.benign || 0));
            graficoTrafico.data.datasets[1].data = puntos.map(p => Number(p.tcp || 0));
            graficoTrafico.data.datasets[2].data = puntos.map(p => Number(p.udp || 0));
            graficoTrafico.data.datasets[3].data = puntos.map(p => Number(p.icmp || 0));
            graficoTrafico.data.datasets[4].data = puntos.map(p => Number(p.other || 0));
            graficoTrafico.update();
            guardarEstadoGraficoEnCache();
        } catch (e) {
            console.warn('No se pudo sincronizar el ring buffer de 90s:', e);
        }
    }

    restaurarEstadoGraficoDesdeCache();
    sincronizarVentanaTiempoReal();
    cargarDatosIniciales();

    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            sincronizarVentanaTiempoReal();
        }
    });

    // 4. Temporizador de Tasa de Flujos por Segundo (1 Hz)
    const intervaloThroughput = setInterval(() => {
        const ahora = new Date().toLocaleTimeString();
        graficoTrafico.data.labels.shift();
        graficoTrafico.data.labels.push(ahora);

        graficoTrafico.data.datasets[0].data.shift();
        graficoTrafico.data.datasets[0].data.push(segundoActualBenigno);

        graficoTrafico.data.datasets[1].data.shift();
        graficoTrafico.data.datasets[1].data.push(segundoActualDDoSTCP);

        graficoTrafico.data.datasets[2].data.shift();
        graficoTrafico.data.datasets[2].data.push(segundoActualDDoSUDP);

        graficoTrafico.data.datasets[3].data.shift();
        graficoTrafico.data.datasets[3].data.push(segundoActualDDoSICMP);

        graficoTrafico.data.datasets[4].data.shift();
        graficoTrafico.data.datasets[4].data.push(segundoActualDDoSOTHER);

        graficoTrafico.update();
        guardarEstadoGraficoEnCache();

        segundoActualBenigno = 0;
        segundoActualDDoSTCP = 0;
        segundoActualDDoSUDP = 0;
        segundoActualDDoSICMP = 0;
        segundoActualDDoSOTHER = 0;
    }, 1000);

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
            if (isNaN(fecha.getTime())) return String(timestamp).substring(0, 19);
            return fecha.toLocaleTimeString('es-PE', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        } catch {
            return String(timestamp).substring(0, 19);
        }
    }

    // 5. Conexión WebSocket de Eventos en Tiempo Real + Badge Dinámico (P3-07)
    let socketGlobal = null;
    let intentosReconexion = 0;
    let temporizadorReconexion = null;
    let sesionFinalizada = false;

    function actualizarBadgeWebSocket(estado) {
        const badge = document.getElementById('wsStatusBadge');
        if (!badge) return;
        badge.textContent = '';
        const icono = document.createElement('i');
        const texto = document.createElement('span');

        if (estado === 'conectado') {
            icono.className = 'bi bi-broadcast text-success me-1';
            texto.textContent = 'WebSocket Conectado';
        } else if (estado === 'reconectando') {
            icono.className = 'bi bi-wifi-off text-danger me-1';
            texto.textContent = 'WebSocket Desconectado (Reintentando...)';
        } else if (estado === 'error') {
            icono.className = 'bi bi-exclamation-triangle-fill text-danger me-1';
            texto.textContent = 'Error WebSocket';
        } else if (estado === 'desconectado') {
            icono.className = 'bi bi-slash-circle text-secondary me-1';
            texto.textContent = 'Sesión Cerrada';
        } else {
            icono.className = 'bi bi-broadcast text-warning me-1';
            texto.textContent = 'Conectando WebSocket...';
        }
        badge.append(icono, texto);
    }

    function conectarWebSocket() {
        if (sesionFinalizada) return;
        if (temporizadorReconexion) {
            clearTimeout(temporizadorReconexion);
            temporizadorReconexion = null;
        }
        if (socketGlobal && (socketGlobal.readyState === WebSocket.OPEN || socketGlobal.readyState === WebSocket.CONNECTING)) {
            return;
        }

        actualizarBadgeWebSocket('conectando');
        const protocoloWs = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${protocoloWs}//${window.location.host}/ws/traffic`);
        socketGlobal = ws;

        ws.onopen = () => {
            intentosReconexion = 0;
            actualizarBadgeWebSocket('conectado');
        };

        ws.onmessage = (evento) => {
            try {
                const datos = JSON.parse(evento.data);
                procesarFlujoEntrante(datos);
            } catch (error) {
                console.error('Error parseando mensaje WebSocket:', error);
            }
        };

        ws.onerror = () => {
            actualizarBadgeWebSocket('error');
            try {
                ws.close();
            } catch (_) {}
        };

        ws.onclose = (evento) => {
            if (socketGlobal === ws) {
                socketGlobal = null;
            }
            if (sesionFinalizada || (evento && evento.code === 1008)) {
                actualizarBadgeWebSocket('desconectado');
                if (typeof window.manejarSesionExpirada === 'function') {
                    window.manejarSesionExpirada();
                } else {
                    window.location.replace('/frontend/login.html');
                }
                return;
            }
            actualizarBadgeWebSocket('reconectando');
            const baseMs = Math.min(30000, 1000 * Math.pow(2, intentosReconexion));
            const jitterMs = Math.floor(Math.random() * 1000);
            intentosReconexion = Math.min(intentosReconexion + 1, 6);
            temporizadorReconexion = setTimeout(conectarWebSocket, baseMs + jitterMs);
        };
    }
    conectarWebSocket();

    // 6. Control de Modo de Alerta (P3-03: sincronizado con localStorage y alarma_global.js)
    let modoAlertaActual = localStorage.getItem('cybershield_modo_alerta') || 'intimidante';

    function renderizarBotonModoAlerta(modo) {
        const modoValido = ['intimidante', 'radar', 'silencio'].includes(modo) ? modo : 'intimidante';
        modoAlertaActual = modoValido;

        const boton = document.getElementById('dropdownAlerta');
        ['itemAlertaIntimidante', 'itemAlertaRadar', 'itemAlertaSilencio'].forEach(id => {
            const item = document.getElementById(id);
            if (item) item.classList.remove('active');
        });

        let idActivo = 'itemAlertaIntimidante';
        let claseBtn = 'btn btn-sm btn-outline-danger fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
        let claseIcono = 'bi bi-megaphone-fill text-danger';
        let textoEtiqueta = 'Sirena Táctica + Voz';

        if (modoValido === 'radar') {
            idActivo = 'itemAlertaRadar';
            claseBtn = 'btn btn-sm btn-outline-primary fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
            claseIcono = 'bi bi-radar text-primary';
            textoEtiqueta = 'Radar Cibernético';
        } else if (modoValido === 'silencio') {
            idActivo = 'itemAlertaSilencio';
            claseBtn = 'btn btn-sm btn-outline-secondary fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
            claseIcono = 'bi bi-volume-mute-fill text-muted';
            textoEtiqueta = 'Silenciado';
        }

        const itemActivo = document.getElementById(idActivo);
        if (itemActivo) itemActivo.classList.add('active');

        if (boton) {
            boton.className = claseBtn;
            boton.textContent = '';
            const icono = document.createElement('i');
            icono.className = claseIcono;
            const spanLabel = document.createElement('span');
            spanLabel.id = 'labelModoAlerta';
            spanLabel.textContent = textoEtiqueta;
            boton.append(icono, document.createTextNode(' '), spanLabel);
        }
    }

    function cambiarModoAlerta(modo) {
        const modoValido = typeof window.cambiarModoAlertaGlobal === 'function'
            ? window.cambiarModoAlertaGlobal(modo)
            : (['intimidante', 'radar', 'silencio'].includes(modo) ? modo : 'intimidante');
        if (typeof window.cambiarModoAlertaGlobal !== 'function') {
            try { localStorage.setItem('cybershield_modo_alerta', modoValido); } catch (_) {}
        }
        renderizarBotonModoAlerta(modoValido);
    }

    // Sincronizar texto inicial del botón #dropdownAlerta al cargar index.html
    renderizarBotonModoAlerta(modoAlertaActual);
    window.addEventListener('storage', (evento) => {
        if (!evento.key || evento.key === 'cybershield_modo_alerta') {
            renderizarBotonModoAlerta(localStorage.getItem('cybershield_modo_alerta') || 'intimidante');
        }
    });

    function alternarSonidoAlerta() {
        cambiarModoAlerta(modoAlertaActual === 'silencio' ? 'intimidante' : 'silencio');
    }

    function reproducirSonidoAlerta(motivo, protocolo = 'TCP') {
        if (window.registrarAtaqueGlobal) {
            window.registrarAtaqueGlobal(motivo, protocolo);
            return;
        }
        if (window.reproducirAlarmaGlobal) {
            window.reproducirAlarmaGlobal(motivo, false, protocolo);
        }
    }

    function obtenerColorBadgeProtocoloAtaque(protocolo) {
        const p = String(protocolo || 'OTHER').trim().toUpperCase();
        if (p === 'ICMP') return 'background-color: #7c3aed; color: #ffffff;';
        if (p === 'UDP') return 'background-color: #ea580c; color: #ffffff;';
        if (p === 'TCP') return 'background-color: #dc2626; color: #ffffff;';
        return 'background-color: #475569; color: #ffffff;';
    }

    // 7. Estado de Retorno a RED SEGURA por Inactividad sin Ataques (P3-09)
    let temporizadorRetornoSeguro = null;
    const TIEMPO_RETORNO_SEGURO_MS = 6000;

    function establecerEstadoRedSegura() {
        const elEstadoGlobal = document.getElementById('globalStatus');
        const elTextoEstado = document.getElementById('statusText');
        if (elEstadoGlobal) {
            elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
            elEstadoGlobal.style.removeProperty('border-color');
        }
        if (elTextoEstado) elTextoEstado.innerText = 'RED SEGURA';
    }

    function programarRetornoRedSegura() {
        if (temporizadorRetornoSeguro) clearTimeout(temporizadorRetornoSeguro);
        temporizadorRetornoSeguro = setTimeout(() => {
            temporizadorRetornoSeguro = null;
            establecerEstadoRedSegura();
        }, TIEMPO_RETORNO_SEGURO_MS);
    }

    // 8. Procesamiento de Flujos Entrantes y Renderizado de Tabla
    let actualizacionUIProgramada = false;
    const MAX_FILAS_TABLA = 10;
    let colaFilasPendientes = [];

    function encolarFilaTabla(flujo) {
        if (!flujo) return;
        colaFilasPendientes.push(flujo);
        if (colaFilasPendientes.length > MAX_FILAS_TABLA) {
            colaFilasPendientes.shift();
        }
    }

    function vaciarColaFilasTabla() {
        if (colaFilasPendientes.length === 0) return;
        const cuerpoTabla = document.getElementById('eventsTableBody');
        if (!cuerpoTabla) {
            colaFilasPendientes = [];
            return;
        }

        const fragmento = document.createDocumentFragment();
        for (let i = colaFilasPendientes.length - 1; i >= 0; i--) {
            const fila = crearElementoFilaTabla(colaFilasPendientes[i]);
            if (fila) fragmento.appendChild(fila);
        }
        colaFilasPendientes = [];

        cuerpoTabla.prepend(fragmento);
        while (cuerpoTabla.children.length > MAX_FILAS_TABLA) {
            cuerpoTabla.removeChild(cuerpoTabla.lastChild);
        }
    }

    function programarRenderizadoUI() {
        if (actualizacionUIProgramada) return;
        actualizacionUIProgramada = true;
        requestAnimationFrame(() => {
            vaciarColaFilasTabla();
            actualizarKPIs();
            actualizarDistribucion();
            actualizacionUIProgramada = false;
        });
    }

    function sumarAtaquePorProtocolo(protocolo, cantidad = 1) {
        const p = String(protocolo || 'OTHER').trim().toUpperCase();
        if (p === 'ICMP') {
            segundoActualDDoSICMP += cantidad;
            conteoDDoSICMP += cantidad;
        } else if (p === 'UDP') {
            segundoActualDDoSUDP += cantidad;
            conteoDDoSUDP += cantidad;
        } else if (p === 'TCP') {
            segundoActualDDoSTCP += cantidad;
            conteoDDoSTCP += cantidad;
        } else {
            segundoActualDDoSOTHER += cantidad;
            conteoDDoSOTHER += cantidad;
        }
    }

    function procesarFlujoEntrante(datos) {
        if (!datos) return;

        const elEstadoGlobal = document.getElementById('globalStatus');
        const elTextoEstado = document.getElementById('statusText');
        const elUltimaDeteccion = document.getElementById('lastDetectionTime');

        if (datos.type === 'batch') {
            const totalLote = Number(datos.total || 0);
            const ddosLote = Number(datos.ddos || 0);
            const benignoLote = datos.benign !== undefined ? Number(datos.benign) : Math.max(0, totalLote - ddosLote);
            const picosInusuales = Number(datos.unusual_peaks || 0);

            conteoTotal += totalLote;
            conteoDDoS += ddosLote;
            conteoBenigno += benignoLote;
            segundoActualBenigno += benignoLote;

            if (ddosLote > 0) {
                const flujoAtaque = Array.isArray(datos.flows) ? datos.flows.find(f => f && f.is_attack) : null;
                const protoAtaque = String(datos.attack_protocol || (flujoAtaque && flujoAtaque.protocol) || 'OTHER').toUpperCase();

                if (datos.ddos_by_protocol && typeof datos.ddos_by_protocol === 'object') {
                    const nTcp = Number(datos.ddos_by_protocol.TCP || 0);
                    const nUdp = Number(datos.ddos_by_protocol.UDP || 0);
                    const nIcmp = Number(datos.ddos_by_protocol.ICMP || 0);
                    const nOther = Number(datos.ddos_by_protocol.OTHER || 0);
                    segundoActualDDoSTCP += nTcp;
                    segundoActualDDoSUDP += nUdp;
                    segundoActualDDoSICMP += nIcmp;
                    segundoActualDDoSOTHER += nOther;
                    conteoDDoSTCP += nTcp;
                    conteoDDoSUDP += nUdp;
                    conteoDDoSICMP += nIcmp;
                    conteoDDoSOTHER += nOther;
                } else {
                    sumarAtaquePorProtocolo(protoAtaque, ddosLote);
                }

                if (elEstadoGlobal) {
                    elEstadoGlobal.className = 'contenedor-estado status-indicator status-attack';
                    const tema = window.obtenerTemaProtocoloAtaque ? window.obtenerTemaProtocoloAtaque(protoAtaque) : null;
                    if (tema) {
                        elEstadoGlobal.style.borderColor = tema.colorHex;
                    }
                }
                if (elTextoEstado) elTextoEstado.innerText = `ALERTA [${protoAtaque}]: ${ddosLote} ATAQUES DETECTADOS`;
                if (elUltimaDeteccion) {
                    elUltimaDeteccion.innerHTML = `<i class="bi bi-exclamation-triangle-fill text-danger"></i> <span>Alerta ${escaparHtml(protoAtaque)}: ${escaparHtml(formatearHoraLocal(datos.timestamp))}</span>`;
                }
                programarRetornoRedSegura();
                reproducirSonidoAlerta(
                    `Peligro. El sistema está sufriendo un ataque DDoS por protocolo ${protoAtaque}`,
                    protoAtaque
                );
            } else if (picosInusuales > 0 && !temporizadorRetornoSeguro) {
                if (elEstadoGlobal) {
                    elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                    elEstadoGlobal.style.borderColor = '#f59e0b';
                }
                if (elTextoEstado) {
                    elTextoEstado.innerText = datos.unusual_label
                        ? `RED ESTABLE • ${datos.unusual_label.toUpperCase()}`
                        : 'RED ESTABLE • TRÁFICO INTENSO (SIN RIESGO)';
                }
                programarRetornoRedSegura();
            } else if (!temporizadorRetornoSeguro) {
                establecerEstadoRedSegura();
            }

            // Usar avg_confidence real del lote emitido por el backend (sin respaldos fabricados 99.0%)
            if (totalLote > 0 && datos.avg_confidence !== null && datos.avg_confidence !== undefined && Number.isFinite(Number(datos.avg_confidence))) {
                confianzaTotalAcumulada += Number(datos.avg_confidence) * totalLote;
                flujosConConfianza += totalLote;
            } else if (Array.isArray(datos.flows) && datos.flows.length > 0) {
                let sumaMuestra = 0;
                let nValidos = 0;
                datos.flows.forEach(flujo => {
                    const rawConf = flujo ? (flujo.confidence_percentage ?? flujo.confidence) : null;
                    if (rawConf !== null && rawConf !== undefined && Number.isFinite(Number(rawConf))) {
                        sumaMuestra += Number(rawConf);
                        nValidos += 1;
                    }
                });
                if (nValidos > 0) {
                    confianzaTotalAcumulada += sumaMuestra;
                    flujosConConfianza += nValidos;
                }
            }

            if (Array.isArray(datos.flows) && datos.flows.length > 0) {
                const ultimosFlujos = datos.flows.slice(-MAX_FILAS_TABLA);
                ultimosFlujos.forEach(flujo => encolarFilaTabla(flujo));
            }
        } else {
            conteoTotal++;
            if (datos.is_attack) {
                conteoDDoS++;
                const protoAtaque = String(datos.protocol || 'OTHER').toUpperCase();
                sumarAtaquePorProtocolo(protoAtaque, 1);

                if (elEstadoGlobal) {
                    elEstadoGlobal.className = 'contenedor-estado status-indicator status-attack';
                    const tema = window.obtenerTemaProtocoloAtaque ? window.obtenerTemaProtocoloAtaque(protoAtaque) : null;
                    if (tema) {
                        elEstadoGlobal.style.borderColor = tema.colorHex;
                    }
                }
                if (elTextoEstado) elTextoEstado.innerText = `ALERTA: DDOS [${protoAtaque}] DETECTADO`;
                if (elUltimaDeteccion) {
                    elUltimaDeteccion.innerHTML = `<i class="bi bi-exclamation-triangle-fill text-danger"></i> <span>Alerta ${escaparHtml(protoAtaque)}: ${escaparHtml(formatearHoraLocal(datos.timestamp))}</span>`;
                }
                programarRetornoRedSegura();
                reproducirSonidoAlerta(`Peligro. El sistema está sufriendo un ataque DDoS por protocolo ${protoAtaque}`, protoAtaque);
            } else {
                conteoBenigno++;
                segundoActualBenigno++;
                if (datos.is_unusual_peak && !temporizadorRetornoSeguro) {
                    if (elEstadoGlobal) {
                        elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                        elEstadoGlobal.style.borderColor = '#f59e0b';
                    }
                    if (elTextoEstado) {
                        elTextoEstado.innerText = datos.status_label
                            ? `RED ESTABLE • ${datos.status_label.toUpperCase()}`
                            : 'RED ESTABLE • TRÁFICO INTENSO (SIN RIESGO)';
                    }
                    programarRetornoRedSegura();
                } else if (!temporizadorRetornoSeguro) {
                    establecerEstadoRedSegura();
                }
            }

            const rawConf = datos.confidence_percentage ?? datos.confidence;
            if (rawConf !== null && rawConf !== undefined && Number.isFinite(Number(rawConf))) {
                confianzaTotalAcumulada += Number(rawConf);
                flujosConConfianza += 1;
            }
            encolarFilaTabla(datos);
        }

        programarRenderizadoUI();
    }

    function actualizarKPIs() {
        const elTotal = document.getElementById('kpiTotal');
        const elDDoS = document.getElementById('kpiDDoS');
        const elConfianza = document.getElementById('kpiAccuracy');
        const elSubConf = document.getElementById('kpiConfidenceSub');

        if (elTotal) elTotal.innerText = conteoTotal.toLocaleString();
        if (elDDoS) elDDoS.innerText = conteoDDoS.toLocaleString();

        if (elConfianza) {
            if (flujosConConfianza > 0) {
                const confPromedio = Math.min(100, Math.max(0, confianzaTotalAcumulada / flujosConConfianza)).toFixed(2);
                elConfianza.innerText = `${confPromedio}%`;
                if (elSubConf) {
                    elSubConf.textContent = `Promedio en vivo (${flujosConConfianza.toLocaleString()} flujos)`;
                }
            } else {
                elConfianza.innerText = '--';
                if (elSubConf) {
                    elSubConf.textContent = 'Sin flujos registrados aún';
                }
            }
        }
    }

    function actualizarDistribucion() {
        const totalDist = conteoBenigno + conteoDDoSTCP + conteoDDoSUDP + conteoDDoSICMP + conteoDDoSOTHER;
        const elVacio = document.getElementById('distributionEmptyState');

        if (totalDist <= 0) {
            if (elVacio) elVacio.classList.remove('d-none');
            graficoDistribucion.data.datasets[0].data = [0, 0, 0, 0, 0];
            graficoDistribucion.update();
            return;
        }

        if (elVacio) elVacio.classList.add('d-none');
        graficoDistribucion.data.datasets[0].data = [
            conteoBenigno,
            conteoDDoSTCP,
            conteoDDoSUDP,
            conteoDDoSICMP,
            conteoDDoSOTHER
        ];
        graficoDistribucion.update();
    }

    function crearElementoFilaTabla(elemento) {
        if (!elemento) return null;
        const fila = document.createElement('tr');
        const esAtaque = Boolean(elemento.is_attack) || elemento.prediction === 'DDoS' || (typeof elemento.prediction === 'string' && elemento.prediction.startsWith('DDoS'));
        const esPicoInusual = !esAtaque && Boolean(elemento.is_unusual_peak);
        const proto = String(elemento.protocol || 'OTHER').toUpperCase();
        const horaFormateada = formatearHoraLocal(elemento.timestamp);
        const conf = (elemento.confidence_percentage !== undefined && elemento.confidence_percentage !== null && Number.isFinite(Number(elemento.confidence_percentage)))
            ? `${elemento.confidence_percentage}%`
            : '--';
        const prob = (elemento.probability !== undefined && elemento.probability !== null && Number.isFinite(Number(elemento.probability)))
            ? Number(elemento.probability).toFixed(4)
            : '--';

        const ipOrig = elemento.src_ip ? String(elemento.src_ip).trim() : 'N/D';
        const ipDest = elemento.dst_ip ? String(elemento.dst_ip).trim() : 'N/D';
        const fuenteRaw = String(elemento.source || 'sensor').toLowerCase();
        const esRfc5737 = ipOrig.startsWith('203.0.113.') || ipOrig.startsWith('198.51.100.') || ipOrig.startsWith('192.0.2.');
        const esLan = ipOrig.startsWith('192.168.') || ipOrig.startsWith('10.') || ipOrig === '127.0.0.1' ||
            (ipOrig.startsWith('172.') && parseInt(ipOrig.split('.')[1] || '0', 10) >= 16 && parseInt(ipOrig.split('.')[1] || '0', 10) <= 31);

        let badgeAlcance = '<span class="badge bg-dark text-white" style="font-size: 0.65rem;">WAN</span>';
        if (ipOrig === 'N/D') {
            badgeAlcance = '<span class="badge bg-secondary text-white" style="font-size: 0.65rem;">N/D</span>';
        } else if (fuenteRaw === 'simulation' || esRfc5737) {
            badgeAlcance = '<span class="badge bg-secondary text-white" style="font-size: 0.65rem;">Testbed</span>';
        } else if (esLan) {
            badgeAlcance = '<span class="badge bg-warning text-dark" style="font-size: 0.65rem;">LAN</span>';
        }

        let vectorNombre = 'Anomalía Protocolo IP (OTHER)';
        if (proto === 'TCP') vectorNombre = 'TCP SYN/ACK Flood';
        else if (proto === 'UDP') vectorNombre = 'UDP Volumetric Flood';
        else if (proto === 'ICMP') vectorNombre = 'ICMP Ping Flood';

        let htmlClasificacion;
        let estadoNids;

        if (esAtaque) {
            const estiloBadge = obtenerColorBadgeProtocoloAtaque(proto);
            htmlClasificacion = `<span class="badge px-2 py-1" style="${estiloBadge}">${escaparHtml(`DDoS • ${proto}`)}</span>`;
            estadoNids = `<span class="badge" style="${estiloBadge} opacity: 0.92;"><i class="bi bi-exclamation-octagon-fill me-1"></i>Amenaza ${escaparHtml(vectorNombre)}</span>`;
        } else if (esPicoInusual) {
            htmlClasificacion = `<span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle px-2 py-1">${escaparHtml(`PICO RED • ${proto}`)}</span>`;
            const etiquetaAmigable = elemento.status_label || 'Pico de Red / Tráfico Intenso (Sin riesgo)';
            estadoNids = `<span class="badge bg-info-subtle text-info-emphasis border border-info-subtle"><i class="bi bi-info-circle-fill me-1"></i>${escaparHtml(etiquetaAmigable)}</span>`;
        } else {
            htmlClasificacion = '<span class="badge bg-success px-2 py-1">BENIGN</span>';
            estadoNids = '<span class="badge bg-success-subtle text-success border border-success-subtle"><i class="bi bi-shield-check me-1"></i>Tráfico Seguro</span>';
        }

        fila.innerHTML = `
            <td class="fw-semibold text-secondary">${escaparHtml(horaFormateada)}</td>
            <td>
                <div class="d-flex align-items-center gap-1 flex-wrap">
                    <code class="small fw-semibold">${escaparHtml(ipOrig)}</code>
                    ${badgeAlcance}
                </div>
            </td>
            <td><code class="small text-secondary">${escaparHtml(ipDest)}</code></td>
            <td><span class="badge bg-light text-dark border">${escaparHtml(proto)}</span></td>
            <td>${htmlClasificacion}</td>
            <td>${escaparHtml(conf)}</td>
            <td class="text-muted">${escaparHtml(prob)}</td>
            <td>${estadoNids}</td>
        `;
        return fila;
    }

    function agregarFilaTabla(elemento, anteponer = true) {
        const fila = crearElementoFilaTabla(elemento);
        if (!fila) return;
        const cuerpoTabla = document.getElementById('eventsTableBody');
        if (!cuerpoTabla) return;

        if (anteponer) {
            cuerpoTabla.prepend(fila);
            while (cuerpoTabla.children.length > MAX_FILAS_TABLA) {
                cuerpoTabla.removeChild(cuerpoTabla.lastChild);
            }
        } else {
            cuerpoTabla.appendChild(fila);
        }
    }

    // 9. Simulación Directa y Ráfagas de Tráfico
    let intervaloTraficoContinuo = null;

    function detenerTraficoContinuo() {
        if (intervaloTraficoContinuo) {
            clearInterval(intervaloTraficoContinuo);
            intervaloTraficoContinuo = null;
        }
        const boton = document.getElementById('btnAutoDemo');
        if (boton) {
            boton.className = 'btn btn-sm btn-outline-success fw-semibold w-100 py-2 rounded-pill';
            boton.innerHTML = '<i class="bi bi-play-circle-fill me-1"></i> Activar Tráfico Continuo';
        }
    }

    async function simularTrafico(esAtaque, cantidad = 20, protocolo = null) {
        let endpoint = esAtaque ? `/api/simulate/ddos?count=${cantidad}` : `/api/simulate/benign?count=${cantidad}`;
        if (protocolo) {
            endpoint += `&protocol=${encodeURIComponent(protocolo)}`;
        }
        try {
            const respuesta = await fetch(endpoint, { method: 'POST' });
            if (respuesta.status === 401) {
                verificarRespuesta(respuesta);
                return;
            }
            if (respuesta.status === 403) {
                detenerTraficoContinuo();
                if (typeof window.notificarSimulacionDeshabilitada === 'function') {
                    window.notificarSimulacionDeshabilitada();
                }
                console.warn('Simulación deshabilitada por el servidor (ENABLE_SIMULATION=false).');
                return;
            }
            if (respuesta.ok) {
                if (!socketGlobal || socketGlobal.readyState !== WebSocket.OPEN) {
                    const datos = await respuesta.json();
                    if (Array.isArray(datos)) {
                        const protoSim = String(protocolo || datos[0]?.protocol || 'TCP').toUpperCase();
                        const confs = datos
                            .map(f => Number(f?.confidence_percentage))
                            .filter(v => Number.isFinite(v));
                        const avgConf = confs.length ? (confs.reduce((a, b) => a + b, 0) / confs.length) : null;
                        procesarFlujoEntrante({
                            type: 'batch',
                            total: datos.length,
                            ddos: esAtaque ? datos.length : 0,
                            benign: esAtaque ? 0 : datos.length,
                            avg_confidence: avgConf,
                            attack_protocol: esAtaque ? protoSim : null,
                            ddos_by_protocol: esAtaque ? {
                                TCP: protoSim === 'TCP' ? datos.length : 0,
                                UDP: protoSim === 'UDP' ? datos.length : 0,
                                ICMP: protoSim === 'ICMP' ? datos.length : 0,
                                OTHER: !['TCP', 'UDP', 'ICMP'].includes(protoSim) ? datos.length : 0
                            } : { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
                            flows: datos,
                            timestamp: datos[0]?.timestamp
                        });
                    } else if (datos) {
                        procesarFlujoEntrante(datos);
                    }
                }
            }
        } catch (error) {
            console.error('Error al simular tráfico:', error);
        }
    }

    function alternarModoDemostracion() {
        const boton = document.getElementById('btnAutoDemo');
        if (intervaloTraficoContinuo) {
            detenerTraficoContinuo();
        } else {
            simularTrafico(false, 10);
            intervaloTraficoContinuo = setInterval(() => {
                const aleatorio = Math.floor(Math.random() * 5) + 3;
                simularTrafico(false, aleatorio);
            }, 1000);
            if (boton) {
                boton.className = 'btn btn-sm btn-success text-white fw-semibold w-100 py-2 rounded-pill';
                boton.innerHTML = '<i class="bi bi-pause-circle-fill me-1"></i> Detener Tráfico';
            }
        }
    }

    // 10. Reloj, Limpieza de Sesión y Exportación Global
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
            sesionFinalizada = true;
            clearInterval(intervaloThroughput);
            clearInterval(intervaloReloj);
            detenerTraficoContinuo();
            if (temporizadorReconexion) {
                clearTimeout(temporizadorReconexion);
                temporizadorReconexion = null;
            }
            if (temporizadorRetornoSeguro) {
                clearTimeout(temporizadorRetornoSeguro);
                temporizadorRetornoSeguro = null;
            }
            if (socketGlobal) {
                try {
                    socketGlobal.onclose = null;
                    socketGlobal.close(1000, 'Session ended');
                } catch (_) {}
                socketGlobal = null;
            }
        });
    }

    window.simularTrafico = simularTrafico;
    window.simulateTraffic = simularTrafico;
    window.alternarModoDemostracion = alternarModoDemostracion;
    window.cargarDatosIniciales = cargarDatosIniciales;
    window.loadInitialData = cargarDatosIniciales;
    window.conectarWebSocket = conectarWebSocket;
    window.connectWebSocket = conectarWebSocket;
    window.procesarFlujoEntrante = procesarFlujoEntrante;
    window.processIncomingFlow = procesarFlujoEntrante;
    window.actualizarKPIs = actualizarKPIs;
    window.updateKPIs = actualizarKPIs;
    window.actualizarDistribucion = actualizarDistribucion;
    window.updateDistribution = actualizarDistribucion;
    window.agregarFilaTabla = agregarFilaTabla;
    window.addTableRow = agregarFilaTabla;
    window.graficoTrafico = graficoTrafico;
    window.trafficChart = graficoTrafico;
    window.graficoDistribucion = graficoDistribucion;
    window.distributionChart = graficoDistribucion;
    window.alternarSonidoAlerta = alternarSonidoAlerta;
    window.reproducirSonidoAlerta = reproducirSonidoAlerta;
    window.cambiarModoAlerta = cambiarModoAlerta;
})();
