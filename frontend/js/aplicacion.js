(function () {
    'use strict';

    // 1. Estado Global y Gráfica de Throughput en Tiempo Real
    let conteoTotal = 0;
    let conteoBenigno = 0;
    let conteoDDoS = 0;
    let conteoDDoSTCP = 0;
    let conteoDDoSUDP = 0;
    let conteoDDoSICMP = 0;
    let confianzaTotalAcumulada = 0;

    let segundoActualBenigno = 0;
    let segundoActualDDoSTCP = 0;
    let segundoActualDDoSUDP = 0;
    let segundoActualDDoSICMP = 0;

    const elTrafico = document.getElementById('trafficChart');
    if (!elTrafico) return;
    const ctxTrafico = elTrafico.getContext('2d');

    const MAX_PUNTOS = 90;
    const etiquetasIniciales = Array.from({ length: MAX_PUNTOS }, (_, i) => {
        const fecha = new Date(Date.now() - (MAX_PUNTOS - i) * 1000);
        return fecha.toLocaleTimeString();
    });

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

// 2. Gráfica de Distribución Acumulada
const ctxDistribucion = document.getElementById('distributionChart').getContext('2d');
const graficoDistribucion = new Chart(ctxDistribucion, {
    type: 'doughnut',
    data: {
        labels: ['Tráfico Benigno', 'DDoS [TCP]', 'DDoS [UDP]', 'DDoS [ICMP]'],
        datasets: [{
            data: [1, 0, 0, 0],
            backgroundColor: ['#0284c7', '#dc2626', '#ea580c', '#7c3aed'],
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
                        const reales = [conteoBenigno, conteoDDoSTCP, conteoDDoSUDP, conteoDDoSICMP];
                        const valorReal = reales[contexto.dataIndex] ?? 0;
                        const sumaTotal = Math.max(1, conteoBenigno + conteoDDoSTCP + conteoDDoSUDP + conteoDDoSICMP);
                        const pct = ((valorReal / sumaTotal) * 100).toFixed(2);
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

        const estadisticas = await respuestaEstadisticas.json();
        conteoTotal = estadisticas.total || 0;
        conteoBenigno = estadisticas.normal || 0;
        conteoDDoS = estadisticas.ddos || 0;
        if (estadisticas.ddos_by_protocol && typeof estadisticas.ddos_by_protocol === 'object') {
            conteoDDoSTCP = estadisticas.ddos_by_protocol.TCP || 0;
            conteoDDoSUDP = estadisticas.ddos_by_protocol.UDP || 0;
            conteoDDoSICMP = estadisticas.ddos_by_protocol.ICMP || 0;
        } else {
            conteoDDoSTCP = conteoDDoS;
            conteoDDoSUDP = 0;
            conteoDDoSICMP = 0;
        }

        const confianzaPromedio = estadisticas.avg_confidence ?? estadisticas.avg_accuracy;
        if (confianzaPromedio !== null && confianzaPromedio !== undefined) {
            confianzaTotalAcumulada = confianzaPromedio * conteoTotal;
            const elementoPrecision = document.getElementById('kpiAccuracy');
            if (elementoPrecision) {
                elementoPrecision.innerText = `${parseFloat(confianzaPromedio).toFixed(2)}%`;
            }
        }

        if (respuestaModelo && respuestaModelo.ok) {
            const infoModelo = await respuestaModelo.json();
            if (infoModelo.test_metrics) {
                const elementoFPR = document.getElementById('kpiFPR');
                if (elementoFPR && infoModelo.test_metrics.fpr !== undefined) {
                    const valorFPR = (infoModelo.test_metrics.fpr * 100).toFixed(2);
                    elementoFPR.innerText = `${valorFPR}%`;
                    const barraFPR = document.getElementById('fprBar');
                    if (barraFPR) {
                        barraFPR.style.width = `${Math.min(Math.max(parseFloat(valorFPR) * 10, 4), 100)}%`;
                    }
                }
            }
        }

        actualizarKPIs();
        actualizarDistribucion();

        const respuestaHistorial = await fetch('/api/history?limit=10');
        const historial = await respuestaHistorial.json();
        const cuerpoTabla = document.getElementById('eventsTableBody');
        cuerpoTabla.innerHTML = '';

        historial.forEach(elemento => agregarFilaTabla(elemento, false));
    } catch (error) {
        console.error('Error sincronizando con la base de datos:', error);
    }
}

const CLAVE_CACHE_THROUGHPUT = 'cybershield_throughput_90s_v1';

function guardarEstadoGraficoEnCache() {
    try {
        const payload = {
            savedAtMs: Date.now(),
            labels: graficoTrafico.data.labels.slice(-MAX_PUNTOS),
            benign: graficoTrafico.data.datasets[0].data.slice(-MAX_PUNTOS),
            tcp: graficoTrafico.data.datasets[1].data.slice(-MAX_PUNTOS),
            udp: graficoTrafico.data.datasets[2].data.slice(-MAX_PUNTOS),
            icmp: graficoTrafico.data.datasets[3].data.slice(-MAX_PUNTOS)
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
        graficoTrafico.update();
        return true;
    } catch (_) {
        return false;
    }
}

async function sincronizarVentanaTiempoReal() {
    try {
        const resp = await fetch(`/api/telemetry/timeseries?seconds=${MAX_PUNTOS}`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data || !Array.isArray(data.points) || data.points.length === 0) return;

        const puntos = data.points.slice(-MAX_PUNTOS);
        graficoTrafico.data.labels = puntos.map(p => new Date(p.epoch * 1000).toLocaleTimeString());
        graficoTrafico.data.datasets[0].data = puntos.map(p => p.benign || 0);
        graficoTrafico.data.datasets[1].data = puntos.map(p => p.tcp || 0);
        graficoTrafico.data.datasets[2].data = puntos.map(p => p.udp || 0);
        graficoTrafico.data.datasets[3].data = puntos.map(p => p.icmp || 0);
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
setInterval(() => {
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

    graficoTrafico.update();
    guardarEstadoGraficoEnCache();

    segundoActualBenigno = 0;
    segundoActualDDoSTCP = 0;
    segundoActualDDoSUDP = 0;
    segundoActualDDoSICMP = 0;
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

// 5. Conexión WebSocket de Eventos en Tiempo Real
let socketGlobal = null;
let intentosReconexion = 0;
let temporizadorReconexion = null;

function conectarWebSocket() {
    if (temporizadorReconexion) {
        clearTimeout(temporizadorReconexion);
        temporizadorReconexion = null;
    }
    if (socketGlobal && (socketGlobal.readyState === WebSocket.OPEN || socketGlobal.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const protocoloWs = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocoloWs}//${window.location.host}/ws/traffic`);
    socketGlobal = ws;

    ws.onopen = () => {
        intentosReconexion = 0;
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
        try {
            ws.close();
        } catch (_) {}
    };

    ws.onclose = () => {
        if (socketGlobal === ws) {
            socketGlobal = null;
        }
        const baseMs = Math.min(30000, 1000 * Math.pow(2, intentosReconexion));
        const jitterMs = Math.floor(Math.random() * 1000);
        intentosReconexion = Math.min(intentosReconexion + 1, 6);
        temporizadorReconexion = setTimeout(conectarWebSocket, baseMs + jitterMs);
    };
}
conectarWebSocket();

// 6. Control de Modo de Alerta
let modoAlertaActual = 'intimidante';
let contextoAudio = null;
let ultimoSonidoAlerta = 0;
let temporizadorDestelloPerimetral = null;

function cambiarModoAlerta(modo) {
    modoAlertaActual = modo;
    if (window.cambiarModoAlertaGlobal) window.cambiarModoAlertaGlobal(modo);
    const boton = document.getElementById('dropdownAlerta');
    const etiqueta = document.getElementById('labelModoAlerta');

    ['itemAlertaIntimidante', 'itemAlertaRadar', 'itemAlertaSilencio'].forEach(id => {
        const item = document.getElementById(id);
        if (item) item.classList.remove('active');
    });

    if (!contextoAudio) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) contextoAudio = new AudioCtx();
    }
    if (contextoAudio && contextoAudio.state === 'suspended') {
        contextoAudio.resume();
    }

    if (modo === 'intimidante') {
        const item = document.getElementById('itemAlertaIntimidante');
        if (item) item.classList.add('active');
        if (etiqueta) etiqueta.innerText = 'Sirena Táctica + Voz';
        if (boton) {
            boton.className = 'btn btn-sm btn-outline-danger fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
            boton.innerHTML = '<i class="bi bi-megaphone-fill text-danger"></i> <span id="labelModoAlerta">Sirena Táctica + Voz</span>';
        }
    } else if (modo === 'radar') {
        const item = document.getElementById('itemAlertaRadar');
        if (item) item.classList.add('active');
        if (etiqueta) etiqueta.innerText = 'Radar Cibernético';
        if (boton) {
            boton.className = 'btn btn-sm btn-outline-primary fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
            boton.innerHTML = '<i class="bi bi-radar text-primary"></i> <span id="labelModoAlerta">Radar Cibernético</span>';
        }
    } else {
        const item = document.getElementById('itemAlertaSilencio');
        if (item) item.classList.add('active');
        if (etiqueta) etiqueta.innerText = 'Silenciado';
        if (boton) {
            boton.className = 'btn btn-sm btn-outline-secondary fw-semibold px-3 py-2 rounded-pill dropdown-toggle d-flex align-items-center gap-2 shadow-sm';
            boton.innerHTML = '<i class="bi bi-volume-mute-fill text-muted"></i> <span id="labelModoAlerta">Silenciado</span>';
        }
    }
}

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
        return;
    }
}

function obtenerColorBadgeProtocoloAtaque(protocolo) {
    const p = String(protocolo || 'TCP').trim().toUpperCase();
    if (p === 'ICMP') return 'background-color: #7c3aed; color: #ffffff;';
    if (p === 'UDP') return 'background-color: #ea580c; color: #ffffff;';
    return 'background-color: #dc2626; color: #ffffff;';
}

// 7. Procesamiento de Flujos Entrantes y Renderizado de Tabla
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
    const p = String(protocolo || 'TCP').trim().toUpperCase();
    if (p === 'ICMP') {
        segundoActualDDoSICMP += cantidad;
        conteoDDoSICMP += cantidad;
    } else if (p === 'UDP') {
        segundoActualDDoSUDP += cantidad;
        conteoDDoSUDP += cantidad;
    } else {
        segundoActualDDoSTCP += cantidad;
        conteoDDoSTCP += cantidad;
    }
}

function procesarFlujoEntrante(datos) {
    if (!datos) return;

    const elEstadoGlobal = document.getElementById('globalStatus');
    const elTextoEstado = document.getElementById('statusText');
    const elUltimaDeteccion = document.getElementById('lastDetectionTime');

    if (datos.type === 'batch') {
        const totalLote = datos.total || 0;
        const ddosLote = datos.ddos || 0;
        const benignoLote = datos.benign !== undefined ? datos.benign : Math.max(0, totalLote - ddosLote);
        const picosInusuales = datos.unusual_peaks || 0;

        conteoTotal += totalLote;
        conteoDDoS += ddosLote;
        conteoBenigno += benignoLote;
        segundoActualBenigno += benignoLote;

        if (ddosLote > 0) {
            const flujoAtaque = Array.isArray(datos.flows) ? datos.flows.find(f => f && f.is_attack) : null;
            const protoAtaque = String(datos.attack_protocol || (flujoAtaque && flujoAtaque.protocol) || 'TCP').toUpperCase();

            if (datos.ddos_by_protocol && typeof datos.ddos_by_protocol === 'object') {
                const nTcp = datos.ddos_by_protocol.TCP || 0;
                const nUdp = datos.ddos_by_protocol.UDP || 0;
                const nIcmp = datos.ddos_by_protocol.ICMP || 0;
                segundoActualDDoSTCP += nTcp;
                segundoActualDDoSUDP += nUdp;
                segundoActualDDoSICMP += nIcmp;
                conteoDDoSTCP += nTcp;
                conteoDDoSUDP += nUdp;
                conteoDDoSICMP += nIcmp;
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
            reproducirSonidoAlerta(
                `Peligro. El sistema está sufriendo un ataque DDoS por protocolo ${protoAtaque}`,
                protoAtaque
            );
        } else if (picosInusuales > 0) {
            if (elEstadoGlobal) {
                elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                elEstadoGlobal.style.borderColor = '#f59e0b';
            }
            if (elTextoEstado) {
                elTextoEstado.innerText = datos.unusual_label
                    ? `RED ESTABLE • ${datos.unusual_label.toUpperCase()}`
                    : 'RED ESTABLE • TRÁFICO INTENSO (SIN RIESGO)';
            }
        } else if (conteoDDoS === 0 || conteoTotal % 10 === 0) {
            if (elEstadoGlobal) {
                elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                elEstadoGlobal.style.removeProperty('border-color');
            }
            if (elTextoEstado) elTextoEstado.innerText = 'RED SEGURA';
        }

        if (Array.isArray(datos.flows) && datos.flows.length > 0) {
            let sumaMuestra = 0;
            datos.flows.forEach(flujo => {
                const valorConfianza = parseFloat(flujo.confidence_percentage ?? flujo.confidence ?? 99.0);
                sumaMuestra += Number.isFinite(valorConfianza) ? valorConfianza : 99.0;
            });
            const promedioMuestra = sumaMuestra / datos.flows.length;
            const pesoLote = totalLote > 0 ? totalLote : datos.flows.length;
            confianzaTotalAcumulada += promedioMuestra * pesoLote;

            const ultimosFlujos = datos.flows.slice(-MAX_FILAS_TABLA);
            ultimosFlujos.forEach(flujo => encolarFilaTabla(flujo));
        } else if (totalLote > 0) {
            const confFallback = parseFloat(datos.avg_confidence ?? 99.0);
            confianzaTotalAcumulada += (Number.isFinite(confFallback) ? confFallback : 99.0) * totalLote;
        }
    } else {
        conteoTotal++;
        if (datos.is_attack) {
            conteoDDoS++;
            const protoAtaque = String(datos.protocol || 'TCP').toUpperCase();
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
            reproducirSonidoAlerta(`Peligro. El sistema está sufriendo un ataque DDoS por protocolo ${protoAtaque}`, protoAtaque);
        } else {
            conteoBenigno++;
            segundoActualBenigno++;
            if (datos.is_unusual_peak) {
                if (elEstadoGlobal) {
                    elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                    elEstadoGlobal.style.borderColor = '#f59e0b';
                }
                if (elTextoEstado) {
                    elTextoEstado.innerText = datos.status_label
                        ? `RED ESTABLE • ${datos.status_label.toUpperCase()}`
                        : 'RED ESTABLE • TRÁFICO INTENSO (SIN RIESGO)';
                }
            } else if (conteoDDoS === 0 || conteoTotal % 10 === 0) {
                if (elEstadoGlobal) {
                    elEstadoGlobal.className = 'contenedor-estado status-indicator status-safe';
                    elEstadoGlobal.style.removeProperty('border-color');
                }
                if (elTextoEstado) elTextoEstado.innerText = 'RED SEGURA';
            }
        }

        const valorConfianza = parseFloat(datos.confidence_percentage ?? datos.confidence ?? 99.0);
        confianzaTotalAcumulada += Number.isFinite(valorConfianza) ? valorConfianza : 99.0;
        encolarFilaTabla(datos);
    }

    programarRenderizadoUI();
}

function actualizarKPIs() {
    const elTotal = document.getElementById('kpiTotal');
    const elDDoS = document.getElementById('kpiDDoS');
    const elPrecision = document.getElementById('kpiAccuracy');

    if (elTotal) elTotal.innerText = conteoTotal.toLocaleString();
    if (elDDoS) elDDoS.innerText = conteoDDoS.toLocaleString();

    if (elPrecision && conteoTotal > 0 && confianzaTotalAcumulada > 0) {
        const confPromedio = Math.min(100, Math.max(0, confianzaTotalAcumulada / conteoTotal)).toFixed(2);
        elPrecision.innerText = `${confPromedio}%`;
    }
}

function actualizarDistribucion() {
    const baseBenigno = conteoBenigno || 1;
    const pisoVisual = Math.max(1, Math.round(baseBenigno * 0.035));
    const visTCP = conteoDDoSTCP > 0 ? Math.max(conteoDDoSTCP, pisoVisual) : 0;
    const visUDP = conteoDDoSUDP > 0 ? Math.max(conteoDDoSUDP, pisoVisual) : 0;
    const visICMP = conteoDDoSICMP > 0 ? Math.max(conteoDDoSICMP, pisoVisual) : 0;
    graficoDistribucion.data.datasets[0].data = [baseBenigno, visTCP, visUDP, visICMP];
    graficoDistribucion.update();
}

function crearElementoFilaTabla(elemento) {
    if (!elemento) return null;
    const fila = document.createElement('tr');
    const esAtaque = elemento.is_attack || elemento.prediction === 'DDoS' || (typeof elemento.prediction === 'string' && elemento.prediction.startsWith('DDoS'));
    const esPicoInusual = !esAtaque && Boolean(elemento.is_unusual_peak);
    const proto = (elemento.protocol || 'TCP').toUpperCase();
    const horaFormateada = formatearHoraLocal(elemento.timestamp);
    const conf = elemento.confidence_percentage !== undefined ? `${elemento.confidence_percentage}%` : '--';
    const prob = elemento.probability !== undefined ? elemento.probability : (esAtaque ? 0.99 : 0.01);

    const ipOrig = String(elemento.src_ip || '192.168.18.x').trim();
    const ipDest = String(elemento.dst_ip || '10.0.0.x').trim();
    const fuenteRaw = String(elemento.source || 'sensor').toLowerCase();
    const esRfc5737 = ipOrig.startsWith('203.0.113.') || ipOrig.startsWith('198.51.100.') || ipOrig.startsWith('192.0.2.');
    const esLan = ipOrig.startsWith('192.168.') || ipOrig.startsWith('10.') || ipOrig === '127.0.0.1' ||
        (ipOrig.startsWith('172.') && parseInt(ipOrig.split('.')[1] || '0', 10) >= 16 && parseInt(ipOrig.split('.')[1] || '0', 10) <= 31);

    let badgeAlcance = '<span class="badge bg-dark text-white" style="font-size: 0.65rem;">WAN</span>';
    if (fuenteRaw === 'simulation' || esRfc5737) {
        badgeAlcance = '<span class="badge bg-secondary text-white" style="font-size: 0.65rem;">Testbed</span>';
    } else if (esLan) {
        badgeAlcance = '<span class="badge bg-warning text-dark" style="font-size: 0.65rem;">LAN</span>';
    }

    let vectorNombre = 'TCP SYN/ACK Flood';
    if (proto === 'UDP') vectorNombre = 'UDP Volumetric Flood';
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
        <td>
            <span class="fw-semibold">${escaparHtml(conf)}</span>
            <span class="text-muted small ms-1">(p=${escaparHtml(prob)})</span>
        </td>
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

// 8. Simulación Directa y Ráfagas de Tráfico
let intervaloTraficoContinuo = null;

async function simularTrafico(esAtaque, cantidad = 20, protocolo = null) {
    let endpoint = esAtaque ? `/api/simulate/ddos?count=${cantidad}` : `/api/simulate/benign?count=${cantidad}`;
    if (protocolo) {
        endpoint += `&protocol=${encodeURIComponent(protocolo)}`;
    }
    try {
        const respuesta = await fetch(endpoint, { method: 'POST' });
        if (respuesta.ok) {
            if (!socketGlobal || socketGlobal.readyState !== WebSocket.OPEN) {
                const datos = await respuesta.json();
                if (Array.isArray(datos)) {
                    const protoSim = String(protocolo || datos[0]?.protocol || 'TCP').toUpperCase();
                    procesarFlujoEntrante({
                        type: 'batch',
                        total: datos.length,
                        ddos: esAtaque ? datos.length : 0,
                        benign: esAtaque ? 0 : datos.length,
                        attack_protocol: esAtaque ? protoSim : null,
                        ddos_by_protocol: esAtaque ? {
                            TCP: protoSim === 'TCP' ? datos.length : 0,
                            UDP: protoSim === 'UDP' ? datos.length : 0,
                            ICMP: protoSim === 'ICMP' ? datos.length : 0
                        } : { TCP: 0, UDP: 0, ICMP: 0 },
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
        clearInterval(intervaloTraficoContinuo);
        intervaloTraficoContinuo = null;
        if (boton) {
            boton.className = 'btn btn-sm btn-outline-success fw-semibold';
            boton.innerHTML = '<i class="bi bi-play-circle-fill"></i> Tráfico Continuo';
        }
    } else {
        simularTrafico(false, 10);
        intervaloTraficoContinuo = setInterval(() => {
            const aleatorio = Math.floor(Math.random() * 5) + 3;
            simularTrafico(false, aleatorio);
        }, 1000);
        if (boton) {
            boton.className = 'btn btn-sm btn-success text-white fw-semibold';
            boton.innerHTML = '<i class="bi bi-pause-circle-fill"></i> Detener Tráfico';
        }
    }
}

// 9. Reloj y Exportación Global
setInterval(() => {
    const elReloj = document.getElementById('currentTime');
    if (elReloj) {
        elReloj.textContent = new Date().toLocaleTimeString('es-ES', {
            weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }
}, 1000);

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