(function () {
    'use strict';

    const MAX_HISTORIAL = 20;
    const elRecursos = document.getElementById('resourceChart');
    if (!elRecursos) return;
    const ctxRecursos = elRecursos.getContext('2d');

    function esNumeroValido(valor) {
        return valor !== null && valor !== undefined && valor !== '' && Number.isFinite(Number(valor));
    }

    // 1. Gráfica de Recursos de Hardware (CPU Proceso / Sistema y RAM RSS) — sin puntos iniciales fabricados
    const graficoRecursos = new Chart(ctxRecursos, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'CPU Proceso NIDS (%)',
                    data: [],
                    borderColor: '#0284c7',
                    backgroundColor: 'rgba(2, 132, 199, 0.12)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.25,
                    pointRadius: 0,
                    yAxisID: 'y'
                },
                {
                    label: 'CPU Sistema (%)',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.04)',
                    borderWidth: 1.6,
                    borderDash: [4, 3],
                    fill: false,
                    tension: 0.25,
                    pointRadius: 0,
                    yAxisID: 'y'
                },
                {
                    label: 'RAM Proceso RSS (MB)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.06)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.25,
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
                    title: { display: true, text: 'RAM RSS (MB)', color: '#10b981' },
                    grid: { drawOnChartArea: false }
                }
            },
            plugins: { legend: { position: 'top' } }
        }
    });

    // 2. Gráfica de Latencia de Inferencia Conv1D — inicializada vacía (cero puntos sintéticos de 2.5 ms)
    const ctxLatencia = document.getElementById('latencyChart').getContext('2d');
    const graficoLatencia = new Chart(ctxLatencia, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Latencia Conv1D (ms)',
                data: [],
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.15)',
                borderWidth: 2,
                fill: true,
                tension: 0.25,
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

    function actualizarBadgeEstadoServicio(estado, detalle) {
        const elBadge = document.getElementById('badgeEstadoTelemetria');
        if (!elBadge) return;
        elBadge.textContent = '';
        const icono = document.createElement('i');
        const texto = document.createElement('span');
        if (estado === 'online') {
            icono.className = 'bi bi-hdd-network text-success me-1';
            texto.textContent = detalle || 'API NIDS: En Línea (Sondeo 1 Hz)';
        } else if (estado === 'degraded') {
            icono.className = 'bi bi-exclamation-triangle-fill text-warning me-1';
            texto.textContent = detalle || 'API NIDS: Servicio Degradado';
        } else {
            icono.className = 'bi bi-wifi-off text-danger me-1';
            texto.textContent = detalle || 'API NIDS: Sin Conexión';
        }
        elBadge.append(icono, texto);
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

    // 3. Metadatos del Modelo (/api/model) y Salud (/api/health)
    let saludEnVuelo = false;

    async function cargarMetadatosModelo() {
        try {
            const resp = await fetch('/api/model');
            if (!verificarRespuesta(resp)) return;
            const info = await resp.json();
            const elResumen = document.getElementById('kpiResumenModelo');
            if (elResumen) {
                const nFeat = esNumeroValido(info.n_features) ? Number(info.n_features) : 77;
                const latLote = info.latency && esNumeroValido(info.latency.avg_per_flow_ms)
                    ? `${Number(info.latency.avg_per_flow_ms).toFixed(3)} ms/flujo en lote`
                    : null;
                const acc = info.test_metrics && esNumeroValido(info.test_metrics.accuracy)
                    ? `Exactitud Test: ${(Number(info.test_metrics.accuracy) * 100).toFixed(2)}%`
                    : null;
                const fpr = info.test_metrics && esNumeroValido(info.test_metrics.fpr)
                    ? `FPR: ${(Number(info.test_metrics.fpr) * 100).toFixed(2)}%`
                    : null;
                const partes = [`Conv1D (${nFeat} características activas de 80 canónicas)`];
                if (latLote) partes.push(latLote);
                if (acc) partes.push(acc);
                if (fpr) partes.push(fpr);
                elResumen.textContent = partes.join(' · ');
            }
        } catch (error) {
            console.warn('No se pudieron consultar metadatos del modelo:', error);
        }
    }

    async function verificarSaludServicio() {
        if (saludEnVuelo) return;
        saludEnVuelo = true;
        try {
            const resp = await fetch('/api/health');
            const datos = await resp.json().catch(() => null);
            const elSalud = document.getElementById('kpiEstadoModeloSalud');
            const elIcono = document.getElementById('iconoSaludMotor');

            if (resp.ok && datos && datos.status === 'online') {
                const wsCount = esNumeroValido(datos.active_websockets) ? Number(datos.active_websockets) : 0;
                actualizarBadgeEstadoServicio('online', `API NIDS: En Línea (1 Hz · WS activos: ${wsCount})`);
                if (elSalud) {
                    elSalud.textContent = `Modelo Conv1D cargado · BD SQLite3 operativa · WS activos: ${wsCount}`;
                }
                if (elIcono) elIcono.className = 'bi bi-check-circle-fill fs-2 text-success';
            } else {
                actualizarBadgeEstadoServicio('degraded', 'API NIDS: Servicio Degradado');
                if (elSalud) {
                    const detalleModelo = datos && datos.model_loaded ? 'Modelo OK' : 'Modelo no disponible';
                    const detalleBd = datos && datos.database ? 'BD OK' : 'BD sin conexión';
                    elSalud.textContent = `${detalleModelo} · ${detalleBd}`;
                }
                if (elIcono) elIcono.className = 'bi bi-exclamation-triangle-fill fs-2 text-warning';
            }
        } catch (_) {
            actualizarBadgeEstadoServicio('offline', 'API NIDS: Sin Conexión');
            const elSalud = document.getElementById('kpiEstadoModeloSalud');
            const elIcono = document.getElementById('iconoSaludMotor');
            if (elSalud) elSalud.textContent = 'No se pudo contactar /api/health';
            if (elIcono) elIcono.className = 'bi bi-x-circle-fill fs-2 text-danger';
        } finally {
            saludEnVuelo = false;
        }
    }

    // 4. Sondeo Periódico de Telemetría (1 Hz) con guardia anti-solapamiento
    let sondeoEnVuelo = false;

    async function actualizarTelemetria() {
        if (sondeoEnVuelo) return;
        sondeoEnVuelo = true;
        try {
            const respuesta = await fetch('/api/performance');
            if (!verificarRespuesta(respuesta)) {
                if (respuesta && respuesta.status !== 401) {
                    actualizarBadgeEstadoServicio('degraded', `Telemetría HTTP ${respuesta.status}`);
                }
                return;
            }
            const datos = await respuesta.json();
            if (!datos || typeof datos !== 'object') return;

            const latNum = esNumeroValido(datos.inference_latency_ms) ? Number(datos.inference_latency_ms) : null;
            const e2eNum = esNumeroValido(datos.end_to_end_ms) ? Number(datos.end_to_end_ms) : null;
            const cpuSistemaNum = esNumeroValido(datos.cpu_percent) ? Number(datos.cpu_percent) : null;
            const cpuProcesoNum = esNumeroValido(datos.process_cpu_percent) ? Number(datos.process_cpu_percent) : cpuSistemaNum;
            const ramRssNum = esNumeroValido(datos.ram_mb) ? Number(datos.ram_mb) : null;
            const ramUssNum = esNumeroValido(datos.ram_uss_mb) ? Number(datos.ram_uss_mb) : null;
            const totalRamGbNum = esNumeroValido(datos.total_ram_gb) ? Number(datos.total_ram_gb) : null;
            const fpsNum = esNumeroValido(datos.throughput_fps) ? Number(datos.throughput_fps) : null;
            const gpuNum = esNumeroValido(datos.gpu_usage) ? Number(datos.gpu_usage) : 0;

            const elLatencia = document.getElementById('kpiLatency');
            const elE2E = document.getElementById('kpiEndToEnd');
            const elCpu = document.getElementById('kpiCpu');
            const elCpuBar = document.getElementById('cpuBar');
            const elCpuSistema = document.getElementById('kpiCpuSistema');
            const elRam = document.getElementById('kpiRam');
            const elRamTotal = document.getElementById('kpiRamTotal');
            const elThroughput = document.getElementById('kpiThroughput');
            const elGpu = document.getElementById('kpiGpuUsage');

            if (elLatencia) elLatencia.innerText = latNum !== null ? `${latNum.toFixed(2)} ms` : 'Sin inferencias aún';
            if (elE2E) elE2E.innerText = e2eNum !== null ? `${e2eNum.toFixed(2)} ms` : 'En espera';
            if (elCpu) elCpu.innerText = cpuProcesoNum !== null ? `${cpuProcesoNum.toFixed(1)}%` : '-- %';
            if (elCpuBar) elCpuBar.style.width = `${cpuProcesoNum !== null ? Math.min(Math.max(cpuProcesoNum, 0), 100) : 0}%`;
            if (elCpuSistema) elCpuSistema.innerText = cpuSistemaNum !== null ? `CPU Sistema: ${cpuSistemaNum.toFixed(1)}%` : 'CPU Sistema: -- %';
            if (elRam) elRam.innerText = ramRssNum !== null ? `${ramRssNum.toFixed(1)} MB` : '-- MB';
            if (elRamTotal) {
                const parteUss = ramUssNum !== null ? `USS: ${ramUssNum.toFixed(1)} MB` : 'USS: --';
                const parteTot = totalRamGbNum !== null ? `De ${totalRamGbNum.toFixed(1)} GB` : 'Total: --';
                elRamTotal.innerText = `${parteUss} · ${parteTot}`;
            }
            if (elThroughput) elThroughput.innerText = fpsNum !== null ? `${fpsNum.toFixed(1)} flujos/s` : '-- flujos/s';
            if (elGpu) elGpu.innerText = `${gpuNum}% (CPU-Only)`;

            const ahora = new Date().toLocaleTimeString();

            if (graficoRecursos.data.labels.length >= MAX_HISTORIAL) {
                graficoRecursos.data.labels.shift();
                graficoRecursos.data.datasets[0].data.shift();
                graficoRecursos.data.datasets[1].data.shift();
                graficoRecursos.data.datasets[2].data.shift();
            }
            graficoRecursos.data.labels.push(ahora);
            graficoRecursos.data.datasets[0].data.push(cpuProcesoNum);
            graficoRecursos.data.datasets[1].data.push(cpuSistemaNum);
            graficoRecursos.data.datasets[2].data.push(ramRssNum);
            graficoRecursos.update();

            if (graficoLatencia.data.labels.length >= MAX_HISTORIAL) {
                graficoLatencia.data.labels.shift();
                graficoLatencia.data.datasets[0].data.shift();
            }
            graficoLatencia.data.labels.push(ahora);
            graficoLatencia.data.datasets[0].data.push(latNum);
            graficoLatencia.update();
        } catch (error) {
            console.error('Error obteniendo telemetría:', error);
            actualizarBadgeEstadoServicio('offline', 'API NIDS: Error de Conexión');
        } finally {
            sondeoEnVuelo = false;
        }
    }

    // 5. Reloj, Sondeos y Limpieza de Sesión
    const intervaloReloj = setInterval(() => {
        const elReloj = document.getElementById('currentTime');
        if (elReloj) {
            elReloj.textContent = new Date().toLocaleTimeString('es-ES', {
                weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }
    }, 1000);

    const intervaloTelemetria = setInterval(actualizarTelemetria, 1000);
    const intervaloSalud = setInterval(verificarSaludServicio, 5000);

    if (typeof window.registrarLimpiezaSesion === 'function') {
        window.registrarLimpiezaSesion(() => {
            clearInterval(intervaloReloj);
            clearInterval(intervaloTelemetria);
            clearInterval(intervaloSalud);
        });
    }

    cargarMetadatosModelo();
    verificarSaludServicio();
    actualizarTelemetria();

    window.actualizarTelemetria = actualizarTelemetria;
    window.updateTelemetry = actualizarTelemetria;
    window.graficoRecursos = graficoRecursos;
    window.resourceChart = graficoRecursos;
    window.graficoLatencia = graficoLatencia;
    window.latencyChart = graficoLatencia;
})();
