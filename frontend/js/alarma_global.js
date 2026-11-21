(function () {
    'use strict';

    // 1. Mapa Cromático de Protocolos de Ataque
    const MAPA_TEMAS_PROTOCOLO = {
        TCP: {
            codigo: 'TCP',
            colorHex: '#dc2626',
            fondoGradiente: 'linear-gradient(135deg, #991b1b, #dc2626)',
            sombraBanner: '0 10px 30px rgba(220, 38, 38, 0.55), 0 0 25px rgba(239, 68, 68, 0.78)',
            glowBajo: 'rgba(239, 68, 68, 0.38)',
            glowAlto: 'rgba(239, 68, 68, 0.82)',
            subtitulo: 'Ataque DDoS [TCP] • Agotamiento de Conexiones / SYN Flood (Capa 4)',
            insigniaEstilo: 'background-color: rgba(220, 38, 38, 0.22); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.55);'
        },
        UDP: {
            codigo: 'UDP',
            colorHex: '#ea580c',
            fondoGradiente: 'linear-gradient(135deg, #9a3412, #ea580c)',
            sombraBanner: '0 10px 30px rgba(234, 88, 12, 0.55), 0 0 25px rgba(249, 115, 22, 0.78)',
            glowBajo: 'rgba(249, 115, 22, 0.38)',
            glowAlto: 'rgba(249, 115, 22, 0.85)',
            subtitulo: 'Ataque DDoS [UDP] • Inundación Volumétrica de Paquetes (UDP Flood)',
            insigniaEstilo: 'background-color: rgba(234, 88, 12, 0.22); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.55);'
        },
        ICMP: {
            codigo: 'ICMP',
            colorHex: '#7c3aed',
            fondoGradiente: 'linear-gradient(135deg, #4c1d95, #7c3aed)',
            sombraBanner: '0 10px 30px rgba(124, 58, 237, 0.55), 0 0 25px rgba(139, 92, 246, 0.80)',
            glowBajo: 'rgba(139, 92, 246, 0.38)',
            glowAlto: 'rgba(139, 92, 246, 0.85)',
            subtitulo: 'Ataque DDoS [ICMP] • Inundación de Diagnóstico / Ping Flood (Capa 3)',
            insigniaEstilo: 'background-color: rgba(124, 58, 237, 0.24); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.58);'
        },
        OTHER: {
            codigo: 'OTHER',
            colorHex: '#475569',
            fondoGradiente: 'linear-gradient(135deg, #334155, #475569)',
            sombraBanner: '0 10px 30px rgba(71, 85, 105, 0.55), 0 0 25px rgba(100, 116, 139, 0.75)',
            glowBajo: 'rgba(100, 116, 139, 0.38)',
            glowAlto: 'rgba(100, 116, 139, 0.80)',
            subtitulo: 'Ataque DDoS [OTHER] • Anomalía Volumétrica en Otro Protocolo IP (Capa 3)',
            insigniaEstilo: 'background-color: rgba(71, 85, 105, 0.24); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.55);'
        }
    };

    function obtenerTemaProtocoloAtaque(protocolo) {
        const clave = String(protocolo || 'TCP').trim().toUpperCase();
        return MAPA_TEMAS_PROTOCOLO[clave] || MAPA_TEMAS_PROTOCOLO.OTHER;
    }

    if (!document.getElementById('estilos-centinela-emergencia')) {
        const estilo = document.createElement('style');
        estilo.id = 'estilos-centinela-emergencia';
        estilo.textContent = `
            :root {
                --color-alerta-glow-bajo: rgba(239, 68, 68, 0.38);
                --color-alerta-glow-alto: rgba(239, 68, 68, 0.82);
            }
            body.alerta-perimetral-activa {
                box-shadow: inset 0 0 80px var(--color-alerta-glow-alto) !important;
                animation: latido-perimetro-global 0.85s infinite alternate ease-in-out !important;
            }
            @keyframes latido-perimetro-global {
                0% { box-shadow: inset 0 0 35px var(--color-alerta-glow-bajo) !important; }
                100% { box-shadow: inset 0 0 95px var(--color-alerta-glow-alto) !important; }
            }
            .banner-alerta-centinela {
                position: fixed;
                top: 18px;
                left: 50%;
                transform: translateX(-50%);
                z-index: 100000;
                background: linear-gradient(135deg, #991b1b, #dc2626);
                color: #ffffff;
                padding: 12px 26px;
                border-radius: 50px;
                box-shadow: 0 10px 30px rgba(220, 38, 38, 0.55), 0 0 25px rgba(239, 68, 68, 0.75);
                display: flex;
                align-items: center;
                gap: 14px;
                font-family: 'Inter', system-ui, -apple-system, sans-serif;
                font-size: 0.90rem;
                font-weight: 700;
                letter-spacing: 0.02em;
                border: 1px solid rgba(255, 255, 255, 0.45);
                backdrop-filter: blur(12px);
                cursor: pointer;
                animation: anim-banner-entrada 0.25s cubic-bezier(0.16, 1, 0.3, 1);
                transition: opacity 0.3s ease, transform 0.3s ease, background 0.25s ease, box-shadow 0.25s ease;
            }
            .banner-alerta-centinela:hover {
                transform: translateX(-50%) scale(1.02);
            }
            @keyframes anim-banner-entrada {
                0% { opacity: 0; transform: translateX(-50%) translateY(-25px) scale(0.95); }
                100% { opacity: 1; transform: translateX(-50%) translateY(0) scale(1); }
            }
            .banner-alerta-icono {
                font-size: 1.35rem;
                animation: anim-icono-alerta 0.8s infinite alternate;
            }
            @keyframes anim-icono-alerta {
                0% { transform: scale(1); }
                100% { transform: scale(1.25); }
            }
            .badge-protocolo-alerta {
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.72rem;
                font-weight: 800;
                background: rgba(255, 255, 255, 0.22);
                border: 1px solid rgba(255, 255, 255, 0.5);
                margin-left: 6px;
                letter-spacing: 0.04em;
            }
            /* --- Tema Gris Descanso Visual (Anti-Fatiga Ocular) --- */
            body.tema-gris {
                background-color: #cbd5e1 !important;
                color: #0f172a !important;
            }
            body.tema-gris .topbar,
            body.tema-gris .kpi-card,
            body.tema-gris .chart-card,
            body.tema-gris .config-card,
            body.tema-gris .card,
            body.tema-gris .card-body,
            body.tema-gris .table-container,
            body.tema-gris .consola-simulacion,
            body.tema-gris .tarjeta-accion-sim,
            body.tema-gris .modal-content {
                --bs-card-bg: #e2e8f0 !important;
                background-color: #e2e8f0 !important;
                border-color: #94a3b8 !important;
                color: #0f172a !important;
            }
            body.tema-gris .table,
            body.tema-gris .table-responsive,
            body.tema-gris table {
                --bs-table-bg: #e2e8f0 !important;
                --bs-table-color: #0f172a !important;
                --bs-table-hover-bg: #cbd5e1 !important;
                --bs-table-hover-color: #0f172a !important;
                --bs-table-striped-bg: #dbe4f0 !important;
                --bs-table-border-color: #94a3b8 !important;
                background-color: #e2e8f0 !important;
                color: #0f172a !important;
                border-color: #94a3b8 !important;
            }
            body.tema-gris thead,
            body.tema-gris .table-light,
            body.tema-gris .table-light th,
            body.tema-gris th {
                --bs-table-bg: #cbd5e1 !important;
                --bs-table-color: #0f172a !important;
                background-color: #cbd5e1 !important;
                color: #0f172a !important;
                border-color: #94a3b8 !important;
            }
            body.tema-gris tbody,
            body.tema-gris tr,
            body.tema-gris td {
                background-color: #e2e8f0 !important;
                color: #0f172a !important;
                border-color: #cbd5e1 !important;
            }
            body.tema-gris tbody tr:hover td {
                background-color: #cbd5e1 !important;
            }
            body.tema-gris .form-select,
            body.tema-gris .form-control,
            body.tema-gris .input-group-text {
                background-color: #f1f5f9 !important;
                border-color: #94a3b8 !important;
                color: #0f172a !important;
            }
            body.tema-gris .page-link {
                background-color: #e2e8f0 !important;
                border-color: #94a3b8 !important;
                color: #0f172a !important;
            }
            /* --- Tema Oscuro SOC (Modo Nocturno de Alto Contraste) --- */
            body.tema-oscuro {
                background-color: #0b1120 !important;
                color: #e2e8f0 !important;
            }
            body.tema-oscuro .topbar,
            body.tema-oscuro .kpi-card,
            body.tema-oscuro .chart-card,
            body.tema-oscuro .config-card,
            body.tema-oscuro .card,
            body.tema-oscuro .card-body,
            body.tema-oscuro .table-container,
            body.tema-oscuro .consola-simulacion,
            body.tema-oscuro .tarjeta-accion-sim,
            body.tema-oscuro .modal-content {
                --bs-card-bg: #1e293b !important;
                background-color: #1e293b !important;
                border-color: #334155 !important;
                color: #f1f5f9 !important;
            }
            body.tema-oscuro .text-dark,
            body.tema-oscuro .setting-label,
            body.tema-oscuro .form-label,
            body.tema-oscuro h4,
            body.tema-oscuro h5,
            body.tema-oscuro h6 {
                color: #f8fafc !important;
            }
            body.tema-oscuro .text-secondary,
            body.tema-oscuro .text-muted,
            body.tema-oscuro .setting-desc,
            body.tema-oscuro .kpi-label {
                color: #94a3b8 !important;
            }
            body.tema-oscuro .bg-light,
            body.tema-oscuro code {
                background-color: #0f172a !important;
                color: #38bdf8 !important;
                border-color: #334155 !important;
            }
            body.tema-oscuro .config-header,
            body.tema-oscuro .setting-item {
                border-color: #334155 !important;
            }
            body.tema-oscuro .table,
            body.tema-oscuro .table-responsive,
            body.tema-oscuro table {
                --bs-table-bg: #1e293b !important;
                --bs-table-color: #e2e8f0 !important;
                --bs-table-hover-bg: #0f172a !important;
                --bs-table-hover-color: #f8fafc !important;
                --bs-table-striped-bg: #162032 !important;
                --bs-table-border-color: #334155 !important;
                background-color: #1e293b !important;
                color: #e2e8f0 !important;
                border-color: #334155 !important;
            }
            body.tema-oscuro thead,
            body.tema-oscuro .table-light,
            body.tema-oscuro .table-light th,
            body.tema-oscuro th {
                --bs-table-bg: #0f172a !important;
                --bs-table-color: #cbd5e1 !important;
                background-color: #0f172a !important;
                color: #cbd5e1 !important;
                border-color: #334155 !important;
            }
            body.tema-oscuro tbody,
            body.tema-oscuro tr,
            body.tema-oscuro td {
                background-color: #1e293b !important;
                color: #e2e8f0 !important;
                border-color: #334155 !important;
            }
            body.tema-oscuro tbody tr:hover td {
                background-color: #0f172a !important;
                color: #f8fafc !important;
            }
            body.tema-oscuro .form-select,
            body.tema-oscuro .form-control,
            body.tema-oscuro .input-group-text {
                background-color: #0f172a !important;
                border-color: #475569 !important;
                color: #f8fafc !important;
            }
            body.tema-oscuro .page-link {
                background-color: #0f172a !important;
                border-color: #334155 !important;
                color: #e2e8f0 !important;
            }
            body.tema-oscuro .page-item.active .page-link {
                background-color: #2563eb !important;
                border-color: #2563eb !important;
                color: #ffffff !important;
            }
        `;
        document.head.appendChild(estilo);
    }

    (function sincronizarTemaInmediato() {
        try {
            const t = localStorage.getItem('cybershield_tema_visual') || 'claro';
            document.documentElement.classList.remove('tema-gris', 'tema-oscuro');
            if (document.body) document.body.classList.remove('tema-gris', 'tema-oscuro');
            if (t === 'gris') {
                document.documentElement.classList.add('tema-gris');
                if (document.body) document.body.classList.add('tema-gris');
            } else if (t === 'oscuro') {
                document.documentElement.classList.add('tema-oscuro');
                if (document.body) document.body.classList.add('tema-oscuro');
            }
        } catch (_) {}
    })();

    // 2. Claves de Almacenamiento y Constantes Operativas
    const CLAVE_STORAGE_ALERTA = 'cybershield_alerta_activa';
    const CLAVE_STORAGE_MODO = 'cybershield_modo_alerta';
    const CLAVE_STORAGE_VOLUMEN = 'cybershield_volumen_alerta';
    const CLAVE_STORAGE_FRASE_TEXTO = 'cybershield_frase_texto';
    const CLAVE_STORAGE_PERFIL_VOZ = 'cybershield_perfil_voz';
    const CLAVE_STORAGE_TONO = 'cybershield_tono_voz';
    const CLAVE_STORAGE_VELOCIDAD = 'cybershield_velocidad_voz';
    const CLAVE_STORAGE_DESTELLO = 'cybershield_destello_activo';
    const CLAVE_STORAGE_BANNER = 'cybershield_banner_activo';
    const CLAVE_STORAGE_ULTIMO_SONIDO = 'cybershield_ultimo_inicio_sonido';
    
    const DURACION_ALARMA_MS = 4800;
    const INTERVALO_CICLO_MS = 5000;
    const RETARDO_ENTRADA_VOZ_MS = 450;
    const VELOCIDAD_VOZ_POR_DEFECTO = '0.95';

    let modoAlerta = localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante';
    let contextoAudio = null;
    let temporizadorDestello = null;
    let temporizadorBanner = null;
    let temporizadorOcultarBanner = null;
    let temporizadorVoz = null;
    let audioActivo = null;
    let urlAudioPrecargado = '';
    let objetoAudioPrecargado = null;
    let cacheAudiosProtocolo = {};
    let cacheAlertaMemoria = null;
    let ultimaEscrituraStorageMs = 0;
    let alertaVisualEstabaActiva = false;
    let ultimoRefrescoAlertasMs = 0;
    let simulacionHabilitadaServidor = true;
    let redirigiendoLogin = false;
    let intervaloCentinelaVisual = null;
    let socketCentinelaActivo = null;
    let intentosReconexionCentinela = 0;
    let temporizadorReconexionCentinela = null;
    const callbacksLimpiezaSesion = [];

    function esPerfilFemenino(perfil) {
        const p = String(perfil || '').toLowerCase();
        return p.includes('camila') || p.includes('dalia') || p.includes('elvira') ||
               p.includes('salome') || p.includes('paloma') || p.startsWith('femenin');
    }

    function obtenerTonoPorDefecto(perfil) {
        return esPerfilFemenino(perfil) ? '1.25' : '0.75';
    }

    function registrarLimpiezaSesion(callback) {
        if (typeof callback === 'function') {
            callbacksLimpiezaSesion.push(callback);
        }
    }

    function limpiarAlmacenamientoSesion() {
        try {
            sessionStorage.clear();
        } catch (_) {}
        [
            CLAVE_STORAGE_ALERTA,
            CLAVE_STORAGE_ULTIMO_SONIDO,
            'cybershield_soar_activo',
            'cybershield_audio_frase'
        ].forEach((clave) => {
            try { localStorage.removeItem(clave); } catch (_) {}
        });
        cacheAlertaMemoria = null;
    }

    function detenerRecursosGlobalesSesion() {
        if (intervaloCentinelaVisual) {
            clearInterval(intervaloCentinelaVisual);
            intervaloCentinelaVisual = null;
        }
        if (temporizadorReconexionCentinela) {
            clearTimeout(temporizadorReconexionCentinela);
            temporizadorReconexionCentinela = null;
        }
        if (temporizadorVoz) {
            clearTimeout(temporizadorVoz);
            temporizadorVoz = null;
        }
        if (temporizadorDestello) {
            clearTimeout(temporizadorDestello);
            temporizadorDestello = null;
        }
        if (temporizadorBanner) {
            clearTimeout(temporizadorBanner);
            temporizadorBanner = null;
        }
        if (temporizadorOcultarBanner) {
            clearTimeout(temporizadorOcultarBanner);
            temporizadorOcultarBanner = null;
        }
        limpiarAudioActivo();
        if (socketCentinelaActivo) {
            try {
                socketCentinelaActivo.onclose = null;
                socketCentinelaActivo.close(1000, 'Session ended');
            } catch (_) {}
            socketCentinelaActivo = null;
        }
        while (callbacksLimpiezaSesion.length > 0) {
            const fn = callbacksLimpiezaSesion.pop();
            try { fn(); } catch (_) {}
        }
    }

    function manejarSesionExpirada() {
        if (redirigiendoLogin) return;
        redirigiendoLogin = true;
        detenerRecursosGlobalesSesion();
        limpiarAlmacenamientoSesion();
        window.location.replace('/frontend/login.html');
    }

    function verificarRespuestaApi(respuesta) {
        if (respuesta && respuesta.status === 401) {
            manejarSesionExpirada();
            return false;
        }
        return Boolean(respuesta && respuesta.ok);
    }

    function cambiarModoAlertaGlobal(modo) {
        const modoValido = ['intimidante', 'radar', 'silencio'].includes(modo) ? modo : 'intimidante';
        modoAlerta = modoValido;
        try {
            localStorage.setItem(CLAVE_STORAGE_MODO, modoValido);
        } catch (_) {}

        if (modoValido !== 'intimidante') {
            if (temporizadorVoz) {
                clearTimeout(temporizadorVoz);
                temporizadorVoz = null;
            }
            limpiarAudioActivo();
            if ('speechSynthesis' in window) {
                try { window.speechSynthesis.cancel(); } catch (_) {}
            }
        } else {
            precargarAudioVozActual();
        }
        return modoValido;
    }

    function formatearFraseConProtocolo(fraseBase, protocolo) {
        const texto = (fraseBase || 'Peligro. El sistema está sufriendo un ataque.').trim();
        const proto = String(protocolo || '').trim().toUpperCase();
        const etiquetaProto = ['TCP', 'UDP', 'ICMP'].includes(proto)
            ? proto
            : (proto === 'OTHER' ? 'otro protocolo IP' : 'TCP');
        if (/\{PROTO(?:COLO)?\}/i.test(texto)) {
            return texto.replace(/\{PROTO(?:COLO)?\}/gi, etiquetaProto);
        }
        const textoLower = texto.toLowerCase();
        if (textoLower.includes('tcp') || textoLower.includes('udp') || textoLower.includes('icmp') || textoLower.includes('otro protocolo')) {
            return texto;
        }
        if (texto.endsWith('.')) {
            return `${texto.slice(0, -1)} DDoS por protocolo ${etiquetaProto}.`;
        }
        return `${texto} DDoS por protocolo ${etiquetaProto}.`;
    }

    function construirUrlVozActual(protocoloAtaque = null) {
        const perfil = localStorage.getItem(CLAVE_STORAGE_PERFIL_VOZ) || 'voz_pe_alex';
        const fraseGuardada = (localStorage.getItem(CLAVE_STORAGE_FRASE_TEXTO) || '').trim();
        const protoEfectivo = protocoloAtaque || (cacheAlertaMemoria && cacheAlertaMemoria.protocolo) || 'TCP';
        const fraseFinal = formatearFraseConProtocolo(
            fraseGuardada || 'Peligro. El sistema está sufriendo un ataque.',
            protoEfectivo
        );
        const tono = localStorage.getItem(CLAVE_STORAGE_TONO) || obtenerTonoPorDefecto(perfil);
        const velocidad = localStorage.getItem(CLAVE_STORAGE_VELOCIDAD) || VELOCIDAD_VOZ_POR_DEFECTO;
        return `/api/tts/audio?voice=${encodeURIComponent(perfil)}&text=${encodeURIComponent(fraseFinal)}&pitch=${encodeURIComponent(tono)}&rate=${encodeURIComponent(velocidad)}`;
    }

    function precargarAudioVozActual() {
        try {
            modoAlerta = localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante';
            if (modoAlerta !== 'intimidante') return;

            ['TCP', 'UDP', 'ICMP'].forEach(proto => {
                const url = construirUrlVozActual(proto);
                if (cacheAudiosProtocolo[proto] && cacheAudiosProtocolo[proto].url === url) return;
                const audio = new Audio();
                audio.preload = 'auto';
                audio.src = url;
                audio.load();
                cacheAudiosProtocolo[proto] = { url, audio };
            });
            const urlBase = construirUrlVozActual('TCP');
            urlAudioPrecargado = urlBase;
            objetoAudioPrecargado = cacheAudiosProtocolo['TCP'] ? cacheAudiosProtocolo['TCP'].audio : null;
        } catch (_) {}
    }

    function obtenerVolumenActual() {
        const guardado = localStorage.getItem(CLAVE_STORAGE_VOLUMEN);
        return guardado !== null ? parseFloat(guardado) : 0.85;
    }

    function obtenerAlertaActiva() {
        const ahora = Date.now();
        if (cacheAlertaMemoria && ahora < cacheAlertaMemoria.expira) {
            return cacheAlertaMemoria;
        }
        try {
            const raw = localStorage.getItem(CLAVE_STORAGE_ALERTA);
            if (!raw) {
                cacheAlertaMemoria = null;
                return null;
            }
            const alerta = JSON.parse(raw);
            if (alerta && ahora < alerta.expira) {
                cacheAlertaMemoria = alerta;
                return alerta;
            }
            cacheAlertaMemoria = null;
            return null;
        } catch (_) {
            cacheAlertaMemoria = null;
            return null;
        }
    }

    function hayAlertaActiva() {
        return obtenerAlertaActiva() !== null;
    }

    function limpiarAudioActivo() {
        if (!audioActivo) return;
        try {
            audioActivo.pause();
            audioActivo.currentTime = 0;
        } catch (_) {}
        audioActivo = null;
    }

    // 3. Síntesis y Locución de Voz en Español
    function emitirVozEspanol(offsetSegundos = 0, protocoloAtaque = null) {
        try {
            if (offsetSegundos >= 3.0) return;

            if ('speechSynthesis' in window) {
                try { window.speechSynthesis.cancel(); } catch (_) {}
            }
            limpiarAudioActivo();

            const proto = String(protocoloAtaque || (cacheAlertaMemoria && cacheAlertaMemoria.protocolo) || 'TCP').trim().toUpperCase();
            const volumen = obtenerVolumenActual();
            const urlAudio = construirUrlVozActual(proto);

            let audio;
            if (cacheAudiosProtocolo[proto] && cacheAudiosProtocolo[proto].url === urlAudio && cacheAudiosProtocolo[proto].audio) {
                audio = cacheAudiosProtocolo[proto].audio;
                try { audio.currentTime = 0; } catch (_) {}
            } else if (objetoAudioPrecargado && urlAudioPrecargado === urlAudio) {
                audio = objetoAudioPrecargado;
                try { audio.currentTime = 0; } catch (_) {}
            } else {
                audio = new Audio(urlAudio);
                cacheAudiosProtocolo[proto] = { url: urlAudio, audio };
                urlAudioPrecargado = urlAudio;
                objetoAudioPrecargado = audio;
            }

            audio.volume = Math.max(0, Math.min(1.0, volumen));
            audio.onended = () => {
                if (audioActivo === audio) {
                    audioActivo = null;
                }
            };

            if (offsetSegundos > 0) {
                const iniciarEnOffset = () => {
                    try {
                        audio.currentTime = Math.min(audio.duration || 3.5, offsetSegundos);
                    } catch (_) {}
                    audio.play().catch(e => console.warn('Centinela: error reanudando offset:', e));
                };

                if (audio.readyState >= 1) {
                    iniciarEnOffset();
                } else {
                    audio.addEventListener('loadedmetadata', iniciarEnOffset, { once: true });
                }
            } else {
                audio.play().catch(e => {
                    console.warn('Centinela: audio bloqueado por política del navegador:', e);
                });
            }
            audioActivo = audio;
        } catch (e) {
            console.warn('Centinela: Error en locución de voz:', e);
        }
    }

    // 4. Alertas Visuales Dinámicas por Protocolo
    function activarAlertasVisuales(mensajeDetalle, protocoloAtaque) {
        alertaVisualEstabaActiva = true;
        const alertaGuardada = cacheAlertaMemoria || obtenerAlertaActiva();
        const protocoloEfectivo = protocoloAtaque || (alertaGuardada && alertaGuardada.protocolo) || 'TCP';
        const tema = obtenerTemaProtocoloAtaque(protocoloEfectivo);

        document.documentElement.style.setProperty('--color-alerta-glow-bajo', tema.glowBajo);
        document.documentElement.style.setProperty('--color-alerta-glow-alto', tema.glowAlto);

        const destelloHabilitado = localStorage.getItem(CLAVE_STORAGE_DESTELLO) !== 'false';
        if (destelloHabilitado) {
            document.body.classList.add('alerta-perimetral-activa');
            if (temporizadorDestello) clearTimeout(temporizadorDestello);
            temporizadorDestello = setTimeout(() => {
                if (!hayAlertaActiva()) {
                    document.body.classList.remove('alerta-perimetral-activa');
                }
                temporizadorDestello = null;
            }, 4000);
        }

        const bannerHabilitado = localStorage.getItem(CLAVE_STORAGE_BANNER) !== 'false';
        if (bannerHabilitado) {
            if (temporizadorOcultarBanner) {
                clearTimeout(temporizadorOcultarBanner);
                temporizadorOcultarBanner = null;
            }
            let banner = document.getElementById('banner-alerta-centinela-global');
            if (!banner) {
                banner = document.createElement('div');
                banner.id = 'banner-alerta-centinela-global';
                banner.className = 'banner-alerta-centinela';
                banner.onclick = () => {
                    banner.style.opacity = '0';
                    banner.style.transform = 'translateX(-50%) translateY(-25px)';
                    if (temporizadorOcultarBanner) clearTimeout(temporizadorOcultarBanner);
                    temporizadorOcultarBanner = setTimeout(() => {
                        temporizadorOcultarBanner = null;
                        if (banner && banner.parentNode) banner.remove();
                    }, 400);
                };
                document.body.appendChild(banner);
            }

            banner.style.background = tema.fondoGradiente;
            banner.style.boxShadow = tema.sombraBanner;

            const frasePersonalizada = localStorage.getItem(CLAVE_STORAGE_FRASE_TEXTO);
            const texto = String(frasePersonalizada || mensajeDetalle || 'Peligro. El sistema está sufriendo un ataque');
            const claveRender = `${tema.codigo}::${texto}`;

            if (banner.dataset.mensajeActual !== claveRender) {
                banner.dataset.mensajeActual = claveRender;
                banner.dataset.protocolo = tema.codigo;
                banner.textContent = '';
                const spanIcono = document.createElement('span');
                spanIcono.className = 'banner-alerta-icono';
                spanIcono.textContent = '🚨';

                const divContenedor = document.createElement('div');
                const divMensaje = document.createElement('div');
                divMensaje.textContent = texto;

                const spanProto = document.createElement('span');
                spanProto.className = 'badge-protocolo-alerta';
                spanProto.textContent = tema.codigo;
                divMensaje.appendChild(spanProto);

                const divSubtitulo = document.createElement('div');
                divSubtitulo.style.cssText = 'font-size: 0.74rem; font-weight: 500; opacity: 0.94;';
                divSubtitulo.textContent = tema.subtitulo;

                divContenedor.append(divMensaje, divSubtitulo);
                banner.append(spanIcono, divContenedor);
            }
            banner.style.opacity = '1';
            banner.style.transform = 'translateX(-50%) translateY(0)';

            if (temporizadorBanner) clearTimeout(temporizadorBanner);
            temporizadorBanner = setTimeout(() => {
                temporizadorBanner = null;
                if (!hayAlertaActiva() && banner && banner.parentNode) {
                    banner.style.opacity = '0';
                    banner.style.transform = 'translateX(-50%) translateY(-25px)';
                    if (temporizadorOcultarBanner) clearTimeout(temporizadorOcultarBanner);
                    temporizadorOcultarBanner = setTimeout(() => {
                        temporizadorOcultarBanner = null;
                        if (!hayAlertaActiva() && banner && banner.parentNode) banner.remove();
                    }, 400);
                }
            }, 5500);
        }
    }

    function desactivarAlertasVisuales() {
        alertaVisualEstabaActiva = false;
        document.body.classList.remove('alerta-perimetral-activa');
        if (temporizadorBanner) {
            clearTimeout(temporizadorBanner);
            temporizadorBanner = null;
        }
        const banner = document.getElementById('banner-alerta-centinela-global');
        if (banner) {
            banner.style.opacity = '0';
            banner.style.transform = 'translateX(-50%) translateY(-25px)';
            if (temporizadorOcultarBanner) clearTimeout(temporizadorOcultarBanner);
            temporizadorOcultarBanner = setTimeout(() => {
                temporizadorOcultarBanner = null;
                if (!hayAlertaActiva() && banner && banner.parentNode) banner.remove();
            }, 400);
        }
    }

    function conectarConDesconexionAutomatica(oscilador, ganancia, destino) {
        oscilador.connect(ganancia);
        ganancia.connect(destino);
        oscilador.onended = () => {
            try { oscilador.disconnect(); } catch (_) {}
            try { ganancia.disconnect(); } catch (_) {}
        };
    }

    // 5. Generación Acústica de Emergencia
    function reproducirAlarmaGlobal(detalleAtaque, forzar = false, protocoloAtaque = null) {
        const protocoloEfectivo = protocoloAtaque || (cacheAlertaMemoria && cacheAlertaMemoria.protocolo) || 'TCP';
        activarAlertasVisuales(detalleAtaque, protocoloEfectivo);

        modoAlerta = localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante';
        if (modoAlerta === 'silencio') return;

        const ahora = Date.now();
        const ultimoSonido = parseInt(localStorage.getItem(CLAVE_STORAGE_ULTIMO_SONIDO) || '0', 10);
        
        if (!forzar && ahora - ultimoSonido < 4500) {
            return;
        }

        try {
            localStorage.setItem(CLAVE_STORAGE_ULTIMO_SONIDO, ahora.toString());
        } catch (_) {}

        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return;

            if (!contextoAudio) contextoAudio = new AudioCtx();
            if (contextoAudio.state === 'suspended') {
                contextoAudio.resume().catch(() => {});
            }

            const t = contextoAudio.currentTime;
            const factorVolumen = obtenerVolumenActual();

            if (modoAlerta === 'intimidante') {
                const oscSirena = contextoAudio.createOscillator();
                const gananciaSirena = contextoAudio.createGain();
                oscSirena.type = 'sawtooth';

                oscSirena.frequency.setValueAtTime(420, t);
                oscSirena.frequency.linearRampToValueAtTime(880, t + 0.22);
                oscSirena.frequency.linearRampToValueAtTime(440, t + 0.42);
                oscSirena.frequency.linearRampToValueAtTime(920, t + 0.65);
                oscSirena.frequency.exponentialRampToValueAtTime(320, t + 0.95);

                gananciaSirena.gain.setValueAtTime(0.35 * factorVolumen, t);
                gananciaSirena.gain.exponentialRampToValueAtTime(0.01, t + 0.95);

                conectarConDesconexionAutomatica(oscSirena, gananciaSirena, contextoAudio.destination);
                oscSirena.start(t);
                oscSirena.stop(t + 0.95);

                const oscBajo = contextoAudio.createOscillator();
                const gananciaBajo = contextoAudio.createGain();
                oscBajo.type = 'triangle';
                oscBajo.frequency.setValueAtTime(110, t);
                oscBajo.frequency.exponentialRampToValueAtTime(45, t + 0.45);
                gananciaBajo.gain.setValueAtTime(0.40 * factorVolumen, t);
                gananciaBajo.gain.exponentialRampToValueAtTime(0.01, t + 0.45);
                conectarConDesconexionAutomatica(oscBajo, gananciaBajo, contextoAudio.destination);
                oscBajo.start(t);
                oscBajo.stop(t + 0.45);

                if (temporizadorVoz) {
                    clearTimeout(temporizadorVoz);
                    temporizadorVoz = null;
                }
                if (document.hidden) {
                    emitirVozEspanol(0, protocoloEfectivo);
                } else {
                    temporizadorVoz = setTimeout(() => {
                        temporizadorVoz = null;
                        if ((localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante') !== 'intimidante') return;
                        emitirVozEspanol(0, protocoloEfectivo);
                    }, RETARDO_ENTRADA_VOZ_MS);
                }

            } else if (modoAlerta === 'radar') {
                const osc1 = contextoAudio.createOscillator();
                const ganancia1 = contextoAudio.createGain();
                osc1.type = 'sawtooth';
                osc1.frequency.setValueAtTime(880, t);
                osc1.frequency.exponentialRampToValueAtTime(720, t + 0.16);
                ganancia1.gain.setValueAtTime(0.20 * factorVolumen, t);
                ganancia1.gain.exponentialRampToValueAtTime(0.01, t + 0.16);
                conectarConDesconexionAutomatica(osc1, ganancia1, contextoAudio.destination);
                osc1.start(t);
                osc1.stop(t + 0.16);

                const osc2 = contextoAudio.createOscillator();
                const ganancia2 = contextoAudio.createGain();
                osc2.type = 'sawtooth';
                osc2.frequency.setValueAtTime(960, t + 0.18);
                osc2.frequency.exponentialRampToValueAtTime(650, t + 0.38);
                ganancia2.gain.setValueAtTime(0.22 * factorVolumen, t + 0.18);
                ganancia2.gain.exponentialRampToValueAtTime(0.01, t + 0.38);
                conectarConDesconexionAutomatica(osc2, ganancia2, contextoAudio.destination);
                osc2.start(t + 0.18);
                osc2.stop(t + 0.38);
            }
        } catch (e) {
            console.warn('Centinela: Error en generador acústico:', e);
        }
    }

    // 6. Registro de Amenazas y Manejo de Ráfagas Continuas
    function registrarAtaqueGlobal(motivo, protocoloAtaque = null) {
        const ahora = Date.now();
        const fraseGuardada = localStorage.getItem(CLAVE_STORAGE_FRASE_TEXTO);
        const textoAlerta = fraseGuardada || motivo || 'Peligro. El sistema está sufriendo un ataque';

        let alerta = cacheAlertaMemoria;
        if (!alerta || ahora >= alerta.expira) {
            const raw = localStorage.getItem(CLAVE_STORAGE_ALERTA);
            try { if (raw) alerta = JSON.parse(raw); } catch (_) { alerta = null; }
        }

        const protocoloNormalizado = String(
            protocoloAtaque || (alerta && alerta.protocolo) || 'TCP'
        ).trim().toUpperCase();

        if (alerta && ahora < alerta.expira) {
            const cambioProtocolo = alerta.protocolo !== protocoloNormalizado;
            alerta.expira = ahora + DURACION_ALARMA_MS;
            alerta.motivo = textoAlerta;
            alerta.protocolo = protocoloNormalizado;
            cacheAlertaMemoria = alerta;

            activarAlertasVisuales(alerta.motivo, protocoloNormalizado);

            if (cambioProtocolo || ahora - ultimaEscrituraStorageMs >= 1000) {
                ultimaEscrituraStorageMs = ahora;
                try { localStorage.setItem(CLAVE_STORAGE_ALERTA, JSON.stringify(alerta)); } catch (_) {}
            }

            const ultimoSonido = parseInt(localStorage.getItem(CLAVE_STORAGE_ULTIMO_SONIDO) || '0', 10);
            if (ahora - ultimoSonido < INTERVALO_CICLO_MS - 800) {
                return;
            }
        } else {
            alerta = {
                inicio: ahora,
                expira: ahora + DURACION_ALARMA_MS,
                motivo: textoAlerta,
                protocolo: protocoloNormalizado,
                timestamp: ahora
            };
            cacheAlertaMemoria = alerta;
            ultimaEscrituraStorageMs = ahora;
            try { localStorage.setItem(CLAVE_STORAGE_ALERTA, JSON.stringify(alerta)); } catch (_) {}
        }

        reproducirAlarmaGlobal(alerta.motivo, false, protocoloNormalizado);
    }

    // 7. Sincronización Acústica entre Ventanas (P3-03: no emitir voz en modo 'radar' o 'silencio')
    function sincronizarAlarmaAlCargarVentana() {
        const alerta = obtenerAlertaActiva();
        if (!alerta) return;

        const ahora = Date.now();
        const protoAlerta = alerta.protocolo || 'TCP';
        activarAlertasVisuales(alerta.motivo, protoAlerta);

        modoAlerta = localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante';
        if (modoAlerta === 'silencio') return;

        const ultimoSonido = parseInt(localStorage.getItem(CLAVE_STORAGE_ULTIMO_SONIDO) || '0', 10);
        const tiempoDesdeUltimoSonido = ahora - ultimoSonido;

        if (tiempoDesdeUltimoSonido < INTERVALO_CICLO_MS) {
            if (modoAlerta !== 'intimidante') return;
            if (tiempoDesdeUltimoSonido < RETARDO_ENTRADA_VOZ_MS) {
                const retardo = Math.max(40, RETARDO_ENTRADA_VOZ_MS - tiempoDesdeUltimoSonido);
                if (temporizadorVoz) clearTimeout(temporizadorVoz);
                temporizadorVoz = setTimeout(() => {
                    temporizadorVoz = null;
                    if ((localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante') !== 'intimidante') return;
                    emitirVozEspanol(0, protoAlerta);
                }, retardo);
            } else if (tiempoDesdeUltimoSonido >= RETARDO_ENTRADA_VOZ_MS && tiempoDesdeUltimoSonido < 4000) {
                const vozOffset = (tiempoDesdeUltimoSonido - RETARDO_ENTRADA_VOZ_MS) / 1000.0;
                emitirVozEspanol(vozOffset, protoAlerta);
            }
        } else {
            reproducirAlarmaGlobal(alerta.motivo, false, protoAlerta);
        }
    }

    window.addEventListener('storage', (evento) => {
        if (evento.key === CLAVE_STORAGE_ALERTA && evento.newValue) {
            try {
                const alerta = JSON.parse(evento.newValue);
                if (alerta && Date.now() < alerta.expira) {
                    cacheAlertaMemoria = alerta;
                    activarAlertasVisuales(alerta.motivo, alerta.protocolo || 'TCP');
                    const ahora = Date.now();
                    const ultimoSonido = parseInt(localStorage.getItem(CLAVE_STORAGE_ULTIMO_SONIDO) || '0', 10);
                    if (ahora - ultimoSonido >= INTERVALO_CICLO_MS - 500) {
                        reproducirAlarmaGlobal(alerta.motivo, false, alerta.protocolo || 'TCP');
                    }
                }
            } catch (_) {}
        }
        const clavesVoz = [
            CLAVE_STORAGE_MODO,
            CLAVE_STORAGE_PERFIL_VOZ,
            CLAVE_STORAGE_TONO,
            CLAVE_STORAGE_VELOCIDAD,
            CLAVE_STORAGE_FRASE_TEXTO
        ];
        if (!evento.key || clavesVoz.includes(evento.key)) {
            modoAlerta = localStorage.getItem(CLAVE_STORAGE_MODO) || 'intimidante';
            precargarAudioVozActual();
        }
        aplicarPreferenciasInterfaz();
    });

    precargarAudioVozActual();
    sincronizarAlarmaAlCargarVentana();

    // 8. Centinela Periódico de Estado Visual
    intervaloCentinelaVisual = setInterval(() => {
        const alerta = obtenerAlertaActiva();
        if (alerta) {
            activarAlertasVisuales(alerta.motivo, alerta.protocolo || 'TCP');
        } else if (alertaVisualEstabaActiva) {
            try { localStorage.removeItem(CLAVE_STORAGE_ALERTA); } catch (_) {}
            desactivarAlertasVisuales();
        }
    }, 200);

    // 9. Conexión WebSocket Centinela en Pantallas Secundarias
    function iniciarWebSocketCentinelaSiNoExiste() {
        if (redirigiendoLogin) return;
        const rutaActual = window.location.pathname;
        const esMonitorPrincipal = rutaActual === '/' || rutaActual === '/frontend' || rutaActual.endsWith('/frontend/') || rutaActual.endsWith('/frontend/index.html');
        if (esMonitorPrincipal) return;

        if (temporizadorReconexionCentinela) {
            clearTimeout(temporizadorReconexionCentinela);
            temporizadorReconexionCentinela = null;
        }
        if (socketCentinelaActivo && (socketCentinelaActivo.readyState === WebSocket.OPEN || socketCentinelaActivo.readyState === WebSocket.CONNECTING)) {
            return;
        }

        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const socket = new WebSocket(`${proto}//${window.location.host}/ws/traffic`);
        socketCentinelaActivo = socket;

        socket.onopen = () => {
            intentosReconexionCentinela = 0;
        };

        socket.onmessage = (evento) => {
            try {
                const datos = JSON.parse(evento.data);
                if (!datos) return;
                let esAtaqueDetectado = false;
                let protocoloDetectado = 'TCP';
                let mensaje = 'Peligro. El sistema está sufriendo un ataque';

                if (datos.type === 'batch') {
                    if (datos.ddos > 0) {
                        esAtaqueDetectado = true;
                        const flujoAtaque = Array.isArray(datos.flows) ? datos.flows.find(f => f && f.is_attack) : null;
                        protocoloDetectado = datos.attack_protocol || (flujoAtaque && flujoAtaque.protocol) || 'OTHER';
                        mensaje = `Peligro. El sistema está sufriendo un ataque [${protocoloDetectado}] (${datos.ddos} flujos DDoS detectados)`;
                    }
                } else if (datos.is_attack) {
                    esAtaqueDetectado = true;
                    protocoloDetectado = datos.protocol || 'OTHER';
                    mensaje = `Peligro. El sistema está sufriendo un ataque [${protocoloDetectado}]`;
                }

                if (esAtaqueDetectado) {
                    registrarAtaqueGlobal(mensaje, protocoloDetectado);
                    const ahora = Date.now();
                    const paginaActualAlertas = typeof window.obtenerPaginaActualAlertas === 'function'
                        ? window.obtenerPaginaActualAlertas()
                        : 1;
                    // Solo auto-refrescar la tabla en vivo si el operador está en la página 1 (P3-09)
                    if (typeof window.cargarAlertas === 'function' && paginaActualAlertas === 1 && ahora - ultimoRefrescoAlertasMs > 1200) {
                        ultimoRefrescoAlertasMs = ahora;
                        try { window.cargarAlertas(1); } catch (_) {}
                    }
                }
            } catch (_) {}
        };

        socket.onerror = () => {
            try { socket.close(); } catch (_) {}
        };

        socket.onclose = (evento) => {
            if (socketCentinelaActivo === socket) {
                socketCentinelaActivo = null;
            }
            if (redirigiendoLogin || (evento && evento.code === 1008)) {
                manejarSesionExpirada();
                return;
            }
            const baseMs = Math.min(15000, 800 * Math.pow(2, intentosReconexionCentinela));
            const jitterMs = Math.floor(Math.random() * 400);
            intentosReconexionCentinela = Math.min(intentosReconexionCentinela + 1, 5);
            temporizadorReconexionCentinela = setTimeout(iniciarWebSocketCentinelaSiNoExiste, baseMs + jitterMs);
        };
    }
    iniciarWebSocketCentinelaSiNoExiste();

    // 10. Preferencias de Interfaz y Permisos de Simulación
    function aplicarPreferenciasInterfaz() {
        const temaVisual = localStorage.getItem('cybershield_tema_visual') || 'claro';
        document.documentElement.classList.remove('tema-gris', 'tema-oscuro');
        if (document.body) document.body.classList.remove('tema-gris', 'tema-oscuro');
        if (temaVisual === 'gris') {
            document.documentElement.classList.add('tema-gris');
            if (document.body) document.body.classList.add('tema-gris');
        } else if (temaVisual === 'oscuro') {
            document.documentElement.classList.add('tema-oscuro');
            if (document.body) document.body.classList.add('tema-oscuro');
        }

        const mostrarConsolaPref = localStorage.getItem('cybershield_mostrar_consola') !== 'false';
        const mostrarConsola = simulacionHabilitadaServidor && mostrarConsolaPref;

        const botonConsola = document.getElementById('btnConsolaSimulacion') || document.querySelector('[data-bs-target="#panelSimulacion"]');
        if (botonConsola) {
            if (!mostrarConsola) {
                botonConsola.classList.add('d-none');
                botonConsola.style.setProperty('display', 'none', 'important');
            } else {
                botonConsola.classList.remove('d-none');
                botonConsola.style.removeProperty('display');
            }
        }
        const panelSimulacion = document.getElementById('panelSimulacion');
        if (panelSimulacion) {
            if (!mostrarConsola) {
                panelSimulacion.classList.remove('show');
                panelSimulacion.classList.add('d-none');
                panelSimulacion.style.setProperty('display', 'none', 'important');
            } else {
                panelSimulacion.classList.remove('d-none');
                panelSimulacion.style.removeProperty('display');
            }
        }

        const btnSimularAlerta = document.getElementById('btnSimularAlerta');
        if (btnSimularAlerta) {
            if (!simulacionHabilitadaServidor) {
                btnSimularAlerta.classList.add('d-none');
                btnSimularAlerta.disabled = true;
            } else {
                btnSimularAlerta.classList.remove('d-none');
                btnSimularAlerta.disabled = false;
            }
        }

        const switchMostrarConsola = document.getElementById('switchMostrarConsola');
        const notaSimServidor = document.getElementById('notaSimulacionServidor');
        if (switchMostrarConsola) {
            if (!simulacionHabilitadaServidor) {
                switchMostrarConsola.checked = false;
                switchMostrarConsola.disabled = true;
                if (notaSimServidor) notaSimServidor.classList.remove('d-none');
            } else {
                switchMostrarConsola.disabled = false;
                if (notaSimServidor) notaSimServidor.classList.add('d-none');
            }
        }

        const mostrarSelector = localStorage.getItem('cybershield_mostrar_selector_alarma') !== 'false';
        const dropdownAlerta = document.getElementById('dropdownAlerta');
        if (dropdownAlerta) {
            const contenedorDropdown = dropdownAlerta.closest('.dropdown') || dropdownAlerta;
            if (!mostrarSelector) {
                contenedorDropdown.classList.add('d-none');
                contenedorDropdown.style.setProperty('display', 'none', 'important');
            } else {
                contenedorDropdown.classList.remove('d-none');
                contenedorDropdown.style.removeProperty('display');
            }
        }

        const mostrarSwagger = localStorage.getItem('cybershield_mostrar_swagger') !== 'false';
        const enlacesSwagger = document.querySelectorAll('.sidebar a[href="/docs"]');
        enlacesSwagger.forEach(enlace => {
            const itemNav = enlace.closest('li.nav-item') || enlace;
            if (!mostrarSwagger) {
                itemNav.classList.add('d-none');
                itemNav.style.setProperty('display', 'none', 'important');
            } else {
                itemNav.classList.remove('d-none');
                itemNav.style.removeProperty('display');
            }
        });

        const listaNav = document.querySelector('.sidebar ul.nav');
        if (listaNav) {
            const soarActivo = localStorage.getItem('cybershield_soar_activo') === 'true';
            let itemSoar = document.getElementById('navItemCentroSoar');
            if (soarActivo) {
                if (!itemSoar) {
                    itemSoar = document.createElement('li');
                    itemSoar.className = 'nav-item';
                    itemSoar.id = 'navItemCentroSoar';
                    const esVistaSoar = window.location.pathname.endsWith('/soar.html');
                    itemSoar.innerHTML = `
                        <a class="nav-link ${esVistaSoar ? 'active' : ''}" href="/frontend/soar.html" style="border: 1px solid rgba(56, 189, 248, 0.35); background: rgba(14, 165, 233, 0.12);">
                            <i class="bi bi-shield-shaded text-info"></i>
                            <span>Centro Mitigación SOAR</span>
                        </a>
                    `;
                    const enlaceConfig = listaNav.querySelector('a[href="/frontend/configuracion.html"]');
                    const liConfig = enlaceConfig ? enlaceConfig.closest('li.nav-item') : null;
                    if (liConfig) {
                        listaNav.insertBefore(itemSoar, liConfig);
                    } else {
                        listaNav.appendChild(itemSoar);
                    }
                }
            } else if (itemSoar) {
                itemSoar.remove();
            }
        }

        if (listaNav && !document.getElementById('navItemCerrarSesion')) {
            const liLogout = document.createElement('li');
            liLogout.className = 'nav-item mt-2 pt-2 border-top border-secondary border-opacity-25';
            liLogout.id = 'navItemCerrarSesion';
            const enlaceLogout = document.createElement('a');
            enlaceLogout.className = 'nav-link text-danger';
            enlaceLogout.href = '#cerrar-sesion';
            enlaceLogout.setAttribute('role', 'button');
            enlaceLogout.innerHTML = '<i class="bi bi-box-arrow-left"></i> Cerrar Sesión';
            enlaceLogout.addEventListener('click', async (e) => {
                e.preventDefault();
                redirigiendoLogin = true;
                detenerRecursosGlobalesSesion();
                try {
                    await fetch('/api/auth/logout', { method: 'POST' });
                } catch (_) {}
                limpiarAlmacenamientoSesion();
                window.location.replace('/frontend/login.html');
            });
            liLogout.appendChild(enlaceLogout);
            listaNav.appendChild(liLogout);
        }
    }

    async function sincronizarEstadoSesionYPermisos() {
        try {
            const resp = await fetch('/api/auth/me');
            if (!verificarRespuestaApi(resp)) return;
            const datos = await resp.json();
            if (datos && typeof datos.simulation_enabled === 'boolean') {
                simulacionHabilitadaServidor = datos.simulation_enabled;
                aplicarPreferenciasInterfaz();
            }
        } catch (_) {}
    }

    async function sincronizarEstadoModuloSoar() {
        try {
            const resp = await fetch('/api/soar/status');
            if (!verificarRespuestaApi(resp)) return;
            const datos = await resp.json();
            const estadoReal = datos && datos.enabled === true ? 'true' : 'false';
            if (localStorage.getItem('cybershield_soar_activo') !== estadoReal) {
                localStorage.setItem('cybershield_soar_activo', estadoReal);
                aplicarPreferenciasInterfaz();
            }
        } catch (_) {}
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            aplicarPreferenciasInterfaz();
            sincronizarEstadoSesionYPermisos();
            sincronizarEstadoModuloSoar();
        });
    } else {
        aplicarPreferenciasInterfaz();
        sincronizarEstadoSesionYPermisos();
        sincronizarEstadoModuloSoar();
    }

    // 11. Activación del Contexto de Audio
    const reanudarAudioAlInteractuar = () => {
        if (!contextoAudio) {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (AudioCtx) contextoAudio = new AudioCtx();
        }
        if (contextoAudio && contextoAudio.state === 'suspended') {
            contextoAudio.resume().catch(() => {});
        }
        if (hayAlertaActiva() && !audioActivo) {
            sincronizarAlarmaAlCargarVentana();
        }
    };
    ['click', 'keydown', 'pointerdown', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, reanudarAudioAlInteractuar, { once: true, passive: true });
    });

    // 12. Exportación Global
    window.reproducirAlarmaGlobal = reproducirAlarmaGlobal;
    window.registrarAtaqueGlobal = registrarAtaqueGlobal;
    window.emitirVozContingencia = emitirVozEspanol;
    window.aplicarPreferenciasInterfaz = aplicarPreferenciasInterfaz;
    window.obtenerTemaProtocoloAtaque = obtenerTemaProtocoloAtaque;
    window.precargarAudioVozActual = precargarAudioVozActual;
    window.cambiarModoAlertaGlobal = cambiarModoAlertaGlobal;
    window.manejarSesionExpirada = manejarSesionExpirada;
    window.verificarRespuestaApi = verificarRespuestaApi;
    window.registrarLimpiezaSesion = registrarLimpiezaSesion;
    window.limpiarAlmacenamientoSesion = limpiarAlmacenamientoSesion;
    window.esSimulacionHabilitada = () => simulacionHabilitadaServidor;
    window.notificarSimulacionDeshabilitada = () => {
        simulacionHabilitadaServidor = false;
        aplicarPreferenciasInterfaz();
    };
    window.VOZ_DEFAULTS_CYBERSHIELD = {
        esPerfilFemenino,
        obtenerTonoPorDefecto,
        VELOCIDAD_POR_DEFECTO: VELOCIDAD_VOZ_POR_DEFECTO
    };

})();

