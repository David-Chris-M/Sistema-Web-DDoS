(function () {
    'use strict';

    // 1. Elementos del DOM y Catálogos
    const switchMostrarConsola = document.getElementById('switchMostrarConsola');
    const switchMostrarSelector = document.getElementById('switchMostrarSelector');
    const switchMostrarSwagger = document.getElementById('switchMostrarSwagger');
    const selectModoAlarma = document.getElementById('selectModoAlarma');
    const selectPerfilVoz = document.getElementById('selectPerfilVoz');
    const sliderTono = document.getElementById('sliderTono');
    const badgeTono = document.getElementById('badgeTono');
    const sliderVelocidad = document.getElementById('sliderVelocidad');
    const badgeVelocidad = document.getElementById('badgeVelocidad');
    const selectPlantillaFrase = document.getElementById('selectPlantillaFrase');
    const inputFraseTexto = document.getElementById('inputFraseTexto');
    const sliderVolumen = document.getElementById('sliderVolumen');
    const badgeVolumen = document.getElementById('badgeVolumen');
    const switchDestello = document.getElementById('switchDestello');
    const switchBanner = document.getElementById('switchBanner');
    const selectUmbralDDoS = document.getElementById('selectUmbralDDoS');

    let temporizadorToastConfig = null;
    let umbralConfirmadoServidor = '50';

    const VOCES_NEURALES = {
        'voz_pe_alex': '🇵🇪 Alex (Hombre - Táctica Militar Grave)',
        'voz_pe_camila': '🇵🇪 Camila (Mujer - Alerta Nítida)',
        'voz_mx_jorge': '🇲🇽 Jorge (Hombre - Autoridad y Firmeza)',
        'voz_mx_dalia': '🇲🇽 Dalia (Mujer - Ejecutiva Seria)',
        'voz_es_alvaro': '🇪🇸 Álvaro (Hombre - Grave y Sobrio)',
        'voz_es_elvira': '🇪🇸 Elvira (Mujer - Rápida y Enérgica)',
        'voz_co_gonzalo': '🇨🇴 Gonzalo (Hombre - Tono Táctico)',
        'voz_co_salome': '🇨🇴 Salomé (Mujer - Emergencia)',
        'voz_ar_tomas': '🇦🇷 Tomás (Hombre - Tono Profundo)',
        'voz_us_paloma': '🇺🇸 Paloma (Mujer - Notificadora)'
    };

    const PLANTILLAS = {
        'pred_1': 'Peligro. El sistema está sufriendo un ataque.',
        'pred_2': 'El sistema está siendo atacado, por favor implementa un plan de contingencia.',
        'pred_3': 'Alerta de seguridad. Intrusión detectada en la red perimetral.',
        'pred_4': 'Ataque DDoS detectado. Activando contramedidas de mitigación.'
    };

    const VELOCIDAD_POR_DEFECTO = (window.VOZ_DEFAULTS_CYBERSHIELD && window.VOZ_DEFAULTS_CYBERSHIELD.VELOCIDAD_POR_DEFECTO) || '0.95';

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

    function esPerfilFemenino(perfil) {
        if (window.VOZ_DEFAULTS_CYBERSHIELD && typeof window.VOZ_DEFAULTS_CYBERSHIELD.esPerfilFemenino === 'function') {
            return window.VOZ_DEFAULTS_CYBERSHIELD.esPerfilFemenino(perfil);
        }
        const p = String(perfil || '').toLowerCase();
        return p.includes('camila') || p.includes('dalia') || p.includes('elvira') ||
               p.includes('salome') || p.includes('paloma') || p.startsWith('femenin');
    }

    function obtenerTonoPorDefecto(perfil) {
        if (window.VOZ_DEFAULTS_CYBERSHIELD && typeof window.VOZ_DEFAULTS_CYBERSHIELD.obtenerTonoPorDefecto === 'function') {
            return parseFloat(window.VOZ_DEFAULTS_CYBERSHIELD.obtenerTonoPorDefecto(perfil));
        }
        return esPerfilFemenino(perfil) ? 1.25 : 0.75;
    }

    function textoTono(factor) {
        if (factor <= 0.65) return `Muy Grave (${factor.toFixed(2)}x)`;
        if (factor <= 0.85) return `Grave (${factor.toFixed(2)}x)`;
        if (factor <= 1.10) return `Natural (${factor.toFixed(2)}x)`;
        if (factor <= 1.30) return `Agudo (${factor.toFixed(2)}x)`;
        return `Muy Agudo (${factor.toFixed(2)}x)`;
    }

    function textoVelocidad(factor) {
        if (factor <= 0.85) return `Pausado (${factor.toFixed(2)}x)`;
        if (factor <= 1.05) return `Normal (${factor.toFixed(2)}x)`;
        return `Rápido (${factor.toFixed(2)}x)`;
    }

    function actualizarBotonesTema(tema) {
        const mapa = {
            claro: document.getElementById('btnTemaClaro'),
            gris: document.getElementById('btnTemaGris'),
            oscuro: document.getElementById('btnTemaOscuro')
        };
        Object.entries(mapa).forEach(([clave, btn]) => {
            if (!btn) return;
            if (clave === tema) {
                btn.classList.remove('btn-outline-secondary');
                btn.classList.add('btn-primary', 'text-white');
            } else {
                btn.classList.remove('btn-primary', 'text-white');
                btn.classList.add('btn-outline-secondary');
            }
        });
    }

    function aplicarValorUmbralEnSelect(valorPorcentaje) {
        if (!selectUmbralDDoS) return;
        const num = Math.round(Number(valorPorcentaje));
        const valStr = Number.isFinite(num) ? String(num) : '50';
        let existeOpcion = false;
        for (let i = 0; i < selectUmbralDDoS.options.length; i++) {
            if (selectUmbralDDoS.options[i].value === valStr) {
                existeOpcion = true;
                break;
            }
        }
        if (!existeOpcion) {
            const opt = document.createElement('option');
            opt.value = valStr;
            opt.textContent = `${valStr}% (Personalizado en Servidor)`;
            selectUmbralDDoS.appendChild(opt);
        }
        selectUmbralDDoS.value = valStr;
    }

    window.cambiarTemaVisual = function (tema) {
        const temaValido = ['claro', 'gris', 'oscuro'].includes(tema) ? tema : 'claro';
        actualizarBotonesTema(temaValido);
        const nombres = {
            claro: 'Tema Claro Corporativo activado',
            gris: 'Tema Gris Descanso Visual activado (Anti-Fatiga)',
            oscuro: 'Tema Oscuro Nocturno SOC activado'
        };
        guardarConfiguracion('cybershield_tema_visual', temaValido, nombres[temaValido]);
    };

    // 2. Carga de Configuración desde localStorage y sincronización con servidor
    function cargarConfiguraciones() {
        const temaGuardado = localStorage.getItem('cybershield_tema_visual') || 'claro';
        actualizarBotonesTema(temaGuardado);
        if (typeof window.aplicarPreferenciasInterfaz === 'function') {
            window.aplicarPreferenciasInterfaz();
        }

        const mostrarConsola = localStorage.getItem('cybershield_mostrar_consola') !== 'false';
        if (switchMostrarConsola && !switchMostrarConsola.disabled) {
            switchMostrarConsola.checked = mostrarConsola;
        }

        const mostrarSelector = localStorage.getItem('cybershield_mostrar_selector_alarma') !== 'false';
        if (switchMostrarSelector) switchMostrarSelector.checked = mostrarSelector;

        const mostrarSwagger = localStorage.getItem('cybershield_mostrar_swagger') !== 'false';
        if (switchMostrarSwagger) switchMostrarSwagger.checked = mostrarSwagger;

        const modo = localStorage.getItem('cybershield_modo_alerta') || 'intimidante';
        if (selectModoAlarma) selectModoAlarma.value = modo;

        const perfil = localStorage.getItem('cybershield_perfil_voz') || 'voz_pe_alex';
        if (selectPerfilVoz) {
            selectPerfilVoz.value = perfil in VOCES_NEURALES ? perfil : 'voz_pe_alex';
        }

        const tonoGuardado = localStorage.getItem('cybershield_tono_voz');
        const factorTono = tonoGuardado !== null ? parseFloat(tonoGuardado) : obtenerTonoPorDefecto(perfil);
        if (sliderTono) {
            sliderTono.value = Math.round(factorTono * 100);
            if (badgeTono) badgeTono.innerText = textoTono(factorTono);
        }

        const velGuardada = localStorage.getItem('cybershield_velocidad_voz');
        const factorVel = velGuardada !== null ? parseFloat(velGuardada) : parseFloat(VELOCIDAD_POR_DEFECTO);
        if (sliderVelocidad) {
            sliderVelocidad.value = Math.round(factorVel * 100);
            if (badgeVelocidad) badgeVelocidad.innerText = textoVelocidad(factorVel);
        }

        const fraseGuardada = localStorage.getItem('cybershield_frase_texto') || 'Peligro. El sistema está sufriendo un ataque.';
        if (inputFraseTexto) inputFraseTexto.value = fraseGuardada;

        if (selectPlantillaFrase) {
            let coincidencia = 'custom';
            for (const [clave, texto] of Object.entries(PLANTILLAS)) {
                if (texto.trim().toLowerCase() === fraseGuardada.trim().toLowerCase()) {
                    coincidencia = clave;
                    break;
                }
            }
            selectPlantillaFrase.value = coincidencia;
        }

        const volumen = localStorage.getItem('cybershield_volumen_alerta') !== null
            ? parseFloat(localStorage.getItem('cybershield_volumen_alerta'))
            : 0.85;
        if (sliderVolumen) {
            sliderVolumen.value = Math.round(volumen * 100);
            if (badgeVolumen) badgeVolumen.innerText = `${Math.round(volumen * 100)}%`;
        }

        const destello = localStorage.getItem('cybershield_destello_activo') !== 'false';
        if (switchDestello) switchDestello.checked = destello;

        const banner = localStorage.getItem('cybershield_banner_activo') !== 'false';
        if (switchBanner) switchBanner.checked = banner;

        const umbral = localStorage.getItem('cybershield_umbral_ddos') || umbralConfirmadoServidor;
        aplicarValorUmbralEnSelect(umbral);
    }

    async function cargarUmbralServidor() {
        try {
            const resp = await fetch('/api/settings/threshold');
            if (!verificarRespuesta(resp)) return;
            const datos = await resp.json();
            if (datos && Number.isFinite(Number(datos.threshold_percent))) {
                umbralConfirmadoServidor = String(Math.round(Number(datos.threshold_percent)));
                localStorage.setItem('cybershield_umbral_ddos', umbralConfirmadoServidor);
                aplicarValorUmbralEnSelect(umbralConfirmadoServidor);
            }
        } catch (error) {
            console.warn('No se pudo leer el umbral del servidor:', error);
        }
    }

    async function cargarEstadoSaludYModelo() {
        const badgeSalud = document.getElementById('badgeEstadoSaludSistema');
        try {
            const respSalud = await fetch('/api/health');
            const datosSalud = await respSalud.json().catch(() => null);
            if (badgeSalud) {
                badgeSalud.textContent = '';
                const ic = document.createElement('i');
                const sp = document.createElement('span');
                if (respSalud.ok && datosSalud && datosSalud.status === 'online') {
                    badgeSalud.className = 'badge bg-success-subtle text-success badge-value';
                    ic.className = 'bi bi-broadcast me-1';
                    const wsActivos = Number.isFinite(Number(datosSalud.active_websockets)) ? Number(datosSalud.active_websockets) : 0;
                    sp.textContent = `API y BD en Línea (WS: ${wsActivos})`;
                } else {
                    badgeSalud.className = 'badge bg-warning-subtle text-warning badge-value';
                    ic.className = 'bi bi-exclamation-triangle-fill me-1';
                    sp.textContent = 'Servicio Degradado';
                }
                badgeSalud.append(ic, sp);
            }
        } catch (_) {
            if (badgeSalud) {
                badgeSalud.className = 'badge bg-danger-subtle text-danger badge-value';
                badgeSalud.textContent = '';
                const ic = document.createElement('i');
                ic.className = 'bi bi-wifi-off me-1';
                const sp = document.createElement('span');
                sp.textContent = 'Sin Conexión API';
                badgeSalud.append(ic, sp);
            }
        }

        try {
            const respModelo = await fetch('/api/model');
            if (!verificarRespuesta(respModelo)) return;
            const info = await respModelo.json();

            const elVec = document.getElementById('specVectorEntrada');
            if (elVec && Number.isFinite(Number(info.n_features))) {
                elVec.textContent = `${Number(info.n_features)} características activas (de 80 canónicas CICFlowMeter / CICIDS2017)`;
            }

            const elEsc = document.getElementById('specEscaladorModo');
            if (elEsc && info.scaler) {
                elEsc.textContent = `CPU-Only · ${info.scaler} (optimizada para hardware accesible de Pymes)`;
            }

            const elLat = document.getElementById('specLatenciaModelo');
            if (elLat) {
                const partes = [];
                if (info.latency && Number.isFinite(Number(info.latency.single_flow_warm_ms))) {
                    const loteTxt = Number.isFinite(Number(info.latency.avg_per_flow_ms))
                        ? ` (${Number(info.latency.avg_per_flow_ms).toFixed(3)} ms en lote)`
                        : '';
                    partes.push(`${Number(info.latency.single_flow_warm_ms).toFixed(2)} ms/flujo${loteTxt}`);
                }
                if (info.test_metrics && Number.isFinite(Number(info.test_metrics.accuracy))) {
                    partes.push(`Exactitud Test: ${(Number(info.test_metrics.accuracy) * 100).toFixed(2)}%`);
                }
                if (info.test_metrics && Number.isFinite(Number(info.test_metrics.fpr))) {
                    partes.push(`FPR: ${(Number(info.test_metrics.fpr) * 100).toFixed(2)}%`);
                }
                elLat.textContent = partes.length ? partes.join(' · ') : 'Modelo listo en CPU';
            }

            if (Number.isFinite(Number(info.decision_threshold))) {
                umbralConfirmadoServidor = String(Math.round(Number(info.decision_threshold) * 100));
                localStorage.setItem('cybershield_umbral_ddos', umbralConfirmadoServidor);
                aplicarValorUmbralEnSelect(umbralConfirmadoServidor);
            }
        } catch (error) {
            console.warn('No se pudo consultar /api/model:', error);
        }
    }

    // 3. Persistencia de Configuración y Notificaciones Seguras (P3-04: sin innerHTML)
    function guardarConfiguracion(clave, valor, mensajeToast) {
        localStorage.setItem(clave, valor);
        if (typeof window.aplicarPreferenciasInterfaz === 'function') {
            window.aplicarPreferenciasInterfaz();
        }
        window.dispatchEvent(new Event('storage'));
        mostrarToastGuardado(mensajeToast || 'Preferencia guardada', false);
    }

    function mostrarToastGuardado(mensaje, esError = false) {
        let toast = document.getElementById('toast-confirmacion-ajustes');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'toast-confirmacion-ajustes';
            toast.style.cssText = `
                position: fixed;
                bottom: 24px;
                right: 24px;
                background: #0f172a;
                color: #f8fafc;
                padding: 12px 20px;
                border-radius: 10px;
                font-size: 0.85rem;
                font-weight: 600;
                box-shadow: 0 10px 25px rgba(0,0,0,0.25);
                border: 1px solid rgba(255,255,255,0.12);
                z-index: 100000;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: opacity 0.3s ease, transform 0.3s ease;
                opacity: 0;
                transform: translateY(20px);
            `;
            document.body.appendChild(toast);
        }

        toast.textContent = '';
        const icono = document.createElement('i');
        icono.className = esError
            ? 'bi bi-exclamation-triangle-fill text-warning fs-5'
            : 'bi bi-check-circle-fill text-success fs-5';
        const spanMensaje = document.createElement('span');
        spanMensaje.textContent = String(mensaje ?? '');
        toast.append(icono, spanMensaje);

        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';

        if (temporizadorToastConfig) clearTimeout(temporizadorToastConfig);
        temporizadorToastConfig = setTimeout(() => {
            if (toast) {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(20px)';
            }
            temporizadorToastConfig = null;
        }, 2800);
    }

    // 4. Asignación de Escuchadores de Eventos
    if (switchMostrarConsola) {
        switchMostrarConsola.addEventListener('change', (e) => {
            guardarConfiguracion('cybershield_mostrar_consola', e.target.checked ? 'true' : 'false',
                e.target.checked ? 'Consola de pruebas habilitada en Monitor' : 'Consola de pruebas oculta (Modo Producción)');
        });
    }

    if (switchMostrarSelector) {
        switchMostrarSelector.addEventListener('change', (e) => {
            guardarConfiguracion('cybershield_mostrar_selector_alarma', e.target.checked ? 'true' : 'false',
                e.target.checked ? 'Selector de alarma visible en cabecera' : 'Selector de alarma oculto');
        });
    }

    if (switchMostrarSwagger) {
        switchMostrarSwagger.addEventListener('change', (e) => {
            guardarConfiguracion('cybershield_mostrar_swagger', e.target.checked ? 'true' : 'false',
                e.target.checked ? 'API Swagger visible en menú lateral' : 'API Swagger oculto del menú lateral');
        });
    }

    if (selectModoAlarma) {
        selectModoAlarma.addEventListener('change', (e) => {
            const modoSel = e.target.value;
            if (typeof window.cambiarModoAlertaGlobal === 'function') {
                window.cambiarModoAlertaGlobal(modoSel);
            }
            guardarConfiguracion('cybershield_modo_alerta', modoSel, `Modo de alarma: ${selectModoAlarma.options[selectModoAlarma.selectedIndex].text}`);
        });
    }

    function obtenerParametrosAcusticosActuales() {
        const perfil = selectPerfilVoz ? selectPerfilVoz.value : 'voz_pe_alex';
        const frase = (inputFraseTexto ? inputFraseTexto.value : '').trim() || 'Peligro. El sistema está sufriendo un ataque.';
        const tonoPorDefecto = obtenerTonoPorDefecto(perfil).toFixed(2);
        const tono = sliderTono ? (parseFloat(sliderTono.value) / 100.0).toFixed(2) : (localStorage.getItem('cybershield_tono_voz') || tonoPorDefecto);
        const velocidad = sliderVelocidad ? (parseFloat(sliderVelocidad.value) / 100.0).toFixed(2) : (localStorage.getItem('cybershield_velocidad_voz') || VELOCIDAD_POR_DEFECTO);
        return { perfil, frase, tono, velocidad };
    }

    function precargarAudioNeural(perfil, texto, tono, velocidad) {
        const modoActual = localStorage.getItem('cybershield_modo_alerta') || 'intimidante';
        if (modoActual !== 'intimidante') return;
        const { perfil: pDef, frase: tDef, tono: tonoDef, velocidad: velDef } = obtenerParametrosAcusticosActuales();
        const p = perfil || pDef;
        const t = texto || tDef;
        const pt = tono || tonoDef;
        const rt = velocidad || velDef;
        fetch(`/api/tts/audio?voice=${encodeURIComponent(p)}&text=${encodeURIComponent(t)}&pitch=${encodeURIComponent(pt)}&rate=${encodeURIComponent(rt)}`).catch(() => {});
    }

    if (selectPerfilVoz) {
        selectPerfilVoz.addEventListener('change', (e) => {
            const perfil = e.target.value;
            const nuevoTono = obtenerTonoPorDefecto(perfil);
            if (sliderTono) {
                sliderTono.value = Math.round(nuevoTono * 100);
                if (badgeTono) badgeTono.innerText = textoTono(nuevoTono);
            }
            // Actualizar cybershield_tono_voz ANTES de despachar el evento storage (P3-11)
            localStorage.setItem('cybershield_tono_voz', nuevoTono.toFixed(2));
            guardarConfiguracion('cybershield_perfil_voz', perfil, `Voz cambiada a: ${selectPerfilVoz.options[selectPerfilVoz.selectedIndex].text}`);

            precargarAudioNeural(perfil, null, nuevoTono.toFixed(2), null);
        });
    }

    if (sliderTono) {
        sliderTono.addEventListener('input', (e) => {
            const factor = parseFloat(e.target.value) / 100.0;
            if (badgeTono) badgeTono.innerText = textoTono(factor);
        });
        sliderTono.addEventListener('change', (e) => {
            const factor = parseFloat(e.target.value) / 100.0;
            guardarConfiguracion('cybershield_tono_voz', factor.toFixed(2), `Tono de voz ajustado: ${factor.toFixed(2)}x`);
            precargarAudioNeural(null, null, factor.toFixed(2), null);
        });
    }

    if (sliderVelocidad) {
        sliderVelocidad.addEventListener('input', (e) => {
            const factor = parseFloat(e.target.value) / 100.0;
            if (badgeVelocidad) badgeVelocidad.innerText = textoVelocidad(factor);
        });
        sliderVelocidad.addEventListener('change', (e) => {
            const factor = parseFloat(e.target.value) / 100.0;
            guardarConfiguracion('cybershield_velocidad_voz', factor.toFixed(2), `Velocidad ajustada: ${factor.toFixed(2)}x`);
            precargarAudioNeural(null, null, null, factor.toFixed(2));
        });
    }

    if (selectPlantillaFrase) {
        selectPlantillaFrase.addEventListener('change', (e) => {
            const clave = e.target.value;
            if (clave in PLANTILLAS) {
                const fraseSeleccionada = PLANTILLAS[clave];
                if (inputFraseTexto) inputFraseTexto.value = fraseSeleccionada;
                guardarConfiguracion('cybershield_frase_texto', fraseSeleccionada, 'Plantilla de frase aplicada');
                precargarAudioNeural(null, fraseSeleccionada, null, null);
            } else {
                if (inputFraseTexto) {
                    inputFraseTexto.focus();
                    inputFraseTexto.select();
                }
            }
        });
    }

    if (inputFraseTexto) {
        let temporizadorAutoguardado = null;
        inputFraseTexto.addEventListener('input', (e) => {
            const texto = e.target.value.trim();
            if (selectPlantillaFrase) {
                let coincidencia = 'custom';
                for (const [clave, t] of Object.entries(PLANTILLAS)) {
                    if (t.trim().toLowerCase() === texto.toLowerCase()) {
                        coincidencia = clave;
                        break;
                    }
                }
                selectPlantillaFrase.value = coincidencia;
            }

            if (temporizadorAutoguardado) clearTimeout(temporizadorAutoguardado);
            temporizadorAutoguardado = setTimeout(() => {
                if (texto) {
                    localStorage.setItem('cybershield_frase_texto', texto);
                    precargarAudioNeural(null, texto, null, null);
                }
            }, 350);
        });
    }

    window.guardarFraseTexto = function () {
        if (!inputFraseTexto) return;
        const texto = inputFraseTexto.value.trim();
        if (!texto) {
            mostrarToastGuardado('Por favor escribe una frase válida', true);
            return;
        }
        guardarConfiguracion('cybershield_frase_texto', texto, 'Frase de emergencia guardada con éxito');

        const modoActual = localStorage.getItem('cybershield_modo_alerta') || 'intimidante';
        if (modoActual !== 'intimidante') return;

        mostrarToastGuardado('Guardando frase y modulando audio neural en español...', false);
        const { perfil, tono, velocidad } = obtenerParametrosAcusticosActuales();
        fetch(`/api/tts/audio?voice=${encodeURIComponent(perfil)}&text=${encodeURIComponent(texto)}&pitch=${encodeURIComponent(tono)}&rate=${encodeURIComponent(velocidad)}`).then((resp) => {
            if (!verificarRespuesta(resp)) return;
            mostrarToastGuardado('Audio neural listo y guardado', false);
        }).catch(() => {});
    };

    if (sliderVolumen) {
        sliderVolumen.addEventListener('input', (e) => {
            const valor = e.target.value;
            if (badgeVolumen) badgeVolumen.innerText = `${valor}%`;
        });
        sliderVolumen.addEventListener('change', (e) => {
            const factor = parseFloat(e.target.value) / 100.0;
            guardarConfiguracion('cybershield_volumen_alerta', factor.toString(), `Volumen establecido al ${e.target.value}%`);
        });
    }

    if (switchDestello) {
        switchDestello.addEventListener('change', (e) => {
            guardarConfiguracion('cybershield_destello_activo', e.target.checked ? 'true' : 'false',
                e.target.checked ? 'Destello perimetral carmesí activado' : 'Destello perimetral desactivado');
        });
    }

    if (switchBanner) {
        switchBanner.addEventListener('change', (e) => {
            guardarConfiguracion('cybershield_banner_activo', e.target.checked ? 'true' : 'false',
                e.target.checked ? 'Banner flotante superior activado' : 'Banner flotante desactivado');
        });
    }

    // Sincronización confirmada con servidor para el Umbral Conv1D (P3-08)
    if (selectUmbralDDoS) {
        selectUmbralDDoS.addEventListener('change', async (e) => {
            const valorAnterior = umbralConfirmadoServidor;
            const valUmbral = parseFloat(e.target.value);
            if (!Number.isFinite(valUmbral)) {
                aplicarValorUmbralEnSelect(valorAnterior);
                return;
            }
            selectUmbralDDoS.disabled = true;
            try {
                const resp = await fetch('/api/settings/threshold', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ threshold_percent: valUmbral })
                });
                if (resp.status === 401) {
                    verificarRespuesta(resp);
                    return;
                }
                const datos = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    aplicarValorUmbralEnSelect(valorAnterior);
                    mostrarToastGuardado(datos.detail || `Error actualizando umbral en servidor. Revertido a ${valorAnterior}%.`, true);
                    return;
                }
                const confirmado = Number.isFinite(Number(datos.threshold_percent))
                    ? String(Math.round(Number(datos.threshold_percent)))
                    : String(Math.round(valUmbral));
                umbralConfirmadoServidor = confirmado;
                aplicarValorUmbralEnSelect(confirmado);
                guardarConfiguracion('cybershield_umbral_ddos', confirmado, `Umbral de detección Conv1D confirmado: ${confirmado}%`);
            } catch (_) {
                aplicarValorUmbralEnSelect(valorAnterior);
                mostrarToastGuardado(`Sin conexión con el servidor. Umbral revertido a ${valorAnterior}%.`, true);
            } finally {
                selectUmbralDDoS.disabled = false;
            }
        });
    }

    // 5. Pruebas de Audio y Voz
    window.probarVozYFraseActual = function () {
        const { perfil, frase, tono, velocidad } = obtenerParametrosAcusticosActuales();
        const factorVolumen = sliderVolumen ? parseFloat(sliderVolumen.value) / 100.0 : 0.85;

        localStorage.setItem('cybershield_frase_texto', frase);
        localStorage.setItem('cybershield_tono_voz', tono);
        localStorage.setItem('cybershield_velocidad_voz', velocidad);

        const textoVoz = selectPerfilVoz ? selectPerfilVoz.options[selectPerfilVoz.selectedIndex].text : 'Voz Neural';
        mostrarToastGuardado(`Generando voz neural en español: ${textoVoz} (${tono}x, ${velocidad}x)...`, false);

        const urlAudio = `/api/tts/audio?voice=${encodeURIComponent(perfil)}&text=${encodeURIComponent(frase)}&pitch=${encodeURIComponent(tono)}&rate=${encodeURIComponent(velocidad)}`;

        try {
            if (window.audioPruebaActual) {
                try { window.audioPruebaActual.pause(); } catch (_) {}
            }
            const aud = new Audio(urlAudio);
            aud.volume = factorVolumen;
            window.audioPruebaActual = aud;

            aud.play().then(() => {
                mostrarToastGuardado(`Reproduciendo voz neural: ${textoVoz} (Tono: ${tono}x, Vel: ${velocidad}x)`, false);
            }).catch((err) => {
                console.warn('Reproducción bloqueada por navegador:', err);
                mostrarToastGuardado('Haz clic en la pantalla para autorizar el audio', true);
            });
        } catch (e) {
            console.error('Error probando audio:', e);
        }
    };

    window.probarAlarmaCompleta = function () {
        const frase = (inputFraseTexto ? inputFraseTexto.value : '').trim() || 'Peligro. El sistema está sufriendo un ataque.';
        localStorage.setItem('cybershield_frase_texto', frase);
        if (typeof window.reproducirAlarmaGlobal === 'function') {
            window.reproducirAlarmaGlobal(frase, true);
            mostrarToastGuardado('Probando ciclo completo: Sirena Táctica + Voz Neural', false);
        } else {
            window.probarVozYFraseActual();
        }
    };

    // 6. Restablecimiento de Valores Predeterminados (sincronizado con POST /api/settings/threshold = 50)
    window.restablecerValoresFabrica = async function () {
        if (!confirm('¿Deseas restablecer todas las configuraciones a sus valores predeterminados?')) return;

        let umbralRestablecidoServidor = false;
        try {
            const resp = await fetch('/api/settings/threshold', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threshold_percent: 50 })
            });
            if (resp.status === 401) {
                verificarRespuesta(resp);
                return;
            }
            if (resp.ok) {
                umbralRestablecidoServidor = true;
                umbralConfirmadoServidor = '50';
            }
        } catch (_) {
            umbralRestablecidoServidor = false;
        }

        localStorage.removeItem('cybershield_tema_visual');
        localStorage.removeItem('cybershield_mostrar_consola');
        localStorage.removeItem('cybershield_mostrar_selector_alarma');
        localStorage.removeItem('cybershield_mostrar_swagger');
        localStorage.removeItem('cybershield_modo_alerta');
        localStorage.removeItem('cybershield_perfil_voz');
        localStorage.removeItem('cybershield_tono_voz');
        localStorage.removeItem('cybershield_velocidad_voz');
        localStorage.removeItem('cybershield_frase_texto');
        localStorage.removeItem('cybershield_volumen_alerta');
        localStorage.removeItem('cybershield_destello_activo');
        localStorage.removeItem('cybershield_banner_activo');
        if (umbralRestablecidoServidor) {
            localStorage.setItem('cybershield_umbral_ddos', '50');
        } else {
            localStorage.setItem('cybershield_umbral_ddos', umbralConfirmadoServidor);
        }

        if (typeof window.cambiarModoAlertaGlobal === 'function') {
            window.cambiarModoAlertaGlobal('intimidante');
        }

        cargarConfiguraciones();
        window.dispatchEvent(new Event('storage'));
        if (umbralRestablecidoServidor) {
            mostrarToastGuardado('Valores predeterminados restablecidos (umbral Conv1D en 50%)', false);
        } else {
            mostrarToastGuardado(`Preferencias locales restablecidas, pero no se pudo restablecer el umbral en el servidor (sigue en ${umbralConfirmadoServidor}%)`, true);
        }
    };

    // 7. Control del Módulo de Bloqueo Inteligente y Análisis SOAR (Contraseña Maestra)
    const switchModuloSoar = document.getElementById('switchModuloSoar');
    const badgeEstadoSoar = document.getElementById('badgeEstadoSoar');
    const panelAccesoRapidoSoar = document.getElementById('panelAccesoRapidoSoar');
    const modalElSoar = document.getElementById('modalClaveMaestraSoar');
    const inputClaveMaestraSoar = document.getElementById('inputClaveMaestraSoar');
    const alertaErrorClaveSoar = document.getElementById('alertaErrorClaveSoar');
    const textoErrorClaveSoar = document.getElementById('textoErrorClaveSoar');
    const btnConfirmarClaveSoar = document.getElementById('btnConfirmarClaveSoar');
    const btnCancelarModalSoar = document.getElementById('btnCancelarModalSoar');
    const btnCerrarModalSoar = document.getElementById('btnCerrarModalSoar');
    const descModalSoar = document.getElementById('descModalSoar');

    let estadoConfirmadoSoar = false;
    let estadoObjetivoSoar = false;

    function abrirModalSoar() {
        if (!modalElSoar) return;
        modalElSoar.classList.remove('d-none');
        if (alertaErrorClaveSoar) alertaErrorClaveSoar.classList.add('d-none');
        if (inputClaveMaestraSoar) {
            inputClaveMaestraSoar.value = '';
            setTimeout(() => inputClaveMaestraSoar.focus(), 60);
        }
    }

    function cerrarModalSoar() {
        if (!modalElSoar) return;
        modalElSoar.classList.add('d-none');
        if (switchModuloSoar) switchModuloSoar.checked = estadoConfirmadoSoar;
    }

    function reflejarEstadoVisualSoar(activo) {
        estadoConfirmadoSoar = Boolean(activo);
        if (switchModuloSoar) switchModuloSoar.checked = estadoConfirmadoSoar;
        if (badgeEstadoSoar) {
            badgeEstadoSoar.textContent = '';
            const ic = document.createElement('i');
            const sp = document.createElement('span');
            if (estadoConfirmadoSoar) {
                badgeEstadoSoar.className = 'badge bg-success-subtle text-success badge-value';
                ic.className = 'bi bi-shield-fill-check me-1';
                sp.textContent = 'Activo (SOAR + IPS)';
            } else {
                badgeEstadoSoar.className = 'badge bg-secondary-subtle text-secondary badge-value';
                ic.className = 'bi bi-lock-fill me-1';
                sp.textContent = 'Desactivado (Aislado)';
            }
            badgeEstadoSoar.append(ic, sp);
        }
        if (panelAccesoRapidoSoar) {
            if (estadoConfirmadoSoar) {
                panelAccesoRapidoSoar.classList.remove('d-none');
            } else {
                panelAccesoRapidoSoar.classList.add('d-none');
            }
        }
        localStorage.setItem('cybershield_soar_activo', estadoConfirmadoSoar ? 'true' : 'false');
        if (typeof window.aplicarPreferenciasInterfaz === 'function') {
            window.aplicarPreferenciasInterfaz();
        }
    }

    window.solicitarAutorizacionSoar = function (evento) {
        if (evento) {
            evento.preventDefault();
            evento.stopPropagation();
        }
        estadoObjetivoSoar = !estadoConfirmadoSoar;
        if (switchModuloSoar) switchModuloSoar.checked = estadoConfirmadoSoar;

        if (descModalSoar) {
            descModalSoar.textContent = estadoObjetivoSoar
                ? 'Ingrese la Contraseña Maestra para ACTIVAR el Módulo de Investigación SOAR y habilitar el Centro de Mitigación en el menú.'
                : 'Ingrese la Contraseña Maestra para DESACTIVAR el Módulo SOAR. El Candado 4 eliminará automáticamente todas las reglas CyberShield_Block_* del Firewall.';
        }
        abrirModalSoar();
        return false;
    };

    async function cargarEstadoInicialSoar() {
        try {
            const resp = await fetch('/api/soar/status');
            if (!verificarRespuesta(resp)) {
                reflejarEstadoVisualSoar(false);
                return;
            }
            const datos = await resp.json();
            reflejarEstadoVisualSoar(Boolean(datos && datos.enabled));
        } catch (_) {
            reflejarEstadoVisualSoar(false);
        }
    }

    async function enviarValidacionClaveMaestra() {
        const clave = (inputClaveMaestraSoar ? inputClaveMaestraSoar.value : '').trim();
        if (!clave) {
            if (textoErrorClaveSoar) textoErrorClaveSoar.textContent = 'Debe ingresar la Contraseña Maestra';
            if (alertaErrorClaveSoar) alertaErrorClaveSoar.classList.remove('d-none');
            return;
        }

        if (btnConfirmarClaveSoar) btnConfirmarClaveSoar.disabled = true;
        try {
            const resp = await fetch('/api/soar/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enabled: estadoObjetivoSoar,
                    master_password: clave
                })
            });
            if (resp.status === 401) {
                verificarRespuesta(resp);
                return;
            }
            const datos = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                if (textoErrorClaveSoar) {
                    textoErrorClaveSoar.textContent = datos.detail || 'Contraseña Maestra incorrecta';
                }
                if (alertaErrorClaveSoar) alertaErrorClaveSoar.classList.remove('d-none');
                if (switchModuloSoar) switchModuloSoar.checked = estadoConfirmadoSoar;
                return;
            }

            cerrarModalSoar();
            reflejarEstadoVisualSoar(Boolean(datos.enabled));
            mostrarToastGuardado(datos.message || (datos.enabled ? 'Módulo SOAR activado' : 'Módulo SOAR desactivado y Firewall limpio'), false);
        } catch (err) {
            if (textoErrorClaveSoar) textoErrorClaveSoar.textContent = 'Error de conexión con el servidor';
            if (alertaErrorClaveSoar) alertaErrorClaveSoar.classList.remove('d-none');
            if (switchModuloSoar) switchModuloSoar.checked = estadoConfirmadoSoar;
        } finally {
            if (btnConfirmarClaveSoar) btnConfirmarClaveSoar.disabled = false;
        }
    }

    if (switchModuloSoar) {
        switchModuloSoar.addEventListener('change', (e) => {
            e.preventDefault();
            switchModuloSoar.checked = estadoConfirmadoSoar;
        });
    }
    if (btnConfirmarClaveSoar) {
        btnConfirmarClaveSoar.addEventListener('click', enviarValidacionClaveMaestra);
    }
    if (btnCancelarModalSoar) {
        btnCancelarModalSoar.addEventListener('click', cerrarModalSoar);
    }
    if (btnCerrarModalSoar) {
        btnCerrarModalSoar.addEventListener('click', cerrarModalSoar);
    }
    if (inputClaveMaestraSoar) {
        inputClaveMaestraSoar.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                enviarValidacionClaveMaestra();
            } else if (e.key === 'Escape') {
                cerrarModalSoar();
            }
        });
    }

    cargarConfiguraciones();
    cargarUmbralServidor();
    cargarEstadoSaludYModelo();
    cargarEstadoInicialSoar();
})();
