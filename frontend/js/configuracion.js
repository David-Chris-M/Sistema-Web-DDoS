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

    function esPerfilFemenino(perfil) {
        return perfil.includes('camila') || perfil.includes('dalia') || perfil.includes('elvira') || 
               perfil.includes('salome') || perfil.includes('paloma') || perfil.startsWith('femenin');
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

    // 2. Carga de Configuración desde localStorage
    function cargarConfiguraciones() {
        const temaGuardado = localStorage.getItem('cybershield_tema_visual') || 'claro';
        actualizarBotonesTema(temaGuardado);
        if (typeof window.aplicarPreferenciasInterfaz === 'function') {
            window.aplicarPreferenciasInterfaz();
        }

        const mostrarConsola = localStorage.getItem('cybershield_mostrar_consola') !== 'false';
        if (switchMostrarConsola) switchMostrarConsola.checked = mostrarConsola;

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
        const factorTono = tonoGuardado !== null ? parseFloat(tonoGuardado) : (esPerfilFemenino(perfil) ? 1.25 : 0.75);
        if (sliderTono) {
            sliderTono.value = Math.round(factorTono * 100);
            if (badgeTono) badgeTono.innerText = textoTono(factorTono);
        }

        const velGuardada = localStorage.getItem('cybershield_velocidad_voz');
        const factorVel = velGuardada !== null ? parseFloat(velGuardada) : 0.95;
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

        const umbral = localStorage.getItem('cybershield_umbral_ddos') || '50';
        if (selectUmbralDDoS) selectUmbralDDoS.value = umbral;
    }

    // 3. Persistencia de Configuración y Notificaciones
    function guardarConfiguracion(clave, valor, mensajeToast) {
        localStorage.setItem(clave, valor);
        if (typeof window.aplicarPreferenciasInterfaz === 'function') {
            window.aplicarPreferenciasInterfaz();
        }
        window.dispatchEvent(new Event('storage'));
        mostrarToastGuardado(mensajeToast || 'Preferencia guardada');
    }

    function mostrarToastGuardado(mensaje) {
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
        toast.innerHTML = `<i class="bi bi-check-circle-fill text-success fs-5"></i> <span>${mensaje}</span>`;
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';

        setTimeout(() => {
            if (toast) {
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(20px)';
            }
        }, 2600);
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
            guardarConfiguracion('cybershield_modo_alerta', e.target.value, `Modo de alarma: ${selectModoAlarma.options[selectModoAlarma.selectedIndex].text}`);
        });
    }

    function obtenerParametrosAcusticosActuales() {
        const perfil = selectPerfilVoz ? selectPerfilVoz.value : 'voz_pe_alex';
        const frase = (inputFraseTexto ? inputFraseTexto.value : '').trim() || 'Peligro. El sistema está sufriendo un ataque.';
        const tono = sliderTono ? (parseFloat(sliderTono.value) / 100.0).toFixed(2) : (localStorage.getItem('cybershield_tono_voz') || '1.00');
        const velocidad = sliderVelocidad ? (parseFloat(sliderVelocidad.value) / 100.0).toFixed(2) : (localStorage.getItem('cybershield_velocidad_voz') || '1.00');
        return { perfil, frase, tono, velocidad };
    }

    function precargarAudioNeural(perfil, texto, tono, velocidad) {
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
            guardarConfiguracion('cybershield_perfil_voz', perfil, `Voz cambiada a: ${selectPerfilVoz.options[selectPerfilVoz.selectedIndex].text}`);
            
            const nuevoTono = esPerfilFemenino(perfil) ? 1.25 : 0.75;
            if (sliderTono) {
                sliderTono.value = Math.round(nuevoTono * 100);
                if (badgeTono) badgeTono.innerText = textoTono(nuevoTono);
            }
            localStorage.setItem('cybershield_tono_voz', nuevoTono.toFixed(2));

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
            mostrarToastGuardado('Por favor escribe una frase válida');
            return;
        }
        guardarConfiguracion('cybershield_frase_texto', texto, 'Frase de emergencia guardada con éxito');

        mostrarToastGuardado('Guardando frase y modulando audio neural en español...');
        const { perfil, tono, velocidad } = obtenerParametrosAcusticosActuales();
        fetch(`/api/tts/audio?voice=${encodeURIComponent(perfil)}&text=${encodeURIComponent(texto)}&pitch=${encodeURIComponent(tono)}&rate=${encodeURIComponent(velocidad)}`).then(() => {
            mostrarToastGuardado('Audio neural listo y guardado');
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

    if (selectUmbralDDoS) {
        selectUmbralDDoS.addEventListener('change', (e) => {
            const valUmbral = parseFloat(e.target.value) || 75;
            guardarConfiguracion('cybershield_umbral_ddos', String(valUmbral), `Umbral de detección Conv1D: ${valUmbral}%`);
            fetch('/api/settings/threshold', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threshold_percent: valUmbral })
            }).catch(() => {});
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
        mostrarToastGuardado(`Generando voz neural en español: ${textoVoz} (${tono}x, ${velocidad}x)...`);

        const urlAudio = `/api/tts/audio?voice=${encodeURIComponent(perfil)}&text=${encodeURIComponent(frase)}&pitch=${encodeURIComponent(tono)}&rate=${encodeURIComponent(velocidad)}`;

        try {
            if (window.audioPruebaActual) {
                try { window.audioPruebaActual.pause(); } catch (_) {}
            }
            const aud = new Audio(urlAudio);
            aud.volume = factorVolumen;
            window.audioPruebaActual = aud;

            aud.play().then(() => {
                mostrarToastGuardado(`Reproduciendo voz neural: ${textoVoz} (Tono: ${tono}x, Vel: ${velocidad}x)`);
            }).catch((err) => {
                console.warn('Reproducción bloqueada por navegador:', err);
                mostrarToastGuardado('Haz clic en la pantalla para autorizar el audio');
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
            mostrarToastGuardado('Probando ciclo completo: Sirena Táctica + Voz Neural');
        } else {
            window.probarVozYFraseActual();
        }
    };

    // 6. Restablecimiento de Valores Predeterminados
    window.restablecerValoresFabrica = function () {
        if (!confirm('¿Deseas restablecer todas las configuraciones a sus valores predeterminados?')) return;

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
        localStorage.removeItem('cybershield_audio_frase');
        localStorage.removeItem('cybershield_destello_activo');
        localStorage.removeItem('cybershield_banner_activo');
        localStorage.removeItem('cybershield_umbral_ddos');

        cargarConfiguraciones();
        window.dispatchEvent(new Event('storage'));
        mostrarToastGuardado('Valores predeterminados restablecidos');
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
            if (estadoConfirmadoSoar) {
                badgeEstadoSoar.className = 'badge bg-success-subtle text-success badge-value';
                badgeEstadoSoar.innerHTML = '<i class="bi bi-shield-fill-check me-1"></i> Activo (SOAR + IPS)';
            } else {
                badgeEstadoSoar.className = 'badge bg-secondary-subtle text-secondary badge-value';
                badgeEstadoSoar.innerHTML = '<i class="bi bi-lock-fill me-1"></i> Desactivado (Aislado)';
            }
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
            if (!resp.ok) {
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
            mostrarToastGuardado(datos.message || (datos.enabled ? 'Módulo SOAR activado' : 'Módulo SOAR desactivado y Firewall limpio'));
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
    cargarEstadoInicialSoar();
})();
