(function () {
    'use strict';

    const kpiCuarentenaActiva = document.getElementById('kpiCuarentenaActiva');
    const kpiIncidentesSoar = document.getElementById('kpiIncidentesSoar');
    const kpiGatewayProtegido = document.getElementById('kpiGatewayProtegido');
    const subKpiCandado1 = document.getElementById('subKpiCandado1');
    const badgeTotalCuarentena = document.getElementById('badgeTotalCuarentena');
    const tbodyCuarentenaActiva = document.getElementById('tbodyCuarentenaActiva');
    const listaResumenCandado1 = document.getElementById('listaResumenCandado1');
    const contenedorFlujoCincoPasos = document.getElementById('contenedorFlujoCincoPasos');
    const switchAutobloqueoIps = document.getElementById('switchAutobloqueoIps');
    const inputIpManualBloquear = document.getElementById('inputIpManualBloquear');
    const selectProtoManualBloquear = document.getElementById('selectProtoManualBloquear');
    const selectDuracionManualBloquear = document.getElementById('selectDuracionManualBloquear');

    let cuarentenaLocal = [];

    function escaparHtml(texto) {
        return String(texto == null ? '' : texto)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatearSegundosMmSs(segundos) {
        const s = Math.max(0, parseInt(segundos, 10) || 0);
        const min = Math.floor(s / 60);
        const seg = s % 60;
        return `${String(min).padStart(2, '0')}:${String(seg).padStart(2, '0')}`;
    }

    function mostrarNotificacionSoar(mensaje, esError) {
        let toast = document.getElementById('toast-soar-accion');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'toast-soar-accion';
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
                box-shadow: 0 10px 25px rgba(0,0,0,0.3);
                border: 1px solid rgba(255,255,255,0.15);
                z-index: 100000;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: opacity 0.25s ease;
            `;
            document.body.appendChild(toast);
        }
        const icono = esError
            ? '<i class="bi bi-shield-fill-exclamation text-warning fs-5"></i>'
            : '<i class="bi bi-check-circle-fill text-success fs-5"></i>';
        toast.innerHTML = `${icono} <span>${escaparHtml(mensaje)}</span>`;
        toast.style.opacity = '1';
        setTimeout(() => {
            if (toast) toast.style.opacity = '0';
        }, 3500);
    }

    function actualizarUrlEdlModal(ipServidor) {
        const hostBase = window.location.host || `${ipServidor || '192.168.18.10'}:8000`;
        const urlCompleta = `${window.location.protocol}//${hostBase}/api/soar/blocklist.txt`;
        const urlLan = `http://${ipServidor || '192.168.18.10'}:8000/api/soar/blocklist.txt`;

        const inputUrl = document.getElementById('inputUrlBlocklistEdl');
        if (inputUrl) inputUrl.value = urlLan;

        const preMikrotik = document.getElementById('preComandoMikrotik');
        if (preMikrotik) {
            preMikrotik.textContent =
                `/ip firewall filter add chain=forward src-address-list=CyberShield_Block action=drop comment="CyberShield SOAR IPS Perimetral" place-before=0\n` +
                `/system scheduler add name="Sync_CyberShield_SOAR" interval=30s on-event="/tool fetch url=\\"${urlLan}\\" dst-path=cybershield.txt; :foreach ip in=[:toarray [/file get cybershield.txt contents]] do={ /ip firewall address-list add list=CyberShield_Block address=\\$ip timeout=15m }"`;
        }
    }

    window.copiarUrlBlocklistEdl = function () {
        const inputUrl = document.getElementById('inputUrlBlocklistEdl');
        if (!inputUrl) return;
        navigator.clipboard.writeText(inputUrl.value).then(() => {
            mostrarNotificacionSoar('URL del Feed Perimetral EDL copiada al portapapeles', false);
        }).catch(() => {
            inputUrl.select();
            document.execCommand('copy');
            mostrarNotificacionSoar('URL del Feed Perimetral EDL copiada', false);
        });
    };

    function renderizarTablaCuarentena() {
        if (!tbodyCuarentenaActiva) return;
        if (kpiCuarentenaActiva) kpiCuarentenaActiva.textContent = String(cuarentenaLocal.length);
        if (badgeTotalCuarentena) {
            badgeTotalCuarentena.textContent = `${cuarentenaLocal.length} ${cuarentenaLocal.length === 1 ? 'regla activa' : 'reglas activas'}`;
        }

        if (!cuarentenaLocal.length) {
            tbodyCuarentenaActiva.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">
                        <i class="bi bi-shield-check text-success fs-4 d-block mb-1"></i>
                        No hay direcciones IP en cuarentena en este momento.
                    </td>
                </tr>
            `;
            return;
        }

        tbodyCuarentenaActiva.innerHTML = cuarentenaLocal.map((item) => {
            const ip = escaparHtml(item.ip);
            const mac = escaparHtml(item.mac || 'N/A (WAN)');
            const ident = escaparHtml(item.identity || 'Host Externo');
            const regla = escaparHtml(item.rule_name || `CyberShield_Block_${ip}`);
            const esPermanente = Boolean(item.is_permanent);

            const htmlExpiracion = esPermanente
                ? `<span class="permanent-pill" title="Bloqueo indefinido hasta que el operador presione Desbloquear IP">
                       <i class="bi bi-infinity me-1"></i>Permanente (Manual)
                   </span>`
                : `<span class="countdown-pill" data-ip-countdown="${ip}">
                       <i class="bi bi-clock-history me-1"></i>15m (${formatearSegundosMmSs(item.remaining_seconds)})
                   </span>`;

            return `
                <tr>
                    <td class="fw-bold text-danger">
                        <i class="bi bi-slash-circle-fill me-1"></i>${ip}
                    </td>
                    <td><code>${mac}</code></td>
                    <td>${ident}</td>
                    <td><span class="badge bg-dark-subtle text-dark font-monospace">${regla}</span></td>
                    <td>${htmlExpiracion}</td>
                    <td class="text-end">
                        <button class="btn btn-sm btn-outline-success rounded-pill px-3 fw-semibold" onclick="desbloquearIpAccion('${ip}')">
                            <i class="bi bi-unlock-fill me-1"></i> Desbloquear IP
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function renderizarFlujoCincoPasos(eventos) {
        if (!contenedorFlujoCincoPasos) return;
        if (kpiIncidentesSoar) kpiIncidentesSoar.textContent = String(eventos.length);

        if (!eventos.length) {
            contenedorFlujoCincoPasos.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="bi bi-radar fs-3 d-block mb-2 text-info"></i>
                    Sin incidentes recientes registrados en la sesión SOAR. Inyecte una prueba o ingrese una IP arriba.
                </div>
            `;
            return;
        }

        contenedorFlujoCincoPasos.innerHTML = eventos.map((ev, idx) => {
            const ip = escaparHtml(ev.src_ip);
            const proto = escaparHtml(ev.protocol || 'TCP');
            const conf = Number(ev.confidence_percentage || 99).toFixed(1);
            const bloqueada = Boolean(ev.is_blocked);
            const esPerm = Boolean(ev.is_permanent);
            const s = ev.steps || {};
            const p1 = s.step1_ttl || {};
            const p2 = s.step2_lan || {};
            const p3 = s.step3_wan || {};
            const p4 = s.step4_sans || {};
            const p5 = s.step5_firewall || {};
            const idSelectTarjeta = `selDurCard_${idx}`;

            const btnAccion = bloqueada
                ? `<button class="btn btn-sm btn-success rounded-pill px-3 fw-semibold" onclick="desbloquearIpAccion('${ip}')">
                       <i class="bi bi-unlock-fill me-1"></i> Desbloquear IP
                   </button>`
                : `<div class="d-flex align-items-center gap-1">
                       <select class="form-select form-select-sm rounded-pill" id="${idSelectTarjeta}" style="width: auto; font-size: 0.76rem;">
                           <option value="permanent" selected>Permanente</option>
                           <option value="15m">15 min</option>
                       </select>
                       <button class="btn btn-sm btn-danger rounded-pill px-3 fw-semibold" onclick="bloquearIpDesdeTarjeta('${ip}', '${proto}', '${idSelectTarjeta}')">
                           <i class="bi bi-shield-fill-x me-1"></i> Aislar IP
                       </button>
                   </div>`;

            const textoEstadoBloqueo = esPerm
                ? 'BLOQUEADA (PERMANENTE)'
                : `BLOQUEADA (15m: ${formatearSegundosMmSs(ev.remaining_seconds || 900)})`;

            const badgeEstado = bloqueada
                ? `<span class="badge bg-danger"><i class="bi bi-lock-fill me-1"></i>${textoEstadoBloqueo}</span>`
                : `<span class="badge bg-secondary"><i class="bi bi-eye me-1"></i>MONITOREADA</span>`;

            const alertaVmNatHtml = p2.nat_vm_warning
                ? `<div class="mt-1"><span class="badge bg-warning text-dark"><i class="bi bi-exclamation-triangle-fill me-1"></i>${escaparHtml(p2.nat_vm_warning)}</span></div>`
                : '';

            const naturalezaWanHtml = (p3.applicable && p3.attacker_type)
                ? `<div class="mt-1"><span class="badge ${String(p3.attacker_type).includes('VPS') ? 'bg-danger-subtle text-danger border border-danger-subtle' : 'bg-info-subtle text-info'}">${escaparHtml(p3.attacker_type)}</span></div>`
                : '';

            return `
                <div class="border rounded-3 p-3 mb-3 shadow-sm">
                    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3 pb-2 border-bottom">
                        <div class="d-flex align-items-center gap-2 flex-wrap">
                            <span class="badge bg-dark font-monospace fs-6 px-3 py-1">${ip}</span>
                            <span class="badge bg-danger-subtle text-danger fw-bold">${proto} • Confianza ${conf}%</span>
                            <span class="badge ${ev.is_lan ? 'bg-info-subtle text-info' : 'bg-warning-subtle text-warning'}">
                                ${ev.is_lan ? 'Origen Red Local (LAN)' : 'Origen Público (WAN)'}
                            </span>
                            ${badgeEstado}
                        </div>
                        <div>${btnAccion}</div>
                    </div>

                    <div class="row g-2">
                        <!-- Paso 1 -->
                        <div class="col-md-4 col-lg">
                            <div class="step-box">
                                <div class="d-flex align-items-center gap-2 mb-1">
                                    <span class="step-number ${p1.spoofing_suspect ? 'bg-warning text-dark' : 'bg-primary text-white'}">1</span>
                                    <span class="fw-bold small">Anti-Spoofing TTL</span>
                                </div>
                                <div class="badge ${p1.spoofing_suspect ? 'bg-warning-subtle text-warning' : 'bg-success-subtle text-success'} mb-1">
                                    ${escaparHtml(p1.badge || 'Verificado')}
                                </div>
                                <div class="text-secondary" style="font-size: 0.75rem;">
                                    ${escaparHtml(p1.detail || '')}
                                </div>
                            </div>
                        </div>

                        <!-- Paso 2 -->
                        <div class="col-md-4 col-lg">
                            <div class="step-box">
                                <div class="d-flex align-items-center gap-2 mb-1">
                                    <span class="step-number ${p2.applicable ? 'bg-info text-white' : 'bg-secondary text-white'}">2</span>
                                    <span class="fw-bold small">Forense LAN (OUI/VM)</span>
                                </div>
                                <div class="badge ${p2.applicable ? 'bg-info-subtle text-info' : 'bg-secondary-subtle text-secondary'} mb-1">
                                    ${escaparHtml(p2.badge || 'N/A')}
                                </div>
                                <div class="text-secondary" style="font-size: 0.75rem;">
                                    ${escaparHtml(p2.detail || '')}
                                    ${alertaVmNatHtml}
                                </div>
                            </div>
                        </div>

                        <!-- Paso 3 -->
                        <div class="col-md-4 col-lg">
                            <div class="step-box">
                                <div class="d-flex align-items-center gap-2 mb-1">
                                    <span class="step-number ${p3.applicable ? 'bg-primary text-white' : 'bg-secondary text-white'}">3</span>
                                    <span class="fw-bold small">Origen WAN (VPS/ISP)</span>
                                </div>
                                <div class="badge ${p3.applicable ? 'bg-primary-subtle text-primary' : 'bg-secondary-subtle text-secondary'} mb-1">
                                    ${escaparHtml(p3.badge || 'N/A')}
                                </div>
                                <div class="text-secondary" style="font-size: 0.75rem;">
                                    ${escaparHtml(p3.detail || '')}
                                    ${naturalezaWanHtml}
                                </div>
                            </div>
                        </div>

                        <!-- Paso 4 -->
                        <div class="col-md-6 col-lg">
                            <div class="step-box">
                                <div class="d-flex align-items-center gap-2 mb-1">
                                    <span class="step-number ${p4.malicious ? 'bg-danger text-white' : 'bg-primary text-white'}">4</span>
                                    <span class="fw-bold small">SANS ISC DShield</span>
                                </div>
                                <div class="badge ${p4.malicious ? 'bg-danger-subtle text-danger' : 'bg-secondary-subtle text-secondary'} mb-1">
                                    ${escaparHtml(p4.badge || 'Consultado')}
                                </div>
                                <div class="text-secondary" style="font-size: 0.75rem;">
                                    ${escaparHtml(p4.detail || '')}
                                </div>
                            </div>
                        </div>

                        <!-- Paso 5 -->
                        <div class="col-md-6 col-lg">
                            <div class="step-box">
                                <div class="d-flex align-items-center gap-2 mb-1">
                                    <span class="step-number ${bloqueada ? 'bg-danger text-white' : 'bg-success text-white'}">5</span>
                                    <span class="fw-bold small">Firewall (4 Candados)</span>
                                </div>
                                <div class="badge ${bloqueada ? 'bg-danger-subtle text-danger' : 'bg-success-subtle text-success'} mb-1">
                                    ${escaparHtml(p5.badge || 'Evaluado')}
                                </div>
                                <div class="text-secondary" style="font-size: 0.75rem;">
                                    ${escaparHtml(p5.detail || '')}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function cargarDashboardSoar() {
        try {
            const resp = await fetch('/api/soar/dashboard');
            if (resp.status === 403) {
                localStorage.setItem('cybershield_soar_activo', 'false');
                window.location.href = '/frontend/configuracion.html';
                return;
            }
            if (!resp.ok) return;
            const datos = await resp.json();

            if (switchAutobloqueoIps) {
                switchAutobloqueoIps.checked = Boolean(datos.auto_block);
            }

            actualizarUrlEdlModal(datos.primary_local_ip || '192.168.18.10');

            const c1 = datos.lock1_protected || {};
            if (kpiGatewayProtegido && c1.primary_gateway) {
                kpiGatewayProtegido.textContent = `Router ${c1.primary_gateway} Protegido`;
            }
            if (subKpiCandado1 && Array.isArray(c1.local_ips)) {
                const nSalientes = Number(c1.active_outbound_sessions_count || 0);
                subKpiCandado1.textContent = `Host + CDNs + ${nSalientes} sesiones salientes`;
            }
            if (listaResumenCandado1) {
                const ipsLocales = (c1.local_ips || []).join(', ');
                const gws = (c1.gateways || []).join(', ');
                const dns = (c1.dns_servers || []).slice(0, 3).join(', ');
                const nSalientes = Number(c1.active_outbound_sessions_count || 0);
                listaResumenCandado1.innerHTML = `
                    <div>• <strong>Servidor Local:</strong> <code>${escaparHtml(ipsLocales)}</code></div>
                    <div>• <strong>Gateway/Router:</strong> <code>${escaparHtml(gws)}</code></div>
                    <div>• <strong>DNS / Loopback:</strong> <code>127.0.0.1, ${escaparHtml(dns)}</code></div>
                    <div>• <strong>CDNs:</strong> Cloudflare, Google, Oracle/Zoom</div>
                    <div>• <strong>Sesiones Salientes Confirmadas:</strong> <span class="text-success fw-semibold">Protección Dinámica Activa (${nSalientes} IPs)</span></div>
                `;
            }

            cuarentenaLocal = Array.isArray(datos.quarantine) ? datos.quarantine : [];
            renderizarTablaCuarentena();
            renderizarFlujoCincoPasos(Array.isArray(datos.events) ? datos.events : []);
        } catch (_) {}
    }

    window.bloquearIpAccion = async function (ip, protocolo, modoDuracion) {
        if (!ip) return;
        const duracion = modoDuracion || 'permanent';
        try {
            const resp = await fetch('/api/soar/block', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: ip.trim(),
                    protocol: protocolo || 'TCP',
                    duration_mode: duracion
                })
            });
            const datos = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                mostrarNotificacionSoar(datos.detail || 'No se pudo bloquear la IP (Candado 1)', true);
                return;
            }
            const etqDur = datos.is_permanent ? 'Permanentemente (Hasta desbloqueo manual)' : 'por 15 minutos';
            mostrarNotificacionSoar(`IP ${ip} aislada en Firewall (${datos.rule_name}) ${etqDur}`, false);
            await cargarDashboardSoar();
        } catch (_) {
            mostrarNotificacionSoar('Error de comunicación con el motor SOAR', true);
        }
    };

    window.bloquearIpDesdeTarjeta = async function (ip, protocolo, idSelector) {
        const elSel = idSelector ? document.getElementById(idSelector) : null;
        const modo = elSel ? elSel.value : 'permanent';
        await window.bloquearIpAccion(ip, protocolo, modo);
    };

    window.desbloquearIpAccion = async function (ip) {
        if (!ip) return;
        try {
            const resp = await fetch('/api/soar/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip.trim(), protocol: 'TCP' })
            });
            const datos = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                mostrarNotificacionSoar(datos.detail || 'No se pudo desbloquear la IP', true);
                return;
            }
            mostrarNotificacionSoar(`IP ${ip} desbloqueada inmediatamente y regla ${datos.rule_name} eliminada`, false);
            await cargarDashboardSoar();
        } catch (_) {
            mostrarNotificacionSoar('Error al desbloquear IP', true);
        }
    };

    window.bloquearIpManualInput = async function () {
        const ip = (inputIpManualBloquear ? inputIpManualBloquear.value : '').trim();
        const proto = selectProtoManualBloquear ? selectProtoManualBloquear.value : 'TCP';
        const modoDur = selectDuracionManualBloquear ? selectDuracionManualBloquear.value : 'permanent';
        if (!ip) {
            mostrarNotificacionSoar('Ingrese una dirección IP válida para investigar y bloquear', true);
            return;
        }
        await window.bloquearIpAccion(ip, proto, modoDur);
        if (inputIpManualBloquear) inputIpManualBloquear.value = '';
    };

    if (switchAutobloqueoIps) {
        switchAutobloqueoIps.addEventListener('change', async (e) => {
            const activo = e.target.checked;
            try {
                const resp = await fetch('/api/soar/autoblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auto_block: activo })
                });
                if (resp.ok) {
                    mostrarNotificacionSoar(
                        activo
                            ? 'Autobloqueo Inteligente IPS activado (Expiración 15m automática)'
                            : 'Modo Manual: Investigará los 5 pasos y esperará su clic para bloqueo Permanente o 15m',
                        false
                    );
                }
            } catch (_) {}
        });
    }

    // Reloj de cuenta regresiva en tiempo real (1 segundo) solo para reglas temporales (15m)
    setInterval(() => {
        if (!cuarentenaLocal.length) return;
        let expiroAlguna = false;
        cuarentenaLocal.forEach((item) => {
            if (item.is_permanent) return;
            if (item.remaining_seconds > 0) {
                item.remaining_seconds -= 1;
            }
            if (item.remaining_seconds <= 0) {
                expiroAlguna = true;
            }
            const pill = document.querySelector(`[data-ip-countdown="${CSS.escape(item.ip)}"]`);
            if (pill) {
                pill.innerHTML = `<i class="bi bi-clock-history me-1"></i>15m (${formatearSegundosMmSs(item.remaining_seconds)})`;
            }
        });
        if (expiroAlguna) {
            cargarDashboardSoar();
        }
    }, 1000);

    window.cargarDashboardSoar = cargarDashboardSoar;
    cargarDashboardSoar();
    setInterval(cargarDashboardSoar, 4000);
})();
