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
    const inputBuscarCuarentena = document.getElementById('inputBuscarCuarentena');
    const selectFiltroCuarentena = document.getElementById('selectFiltroCuarentena');
    const inputBuscarEventosSoar = document.getElementById('inputBuscarEventosSoar');
    const selectFiltroEstadoEventos = document.getElementById('selectFiltroEstadoEventos');

    let cuarentenaLocal = [];
    let eventosLocal = [];
    let dashboardEnVuelo = false;
    let refrescoPendiente = false;
    let ultimoRefrescoExpiracionMs = 0;
    let temporizadorToastSoar = null;
    const COOLDOWN_EXPIRACION_MS = 3000;
    const duracionSeleccionadaPorIp = new Map();

    function escaparHtml(texto) {
        return String(texto == null ? '' : texto)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function verificarSesion401(resp) {
        if (resp && resp.status === 401) {
            if (typeof window.manejarSesionExpirada === 'function') {
                window.manejarSesionExpirada();
            } else {
                window.location.replace('/frontend/login.html');
            }
            return true;
        }
        return false;
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
        toast.textContent = '';
        const icono = document.createElement('i');
        icono.className = esError
            ? 'bi bi-shield-fill-exclamation text-warning fs-5'
            : 'bi bi-check-circle-fill text-success fs-5';
        const spanTxt = document.createElement('span');
        spanTxt.textContent = String(mensaje ?? '');
        toast.append(icono, spanTxt);
        toast.style.opacity = '1';

        if (temporizadorToastSoar) clearTimeout(temporizadorToastSoar);
        temporizadorToastSoar = setTimeout(() => {
            if (toast) toast.style.opacity = '0';
            temporizadorToastSoar = null;
        }, 3500);
    }

    // Construcción dinámica de URL EDL respetando protocolo y puerto reales + primary_local_ip en loopback (P3-10)
    function construirUrlEdlDinamica(ipServidor) {
        const protocolo = window.location.protocol || 'http:';
        const hostnameActual = (window.location.hostname || '').trim();
        const puertoActual = window.location.port ? `:${window.location.port}` : '';
        const esLoopbackLocal = !hostnameActual ||
            hostnameActual === 'localhost' ||
            hostnameActual === '127.0.0.1' ||
            hostnameActual === '::1' ||
            hostnameActual === '[::1]';
        const ipLocalReal = (ipServidor && String(ipServidor).trim()) ? String(ipServidor).trim() : '';
        const hostObjetivo = (esLoopbackLocal && ipLocalReal) ? ipLocalReal : (hostnameActual || '127.0.0.1');
        const hostFormateado = hostObjetivo.includes(':') && !hostObjetivo.startsWith('[')
            ? `[${hostObjetivo}]`
            : hostObjetivo;
        return `${protocolo}//${hostFormateado}${puertoActual}/api/soar/blocklist.txt`;
    }

    function actualizarUrlEdlModal(ipServidor) {
        const urlEdl = construirUrlEdlDinamica(ipServidor);

        const inputUrl = document.getElementById('inputUrlBlocklistEdl');
        if (inputUrl) inputUrl.value = urlEdl;

        const preMikrotik = document.getElementById('preComandoMikrotik');
        if (preMikrotik) {
            preMikrotik.textContent =
                `/ip firewall filter add chain=forward src-address-list=CyberShield_Block action=drop comment="CyberShield SOAR IPS Perimetral" place-before=0\n` +
                `/system scheduler add name="Sync_CyberShield_SOAR" interval=30s on-event="/tool fetch url=\\"${urlEdl}\\" dst-path=cybershield.txt; :foreach ip in=[:toarray [/file get cybershield.txt contents]] do={ /ip firewall address-list add list=CyberShield_Block address=\\$ip timeout=15m }"`;
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

    function normalizarTextoBusqueda(txt) {
        return String(txt || '').toLowerCase().trim();
    }

    function filtrarItemsCuarentena(lista) {
        const q = normalizarTextoBusqueda(inputBuscarCuarentena ? inputBuscarCuarentena.value : '');
        const qMac = q.replace(/:/g, '-');
        const filtroTipo = selectFiltroCuarentena ? selectFiltroCuarentena.value : 'all';

        return lista.filter((item) => {
            const esLan = item.is_lan !== undefined
                ? Boolean(item.is_lan)
                : (String(item.mac || '').includes('-') && !String(item.mac || '').includes('WAN'));
            const esPerm = Boolean(item.is_permanent);

            if (filtroTipo === 'lan' && !esLan) return false;
            if (filtroTipo === 'wan' && esLan) return false;
            if (filtroTipo === 'permanent' && !esPerm) return false;
            if (filtroTipo === '15m' && esPerm) return false;

            if (!q) return true;

            const campos = [
                item.ip,
                item.mac,
                String(item.mac || '').replace(/-/g, ':'),
                item.hostname,
                item.vendor,
                item.device_nature,
                item.identity,
                item.protocol,
                item.rule_name,
                item.mode,
                item.country,
                item.asn
            ].map(normalizarTextoBusqueda);

            return campos.some((c) => c.includes(q) || (qMac && c.includes(qMac)));
        });
    }

    function renderizarTablaCuarentena() {
        if (!tbodyCuarentenaActiva) return;
        if (kpiCuarentenaActiva) kpiCuarentenaActiva.textContent = String(cuarentenaLocal.length);

        const filtrados = filtrarItemsCuarentena(cuarentenaLocal);

        if (badgeTotalCuarentena) {
            if (filtrados.length !== cuarentenaLocal.length) {
                badgeTotalCuarentena.textContent = `${filtrados.length} de ${cuarentenaLocal.length} reglas`;
            } else {
                badgeTotalCuarentena.textContent = `${cuarentenaLocal.length} ${cuarentenaLocal.length === 1 ? 'regla activa' : 'reglas activas'}`;
            }
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

        if (!filtrados.length) {
            const termino = escaparHtml(inputBuscarCuarentena ? inputBuscarCuarentena.value : '');
            tbodyCuarentenaActiva.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">
                        <i class="bi bi-search text-secondary fs-4 d-block mb-1"></i>
                        Ningún atacante en cuarentena coincide con la referencia <strong>"${termino}"</strong>.
                    </td>
                </tr>
            `;
            return;
        }

        tbodyCuarentenaActiva.innerHTML = filtrados.map((item) => {
            const ip = escaparHtml(item.ip);
            const macRaw = String(item.mac || 'N/A (WAN)');
            const mac = escaparHtml(macRaw);
            const ident = escaparHtml(item.identity || 'Host Externo');
            const proto = escaparHtml(item.protocol || 'UDP/TCP');
            const hostname = escaparHtml(item.hostname || '');
            const vendor = escaparHtml(item.vendor || '');
            const esLan = item.is_lan !== undefined
                ? Boolean(item.is_lan)
                : (macRaw.includes('-') && !macRaw.includes('WAN'));
            const regla = escaparHtml(item.rule_name || `CyberShield_Block_${ip}`);
            const esPermanente = Boolean(item.is_permanent);
            const flujosMitigados = Number(item.mitigated_flows || 0);
            const badgeMitigados = flujosMitigados > 0
                ? `<div class="mt-1"><span class="badge bg-success-subtle text-success border border-success-subtle" title="Ráfagas de ataque posteriores interceptadas y descartadas por la cuarentena activa"><i class="bi bi-shield-fill-check me-1"></i>${flujosMitigados} flujos neutralizados</span></div>`
                : '';

            const subDetalleIdentidad = (hostname || vendor)
                ? `<div class="text-secondary mt-1" style="font-size: 0.74rem;">
                       ${hostname ? `<span class="me-2"><i class="bi bi-pc-display me-1"></i><strong>Host:</strong> ${hostname}</span>` : ''}
                       ${vendor ? `<span><i class="bi bi-cpu me-1"></i><strong>NIC/ISP:</strong> ${vendor}</span>` : ''}
                   </div>`
                : '';

            const htmlExpiracion = esPermanente
                ? `<span class="permanent-pill" title="Bloqueo indefinido hasta que el operador presione Desbloquear IP">
                       <i class="bi bi-infinity me-1"></i>Permanente (Manual)
                   </span>`
                : `<span class="countdown-pill" data-ip-countdown="${ip}">
                       <i class="bi bi-clock-history me-1"></i>15m (${formatearSegundosMmSs(item.remaining_seconds ?? 0)})
                   </span>`;

            return `
                <tr>
                    <td class="fw-bold text-danger">
                        <div class="d-flex align-items-center gap-1 flex-wrap">
                            <span><i class="bi bi-slash-circle-fill me-1"></i>${ip}</span>
                            <span class="badge bg-danger-subtle text-danger" style="font-size: 0.68rem;">${proto}</span>
                            <span class="badge ${esLan ? 'bg-info-subtle text-info' : 'bg-warning-subtle text-warning'}" style="font-size: 0.68rem;">${esLan ? 'LAN' : 'WAN'}</span>
                        </div>
                        ${badgeMitigados}
                    </td>
                    <td>
                        <code class="fw-bold">${mac}</code>
                        ${esLan && macRaw.includes('-') ? `<div class="text-muted" style="font-size: 0.7rem;">Física ARP L2</div>` : ''}
                    </td>
                    <td>
                        <div class="fw-semibold">${ident}</div>
                        ${subDetalleIdentidad}
                    </td>
                    <td><span class="badge bg-dark-subtle text-dark font-monospace">${regla}</span></td>
                    <td>${htmlExpiracion}</td>
                    <td class="text-end">
                        <button type="button" class="btn btn-sm btn-outline-success rounded-pill px-3 fw-semibold" data-action="unblock" data-ip="${ip}">
                            <i class="bi bi-unlock-fill me-1"></i> Desbloquear IP
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function filtrarEventosCincoPasos(lista) {
        const q = normalizarTextoBusqueda(inputBuscarEventosSoar ? inputBuscarEventosSoar.value : '');
        const qMac = q.replace(/:/g, '-');
        const estadoFiltro = selectFiltroEstadoEventos ? selectFiltroEstadoEventos.value : 'all';

        return lista.filter((ev) => {
            const bloqueada = Boolean(ev.is_blocked);
            if (estadoFiltro === 'blocked' && !bloqueada) return false;
            if (estadoFiltro === 'monitored' && bloqueada) return false;

            if (!q) return true;

            const s = ev.steps || {};
            const p2 = s.step2_lan || {};
            const p3 = s.step3_wan || {};
            const p5 = s.step5_firewall || {};

            const campos = [
                ev.src_ip,
                ev.protocol,
                p2.mac,
                String(p2.mac || '').replace(/-/g, ':'),
                p2.hostname,
                p2.vendor,
                p2.device_nature,
                p2.detail,
                p3.country,
                p3.isp,
                p3.asn,
                p3.attacker_type,
                p5.rule_name,
                p5.badge
            ].map(normalizarTextoBusqueda);

            return campos.some((c) => c.includes(q) || (qMac && c.includes(qMac)));
        });
    }

    function renderizarFlujoCincoPasos(eventos) {
        if (!contenedorFlujoCincoPasos) return;
        if (Array.isArray(eventos)) {
            eventosLocal = eventos;
        }
        if (kpiIncidentesSoar) kpiIncidentesSoar.textContent = String(eventosLocal.length);

        if (!eventosLocal.length) {
            contenedorFlujoCincoPasos.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="bi bi-radar fs-3 d-block mb-2 text-info"></i>
                    Sin incidentes recientes registrados en la sesión SOAR. Inyecte una prueba o ingrese una IP arriba.
                </div>
            `;
            return;
        }

        const eventosFiltrados = filtrarEventosCincoPasos(eventosLocal);
        if (!eventosFiltrados.length) {
            const termino = escaparHtml(inputBuscarEventosSoar ? inputBuscarEventosSoar.value : '');
            contenedorFlujoCincoPasos.innerHTML = `
                <div class="text-center text-muted py-4">
                    <i class="bi bi-search fs-3 d-block mb-2 text-secondary"></i>
                    No se encontraron investigaciones que coincidan con el filtro <strong>"${termino}"</strong>.
                </div>
            `;
            return;
        }

        contenedorFlujoCincoPasos.innerHTML = eventosFiltrados.map((ev, idx) => {
            const ipRaw = String(ev.src_ip || '');
            const ip = escaparHtml(ipRaw);
            const proto = escaparHtml(ev.protocol || 'OTHER');
            const conf = (ev.confidence_percentage !== null && ev.confidence_percentage !== undefined && Number.isFinite(Number(ev.confidence_percentage)))
                ? `${Number(ev.confidence_percentage).toFixed(1)}%`
                : 'N/D';
            const bloqueada = Boolean(ev.is_blocked);
            const esPerm = Boolean(ev.is_permanent);
            const s = ev.steps || {};
            const p1 = s.step1_ttl || {};
            const p2 = s.step2_lan || {};
            const p3 = s.step3_wan || {};
            const p4 = s.step4_sans || {};
            const p5 = s.step5_firewall || {};
            const idSelectTarjeta = `selDurCard_${idx}`;
            const durGuardada = duracionSeleccionadaPorIp.get(ipRaw) || 'permanent';
            const macEvento = (p2.applicable && p2.mac && p2.mac !== 'N/A (Tráfico WAN)')
                ? `<span class="badge bg-secondary-subtle text-dark font-monospace border" title="Dirección MAC Física del Atacante LAN"><i class="bi bi-hdd-network me-1"></i>MAC: ${escaparHtml(p2.mac)}</span>`
                : '';

            const btnAccion = bloqueada
                ? `<button type="button" class="btn btn-sm btn-success rounded-pill px-3 fw-semibold" data-action="unblock" data-ip="${ip}">
                       <i class="bi bi-unlock-fill me-1"></i> Desbloquear IP
                   </button>`
                : `<div class="d-flex align-items-center gap-1 soar-card-actions">
                       <select class="form-select form-select-sm rounded-pill sel-duracion-tarjeta" id="${idSelectTarjeta}" data-ip="${ip}" style="width: auto; font-size: 0.76rem;">
                           <option value="permanent" ${durGuardada === 'permanent' ? 'selected' : ''}>Permanente</option>
                           <option value="15m" ${durGuardada === '15m' ? 'selected' : ''}>15 min</option>
                       </select>
                       <button type="button" class="btn btn-sm btn-danger rounded-pill px-3 fw-semibold" data-action="block" data-ip="${ip}" data-proto="${proto}" data-select-id="${idSelectTarjeta}">
                           <i class="bi bi-shield-fill-x me-1"></i> Aislar IP
                       </button>
                   </div>`;

            const textoEstadoBloqueo = esPerm
                ? 'BLOQUEADA (PERMANENTE)'
                : `BLOQUEADA (15m: ${formatearSegundosMmSs(ev.remaining_seconds ?? 0)})`;

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
                            ${macEvento}
                            <span class="badge bg-danger-subtle text-danger fw-bold">${proto} • Confianza ${conf}</span>
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

    // Delegación segura de eventos por atributos data-* y preservación de duración por IP
    if (tbodyCuarentenaActiva) {
        tbodyCuarentenaActiva.addEventListener('click', (evento) => {
            const btn = evento.target.closest('button[data-action="unblock"]');
            if (!btn) return;
            const ipObjetivo = btn.dataset.ip;
            if (ipObjetivo) {
                window.desbloquearIpAccion(ipObjetivo);
            }
        });
    }

    if (contenedorFlujoCincoPasos) {
        contenedorFlujoCincoPasos.addEventListener('click', (evento) => {
            const btn = evento.target.closest('button[data-action]');
            if (!btn) return;
            const accion = btn.dataset.action;
            const ipObjetivo = btn.dataset.ip;
            if (!ipObjetivo) return;
            if (accion === 'unblock') {
                window.desbloquearIpAccion(ipObjetivo);
            } else if (accion === 'block') {
                window.bloquearIpDesdeTarjeta(ipObjetivo, btn.dataset.proto || 'TCP', btn.dataset.selectId || '');
            }
        });

        contenedorFlujoCincoPasos.addEventListener('change', (evento) => {
            const sel = evento.target.closest('select.sel-duracion-tarjeta');
            if (!sel || !sel.dataset.ip) return;
            duracionSeleccionadaPorIp.set(sel.dataset.ip, sel.value);
        });
    }

    async function cargarDashboardSoar(forzar = false) {
        if (dashboardEnVuelo) {
            if (forzar) refrescoPendiente = true;
            return;
        }
        dashboardEnVuelo = true;
        try {
            const resp = await fetch('/api/soar/dashboard');
            if (verificarSesion401(resp)) return;
            if (resp.status === 403) {
                localStorage.setItem('cybershield_soar_activo', 'false');
                window.location.replace('/frontend/configuracion.html');
                return;
            }
            if (!resp.ok) return;
            const datos = await resp.json();

            if (switchAutobloqueoIps && !switchAutobloqueoIps.disabled) {
                switchAutobloqueoIps.checked = Boolean(datos.auto_block);
            }

            actualizarUrlEdlModal(datos.primary_local_ip || '');

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
        } catch (_) {
        } finally {
            dashboardEnVuelo = false;
            if (refrescoPendiente) {
                refrescoPendiente = false;
                cargarDashboardSoar(false);
            }
        }
    }

    window.bloquearIpAccion = async function (ip, protocolo, modoDuracion) {
        if (!ip) return false;
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
            if (verificarSesion401(resp)) return false;
            const datos = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                mostrarNotificacionSoar(datos.detail || 'No se pudo bloquear la IP (Candado 1)', true);
                return false;
            }
            duracionSeleccionadaPorIp.delete(ip.trim());
            const etqDur = datos.is_permanent ? 'Permanentemente (Hasta desbloqueo manual)' : 'por 15 minutos';
            mostrarNotificacionSoar(`IP ${ip} aislada en Firewall (${datos.rule_name}) ${etqDur}`, false);
            await cargarDashboardSoar(true);
            return true;
        } catch (_) {
            mostrarNotificacionSoar('Error de comunicación con el motor SOAR', true);
            return false;
        }
    };

    window.bloquearIpDesdeTarjeta = async function (ip, protocolo, idSelector) {
        const elSel = idSelector ? document.getElementById(idSelector) : null;
        const modo = elSel ? elSel.value : (duracionSeleccionadaPorIp.get(ip) || 'permanent');
        await window.bloquearIpAccion(ip, protocolo, modo);
    };

    window.desbloquearIpAccion = async function (ipOReferencia) {
        if (!ipOReferencia) return false;
        try {
            const resp = await fetch('/api/soar/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ipOReferencia.trim(), protocol: 'TCP' })
            });
            if (verificarSesion401(resp)) return false;
            const datos = await resp.json().catch(() => ({}));
            if (!resp.ok) {
                mostrarNotificacionSoar(datos.detail || 'No se pudo desbloquear la referencia indicada', true);
                return false;
            }
            const ipResuelta = datos.unblocked_ip || ipOReferencia;
            const macInfo = (datos.mac && datos.mac !== 'N/A (WAN)') ? ` [MAC: ${datos.mac}]` : '';
            mostrarNotificacionSoar(`Atacante ${ipResuelta}${macInfo} desbloqueado y regla ${datos.rule_name} eliminada`, false);
            await cargarDashboardSoar(true);
            return true;
        } catch (_) {
            mostrarNotificacionSoar('Error al desbloquear IP/Referencia', true);
            return false;
        }
    };

    window.limpiarBusquedaCuarentena = function () {
        if (inputBuscarCuarentena) inputBuscarCuarentena.value = '';
        if (selectFiltroCuarentena) selectFiltroCuarentena.value = 'all';
        renderizarTablaCuarentena();
    };

    window.desbloquearPorReferenciaBuscada = async function () {
        const refTexto = (inputBuscarCuarentena ? inputBuscarCuarentena.value : '').trim();
        const filtrados = filtrarItemsCuarentena(cuarentenaLocal);

        if (!refTexto && filtrados.length !== 1) {
            mostrarNotificacionSoar(
                'Escriba en el buscador una referencia del atacante (IP, MAC, Hostname, Fabricante o Regla) para desbloquearlo',
                true
            );
            if (inputBuscarCuarentena) inputBuscarCuarentena.focus();
            return;
        }

        const objetivo = filtrados.length === 1 ? filtrados[0].ip : refTexto;
        const exito = await window.desbloquearIpAccion(objetivo);
        if (exito && inputBuscarCuarentena && filtrados.length <= 1) {
            inputBuscarCuarentena.value = '';
            renderizarTablaCuarentena();
        }
    };

    if (inputBuscarCuarentena) {
        inputBuscarCuarentena.addEventListener('input', () => renderizarTablaCuarentena());
        inputBuscarCuarentena.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter') {
                ev.preventDefault();
                window.desbloquearPorReferenciaBuscada();
            }
        });
    }
    if (selectFiltroCuarentena) {
        selectFiltroCuarentena.addEventListener('change', () => renderizarTablaCuarentena());
    }
    if (inputBuscarEventosSoar) {
        inputBuscarEventosSoar.addEventListener('input', () => renderizarFlujoCincoPasos());
    }
    if (selectFiltroEstadoEventos) {
        selectFiltroEstadoEventos.addEventListener('change', () => renderizarFlujoCincoPasos());
    }

    window.bloquearIpManualInput = async function () {
        const ip = (inputIpManualBloquear ? inputIpManualBloquear.value : '').trim();
        const proto = selectProtoManualBloquear ? selectProtoManualBloquear.value : 'TCP';
        const modoDur = selectDuracionManualBloquear ? selectDuracionManualBloquear.value : 'permanent';
        if (!ip) {
            mostrarNotificacionSoar('Ingrese una dirección IP válida para investigar y bloquear', true);
            return;
        }
        const exito = await window.bloquearIpAccion(ip, proto, modoDur);
        if (exito && inputIpManualBloquear) {
            inputIpManualBloquear.value = '';
        }
    };

    if (switchAutobloqueoIps) {
        switchAutobloqueoIps.addEventListener('change', async (e) => {
            const activo = e.target.checked;
            const estadoPrevio = !activo;
            switchAutobloqueoIps.disabled = true;
            try {
                const resp = await fetch('/api/soar/autoblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ auto_block: activo })
                });
                if (verificarSesion401(resp)) return;
                if (resp.ok) {
                    mostrarNotificacionSoar(
                        activo
                            ? 'Autobloqueo Inteligente IPS activado (Expiración 15m automática)'
                            : 'Modo Manual: Investigará los 5 pasos y esperará su clic para bloqueo Permanente o 15m',
                        false
                    );
                } else {
                    const datos = await resp.json().catch(() => ({}));
                    switchAutobloqueoIps.checked = estadoPrevio;
                    mostrarNotificacionSoar(datos.detail || 'No se pudo cambiar el estado de autobloqueo IPS en el servidor', true);
                }
            } catch (_) {
                switchAutobloqueoIps.checked = estadoPrevio;
                mostrarNotificacionSoar('Error de conexión: no se pudo actualizar el autobloqueo IPS', true);
            } finally {
                switchAutobloqueoIps.disabled = false;
            }
        });
    }

    // Reloj de cuenta regresiva en tiempo real (1 segundo) con cooldown en expiración (P3-09)
    const intervaloCountdown = setInterval(() => {
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
                pill.innerHTML = `<i class="bi bi-clock-history me-1"></i>15m (${formatearSegundosMmSs(item.remaining_seconds ?? 0)})`;
            }
        });
        if (expiroAlguna && !dashboardEnVuelo) {
            const ahora = Date.now();
            if (ahora - ultimoRefrescoExpiracionMs >= COOLDOWN_EXPIRACION_MS) {
                ultimoRefrescoExpiracionMs = ahora;
                cargarDashboardSoar(false);
            }
        }
    }, 1000);

    const intervaloRefrescoSoar = setInterval(() => cargarDashboardSoar(false), 4000);

    if (typeof window.registrarLimpiezaSesion === 'function') {
        window.registrarLimpiezaSesion(() => {
            clearInterval(intervaloCountdown);
            clearInterval(intervaloRefrescoSoar);
            if (temporizadorToastSoar) {
                clearTimeout(temporizadorToastSoar);
                temporizadorToastSoar = null;
            }
        });
    }

    // Inicializar URL EDL con el origen real antes del primer sondeo
    actualizarUrlEdlModal('');
    window.cargarDashboardSoar = () => cargarDashboardSoar(true);
    cargarDashboardSoar(true);
})();
