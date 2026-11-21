import atexit
import io
import os
import shutil
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# --- Aislamiento estricto de BD temporal ANTES de importar backend.* ---
_DIR_TMP_PRUEBA = tempfile.mkdtemp(prefix="cybershield_audit_db_")
_RUTA_BD_TMP = os.path.join(_DIR_TMP_PRUEBA, "test_produccion.db").replace(os.sep, "/")
os.environ["DATABASE_URL"] = f"sqlite:///{_RUTA_BD_TMP}"
os.environ.setdefault("SOAR_ENABLE_EXTERNAL_ENRICHMENT", "false")

# En entornos limpios sin .env, proveer credenciales efímeras solo para la suite aislada
_DIR_RAIZ = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(os.path.join(_DIR_RAIZ, ".env")):
    os.environ.setdefault("ADMIN_USER", "admin")
    os.environ.setdefault("ADMIN_PASSWORD", "AuditPass-Temp-2026!")
    os.environ.setdefault("SENSOR_API_KEY", "AuditSensorKey-Temp-2026!")
    os.environ.setdefault("SOAR_MASTER_PASSWORD", "AuditSoarMaster-Temp-2026!")
    os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from backend.base_datos import motor_bd  # noqa: E402
from backend.configuracion import configuracion  # noqa: E402
from backend.inferencia import TOTAL_CANONICAS  # noqa: E402
from backend.principal import (  # noqa: E402
    NOMBRE_COOKIE_SESION,
    _obtener_ip_local_principal,
    aplicacion,
)
from sensor.capturador_trafico_vivo import TablaFlujos  # noqa: E402

N_CANONICO = TOTAL_CANONICAS


def _limpiar_bd_temporal() -> None:
    try:
        motor_bd.dispose()
    except Exception:
        pass
    shutil.rmtree(_DIR_TMP_PRUEBA, ignore_errors=True)


atexit.register(_limpiar_bd_temporal)


def ejecutar_auditoria_produccion() -> bool:
    print("=" * 72)
    print("  CYBERSHIELD PYME - SUITE DE VALIDACION DE PRODUCCION 24/7 (AISLADA)")
    print(f"  BD Temporal Aislada: {_RUTA_BD_TMP}")
    print("=" * 72)
    superadas = 0
    totales = 0

    def afirmar_prueba(nombre: str, condicion: bool, extra: str = ""):
        nonlocal superadas, totales
        totales += 1
        if condicion:
            superadas += 1
            print(f"  [OK - PASS] {nombre} {extra}".rstrip())
        else:
            print(f"  [ERROR - FAIL] {nombre} {extra}".rstrip())

    try:
        with TestClient(aplicacion) as cliente:
            # 1. Healthcheck público (sin filtrar excepciones internas)
            r_health = cliente.get("/api/health")
            body_health = r_health.json()
            afirmar_prueba(
                "1. Healthcheck API público sin fuga de errores",
                r_health.status_code == 200
                and body_health.get("status") == "online"
                and body_health.get("model_error") is None,
            )

            # 2. Rechazo sin autenticación (401 en APIs y 302 en vistas frontend; sin bypass testclient)
            r_unauth_model = cliente.get("/api/model")
            r_unauth_alerts = cliente.get("/api/alerts")
            r_unauth_soar = cliente.get("/api/soar/status")
            r_unauth_ui = cliente.get("/frontend/", follow_redirects=False)
            afirmar_prueba(
                "2. Control de acceso sin sesión (401 API / 302 UI, sin bypass testclient)",
                r_unauth_model.status_code == 401
                and r_unauth_alerts.status_code == 401
                and r_unauth_soar.status_code == 401
                and r_unauth_ui.status_code == 302
                and "/frontend/login.html" in r_unauth_ui.headers.get("location", ""),
            )

            # 3. Separación estricta de privilegios X-API-Key (solo ingesta /api/predict*)
            flujo_simulado = {
                "features": [0.0] * N_CANONICO,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.5",
                "protocol": "TCP",
                "duration_ms": 120.0,
                "total_bytes": 1500,
            }
            cab_sensor = {"X-API-Key": configuracion.clave_api_sensor or ""}
            r_pred_sin_key = cliente.post("/api/predict", json=flujo_simulado)
            r_pred_key_mala = cliente.post(
                "/api/predict", json=flujo_simulado, headers={"X-API-Key": "clave-sensor-falsa"}
            )
            r_key_en_model = cliente.get("/api/model", headers=cab_sensor)
            r_key_en_soar = cliente.get("/api/soar/status", headers=cab_sensor)
            r_key_en_umbral = cliente.post(
                "/api/settings/threshold", json={"threshold_percent": 60.0}, headers=cab_sensor
            )
            afirmar_prueba(
                "3. Separación de privilegios X-API-Key (401 en admin y sin clave)",
                bool(configuracion.clave_api_sensor)
                and r_pred_sin_key.status_code == 401
                and r_pred_key_mala.status_code == 401
                and r_key_en_model.status_code == 401
                and r_key_en_soar.status_code == 401
                and r_key_en_umbral.status_code == 401,
            )

            # 4. Ingesta unitaria y por lotes con X-API-Key válida
            r_pred = cliente.post("/api/predict", json=flujo_simulado, headers=cab_sensor)
            carga_lote = {"records": [flujo_simulado] * 10}
            r_lote = cliente.post("/api/predict/batch", json=carga_lote, headers=cab_sensor)
            afirmar_prueba(
                "4. Inferencia Unitaria y por Lotes (/api/predict y /api/predict/batch)",
                r_pred.status_code == 200 and r_lote.status_code == 200,
                f"(Pred={r_pred.json().get('prediction')} | Latencia={r_lote.json().get('avg_latency_per_flow_ms')} ms/flujo)",
            )

            # 5. Autenticación Web real (/api/auth/login) y verificación de cookie HttpOnly
            r_login_malo = cliente.post(
                "/api/auth/login",
                json={"usuario": configuracion.usuario_admin, "contrasena": "clave_incorrecta_123"},
            )
            r_login_ok = cliente.post(
                "/api/auth/login",
                json={"usuario": configuracion.usuario_admin, "contrasena": configuracion.clave_admin},
            )
            cookie_sesion = r_login_ok.cookies.get(NOMBRE_COOKIE_SESION)
            r_me = cliente.get("/api/auth/me")
            set_cookie_hdr = r_login_ok.headers.get("set-cookie", "").lower()
            afirmar_prueba(
                "5. Login real con Cookie HttpOnly (/api/auth/login y /api/auth/me)",
                r_login_malo.status_code == 401
                and r_login_ok.status_code == 200
                and bool(cookie_sesion)
                and "httponly" in set_cookie_hdr
                and r_me.status_code == 200
                and r_me.json().get("authenticated") is True,
            )

            # 6. Metadata Conv1D (77 características) y sincronización viva del umbral
            r_model = cliente.get("/api/model")
            r_set_thr = cliente.post("/api/settings/threshold", json={"threshold_percent": 65.0})
            r_model_upd = cliente.get("/api/model")
            r_reset_thr = cliente.post("/api/settings/threshold", json={"threshold_percent": 50.0})
            afirmar_prueba(
                "6. Metadata Conv1D (77 features) y umbral vivo en /api/model",
                r_model.status_code == 200
                and r_model.json().get("n_features") == 77
                and r_set_thr.status_code == 200
                and r_model_upd.status_code == 200
                and abs(float(r_model_upd.json().get("decision_threshold", 0.0)) - 0.65) < 1e-4
                and r_reset_thr.status_code == 200,
            )

            # 7. Validación CSRF (bloquea origen cruzado; permite localhost y LAN del servidor)
            ip_lan_srv = _obtener_ip_local_principal()
            r_csrf_evil = cliente.post(
                "/api/settings/threshold",
                json={"threshold_percent": 55.0},
                headers={"Origin": "http://evil.attacker.example"},
            )
            r_csrf_secfetch = cliente.post(
                "/api/settings/threshold",
                json={"threshold_percent": 55.0},
                headers={"Sec-Fetch-Site": "cross-site"},
            )
            r_csrf_local = cliente.post(
                "/api/settings/threshold",
                json={"threshold_percent": 50.0},
                headers={"Host": "localhost:8000", "Origin": "http://localhost:8000"},
            )
            r_csrf_lan = cliente.post(
                "/api/settings/threshold",
                json={"threshold_percent": 50.0},
                headers={"Host": f"{ip_lan_srv}:8000", "Origin": f"http://{ip_lan_srv}:8000"},
            )
            afirmar_prueba(
                "7. Protección CSRF estricta (403 externo / 200 localhost y LAN)",
                r_csrf_evil.status_code == 403
                and r_csrf_secfetch.status_code == 403
                and r_csrf_local.status_code == 200
                and r_csrf_lan.status_code == 200,
                f"(Host LAN probado: {ip_lan_srv}:8000)",
            )

            # 8. Cabeceras de seguridad y compatibilidad CSP con Frontend/Audio/CDN
            csp = r_model.headers.get("content-security-policy", "")
            afirmar_prueba(
                "8. Cabeceras de Seguridad y Content-Security-Policy compatible",
                r_model.headers.get("x-content-type-options") == "nosniff"
                and r_model.headers.get("x-frame-options") == "DENY"
                and "cdn.jsdelivr.net" in csp
                and "fonts.googleapis.com" in csp
                and "media-src 'self'" in csp
                and "connect-src 'self' ws: wss:" in csp
                and "object-src 'none'" in csp
                and "frame-ancestors 'none'" in csp,
            )

            # 9. Bloqueo de Path Traversal en /api/tts/audio (lista blanca estricta)
            r_tts_trav1 = cliente.get("/api/tts/audio?voice=../principal&text=hola")
            r_tts_trav2 = cliente.get("/api/tts/audio?voice=C:/Windows/win.ini&text=hola")
            r_tts_trav3 = cliente.get("/api/tts/audio?voice=voz_inexistente_xyz&text=hola")
            afirmar_prueba(
                "9. Path Traversal bloqueado en /api/tts/audio (422)",
                r_tts_trav1.status_code == 422
                and r_tts_trav2.status_code == 422
                and r_tts_trav3.status_code == 422,
            )

            # 10. Filtrado de Alertas y Exportación CSV con filtros (severity / search_ip)
            severidades = ["all", "critical", "high", "medium", "Crítica", "Alta", "Media"]
            todas_sev_ok = all(cliente.get(f"/api/alerts?severity={s}").status_code == 200 for s in severidades)
            periodos = ["all", "day", "week", "month"]
            todos_per_ok = all(
                cliente.get(f"/api/alerts?period={p}&limit=5").status_code == 200
                and "kpis" in cliente.get(f"/api/alerts?period={p}&limit=5").json()
                for p in periodos
            )
            r_historial = cliente.get("/api/history?limit=5")
            r_exportar = cliente.get("/api/export/csv?limit=10&severity=all&search_ip=192.168")
            afirmar_prueba(
                "10. Alertas, Historial y Exportación CSV filtrada (/api/export/csv)",
                todas_sev_ok
                and todos_per_ok
                and r_historial.status_code == 200
                and r_exportar.status_code == 200
                and "Timestamp_UTC" in r_exportar.text,
            )

            # 11. Validación Pasiva CSV (métricas reales + CSV vacío sin error 500)
            csv_ejemplo = (
                "Source IP,Destination IP,Protocol,Flow Duration,Total Length of Fwd Packets,"
                + ",".join([f"f_{i}" for i in range(N_CANONICO)])
                + "\n"
            )
            csv_ejemplo += "192.168.1.50,10.0.0.1,TCP,250000,4096," + ",".join(["1.0"] * N_CANONICO) + "\n"
            csv_ejemplo += "203.0.113.15,10.0.0.1,UDP,120000,65536," + ",".join(["50000.0"] * N_CANONICO) + "\n"
            r_importar = cliente.post(
                "/api/import/csv",
                files={"file": ("pyme_audit_sample.csv", io.BytesIO(csv_ejemplo.encode("utf-8")), "text/csv")},
            )
            r_import_vacio = cliente.post(
                "/api/import/csv",
                files={"file": ("vacio.csv", io.BytesIO(b"Source IP,Destination IP,Protocol\n"), "text/csv")},
            )
            afirmar_prueba(
                "11. Validación Pasiva CSV con Ley 29733 y manejo de CSV vacío",
                r_importar.status_code == 200
                and r_importar.json().get("anonymized") is True
                and r_importar.json().get("processed_flows") == 2
                and r_import_vacio.status_code == 200
                and r_import_vacio.json().get("processed_flows") == 0,
                f"(Procesados={r_importar.json().get('processed_flows')})",
            )

            # 12. Simulación por protocolo (respetando ENABLE_SIMULATION)
            r_sim_icmp = cliente.post("/api/simulate/ddos?count=2&protocol=ICMP")
            r_sim_udp = cliente.post("/api/simulate/ddos?count=2&protocol=UDP")
            r_sim_tcp = cliente.post("/api/simulate/ddos?count=2&protocol=TCP")
            if configuracion.permitir_simulacion:
                sim_ok = (
                    r_sim_icmp.status_code == 200
                    and r_sim_udp.status_code == 200
                    and r_sim_tcp.status_code == 200
                    and r_sim_icmp.json()[0].get("protocol") == "ICMP"
                    and r_sim_udp.json()[0].get("protocol") == "UDP"
                    and r_sim_tcp.json()[0].get("protocol") == "TCP"
                )
                extra_sim = "(ENABLE_SIMULATION=true -> 200)"
            else:
                sim_ok = (
                    r_sim_icmp.status_code == 403
                    and r_sim_udp.status_code == 403
                    and r_sim_tcp.status_code == 403
                )
                extra_sim = "(ENABLE_SIMULATION=false -> 403)"
            afirmar_prueba("12. Endpoints de Simulación DDoS (TCP/UDP/ICMP)", sim_ok, extra_sim)

            # 13. Análisis Forense (filtrado case-insensitive sin exclusión indebida)
            analisis_ok = True
            for p in periodos:
                rp = cliente.get(f"/api/analysis/protocol-distribution?period={p}")
                rh = cliente.get(f"/api/analysis/traffic-by-hour?period={p}&protocol=tcp&prediction=all")
                rf = cliente.get(f"/api/analysis/flows?period={p}&limit=5")
                if rp.status_code != 200 or rh.status_code != 200 or rf.status_code != 200:
                    analisis_ok = False
            rp_tcp = cliente.get("/api/analysis/protocol-distribution?period=day&protocol=tcp").json()
            if rp_tcp.get("labels") not in (["TCP"], []):
                analisis_ok = False
            afirmar_prueba("13. Análisis Forense con filtrado protocol case-insensitive", analisis_ok)

            # 14. Telemetría Real de Hardware (/api/performance sin descuento artificial -68 MB)
            r_rend = cliente.get("/api/performance")
            datos_rend = r_rend.json()
            ram_rss_mb = datos_rend.get("ram_mb", 0.0)
            ram_uss_mb = datos_rend.get("ram_uss_mb", 0.0)
            tamano_pool = motor_bd.pool.size()
            afirmar_prueba(
                "14. Telemetría real de RAM (RSS sin descuento artificial) y Pool BD",
                r_rend.status_code == 200
                and ram_rss_mb > 0
                and ram_uss_mb > 0
                and tamano_pool == 15,
                f"(RAM RSS real={ram_rss_mb} MB | RAM USS={ram_uss_mb} MB | CPU={datos_rend.get('cpu_percent')}% | Pool={tamano_pool})",
            )

            # 15. Feed EDL /api/soar/blocklist.txt (401 WAN/RFC5737, 200 LAN / sesión / token)
            cliente_wan_pub = TestClient(aplicacion, client=("8.8.4.4", 54321))
            cliente_rfc5737 = TestClient(aplicacion, client=("203.0.113.99", 54323))
            cliente_lan_router = TestClient(aplicacion, client=("192.168.18.1", 54322))
            r_edl_pub = cliente_wan_pub.get("/api/soar/blocklist.txt")
            r_edl_rfc = cliente_rfc5737.get("/api/soar/blocklist.txt")
            r_edl_admin = cliente.get("/api/soar/blocklist.txt")
            if configuracion.token_edl:
                r_edl_router_sin = cliente_lan_router.get("/api/soar/blocklist.txt")
                r_edl_router_con = cliente_lan_router.get(
                    "/api/soar/blocklist.txt", headers={"X-EDL-Token": configuracion.token_edl}
                )
                edl_ok = (
                    r_edl_pub.status_code == 401
                    and r_edl_rfc.status_code == 401
                    and r_edl_router_sin.status_code == 401
                    and r_edl_router_con.status_code == 200
                    and r_edl_admin.status_code == 200
                )
                extra_edl = "(Modo EDL_API_TOKEN: WAN=401, RFC5737=401, Router sin token=401, con token=200)"
            else:
                r_edl_lan = cliente_lan_router.get("/api/soar/blocklist.txt")
                edl_ok = (
                    r_edl_pub.status_code == 401
                    and r_edl_rfc.status_code == 401
                    and r_edl_lan.status_code == 200
                    and r_edl_admin.status_code == 200
                )
                extra_edl = "(Modo LAN RFC1918: WAN=401, RFC5737=401, Router LAN=200, Admin=200)"
            afirmar_prueba("15. Feed Perimetral EDL (/api/soar/blocklist.txt)", edl_ok, extra_edl)

            # 16. Direction Pinning LRU, Reversión Mid-Stream, Conntrack Anti-FP y Detección Conv1D Pura
            tabla_pin = TablaFlujos()
            t_base = 1000.0
            for i in range(810):
                t_pkt = t_base + (i * 0.001)
                if i % 10 == 1:
                    tabla_pin._ingestar_campos_flujo(
                        t_pkt, ip_lan_srv, 54321, "172.217.115.4", 443, 6, "TCP", 0, 0x10, 20, 64240
                    )
                else:
                    tabla_pin._ingestar_campos_flujo(
                        t_pkt, "172.217.115.4", 443, ip_lan_srv, 54321, 6, "TCP", 12000, 0x18, 20, 65535
                    )
            tabla_pin.expirar_inactivos(t_base + 4.0, forzar_todos=False)
            for i in range(400):
                t_pkt = t_base + 4.5 + (i * 0.00001)
                tabla_pin._ingestar_campos_flujo(
                    t_pkt, "172.217.115.4", 443, ip_lan_srv, 54321, 6, "TCP", 1350, 0x18, 20, 65535
                )
            tabla_pin._ingestar_campos_flujo(
                t_base + 5.0, ip_lan_srv, 50768, "170.114.76.41", 8801, 17, "UDP", 120, 0, 20, -1
            )
            for i in range(399):
                tabla_pin._ingestar_campos_flujo(
                    t_base + 5.01 + (i * 0.001), "170.114.76.41", 8801, ip_lan_srv, 50768, 17, "UDP", 1100, 0, 20, -1
                )
            tabla_pin._ingestar_campos_flujo(
                t_base + 6.0, ip_lan_srv, 49915, "104.29.143.47", 19300, 17, "UDP", 90, 0, 20, -1
            )
            for i in range(399):
                tabla_pin._ingestar_campos_flujo(
                    t_base + 6.01 + (i * 0.001), "104.29.143.47", 19300, ip_lan_srv, 49915, 17, "UDP", 950, 0, 20, -1
                )

            tabla_pin.expirar_inactivos(t_base + 15.0, forzar_todos=True)
            regs_descarga = tabla_pin.extraer_registros()
            pinning_descarga_ok = (
                len(regs_descarga) == 6
                and all(r["src_ip"] == ip_lan_srv for r in regs_descarga)
            )
            r_lote_descarga = cliente.post("/api/predict/batch", json={"records": regs_descarga}, headers=cab_sensor)
            conntrack_descarga_ok = r_lote_descarga.status_code == 200 and r_lote_descarga.json().get("ddos") == 0

            # Reversión mid-stream unidireccional en TablaFlujos
            for puerto_dst in (80, 8080):
                for i in range(400):
                    t_pkt = t_base + 20.0 + (i * 0.00002)
                    tabla_pin._ingestar_campos_flujo(
                        t_pkt, "203.0.113.88", 443, ip_lan_srv, puerto_dst, 6, "TCP", 1400, 0x18, 20, 512
                    )
            regs_rev = tabla_pin.extraer_registros()
            reversion_midstream_ok = (
                len(regs_rev) == 2
                and all(
                    r["src_ip"] == "203.0.113.88"
                    and r["dst_ip"] == ip_lan_srv
                    and r["features"][4] == 400.0
                    and r["features"][5] == 0.0
                    for r in regs_rev
                )
            )

            # Detección Conv1D pura (sin reglas heurísticas) sobre ráfaga TCP DDoS realista (perfil CICIDS2017 LOIC)
            tabla_loic = TablaFlujos()
            for sport_atq in (50080, 50081):
                for i in range(6):
                    t_pkt = t_base + 30.0 + (i * 0.001)
                    tabla_loic._ingestar_campos_flujo(
                        t_pkt, "203.0.113.88", sport_atq, ip_lan_srv, 80, 6, "TCP", 6, 0x18, 20, 256
                    )
            tabla_loic.expirar_inactivos(t_base + 40.0, forzar_todos=True)
            regs_loic = tabla_loic.extraer_registros()
            r_lote_loic = cliente.post("/api/predict/batch", json={"records": regs_loic}, headers=cab_sensor)
            deteccion_conv1d_ok = r_lote_loic.status_code == 200 and r_lote_loic.json().get("ddos") == 2

            afirmar_prueba(
                "16. Direction Pinning, Reversión Mid-Stream, Conntrack Anti-FP y Conv1D Pura",
                pinning_descarga_ok and conntrack_descarga_ok and reversion_midstream_ok and deteccion_conv1d_ok,
                f"(Descarga/Zoom/WebRTC DDoS={r_lote_descarga.json().get('ddos')}/6 | Reversión=2/2 | Conv1D DDoS={r_lote_loic.json().get('ddos')}/2)",
            )

            # 17. WebSocket autenticado vs anónimo, Logout solo POST y revocación en servidor
            ws_anon_rechazado = False
            cliente_ws_anon = TestClient(aplicacion)
            try:
                with cliente_ws_anon.websocket_connect("/ws/traffic"):
                    ws_anon_rechazado = False
            except WebSocketDisconnect as exc:
                ws_anon_rechazado = exc.code == 1008

            ws_auth_ok = False
            with cliente.websocket_connect("/ws/traffic") as ws_ok:
                ws_ok.send_text("ping")
                ws_auth_ok = True

            r_logout_get = cliente.get("/api/auth/logout")
            r_logout_post = cliente.post("/api/auth/logout")
            # Reinyectar la cookie antigua revocada para comprobar rechazo en servidor
            r_replay = cliente.get("/api/auth/me", cookies={NOMBRE_COOKIE_SESION: cookie_sesion or ""})
            afirmar_prueba(
                "17. WebSocket autenticado, Logout solo POST (405 en GET) y revocación en servidor",
                ws_anon_rechazado
                and ws_auth_ok
                and r_logout_get.status_code == 405
                and r_logout_post.status_code == 200
                and r_replay.status_code == 401,
            )

        print("=" * 72)
        print(f"  RESULTADO FINAL: {superadas}/{totales} PRUEBAS SUPERADAS SATISFACTORIAMENTE")
        print("=" * 72)
        return superadas == totales
    finally:
        _limpiar_bd_temporal()


run_production_audit = ejecutar_auditoria_produccion


if __name__ == "__main__":
    exito = ejecutar_auditoria_produccion()
    sys.exit(0 if exito else 1)
