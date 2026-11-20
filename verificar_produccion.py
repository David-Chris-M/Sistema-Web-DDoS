import io
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from fastapi.testclient import TestClient

from backend.base_datos import motor_bd
from backend.configuracion import configuracion
from backend.inferencia import TOTAL_CANONICAS
from backend.principal import aplicacion
from sensor.capturador_trafico_vivo import TablaFlujos

N_CANONICO = TOTAL_CANONICAS


def ejecutar_auditoria_produccion() -> bool:
    print("=" * 65)
    print("  CYBERSHIELD PYME - SUITE DE VALIDACION DE PRODUCCION 24/7")
    print("=" * 65)
    superadas = 0
    totales = 0

    def afirmar_prueba(nombre: str, condicion: bool, extra: str = ""):
        nonlocal superadas, totales
        totales += 1
        if condicion:
            superadas += 1
            print(f"  [OK - PASS] {nombre} {extra}")
        else:
            print(f"  [ERROR - FAIL] {nombre} {extra}")

    with TestClient(aplicacion) as cliente:
        # 1. Healthcheck
        r = cliente.get("/api/health")
        afirmar_prueba("Healthcheck API", r.status_code == 200 and r.json().get("status") == "online")

        # 2. Metadatos del Modelo
        r = cliente.get("/api/model")
        afirmar_prueba("Metadata Conv1D", r.status_code == 200 and r.json().get("n_features") == 77)

        # 3. Autenticación de Ingesta
        flujo_simulado = {
            "features": [0.0] * N_CANONICO,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "protocol": "TCP",
            "duration_ms": 120.0,
            "total_bytes": 1500,
        }

        if configuracion.clave_api_sensor:
            r_no_autorizado = cliente.post("/api/predict", json=flujo_simulado)
            afirmar_prueba("Rechazo de ingesta no autenticada (401)", r_no_autorizado.status_code == 401)
            cabeceras = {"X-API-Key": configuracion.clave_api_sensor}
        else:
            cabeceras = {}

        # 4. Inferencia Unitaria
        r_pred = cliente.post("/api/predict", json=flujo_simulado, headers=cabeceras)
        afirmar_prueba("Inferencia Unitaria (/api/predict)", r_pred.status_code == 200,
                      f"Predicción: {r_pred.json().get('prediction')}")

        # 5. Inferencia por Lotes
        carga_lote = {"records": [flujo_simulado] * 10}
        r_lote = cliente.post("/api/predict/batch", json=carga_lote, headers=cabeceras)
        afirmar_prueba("Inferencia por Lotes (/api/predict/batch)", r_lote.status_code == 200,
                      f"Latencia: {r_lote.json().get('avg_latency_per_flow_ms')} ms/flujo")

        # 6. Filtrado de Alertas
        severidades = ["all", "critical", "high", "medium", "Crítica", "Alta", "Media"]
        todas_sev_ok = True
        for s in severidades:
            if cliente.get(f"/api/alerts?severity={s}").status_code != 200:
                todas_sev_ok = False
        afirmar_prueba("Módulo de Alertas Tolerante (/api/alerts)", todas_sev_ok)

        # 7. Importación Pasiva CSV
        csv_ejemplo = "Source IP,Destination IP,Protocol," + ",".join([f"f_{i}" for i in range(N_CANONICO)]) + "\n"
        csv_ejemplo += "192.168.1.50,10.0.0.1,TCP," + ",".join(["1.0"] * N_CANONICO) + "\n"
        csv_ejemplo += "203.0.113.15,10.0.0.1,UDP," + ",".join(["50000.0"] * N_CANONICO) + "\n"

        archivos = {"file": ("pyme_audit_sample.csv", io.BytesIO(csv_ejemplo.encode("utf-8")), "text/csv")}
        r_importar = cliente.post("/api/import/csv", files=archivos)
        afirmar_prueba("Validación Pasiva CSV con Ley 29733 (/api/import/csv)",
                      r_importar.status_code == 200 and r_importar.json().get("anonymized") is True,
                      f"Procesados: {r_importar.json().get('processed_flows')}")

        # 8. Autenticación Web y Exportación CSV
        r_login_malo = cliente.post("/api/auth/login", json={"usuario": configuracion.usuario_admin, "contrasena": "clave_incorrecta_123"})
        r_login_ok = cliente.post("/api/auth/login", json={"usuario": configuracion.usuario_admin, "contrasena": configuracion.clave_admin})
        r_historial = cliente.get("/api/history?limit=5")
        r_exportar = cliente.get("/api/export/csv?limit=10")
        afirmar_prueba(
            "Login Cookie HttpOnly (/api/auth/login) y Exportación CSV",
            r_login_malo.status_code == 401
            and r_login_ok.status_code == 200
            and "cybershield_session" in r_login_ok.cookies
            and r_historial.status_code == 200
            and r_exportar.status_code == 200
            and "Timestamp_UTC" in r_exportar.text,
        )

        # 9. Telemetría de Recursos
        r_rendimiento = cliente.get("/api/performance")
        datos_rendimiento = r_rendimiento.json()
        afirmar_prueba("Telemetría de Recursos en Hardware Pyme",
                      r_rendimiento.status_code == 200 and datos_rendimiento.get("ram_mb", 0) > 0,
                      f"RAM: {datos_rendimiento.get('ram_mb')} MB | CPU: {datos_rendimiento.get('cpu_percent')}%")

        # 10. Simulación por Protocolo
        r_sim_icmp = cliente.post("/api/simulate/ddos?count=2&protocol=ICMP", headers=cabeceras)
        r_sim_udp = cliente.post("/api/simulate/ddos?count=2&protocol=UDP", headers=cabeceras)
        r_sim_tcp = cliente.post("/api/simulate/ddos?count=2&protocol=TCP", headers=cabeceras)
        sim_ok = (
            r_sim_icmp.status_code == 200
            and r_sim_udp.status_code == 200
            and r_sim_tcp.status_code == 200
            and r_sim_icmp.json()[0].get("protocol") == "ICMP"
            and r_sim_udp.json()[0].get("protocol") == "UDP"
            and r_sim_tcp.json()[0].get("protocol") == "TCP"
        )
        afirmar_prueba("Ataques Diferenciados por Protocolo (TCP / UDP / ICMP)", sim_ok)

        # 11. Filtrado en Análisis Forense
        periodos = ["all", "day", "week", "month"]
        analisis_ok = True
        for p in periodos:
            rp = cliente.get(f"/api/analysis/protocol-distribution?period={p}")
            rh = cliente.get(f"/api/analysis/traffic-by-hour?period={p}&protocol=TCP&prediction=all")
            rf = cliente.get(f"/api/analysis/flows?period={p}&limit=5")
            if rp.status_code != 200 or rh.status_code != 200 or rf.status_code != 200:
                analisis_ok = False
            if "OTHER" in rp.json().get("labels", []):
                analisis_ok = False
        rp_tcp = cliente.get("/api/analysis/protocol-distribution?period=day&protocol=TCP").json()
        if rp_tcp.get("labels") not in (["TCP"], []):
            analisis_ok = False
        afirmar_prueba("Filtrado Integral en Gráficos de Análisis Forense (Sin 'OTHER')", analisis_ok)

        # 12. Filtrado e Historial de Alertas
        alertas_periodo_ok = True
        for p in periodos:
            ra = cliente.get(f"/api/alerts?period={p}&limit=5")
            if ra.status_code != 200 or "kpis" not in ra.json():
                alertas_periodo_ok = False
        total_alertas_hist = cliente.get("/api/alerts?period=all&limit=1").json().get("total", 0)
        afirmar_prueba(
            "Historial Completo de Alertas Restaurado y Filtrado Día/Semana/Mes",
            alertas_periodo_ok and total_alertas_hist >= 2500,
            f"Total alertas históricas en BD: {total_alertas_hist}",
        )

        # 13. Pool de Conexiones y Memoria RAM
        r_ram_post = cliente.get("/api/performance").json().get("ram_mb", 999.0)
        tamano_pool = motor_bd.pool.size()
        afirmar_prueba(
            "Pool de 15 Conexiones Intacto y Memoria RAM Optimizada",
            tamano_pool == 15 and r_ram_post < 500.0,
            f"Pool: {tamano_pool} conexiones | RAM tras simulaciones: {r_ram_post} MB",
        )

        tabla_pin = TablaFlujos()
        t_base = 1000.0
        for i in range(810):
            t_pkt = t_base + (i * 0.001)
            if i % 10 == 1:
                tabla_pin._ingestar_campos_flujo(
                    t_pkt, "192.168.18.10", 54321, "172.217.115.4", 443, 6, "TCP", 0, 0x10, 20, 64240
                )
            else:
                tabla_pin._ingestar_campos_flujo(
                    t_pkt, "172.217.115.4", 443, "192.168.18.10", 54321, 6, "TCP", 12000, 0x18, 20, 65535
                )
        # Simular pausa de 3s (> 2s idle) y luego ráfaga pura de 400 paquetes del servidor en 4ms (0 paq locales en sub-ventana)
        tabla_pin.expirar_inactivos(t_base + 4.0, forzar_todos=False)
        for i in range(400):
            t_pkt = t_base + 4.5 + (i * 0.00001)
            tabla_pin._ingestar_campos_flujo(
                t_pkt, "172.217.115.4", 443, "192.168.18.10", 54321, 6, "TCP", 1350, 0x18, 20, 65535
            )
        # Simular videollamada Zoom UDP 8801 (170.114.76.41) y WebRTC UDP 19300 (104.29.143.47)
        tabla_pin._ingestar_campos_flujo(
            t_base + 5.0, "192.168.18.10", 50768, "170.114.76.41", 8801, 17, "UDP", 120, 0, 20, -1
        )
        for i in range(399):
            tabla_pin._ingestar_campos_flujo(
                t_base + 5.01 + (i * 0.001), "170.114.76.41", 8801, "192.168.18.10", 50768, 17, "UDP", 1100, 0, 20, -1
            )
        tabla_pin._ingestar_campos_flujo(
            t_base + 6.0, "192.168.18.10", 49915, "104.29.143.47", 19300, 17, "UDP", 90, 0, 20, -1
        )
        for i in range(399):
            tabla_pin._ingestar_campos_flujo(
                t_base + 6.01 + (i * 0.001), "104.29.143.47", 19300, "192.168.18.10", 49915, 17, "UDP", 950, 0, 20, -1
            )

        tabla_pin.expirar_inactivos(t_base + 15.0, forzar_todos=True)
        regs_descarga = tabla_pin.extraer_registros()
        pinning_descarga_ok = (
            len(regs_descarga) == 6
            and all(r["src_ip"] == "192.168.18.10" for r in regs_descarga)
        )
        r_lote_descarga = cliente.post("/api/predict/batch", json={"records": regs_descarga}, headers=cabeceras)
        conntrack_descarga_ok = r_lote_descarga.status_code == 200 and r_lote_descarga.json().get("ddos") == 0

        for puerto_dst in (80, 8080):
            for i in range(400):
                t_pkt = t_base + 20.0 + (i * 0.00002)
                tabla_pin._ingestar_campos_flujo(
                    t_pkt, "203.0.113.88", 443, "192.168.18.10", puerto_dst, 6, "TCP", 11500, 0x18, 20, 512
                )
        regs_flood = tabla_pin.extraer_registros()
        reversion_midstream_ok = (
            len(regs_flood) == 2
            and all(
                r["src_ip"] == "203.0.113.88"
                and r["dst_ip"] == "192.168.18.10"
                and r["features"][4] == 400.0
                and r["features"][5] == 0.0
                for r in regs_flood
            )
        )
        r_lote_flood = cliente.post("/api/predict/batch", json={"records": regs_flood}, headers=cabeceras)
        deteccion_flood_ok = r_lote_flood.status_code == 200 and r_lote_flood.json().get("ddos") == 2

        afirmar_prueba(
            "Direction Pinning LRU, Reversión Mid-Stream Unidireccional y Conntrack Anti-FP",
            pinning_descarga_ok and conntrack_descarga_ok and reversion_midstream_ok and deteccion_flood_ok,
            f"Descarga/Zoom/WebRTC DDoS={r_lote_descarga.json().get('ddos')}/6 | Flood ACK DDoS={r_lote_flood.json().get('ddos')}/2",
        )

    print("=" * 65)
    print(f"  RESULTADO FINAL: {superadas}/{totales} PRUEBAS SUPERADAS SATISFACTORIAMENTE")
    print("=" * 65)
    return superadas == totales


run_production_audit = ejecutar_auditoria_produccion


if __name__ == "__main__":
    exito = ejecutar_auditoria_produccion()
    sys.exit(0 if exito else 1)
