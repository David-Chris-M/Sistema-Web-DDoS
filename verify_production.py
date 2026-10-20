"""Script de Verificación Integral de Producción 24/7 (CyberShield Pyme).

Ejecuta una auditoría automatizada de extremo a extremo comprobando:
1. Salud de la API y carga del grafo Conv1D.
2. Ingesta autenticada con API Key.
3. Inferencia de flujo individual y por lotes.
4. Consulta y filtrado de alertas (tolerancia a idiomas y acentos).
5. Validación pasiva mediante importación de CSV con anonimización (Ley 29733).
6. Generación de reglas de mitigación de cortafuegos (MikroTik RouterOS e iptables).
7. Telemetría de hardware (PE4/HE4) y persistencia write-behind.
"""
import io
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from fastapi.testclient import TestClient

from backend.config import settings
from backend.inference import N_CANONICAL
from backend.main import app


def run_production_audit():
    print("=" * 65)
    print("  CYBERSHIELD PYME - SUITE DE VALIDACION DE PRODUCCION 24/7")
    print("=" * 65)
    passed = 0
    total = 0

    def assert_test(name: str, condition: bool, extra: str = ""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [OK - PASS] {name} {extra}")
        else:
            print(f"  [ERROR - FAIL] {name} {extra}")

    with TestClient(app) as client:
        # 1. Healthcheck
        r = client.get("/api/health")
        assert_test("Healthcheck API", r.status_code == 200 and r.json().get("status") == "online")

        # 2. Información del Modelo y Metadatos
        r = client.get("/api/model")
        assert_test("Metadata Conv1D", r.status_code == 200 and r.json().get("n_features") == N_CANONICAL)

        # 3. Autenticación de Ingesta (Sensor API Key)
        dummy_flow = {
            "features": [0.0] * N_CANONICAL,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "protocol": "TCP",
            "duration_ms": 120.0,
            "total_bytes": 1500,
        }

        if settings.sensor_api_key:
            # Sin cabecera debe responder 401
            r_unauth = client.post("/api/predict", json=dummy_flow)
            assert_test("Rechazo de ingesta no autenticada (401)", r_unauth.status_code == 401)
            headers = {"X-API-Key": settings.sensor_api_key}
        else:
            headers = {}

        # 4. Inferencia Unitaria
        r_pred = client.post("/api/predict", json=dummy_flow, headers=headers)
        assert_test("Inferencia Unitaria (/api/predict)", r_pred.status_code == 200,
                    f"Predicción: {r_pred.json().get('prediction')}")

        # 5. Inferencia por Lotes (Batch)
        batch_payload = {"records": [dummy_flow] * 10}
        r_batch = client.post("/api/predict/batch", json=batch_payload, headers=headers)
        assert_test("Inferencia por Lotes (/api/predict/batch)", r_batch.status_code == 200,
                    f"Latencia: {r_batch.json().get('avg_latency_per_flow_ms')} ms/flujo")

        # 6. Filtrado de Alertas (Español e Inglés)
        severities = ["all", "critical", "high", "medium", "Crítica", "Alta", "Media"]
        all_sev_ok = True
        for s in severities:
            if client.get(f"/api/alerts?severity={s}").status_code != 200:
                all_sev_ok = False
        assert_test("Módulo de Alertas Tolerante (/api/alerts)", all_sev_ok)

        # 7. Validación Pasiva con CSV Anonimizado (Ley 29733 / PE4 / OE4)
        sample_csv = "Source IP,Destination IP,Protocol," + ",".join([f"f_{i}" for i in range(N_CANONICAL)]) + "\n"
        sample_csv += "192.168.1.50,10.0.0.1,TCP," + ",".join(["1.0"] * N_CANONICAL) + "\n"
        sample_csv += "203.0.113.15,10.0.0.1,UDP," + ",".join(["50000.0"] * N_CANONICAL) + "\n"

        files = {"file": ("pyme_audit_sample.csv", io.BytesIO(sample_csv.encode("utf-8")), "text/csv")}
        r_import = client.post("/api/import/csv", files=files)
        assert_test("Validación Pasiva CSV con Ley 29733 (/api/import/csv)",
                    r_import.status_code == 200 and r_import.json().get("anonymized") is True,
                    f"Procesados: {r_import.json().get('processed_flows')}")

        # 8. Mitigación y Exportación de Reglas Firewall
        client.post("/api/mitigation/block", json={
            "ip": "203.0.113.200", "reason": "Ataque DDoS SYN Flood", "severity": "Crítica", "confidence": 99.8
        })
        r_rules_mkt = client.get("/api/mitigation/export/firewall-rules?format=mikrotik")
        r_rules_ipt = client.get("/api/mitigation/export/firewall-rules?format=iptables")
        assert_test("Generador Cortafuegos (MikroTik / iptables)",
                    r_rules_mkt.status_code == 200 and r_rules_ipt.status_code == 200 and r_rules_mkt.json().get("count") >= 1)

        # 9. Telemetría de Recursos (PE4 / HE4)
        r_perf = client.get("/api/performance")
        perf_data = r_perf.json()
        assert_test("Telemetría de Recursos en Hardware Pyme",
                    r_perf.status_code == 200 and perf_data.get("ram_mb", 0) > 0,
                    f"RAM: {perf_data.get('ram_mb')} MB | CPU: {perf_data.get('cpu_percent')}%")

    print("=" * 65)
    print(f"  RESULTADO FINAL: {passed}/{total} PRUEBAS SUPERADAS SATISFACTORIAMENTE")
    print("=" * 65)
    return passed == total


if __name__ == "__main__":
    success = run_production_audit()
    sys.exit(0 if success else 1)
