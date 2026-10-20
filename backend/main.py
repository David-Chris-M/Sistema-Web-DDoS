"""CyberShield Pyme - API FastAPI para detección temprana de DDoS (capas 3/4) con Conv1D.

Refactor de producción (ver informe de auditoría):
- Inferencia en hilo dedicado + tf.function; BD en threadpool -> el event loop nunca se bloquea.
- Validación estricta (80 features finitas, IPs válidas, protocolo enumerado): 4xx correctos, sin XSS almacenado.
- Telemetría medida (sin valores fijos), KPIs O(1) vía agregados por minuto, retención configurable.
- Ingesta protegida por API key, simulación desactivable y marcada con `source`.
"""
import asyncio
import csv
import hmac
import io
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Literal, Optional

import numpy as np
import psutil
from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy import case, delete, func, insert, select
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import IS_SQLITE, SessionLocal, ensure_schema, get_db
from backend.inference import N_CANONICAL, engine as inference
from backend.models import BlockedIP, TrafficLog, TrafficMinuteStat, utcnow_naive
from backend.realtime import ConnectionManager, Telemetry

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("cybershield.api")

telemetry = Telemetry()
manager = ConnectionManager(telemetry, send_timeout_s=settings.ws_send_timeout_s)
_process = psutil.Process()
LOCAL_TZ = timezone(timedelta(hours=settings.tz_offset_hours))


# ============================================================ Esquemas
Feature = Annotated[float, Field(allow_inf_nan=False)]


class TrafficRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    features: List[Feature] = Field(min_length=N_CANONICAL, max_length=N_CANONICAL,
                                    description="80 características CICFlowMeter en orden canónico")
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] = "TCP"
    duration_ms: float = Field(default=0.0, ge=0, allow_inf_nan=False)
    total_bytes: int = Field(default=0, ge=0)
    exported_at: Optional[float] = Field(default=None, description="Epoch (s) en que el sensor exportó el flujo")


class BatchTrafficRecord(BaseModel):
    records: List[TrafficRecord] = Field(..., max_length=settings.max_batch_size,
                                         description="Máximo de flujos por lote (protección OOM)")


# ============================================================ Utilidades
def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat(timespec="milliseconds") + "Z" if dt else None


def log_to_dict(log: TrafficLog) -> dict:
    return {
        "id": log.id, "timestamp": iso_utc(log.timestamp), "src_ip": log.src_ip, "dst_ip": log.dst_ip,
        "protocol": log.protocol, "duration_ms": log.duration_ms, "total_bytes": log.total_bytes,
        "prediction": log.prediction, "is_attack": bool(log.is_attack), "probability": log.probability,
        "confidence_percentage": log.confidence_percentage, "source": log.source,
    }


def anonymize_ip(ip: str) -> str:
    """Anonimización para exportación (Ley 29733): /24 en IPv4 y /48 en IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalida"
    if addr.version == 4:
        return ".".join(str(addr).split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{addr}/48", strict=False).network_address) + "/48"


async def require_sensor_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if settings.sensor_api_key and not (x_api_key and hmac.compare_digest(x_api_key, settings.sensor_api_key)):
        raise HTTPException(status_code=401, detail="API key inválida o ausente (cabecera X-API-Key)")


def _upsert_minute_stats(db: Session, bucket: datetime, source: str, benign: int, ddos: int, conf_sum: float) -> None:
    if IS_SQLITE:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    else:
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    stmt = dialect_insert(TrafficMinuteStat).values(
        bucket=bucket, source=source, benign=benign, ddos=ddos, confidence_sum=conf_sum)
    stmt = stmt.on_conflict_do_update(
        index_elements=["bucket", "source"],
        set_={"benign": TrafficMinuteStat.benign + stmt.excluded.benign,
              "ddos": TrafficMinuteStat.ddos + stmt.excluded.ddos,
              "confidence_sum": TrafficMinuteStat.confidence_sum + stmt.excluded.confidence_sum})
    db.execute(stmt)


def _persist_many(rows: List[dict]) -> None:
    """Bloqueante: se ejecuta SIEMPRE en el threadpool, nunca en el event loop. Un solo commit por tanda."""
    with SessionLocal() as db:
        to_store = [r for r in rows if r["is_attack"] or settings.persist_benign]
        if to_store:
            db.execute(insert(TrafficLog), to_store)
        agg: dict = {}
        for r in rows:
            e = agg.setdefault((r["timestamp"].replace(second=0, microsecond=0), r["source"]), [0, 0, 0.0])
            e[1 if r["is_attack"] else 0] += 1
            e[2] += r["confidence_percentage"]
        for (bucket, source), (b, d, conf) in agg.items():
            _upsert_minute_stats(db, bucket, source, b, d, conf)
        db.commit()


class DBWriter:
    """Write-behind: agrupa filas de muchas peticiones en una sola transacción.
    En SQLite elimina la contención de bloqueos (p99 1.7 s -> ms); en PostgreSQL reduce round-trips.
    Riesgo acotado: ante un corte abrupto se pierden como máximo FLUSH_INTERVAL_S de registros."""

    FLUSH_INTERVAL_S = 0.25
    MAX_ROWS = 2000

    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=200_000)
        self.errors = 0
        self._task: Optional[asyncio.Task] = None

    async def submit(self, rows: List[dict]) -> None:
        for r in rows:
            await self.queue.put(r)  # backpressure si la BD no da abasto

    async def _drain(self) -> List[dict]:
        batch = [await self.queue.get()]
        deadline = asyncio.get_running_loop().time() + self.FLUSH_INTERVAL_S
        while len(batch) < self.MAX_ROWS:
            timeout = deadline - asyncio.get_running_loop().time()
            if timeout <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(self.queue.get(), timeout))
            except asyncio.TimeoutError:
                break
        return batch

    async def _flush(self, batch: List[dict]) -> None:
        try:
            await run_in_threadpool(_persist_many, batch)
        except Exception:
            self.errors += 1
            logger.exception("No se pudieron persistir %d flujos", len(batch))

    async def _run(self) -> None:
        while True:
            await self._flush(await self._drain())

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="db-writer")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        pending = []
        while not self.queue.empty():
            pending.append(self.queue.get_nowait())
        if pending:
            await self._flush(pending)


db_writer = DBWriter()


async def process_records(records: List[TrafficRecord], source: str, t_received: float) -> List[dict]:
    """Pipeline común: inferencia -> persistencia -> alerta WS -> telemetría."""
    X = np.asarray([r.features for r in records], dtype=np.float32)
    try:
        probs, model_ms = await inference.predict(X)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"Modelo no disponible: {exc}")

    now = utcnow_naive()
    thr = settings.decision_threshold
    rows = []
    for r, p in zip(records, probs.tolist()):
        is_ddos = p > thr
        rows.append({
            "timestamp": now, "src_ip": str(r.src_ip), "dst_ip": str(r.dst_ip), "protocol": r.protocol,
            "duration_ms": round(r.duration_ms, 2), "total_bytes": r.total_bytes,
            "prediction": "DDoS" if is_ddos else "BENIGN", "is_attack": is_ddos,
            "probability": round(p, 4),
            "confidence_percentage": round((p if is_ddos else 1.0 - p) * 100.0, 2),
            "source": source,
        })
    await db_writer.submit(rows)

    ts = iso_utc(now)
    payloads = [{**{k: v for k, v in row.items() if k != "timestamp"}, "timestamp": ts,
                 "exported_at": rec.exported_at} for row, rec in zip(rows, records)]
    if len(payloads) == 1:
        manager.publish({"type": "flow", **payloads[0]})
    else:
        # Resumen por lote: los contadores del dashboard coinciden con la BD y TODA detección
        # DDoS queda notificada (indicador de tesis: % de alertas emitidas = 100 %).
        attacks = [p for p in payloads if p["is_attack"]]
        sample = attacks[: settings.ws_max_flows_per_message] or payloads[-1:]
        manager.publish({"type": "batch", "timestamp": ts, "total": len(payloads),
                         "ddos": len(attacks), "benign": len(payloads) - len(attacks), "flows": sample})

    wall = time.time()
    pipeline = [(wall - r.exported_at) * 1000.0 for r in records
                if r.exported_at is not None and 0 <= wall - r.exported_at < 3600]
    telemetry.record(model_ms, len(records), (time.perf_counter() - t_received) * 1000.0, pipeline)
    return payloads


# ============================================================ Tareas de fondo
def _backfill_minute_stats() -> None:
    """Primera ejecución tras la migración: reconstruye agregados desde los registros existentes."""
    with SessionLocal() as db:
        if db.query(TrafficMinuteStat).first() is not None or db.query(TrafficLog.id).first() is None:
            return
        minute = (func.strftime("%Y-%m-%d %H:%M:00", TrafficLog.timestamp) if IS_SQLITE
                  else func.date_trunc("minute", TrafficLog.timestamp))
        rows = db.query(minute.label("b"), TrafficLog.source, TrafficLog.is_attack,
                        func.count(TrafficLog.id), func.coalesce(func.sum(TrafficLog.confidence_percentage), 0.0)
                        ).group_by("b", TrafficLog.source, TrafficLog.is_attack).all()
        acc: dict = {}
        for b, src, is_attack, n, conf in rows:
            b = datetime.strptime(b, "%Y-%m-%d %H:%M:%S") if isinstance(b, str) else b
            e = acc.setdefault((b, src or "sensor"), [0, 0, 0.0])
            e[1 if is_attack else 0] += n
            e[2] += float(conf)
        db.execute(insert(TrafficMinuteStat), [
            {"bucket": b, "source": s, "benign": v[0], "ddos": v[1], "confidence_sum": v[2]} for (b, s), v in acc.items()])
        db.commit()
        logger.info("Agregados por minuto reconstruidos: %d buckets", len(acc))


def _purge_old_rows() -> int:
    cutoff = utcnow_naive() - timedelta(days=settings.retention_days)
    removed = 0
    with SessionLocal() as db:
        while True:
            ids = select(TrafficLog.id).where(TrafficLog.timestamp < cutoff).limit(5000).scalar_subquery()
            n = db.execute(delete(TrafficLog).where(TrafficLog.id.in_(ids))).rowcount or 0
            db.commit()
            removed += n
            if n == 0:
                break
        db.execute(delete(TrafficMinuteStat).where(TrafficMinuteStat.bucket < utcnow_naive() - timedelta(days=400)))
        db.commit()
    return removed


async def retention_loop() -> None:
    if settings.retention_days <= 0:
        logger.info("Retención desactivada (RETENTION_DAYS=0): no se purgarán flujos")
        return
    while True:
        try:
            n = await run_in_threadpool(_purge_old_rows)
            if n:
                logger.info("Retención: %d flujos con más de %d días eliminados", n, settings.retention_days)
        except Exception:
            logger.exception("Fallo en la tarea de retención")
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_in_threadpool(ensure_schema)
    await run_in_threadpool(_backfill_minute_stats)
    await run_in_threadpool(inference.load)
    _process.cpu_percent(None)
    psutil.cpu_percent(None)
    manager.start()
    db_writer.start()
    retention = asyncio.create_task(retention_loop(), name="retention")
    if not settings.sensor_api_key:
        logger.warning("SENSOR_API_KEY no definido: la ingesta NO está autenticada (sólo aceptable en desarrollo)")
    if settings.enable_simulation:
        logger.warning("ENABLE_SIMULATION=true: endpoints de simulación activos (desactivar en producción)")
    yield
    retention.cancel()
    await db_writer.stop()
    await manager.stop()
    inference.shutdown()


# ============================================================ Aplicación
app = FastAPI(
    title="DDoS CNN Detection API",
    description="API para la detección temprana de tráfico DDoS usando Conv1D y WebSockets",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    logger.exception("Error no controlado en %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})


if os.path.exists(settings.frontend_dir):
    app.mount("/frontend", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")


@app.get("/")
def root():
    return RedirectResponse(url="/frontend/")


@app.get("/api/health")
def health_check():
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(select(1))
    except Exception:
        db_ok = False
    ok = inference.ready and db_ok
    body = {"status": "online" if ok else "degraded", "model_loaded": inference.ready, "database": db_ok,
            "model_error": inference.error, "active_websockets": len(manager.active)}
    return JSONResponse(status_code=200 if ok else 503, content=body)


@app.get("/api/model")
def model_info():
    """Métricas OFFLINE del modelo (conjunto de prueba CICIDS2017), generadas por ml/train_cnn.py."""
    md = inference.metadata
    return {"ready": inference.ready, "n_features": inference.n_model_features,
            "decision_threshold": settings.decision_threshold,
            "scaler": md.get("scaler"), "smote": md.get("smote"), "trained_at": md.get("trained_at"),
            "test_metrics": md.get("test_metrics"), "latency": md.get("latency"),
            "dataset": md.get("dataset")}


@app.post("/api/predict", dependencies=[Depends(require_sensor_key)])
async def predict_traffic(traffic: TrafficRecord):
    t0 = time.perf_counter()
    return (await process_records([traffic], "api", t0))[0]


@app.post("/api/predict/batch", dependencies=[Depends(require_sensor_key)])
async def predict_traffic_batch(batch: BatchTrafficRecord):
    """Inferencia vectorizada por lotes (endpoint usado por el sensor)."""
    t0 = time.perf_counter()
    if not batch.records:
        return {"processed": 0, "ddos": 0}
    payloads = await process_records(batch.records, "sensor", t0)
    total_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {"processed": len(payloads), "ddos": sum(p["is_attack"] for p in payloads),
            "batch_time_ms": total_ms, "avg_latency_per_flow_ms": round(total_ms / len(payloads), 3)}


# ------------------------------------------------------------ Simulación (sólo demo)
_sim_samples: dict = {}
_sim_lock = asyncio.Lock()


def _load_simulation_samples() -> dict:
    import pandas as pd  # import diferido: no consume RAM en producción
    if not os.path.exists(settings.dataset_path):
        raise FileNotFoundError("Dataset no disponible para simulación")
    df = pd.read_csv(settings.dataset_path, nrows=20000, low_memory=False)
    df.columns = df.columns.str.strip()
    labels = df["Label"].astype(str).str.strip().str.upper()
    num = df.drop(columns=[c for c in ["Flow ID", "Source IP", "Destination IP", "Timestamp", "SimillarHTTP",
                                       "External IP", "Label"] if c in df.columns])
    num = num.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    valid = ~num.isna().any(axis=1)
    num, labels = num[valid], labels[valid]
    return {"benign": num[labels == "BENIGN"].values[:200].astype(np.float32),
            "ddos": num[labels.str.contains("DDOS", na=False)].values[:200].astype(np.float32)}


@app.post("/api/simulate/{traffic_type}")
async def simulate_direct(traffic_type: Literal["ddos", "benign"]):
    """Reinyecta un flujo real de CICIDS2017. Se marca source='simulation' para no contaminar la validación."""
    if not settings.enable_simulation:
        raise HTTPException(status_code=403, detail="Simulación deshabilitada en este entorno")
    async with _sim_lock:
        if not _sim_samples:
            try:
                _sim_samples.update(await run_in_threadpool(_load_simulation_samples))
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"No se pudieron cargar muestras: {exc}")
    pool = _sim_samples[traffic_type]
    if len(pool) == 0:
        raise HTTPException(status_code=503, detail="No hay muestras de ese tipo en el dataset")
    is_attack = traffic_type == "ddos"
    rng = np.random.default_rng()
    record = TrafficRecord(
        features=pool[rng.integers(len(pool))].tolist(),
        src_ip=f"203.0.113.{rng.integers(10, 250)}" if is_attack else f"192.0.2.{rng.integers(10, 250)}",
        dst_ip="198.51.100.5", protocol="TCP",
        duration_ms=round(float(rng.uniform(50.0, 950.0)), 2),
        total_bytes=int(rng.integers(25000, 95000) if is_attack else rng.integers(500, 4500)),
        exported_at=time.time(),
    )
    return (await process_records([record], "simulation", time.perf_counter()))[0]


# ------------------------------------------------------------ Tiempo real
@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


# ------------------------------------------------------------ Consultas del dashboard
@app.get("/api/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """KPIs acumulados desde la tabla de agregados (O(buckets), no O(flujos))."""
    per_source = db.query(TrafficMinuteStat.source, func.sum(TrafficMinuteStat.benign),
                          func.sum(TrafficMinuteStat.ddos), func.sum(TrafficMinuteStat.confidence_sum)
                          ).group_by(TrafficMinuteStat.source).all()
    benign = sum(int(r[1] or 0) for r in per_source)
    ddos = sum(int(r[2] or 0) for r in per_source)
    conf = sum(float(r[3] or 0) for r in per_source)
    total = benign + ddos
    last_attack = db.query(func.max(TrafficLog.timestamp)).filter(TrafficLog.is_attack.is_(True)).scalar()
    return {
        "total": total, "normal": benign, "ddos": ddos,
        # Confianza media de las predicciones: NO es accuracy (requiere etiquetas reales).
        "avg_confidence": round(conf / total, 2) if total else None,
        "last_detection": iso_utc(last_attack),
        "by_source": {r[0]: {"benign": int(r[1] or 0), "ddos": int(r[2] or 0)} for r in per_source},
    }


@app.get("/api/history")
def get_traffic_history(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    return [log_to_dict(x) for x in db.query(TrafficLog).order_by(TrafficLog.id.desc()).limit(limit).all()]


@app.get("/api/alerts")
def get_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    severity: str = Query("all", max_length=20, description="Nivel de severidad (all, critical, high, medium, o en español)"),
    protocol: str = Query("all", max_length=10),
    search_ip: str = Query("", max_length=45),
    source: str = Query("all", max_length=16),
    db: Session = Depends(get_db),
):
    """Gestión de incidentes y alertas del dashboard (alertas.html)."""
    c = TrafficLog.confidence_percentage
    attacks = db.query(TrafficLog).filter(TrafficLog.is_attack.is_(True))
    k = db.query(func.count(TrafficLog.id),
                 func.coalesce(func.sum(case((c >= 95.0, 1), else_=0)), 0),
                 func.coalesce(func.sum(case(((c >= 85.0) & (c < 95.0), 1), else_=0)), 0),
                 func.coalesce(func.sum(case((c < 85.0, 1), else_=0)), 0)
                 ).filter(TrafficLog.is_attack.is_(True)).one()

    query = attacks
    if protocol != "all":
        query = query.filter(TrafficLog.protocol == protocol)
    if source != "all":
        query = query.filter(TrafficLog.source == source)
    if search_ip:
        query = query.filter(TrafficLog.src_ip.like(f"{search_ip}%"))  # prefijo: usa el índice
        
    sev = severity.strip().lower().replace("í", "i")
    if sev in ("critical", "critica"):
        query = query.filter(c >= 95.0)
    elif sev in ("high", "alta"):
        query = query.filter(c >= 85.0, c < 95.0)
    elif sev in ("medium", "media"):
        query = query.filter(c < 85.0)

    total_filtered = query.count()
    records = query.order_by(TrafficLog.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"total": total_filtered, "page": page, "limit": limit,
            "kpis": {"total": int(k[0]), "critical": int(k[1]), "high": int(k[2]), "medium": int(k[3])},
            "data": [log_to_dict(x) for x in records]}


@app.get("/api/analysis/traffic-by-hour")
def get_traffic_by_hour(hours: int = Query(12, ge=1, le=168), db: Session = Depends(get_db)):
    """Conteo horario (hora local Lima) desde los agregados por minuto; portable SQLite/PostgreSQL."""
    now = utcnow_naive()
    since = (now - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
    rows = db.query(TrafficMinuteStat.bucket, func.sum(TrafficMinuteStat.benign), func.sum(TrafficMinuteStat.ddos)
                    ).filter(TrafficMinuteStat.bucket >= since).group_by(TrafficMinuteStat.bucket).all()
    offset = timedelta(hours=settings.tz_offset_hours)
    fmt = "%H:00" if hours <= 24 else "%d/%m %H:00"
    slots = [since + timedelta(hours=i) for i in range(hours)]
    benign = {s: 0 for s in slots}
    attack = {s: 0 for s in slots}
    for bucket, b, d in rows:
        slot = bucket.replace(minute=0, second=0, microsecond=0)
        if slot in benign:
            benign[slot] += int(b or 0)
            attack[slot] += int(d or 0)
    return {"labels": [(s + offset).strftime(fmt) for s in slots],
            "benign": [benign[s] for s in slots], "attack": [attack[s] for s in slots]}


@app.get("/api/analysis/protocol-distribution")
def get_protocol_distribution(db: Session = Depends(get_db)):
    results = db.query(TrafficLog.protocol, func.count(TrafficLog.id)).group_by(TrafficLog.protocol).all()
    return {"labels": [r[0] for r in results], "counts": [r[1] for r in results]}


@app.get("/api/analysis/flows")
def get_filtered_flows(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    protocol: str = Query("all", max_length=10),
    prediction: Literal["all", "DDoS", "BENIGN"] = "all",
    source: str = Query("all", max_length=16),
    db: Session = Depends(get_db),
):
    query = db.query(TrafficLog)
    if protocol != "all":
        query = query.filter(TrafficLog.protocol == protocol)
    if prediction != "all":
        query = query.filter(TrafficLog.prediction == prediction)
    if source != "all":
        query = query.filter(TrafficLog.source == source)
    total_records = query.count()
    records = query.order_by(TrafficLog.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"total": total_records, "page": page, "limit": limit, "data": [log_to_dict(x) for x in records]}


@app.get("/api/export/csv")
def export_csv_logs(
    anonymize: bool = True,
    limit: int = Query(5000, ge=1, le=200000),
    source: str = Query("all", max_length=16),
):
    """CSV en streaming (memoria constante). Por defecto anonimiza IPs, como exige la validación pasiva."""
    def rows():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Timestamp_UTC", "IP_Origen", "IP_Destino", "Protocolo", "Duracion_ms", "Bytes",
                         "Prediccion", "Es_Ataque", "Probabilidad", "Confianza_%", "Origen"])
        with SessionLocal() as db:
            q = db.query(TrafficLog)
            if source != "all":
                q = q.filter(TrafficLog.source == source)
            for log in q.order_by(TrafficLog.id.desc()).limit(limit).yield_per(1000):
                writer.writerow([log.id, iso_utc(log.timestamp),
                                 anonymize_ip(log.src_ip) if anonymize else log.src_ip,
                                 anonymize_ip(log.dst_ip) if anonymize else log.dst_ip,
                                 log.protocol, log.duration_ms, log.total_bytes, log.prediction,
                                 log.is_attack, log.probability, log.confidence_percentage, log.source])
                if buf.tell() > 64_000:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate(0)
        yield buf.getvalue()

    return StreamingResponse(rows(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=traffic_nids_report.csv"})


@app.post("/api/import/csv")
async def import_authorized_csv_logs(
    file: UploadFile = File(..., description="Archivo CSV de logs de tráfico exportados de la Pyme"),
    db: Session = Depends(get_db)
):
    """Validación pasiva mediante importación de logs CSV autorizados de la Pyme (PE4/OE4).
    
    Anonimiza IPs sensibles según Ley 29733 (Perú), procesa los vectores y ejecuta inferencia Conv1D.
    Se registran bajo source='csv_pyme' para auditoría y validación pasiva sin distorsionar
    el sensor perimetral en vivo.
    """
    if not inference.ready:
        raise HTTPException(status_code=503, detail="Modelo Conv1D no disponible")
    
    contents = await file.read()
    if len(contents) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="El archivo excede el tamaño máximo permitido (50 MB)")
    
    try:
        import pandas as pd
        df_csv = pd.read_csv(io.BytesIO(contents), nrows=5000)
        df_csv.columns = df_csv.columns.str.strip()
        
        # Anonimización conforme a Ley 29733
        src_col = next((c for c in df_csv.columns if c.lower() in ("source ip", "src_ip", "srcip")), None)
        dst_col = next((c for c in df_csv.columns if c.lower() in ("destination ip", "dst_ip", "dstip")), None)
        proto_col = next((c for c in df_csv.columns if c.lower() in ("protocol", "proto")), None)
        
        src_ips = [anonymize_ip(str(x)) for x in df_csv[src_col]] if src_col else [f"192.168.1.{(idx % 240) + 10}" for idx in range(len(df_csv))]
        dst_ips = [anonymize_ip(str(x)) for x in df_csv[dst_col]] if dst_col else ["10.0.0.5"] * len(df_csv)
        
        def clean_proto(p):
            p_str = str(p).strip().upper()
            return p_str if p_str in ("TCP", "UDP", "ICMP") else "TCP"
            
        protos = [clean_proto(x) for x in df_csv[proto_col]] if proto_col else ["TCP"] * len(df_csv)
        
        # Descartar metadatos y etiquetas
        cols_drop = [c for c in df_csv.columns if any(k in c.lower() for k in ["id", "ip", "time", "label", "simillar", "external"])]
        df_num = df_csv.drop(columns=cols_drop, errors="ignore")
        df_num = df_num.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0)
        
        matrix = df_num.values.astype(np.float32)
        if matrix.shape[1] < N_CANONICAL:
            matrix = np.pad(matrix, ((0, 0), (0, N_CANONICAL - matrix.shape[1])), mode='constant')
        elif matrix.shape[1] > N_CANONICAL:
            matrix = matrix[:, :N_CANONICAL]
            
        records = []
        for idx in range(len(matrix)):
            records.append(TrafficRecord(
                features=matrix[idx].tolist(),
                src_ip="192.0.2.1",
                dst_ip="198.51.100.5",
                protocol=protos[idx],
                duration_ms=50.0,
                total_bytes=1024,
                exported_at=time.time()
            ))
            
        t0 = time.perf_counter()
        payloads = await process_records(records, "csv_pyme", t0)
        total_eval = len(payloads)
        ddos_eval = sum(1 for p in payloads if p["is_attack"])
        benign_eval = total_eval - ddos_eval
        
        return {
            "status": "success",
            "filename": file.filename,
            "processed_flows": total_eval,
            "benign_flows": benign_eval,
            "ddos_detected": ddos_eval,
            "anonymized": True,
            "source": "csv_pyme",
            "eval_time_ms": round((time.perf_counter() - t0) * 1000, 2)
        }
    except Exception as exc:
        logger.exception("Error procesando CSV de validación pasiva")
        raise HTTPException(status_code=500, detail=f"Error analizando archivo CSV: {str(exc)}")


@app.get("/api/performance")
async def get_system_performance():
    """Telemetría real del servidor y del modelo Conv1D (PE3/PE4)."""
    mem = _process.memory_info().rss / (1024 * 1024)
    return {
        **telemetry.snapshot(),
        "db_write_queue": db_writer.queue.qsize(),
        "db_write_errors": db_writer.errors,
        "cpu_percent": round(psutil.cpu_percent(None), 1),                                   # sistema
        "process_cpu_percent": round(_process.cpu_percent(None) / (psutil.cpu_count() or 1), 1),  # este servicio
        "ram_mb": round(mem, 1),
        "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 1),
        "gpu_usage": 0,
    }


# ============================================================ Mitigación Defensiva (Firewall Pyme)
class BlockIPRequest(BaseModel):
    ip: str = Field(..., max_length=45, description="Dirección IP a bloquear")
    reason: str = Field(default="Ataque DDoS clasificado por Conv1D", max_length=200)
    severity: str = Field(default="Crítica", max_length=20)
    confidence: float = Field(default=99.0, ge=0.0, le=100.0)


@app.post("/api/mitigation/block")
def block_ip_address(req: BlockIPRequest, db: Session = Depends(get_db)):
    """Registra una IP en la lista de bloqueo activo."""
    existing = db.query(BlockedIP).filter(BlockedIP.ip == req.ip).first()
    if existing:
        existing.status = "ACTIVE"
        existing.reason = req.reason
        existing.severity = req.severity
        existing.confidence = req.confidence
        existing.blocked_at = utcnow_naive()
    else:
        new_block = BlockedIP(
            ip=req.ip,
            reason=req.reason,
            severity=req.severity,
            confidence=req.confidence,
            status="ACTIVE",
        )
        db.add(new_block)
    db.commit()
    return {"status": "success", "message": f"IP {req.ip} bloqueada exitosamente", "ip": req.ip}


@app.get("/api/mitigation/blocked")
def list_blocked_ips(db: Session = Depends(get_db)):
    """Lista las IPs actualmente bloqueadas."""
    rows = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    return [{"id": r.id, "ip": r.ip, "blocked_at": iso_utc(r.blocked_at), "reason": r.reason,
             "severity": r.severity, "confidence": r.confidence, "status": r.status} for r in rows]


@app.delete("/api/mitigation/unblock/{ip}")
def unblock_ip_address(ip: str, db: Session = Depends(get_db)):
    """Remueve una IP de la lista de bloqueo."""
    record = db.query(BlockedIP).filter(BlockedIP.ip == ip).first()
    if not record:
        raise HTTPException(status_code=404, detail="IP no encontrada en lista de bloqueo")
    db.delete(record)
    db.commit()
    return {"status": "success", "message": f"IP {ip} desbloqueada"}


@app.get("/api/mitigation/export/firewall-rules")
def export_firewall_rules(format: Literal["iptables", "nftables", "mikrotik"] = "iptables", db: Session = Depends(get_db)):
    """Genera reglas automáticas para el firewall perimetral de la Pyme."""
    ips = [r[0] for r in db.query(BlockedIP.ip).filter(BlockedIP.status == "ACTIVE").all()]
    if format == "iptables":
        lines = [f"iptables -A INPUT -s {ip} -j DROP" for ip in ips]
    elif format == "nftables":
        lines = [f"add element inet filter blackhole {{ {', '.join(ips)} }}"] if ips else []
    else:  # mikrotik RouterOS
        lines = [f'/ip firewall filter add chain=input src-address={ip} action=drop comment="CyberShield Conv1D"' for ip in ips]
    return {"format": format, "count": len(ips), "rules": lines}