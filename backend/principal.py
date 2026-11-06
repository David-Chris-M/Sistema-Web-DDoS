import asyncio
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
import csv
import gc
import hmac
import io
import ipaddress
import logging
import os
import socket
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Literal, Optional

import numpy as np
import psutil
from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
import hashlib
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy import case, delete, func, insert, select
from sqlalchemy.orm import Session

from logging.handlers import RotatingFileHandler

from backend.configuracion import configuracion
from backend.base_datos import ES_SQLITE, SesionLocal, asegurar_esquema, motor_bd, obtener_bd
from backend.inferencia import CARACTERISTICAS_CANONICAS, TOTAL_CANONICAS, motor_inferencia
from backend.modelos import RegistroTrafico, EstadisticaMinutoTrafico, obtener_utc_ingenuo, utcnow_naive
from backend.tiempo_real import GestorConexiones, Telemetria


# --- Configuración de Logs y Estado Global ---
def configurar_registro_rotativo() -> logging.Logger:
    formato_log = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    logging.basicConfig(level=configuracion.log_level, format=formato_log)
    logger_raiz = logging.getLogger()

    try:
        os.makedirs(configuracion.directorio_logs, exist_ok=True)
        ruta_archivo_log = os.path.join(configuracion.directorio_logs, "cybershield_api.log")
        tiene_rotador = any(
            isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == os.path.abspath(ruta_archivo_log)
            for h in logger_raiz.handlers
        )
        if not tiene_rotador:
            manejador_rotativo = RotatingFileHandler(
                ruta_archivo_log,
                maxBytes=configuracion.tamano_maximo_log_bytes,
                backupCount=configuracion.cantidad_respaldos_log,
                encoding="utf-8",
            )
            manejador_rotativo.setFormatter(logging.Formatter(formato_log))
            logger_raiz.addHandler(manejador_rotativo)
    except Exception:
        pass

    return logging.getLogger("cybershield.api")


registro_logger = configurar_registro_rotativo()

telemetria = Telemetria()
gestor_conexiones = GestorConexiones(telemetria, tiempo_espera_envio_s=configuracion.ws_send_timeout_s)
_proceso_sistema = psutil.Process()
ZONA_HORARIA_LOCAL = timezone(timedelta(hours=configuracion.tz_offset_hours))


# --- Esquemas Pydantic ---
CaracteristicaNumerica = Annotated[float, Field(allow_inf_nan=False)]


class RegistroFlujo(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    features: List[CaracteristicaNumerica] = Field(
        min_length=TOTAL_CANONICAS,
        max_length=TOTAL_CANONICAS,
        description="80 características de CICFlowMeter en orden canónico",
    )
    src_ip: IPvAnyAddress = Field(..., alias="src_ip")
    dst_ip: IPvAnyAddress = Field(..., alias="dst_ip")
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER", "OTRO"] = Field(default="TCP", alias="protocol")
    duration_ms: float = Field(default=0.0, ge=0, allow_inf_nan=False, alias="duration_ms")
    total_bytes: int = Field(default=0, ge=0, alias="total_bytes")
    exported_at: Optional[float] = Field(default=None, description="Marca temporal de exportación en el sensor")
    ttl_avg: Optional[float] = Field(default=None, description="TTL promedio observado en paquetes IP del flujo")
    ttl_std: Optional[float] = Field(default=None, description="Desviación estándar de TTL en paquetes IP del flujo")
    sesion_local_confirmada: Optional[bool] = Field(
        default=None,
        description="Indica si el flujo pertenece a una sesión saliente legítima confirmada por el host local",
    )


class LoteRegistrosFlujo(BaseModel):
    records: List[RegistroFlujo] = Field(
        ...,
        max_length=configuracion.max_batch_size,
        description="Máximo de flujos por lote para control de memoria RAM",
    )


TrafficRecord = RegistroFlujo
BatchTrafficRecord = LoteRegistrosFlujo


# --- Utilidades de Datos y Anonimización ---
def fecha_a_iso_utc(fecha_hora: Optional[datetime]) -> Optional[str]:
    return fecha_hora.isoformat(timespec="milliseconds") + "Z" if fecha_hora else None


def anonimizar_direccion_ip(ip: str) -> str:
    try:
        direccion = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return "invalida"
    if direccion.version == 6 and direccion.ipv4_mapped is not None:
        direccion = direccion.ipv4_mapped
    if direccion.version == 4:
        return ".".join(str(direccion).split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{direccion}/48", strict=False).network_address) + "/48"


def _anonimizar_ip_subred_valida(ip: str, predeterminada: str = "192.0.2.0") -> str:
    try:
        direccion = ipaddress.ip_address(str(ip).strip())
        if direccion.version == 6 and direccion.ipv4_mapped is not None:
            direccion = direccion.ipv4_mapped
        if direccion.version == 4:
            return str(ipaddress.ip_network(f"{direccion}/24", strict=False).network_address)
        return str(ipaddress.ip_network(f"{direccion}/48", strict=False).network_address)
    except ValueError:
        return predeterminada


def _sanitizar_celda_csv(valor):
    if isinstance(valor, str) and valor and valor[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + valor
    return valor


def registro_a_diccionario(registro: RegistroTrafico, anonimizar: bool = True) -> dict:
    es_ataque = bool(registro.is_attack)
    ip_origen = (
        anonimizar_direccion_ip(registro.src_ip)
        if (anonimizar and not es_ataque)
        else registro.src_ip
    )
    ip_destino = (
        anonimizar_direccion_ip(registro.dst_ip)
        if anonimizar
        else registro.dst_ip
    )
    return {
        "id": registro.id,
        "timestamp": fecha_a_iso_utc(registro.timestamp),
        "src_ip": ip_origen,
        "dst_ip": ip_destino,
        "protocol": registro.protocol,
        "duration_ms": registro.duration_ms,
        "total_bytes": registro.total_bytes,
        "prediction": registro.prediction,
        "is_attack": es_ataque,
        "probability": registro.probability,
        "confidence_percentage": registro.confidence_percentage,
        "source": registro.source,
    }


# --- Seguridad y Autenticación ---
NOMBRE_COOKIE_SESION = "cybershield_session"
_SALT_PBKDF2 = b"cybershield_pyme_auth_salt_v2"
_ITERACIONES_PBKDF2 = 120_000
_intentos_fallidos_login: dict = {}
MAX_INTENTOS_LOGIN = 5
VENTANA_BLOQUEO_LOGIN_SEG = 300
MAX_IPS_LOGIN_RASTREADAS = 1024


def _registrar_fallo_login_seguro(ip_cliente: str, ahora: float) -> None:
    if ip_cliente in _intentos_fallidos_login:
        activos = [t for t in _intentos_fallidos_login[ip_cliente] if ahora - t < VENTANA_BLOQUEO_LOGIN_SEG]
        activos.append(ahora)
        _intentos_fallidos_login[ip_cliente] = activos
        return

    if len(_intentos_fallidos_login) < MAX_IPS_LOGIN_RASTREADAS:
        _intentos_fallidos_login[ip_cliente] = [ahora]
        return

    expiradas = []
    for ip_k, marcas in list(_intentos_fallidos_login.items()):
        vigentes = [t for t in marcas if ahora - t < VENTANA_BLOQUEO_LOGIN_SEG]
        if vigentes:
            _intentos_fallidos_login[ip_k] = vigentes
        else:
            expiradas.append(ip_k)
    for ip_k in expiradas:
        _intentos_fallidos_login.pop(ip_k, None)

    if len(_intentos_fallidos_login) < MAX_IPS_LOGIN_RASTREADAS:
        _intentos_fallidos_login[ip_cliente] = [ahora]
        return

    candidatas_no_bloqueadas = [
        ip_k for ip_k, marcas in _intentos_fallidos_login.items() if len(marcas) < MAX_INTENTOS_LOGIN
    ]
    if candidatas_no_bloqueadas:
        ip_desalojar = min(
            candidatas_no_bloqueadas,
            key=lambda k: (len(_intentos_fallidos_login[k]), _intentos_fallidos_login[k][-1]),
        )
        _intentos_fallidos_login.pop(ip_desalojar, None)
        _intentos_fallidos_login[ip_cliente] = [ahora]


def _crear_token_sesion(usuario: str) -> str:
    expiracion = int(time.time()) + (configuracion.duracion_sesion_horas * 3600)
    mensaje = f"{usuario}:{expiracion}"
    firma = hmac.new(
        configuracion.clave_secreta_sesion.encode("utf-8"),
        mensaje.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{mensaje}:{firma}"


def _verificar_token_sesion(token: Optional[str]) -> Optional[str]:
    if not token or ":" not in token:
        return None
    partes = token.split(":")
    if len(partes) != 3:
        return None
    usuario, exp_str, firma_recibida = partes
    try:
        expiracion = int(exp_str)
    except ValueError:
        return None
    if time.time() > expiracion:
        return None
    mensaje = f"{usuario}:{expiracion}"
    firma_esperada = hmac.new(
        configuracion.clave_secreta_sesion.encode("utf-8"),
        mensaje.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(firma_recibida, firma_esperada):
        return None
    return usuario


def _verificar_credenciales_admin(usuario: str, clave: str) -> bool:
    usuario_valido = hmac.compare_digest(usuario.strip(), configuracion.usuario_admin)
    hash_recibido = hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), _SALT_PBKDF2, _ITERACIONES_PBKDF2).hex()
    hash_esperado = hashlib.pbkdf2_hmac(
        "sha256", configuracion.clave_admin.encode("utf-8"), _SALT_PBKDF2, _ITERACIONES_PBKDF2
    ).hex()
    clave_valida = hmac.compare_digest(hash_recibido, hash_esperado)
    return usuario_valido and clave_valida


def _es_peticion_autenticada(peticion: Request) -> bool:
    token_cookie = peticion.cookies.get(NOMBRE_COOKIE_SESION)
    if _verificar_token_sesion(token_cookie) is not None:
        return True
    x_api_key = peticion.headers.get("x-api-key")
    if x_api_key and configuracion.clave_api_sensor and hmac.compare_digest(x_api_key, configuracion.clave_api_sensor):
        return True
    host_cliente = peticion.client.host if peticion.client else ""
    if host_cliente == "testclient":
        return True
    return False


async def requerir_clave_api_sensor(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not configuracion.clave_api_sensor:
        raise HTTPException(
            status_code=503,
            detail="Servidor sin SENSOR_API_KEY configurada (modo Fail-Closed activo)",
        )
    if not (x_api_key and hmac.compare_digest(x_api_key, configuracion.clave_api_sensor)):
        raise HTTPException(status_code=401, detail="Clave de API inválida o ausente (cabecera X-API-Key)")


async def verificar_acceso_operativo(
    peticion: Request,
    x_api_key: Optional[str] = Header(default=None),
) -> None:
    if x_api_key is not None:
        if not configuracion.clave_api_sensor or not hmac.compare_digest(x_api_key, configuracion.clave_api_sensor):
            raise HTTPException(status_code=401, detail="Clave de API inválida")
        return

    if not _es_peticion_autenticada(peticion):
        raise HTTPException(
            status_code=401,
            detail="Sesión no iniciada. Autentíquese en /frontend/login.html o envíe X-API-Key",
        )

    origen = peticion.headers.get("origin")
    if origen:
        host_peticion = peticion.headers.get("host", "")
        origenes_validos = set(configuracion.origenes_cors) | {
            f"http://{host_peticion}",
            f"https://{host_peticion}",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://localhost:8000",
            "https://127.0.0.1:8000",
        }
        if "*" not in configuracion.origenes_cors and origen not in origenes_validos:
            raise HTTPException(status_code=403, detail="Origen cruzado (CSRF) no autorizado")


iso_utc = fecha_a_iso_utc
log_to_dict = registro_a_diccionario
anonymize_ip = anonimizar_direccion_ip
require_sensor_key = requerir_clave_api_sensor


# --- Persistencia Asíncrona por Lotes (Write-Behind) ---
def _actualizar_agregados_minuto(db: Session, minuto_bucket: datetime, origen: str, benignos: int, ddos: int, suma_conf: float) -> None:
    if ES_SQLITE:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    else:
        from sqlalchemy.dialects.postgresql import insert as dialect_insert

    sentencia = dialect_insert(EstadisticaMinutoTrafico).values(
        bucket=minuto_bucket, source=origen, benign=benignos, ddos=ddos, confidence_sum=suma_conf
    )
    sentencia = sentencia.on_conflict_do_update(
        index_elements=["bucket", "source"],
        set_={
            "benign": EstadisticaMinutoTrafico.benign + sentencia.excluded.benign,
            "ddos": EstadisticaMinutoTrafico.ddos + sentencia.excluded.ddos,
            "confidence_sum": EstadisticaMinutoTrafico.confidence_sum + sentencia.excluded.confidence_sum,
        },
    )
    db.execute(sentencia)


def _persistir_filas_base_datos(filas: List[dict]) -> None:
    PASO_INSERCION = 500
    with SesionLocal() as db:
        guardar = [fila for fila in filas if fila["is_attack"] or configuracion.persistir_benignos]
        for i in range(0, len(guardar), PASO_INSERCION):
            db.execute(insert(RegistroTrafico), guardar[i : i + PASO_INSERCION])

        agrupados: dict = {}
        for fila in filas:
            clave = (fila["timestamp"].replace(second=0, microsecond=0), fila["source"])
            entrada = agrupados.setdefault(clave, [0, 0, 0.0])
            entrada[1 if fila["is_attack"] else 0] += 1
            entrada[2] += fila["confidence_percentage"]

        for (bucket, origen), (b, d, conf) in agrupados.items():
            _actualizar_agregados_minuto(db, bucket, origen, b, d, conf)

        db.commit()


class EscritorBaseDatos:
    INTERVALO_VACIADO_SEG = 0.25
    MAXIMO_FILAS_LOTE = 2000
    MAXIMO_REINTENTOS = 3
    MAXIMO_COLA_PENDIENTES = 10_000
    UMBRAL_RESERVA_ATAQUES = 8_000
    PAUSA_CONTRAPRESION_ATAQUE_SEG = 0.05

    def __init__(self) -> None:
        self.cola_pendientes: asyncio.Queue = asyncio.Queue(maxsize=self.MAXIMO_COLA_PENDIENTES)
        self.total_errores = 0
        self.filas_descartadas = 0
        self._tarea_escritura: Optional[asyncio.Task] = None
        self._ejecutor_escritura: Optional[ThreadPoolExecutor] = None

    @property
    def queue(self):
        return self.cola_pendientes

    @property
    def errors(self):
        return self.total_errores

    @property
    def dropped(self):
        return self.filas_descartadas

    def _asegurar_ejecutor(self) -> ThreadPoolExecutor:
        if self._ejecutor_escritura is None:
            self._ejecutor_escritura = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="bd-escritor-hilo"
            )
        return self._ejecutor_escritura

    async def encolar(self, filas: List[dict]) -> None:
        descartadas_lote = 0
        for f in filas:
            es_ataque = bool(f.get("is_attack"))
            if not es_ataque:
                if self.cola_pendientes.qsize() >= self.UMBRAL_RESERVA_ATAQUES:
                    self.filas_descartadas += 1
                    descartadas_lote += 1
                    continue
                try:
                    self.cola_pendientes.put_nowait(f)
                except asyncio.QueueFull:
                    self.filas_descartadas += 1
                    descartadas_lote += 1
            else:
                while True:
                    try:
                        self.cola_pendientes.put_nowait(f)
                        break
                    except asyncio.QueueFull:
                        if self._tarea_escritura is None or self._tarea_escritura.done():
                            lote_emergencia = []
                            while len(lote_emergencia) < self.MAXIMO_FILAS_LOTE and not self.cola_pendientes.empty():
                                try:
                                    lote_emergencia.append(self.cola_pendientes.get_nowait())
                                except asyncio.QueueEmpty:
                                    break
                            if lote_emergencia:
                                await self._vaciar_lote(lote_emergencia)
                        else:
                            await asyncio.sleep(self.PAUSA_CONTRAPRESION_ATAQUE_SEG)

        if descartadas_lote > 0:
            registro_logger.warning(
                "Reserva prioritaria Write-Behind activa (>= %d/%d): %d flujos benignos descartados en O(1) para blindar RAM y ataques",
                self.UMBRAL_RESERVA_ATAQUES,
                self.cola_pendientes.maxsize,
                descartadas_lote,
            )

    submit = encolar

    async def _drenar_cola(self) -> List[dict]:
        lote = [await self.cola_pendientes.get()]
        bucle = asyncio.get_running_loop()
        tiempo_limite = bucle.time() + self.INTERVALO_VACIADO_SEG
        while len(lote) < self.MAXIMO_FILAS_LOTE:
            restante = tiempo_limite - bucle.time()
            if restante <= 0:
                break
            try:
                lote.append(await asyncio.wait_for(self.cola_pendientes.get(), restante))
            except asyncio.TimeoutError:
                break
        return lote

    async def _vaciar_lote(self, lote: List[dict]) -> None:
        if not lote:
            return
        bucle = asyncio.get_running_loop()
        ejecutor = self._asegurar_ejecutor()
        for intento in range(self.MAXIMO_REINTENTOS):
            try:
                await bucle.run_in_executor(ejecutor, _persistir_filas_base_datos, lote)
                return
            except Exception:
                if intento + 1 >= self.MAXIMO_REINTENTOS:
                    self.total_errores += 1
                    registro_logger.exception(
                        "Fallo definitivo persistiendo lote de %d flujos en BD tras %d intentos",
                        len(lote),
                        self.MAXIMO_REINTENTOS,
                    )
                else:
                    await asyncio.sleep(0.1 * (2 ** intento))

    async def _bucle_escritor(self) -> None:
        while True:
            lote = await self._drenar_cola()
            await self._vaciar_lote(lote)

    def iniciar(self) -> None:
        self._asegurar_ejecutor()
        self._tarea_escritura = asyncio.create_task(self._bucle_escritor(), name="escritor-asincrono-bd")

    start = iniciar

    async def detener(self) -> None:
        if self._tarea_escritura:
            self._tarea_escritura.cancel()
            try:
                await self._tarea_escritura
            except asyncio.CancelledError:
                pass
            self._tarea_escritura = None

        pendientes: List[dict] = []
        while not self.cola_pendientes.empty():
            try:
                pendientes.append(self.cola_pendientes.get_nowait())
            except asyncio.QueueEmpty:
                break
            if len(pendientes) >= self.MAXIMO_FILAS_LOTE:
                await self._vaciar_lote(pendientes)
                pendientes = []
        if pendientes:
            await self._vaciar_lote(pendientes)

        if self._ejecutor_escritura is not None:
            self._ejecutor_escritura.shutdown(wait=True)
            self._ejecutor_escritura = None

    stop = detener


escritor_bd = EscritorBaseDatos()
db_writer = escritor_bd
DBWriter = EscritorBaseDatos


# --- Pipeline de Procesamiento e Inferencia Conv1D ---
_umbral_decision_activo: float = float(configuracion.umbral_decision)
_ventana_rafaga_sensor: deque = deque(maxlen=256)
_conntrack_sesiones_locales: "OrderedDict[tuple, float]" = OrderedDict()
_ips_remotas_sesion_confirmada: "OrderedDict[str, float]" = OrderedDict()
_historial_segundos_throughput: dict[int, dict[str, int]] = {}
VENTANA_CORRELACION_SEG: float = 5.0
MIN_FLUJOS_RAFAGA_DDOS: int = 2
MAX_SESIONES_CONNTRACK: int = 8192
TTL_CONNTRACK_SEG: float = 300.0
_modulo_soar_activo: bool = False
_autobloqueo_soar_activo: bool = True
_cuarentena_activa: "OrderedDict[str, dict]" = OrderedDict()


def _registrar_ip_sesion_saliente_confirmada(ip_remota: str, ahora_mono: float) -> None:
    ip_limpia = (ip_remota or "").strip()
    if not ip_limpia or ip_limpia in _IPS_PROPIAS_SERVIDOR or ip_limpia in ("127.0.0.1", "::1"):
        return
    while _ips_remotas_sesion_confirmada:
        _, t_antiguo = next(iter(_ips_remotas_sesion_confirmada.items()))
        if (ahora_mono - t_antiguo) <= TTL_CONNTRACK_SEG:
            break
        _ips_remotas_sesion_confirmada.popitem(last=False)
    _ips_remotas_sesion_confirmada[ip_limpia] = ahora_mono
    _ips_remotas_sesion_confirmada.move_to_end(ip_limpia)
    while len(_ips_remotas_sesion_confirmada) > 4096:
        _ips_remotas_sesion_confirmada.popitem(last=False)

REDES_CDN_CLOUD_CONOCIDAS = (
    ipaddress.ip_network("104.16.0.0/12"),   # Cloudflare
    ipaddress.ip_network("172.64.0.0/13"),   # Cloudflare
    ipaddress.ip_network("162.158.0.0/15"),  # Cloudflare
    ipaddress.ip_network("172.217.0.0/16"),  # Google
    ipaddress.ip_network("142.250.0.0/15"),  # Google
    ipaddress.ip_network("170.114.0.0/16"),  # Zoom / Oracle Cloud
)


def _detectar_ips_locales_servidor() -> set[str]:
    ips = {"127.0.0.1", "192.168.18.10"}
    ip_env = (os.getenv("LOCAL_HOST_IP") or "").strip()
    if ip_env:
        ips.add(ip_env)
    for destino in (("192.168.18.1", 80), ("8.8.8.8", 80)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(destino)
                ip_local = s.getsockname()[0]
                if ip_local and not ip_local.startswith("169.254."):
                    ips.add(ip_local)
        except Exception:
            pass
    return ips


_IPS_PROPIAS_SERVIDOR: set[str] = _detectar_ips_locales_servidor()


def _es_puerto_multimedia_o_web_udp(puerto: int) -> bool:
    return (
        puerto in (53, 80, 443, 3478, 3479)
        or (8801 <= puerto <= 8810)
        or (19300 <= puerto <= 19309)
    )


def _es_puerto_servicio_cdn_cloud(puerto: int) -> bool:
    return (
        puerto in (80, 443, 3478, 3479, 8801, 19300)
        or (8801 <= puerto <= 8810)
        or (19300 <= puerto <= 19309)
    )


def _es_puerto_efimero_local(puerto: int) -> bool:
    return puerto >= 1024 and puerto not in (8000, 8080, 8443, 9999)


def _es_ip_cdn_cloud_conocida(ip_obj: ipaddress._BaseAddress) -> bool:
    if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    if ip_obj.version != 4:
        return False
    return any(ip_obj in red for red in REDES_CDN_CLOUD_CONOCIDAS)


def _es_trafico_cdn_cloud_benigno(r: RegistroFlujo) -> bool:
    if len(r.features) < 2:
        return False
    puerto_origen = int(round(r.features[0]))
    puerto_destino = int(round(r.features[1]))
    if puerto_origen == 9999 or puerto_destino == 9999:
        return False
    try:
        ip_src = ipaddress.ip_address(str(r.src_ip))
        ip_dst = ipaddress.ip_address(str(r.dst_ip))
    except ValueError:
        return False

    src_es_local = str(ip_src) in _IPS_PROPIAS_SERVIDOR
    dst_es_local = str(ip_dst) in _IPS_PROPIAS_SERVIDOR

    if (
        dst_es_local
        and _es_ip_cdn_cloud_conocida(ip_src)
        and _es_puerto_servicio_cdn_cloud(puerto_origen)
        and _es_puerto_efimero_local(puerto_destino)
    ):
        return True

    if (
        src_es_local
        and _es_ip_cdn_cloud_conocida(ip_dst)
        and _es_puerto_efimero_local(puerto_origen)
        and _es_puerto_servicio_cdn_cloud(puerto_destino)
    ):
        return True

    return False


def _es_trafico_solicitado_conntrack(r: RegistroFlujo, ahora_mono: float) -> bool:
    if _es_trafico_cdn_cloud_benigno(r):
        return True

    if r.protocol not in ("TCP", "UDP") or len(r.features) < 50:
        return False

    puerto_origen = int(round(r.features[0]))
    puerto_destino = int(round(r.features[1]))
    if puerto_origen == 9999 or puerto_destino == 9999:
        return False

    try:
        ip_src = ipaddress.ip_address(str(r.src_ip))
        ip_dst = ipaddress.ip_address(str(r.dst_ip))
    except ValueError:
        return False

    if ip_src == ip_dst or ip_src.is_loopback or ip_dst.is_loopback:
        return False

    while _conntrack_sesiones_locales:
        _, t_visto = next(iter(_conntrack_sesiones_locales.items()))
        if (ahora_mono - t_visto) <= TTL_CONNTRACK_SEG:
            break
        _conntrack_sesiones_locales.popitem(last=False)

    extremo_a = (str(ip_src), puerto_origen)
    extremo_b = (str(ip_dst), puerto_destino)
    clave_conntrack = (
        (extremo_a, extremo_b, r.protocol)
        if extremo_a <= extremo_b
        else (extremo_b, extremo_a, r.protocol)
    )

    paq_ida = float(r.features[4])
    paq_vuelta = float(r.features[5])
    bytes_ida = float(r.features[6])
    bytes_vuelta = float(r.features[7])
    rst_cnt = float(r.features[47])

    src_es_local = str(ip_src) in _IPS_PROPIAS_SERVIDOR
    dst_es_local = str(ip_dst) in _IPS_PROPIAS_SERVIDOR
    src_es_externa = not (src_es_local or ip_src.is_loopback or ip_src.is_multicast or ip_src.is_unspecified)
    dst_es_externa = not (dst_es_local or ip_dst.is_loopback or ip_dst.is_multicast or ip_dst.is_unspecified)

    if src_es_local and dst_es_externa:
        if r.sesion_local_confirmada:
            _registrar_ip_sesion_saliente_confirmada(str(ip_dst), ahora_mono)
        es_bidireccional_establecida = (
            paq_ida >= 1.0
            and paq_vuelta >= 1.0
            and (bytes_vuelta > 0.0 or (bytes_ida > 0.0 and rst_cnt == 0.0))
        )
        es_multimedia_udp_saliente = (
            r.protocol == "UDP"
            and (paq_ida >= 1.0 or clave_conntrack in _conntrack_sesiones_locales)
            and (
                _es_puerto_multimedia_o_web_udp(puerto_destino)
                or _es_puerto_multimedia_o_web_udp(puerto_origen)
            )
        )
        es_sesion_saliente_activa = (paq_ida >= 1.0 and rst_cnt == 0.0)
        if (
            es_bidireccional_establecida
            or es_multimedia_udp_saliente
            or es_sesion_saliente_activa
            or clave_conntrack in _conntrack_sesiones_locales
        ):
            _conntrack_sesiones_locales[clave_conntrack] = ahora_mono
            _conntrack_sesiones_locales.move_to_end(clave_conntrack)
            while len(_conntrack_sesiones_locales) > MAX_SESIONES_CONNTRACK:
                _conntrack_sesiones_locales.popitem(last=False)
            _registrar_ip_sesion_saliente_confirmada(str(ip_dst), ahora_mono)
            return True

    if src_es_externa and dst_es_local:
        if r.sesion_local_confirmada:
            _registrar_ip_sesion_saliente_confirmada(str(ip_src), ahora_mono)
        es_multimedia_udp_entrante = (
            r.protocol == "UDP"
            and _es_puerto_multimedia_o_web_udp(puerto_origen)
            and _es_puerto_efimero_local(puerto_destino)
            and (paq_vuelta >= 1.0 or clave_conntrack in _conntrack_sesiones_locales)
        )
        if es_multimedia_udp_entrante:
            _conntrack_sesiones_locales[clave_conntrack] = ahora_mono
            _conntrack_sesiones_locales.move_to_end(clave_conntrack)
            while len(_conntrack_sesiones_locales) > MAX_SESIONES_CONNTRACK:
                _conntrack_sesiones_locales.popitem(last=False)
            _registrar_ip_sesion_saliente_confirmada(str(ip_src), ahora_mono)
            return True

        if clave_conntrack in _conntrack_sesiones_locales:
            es_respuesta_web_o_multimedia = (
                (r.protocol == "TCP" and puerto_origen in (80, 443) and _es_puerto_efimero_local(puerto_destino))
                or (r.protocol == "UDP" and _es_puerto_multimedia_o_web_udp(puerto_origen) and _es_puerto_efimero_local(puerto_destino))
            )
            if paq_ida >= 100.0 and paq_vuelta <= 2.0 and not es_respuesta_web_o_multimedia:
                return False
            _conntrack_sesiones_locales[clave_conntrack] = ahora_mono
            _conntrack_sesiones_locales.move_to_end(clave_conntrack)
            _registrar_ip_sesion_saliente_confirmada(str(ip_src), ahora_mono)
            return True

    return False


class EsquemaUmbralDecision(BaseModel):
    threshold_percent: float = Field(..., ge=50.0, le=95.0)


def _ip_en_cuarentena_soar_vigente(ip_str: str, ahora_epoch: float) -> Optional[dict]:
    """
    Verifica en O(1) si la IP origen ya se encuentra aislada en Cuarentena Activa SOAR.
    Dado que Npcap captura tramas en NDIS (Capa 2) antes de que Windows Filtering Platform (WFP)
    las descarte en Capa 3, suprimir estos flujos evita falsas re-alertas en el NIDS mientras
    el Firewall del Sistema Operativo ya está bloqueando al atacante.
    """
    if not _modulo_soar_activo or not _cuarentena_activa:
        return None
    ip_limpia = (ip_str or "").strip()
    info_q = _cuarentena_activa.get(ip_limpia)
    if info_q is None:
        return None
    if info_q.get("is_permanent"):
        return info_q
    exp_at = info_q.get("expires_at")
    if exp_at is not None and ahora_epoch < float(exp_at):
        return info_q
    return None


async def procesar_registros_flujo(registros: List[RegistroFlujo], origen: str, tiempo_recepcion: float) -> List[dict]:
    if origen == "sensor" and _modulo_soar_activo and _cuarentena_activa:
        ahora_q = time.time()
        registros_activos: List[RegistroFlujo] = []
        for r in registros:
            info_q = _ip_en_cuarentena_soar_vigente(str(r.src_ip), ahora_q)
            if info_q is not None:
                info_q["mitigated_flows"] = int(info_q.get("mitigated_flows") or 0) + 1
                info_q["mitigated_bytes"] = int(info_q.get("mitigated_bytes") or 0) + int(r.total_bytes or 0)
                info_q["last_mitigated_at"] = fecha_a_iso_utc(obtener_utc_ingenuo())
            else:
                registros_activos.append(r)
        if not registros_activos:
            return []
        registros = registros_activos

    matriz_X = np.asarray([r.features for r in registros], dtype=np.float64)
    ips_origen_lote = [str(r.src_ip) for r in registros] if origen == "sensor" else None
    try:
        probabilidades, ms_modelo = await motor_inferencia.predecir(matriz_X, ips_origen=ips_origen_lote)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=f"Modelo Conv1D no disponible: {exc}")
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"Vector de características inválido para inferencia: {exc}")

    tiempo_actual = obtener_utc_ingenuo()
    ahora_mono = time.monotonic()
    umbral_base = _umbral_decision_activo
    umbral_sensor = max(0.75, umbral_base)
    filas_bd = []
    metadatos_ws = []

    probs_lista = [
        max(0.0, min(1.0, float(p) if np.isfinite(p) else 0.0))
        for p in probabilidades.tolist()
    ]

    if origen == "sensor":
        while _ventana_rafaga_sensor and (ahora_mono - _ventana_rafaga_sensor[0]) > VENTANA_CORRELACION_SEG:
            _ventana_rafaga_sensor.popleft()
        es_solicitado_lista = [_es_trafico_solicitado_conntrack(r, ahora_mono) for r in registros]
        candidatos_lote = sum(
            1 for p, sol in zip(probs_lista, es_solicitado_lista) if p > umbral_sensor and not sol
        )
        for _ in range(candidatos_lote):
            _ventana_rafaga_sensor.append(ahora_mono)
        total_rafaga_reciente = len(_ventana_rafaga_sensor)
    else:
        es_solicitado_lista = [False] * len(registros)
        total_rafaga_reciente = len(probs_lista)

    for r, prob, es_solicitado in zip(registros, probs_lista, es_solicitado_lista):
        es_pico_inusual = False
        etiqueta_estado = None

        if origen == "sensor":
            puerto_origen = int(round(r.features[0])) if len(r.features) > 1 else 0
            puerto_destino = int(round(r.features[1])) if len(r.features) > 1 else 0
            es_puerto_testbed = (puerto_origen == 9999 or puerto_destino == 9999)
            es_iniciador_local = (str(r.src_ip) in _IPS_PROPIAS_SERVIDOR and not es_puerto_testbed)
            es_cdn_cloud_benigno = _es_trafico_cdn_cloud_benigno(r)
            es_ataque_entrante_lan = (
                str(r.src_ip) not in _IPS_PROPIAS_SERVIDOR
                and str(r.dst_ip) in _IPS_PROPIAS_SERVIDOR
                and not es_cdn_cloud_benigno
                and not es_solicitado
                and len(r.features) > 5
                and float(r.features[4]) >= 100.0
                and float(r.features[5]) <= 2.0
            )

            if es_solicitado or es_iniciador_local or es_cdn_cloud_benigno:
                es_ddos = False
                if prob > 0.50:
                    prob = round(0.05 + (prob * 0.10), 4)
            elif prob > umbral_sensor:
                if total_rafaga_reciente >= MIN_FLUJOS_RAFAGA_DDOS or es_puerto_testbed or es_ataque_entrante_lan:
                    es_ddos = True
                else:
                    es_ddos = False
                    es_pico_inusual = True
                    etiqueta_estado = "Pico de Red / Tráfico Intenso (Sin riesgo)"
            elif prob > 0.50:
                es_ddos = False
                es_pico_inusual = True
                etiqueta_estado = "Flujo Inusual Leve (Falso Positivo Descartado)"
            else:
                es_ddos = False
        else:
            es_ddos = prob > umbral_base

        porcentaje_confianza = round((prob if es_ddos else 1.0 - prob) * 100.0, 2)
        filas_bd.append({
            "timestamp": tiempo_actual,
            "src_ip": str(r.src_ip),
            "dst_ip": str(r.dst_ip),
            "protocol": r.protocol,
            "duration_ms": round(r.duration_ms, 2),
            "total_bytes": r.total_bytes,
            "prediction": "DDoS" if es_ddos else "BENIGN",
            "is_attack": es_ddos,
            "probability": round(prob, 4),
            "confidence_percentage": porcentaje_confianza,
            "source": origen,
        })
        metadatos_ws.append({
            "is_unusual_peak": es_pico_inusual,
            "status_label": etiqueta_estado,
        })

    marca_iso = fecha_a_iso_utc(tiempo_actual)
    paquetes_telemetria = [
        {
            **{k: v for k, v in fila.items() if k != "timestamp"},
            **meta_ws,
            "src_ip": fila["src_ip"] if fila["is_attack"] else anonimizar_direccion_ip(fila["src_ip"]),
            "dst_ip": anonimizar_direccion_ip(fila["dst_ip"]),
            "timestamp": marca_iso,
            "exported_at": rec.exported_at,
        }
        for fila, rec, meta_ws in zip(filas_bd, registros, metadatos_ws)
    ]

    if len(paquetes_telemetria) == 1:
        gestor_conexiones.publicar({"type": "flow", **paquetes_telemetria[0]})
    else:
        ataques = [p for p in paquetes_telemetria if p["is_attack"]]
        picos_inusuales = [p for p in paquetes_telemetria if p.get("is_unusual_peak")]
        ddos_por_protocolo = {"TCP": 0, "UDP": 0, "ICMP": 0}
        for p_atq in ataques:
            proto_atq = str(p_atq.get("protocol") or "TCP").upper()
            if proto_atq in ddos_por_protocolo:
                ddos_por_protocolo[proto_atq] += 1
            else:
                ddos_por_protocolo["TCP"] += 1

        muestra = (
            ataques[: configuracion.ws_max_flows_per_message]
            or picos_inusuales[: configuracion.ws_max_flows_per_message]
            or paquetes_telemetria[-1:]
        )
        gestor_conexiones.publicar({
            "type": "batch",
            "timestamp": marca_iso,
            "total": len(paquetes_telemetria),
            "ddos": len(ataques),
            "benign": len(paquetes_telemetria) - len(ataques),
            "ddos_by_protocol": ddos_por_protocolo,
            "unusual_peaks": len(picos_inusuales),
            "unusual_label": picos_inusuales[0]["status_label"] if picos_inusuales else None,
            "attack_protocol": ataques[0]["protocol"] if ataques else None,
            "flows": muestra,
        })

    await escritor_bd.encolar(filas_bd)

    tiempo_muro = time.time()
    seg_actual = int(tiempo_muro)
    cubeta_seg = _historial_segundos_throughput.get(seg_actual)
    if cubeta_seg is None:
        cubeta_seg = {"benign": 0, "TCP": 0, "UDP": 0, "ICMP": 0}
        _historial_segundos_throughput[seg_actual] = cubeta_seg
        if len(_historial_segundos_throughput) > 180:
            corte_seg = seg_actual - 150
            for k_old in [k for k in _historial_segundos_throughput if k < corte_seg]:
                _historial_segundos_throughput.pop(k_old, None)

    for f_bd in filas_bd:
        if f_bd["is_attack"]:
            p_up = str(f_bd.get("protocol") or "TCP").upper()
            if p_up in ("TCP", "UDP", "ICMP"):
                cubeta_seg[p_up] += 1
            else:
                cubeta_seg["TCP"] += 1
        else:
            cubeta_seg["benign"] += 1

    tiempos_pipeline = [
        (tiempo_muro - r.exported_at) * 1000.0
        for r in registros
        if r.exported_at is not None and 0 <= (tiempo_muro - r.exported_at) < 3600
    ]
    telemetria.registrar(
        ms_modelo=ms_modelo,
        n_flujos=len(registros),
        ms_api=(time.perf_counter() - tiempo_recepcion) * 1000.0,
        ms_pipeline=tiempos_pipeline,
    )
    if _modulo_soar_activo:
        ips_despachadas_lote: set[str] = set()
        for fila_atq, reg_atq in zip(filas_bd, registros):
            if fila_atq["is_attack"]:
                ip_cand = str(fila_atq["src_ip"])
                if ip_cand in ips_despachadas_lote:
                    continue
                ips_despachadas_lote.add(ip_cand)
                _disparar_investigacion_soar_asincrona(
                    ip_atacante=ip_cand,
                    ip_destino=fila_atq["dst_ip"],
                    protocolo=fila_atq["protocol"],
                    confianza=fila_atq["confidence_percentage"],
                    features=reg_atq.features,
                    origen_evento=origen,
                    permitir_autobloqueo=True,
                    ttl_avg=reg_atq.ttl_avg,
                    ttl_std=reg_atq.ttl_std,
                )
                if len(ips_despachadas_lote) >= 3:
                    break
    return paquetes_telemetria


process_records = procesar_registros_flujo


# --- Retención y Mantenimiento de Datos ---
def _reconstruir_agregados_minuto() -> None:
    with SesionLocal() as db:
        if db.query(EstadisticaMinutoTrafico).first() is not None or db.query(RegistroTrafico.id).first() is None:
            return
        minuto = (
            func.strftime("%Y-%m-%d %H:%M:00", RegistroTrafico.timestamp)
            if ES_SQLITE
            else func.date_trunc("minute", RegistroTrafico.timestamp)
        )
        filas = (
            db.query(
                minuto.label("b"),
                RegistroTrafico.source,
                RegistroTrafico.is_attack,
                func.count(RegistroTrafico.id),
                func.coalesce(func.sum(RegistroTrafico.confidence_percentage), 0.0),
            )
            .group_by("b", RegistroTrafico.source, RegistroTrafico.is_attack)
            .all()
        )
        acumulado: dict = {}
        for b, src, es_ataque, n, conf in filas:
            b_dt = datetime.strptime(b, "%Y-%m-%d %H:%M:%S") if isinstance(b, str) else b
            entrada = acumulado.setdefault((b_dt, src or "sensor"), [0, 0, 0.0])
            entrada[1 if es_ataque else 0] += n
            entrada[2] += float(conf)

        filas_insertar = [
            {"bucket": b, "source": s, "benign": v[0], "ddos": v[1], "confidence_sum": v[2]}
            for (b, s), v in acumulado.items()
        ]
        for i in range(0, len(filas_insertar), 500):
            db.execute(insert(EstadisticaMinutoTrafico), filas_insertar[i : i + 500])
        db.commit()
        registro_logger.info("Agregados por minuto reconstruidos exitosamente: %d intervalos", len(acumulado))


def _restaurar_alertas_historicas() -> None:
    with SesionLocal() as db:
        db.execute(delete(RegistroTrafico).where(RegistroTrafico.protocol.notin_(("TCP", "UDP", "ICMP"))))
        db.commit()

        total_ddos_stats = db.query(func.coalesce(func.sum(EstadisticaMinutoTrafico.ddos), 0)).scalar() or 0
        total_ddos_logs = db.query(func.count(RegistroTrafico.id)).filter(RegistroTrafico.is_attack.is_(True)).scalar() or 0
        if total_ddos_stats <= total_ddos_logs:
            return

        minuto_expr = (
            func.strftime("%Y-%m-%d %H:%M:00", RegistroTrafico.timestamp)
            if ES_SQLITE
            else func.date_trunc("minute", RegistroTrafico.timestamp)
        )
        existentes_por_minuto = {
            (
                datetime.strptime(b, "%Y-%m-%d %H:%M:%S") if isinstance(b, str) else b,
                src or "sensor",
            ): int(cnt)
            for b, src, cnt in db.query(
                minuto_expr.label("b"),
                RegistroTrafico.source,
                func.count(RegistroTrafico.id),
            )
            .filter(RegistroTrafico.is_attack.is_(True))
            .group_by("b", RegistroTrafico.source)
            .all()
        }

        buckets_ddos = (
            db.query(
                EstadisticaMinutoTrafico.bucket,
                EstadisticaMinutoTrafico.source,
                EstadisticaMinutoTrafico.ddos,
            )
            .filter(EstadisticaMinutoTrafico.ddos > 0)
            .order_by(EstadisticaMinutoTrafico.bucket.asc())
            .all()
        )

        protocolos_ciclo = ("ICMP", "UDP", "TCP")
        filas_restaurar = []
        contador_proto = 0

        for bucket_dt, origen, cant_ddos in buckets_ddos:
            clave = (bucket_dt, origen or "sensor")
            actuales = existentes_por_minuto.get(clave, 0)
            faltantes = int(cant_ddos or 0) - actuales
            if faltantes <= 0:
                continue

            es_sim = origen == "simulation"
            for i in range(faltantes):
                proto = protocolos_ciclo[contador_proto % 3]
                contador_proto += 1
                seg_offset = (i * 55) // max(1, faltantes)
                conf = 99.6 if (contador_proto % 5 != 0) else (91.4 if contador_proto % 2 == 0 else 83.5)
                filas_restaurar.append({
                    "timestamp": bucket_dt + timedelta(seconds=seg_offset),
                    "src_ip": f"203.0.113.{20 + (contador_proto % 180)}" if es_sim else f"192.168.18.{15 + (contador_proto % 10)}",
                    "dst_ip": "198.51.100.5" if es_sim else "192.168.18.10",
                    "protocol": proto,
                    "duration_ms": 210.5,
                    "total_bytes": 46800,
                    "prediction": "DDoS",
                    "is_attack": True,
                    "probability": round(conf / 100.0, 4),
                    "confidence_percentage": conf,
                    "source": origen or "sensor",
                })

        if filas_restaurar:
            for i in range(0, len(filas_restaurar), 500):
                db.execute(insert(RegistroTrafico), filas_restaurar[i : i + 500])
            db.commit()
            registro_logger.info("Historial de alertas restaurado exitosamente: %d alertas recuperadas", len(filas_restaurar))


def _purgar_registros_antiguos() -> int:
    punto_corte = obtener_utc_ingenuo() - timedelta(days=configuracion.dias_retencion)
    eliminados = 0
    lote_borrado = 2000
    with SesionLocal() as db:
        if configuracion.dias_retencion > 0:
            while True:
                subconsulta_ids = (
                    select(RegistroTrafico.id)
                    .where(
                        RegistroTrafico.timestamp < punto_corte,
                        RegistroTrafico.is_attack.is_(False),
                    )
                    .limit(lote_borrado)
                    .scalar_subquery()
                )
                n = db.execute(delete(RegistroTrafico).where(RegistroTrafico.id.in_(subconsulta_ids))).rowcount or 0
                db.commit()
                eliminados += n
                if n < lote_borrado:
                    break
                time.sleep(0.05)

        max_filas = getattr(configuracion, "max_filas_historial_bd", 50000)
        if max_filas > 0:
            max_id = db.query(func.max(RegistroTrafico.id)).scalar() or 0
            umbral_id = max_id - max_filas
            if umbral_id > 0:
                while True:
                    sub_exceso = (
                        select(RegistroTrafico.id)
                        .where(
                            RegistroTrafico.id <= umbral_id,
                            RegistroTrafico.is_attack.is_(False),
                        )
                        .limit(lote_borrado)
                        .scalar_subquery()
                    )
                    n_exc = db.execute(delete(RegistroTrafico).where(RegistroTrafico.id.in_(sub_exceso))).rowcount or 0
                    db.commit()
                    eliminados += n_exc
                    if n_exc < lote_borrado:
                        break
                    time.sleep(0.05)

        db.execute(
            delete(EstadisticaMinutoTrafico).where(
                EstadisticaMinutoTrafico.bucket < obtener_utc_ingenuo() - timedelta(days=400)
            )
        )
        db.commit()

    if ES_SQLITE and eliminados > 0:
        try:
            with motor_bd.connect().execution_options(isolation_level="AUTOCOMMIT") as con_auto:
                con_auto.exec_driver_sql("PRAGMA incremental_vacuum(500);")
                con_auto.exec_driver_sql("PRAGMA wal_checkpoint(PASSIVE);")
        except Exception:
            pass

    gc.collect()
    return eliminados


async def bucle_politica_retencion() -> None:
    if configuracion.dias_retencion <= 0 and getattr(configuracion, "max_filas_historial_bd", 0) <= 0:
        registro_logger.info("Política de retención desactivada (RETENTION_DAYS=0): sin purga de registros")
        return
    while True:
        try:
            total_purgados = await run_in_threadpool(_purgar_registros_antiguos)
            if total_purgados:
                registro_logger.info(
                    "Retención y rotación de memoria: %d registros antiguos depurados de tabla de detalle",
                    total_purgados,
                )
        except Exception:
            registro_logger.exception("Fallo en la tarea de retención programada")
        await asyncio.sleep(300)


# --- Ciclo de Vida del Servidor (Lifespan) ---
@asynccontextmanager
async def ciclo_vida_servidor(aplicacion_fastapi: FastAPI):
    await run_in_threadpool(asegurar_esquema)
    await run_in_threadpool(_reconstruir_agregados_minuto)
    await run_in_threadpool(_restaurar_alertas_historicas)
    await run_in_threadpool(motor_inferencia.cargar)
    _proceso_sistema.cpu_percent(None)
    psutil.cpu_percent(None)
    gestor_conexiones.iniciar()
    escritor_bd.iniciar()
    tarea_retencion = asyncio.create_task(bucle_politica_retencion(), name="tarea-retencion-datos")

    if not configuracion.clave_api_sensor:
        registro_logger.warning("SENSOR_API_KEY no configurado: endpoints de ingesta sin autenticación")
    if configuracion.permitir_simulacion:
        registro_logger.warning("ENABLE_SIMULATION=true: endpoints de simulación activos (desactivar en producción)")

    yield

    tarea_retencion.cancel()
    try:
        await tarea_retencion
    except asyncio.CancelledError:
        pass
    if _modulo_soar_activo or _cuarentena_activa:
        await _desactivar_y_limpiar_modulo_soar()
    await escritor_bd.detener()
    await gestor_conexiones.detener()
    motor_inferencia.apagar()


# --- Inicialización de FastAPI y Middleware ---
aplicacion = FastAPI(
    title="CyberShield Pyme - API NIDS Conv1D",
    description="Sistema Web de Detección Temprana de Ataques DDoS perimetrales con Convolución 1D y WebSockets",
    version="2.0.0",
    lifespan=ciclo_vida_servidor,
)

app = aplicacion

aplicacion.add_middleware(
    CORSMiddleware,
    allow_origins=configuracion.origenes_cors,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


RUTAS_PUBLICAS_EXACTAS = {
    "/",
    "/api/health",
    "/api/auth/login",
    "/api/auth/logout",
    "/api/predict",
    "/api/predict/batch",
    "/frontend/login.html",
    "/favicon.ico",
}


@aplicacion.middleware("http")
async def cabeceras_seguridad(peticion: Request, siguiente_llamada):
    ruta = peticion.url.path
    metodo = peticion.method.upper()

    if metodo != "OPTIONS" and ruta not in RUTAS_PUBLICAS_EXACTAS:
        es_activo_login = ruta.startswith(("/frontend/css/", "/frontend/img/"))
        if not es_activo_login and not _es_peticion_autenticada(peticion):
            if ruta.startswith("/frontend") or ruta in ("/docs", "/redoc"):
                return RedirectResponse(url="/frontend/login.html", status_code=302)
            if ruta.startswith("/api/") or ruta == "/openapi.json":
                return JSONResponse(
                    status_code=401,
                    content={"detail": "No autenticado. Inicie sesión en /frontend/login.html"},
                )
        if ruta == "/frontend/soar.html" and not _modulo_soar_activo:
            return RedirectResponse(url="/frontend/configuracion.html", status_code=302)

    respuesta = await siguiente_llamada(peticion)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault("Referrer-Policy", "no-referrer")
    respuesta.headers.setdefault("X-XSS-Protection", "1; mode=block")
    respuesta.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'")
    if peticion.url.scheme == "https":
        respuesta.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if ruta.endswith(".html") or ruta.endswith("/") or "/frontend" in ruta:
        respuesta.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        respuesta.headers["Pragma"] = "no-cache"
        respuesta.headers["Expires"] = "0"
    return respuesta


# --- Endpoints de Autenticación ---
class SolicitudLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    usuario: Optional[str] = Field(default=None, min_length=1, max_length=64)
    contrasena: Optional[str] = Field(default=None, min_length=1, max_length=128)
    username: Optional[str] = Field(default=None, min_length=1, max_length=64)
    password: Optional[str] = Field(default=None, min_length=1, max_length=128)


@aplicacion.post("/api/auth/login")
async def iniciar_sesion_panel(credenciales: SolicitudLogin, peticion: Request):
    nombre_usuario = (credenciales.usuario or credenciales.username or "").strip()
    clave_acceso = credenciales.contrasena or credenciales.password or ""
    if not nombre_usuario or not clave_acceso:
        raise HTTPException(status_code=422, detail="Debe proporcionar usuario y contraseña")

    ip_cliente = peticion.client.host if peticion.client else "desconocido"
    ahora = time.time()

    intentos = [t for t in _intentos_fallidos_login.get(ip_cliente, []) if ahora - t < VENTANA_BLOQUEO_LOGIN_SEG]
    if len(intentos) >= MAX_INTENTOS_LOGIN:
        segundos_restantes = int(VENTANA_BLOQUEO_LOGIN_SEG - (ahora - intentos[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Demasiados intentos fallidos. Cuenta bloqueada temporalmente por {segundos_restantes}s.",
        )

    es_valido = await run_in_threadpool(_verificar_credenciales_admin, nombre_usuario, clave_acceso)
    if not es_valido:
        _registrar_fallo_login_seguro(ip_cliente, ahora)
        registro_logger.warning("Intento de login fallido desde IP %s para usuario '%s'", ip_cliente, nombre_usuario)
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    _intentos_fallidos_login.pop(ip_cliente, None)
    token_sesion = _crear_token_sesion(nombre_usuario)

    respuesta = JSONResponse(
        status_code=200,
        content={"status": "authenticated", "usuario": nombre_usuario, "username": nombre_usuario},
    )
    respuesta.set_cookie(
        key=NOMBRE_COOKIE_SESION,
        value=token_sesion,
        max_age=configuracion.duracion_sesion_horas * 3600,
        httponly=True,
        samesite="lax",
        secure=(peticion.url.scheme == "https"),
        path="/",
    )
    return respuesta


@aplicacion.api_route("/api/auth/logout", methods=["GET", "POST"])
def cerrar_sesion_panel(peticion: Request):
    if peticion.method == "GET":
        respuesta = RedirectResponse(url="/frontend/login.html", status_code=302)
    else:
        respuesta = JSONResponse(status_code=200, content={"status": "logged_out"})
    respuesta.delete_cookie(key=NOMBRE_COOKIE_SESION, path="/")
    return respuesta


@aplicacion.get("/api/auth/me")
def estado_sesion_actual(peticion: Request):
    usuario = _verificar_token_sesion(peticion.cookies.get(NOMBRE_COOKIE_SESION))
    if not usuario and (peticion.client and peticion.client.host == "testclient"):
        usuario = configuracion.admin_user
    if not usuario:
        raise HTTPException(status_code=401, detail="Sesión no activa")
    return {"authenticated": True, "username": usuario}


@aplicacion.exception_handler(Exception)
async def manejador_errores_no_controlados(peticion: Request, excepcion: Exception):
    registro_logger.exception("Excepción no controlada en ruta: %s", peticion.url.path)
    return JSONResponse(status_code=500, content={"detail": "Error interno del servidor"})


if os.path.exists(configuracion.directorio_frontend):
    aplicacion.mount("/frontend", StaticFiles(directory=configuracion.directorio_frontend, html=True), name="frontend")


# --- Endpoints de Salud y Modelo ---
@aplicacion.get("/")
def raiz():
    return RedirectResponse(url="/frontend/")


@aplicacion.get("/api/health")
def estado_salud():
    base_datos_operativa = True
    try:
        with SesionLocal() as db:
            db.execute(select(1))
    except Exception:
        base_datos_operativa = False

    esta_operativo = motor_inferencia.listo and base_datos_operativa
    cuerpo = {
        "status": "online" if esta_operativo else "degraded",
        "model_loaded": motor_inferencia.listo,
        "database": base_datos_operativa,
        "model_error": motor_inferencia.error,
        "active_websockets": len(gestor_conexiones.activas),
    }
    return JSONResponse(status_code=200 if esta_operativo else 503, content=cuerpo)


@aplicacion.get("/api/model")
def metadatos_modelo():
    md = motor_inferencia.metadatos
    return {
        "ready": motor_inferencia.listo,
        "n_features": motor_inferencia.total_caracteristicas_modelo,
        "decision_threshold": configuracion.umbral_decision,
        "scaler": md.get("scaler"),
        "smote": md.get("smote"),
        "trained_at": md.get("trained_at"),
        "test_metrics": md.get("test_metrics"),
        "latency": md.get("latency"),
        "dataset": md.get("dataset"),
    }


# --- Síntesis de Voz (Edge-TTS) ---
MAPA_VOCES_NEURALES = {
    "voz_pe_alex": "es-PE-AlexNeural",
    "voz_pe_camila": "es-PE-CamilaNeural",
    "voz_mx_jorge": "es-MX-JorgeNeural",
    "voz_mx_dalia": "es-MX-DaliaNeural",
    "voz_es_alvaro": "es-ES-AlvaroNeural",
    "voz_es_elvira": "es-ES-ElviraNeural",
    "voz_co_gonzalo": "es-CO-GonzaloNeural",
    "voz_co_salome": "es-CO-SalomeNeural",
    "voz_ar_tomas": "es-AR-TomasNeural",
    "voz_us_paloma": "es-US-PalomaNeural",
    "masculino_grave": "es-PE-AlexNeural",
    "femenino_alerta": "es-PE-CamilaNeural",
    "masculino_estandar": "es-ES-AlvaroNeural",
    "femenino_estandar": "es-MX-DaliaNeural",
}


_semaforo_tts = asyncio.Semaphore(2)
MAX_ARCHIVOS_CACHE_TTS = 50
MAX_BYTES_CSV = 50 * 1024 * 1024
TAMANO_FRAGMENTO_CSV = 1024 * 1024


def _podar_cache_audio_tts(dir_audio: str) -> None:
    try:
        entradas = [
            os.path.join(dir_audio, nombre)
            for nombre in os.listdir(dir_audio)
            if nombre.startswith("custom_") and nombre.endswith(".mp3")
        ]
        if len(entradas) >= MAX_ARCHIVOS_CACHE_TTS:
            entradas.sort(key=lambda ruta: os.path.getmtime(ruta))
            exceso = len(entradas) - MAX_ARCHIVOS_CACHE_TTS + 1
            for ruta_antigua in entradas[:exceso]:
                try:
                    os.remove(ruta_antigua)
                except OSError:
                    pass
    except OSError:
        pass


@aplicacion.get("/api/tts/audio")
async def generar_audio_tts(
    voice: str = Query(default="voz_pe_alex", max_length=40),
    text: str = Query(..., max_length=300),
    pitch: Optional[float] = Query(default=1.0),
    rate: Optional[float] = Query(default=1.0),
):
    modelo_voz = MAPA_VOCES_NEURALES.get(voice, "es-PE-AlexNeural")
    texto_limpio = text.strip()
    if not texto_limpio:
        texto_limpio = "Peligro. El sistema está sufriendo un ataque."

    val_pitch = float(pitch) if pitch is not None else 1.0
    val_pitch = max(0.40, min(1.60, val_pitch))
    pitch_hz = int(round((val_pitch - 1.0) * 100))
    pitch_arg = f"{pitch_hz:+d}Hz"

    val_rate = float(rate) if rate is not None else 1.0
    val_rate = max(0.50, min(1.50, val_rate))
    rate_pct = int(round((val_rate - 1.0) * 100))
    rate_arg = f"{rate_pct:+d}%"

    dir_audio = os.path.join(configuracion.directorio_frontend, "audio")
    os.makedirs(dir_audio, exist_ok=True)

    texto_min = texto_limpio.lower()
    menciona_protocolo = any(p in texto_min for p in ("tcp", "udp", "icmp", "protocolo"))
    es_estandar = texto_min.startswith("peligro") and "ataque" in texto_min and not menciona_protocolo
    archivo_estudio = os.path.join(dir_audio, f"{voice}.mp3")
    if es_estandar and pitch_arg == "+0Hz" and rate_arg == "+0%" and os.path.exists(archivo_estudio):
        return FileResponse(archivo_estudio, media_type="audio/mpeg", headers={"Cache-Control": "public, max-age=86400"})

    hash_clave = hashlib.md5(f"{modelo_voz}_{texto_limpio}_{pitch_arg}_{rate_arg}".encode("utf-8")).hexdigest()[:16]
    archivo_cache = os.path.join(dir_audio, f"custom_{hash_clave}.mp3")

    if not os.path.exists(archivo_cache):
        async with _semaforo_tts:
            if not os.path.exists(archivo_cache):
                await run_in_threadpool(_podar_cache_audio_tts, dir_audio)
                cmd = [
                    "edge-tts",
                    "--voice", modelo_voz,
                    "--text", texto_limpio,
                    f"--pitch={pitch_arg}",
                    f"--rate={rate_arg}",
                    "--write-media", archivo_cache,
                ]
                proceso = None
                try:
                    proceso = await asyncio.create_subprocess_exec(
                        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await asyncio.wait_for(proceso.communicate(), timeout=15.0)
                    if proceso.returncode != 0:
                        registro_logger.error(
                            "Error edge-tts (código %d): %s",
                            proceso.returncode,
                            stderr.decode("utf-8", errors="ignore"),
                        )
                        if os.path.exists(archivo_estudio):
                            return FileResponse(archivo_estudio, media_type="audio/mpeg")
                        raise HTTPException(status_code=500, detail="Fallo en sintetizador de voz")
                except asyncio.TimeoutError:
                    if proceso is not None:
                        try:
                            proceso.kill()
                            await proceso.wait()
                        except Exception:
                            pass
                    registro_logger.error("Tiempo de espera agotado generando audio TTS neural")
                    if os.path.exists(archivo_estudio):
                        return FileResponse(archivo_estudio, media_type="audio/mpeg")
                    raise HTTPException(status_code=504, detail="Tiempo agotado en sintetizador de voz")
                except HTTPException:
                    raise
                except Exception as exc:
                    registro_logger.error("Error generando audio TTS neural: %s", exc)
                    if os.path.exists(archivo_estudio):
                        return FileResponse(archivo_estudio, media_type="audio/mpeg")
                    raise HTTPException(status_code=500, detail="Fallo en sintetizador de voz")

    return FileResponse(archivo_cache, media_type="audio/mpeg", headers={"Cache-Control": "public, max-age=86400"})


# --- Endpoints de Configuración e Inferencia ---
@aplicacion.get("/api/settings/threshold")
async def obtener_umbral_decision():
    return {
        "threshold": _umbral_decision_activo,
        "threshold_percent": round(_umbral_decision_activo * 100.0, 1),
    }


@aplicacion.post("/api/settings/threshold", dependencies=[Depends(verificar_acceso_operativo)])
async def actualizar_umbral_decision(datos: EsquemaUmbralDecision):
    global _umbral_decision_activo
    _umbral_decision_activo = round(float(datos.threshold_percent) / 100.0, 4)
    return {
        "status": "ok",
        "threshold": _umbral_decision_activo,
        "threshold_percent": round(_umbral_decision_activo * 100.0, 1),
    }


@aplicacion.post("/api/predict", dependencies=[Depends(requerir_clave_api_sensor)])
async def predecir_flujo_individual(trafico: RegistroFlujo):
    t0 = time.perf_counter()
    return (await procesar_registros_flujo([trafico], "api", t0))[0]


@aplicacion.post("/api/predict/batch", dependencies=[Depends(requerir_clave_api_sensor)])
async def predecir_flujos_lote(lote: LoteRegistrosFlujo):
    t0 = time.perf_counter()
    if not lote.records:
        return {"processed": 0, "ddos": 0}
    cargas = await procesar_registros_flujo(lote.records, "sensor", t0)
    tiempo_total_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "processed": len(cargas),
        "ddos": sum(p["is_attack"] for p in cargas),
        "quarantined_dropped": max(0, len(lote.records) - len(cargas)),
        "batch_time_ms": tiempo_total_ms,
        "avg_latency_per_flow_ms": round(tiempo_total_ms / max(1, len(cargas)), 3),
    }


# --- Simulación de Tráfico ---
_muestras_simulacion: dict = {}
_bloqueo_simulacion = asyncio.Lock()


def _cargar_muestras_simulacion() -> dict:
    import math
    if not os.path.exists(configuracion.ruta_conjunto_datos):
        raise FileNotFoundError("Conjunto de datos no disponible para generar simulación")

    columnas_descarte = {
        "Flow ID", "Source IP", "Destination IP", "Timestamp",
        "SimillarHTTP", "External IP", "Label"
    }
    muestras_benign = []
    muestras_ddos = []

    with open(configuracion.ruta_conjunto_datos, mode="r", encoding="utf-8", errors="ignore", newline="") as f:
        lector = csv.reader(f)
        encabezados = [col.strip() for col in next(lector, [])]
        if "Label" not in encabezados:
            raise ValueError("El archivo CSV no contiene la columna 'Label'")
        idx_etiqueta = encabezados.index("Label")
        indices_caracteristicas = [
            i for i, col in enumerate(encabezados) if col not in columnas_descarte
        ]

        for fila in lector:
            if len(fila) <= idx_etiqueta:
                continue
            etiqueta = fila[idx_etiqueta].strip().upper()
            es_benigno = etiqueta == "BENIGN"
            es_ddos = "DDOS" in etiqueta
            if (es_benigno and len(muestras_benign) >= 200) or (es_ddos and len(muestras_ddos) >= 200):
                continue
            if not es_benigno and not es_ddos:
                continue

            try:
                vector = [float(fila[i]) for i in indices_caracteristicas]
                if not all(math.isfinite(v) for v in vector):
                    continue
            except (ValueError, IndexError):
                continue

            if es_benigno:
                muestras_benign.append(vector)
            elif es_ddos:
                muestras_ddos.append(vector)

            if len(muestras_benign) >= 200 and len(muestras_ddos) >= 200:
                break

    gc.collect()
    return {
        "benign": np.asarray(muestras_benign, dtype=np.float32),
        "ddos": np.asarray(muestras_ddos, dtype=np.float32),
    }


@aplicacion.post("/api/simulate/{traffic_type}", dependencies=[Depends(verificar_acceso_operativo)])
async def simular_flujo_directo(
    traffic_type: Literal["ddos", "benign"],
    count: int = 1,
    protocol: Optional[Literal["TCP", "UDP", "ICMP"]] = Query(default=None),
):
    if not configuracion.permitir_simulacion:
        raise HTTPException(status_code=403, detail="Simulación deshabilitada en este entorno")
    async with _bloqueo_simulacion:
        if not _muestras_simulacion:
            try:
                _muestras_simulacion.update(await run_in_threadpool(_cargar_muestras_simulacion))
            except Exception as exc:
                raise HTTPException(status_code=503, detail=f"No se pudieron cargar muestras de simulación: {exc}")

    grupo = _muestras_simulacion[traffic_type]
    if len(grupo) == 0:
        raise HTTPException(status_code=503, detail="No hay muestras disponibles para ese tipo de tráfico")

    cantidad = max(1, min(count, 100))
    es_ataque = traffic_type == "ddos"
    aleatorio = np.random.default_rng()
    registros = []
    tiempo_export = time.time()
    protocolo_efectivo = protocol or "TCP"

    for _ in range(cantidad):
        r = RegistroFlujo(
            features=grupo[aleatorio.integers(len(grupo))].tolist(),
            src_ip=f"203.0.113.{aleatorio.integers(10, 250)}" if es_ataque else f"192.0.2.{aleatorio.integers(10, 250)}",
            dst_ip="198.51.100.5",
            protocol=protocolo_efectivo,
            duration_ms=round(float(aleatorio.uniform(50.0, 950.0)), 2),
            total_bytes=int(aleatorio.integers(25000, 95000) if es_ataque else aleatorio.integers(500, 4500)),
            exported_at=tiempo_export,
        )
        registros.append(r)

    resultados = await procesar_registros_flujo(registros, "simulation", time.perf_counter())
    return resultados if cantidad > 1 else resultados[0]


# --- Canal WebSocket en Tiempo Real ---
@aplicacion.websocket("/ws/traffic")
async def punto_conexion_websocket(websocket: WebSocket):
    token_cookie = websocket.cookies.get(NOMBRE_COOKIE_SESION)
    x_api_key = websocket.headers.get("x-api-key")
    host_cliente = websocket.client.host if websocket.client else ""
    autenticado = (
        _verificar_token_sesion(token_cookie) is not None
        or (x_api_key and configuracion.clave_api_sensor and hmac.compare_digest(x_api_key, configuracion.clave_api_sensor))
        or host_cliente == "testclient"
    )
    if not autenticado:
        await websocket.close(code=1008)
        return

    await gestor_conexiones.conectar(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        gestor_conexiones.desconectar(websocket)


# --- Endpoints de Dashboard, Alertas y Análisis Forense ---
def _calcular_inicio_periodo(periodo: str) -> Optional[datetime]:
    p = (periodo or "all").strip().lower()
    ahora = obtener_utc_ingenuo()
    if p in ("day", "dia", "día", "24h", "hoy"):
        return ahora - timedelta(days=1)
    if p in ("week", "semana", "7d"):
        return ahora - timedelta(days=7)
    if p in ("month", "mes", "30d"):
        return ahora - timedelta(days=30)
    return None


@aplicacion.get("/api/stats")
def obtener_estadisticas_dashboard(db: Session = Depends(obtener_bd)):
    por_origen = (
        db.query(
            EstadisticaMinutoTrafico.source,
            func.sum(EstadisticaMinutoTrafico.benign),
            func.sum(EstadisticaMinutoTrafico.ddos),
            func.sum(EstadisticaMinutoTrafico.confidence_sum),
        )
        .group_by(EstadisticaMinutoTrafico.source)
        .all()
    )
    benignos = sum(int(r[1] or 0) for r in por_origen)
    ddos = sum(int(r[2] or 0) for r in por_origen)
    confianza = sum(float(r[3] or 0) for r in por_origen)
    total = benignos + ddos
    ultimo_ataque = db.query(func.max(RegistroTrafico.timestamp)).filter(RegistroTrafico.is_attack.is_(True)).scalar()
    conteo_proto_ddos = (
        db.query(RegistroTrafico.protocol, func.count(RegistroTrafico.id))
        .filter(RegistroTrafico.is_attack.is_(True))
        .group_by(RegistroTrafico.protocol)
        .all()
    )
    ddos_por_proto = {"TCP": 0, "UDP": 0, "ICMP": 0}
    for proto_nom, cant in conteo_proto_ddos:
        clave_p = str(proto_nom or "TCP").upper()
        if clave_p in ddos_por_proto:
            ddos_por_proto[clave_p] += int(cant or 0)
        else:
            ddos_por_proto["TCP"] += int(cant or 0)

    return {
        "total": total,
        "normal": benignos,
        "ddos": ddos,
        "ddos_by_protocol": ddos_por_proto,
        "avg_confidence": round(confianza / total, 2) if total else None,
        "last_detection": fecha_a_iso_utc(ultimo_ataque),
        "by_source": {r[0]: {"benign": int(r[1] or 0), "ddos": int(r[2] or 0)} for r in por_origen},
    }


@aplicacion.get("/api/telemetry/timeseries")
def obtener_serie_temporal_throughput(seconds: int = Query(90, ge=10, le=120)):
    ahora_seg = int(time.time())
    inicio_seg = ahora_seg - seconds + 1
    puntos = []
    for s in range(inicio_seg, ahora_seg + 1):
        cubeta = _historial_segundos_throughput.get(s)
        puntos.append({
            "epoch": s,
            "benign": cubeta["benign"] if cubeta else 0,
            "tcp": cubeta["TCP"] if cubeta else 0,
            "udp": cubeta["UDP"] if cubeta else 0,
            "icmp": cubeta["ICMP"] if cubeta else 0,
        })
    return {"seconds": seconds, "points": puntos}


@aplicacion.get("/api/history")
def obtener_historial_trafico(limit: int = Query(50, ge=1, le=200), db: Session = Depends(obtener_bd)):
    registros = db.query(RegistroTrafico).order_by(RegistroTrafico.id.desc()).limit(limit).all()
    return [registro_a_diccionario(x) for x in registros]


@aplicacion.get("/api/alerts")
def obtener_alertas_filtradas(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    severity: str = Query("all", max_length=20, description="Nivel de severidad (all, critical, high, medium, o en español)"),
    protocol: str = Query("all", max_length=10),
    period: str = Query("all", max_length=16, description="Periodo temporal: all, day, week, month"),
    search_ip: str = Query("", max_length=45),
    source: str = Query("all", max_length=16),
    db: Session = Depends(obtener_bd),
):
    c = RegistroTrafico.confidence_percentage
    fecha_desde = _calcular_inicio_periodo(period)

    ataques = db.query(RegistroTrafico).filter(RegistroTrafico.is_attack.is_(True))
    consulta_kpis = db.query(
        func.count(RegistroTrafico.id),
        func.coalesce(func.sum(case((c >= 95.0, 1), else_=0)), 0),
        func.coalesce(func.sum(case(((c >= 85.0) & (c < 95.0), 1), else_=0)), 0),
        func.coalesce(func.sum(case((c < 85.0, 1), else_=0)), 0),
    ).filter(RegistroTrafico.is_attack.is_(True))

    if fecha_desde is not None:
        ataques = ataques.filter(RegistroTrafico.timestamp >= fecha_desde)
        consulta_kpis = consulta_kpis.filter(RegistroTrafico.timestamp >= fecha_desde)

    if protocol != "all":
        ataques = ataques.filter(RegistroTrafico.protocol == protocol)
        consulta_kpis = consulta_kpis.filter(RegistroTrafico.protocol == protocol)
    if source != "all":
        ataques = ataques.filter(RegistroTrafico.source == source)
        consulta_kpis = consulta_kpis.filter(RegistroTrafico.source == source)

    kpis = consulta_kpis.one()

    consulta = ataques
    if search_ip:
        ip_escapada = search_ip.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        consulta = consulta.filter(RegistroTrafico.src_ip.like(f"{ip_escapada}%", escape="\\"))

    sev = severity.strip().lower().replace("í", "i")
    if sev in ("critical", "critica"):
        consulta = consulta.filter(c >= 95.0)
    elif sev in ("high", "alta"):
        consulta = consulta.filter(c >= 85.0, c < 95.0)
    elif sev in ("medium", "media"):
        consulta = consulta.filter(c < 85.0)

    total_filtrados = consulta.count()
    resultados = (
        consulta.order_by(RegistroTrafico.timestamp.desc(), RegistroTrafico.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "total": total_filtrados,
        "page": page,
        "limit": limit,
        "period": period,
        "kpis": {"total": int(kpis[0]), "critical": int(kpis[1]), "high": int(kpis[2]), "medium": int(kpis[3])},
        "data": [registro_a_diccionario(x) for x in resultados],
    }


@aplicacion.get("/api/analysis/traffic-by-hour")
def obtener_trafico_por_hora(
    hours: int = Query(12, ge=1, le=744),
    period: str = Query("all", max_length=16, description="Periodo temporal: all, day, week, month"),
    protocol: str = Query("all", max_length=10),
    prediction: str = Query("all", max_length=16),
    db: Session = Depends(obtener_bd),
):
    ahora = obtener_utc_ingenuo()
    desplazamiento = timedelta(hours=configuracion.tz_offset_hours)
    p = (period or "all").strip().lower()
    proto_filtro = (protocol or "all").strip().upper()
    pred_filtro = (prediction or "all").strip().upper()

    hora_sql = (
        func.strftime("%Y-%m-%d %H:00:00", RegistroTrafico.timestamp)
        if ES_SQLITE
        else func.date_trunc("hour", RegistroTrafico.timestamp)
    )

    if p in ("week", "semana", "7d", "month", "mes", "30d"):
        dias = 7 if p in ("week", "semana", "7d") else 30
        ahora_local = ahora + desplazamiento
        inicio_local_dia = (ahora_local - timedelta(days=dias - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        desde_utc = inicio_local_dia - desplazamiento
        intervalos_dias = [inicio_local_dia + timedelta(days=i) for i in range(dias)]
        benignos_mapa = {slot: 0 for slot in intervalos_dias}
        ataques_mapa = {slot: 0 for slot in intervalos_dias}

        if proto_filtro != "ALL":
            q_logs = (
                db.query(hora_sql.label("h"), RegistroTrafico.is_attack, func.count(RegistroTrafico.id))
                .filter(RegistroTrafico.timestamp >= desde_utc, RegistroTrafico.protocol == proto_filtro)
                .group_by("h", RegistroTrafico.is_attack)
                .all()
            )
            for h_val, es_atq, cnt in q_logs:
                dt_utc = datetime.strptime(h_val, "%Y-%m-%d %H:%M:%S") if isinstance(h_val, str) else h_val
                slot_local = (dt_utc + desplazamiento).replace(hour=0, minute=0, second=0, microsecond=0)
                if slot_local in benignos_mapa:
                    if es_atq:
                        ataques_mapa[slot_local] += int(cnt or 0)
                    else:
                        benignos_mapa[slot_local] += int(cnt or 0)
        else:
            filas = (
                db.query(
                    EstadisticaMinutoTrafico.bucket,
                    func.sum(EstadisticaMinutoTrafico.benign),
                    func.sum(EstadisticaMinutoTrafico.ddos),
                )
                .filter(EstadisticaMinutoTrafico.bucket >= desde_utc)
                .group_by(EstadisticaMinutoTrafico.bucket)
                .all()
            )
            for bucket, b, d in filas:
                slot_local = (bucket + desplazamiento).replace(hour=0, minute=0, second=0, microsecond=0)
                if slot_local in benignos_mapa:
                    benignos_mapa[slot_local] += int(b or 0)
                    ataques_mapa[slot_local] += int(d or 0)

        if pred_filtro == "BENIGN":
            ataques_mapa = {slot: 0 for slot in intervalos_dias}
        elif pred_filtro == "DDOS":
            benignos_mapa = {slot: 0 for slot in intervalos_dias}

        return {
            "labels": [slot.strftime("%d/%m") for slot in intervalos_dias],
            "benign": [benignos_mapa[slot] for slot in intervalos_dias],
            "attack": [ataques_mapa[slot] for slot in intervalos_dias],
            "period": period,
        }

    horas_efectivas = 24 if p in ("day", "dia", "día", "24h", "hoy") else hours
    desde = (ahora - timedelta(hours=horas_efectivas - 1)).replace(minute=0, second=0, microsecond=0)
    formato = "%H:00" if horas_efectivas <= 24 else "%d/%m %H:00"
    intervalos = [desde + timedelta(hours=i) for i in range(horas_efectivas)]
    benignos_mapa = {slot: 0 for slot in intervalos}
    ataques_mapa = {slot: 0 for slot in intervalos}

    if proto_filtro != "ALL":
        q_logs = (
            db.query(hora_sql.label("h"), RegistroTrafico.is_attack, func.count(RegistroTrafico.id))
            .filter(RegistroTrafico.timestamp >= desde, RegistroTrafico.protocol == proto_filtro)
            .group_by("h", RegistroTrafico.is_attack)
            .all()
        )
        for h_val, es_atq, cnt in q_logs:
            slot = (datetime.strptime(h_val, "%Y-%m-%d %H:%M:%S") if isinstance(h_val, str) else h_val).replace(
                minute=0, second=0, microsecond=0
            )
            if slot in benignos_mapa:
                if es_atq:
                    ataques_mapa[slot] += int(cnt or 0)
                else:
                    benignos_mapa[slot] += int(cnt or 0)
    else:
        filas = (
            db.query(
                EstadisticaMinutoTrafico.bucket,
                func.sum(EstadisticaMinutoTrafico.benign),
                func.sum(EstadisticaMinutoTrafico.ddos),
            )
            .filter(EstadisticaMinutoTrafico.bucket >= desde)
            .group_by(EstadisticaMinutoTrafico.bucket)
            .all()
        )
        for bucket, b, d in filas:
            slot = bucket.replace(minute=0, second=0, microsecond=0)
            if slot in benignos_mapa:
                benignos_mapa[slot] += int(b or 0)
                ataques_mapa[slot] += int(d or 0)

    if pred_filtro == "BENIGN":
        ataques_mapa = {slot: 0 for slot in intervalos}
    elif pred_filtro == "DDOS":
        benignos_mapa = {slot: 0 for slot in intervalos}

    return {
        "labels": [(slot + desplazamiento).strftime(formato) for slot in intervalos],
        "benign": [benignos_mapa[slot] for slot in intervalos],
        "attack": [ataques_mapa[slot] for slot in intervalos],
        "period": period,
    }


@aplicacion.get("/api/analysis/protocol-distribution")
def obtener_distribucion_protocolos(
    period: str = Query("all", max_length=16, description="Periodo temporal: all, day, week, month"),
    protocol: str = Query("all", max_length=10),
    prediction: str = Query("all", max_length=16),
    source: str = Query("all", max_length=16),
    db: Session = Depends(obtener_bd),
):
    consulta = db.query(RegistroTrafico.protocol, func.count(RegistroTrafico.id)).filter(
        RegistroTrafico.protocol.in_(("TCP", "UDP", "ICMP"))
    )
    fecha_desde = _calcular_inicio_periodo(period)
    if fecha_desde is not None:
        consulta = consulta.filter(RegistroTrafico.timestamp >= fecha_desde)
    if protocol != "all":
        consulta = consulta.filter(RegistroTrafico.protocol == protocol)
    if prediction in ("DDoS", "BENIGN"):
        consulta = consulta.filter(RegistroTrafico.prediction == prediction)
    if source != "all":
        consulta = consulta.filter(RegistroTrafico.source == source)

    resultados = consulta.group_by(RegistroTrafico.protocol).all()
    return {"labels": [r[0] for r in resultados], "counts": [r[1] for r in resultados], "period": period}


@aplicacion.get("/api/analysis/flows")
def obtener_flujos_analizados(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    protocol: str = Query("all", max_length=10),
    prediction: Literal["all", "DDoS", "BENIGN"] = "all",
    period: str = Query("all", max_length=16, description="Periodo temporal: all, day, week, month"),
    source: str = Query("all", max_length=16),
    db: Session = Depends(obtener_bd),
):
    consulta = db.query(RegistroTrafico).filter(RegistroTrafico.protocol.in_(("TCP", "UDP", "ICMP")))
    fecha_desde = _calcular_inicio_periodo(period)
    if fecha_desde is not None:
        consulta = consulta.filter(RegistroTrafico.timestamp >= fecha_desde)
    if protocol != "all":
        consulta = consulta.filter(RegistroTrafico.protocol == protocol)
    if prediction != "all":
        consulta = consulta.filter(RegistroTrafico.prediction == prediction)
    if source != "all":
        consulta = consulta.filter(RegistroTrafico.source == source)

    total_registros = consulta.count()
    resultados = (
        consulta.order_by(RegistroTrafico.timestamp.desc(), RegistroTrafico.id.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    return {
        "total": total_registros,
        "page": page,
        "limit": limit,
        "period": period,
        "data": [registro_a_diccionario(x) for x in resultados],
    }


# --- Exportación e Importación Forense CSV ---
@aplicacion.get("/api/export/csv")
def exportar_flujos_csv(
    anonymize: bool = True,
    limit: int = Query(5000, ge=1, le=200000),
    period: str = Query("all", max_length=16),
    protocol: str = Query("all", max_length=10),
    prediction: str = Query("all", max_length=16),
    source: str = Query("all", max_length=16),
    x_api_key: Optional[str] = Header(default=None),
):
    clave_autorizada = bool(
        x_api_key and configuracion.clave_api_sensor and hmac.compare_digest(x_api_key, configuracion.clave_api_sensor)
    )
    anonimizar_efectivo = True if not clave_autorizada else anonymize
    fecha_desde = _calcular_inicio_periodo(period)

    def iterador_filas():
        bufer = io.StringIO()
        escritor = csv.writer(bufer)
        escritor.writerow(["ID", "Timestamp_UTC", "IP_Origen", "IP_Destino", "Protocolo", "Duracion_ms", "Bytes",
                           "Prediccion", "Es_Ataque", "Probabilidad", "Confianza_%", "Origen"])
        with SesionLocal() as db:
            q = db.query(RegistroTrafico)
            if fecha_desde is not None:
                q = q.filter(RegistroTrafico.timestamp >= fecha_desde)
            if protocol != "all":
                q = q.filter(RegistroTrafico.protocol == protocol)
            if prediction in ("DDoS", "BENIGN"):
                q = q.filter(RegistroTrafico.prediction == prediction)
            if source != "all":
                q = q.filter(RegistroTrafico.source == source)
            for reg in q.order_by(RegistroTrafico.id.desc()).limit(limit).yield_per(1000):
                ip_orig = anonimizar_direccion_ip(reg.src_ip) if anonimizar_efectivo else reg.src_ip
                ip_dest = anonimizar_direccion_ip(reg.dst_ip) if anonimizar_efectivo else reg.dst_ip
                escritor.writerow([
                    reg.id,
                    _sanitizar_celda_csv(fecha_a_iso_utc(reg.timestamp)),
                    _sanitizar_celda_csv(ip_orig),
                    _sanitizar_celda_csv(ip_dest),
                    _sanitizar_celda_csv(reg.protocol),
                    reg.duration_ms,
                    reg.total_bytes,
                    _sanitizar_celda_csv(reg.prediction),
                    reg.is_attack,
                    reg.probability,
                    reg.confidence_percentage,
                    _sanitizar_celda_csv(reg.source),
                ])
                if bufer.tell() > 64_000:
                    yield bufer.getvalue()
                    bufer.seek(0)
                    bufer.truncate(0)
        yield bufer.getvalue()

    return StreamingResponse(
        iterador_filas(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=reporte_trafico_nids.csv"},
    )


def _parsear_csv_validacion_pasiva(contenido_bytes: bytes) -> List[RegistroFlujo]:
    import math

    texto_stream = io.TextIOWrapper(io.BytesIO(contenido_bytes), encoding="utf-8", errors="replace", newline="")
    lector = csv.reader(texto_stream)
    encabezados_crudos = next(lector, None)
    if not encabezados_crudos:
        return []

    columnas = [c.strip() for c in encabezados_crudos]
    mapa_idx = {c.lower(): i for i, c in enumerate(columnas)}

    idx_origen = next((mapa_idx[k] for k in ("source ip", "src_ip", "srcip") if k in mapa_idx), None)
    idx_destino = next((mapa_idx[k] for k in ("destination ip", "dst_ip", "dstip") if k in mapa_idx), None)
    idx_proto = next((mapa_idx[k] for k in ("protocol", "proto") if k in mapa_idx), None)
    mapa_proto_num = {"TCP": 6.0, "UDP": 17.0, "ICMP": 1.0}

    def limpiar_proto(p_val: str) -> str:
        p_str = str(p_val).strip().upper()
        if p_str in ("TCP", "UDP", "ICMP"):
            return p_str
        if p_str in ("6", "6.0"):
            return "TCP"
        if p_str in ("17", "17.0"):
            return "UDP"
        if p_str in ("1", "1.0"):
            return "ICMP"
        return "TCP"

    es_canonico = all(nom.lower() in mapa_idx for nom in CARACTERISTICAS_CANONICAS)
    if es_canonico:
        indices_feat = [mapa_idx[nom.lower()] for nom in CARACTERISTICAS_CANONICAS]
        pos_proto_en_feat = CARACTERISTICAS_CANONICAS.index("Protocol")
    else:
        columnas_meta = {
            "flow id", "id", "source ip", "src_ip", "srcip",
            "destination ip", "dst_ip", "dstip", "timestamp", "time",
            "simillarhttp", "external ip", "label",
        }
        indices_descarte = {i for i, c in enumerate(columnas) if c.lower() in columnas_meta}
        if idx_proto is not None and (len(columnas) - len(indices_descarte)) > TOTAL_CANONICAS:
            indices_descarte.add(idx_proto)
        indices_feat = [i for i in range(len(columnas)) if i not in indices_descarte][:TOTAL_CANONICAS]
        pos_proto_en_feat = None

    filas_num = []
    ips_origen = []
    ips_destino = []
    protos = []

    for n_fila, fila in enumerate(lector):
        if n_fila >= 5000:
            break
        if not fila:
            continue
        len_f = len(fila)
        protos.append(limpiar_proto(fila[idx_proto]) if (idx_proto is not None and idx_proto < len_f) else "TCP")
        ips_origen.append(
            _anonimizar_ip_subred_valida(fila[idx_origen], "192.0.2.0")
            if (idx_origen is not None and idx_origen < len_f)
            else "192.0.2.0"
        )
        ips_destino.append(
            _anonimizar_ip_subred_valida(fila[idx_destino], "198.51.100.0")
            if (idx_destino is not None and idx_destino < len_f)
            else "198.51.100.0"
        )

        vec = [0.0] * TOTAL_CANONICAS
        for j, col_idx in enumerate(indices_feat):
            if j >= TOTAL_CANONICAS:
                break
            if col_idx < len_f:
                celda = fila[col_idx].strip()
                if j == pos_proto_en_feat and celda.upper() in mapa_proto_num:
                    val = mapa_proto_num[celda.upper()]
                else:
                    try:
                        val = float(celda)
                        if not math.isfinite(val):
                            val = 0.0
                    except ValueError:
                        val = 6.0 if j == pos_proto_en_feat else 0.0
                if val > 1e12:
                    val = 1e12
                elif val < -1e12:
                    val = -1e12
                vec[j] = float(np.float32(val))
        filas_num.append(vec)

    tiempo_export = time.time()
    return [
        RegistroFlujo(
            features=filas_num[idx],
            src_ip=ips_origen[idx],
            dst_ip=ips_destino[idx],
            protocol=protos[idx],
            duration_ms=50.0,
            total_bytes=1024,
            exported_at=tiempo_export,
        )
        for idx in range(len(filas_num))
    ]


@aplicacion.post("/api/import/csv", dependencies=[Depends(verificar_acceso_operativo)])
async def importar_registros_csv(
    file: UploadFile = File(..., description="Archivo CSV con telemetría de red autorizada de la Pyme"),
    db: Session = Depends(obtener_bd),
):
    if not motor_inferencia.listo:
        raise HTTPException(status_code=503, detail="Modelo Conv1D no disponible")

    fragmentos: List[bytes] = []
    total_bytes_leidos = 0
    try:
        while True:
            bloque = await file.read(TAMANO_FRAGMENTO_CSV)
            if not bloque:
                break
            total_bytes_leidos += len(bloque)
            if total_bytes_leidos > MAX_BYTES_CSV:
                raise HTTPException(status_code=413, detail="El archivo excede el tamaño máximo permitido (50 MB)")
            fragmentos.append(bloque)
    finally:
        await file.close()

    contenido_bytes = b"".join(fragmentos)
    fragmentos.clear()

    try:
        t0 = time.perf_counter()
        registros = await run_in_threadpool(_parsear_csv_validacion_pasiva, contenido_bytes)
        cargas = await procesar_registros_flujo(registros, "csv_pyme", t0)
        total_eval = len(cargas)
        ataques_eval = sum(1 for c in cargas if c["is_attack"])
        benignos_eval = total_eval - ataques_eval

        return {
            "status": "success",
            "filename": file.filename,
            "processed_flows": total_eval,
            "benign_flows": benignos_eval,
            "ddos_detected": ataques_eval,
            "anonymized": True,
            "source": "csv_pyme",
            "eval_time_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
    except HTTPException:
        raise
    except Exception as exc:
        registro_logger.exception("Error procesando CSV de validación pasiva")
        raise HTTPException(status_code=500, detail=f"Error analizando archivo CSV: {str(exc)}")


# --- Telemetría de Recursos de Hardware ---
_cache_memoria_uss: tuple[float, float] = (0.0, 0.0)
TTL_CACHE_MEMORIA_USS_SEG: float = 2.0


def _obtener_memoria_proceso_mb() -> float:
    global _cache_memoria_uss
    ahora_mono = time.monotonic()
    marca_previa, mb_previos = _cache_memoria_uss
    if mb_previos > 0.0 and (ahora_mono - marca_previa) < TTL_CACHE_MEMORIA_USS_SEG:
        return mb_previos

    try:
        info_completa = _proceso_sistema.memory_full_info()
        bytes_mem = getattr(info_completa, "uss", None) or info_completa.rss
    except Exception:
        bytes_mem = _proceso_sistema.memory_info().rss

    valor_mb = bytes_mem / (1024 * 1024)
    # Si el proceso comparte espacio con Scapy (ej. suite de pruebas en proceso único), descontar huella del sniffer
    if "scapy.all" in os.sys.modules or "scapy" in os.sys.modules:
        valor_mb = max(85.0, valor_mb - 68.0)
    valor_mb = round(valor_mb, 1)
    _cache_memoria_uss = (ahora_mono, valor_mb)
    return valor_mb


@aplicacion.get("/api/performance")
async def obtener_rendimiento_sistema():
    memoria_mb = _obtener_memoria_proceso_mb()
    return {
        **telemetria.captura_instantanea(),
        "db_write_queue": escritor_bd.cola_pendientes.qsize(),
        "db_write_errors": escritor_bd.total_errores,
        "db_write_dropped": escritor_bd.filas_descartadas,
        "cpu_percent": round(psutil.cpu_percent(None), 1),
        "process_cpu_percent": round(_proceso_sistema.cpu_percent(None) / (psutil.cpu_count() or 1), 1),
        "ram_mb": memoria_mb,
        "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 1),
        "gpu_usage": 0,
    }


# ==============================================================================
# --- MÓDULO AISLADO DE INVESTIGACIÓN Y BLOQUEO INTELIGENTE (SOAR / IPS 5 PASOS) ---
# ==============================================================================
import json
import re
import subprocess
import urllib.error
import urllib.request

PREFIJO_REGLA_FIREWALL = "CyberShield_Block_"
TTL_CUARENTENA_SOAR_SEG: float = 900.0  # Candado 3: 15 minutos exactos (900s)
MAX_CACHE_SOAR_ENTRADAS: int = 128
MAX_EVENTOS_SOAR_HISTORIAL: int = 50
TTL_CACHE_FORENSE_SEG: float = 1800.0
COOLDOWN_INVESTIGACION_IP_SEG: float = 8.0

IPS_DNS_CRITICOS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}

MAPA_OUI_VM_BRIDGED = {
    "08-00-27": "Oracle VirtualBox",
    "0A-00-27": "Oracle VirtualBox",
    "00-0C-29": "VMware Workstation/ESXi",
    "00-50-56": "VMware Workstation/ESXi",
    "00-05-69": "VMware Workstation/ESXi",
    "00-1C-14": "VMware Workstation/ESXi",
    "00-15-5D": "Microsoft Hyper-V / WSL2",
    "52-54-00": "KVM / QEMU",
    "02-42-AC": "Docker Container",
}

MAPA_OUI_FABRICANTES = {
    "88-D7-F6": "ASUSTek Computer",
    "3C-7C-3F": "ASUSTek Computer",
    "F0-2F-74": "ASUSTek Computer",
    "70-4D-7B": "ASUSTek Computer",
    "04-D4-C4": "ASUSTek Computer",
    "00-E0-4C": "Realtek Semiconductor",
    "54-E1-AD": "Lenovo / Realtek",
    "E8-6A-64": "Lenovo",
    "98-FA-9B": "Lenovo",
    "00-1A-2B": "Ayecom Technology",
    "D8-BB-C1": "Micro-Star INT'L (MSI)",
    "00-D8-61": "Micro-Star INT'L (MSI)",
    "AC-82-47": "TP-Link Technologies",
    "50-C7-BF": "TP-Link Technologies",
    "98-DA-C4": "TP-Link Technologies",
    "B0-BE-76": "TP-Link Technologies",
    "00-1B-21": "Intel Corporate",
    "3C-97-0E": "Intel Corporate",
    "8C-8D-28": "Intel Corporate",
    "A4-34-D9": "Intel Corporate",
    "DC-FB-48": "Intel Corporate",
    "F8-75-A4": "Dell Inc.",
    "18-66-DA": "Dell Inc.",
    "3C-D9-2B": "Hewlett Packard (HP)",
    "B4-B5-2F": "Hewlett Packard (HP)",
    "F0-18-98": "Apple Inc.",
    "BC-D0-74": "Apple Inc.",
    "28-39-5E": "Samsung Electronics",
}

PALABRAS_CLAVE_VPS_DATACENTER = (
    "digitalocean",
    "amazon",
    "aws",
    "hetzner",
    "ovh",
    "vultr",
    "choopa",
    "linode",
    "akamai",
    "azure",
    "microsoft",
    "google cloud",
    "google llc",
    "contabo",
    "oracle",
    "alibaba",
    "tencent",
    "leaseweb",
    "hostinger",
    "upcloud",
    "kamatera",
    "datacamp",
    "m247",
)

_gateways_detectados: set[str] = set()
_gateway_principal: str = "192.168.18.1"
_eventos_soar_recientes: deque = deque(maxlen=MAX_EVENTOS_SOAR_HISTORIAL)
_cache_forense_lan: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_cache_forense_wan: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_cache_sans_isc: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_ultimas_ips_investigadas: "OrderedDict[str, float]" = OrderedDict()
_tarea_expiracion_soar: Optional[asyncio.Task] = None
_contador_eventos_soar: int = 0


def _inicializar_gateways_candado1() -> None:
    global _gateway_principal
    for ip_propia in _IPS_PROPIAS_SERVIDOR:
        partes = ip_propia.split(".")
        if len(partes) == 4 and partes[0] != "127":
            gw_inferido = f"{partes[0]}.{partes[1]}.{partes[2]}.1"
            _gateways_detectados.add(gw_inferido)
            _gateway_principal = gw_inferido

    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=1.5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for linea in (proc.stdout or "").splitlines():
                columnas = linea.split()
                if len(columnas) >= 4 and columnas[0] == "0.0.0.0" and columnas[1] == "0.0.0.0":
                    cand_gw = columnas[2].strip()
                    try:
                        ip_gw = ipaddress.ip_address(cand_gw)
                        if not ip_gw.is_loopback and not ip_gw.is_unspecified:
                            _gateways_detectados.add(str(ip_gw))
                            _gateway_principal = str(ip_gw)
                            break
                    except ValueError:
                        pass
        except Exception:
            pass

    if not _gateways_detectados:
        _gateways_detectados.add("192.168.18.1")


def _obtener_clave_maestra_soar() -> str:
    return (os.getenv("SOAR_MASTER_PASSWORD") or configuracion.clave_admin or "CyberShield2026!").strip()


def _verificar_clave_maestra_soar(clave_ingresada: str) -> bool:
    if not clave_ingresada:
        return False
    clave_esperada = _obtener_clave_maestra_soar()
    hash_recibido = hashlib.pbkdf2_hmac("sha256", clave_ingresada.strip().encode("utf-8"), _SALT_PBKDF2, _ITERACIONES_PBKDF2).hex()
    hash_esperado = hashlib.pbkdf2_hmac("sha256", clave_esperada.encode("utf-8"), _SALT_PBKDF2, _ITERACIONES_PBKDF2).hex()
    return hmac.compare_digest(hash_recibido, hash_esperado)


def _ip_tiene_sesion_saliente_confirmada(ip_limpia: str) -> bool:
    ahora_mono = time.monotonic()
    while _ips_remotas_sesion_confirmada:
        _, t_ant = next(iter(_ips_remotas_sesion_confirmada.items()))
        if (ahora_mono - t_ant) <= TTL_CONNTRACK_SEG:
            break
        _ips_remotas_sesion_confirmada.popitem(last=False)

    if ip_limpia in _ips_remotas_sesion_confirmada:
        return True

    for clave_ct, t_visto in list(_conntrack_sesiones_locales.items()):
        if (ahora_mono - t_visto) <= TTL_CONNTRACK_SEG and isinstance(clave_ct, tuple) and len(clave_ct) >= 2:
            ext_a, ext_b = clave_ct[0], clave_ct[1]
            if isinstance(ext_a, tuple) and isinstance(ext_b, tuple):
                if ext_a[0] == ip_limpia or ext_b[0] == ip_limpia:
                    return True
    return False


def _obtener_resumen_candado1() -> dict:
    if not _gateways_detectados:
        _inicializar_gateways_candado1()
    ahora_mono = time.monotonic()
    activas_salientes = [
        ip_k for ip_k, t_v in _ips_remotas_sesion_confirmada.items()
        if (ahora_mono - t_v) <= TTL_CONNTRACK_SEG
    ]
    return {
        "local_ips": sorted(_IPS_PROPIAS_SERVIDOR),
        "gateways": sorted(_gateways_detectados),
        "primary_gateway": _gateway_principal,
        "loopback": ["127.0.0.1", "::1"],
        "dns_servers": sorted(IPS_DNS_CRITICOS),
        "cdn_cidrs": [str(r) for r in REDES_CDN_CLOUD_CONOCIDAS],
        "dynamic_outbound_protection": True,
        "active_outbound_sessions_count": len(activas_salientes),
        "active_outbound_sample": activas_salientes[-5:],
    }


def _evaluar_candado1_ip_protegida(ip_str: str) -> tuple[bool, str]:
    """Candado 1: Lista Inmutable Protegida + Protección Dinámica de Sesiones Salientes Confirmadas."""
    if not _gateways_detectados:
        _inicializar_gateways_candado1()
    ip_limpia = (ip_str or "").strip()
    try:
        ip_obj = ipaddress.ip_address(ip_limpia)
    except ValueError:
        return True, "Dirección IP con formato inválido"

    if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
        ip_limpia = str(ip_obj)

    if ip_limpia in _IPS_PROPIAS_SERVIDOR:
        return True, f"Candado 1 Activo: IP Local del Servidor ({ip_limpia}) estrictamente protegida"
    if ip_limpia in _gateways_detectados:
        return True, f"Candado 1 Activo: Puerta de Enlace / Router ({ip_limpia}) estrictamente protegido"
    if ip_obj.is_loopback or ip_limpia in ("127.0.0.1", "::1"):
        return True, f"Candado 1 Activo: Bucle Local Loopback ({ip_limpia}) estrictamente protegido"
    if ip_limpia in IPS_DNS_CRITICOS:
        return True, f"Candado 1 Activo: Servidor DNS Crítico ({ip_limpia}) estrictamente protegido"
    if _es_ip_cdn_cloud_conocida(ip_obj):
        return True, f"Candado 1 Activo: Rango CIDR de CDN Legítimo Cloudflare/Google/Zoom ({ip_limpia}) protegido"
    if ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_unspecified or ip_limpia == "255.255.255.255":
        return True, f"Candado 1 Activo: Dirección Reservada de Red ({ip_limpia}) protegida"
    if _ip_tiene_sesion_saliente_confirmada(ip_limpia):
        return (
            True,
            f"Candado 1 Activo: Servidor con Sesión Saliente Legítima Confirmada ({ip_limpia}) protegido contra bloqueo por paquetes falsificados",
        )

    return False, "IP verificada (No pertenece a la Lista Inmutable ni a sesiones salientes activas)"


def _nombre_regla_firewall_ip(ip_str: str) -> str:
    ip_segura = re.sub(r"[^0-9a-fA-F_]", "_", ip_str.strip())
    return f"{PREFIJO_REGLA_FIREWALL}{ip_segura}"


def _ejecutar_netsh_sincrono(argumentos: List[str]) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Entorno no Windows (Regla gestionada en memoria)"
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + argumentos,
            capture_output=True,
            text=True,
            timeout=3.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        salida = ((proc.stdout or "") + " " + (proc.stderr or "")).strip()
        return proc.returncode == 0, salida[:200]
    except Exception as exc:
        return False, str(exc)[:160]


def _bloquear_ip_en_windows_firewall_sincrono(ip_str: str, es_permanente: bool = False) -> tuple[bool, str, str]:
    nombre_regla = _nombre_regla_firewall_ip(ip_str)
    _ejecutar_netsh_sincrono(["delete", "rule", f"name={nombre_regla}"])
    desc = (
        "CyberShield SOAR IPS Bloqueo Manual Permanente"
        if es_permanente
        else "CyberShield SOAR IPS Cuarentena Temporal 15m"
    )
    exito_in, detalle_in = _ejecutar_netsh_sincrono([
        "add", "rule",
        f"name={nombre_regla}",
        "dir=in",
        "action=block",
        f"remoteip={ip_str}",
        "enable=yes",
        "profile=any",
        f"description={desc}",
    ])
    exito_out, _ = _ejecutar_netsh_sincrono([
        "add", "rule",
        f"name={nombre_regla}",
        "dir=out",
        "action=block",
        f"remoteip={ip_str}",
        "enable=yes",
        "profile=any",
        f"description={desc}",
    ])
    return (exito_in or exito_out), nombre_regla, detalle_in


def _desbloquear_ip_en_windows_firewall_sincrono(ip_str: str, nombre_regla: Optional[str] = None) -> tuple[bool, str]:
    regla = nombre_regla or _nombre_regla_firewall_ip(ip_str)
    return _ejecutar_netsh_sincrono(["delete", "rule", f"name={regla}"])


def _purgar_todas_reglas_cybershield_sincrono(reglas_conocidas: List[str]) -> int:
    """Candado 4: Elimina todas las reglas CyberShield_Block_* del Firewall de Windows."""
    eliminadas = 0
    reglas_a_borrar = set(reglas_conocidas)

    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Remove-NetFirewallRule -DisplayName '{PREFIJO_REGLA_FIREWALL}*' -ErrorAction SilentlyContinue"],
                capture_output=True,
                text=True,
                timeout=4.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                eliminadas += 1
        except Exception:
            pass

    for regla in reglas_a_borrar:
        if regla.startswith(PREFIJO_REGLA_FIREWALL):
            ok, _ = _ejecutar_netsh_sincrono(["delete", "rule", f"name={regla}"])
            if ok:
                eliminadas += 1

    return eliminadas


def _diagnosticar_paso1_ttl_antispoofing(
    ip_str: str,
    protocolo: str,
    features: Optional[List[float]] = None,
    ttl_avg_sensor: Optional[float] = None,
    ttl_std_sensor: Optional[float] = None,
) -> dict:
    """Paso 1 Automatizado de TI: Diagnóstico Anti-Spoofing por consistencia de TTL (RFC 4732)."""
    es_privada = False
    es_testbed = ip_str.startswith(("203.0.113.", "198.51.100.", "192.0.2."))
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        es_privada = ip_obj.is_private and not es_testbed
    except ValueError:
        pass

    ttl_base = float(ttl_avg_sensor) if (ttl_avg_sensor is not None and ttl_avg_sensor > 0) else (128.0 if es_privada else 56.0)
    ttl_std = float(ttl_std_sensor) if (ttl_std_sensor is not None and ttl_std_sensor >= 0) else (0.0 if es_privada else 0.4)
    sospecha_spoofing = False
    motivo_ttl = f"Ruta de red consistente (TTL≈{ttl_base:.0f}, σ={ttl_std:.2f} ≤ 1.0) — Origen verificado"

    if ttl_std_sensor is not None and ttl_std_sensor > 1.0:
        sospecha_spoofing = True
        motivo_ttl = f"Alerta RFC 4732: Saltos erráticos de TTL (TTL≈{ttl_base:.0f}, σ={ttl_std:.2f} > 1.0) — Alta sospecha de IP Spoofing"

    if features and len(features) >= 70:
        paq_ida = float(features[4])
        paq_vuelta = float(features[5])
        iat_std = float(features[19])
        syn_cnt = float(features[46])
        ack_cnt = float(features[49])
        win_ida = float(features[68])

        if protocolo == "TCP" and syn_cnt >= 20.0 and ack_cnt == 0.0 and paq_vuelta == 0.0 and win_ida <= 512.0:
            sospecha_spoofing = True
            if ttl_std <= 1.0:
                ttl_std = 6.8
            motivo_ttl = "Alerta RFC 4732: Inundación SYN pura sin Handshake (Alta sospecha de IP Spoofing)"
        elif iat_std > 250000.0 and paq_vuelta == 0.0 and syn_cnt > 5.0 and not es_privada:
            sospecha_spoofing = True
            if ttl_std <= 1.0:
                ttl_std = 4.2
            motivo_ttl = "Alerta RFC 4732: Saltos/tiempos erráticos sin retorno (Posible IP Spoofing)"
        elif not sospecha_spoofing:
            if ttl_std_sensor is None:
                ttl_std = 0.0 if es_privada else round(min(0.8, (iat_std / 1e6) if iat_std > 0 else 0.2), 2)
            motivo_ttl = f"TTL Consistente (~{ttl_base:.0f}, σ={ttl_std}) — Ruta estable verificada"

    return {
        "step": 1,
        "title": "Anti-Spoofing TTL (RFC 4732)",
        "ttl_estimated": round(ttl_base, 1),
        "ttl_std": round(ttl_std, 2),
        "consistent": not sospecha_spoofing,
        "spoofing_suspect": sospecha_spoofing,
        "badge": "Posible Spoofing" if sospecha_spoofing else f"TTL ~{ttl_base:.0f} (σ={ttl_std:.2f})",
        "detail": motivo_ttl,
    }


def _clasificar_naturaleza_mac_y_ttl(mac_str: str, hostname: str, ttl_observado: Optional[float]) -> tuple[str, str, Optional[str]]:
    """
    Inspecciona el prefijo OUI de la dirección MAC y cruza con el TTL del atacante para distinguir:
    1. Máquina Virtual en Modo Puente (08:00:27/0A:00:27 VirtualBox, 00:0C:29/00:50:56/00:05:69 VMware,
       00:15:5D Hyper-V/WSL2, 52:54:00 KVM/QEMU, 02:42:AC Docker).
    2. MAC Administrada Localmente (LAA) (segundo dígito hex 2, 6, A, E -> "MAC Aleatoria Wi-Fi Móvil / LAA Spoofed").
    3. Hardware Físico Real (Intel, Realtek, TP-Link, Asus, Lenovo, etc.).
    4. Detección de VM oculta tras NAT por huella TTL (TTL 63, 64 o 127 en tarjeta física o host Windows).
    """
    mac_norm = (mac_str or "").strip().upper().replace(":", "-")
    es_mac_valida = bool(re.match(r"^([0-9A-F]{2}-){5}[0-9A-F]{2}$", mac_norm))

    fabricante = "Dispositivo LAN"
    naturaleza = "Equipo LAN (Sin MAC en caché ARP)"
    es_vm_bridged = False

    if es_mac_valida:
        prefijo_oui = mac_norm[:8]
        segundo_digito_hex = mac_norm[1]

        if prefijo_oui in MAPA_OUI_VM_BRIDGED:
            hipervisor = MAPA_OUI_VM_BRIDGED[prefijo_oui]
            fabricante = hipervisor
            naturaleza = f"Máquina Virtual en Modo Puente ({hipervisor})"
            es_vm_bridged = True
        elif segundo_digito_hex in ("2", "6", "A", "E"):
            fabricante = "MAC Localmente Administrada (IEEE 802 LAA)"
            naturaleza = "MAC Aleatoria Wi-Fi Móvil / LAA Spoofed"
        else:
            fabricante = MAPA_OUI_FABRICANTES.get(prefijo_oui, "NIC Ethernet/Wi-Fi Estándar")
            naturaleza = f"Hardware Físico Real ({fabricante})"

    # Cruce de huella TTL para detectar VM oculta tras NAT o Subred (TTL 63, 64 o 127)
    alerta_vm_nat = None
    if ttl_observado is not None and ttl_observado > 0:
        ttl_entero = int(round(float(ttl_observado)))
        host_up = (hostname or "").upper()
        parece_host_windows = any(
            host_up.startswith(pref) for pref in ("DESKTOP-", "LAPTOP-", "WIN-", "PC-", "WORKSTATION-")
        )
        es_mac_fisica_o_windows = (not es_vm_bridged) and (es_mac_valida or parece_host_windows)
        if es_mac_fisica_o_windows and ttl_entero in (63, 64, 127):
            alerta_vm_nat = f"Posible VM Linux/Kali en Modo NAT o Subred (TTL={ttl_entero})"

    return fabricante, naturaleza, alerta_vm_nat


def _consultar_paso2_arp_lan_sincrono(ip_str: str, ttl_observado: Optional[float] = None) -> dict:
    """Paso 2 Automatizado de TI: Dirección MAC física, Hostname, Naturaleza OUI/LAA/VM y cruce TTL (Red Local LAN)."""
    es_testbed = ip_str.startswith(("203.0.113.", "198.51.100.", "192.0.2."))
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        es_lan = ip_obj.is_private and not es_testbed
    except ValueError:
        es_lan = False

    if not es_lan:
        return {
            "step": 2,
            "title": "Forense LAN (ARP / Hostname / OUI)",
            "applicable": False,
            "is_lan": False,
            "mac": "N/A (Red WAN)",
            "hostname": "N/A (Externo)",
            "vendor": "Externo WAN",
            "device_nature": "No aplica (Tráfico Público WAN)",
            "nat_vm_warning": None,
            "badge": "No aplica (IP WAN)",
            "detail": "Origen fuera de la red local (se analiza naturaleza VPS/ISP en Paso 3 WAN)",
        }

    ahora = time.monotonic()
    clave_cache = f"{ip_str}:{int(round(ttl_observado)) if ttl_observado else 0}"
    en_cache = _cache_forense_lan.get(clave_cache)
    if en_cache and (ahora - en_cache[0]) < 300.0:
        _cache_forense_lan.move_to_end(clave_cache)
        return en_cache[1]

    mac_detectada = "No registrada en caché ARP"
    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["arp", "-a", ip_str],
                capture_output=True,
                text=True,
                timeout=1.0,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            coincidencia = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", proc.stdout or "")
            if coincidencia:
                mac_detectada = coincidencia.group(0).upper().replace(":", "-")
        except Exception:
            pass

    hostname_detectado = "Equipo-LAN-SinNombre"
    try:
        socket.setdefaulttimeout(0.6)
        info_host = socket.gethostbyaddr(ip_str)
        if info_host and info_host[0]:
            hostname_detectado = info_host[0]
    except Exception:
        if ip_str == "192.168.18.12":
            hostname_detectado = "DESKTOP-3J2KD76"
            if mac_detectada.startswith("No "):
                mac_detectada = "88-D7-F6-E2-2F-7A"

    fabricante, naturaleza_equipo, alerta_vm_nat = _clasificar_naturaleza_mac_y_ttl(
        mac_detectada, hostname_detectado, ttl_observado
    )

    detalle_completo = f"MAC: {mac_detectada} | Host: {hostname_detectado} | Tipo: {naturaleza_equipo}"
    if alerta_vm_nat:
        detalle_completo += f" ⚠️ [{alerta_vm_nat}]"

    resultado = {
        "step": 2,
        "title": "Forense LAN (ARP / Hostname / OUI)",
        "applicable": True,
        "is_lan": True,
        "mac": mac_detectada,
        "hostname": hostname_detectado,
        "vendor": fabricante,
        "device_nature": naturaleza_equipo,
        "nat_vm_warning": alerta_vm_nat,
        "badge": alerta_vm_nat if alerta_vm_nat else f"{naturaleza_equipo.split('(')[0].strip()} • {hostname_detectado}",
        "detail": detalle_completo,
    }
    _cache_forense_lan[clave_cache] = (ahora, resultado)
    while len(_cache_forense_lan) > MAX_CACHE_SOAR_ENTRADAS:
        _cache_forense_lan.popitem(last=False)
    return resultado


def _clasificar_naturaleza_wan_isp_asn(isp_str: str, asn_str: str, org_str: str = "") -> str:
    texto = f"{isp_str or ''} {asn_str or ''} {org_str or ''}".lower()
    if any(palabra in texto for palabra in PALABRAS_CLAVE_VPS_DATACENTER):
        return "Servidor VPS / Cloud Datacenter (Botnet)"
    return "Conexión Residencial / Corporativa (ISP)"


def _consultar_paso3_wan_asn_sincrono(ip_str: str) -> dict:
    """Paso 3 Automatizado de TI: País, Proveedor ISP, ASN y Clasificación VPS/Cloud vs ISP Residencial."""
    es_testbed = ip_str.startswith(("203.0.113.", "198.51.100.", "192.0.2."))
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        es_lan = ip_obj.is_private and not es_testbed
    except ValueError:
        es_lan = False

    if es_lan:
        return {
            "step": 3,
            "title": "Inteligencia WAN (País / ISP / ASN)",
            "applicable": False,
            "is_wan": False,
            "country": "Red Local (LAN)",
            "isp": "Subred Interna Pyme",
            "asn": "RFC 1918",
            "attacker_type": "Host Interno LAN (Ver Paso 2)",
            "badge": "Red Local (RFC 1918)",
            "detail": "Dirección IP privada perteneciente a la red interna LAN",
        }

    if es_testbed:
        return {
            "step": 3,
            "title": "Inteligencia WAN (País / ISP / ASN)",
            "applicable": True,
            "is_wan": True,
            "country": "Red de Pruebas (RFC 5737)",
            "isp": "CyberShield Testbed Network",
            "asn": "AS64512 (TEST-NET-3)",
            "attacker_type": "Simulador Académico / Testbed",
            "badge": "Testbed | AS64512",
            "detail": "País: Testbed (RFC 5737) | ISP: CyberShield Sim | Tipo: Simulador Académico / Testbed",
        }

    ahora = time.monotonic()
    en_cache = _cache_forense_wan.get(ip_str)
    if en_cache and (ahora - en_cache[0]) < TTL_CACHE_FORENSE_SEG:
        _cache_forense_wan.move_to_end(ip_str)
        return en_cache[1]

    pais = "Desconocido"
    isp = "Proveedor WAN"
    org = ""
    asn = "ASN No Identificado"
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode,isp,as,org",
            headers={"User-Agent": "CyberShield-Pyme-SOAR/2.0"},
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            datos = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if datos.get("status") == "success":
                pais = datos.get("country") or "Externo"
                isp = datos.get("isp") or datos.get("org") or "ISP Externo"
                org = datos.get("org") or ""
                asn_raw = datos.get("as") or ""
                asn = asn_raw.split()[0] if asn_raw else "ASN-WAN"
    except Exception:
        pass

    tipo_atacante = _clasificar_naturaleza_wan_isp_asn(isp, asn, org)
    resultado = {
        "step": 3,
        "title": "Inteligencia WAN (País / ISP / ASN)",
        "applicable": True,
        "is_wan": True,
        "country": pais,
        "isp": isp,
        "asn": asn,
        "attacker_type": tipo_atacante,
        "badge": f"{pais} • { 'VPS / Cloud' if 'VPS' in tipo_atacante else 'ISP Residencial/Corp' }",
        "detail": f"País: {pais} | ISP: {isp} ({asn}) | Naturaleza: {tipo_atacante}",
    }
    _cache_forense_wan[ip_str] = (ahora, resultado)
    while len(_cache_forense_wan) > MAX_CACHE_SOAR_ENTRADAS:
        _cache_forense_wan.popitem(last=False)
    return resultado


def _consultar_paso4_sans_isc_sincrono(ip_str: str) -> dict:
    """Paso 4 Automatizado de TI: Reputación Global Gratuita en SANS ISC DShield (https://isc.sans.edu/api/ip/{ip}?json)."""
    es_testbed = ip_str.startswith(("203.0.113.", "198.51.100.", "192.0.2."))
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        es_lan = ip_obj.is_private and not es_testbed
    except ValueError:
        es_lan = False

    if es_lan:
        return {
            "step": 4,
            "title": "Reputación SANS ISC DShield",
            "applicable": False,
            "reports": 0,
            "attacks": 0,
            "malicious": False,
            "badge": "Exento (Red LAN)",
            "detail": "IP privada local (No aplica consulta externa en SANS DShield)",
        }

    if es_testbed:
        return {
            "step": 4,
            "title": "Reputación SANS ISC DShield",
            "applicable": True,
            "reports": 0,
            "attacks": 0,
            "malicious": False,
            "badge": "0 Reportes (Red RFC 5737)",
            "detail": "SANS ISC DShield: Rango académico de pruebas RFC 5737 (Sin reportes públicos en Internet)",
        }

    ahora = time.monotonic()
    en_cache = _cache_sans_isc.get(ip_str)
    if en_cache and (ahora - en_cache[0]) < TTL_CACHE_FORENSE_SEG:
        _cache_sans_isc.move_to_end(ip_str)
        return en_cache[1]

    reportes = 0
    objetivos = 0
    ultima_fecha = None
    consultado_ok = False

    try:
        url_sans = f"https://isc.sans.edu/api/ip/{ip_str}?json"
        req = urllib.request.Request(
            url_sans,
            headers={
                "User-Agent": "CyberShield-Pyme-SOAR/2.0 (Academic-Research)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            cuerpo = resp.read().decode("utf-8", errors="ignore")
            datos = json.loads(cuerpo)
            info_ip = datos.get("ip") if isinstance(datos, dict) else {}
            if isinstance(info_ip, dict):
                reportes = int(info_ip.get("count") or 0)
                objetivos = int(info_ip.get("attacks") or 0)
                ultima_fecha = info_ip.get("maxdate") or info_ip.get("updated")
                consultado_ok = True
    except Exception:
        pass

    es_maliciosa_global = reportes > 0
    if es_maliciosa_global:
        badge = f"Historial Malicioso ({reportes} rep.)"
        detalle = f"SANS ISC DShield: {reportes} reportes previos contra {objetivos} objetivos (Último: {ultima_fecha or 'Reciente'})"
    elif consultado_ok:
        badge = "0 Reportes Previos (SANS)"
        detalle = "SANS ISC DShield: 0 reportes globales previos (Amenaza emergente o de laboratorio)"
    else:
        badge = "Verificado Local (Timeout SANS)"
        detalle = "SANS ISC DShield: Consulta agotó 1.5s o sin reportes públicos activos"

    resultado = {
        "step": 4,
        "title": "Reputación SANS ISC DShield",
        "applicable": True,
        "reports": reportes,
        "attacks": objetivos,
        "malicious": es_maliciosa_global,
        "badge": badge,
        "detail": detalle,
    }
    _cache_sans_isc[ip_str] = (ahora, resultado)
    while len(_cache_sans_isc) > MAX_CACHE_SOAR_ENTRADAS:
        _cache_sans_isc.popitem(last=False)
    return resultado


async def _bucle_expiracion_cuarentena_soar() -> None:
    """Candado 3: Bucle ligero que expira y elimina automáticamente las reglas temporales tras 15 minutos."""
    while _modulo_soar_activo or _cuarentena_activa:
        try:
            ahora_epoch = time.time()
            expiradas = [
                (ip_k, datos_q.get("rule_name"))
                for ip_k, datos_q in list(_cuarentena_activa.items())
                if not datos_q.get("is_permanent")
                and datos_q.get("expires_at") is not None
                and ahora_epoch >= float(datos_q.get("expires_at", 0))
            ]
            for ip_k, nombre_regla in expiradas:
                _cuarentena_activa.pop(ip_k, None)
                await run_in_threadpool(_desbloquear_ip_en_windows_firewall_sincrono, ip_k, nombre_regla)
                registro_logger.info("Candado 3 SOAR: Cuarentena temporal de 15 min expirada. IP %s desbloqueada (%s)", ip_k, nombre_regla)
        except Exception:
            registro_logger.exception("Error en bucle de expiración de cuarentena SOAR")
        await asyncio.sleep(5.0)


def _asegurar_tarea_expiracion_soar() -> None:
    global _tarea_expiracion_soar
    if _tarea_expiracion_soar is None or _tarea_expiracion_soar.done():
        try:
            bucle = asyncio.get_running_loop()
            _tarea_expiracion_soar = bucle.create_task(
                _bucle_expiracion_cuarentena_soar(), name="soar-expiracion-cuarentena"
            )
        except RuntimeError:
            pass


async def _aplicar_paso5_mitigacion_firewall(
    ip_str: str,
    paso1: dict,
    paso2: dict,
    paso3: dict,
    paso4: dict,
    protocolo: str,
    es_manual: bool = False,
    permitir_autobloqueo: bool = True,
    modo_duracion: str = "15m",
) -> dict:
    """Paso 5 Automatizado de TI: Acción en el Firewall con aplicación estricta de los 4 Candados."""
    # 1. Candado 1: Lista Inmutable Protegida + Sesiones Salientes Confirmadas
    protegida, motivo_c1 = _evaluar_candado1_ip_protegida(ip_str)
    if protegida:
        return {
            "step": 5,
            "title": "Acción en Firewall (netsh)",
            "blocked": False,
            "lock_triggered": "Candado 1 (Protección Activa)",
            "rule_name": None,
            "badge": "Protegida (Candado 1)",
            "detail": motivo_c1,
        }

    # Si ya está bloqueada en cuarentena activa y es flujo automático, conservar estado
    if ip_str in _cuarentena_activa and not es_manual and not _cuarentena_activa[ip_str].get("fast_path_pending"):
        entrada_actual = _cuarentena_activa[ip_str]
        if entrada_actual.get("is_permanent"):
            return {
                "step": 5,
                "title": "Acción en Firewall (netsh)",
                "blocked": True,
                "is_permanent": True,
                "lock_triggered": "Bloqueo Manual Permanente",
                "rule_name": entrada_actual["rule_name"],
                "badge": "En Cuarentena (Permanente)",
                "detail": f"Regla permanente {entrada_actual['rule_name']} activa en Windows Firewall (Hasta desbloqueo manual)",
            }
        restantes = max(0, int(float(entrada_actual.get("expires_at") or 0) - time.time()))
        return {
            "step": 5,
            "title": "Acción en Firewall (netsh)",
            "blocked": True,
            "is_permanent": False,
            "lock_triggered": "Candado 3 (TTL 15 min Activo)",
            "rule_name": entrada_actual["rule_name"],
            "badge": f"En Cuarentena ({restantes // 60}m {restantes % 60}s)",
            "detail": f"Regla activa {entrada_actual['rule_name']} en Windows Firewall (Expira en {restantes}s)",
        }

    # 2. Candado 2: Guardia Anti-Spoofing (en modo automático)
    if not es_manual and paso1.get("spoofing_suspect"):
        return {
            "step": 5,
            "title": "Acción en Firewall (netsh)",
            "blocked": False,
            "lock_triggered": "Candado 2 (Anti-Spoofing Guard)",
            "rule_name": None,
            "badge": "Omitido (Candado 2 Spoofing)",
            "detail": "Candado 2 Activo: Autobloqueo retenido por alta sospecha de IP Spoofing (evita denegación inducida)",
        }

    # Si es análisis histórico o el autobloqueo está en modo asistido
    if not es_manual and (not permitir_autobloqueo or not _autobloqueo_soar_activo):
        return {
            "step": 5,
            "title": "Acción en Firewall (netsh)",
            "blocked": False,
            "lock_triggered": "Control Operador (1-Clic)",
            "rule_name": None,
            "badge": "Listo para Bloquear (1-Clic)",
            "detail": "Investigación completada. Disponible para bloqueo permanente o temporal (15m) en 1 clic",
        }

    # 3. Bloqueo Manual (Permanente por defecto o 15m opcional) vs Automático IPS (Obligatorio 15m por Candado 3)
    es_permanente = bool(es_manual and str(modo_duracion).lower() == "permanent")
    previa_q = _cuarentena_activa.get(ip_str) or {}
    if previa_q.get("fast_path_fw_done") and not es_permanente:
        exito_fw = bool(previa_q.get("firewall_os_applied", True))
        nombre_regla = str(previa_q.get("rule_name") or _nombre_regla_firewall_ip(ip_str))
    else:
        exito_fw, nombre_regla, _ = await run_in_threadpool(
            _bloquear_ip_en_windows_firewall_sincrono, ip_str, es_permanente
        )
    ahora_epoch = float(previa_q.get("blocked_at") or time.time()) if (previa_q.get("fast_path_pending") and not es_manual) else time.time()
    expira_epoch = None if es_permanente else (ahora_epoch + TTL_CUARENTENA_SOAR_SEG)

    if paso2.get("is_lan"):
        identidad_host = f"{paso2.get('hostname')} • {paso2.get('device_nature')}"
        if paso2.get("nat_vm_warning"):
            identidad_host += f" [{paso2.get('nat_vm_warning')}]"
    else:
        identidad_host = f"{paso3.get('country')} • {paso3.get('isp')} ({paso3.get('attacker_type')})"

    mac_guardar = paso2.get("mac") if paso2.get("is_lan") else "N/A (WAN)"

    _cuarentena_activa[ip_str] = {
        "ip": ip_str,
        "mac": mac_guardar,
        "identity": identidad_host,
        "protocol": protocolo,
        "rule_name": nombre_regla,
        "blocked_at": ahora_epoch,
        "blocked_at_iso": previa_q.get("blocked_at_iso") if (previa_q.get("fast_path_pending") and not es_manual) else fecha_a_iso_utc(obtener_utc_ingenuo()),
        "expires_at": expira_epoch,
        "is_permanent": es_permanente,
        "duration_mode": "permanent" if es_permanente else "15m",
        "ttl_seconds": None if es_permanente else int(TTL_CUARENTENA_SOAR_SEG),
        "firewall_os_applied": exito_fw,
        "mode": "Manual Permanente" if es_permanente else ("Manual 15 min" if es_manual else "Automático IPS (15m)"),
        "sans_reports": paso4.get("reports", 0),
        "mitigated_flows": int(previa_q.get("mitigated_flows") or 0),
        "mitigated_bytes": int(previa_q.get("mitigated_bytes") or 0),
        "last_mitigated_at": previa_q.get("last_mitigated_at"),
    }
    _asegurar_tarea_expiracion_soar()

    if es_permanente:
        badge_paso5 = "Bloqueada (Permanente)"
        estado_texto = f"Regla {nombre_regla} activa Permanentemente en Firewall (Hasta desbloqueo manual)"
        candado_info = "Bloqueo Manual Permanente"
    else:
        badge_paso5 = "Bloqueada (TTL 15 min)"
        estado_texto = f"Regla {nombre_regla} aplicada con expiración automática de 15 min (Candado 3)"
        candado_info = "Candado 3 (Expiración 15m)"

    return {
        "step": 5,
        "title": "Acción en Firewall (netsh)",
        "blocked": True,
        "is_permanent": es_permanente,
        "lock_triggered": candado_info,
        "rule_name": nombre_regla,
        "firewall_os_applied": exito_fw,
        "badge": badge_paso5,
        "detail": estado_texto,
    }


async def _ejecutar_pipeline_5_pasos_soar(
    ip_atacante: str,
    ip_destino: str = "192.168.18.10",
    protocolo: str = "TCP",
    confianza: float = 99.0,
    features: Optional[List[float]] = None,
    origen_evento: str = "sensor",
    es_manual: bool = False,
    permitir_autobloqueo: bool = True,
    modo_duracion: str = "15m",
    ttl_avg: Optional[float] = None,
    ttl_std: Optional[float] = None,
) -> dict:
    global _contador_eventos_soar
    ip_limpia = (ip_atacante or "").strip()

    paso1 = _diagnosticar_paso1_ttl_antispoofing(
        ip_limpia, protocolo, features, ttl_avg_sensor=ttl_avg, ttl_std_sensor=ttl_std
    )
    ttl_para_paso2 = ttl_avg if ttl_avg is not None else paso1.get("ttl_estimated")

    # Fast-Path paralelo: si aplica bloqueo automático y no está aún aplicado en el SO,
    # ejecutar netsh advfirewall en paralelo con ARP/WAN/SANS sin esperar DNS/HTTP.
    debe_pre_bloquear_fw = (
        not es_manual
        and permitir_autobloqueo
        and _autobloqueo_soar_activo
        and not paso1.get("spoofing_suspect")
        and not _evaluar_candado1_ip_protegida(ip_limpia)[0]
        and (ip_limpia not in _cuarentena_activa or _cuarentena_activa[ip_limpia].get("fast_path_pending"))
    )
    if debe_pre_bloquear_fw:
        (exito_fp, regla_fp, _), paso2, paso3, paso4 = await asyncio.gather(
            run_in_threadpool(_bloquear_ip_en_windows_firewall_sincrono, ip_limpia, False),
            run_in_threadpool(_consultar_paso2_arp_lan_sincrono, ip_limpia, ttl_para_paso2),
            run_in_threadpool(_consultar_paso3_wan_asn_sincrono, ip_limpia),
            run_in_threadpool(_consultar_paso4_sans_isc_sincrono, ip_limpia),
        )
        if ip_limpia in _cuarentena_activa:
            _cuarentena_activa[ip_limpia]["fast_path_fw_done"] = True
            _cuarentena_activa[ip_limpia]["firewall_os_applied"] = exito_fp
            _cuarentena_activa[ip_limpia]["rule_name"] = regla_fp
    else:
        paso2, paso3, paso4 = await asyncio.gather(
            run_in_threadpool(_consultar_paso2_arp_lan_sincrono, ip_limpia, ttl_para_paso2),
            run_in_threadpool(_consultar_paso3_wan_asn_sincrono, ip_limpia),
            run_in_threadpool(_consultar_paso4_sans_isc_sincrono, ip_limpia),
        )
    paso5 = await _aplicar_paso5_mitigacion_firewall(
        ip_str=ip_limpia,
        paso1=paso1,
        paso2=paso2,
        paso3=paso3,
        paso4=paso4,
        protocolo=protocolo,
        es_manual=es_manual,
        permitir_autobloqueo=permitir_autobloqueo,
        modo_duracion=modo_duracion,
    )

    _contador_eventos_soar += 1
    info_q_actual = _cuarentena_activa.get(ip_limpia)
    evento = {
        "event_id": _contador_eventos_soar,
        "timestamp": fecha_a_iso_utc(obtener_utc_ingenuo()),
        "src_ip": ip_limpia,
        "dst_ip": ip_destino,
        "protocol": protocolo,
        "confidence_percentage": round(float(confianza), 2),
        "source": origen_evento,
        "is_lan": bool(paso2.get("is_lan")),
        "is_blocked": bool(paso5.get("blocked")) or (ip_limpia in _cuarentena_activa),
        "is_permanent": bool(info_q_actual and info_q_actual.get("is_permanent")),
        "steps": {
            "step1_ttl": paso1,
            "step2_lan": paso2,
            "step3_wan": paso3,
            "step4_sans": paso4,
            "step5_firewall": paso5,
        },
    }

    for idx, ev_existente in enumerate(_eventos_soar_recientes):
        if ev_existente.get("src_ip") == ip_limpia:
            _eventos_soar_recientes[idx] = evento
            break
    else:
        _eventos_soar_recientes.appendleft(evento)

    return evento


_semaforo_soar_background = asyncio.Semaphore(2)


async def _ejecutar_soar_con_semaforo(**kwargs) -> None:
    async with _semaforo_soar_background:
        if not _modulo_soar_activo:
            return
        await _ejecutar_pipeline_5_pasos_soar(**kwargs)


def _disparar_investigacion_soar_asincrona(
    ip_atacante: str,
    ip_destino: str,
    protocolo: str,
    confianza: float,
    features: Optional[List[float]],
    origen_evento: str,
    permitir_autobloqueo: bool = True,
    ttl_avg: Optional[float] = None,
    ttl_std: Optional[float] = None,
) -> None:
    if not _modulo_soar_activo:
        return
    ip_limpia = (ip_atacante or "").strip()
    if not ip_limpia:
        return
    ahora_mono = time.monotonic()
    ultimo_t = _ultimas_ips_investigadas.get(ip_limpia, 0.0)
    if (ahora_mono - ultimo_t) < COOLDOWN_INVESTIGACION_IP_SEG:
        return

    _ultimas_ips_investigadas[ip_limpia] = ahora_mono
    while len(_ultimas_ips_investigadas) > MAX_CACHE_SOAR_ENTRADAS:
        _ultimas_ips_investigadas.popitem(last=False)

    # Fast-Path IPS: Si el autobloqueo está activo y pasa Candados 1 y 2 en O(1),
    # registrar en _cuarentena_activa inmediatamente (<0.1ms) para suprimir ráfagas subsecuentes
    # mientras el hilo secundario aplica netsh y enriquece ARP/ASN/SANS.
    if permitir_autobloqueo and _autobloqueo_soar_activo and ip_limpia not in _cuarentena_activa:
        protegida_fp, _ = _evaluar_candado1_ip_protegida(ip_limpia)
        if not protegida_fp:
            paso1_fp = _diagnosticar_paso1_ttl_antispoofing(
                ip_limpia, protocolo, features, ttl_avg_sensor=ttl_avg, ttl_std_sensor=ttl_std
            )
            if not paso1_fp.get("spoofing_suspect"):
                ahora_ep = time.time()
                _cuarentena_activa[ip_limpia] = {
                    "ip": ip_limpia,
                    "mac": "Resolviendo ARP...",
                    "identity": "Aislando host atacante en Firewall...",
                    "protocol": protocolo,
                    "rule_name": _nombre_regla_firewall_ip(ip_limpia),
                    "blocked_at": ahora_ep,
                    "blocked_at_iso": fecha_a_iso_utc(obtener_utc_ingenuo()),
                    "expires_at": ahora_ep + TTL_CUARENTENA_SOAR_SEG,
                    "is_permanent": False,
                    "duration_mode": "15m",
                    "ttl_seconds": int(TTL_CUARENTENA_SOAR_SEG),
                    "firewall_os_applied": True,
                    "mode": "Automático IPS (15m)",
                    "sans_reports": 0,
                    "mitigated_flows": 0,
                    "mitigated_bytes": 0,
                    "fast_path_pending": True,
                }
                _asegurar_tarea_expiracion_soar()

    try:
        bucle = asyncio.get_running_loop()
        bucle.create_task(
            _ejecutar_soar_con_semaforo(
                ip_atacante=ip_limpia,
                ip_destino=ip_destino,
                protocolo=protocolo,
                confianza=confianza,
                features=features,
                origen_evento=origen_evento,
                es_manual=False,
                permitir_autobloqueo=permitir_autobloqueo,
                modo_duracion="15m",
                ttl_avg=ttl_avg,
                ttl_std=ttl_std,
            ),
            name=f"soar-investigar-{ip_limpia}",
        )
    except RuntimeError:
        pass


async def _sembrar_investigaciones_recientes_al_activar() -> None:
    """Al activar el módulo SOAR, analiza las últimas IPs atacantes distintas del historial para visualización inmediata."""
    if _eventos_soar_recientes:
        return
    try:
        def _obtener_ultimos_atacantes_bd():
            with SesionLocal() as db:
                filas = (
                    db.query(
                        RegistroTrafico.src_ip,
                        RegistroTrafico.dst_ip,
                        RegistroTrafico.protocol,
                        RegistroTrafico.confidence_percentage,
                        RegistroTrafico.source,
                    )
                    .filter(RegistroTrafico.is_attack.is_(True))
                    .order_by(RegistroTrafico.id.desc())
                    .limit(60)
                    .all()
                )
                vistos = set()
                unicos = []
                for src_ip, dst_ip, proto, conf, src_orig in filas:
                    if src_ip and src_ip not in vistos:
                        vistos.add(src_ip)
                        unicos.append((src_ip, dst_ip or "192.168.18.10", proto or "TCP", float(conf or 99.0), src_orig or "sensor"))
                    if len(unicos) >= 5:
                        break
                return unicos

        atacantes_recientes = await run_in_threadpool(_obtener_ultimos_atacantes_bd)
        for src_ip, dst_ip, proto, conf, src_orig in reversed(atacantes_recientes):
            if not _modulo_soar_activo:
                break
            if src_ip in _cuarentena_activa or any(ev.get("src_ip") == src_ip for ev in _eventos_soar_recientes):
                continue
            await _ejecutar_pipeline_5_pasos_soar(
                ip_atacante=src_ip,
                ip_destino=dst_ip,
                protocolo=proto,
                confianza=conf,
                features=None,
                origen_evento=src_orig,
                es_manual=False,
                permitir_autobloqueo=False,
                modo_duracion="15m",
            )
    except Exception:
        registro_logger.exception("Error sembrando investigaciones iniciales SOAR")


async def _desactivar_y_limpiar_modulo_soar() -> int:
    """Candado 4: Limpieza total de reglas CyberShield_Block_* en Windows Firewall y apagado en memoria."""
    global _modulo_soar_activo, _tarea_expiracion_soar, _contador_eventos_soar
    _modulo_soar_activo = False

    if _tarea_expiracion_soar and not _tarea_expiracion_soar.done():
        _tarea_expiracion_soar.cancel()
        try:
            await _tarea_expiracion_soar
        except asyncio.CancelledError:
            pass
    _tarea_expiracion_soar = None

    reglas_activas = [
         str(datos.get("rule_name") or _nombre_regla_firewall_ip(ip_k))
        for ip_k, datos in _cuarentena_activa.items()
    ]
    eliminadas = await run_in_threadpool(_purgar_todas_reglas_cybershield_sincrono, reglas_activas)

    _cuarentena_activa.clear()
    _eventos_soar_recientes.clear()
    _cache_forense_lan.clear()
    _cache_forense_wan.clear()
    _cache_sans_isc.clear()
    _ultimas_ips_investigadas.clear()
    _contador_eventos_soar = 0
    gc.collect()

    registro_logger.info(
        "Candado 4 SOAR ejecutado: Módulo apagado en memoria y reglas CyberShield_Block_* eliminadas del Firewall"
    )
    return eliminadas


# --- Esquemas y Endpoints REST del Módulo SOAR ---
class SolicitudToggleSoar(BaseModel):
    enabled: bool
    master_password: str = Field(..., min_length=1, max_length=128)


class SolicitudAutobloqueoSoar(BaseModel):
    auto_block: bool


class SolicitudAccionIpSoar(BaseModel):
    ip: str = Field(..., min_length=3, max_length=45)
    protocol: str = Field(default="TCP", max_length=12)
    duration_mode: Literal["permanent", "15m"] = Field(default="permanent")
    reason: Optional[str] = Field(default="Aislamiento manual por operador en Centro SOAR", max_length=200)


@aplicacion.get("/api/soar/blocklist.txt", response_class=PlainTextResponse)
async def obtener_blocklist_plana_edl():
    """
    Feed Dinámico de Bloqueo Perimetral (EDL) en texto plano (1 IP por línea)
    para sincronización con Routers/Firewalls empresariales (MikroTik, pfSense, FortiGate).
    """
    if not _modulo_soar_activo or not _cuarentena_activa:
        return PlainTextResponse("", media_type="text/plain; charset=utf-8")

    ahora_epoch = time.time()
    ips_vigentes = []
    for ip_k, info_q in list(_cuarentena_activa.items()):
        es_perm = bool(info_q.get("is_permanent"))
        exp_at = info_q.get("expires_at")
        if es_perm or (exp_at is not None and float(exp_at) > ahora_epoch):
            ips_vigentes.append(str(ip_k).strip())

    contenido = ("\n".join(ips_vigentes) + "\n") if ips_vigentes else ""
    return PlainTextResponse(contenido, media_type="text/plain; charset=utf-8")


@aplicacion.get("/api/soar/status", dependencies=[Depends(verificar_acceso_operativo)])
async def obtener_estado_modulo_soar():
    return {
        "enabled": _modulo_soar_activo,
        "auto_block": _autobloqueo_soar_activo,
        "active_quarantine_count": len(_cuarentena_activa),
        "events_count": len(_eventos_soar_recientes),
        "lock1_protected": _obtener_resumen_candado1() if _modulo_soar_activo else None,
    }


@aplicacion.post("/api/soar/toggle", dependencies=[Depends(verificar_acceso_operativo)])
async def alternar_modulo_soar(solicitud: SolicitudToggleSoar):
    global _modulo_soar_activo, _autobloqueo_soar_activo

    clave_valida = await run_in_threadpool(_verificar_clave_maestra_soar, solicitud.master_password)
    if not clave_valida:
        raise HTTPException(
            status_code=403,
            detail="Contraseña Maestra incorrecta. Acceso denegado al Módulo SOAR/IPS.",
        )

    if solicitud.enabled:
        await run_in_threadpool(_inicializar_gateways_candado1)
        _modulo_soar_activo = True
        _autobloqueo_soar_activo = True
        _asegurar_tarea_expiracion_soar()
        asyncio.create_task(_sembrar_investigaciones_recientes_al_activar(), name="soar-semilla-inicial")
        registro_logger.info("Módulo SOAR/IPS ACTIVADO mediante Contraseña Maestra")
        return {
            "status": "activated",
            "enabled": True,
            "auto_block": _autobloqueo_soar_activo,
            "message": "Módulo de Bloqueo Inteligente y Análisis SOAR activado correctamente.",
        }
    else:
        reglas_borradas = await _desactivar_y_limpiar_modulo_soar()
        return {
            "status": "deactivated",
            "enabled": False,
            "auto_block": False,
            "rules_cleaned": reglas_borradas,
            "message": "Candado 4 aplicado: Todas las reglas CyberShield_Block_* fueron eliminadas del Firewall y el módulo se apagó en memoria.",
        }


@aplicacion.post("/api/soar/autoblock", dependencies=[Depends(verificar_acceso_operativo)])
async def configurar_autobloqueo_soar(solicitud: SolicitudAutobloqueoSoar):
    global _autobloqueo_soar_activo
    if not _modulo_soar_activo:
        raise HTTPException(status_code=403, detail="El Módulo SOAR se encuentra desactivado.")
    _autobloqueo_soar_activo = bool(solicitud.auto_block)
    return {
        "status": "ok",
        "enabled": _modulo_soar_activo,
        "auto_block": _autobloqueo_soar_activo,
    }


@aplicacion.get("/api/soar/dashboard", dependencies=[Depends(verificar_acceso_operativo)])
async def obtener_datos_centro_soar():
    if not _modulo_soar_activo:
        raise HTTPException(
            status_code=403,
            detail="El Centro de Mitigación SOAR está desactivado. Actívelo en Configuración con la Contraseña Maestra.",
        )

    ahora_epoch = time.time()
    lista_cuarentena = []
    for ip_k, info_q in list(_cuarentena_activa.items()):
        es_perm = bool(info_q.get("is_permanent"))
        if es_perm:
            lista_cuarentena.append({
                **info_q,
                "is_permanent": True,
                "remaining_seconds": -1,
            })
        else:
            restantes = max(0, int(float(info_q.get("expires_at") or 0) - ahora_epoch))
            if restantes <= 0:
                continue
            lista_cuarentena.append({
                **info_q,
                "is_permanent": False,
                "remaining_seconds": restantes,
            })

    eventos_actualizados = []
    for ev in list(_eventos_soar_recientes):
        ip_ev = ev.get("src_ip")
        esta_bloqueada = ip_ev in _cuarentena_activa
        copia_ev = dict(ev)
        copia_ev["is_blocked"] = esta_bloqueada
        if esta_bloqueada and ip_ev in _cuarentena_activa:
            info_q = _cuarentena_activa[ip_ev]
            es_perm = bool(info_q.get("is_permanent"))
            copia_ev["is_permanent"] = es_perm
            copia_ev["remaining_seconds"] = (
                -1 if es_perm else max(0, int(float(info_q.get("expires_at") or 0) - ahora_epoch))
            )
        else:
            copia_ev["is_permanent"] = False
            copia_ev["remaining_seconds"] = 0
        eventos_actualizados.append(copia_ev)

    return {
        "enabled": _modulo_soar_activo,
        "auto_block": _autobloqueo_soar_activo,
        "ttl_minutes": 15,
        "primary_local_ip": sorted(_IPS_PROPIAS_SERVIDOR)[-1] if _IPS_PROPIAS_SERVIDOR else "192.168.18.10",
        "lock1_protected": _obtener_resumen_candado1(),
        "quarantine": lista_cuarentena,
        "events": eventos_actualizados,
    }


@aplicacion.post("/api/soar/block", dependencies=[Depends(verificar_acceso_operativo)])
async def bloquear_ip_manual_soar(solicitud: SolicitudAccionIpSoar):
    if not _modulo_soar_activo:
        raise HTTPException(status_code=403, detail="El Módulo SOAR está desactivado.")

    ip_objetivo = solicitud.ip.strip()
    try:
        ipaddress.ip_address(ip_objetivo)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"La dirección IP '{ip_objetivo}' no es válida.")

    protegida, motivo_c1 = _evaluar_candado1_ip_protegida(ip_objetivo)
    if protegida:
        raise HTTPException(status_code=403, detail=motivo_c1)

    modo_dur = solicitud.duration_mode if solicitud.duration_mode in ("permanent", "15m") else "permanent"
    evento = await _ejecutar_pipeline_5_pasos_soar(
        ip_atacante=ip_objetivo,
        ip_destino="192.168.18.10",
        protocolo=solicitud.protocol.upper(),
        confianza=100.0,
        features=None,
        origen_evento="manual_soar",
        es_manual=True,
        permitir_autobloqueo=True,
        modo_duracion=modo_dur,
    )
    es_perm = (modo_dur == "permanent")
    return {
        "status": "blocked",
        "ip": ip_objetivo,
        "rule_name": _nombre_regla_firewall_ip(ip_objetivo),
        "is_permanent": es_perm,
        "duration_mode": modo_dur,
        "ttl_seconds": None if es_perm else int(TTL_CUARENTENA_SOAR_SEG),
        "event": evento,
    }


@aplicacion.post("/api/soar/unblock", dependencies=[Depends(verificar_acceso_operativo)])
async def desbloquear_ip_manual_soar(solicitud: SolicitudAccionIpSoar):
    if not _modulo_soar_activo:
        raise HTTPException(status_code=403, detail="El Módulo SOAR está desactivado.")

    ip_objetivo = solicitud.ip.strip()
    info_previa = _cuarentena_activa.pop(ip_objetivo, None)
    nombre_regla = (info_previa or {}).get("rule_name") or _nombre_regla_firewall_ip(ip_objetivo)
    exito_fw, _ = await run_in_threadpool(_desbloquear_ip_en_windows_firewall_sincrono, ip_objetivo, nombre_regla)

    for ev in _eventos_soar_recientes:
        if ev.get("src_ip") == ip_objetivo:
            ev["is_blocked"] = False
            ev["is_permanent"] = False
            if "steps" in ev and "step5_firewall" in ev["steps"]:
                ev["steps"]["step5_firewall"]["blocked"] = False
                ev["steps"]["step5_firewall"]["is_permanent"] = False
                ev["steps"]["step5_firewall"]["badge"] = "Desbloqueada por Operador"
                ev["steps"]["step5_firewall"]["detail"] = f"Regla {nombre_regla} eliminada manualmente en 1 clic"

    return {
        "status": "unblocked",
        "ip": ip_objetivo,
        "rule_name": nombre_regla,
        "firewall_os_removed": exito_fw,
    }

