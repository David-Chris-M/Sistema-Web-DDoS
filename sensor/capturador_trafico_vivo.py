import argparse
import csv
import logging
import math
import os
import queue
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict, deque
from urllib.parse import urlparse

import numpy as np
import requests

try:
    from scapy.all import ICMP, IP, TCP, UDP, Ether, PcapReader, conf as scapy_conf, sniff
    TIENE_SCAPY = True
except ImportError:  # pragma: no cover
    TIENE_SCAPY = False

# --- 0. Configuración y Carga de Variables de Entorno ---
_directorio_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_archivo_env = os.path.join(_directorio_base, ".env")
if os.path.exists(_archivo_env):
    try:
        with open(_archivo_env, encoding="utf-8") as _manejador_env:
            for _linea in _manejador_env:
                _linea = _linea.strip()
                if _linea and not _linea.startswith("#") and "=" in _linea:
                    _clave, _valor = _linea.split("=", 1)
                    os.environ.setdefault(_clave.strip(), _valor.strip())
    except Exception:
        pass

URL_LOTE_API = os.getenv("API_BATCH_URL", "http://127.0.0.1:8000/api/predict/batch")
CLAVE_API_SENSOR = os.getenv("SENSOR_API_KEY", "").strip()
INTERFAZ_CAPTURA = os.getenv("SNIFF_IFACE") or None

TIEMPO_INACTIVIDAD_SEGUNDOS = float(os.getenv("FLOW_IDLE_TIMEOUT", "2.0"))
TIEMPO_VENTANA_ACTIVA_SEGUNDOS = float(os.getenv("FLOW_ACTIVE_TIMEOUT", "2.0"))
UMBRAL_ACTIVIDAD_MICROSEGUNDOS = 5_000_000
PAQUETES_CORTE_TEMPRANO = int(os.getenv("EARLY_EXPORT_PACKETS", "400"))
MAXIMO_MUESTRAS_POR_FLUJO = int(os.getenv("MAX_SAMPLES_PER_FLOW", "4096"))
MAXIMO_FLUJOS_ACTIVOS = int(os.getenv("MAX_ACTIVE_FLOWS", "50000"))
MAXIMO_COLA_LISTOS = int(os.getenv("MAX_READY_FLOWS", str(MAXIMO_FLUJOS_ACTIVOS * 2)))
INTERVALO_VACIADO_SEGUNDOS = float(os.getenv("FLUSH_INTERVAL", "0.3"))
TAMANO_MAXIMO_LOTE = int(os.getenv("MAX_BATCH", "500"))
SNAPLEN_CAPTURA = int(os.getenv("CAPTURE_SNAPLEN", "96"))
BYTES_CABECERA_UDP = 20

registro_logger = logging.getLogger("cybershield.sensor")


# --- Utilidades de Extracción y Decodificación de Paquetes ---
def _sanitizar_escalar_finito(valor: float) -> float:
    v = float(valor)
    if math.isfinite(v):
        return v
    if math.isnan(v):
        return 0.0
    return 1e12 if v > 0 else -1e12


def _calcular_estadisticas_vector(valores):
    n = len(valores)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    if n == 1:
        v = _sanitizar_escalar_finito(valores[0])
        return v, v, v, 0.0
    if n <= 256:
        limpios = [_sanitizar_escalar_finito(x) for x in valores]
        vmax = max(limpios)
        vmin = min(limpios)
        media = sum(limpios) / n
        varianza = sum((x - media) ** 2 for x in limpios) / (n - 1)
        desviacion_std = math.sqrt(varianza) if math.isfinite(varianza) and varianza > 0.0 else 0.0
        if not math.isfinite(desviacion_std):
            desviacion_std = 0.0
        return float(vmax), float(vmin), float(media), float(desviacion_std)

    arreglo = np.nan_to_num(np.asarray(valores, dtype=np.float64), nan=0.0, posinf=1e12, neginf=-1e12)
    desviacion_std = float(arreglo.std(ddof=1)) if arreglo.size > 1 else 0.0
    if not math.isfinite(desviacion_std):
        desviacion_std = 0.0
    return float(arreglo.max()), float(arreglo.min()), float(arreglo.mean()), desviacion_std


def _obtener_longitud_datos_utiles(paquete) -> int:
    ip = paquete[IP]
    ip_len = getattr(ip, "len", None)
    ihl_bytes = int(getattr(ip, "ihl", None) or 5) * 4

    if paquete.haslayer(TCP):
        tcp = paquete[TCP]
        cabecera_l4 = int(getattr(tcp, "dataofs", None) or 5) * 4
        if ip_len is not None and ip_len >= ihl_bytes + cabecera_l4:
            return int(ip_len) - ihl_bytes - cabecera_l4
        return len(tcp.payload)

    if paquete.haslayer(UDP):
        udp = paquete[UDP]
        udp_len = getattr(udp, "len", None)
        if udp_len is not None and udp_len >= 8:
            return int(udp_len) - 8
        if ip_len is not None and ip_len >= ihl_bytes + 8:
            return int(ip_len) - ihl_bytes - 8
        return len(udp.payload)

    if paquete.haslayer(ICMP):
        if ip_len is not None and ip_len >= ihl_bytes + 8:
            return int(ip_len) - ihl_bytes - 8
        return len(paquete[ICMP].payload)

    if ip_len is not None and ip_len >= ihl_bytes:
        return int(ip_len) - ihl_bytes
    return len(ip.payload)


def _parsear_trama_binaria_rapida(trama: bytes, marca_tiempo: float):
    longitud_trama = len(trama)
    if longitud_trama < 20:
        return None

    offset_ip = 0
    primer_nibble = trama[0] >> 4
    if primer_nibble != 4:
        if longitud_trama < 34:
            return None
        eth_type = struct.unpack_from("!H", trama, 12)[0]
        offset_ip = 14
        if eth_type == 0x8100:
            if longitud_trama < 38:
                return None
            eth_type = struct.unpack_from("!H", trama, 16)[0]
            offset_ip = 18
        if eth_type != 0x0800:
            return None

    if longitud_trama < offset_ip + 20:
        return None

    ver_ihl, _tos, ip_total_len, _id, _frag, _ttl, proto, _csum, src_raw, dst_raw = struct.unpack_from(
        "!BBHHHBBH4s4s", trama, offset_ip
    )
    if (ver_ihl >> 4) != 4:
        return None

    ihl_bytes = (ver_ihl & 0x0F) * 4
    if ihl_bytes < 20 or longitud_trama < offset_ip + ihl_bytes:
        return None

    if ip_total_len < ihl_bytes:
        ip_total_len = longitud_trama - offset_ip

    ip_origen = socket.inet_ntoa(src_raw)
    ip_destino = socket.inet_ntoa(dst_raw)
    offset_l4 = offset_ip + ihl_bytes

    if proto == 6:
        if longitud_trama < offset_l4 + 20:
            return None
        puerto_origen, puerto_destino, _seq, _ack, dataofs_res, banderas_tcp, ventana_tcp = struct.unpack_from(
            "!HHIIBBH", trama, offset_l4
        )
        cabecera_tcp = ((dataofs_res >> 4) & 0x0F) * 4
        if cabecera_tcp < 20:
            cabecera_tcp = 20
        longitud_datos = max(0, ip_total_len - ihl_bytes - cabecera_tcp)
        return (
            marca_tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino,
            6, "TCP", longitud_datos, banderas_tcp, cabecera_tcp, ventana_tcp
        )

    if proto == 17:
        if longitud_trama < offset_l4 + 8:
            return None
        puerto_origen, puerto_destino, udp_len = struct.unpack_from("!HHH", trama, offset_l4)
        longitud_datos = max(0, (udp_len - 8) if udp_len >= 8 else (ip_total_len - ihl_bytes - 8))
        return (
            marca_tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino,
            17, "UDP", longitud_datos, 0, BYTES_CABECERA_UDP, -1
        )

    if proto == 1:
        longitud_datos = max(0, ip_total_len - ihl_bytes - 8)
        return (
            marca_tiempo, ip_origen, 0, ip_destino, 0,
            1, "ICMP", longitud_datos, 0, 8, -1
        )

    return None


# --- 1. Acumulador de Estadísticas del Flujo (5-Tupla) ---
class EstadisticasFlujo:
    __slots__ = (
        "clave", "ip_origen", "ip_destino", "puerto_origen", "puerto_destino", "protocolo",
        "nombre_protocolo", "tiempo_inicio", "tiempo_ultimo", "longitud_primer_paquete",
        "longitudes_ida", "longitudes_vuelta", "iat_flujo", "iat_ida", "iat_vuelta",
        "ultimo_tiempo_ida", "ultimo_tiempo_vuelta", "banderas_tcp", "psh_ida", "psh_vuelta",
        "urg_ida", "urg_vuelta", "longitud_cabecera_ida", "longitud_cabecera_vuelta",
        "ventana_inicial_ida", "ventana_inicial_vuelta", "paquetes_datos_ida",
        "segmento_minimo_ida", "inicio_activo", "fin_activo", "tiempos_activos",
        "tiempos_inactivos", "cerrado_por_bandera"
    )

    def __init__(self, clave, marca_tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino, protocolo, nombre_protocolo):
        self.clave = clave
        self.ip_origen, self.puerto_origen = ip_origen, puerto_origen
        self.ip_destino, self.puerto_destino = ip_destino, puerto_destino
        self.protocolo, self.nombre_protocolo = protocolo, nombre_protocolo
        self.tiempo_inicio = self.tiempo_ultimo = marca_tiempo
        self.longitud_primer_paquete = None
        self.longitudes_ida, self.longitudes_vuelta = [], []
        self.iat_flujo, self.iat_ida, self.iat_vuelta = [], [], []
        self.ultimo_tiempo_ida = self.ultimo_tiempo_vuelta = None
        self.banderas_tcp = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0}
        self.psh_ida = self.psh_vuelta = self.urg_ida = self.urg_vuelta = 0
        self.longitud_cabecera_ida = self.longitud_cabecera_vuelta = 0
        self.ventana_inicial_ida = self.ventana_inicial_vuelta = -1
        self.paquetes_datos_ida = 0
        self.segmento_minimo_ida = None
        self.inicio_activo = self.fin_activo = marca_tiempo
        self.tiempos_activos, self.tiempos_inactivos = [], []
        self.cerrado_por_bandera = False

    @property
    def total_paquetes(self) -> int:
        return len(self.longitudes_ida) + len(self.longitudes_vuelta)

    packets = total_paquetes

    def actualizar_campos_rapidos(
        self,
        marca_tiempo: float,
        es_ida: bool,
        longitud_datos: int,
        proto: int,
        banderas_tcp: int,
        cabecera_l4: int,
        ventana_tcp: int,
    ) -> None:
        if self.total_paquetes > 0 and len(self.iat_flujo) < MAXIMO_MUESTRAS_POR_FLUJO:
            self.iat_flujo.append(max(marca_tiempo - self.tiempo_ultimo, 0.0) * 1e6)

        intervalo_inactividad_us = (marca_tiempo - self.fin_activo) * 1e6
        if intervalo_inactividad_us > UMBRAL_ACTIVIDAD_MICROSEGUNDOS:
            if self.fin_activo > self.inicio_activo and len(self.tiempos_activos) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.tiempos_activos.append((self.fin_activo - self.inicio_activo) * 1e6)
            if len(self.tiempos_inactivos) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.tiempos_inactivos.append(intervalo_inactividad_us)
            self.inicio_activo = self.fin_activo = marca_tiempo
        else:
            self.fin_activo = marca_tiempo

        self.tiempo_ultimo = marca_tiempo
        if self.longitud_primer_paquete is None:
            self.longitud_primer_paquete = longitud_datos

        if es_ida:
            if self.ultimo_tiempo_ida is not None and len(self.iat_ida) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.iat_ida.append(max(marca_tiempo - self.ultimo_tiempo_ida, 0.0) * 1e6)
            self.ultimo_tiempo_ida = marca_tiempo
            if len(self.longitudes_ida) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.longitudes_ida.append(longitud_datos)
        else:
            if self.ultimo_tiempo_vuelta is not None and len(self.iat_vuelta) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.iat_vuelta.append(max(marca_tiempo - self.ultimo_tiempo_vuelta, 0.0) * 1e6)
            self.ultimo_tiempo_vuelta = marca_tiempo
            if len(self.longitudes_vuelta) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.longitudes_vuelta.append(longitud_datos)

        if proto == 6:
            if es_ida:
                self.longitud_cabecera_ida += cabecera_l4
                self.segmento_minimo_ida = cabecera_l4 if self.segmento_minimo_ida is None else min(self.segmento_minimo_ida, cabecera_l4)
                if self.ventana_inicial_ida == -1 and ventana_tcp >= 0:
                    self.ventana_inicial_ida = ventana_tcp
                if longitud_datos > 0:
                    self.paquetes_datos_ida += 1
                if len(self.longitudes_ida) == 1:
                    self.psh_ida |= bool(banderas_tcp & 0x08)
                self.urg_ida |= bool(banderas_tcp & 0x20)
            else:
                self.longitud_cabecera_vuelta += cabecera_l4
                if self.ventana_inicial_vuelta == -1 and ventana_tcp >= 0:
                    self.ventana_inicial_vuelta = ventana_tcp
                self.psh_vuelta |= bool(banderas_tcp & 0x08)
                self.urg_vuelta |= bool(banderas_tcp & 0x20)

            if banderas_tcp:
                if banderas_tcp & 0x01:
                    self.banderas_tcp["FIN"] = 1
                if banderas_tcp & 0x02:
                    self.banderas_tcp["SYN"] = 1
                if banderas_tcp & 0x04:
                    self.banderas_tcp["RST"] = 1
                if banderas_tcp & 0x08:
                    self.banderas_tcp["PSH"] = 1
                if banderas_tcp & 0x10:
                    self.banderas_tcp["ACK"] = 1
                if banderas_tcp & 0x20:
                    self.banderas_tcp["URG"] = 1
                if banderas_tcp & 0x40:
                    self.banderas_tcp["ECE"] = 1
                if banderas_tcp & 0x80:
                    self.banderas_tcp["CWR"] = 1
                if banderas_tcp & 0x05:
                    self.cerrado_por_bandera = True

        elif proto == 17:
            if es_ida:
                self.longitud_cabecera_ida += BYTES_CABECERA_UDP
                self.segmento_minimo_ida = BYTES_CABECERA_UDP
            else:
                self.longitud_cabecera_vuelta += BYTES_CABECERA_UDP

    def actualizar(self, paquete, marca_tiempo: float, es_ida: bool) -> None:
        longitud_datos = _obtener_longitud_datos_utiles(paquete)
        if paquete.haslayer(TCP):
            tcp = paquete[TCP]
            self.actualizar_campos_rapidos(
                marca_tiempo,
                es_ida,
                longitud_datos,
                6,
                int(tcp.flags),
                int(tcp.dataofs or 5) * 4,
                int(tcp.window),
            )
        elif paquete.haslayer(UDP):
            self.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, 17, 0, BYTES_CABECERA_UDP, -1
            )
        else:
            proto = int(getattr(paquete[IP], "proto", 0)) if paquete.haslayer(IP) else 0
            self.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, proto, 0, 0, -1
            )

    update = actualizar

    def hacia_vector(self) -> list:
        tiempos_activos = list(self.tiempos_activos)
        if self.tiempos_inactivos and self.fin_activo > self.inicio_activo:
            tiempos_activos.append((self.fin_activo - self.inicio_activo) * 1e6)

        conteo_ida, conteo_vuelta = len(self.longitudes_ida), len(self.longitudes_vuelta)
        total_p = conteo_ida + conteo_vuelta
        bytes_ida, bytes_vuelta = float(sum(self.longitudes_ida)), float(sum(self.longitudes_vuelta))
        duracion_us = max(self.tiempo_ultimo - self.tiempo_inicio, 0.0) * 1e6
        duracion_seg = (max(duracion_us, 1.0) / 1e6) if duracion_us > 0 else 0.0
        tasa = (lambda x: x / duracion_seg) if duracion_seg > 0 else (lambda x: 0.0)

        fmax, fmin, fmean, fstd = _calcular_estadisticas_vector(self.longitudes_ida)
        bmax, bmin, bmean, bstd = _calcular_estadisticas_vector(self.longitudes_vuelta)

        lista_longitudes = self.longitudes_ida + self.longitudes_vuelta
        pmax, pmin, pmean, pstd = _calcular_estadisticas_vector(lista_longitudes)
        iat = _calcular_estadisticas_vector(self.iat_flujo)
        fi = _calcular_estadisticas_vector(self.iat_ida)
        bi = _calcular_estadisticas_vector(self.iat_vuelta)
        act = _calcular_estadisticas_vector(tiempos_activos)
        idl = _calcular_estadisticas_vector(self.tiempos_inactivos)
        fl = self.banderas_tcp

        vector_crudo = [
            float(self.puerto_origen), float(self.puerto_destino), float(self.protocolo), duracion_us,
            float(conteo_ida), float(conteo_vuelta), bytes_ida, bytes_vuelta,
            fmax, fmin, fmean, fstd, bmax, bmin, bmean, bstd,
            tasa(bytes_ida + bytes_vuelta), tasa(float(total_p)),
            iat[2], iat[3], iat[0], iat[1],
            float(sum(self.iat_ida)), fi[2], fi[3], fi[0], fi[1],
            float(sum(self.iat_vuelta)), bi[2], bi[3], bi[0], bi[1],
            float(self.psh_ida), float(self.psh_vuelta), float(self.urg_ida), float(self.urg_vuelta),
            float(self.longitud_cabecera_ida), float(self.longitud_cabecera_vuelta), tasa(float(conteo_ida)), tasa(float(conteo_vuelta)),
            pmin, pmax, pmean, pstd, min(pstd ** 2, 1e12),
            float(fl["FIN"]), float(fl["SYN"]), float(fl["RST"]), float(fl["PSH"]),
            float(fl["ACK"]), float(fl["URG"]), float(fl["CWR"]), float(fl["ECE"]),
            float(math.floor(conteo_vuelta / conteo_ida)) if conteo_ida else 0.0,
            (bytes_ida + bytes_vuelta) / total_p if total_p else 0.0, fmean, bmean,
            float(self.longitud_cabecera_ida),
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            float(conteo_ida), bytes_ida, float(conteo_vuelta), bytes_vuelta,
            float(self.ventana_inicial_ida), float(self.ventana_inicial_vuelta), float(self.paquetes_datos_ida),
            float(self.segmento_minimo_ida or 0),
            act[2], act[3], act[0], act[1], idl[2], idl[3], idl[0], idl[1],
        ]
        return [
            max(-1e12, min(1e12, float(v))) if math.isfinite(v) else 0.0
            for v in vector_crudo
        ]

    to_vector = hacia_vector

    def hacia_registro(self, tiempo_exportacion: float) -> dict:
        return {
            "features": self.hacia_vector(),
            "src_ip": str(self.ip_origen),
            "dst_ip": str(self.ip_destino),
            "protocol": self.nombre_protocolo,
            "duration_ms": round(max(self.tiempo_ultimo - self.tiempo_inicio, 0.0) * 1000, 2),
            "total_bytes": int(sum(self.longitudes_ida) + sum(self.longitudes_vuelta)),
            "exported_at": tiempo_exportacion,
        }

    to_record = hacia_registro


# --- 2. Tabla de Gestión de Flujos (LRU) ---
class TablaFlujos:
    MAXIMO_EXTRACCION_POR_CICLO = 10000

    def __init__(self) -> None:
        self.flujos: "OrderedDict[tuple, EstadisticasFlujo]" = OrderedDict()
        self.bloqueo = threading.Lock()
        self.cola_listos: deque = deque(maxlen=MAXIMO_COLA_LISTOS)
        self.contadores = {"paquetes": 0, "exportados": 0, "desalojados": 0, "descartados_memoria": 0}

    def _seleccionar_victima_desalojo(self, marca_tiempo: float):
        primera_clave = None
        for idx, (clave_cand, flujo_cand) in enumerate(self.flujos.items()):
            if idx == 0:
                primera_clave = clave_cand
            if (marca_tiempo - flujo_cand.tiempo_ultimo) > TIEMPO_INACTIVIDAD_SEGUNDOS or flujo_cand.total_paquetes <= 1:
                return clave_cand
            if idx >= 7:
                break
        return primera_clave

    def _ingestar_campos_flujo(
        self,
        marca_tiempo: float,
        ip_origen: str,
        puerto_origen: int,
        ip_destino: str,
        puerto_destino: int,
        proto: int,
        nombre_protocolo: str,
        longitud_datos: int,
        banderas_tcp: int,
        cabecera_l4: int,
        ventana_tcp: int,
    ) -> None:
        clave_ida = (ip_origen, puerto_origen, ip_destino, puerto_destino, proto)
        clave_retorno = (ip_destino, puerto_destino, ip_origen, puerto_origen, proto)

        with self.bloqueo:
            self.contadores["paquetes"] += 1
            if clave_ida in self.flujos:
                clave_elegida, es_ida = clave_ida, True
            elif clave_retorno in self.flujos:
                clave_elegida, es_ida = clave_retorno, False
            else:
                clave_elegida, es_ida = None, True

            flujo = self.flujos.get(clave_elegida) if clave_elegida else None

            if flujo is not None and (marca_tiempo - flujo.tiempo_inicio) > TIEMPO_VENTANA_ACTIVA_SEGUNDOS:
                self._exportar_flujo(clave_elegida)
                flujo, es_ida = None, True

            if flujo is None:
                if len(self.flujos) >= MAXIMO_FLUJOS_ACTIVOS:
                    victima = self._seleccionar_victima_desalojo(marca_tiempo)
                    self._exportar_flujo(victima)
                    self.contadores["desalojados"] += 1

                clave_elegida = clave_ida
                flujo = EstadisticasFlujo(
                    clave_elegida, marca_tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino, proto, nombre_protocolo
                )
                self.flujos[clave_elegida] = flujo

            flujo.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, proto, banderas_tcp, cabecera_l4, ventana_tcp
            )
            self.flujos.move_to_end(clave_elegida)

            limite_paquetes = PAQUETES_CORTE_TEMPRANO if PAQUETES_CORTE_TEMPRANO > 0 else MAXIMO_MUESTRAS_POR_FLUJO
            if flujo.cerrado_por_bandera or flujo.total_paquetes >= limite_paquetes:
                self._exportar_flujo(clave_elegida)

    def procesar_trama_cruda(self, trama: bytes, marca_tiempo: float = None) -> None:
        campos = _parsear_trama_binaria_rapida(trama, time.time() if marca_tiempo is None else float(marca_tiempo))
        if campos is not None:
            self._ingestar_campos_flujo(*campos)

    def procesar_paquete(self, paquete, marca_tiempo_explicita: float = None) -> None:
        if isinstance(paquete, (bytes, bytearray, memoryview)):
            self.procesar_trama_cruda(paquete, marca_tiempo_explicita)
            return

        if not paquete.haslayer(IP):
            return

        marca_tiempo = float(paquete.time) if marca_tiempo_explicita is None else float(marca_tiempo_explicita)
        ip = paquete[IP]
        longitud_datos = _obtener_longitud_datos_utiles(paquete)

        if paquete.haslayer(TCP):
            tcp = paquete[TCP]
            puerto_origen, puerto_destino, nombre_protocolo = int(tcp.sport), int(tcp.dport), "TCP"
            banderas_tcp = int(tcp.flags)
            cabecera_l4 = int(tcp.dataofs or 5) * 4
            ventana_tcp = int(tcp.window)
        elif paquete.haslayer(UDP):
            udp = paquete[UDP]
            puerto_origen, puerto_destino, nombre_protocolo = int(udp.sport), int(udp.dport), "UDP"
            banderas_tcp, cabecera_l4, ventana_tcp = 0, BYTES_CABECERA_UDP, -1
        else:
            puerto_origen, puerto_destino = 0, 0
            nombre_protocolo = "ICMP" if paquete.haslayer(ICMP) else "OTHER"
            banderas_tcp, cabecera_l4, ventana_tcp = 0, 0, -1

        self._ingestar_campos_flujo(
            marca_tiempo,
            ip.src,
            puerto_origen,
            ip.dst,
            puerto_destino,
            int(ip.proto),
            nombre_protocolo,
            longitud_datos,
            banderas_tcp,
            cabecera_l4,
            ventana_tcp,
        )

    process = procesar_paquete

    def _exportar_flujo(self, clave) -> None:
        flujo = self.flujos.pop(clave, None)
        if flujo is not None:
            if self.cola_listos.maxlen and len(self.cola_listos) >= self.cola_listos.maxlen:
                self.contadores["descartados_memoria"] += 1
            self.cola_listos.append(flujo)
            self.contadores["exportados"] += 1

    def expirar_inactivos(self, tiempo_actual: float, forzar_todos: bool = False) -> None:
        with self.bloqueo:
            while self.flujos:
                clave, flujo = next(iter(self.flujos.items()))
                if not forzar_todos and (tiempo_actual - flujo.tiempo_ultimo) <= TIEMPO_INACTIVIDAD_SEGUNDOS:
                    break
                self._exportar_flujo(clave)

    expire = expirar_inactivos

    def extraer_registros(self, max_extraccion: int = MAXIMO_EXTRACCION_POR_CICLO) -> list:
        flujos_listos = []
        with self.bloqueo:
            while self.cola_listos and (max_extraccion <= 0 or len(flujos_listos) < max_extraccion):
                flujos_listos.append(self.cola_listos.popleft())

        tiempo_actual = time.time()
        return [flujo.hacia_registro(tiempo_actual) for flujo in flujos_listos]

    drain_records = extraer_registros


# --- 3. Despachador Asíncrono de Telemetría ---
class DespachadorApi(threading.Thread):
    def __init__(self, url_destino: str, clave_api: str) -> None:
        super().__init__(daemon=True, name="despachador-api-sensor")
        self.url_destino = url_destino
        self.cola_envio: queue.Queue = queue.Queue(maxsize=200)
        self.sesion = requests.Session()
        if clave_api:
            self.sesion.headers["X-API-Key"] = clave_api
        self.estadisticas = {"enviados": 0, "ddos": 0, "descartados": 0, "errores": 0}
        self._bloqueo_estadisticas = threading.Lock()

    def encolar_lote(self, registros: list) -> None:
        for i in range(0, len(registros), TAMANO_MAXIMO_LOTE):
            sub_lote = registros[i:i + TAMANO_MAXIMO_LOTE]
            try:
                self.cola_envio.put_nowait(sub_lote)
            except queue.Full:
                with self._bloqueo_estadisticas:
                    self.estadisticas["descartados"] += len(sub_lote)
                registro_logger.warning("Cola de despacho llena: %d flujos descartados por congestión", len(sub_lote))

    submit = encolar_lote

    def detener(self, tiempo_espera: float = 10.0) -> None:
        self.cola_envio.put(None)
        self.cola_envio.join()
        self.join(timeout=tiempo_espera)

    stop = detener

    def run(self) -> None:
        while True:
            lote = self.cola_envio.get()
            if lote is None:
                self.cola_envio.task_done()
                break
            for intento in range(4):
                try:
                    respuesta = self.sesion.post(self.url_destino, json={"records": lote}, timeout=(3.05, 15))
                    if respuesta.status_code == 200:
                        datos_respuesta = respuesta.json()
                        procesados = datos_respuesta.get("processed", len(lote))
                        ataques = datos_respuesta.get("ddos", 0)
                        with self._bloqueo_estadisticas:
                            self.estadisticas["enviados"] += procesados
                            self.estadisticas["ddos"] += ataques
                        if ataques > 0:
                            registro_logger.warning("ALERTA CRÍTICA: %d/%d flujos identificados como DDoS", ataques, procesados)
                        break
                    if 400 <= respuesta.status_code < 500 and respuesta.status_code != 429:
                        registro_logger.error("Lote rechazado por API (Código %d): %s", respuesta.status_code, respuesta.text[:300])
                        with self._bloqueo_estadisticas:
                            self.estadisticas["errores"] += 1
                        break
                except requests.RequestException as excepcion:
                    registro_logger.warning("Servidor API no disponible (intento %d/4): %s", intento + 1, excepcion)
                time.sleep(0.5 * (2 ** intento))
            else:
                with self._bloqueo_estadisticas:
                    self.estadisticas["descartados"] += len(lote)
            self.cola_envio.task_done()


# --- 4. Vaciado Periódico, Filtros BPF y Modo PCAP ---
def hilo_vaciado_periodico(tabla: TablaFlujos, despachador: DespachadorApi, evento_parada: threading.Event) -> None:
    ultimo_reporte = time.time()
    while not evento_parada.wait(INTERVALO_VACIADO_SEGUNDOS):
        tabla.expirar_inactivos(time.time())
        registros = tabla.extraer_registros()
        if registros and despachador:
            despachador.encolar_lote(registros)

        if time.time() - ultimo_reporte >= 10.0:
            ultimo_reporte = time.time()
            if despachador:
                with tabla.bloqueo:
                    paquetes = tabla.contadores["paquetes"]
                    activos = len(tabla.flujos)
                    exportados = tabla.contadores["exportados"]
                with despachador._bloqueo_estadisticas:
                    enviados = despachador.estadisticas["enviados"]
                    ddos = despachador.estadisticas["ddos"]
                registro_logger.info(
                    "Telemetría Sensor: Paquetes=%d | Flujos Activos=%d | Exportados=%d | Despachados API=%d | DDoS Detectados=%d",
                    paquetes, activos, exportados, enviados, ddos
                )


def construir_filtro_bpf_predeterminado() -> str:
    filtro_personalizado = os.getenv("BPF_FILTER", "").strip()
    if filtro_personalizado:
        return filtro_personalizado
    url_parseada = urlparse(URL_LOTE_API)
    host = (url_parseada.hostname or "127.0.0.1").strip()
    caracteres_permitidos = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:")
    if not host or any(c not in caracteres_permitidos for c in host):
        host = "127.0.0.1"
    puerto = int(url_parseada.port or (443 if url_parseada.scheme == "https" else 80))
    if not (1 <= puerto <= 65535):
        puerto = 8000
    return f"ip and not (host {host} and tcp port {puerto})"


def ejecutar_modo_desconectado(ruta_pcap: str, archivo_csv_salida: str, despachador: DespachadorApi) -> None:
    tabla = TablaFlujos()
    escritor_csv, manejador_archivo = None, None
    if archivo_csv_salida:
        manejador_archivo = open(archivo_csv_salida, "w", newline="", encoding="utf-8")
        escritor_csv = csv.writer(manejador_archivo)
        escritor_csv.writerow(["src_ip", "dst_ip", "protocol", "duration_ms", "total_bytes"] + [f"f{i}" for i in range(80)])

    def emitir(registros):
        if escritor_csv:
            for reg in registros:
                escritor_csv.writerow([reg["src_ip"], reg["dst_ip"], reg["protocol"], reg["duration_ms"], reg["total_bytes"]] + reg["features"])
        if despachador:
            despachador.encolar_lote(registros)

    reloj = 0.0
    with PcapReader(ruta_pcap) as lector_pcap:
        for i, paquete in enumerate(lector_pcap):
            tabla.procesar_paquete(paquete)
            reloj = float(paquete.time)
            if i % 5000 == 0:
                tabla.expirar_inactivos(reloj)
                emitir(tabla.extraer_registros())

    tabla.expirar_inactivos(reloj, forzar_todos=True)
    while True:
        lote_final = tabla.extraer_registros()
        if not lote_final:
            break
        emitir(lote_final)

    if manejador_archivo:
        manejador_archivo.close()
    if despachador:
        despachador.detener()
    registro_logger.info("PCAP procesado con éxito: %d paquetes analizados, %d flujos exportados", tabla.contadores["paquetes"], tabla.contadores["exportados"])


# --- 5. Punto de Entrada Principal del Sensor ---
def configurar_registro_rotativo_sensor() -> None:
    from logging.handlers import RotatingFileHandler

    formato_log = "%(asctime)s [%(levelname)s] %(message)s"
    nivel = os.getenv("LOG_LEVEL", "INFO")
    logging.basicConfig(level=nivel, format=formato_log)

    try:
        directorio_logs = os.path.join(_directorio_base, "logs")
        os.makedirs(directorio_logs, exist_ok=True)
        ruta_log_sensor = os.path.join(directorio_logs, "cybershield_sensor.log")
        max_bytes = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
        respaldos = int(os.getenv("LOG_BACKUP_COUNT", "5"))
        logger_raiz = logging.getLogger()
        tiene_rotador = any(
            isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", "") == os.path.abspath(ruta_log_sensor)
            for h in logger_raiz.handlers
        )
        if not tiene_rotador:
            manejador = RotatingFileHandler(
                ruta_log_sensor, maxBytes=max_bytes, backupCount=respaldos, encoding="utf-8"
            )
            manejador.setFormatter(logging.Formatter(formato_log))
            logger_raiz.addHandler(manejador)
    except Exception:
        pass


def principal() -> None:
    configurar_registro_rotativo_sensor()
    analizador_argumentos = argparse.ArgumentParser(description="Sensor NIDS Conv1D CyberShield (Captura y Detección)")
    analizador_argumentos.add_argument("--pcap", help="Ruta a archivo PCAP para procesar en modo desconectado")
    analizador_argumentos.add_argument("--csv-out", help="Archivo CSV donde exportar vectores calculados")
    analizador_argumentos.add_argument("--no-send", action="store_true", help="Desactivar envío HTTP a la API")
    argumentos = analizador_argumentos.parse_args()

    if not TIENE_SCAPY:
        registro_logger.critical("Scapy no está instalado en este entorno: pip install -r sensor/requirements.txt")
        sys.exit(1)

    despachador = None if argumentos.no_send else DespachadorApi(URL_LOTE_API, CLAVE_API_SENSOR)
    if despachador:
        despachador.start()

    if argumentos.pcap:
        ejecutar_modo_desconectado(argumentos.pcap, argumentos.csv_out, despachador)
        return

    if not CLAVE_API_SENSOR:
        registro_logger.warning("SENSOR_API_KEY no configurado: la API rechazará los lotes si exige autenticación")

    tabla = TablaFlujos()
    evento_parada = threading.Event()
    hilo_temporizador = threading.Thread(
        target=hilo_vaciado_periodico, args=(tabla, despachador, evento_parada), daemon=True, name="temporizador-sensor"
    )
    hilo_temporizador.start()

    filtro_bpf = construir_filtro_bpf_predeterminado()
    try:
        scapy_conf.layers.filter([Ether, IP, TCP, UDP, ICMP])
    except Exception:
        pass
    registro_logger.info("Sensor NIDS activado | Interfaz: %s | Filtro BPF: '%s' | Snaplen: %dB | Destino: %s",
                         INTERFAZ_CAPTURA or "Predeterminada", filtro_bpf, SNAPLEN_CAPTURA, URL_LOTE_API)
    registro_logger.info("Detección Temprana Activa (Ventana: %.1fs | Inactividad: %.1fs)",
                         TIEMPO_VENTANA_ACTIVA_SEGUNDOS, TIEMPO_INACTIVIDAD_SEGUNDOS)

    try:
        sniff(iface=INTERFAZ_CAPTURA, filter=filtro_bpf, prn=tabla.procesar_paquete, store=False)
    except KeyboardInterrupt:
        registro_logger.info("Interrupción por teclado detectada. Cerrando sensor...")
    finally:
        evento_parada.set()
        hilo_temporizador.join(timeout=5.0)
        tabla.expirar_inactivos(time.time(), forzar_todos=True)
        if despachador:
            while True:
                registros_finales = tabla.extraer_registros()
                if not registros_finales:
                    break
                despachador.encolar_lote(registros_finales)
            despachador.detener()
        registro_logger.info("Sensor NIDS detenido correctamente.")


if __name__ == "__main__":
    principal()
