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
    from scapy.all import ICMP, IP, TCP, UDP, Ether, PcapReader, conf as scapy_conf, get_working_ifaces, sniff
    TIENE_SCAPY = True
except ImportError:  # pragma: no cover
    TIENE_SCAPY = False

# --- 0. Configuración y Carga de Variables de Entorno ---
def _limpiar_valor_env(valor_crudo: str) -> str:
    valor = valor_crudo.strip()
    if not valor:
        return ""
    if valor[0] in ("'", '"'):
        comilla = valor[0]
        idx_cierre = valor.find(comilla, 1)
        if idx_cierre != -1:
            return valor[1:idx_cierre].strip()
        return valor[1:].strip()
    if "#" in valor:
        valor = valor.split("#", 1)[0].strip()
    return valor


_directorio_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_archivo_env = os.path.join(_directorio_base, ".env")
if os.path.exists(_archivo_env):
    try:
        with open(_archivo_env, encoding="utf-8") as _manejador_env:
            for _linea in _manejador_env:
                _linea = _linea.strip()
                if _linea and not _linea.startswith("#") and "=" in _linea:
                    _clave, _valor = _linea.split("=", 1)
                    _clave_limpia = _clave.strip()
                    if _clave_limpia:
                        os.environ.setdefault(_clave_limpia, _limpiar_valor_env(_valor))
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
BYTES_CABECERA_UDP = 8

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

    offset_ip = None
    eth_type = None
    if longitud_trama >= 34:
        eth_type = struct.unpack_from("!H", trama, 12)[0]
        if eth_type == 0x0800:
            cand_ver_ihl = trama[14]
            cand_ihl = (cand_ver_ihl & 0x0F) * 4
            if (cand_ver_ihl >> 4) == 4 and cand_ihl >= 20 and longitud_trama >= 14 + cand_ihl:
                cand_total = struct.unpack_from("!H", trama, 16)[0]
                if cand_total == 0 or cand_total >= cand_ihl:
                    offset_ip = 14
        elif eth_type == 0x8100 and longitud_trama >= 38:
            vlan_eth_type = struct.unpack_from("!H", trama, 16)[0]
            if vlan_eth_type == 0x0800:
                cand_ver_ihl = trama[18]
                cand_ihl = (cand_ver_ihl & 0x0F) * 4
                if (cand_ver_ihl >> 4) == 4 and cand_ihl >= 20 and longitud_trama >= 18 + cand_ihl:
                    cand_total = struct.unpack_from("!H", trama, 20)[0]
                    if cand_total == 0 or cand_total >= cand_ihl:
                        offset_ip = 18

    if offset_ip is None:
        if eth_type in (0x0806, 0x86DD, 0x88CC, 0x8100, 0x88A8, 0x8863, 0x8864):
            return None
        raw_ver_ihl = trama[0]
        raw_ihl = (raw_ver_ihl & 0x0F) * 4
        if (raw_ver_ihl >> 4) == 4 and raw_ihl >= 20 and longitud_trama >= raw_ihl:
            raw_total = struct.unpack_from("!H", trama, 2)[0]
            if (raw_total == 0 or raw_total >= raw_ihl) and trama[9] in (1, 6, 17):
                offset_ip = 0

    if offset_ip is None or longitud_trama < offset_ip + 20:
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
            6, "TCP", longitud_datos, banderas_tcp, cabecera_tcp, ventana_tcp, int(_ttl)
        )

    if proto == 17:
        if longitud_trama < offset_l4 + 8:
            return None
        puerto_origen, puerto_destino, udp_len = struct.unpack_from("!HHH", trama, offset_l4)
        longitud_datos = max(0, (udp_len - 8) if udp_len >= 8 else (ip_total_len - ihl_bytes - 8))
        return (
            marca_tiempo, ip_origen, puerto_origen, ip_destino, puerto_destino,
            17, "UDP", longitud_datos, 0, BYTES_CABECERA_UDP, -1, int(_ttl)
        )

    if proto == 1:
        if longitud_trama < offset_l4 + 8:
            return None
        longitud_datos = max(0, ip_total_len - ihl_bytes - 8)
        return (
            marca_tiempo, ip_origen, 0, ip_destino, 0,
            1, "ICMP", longitud_datos, 0, 8, -1, int(_ttl)
        )

    return None


def _es_ipv4_privada_rfc1918(ip_str: str) -> bool:
    if not ip_str:
        return False
    if ip_str.startswith(("192.168.", "10.")):
        return True
    if ip_str.startswith("172."):
        partes = ip_str.split(".")
        if len(partes) == 4 and partes[1].isdigit():
            return 16 <= int(partes[1]) <= 31
    return False


def _detectar_red_host_principal():
    ip_host = (os.getenv("LOCAL_HOST_IP") or "").strip()
    if not ip_host:
        for destino_prueba in (("8.8.8.8", 80), ("1.1.1.1", 80)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(destino_prueba)
                    candidata = sock.getsockname()[0]
                    if candidata and not candidata.startswith(("127.", "169.254.")):
                        ip_host = candidata
                        break
            except Exception:
                pass

    if not ip_host:
        try:
            for candidata in socket.gethostbyname_ex(socket.gethostname())[2]:
                if candidata and not candidata.startswith(("127.", "169.254.")):
                    ip_host = candidata
                    break
        except Exception:
            pass

    interfaz_env = (os.getenv("SNIFF_IFACE") or "").strip()
    interfaz_elegida = interfaz_env or None
    etiqueta_interfaz = interfaz_env or "Predeterminada"

    if TIENE_SCAPY:
        try:
            palabras_virtuales = (
                "virtual", "hyper-v", "vethernet", "vmware", "vbox",
                "loopback", "wi-fi direct", "wan miniport", "teredo", "bluetooth"
            )
            interfaces_activas = list(get_working_ifaces())

            if not ip_host:
                for iface in interfaces_activas:
                    ip_if = getattr(iface, "ip", "") or ""
                    desc_if = f"{getattr(iface, 'name', '')} {getattr(iface, 'description', '')}".lower()
                    if _es_ipv4_privada_rfc1918(ip_if) and not any(v in desc_if for v in palabras_virtuales):
                        ip_host = ip_if
                        break

            if not interfaz_elegida:
                mejor_iface = None
                if ip_host:
                    for iface in interfaces_activas:
                        if (getattr(iface, "ip", "") or "") == ip_host:
                            mejor_iface = iface
                            break
                if mejor_iface is None:
                    for iface in interfaces_activas:
                        ip_if = getattr(iface, "ip", "") or ""
                        desc_if = f"{getattr(iface, 'name', '')} {getattr(iface, 'description', '')}".lower()
                        if _es_ipv4_privada_rfc1918(ip_if) and not any(v in desc_if for v in palabras_virtuales):
                            mejor_iface = iface
                            break
                if mejor_iface is not None:
                    interfaz_elegida = getattr(mejor_iface, "name", None) or mejor_iface
                    ip_mostrar = getattr(mejor_iface, "ip", "") or ip_host or "sin-ip"
                    desc_mostrar = getattr(mejor_iface, "description", "") or str(interfaz_elegida)
                    etiqueta_interfaz = f"{interfaz_elegida} ({ip_mostrar} - {desc_mostrar})"
                    if not ip_host and ip_mostrar != "sin-ip":
                        ip_host = ip_mostrar
        except Exception:
            pass

    if not ip_host:
        ip_host = "127.0.0.1"

    ips_propias = {"127.0.0.1"}
    if ip_host:
        ips_propias.add(ip_host)
    return ip_host, ips_propias, interfaz_elegida, etiqueta_interfaz


IP_LOCAL_HOST, IPS_PROPIAS_PC, INTERFAZ_CAPTURA, ETIQUETA_INTERFAZ_CAPTURA = _detectar_red_host_principal()


def _es_ip_local_privada(ip_str: str) -> bool:
    if not ip_str:
        return False
    return ip_str in IPS_PROPIAS_PC


def _es_puerto_multimedia_o_web_udp(puerto: int) -> bool:
    return (
        puerto in (53, 80, 443, 3478, 3479)
        or (8801 <= puerto <= 8810)
        or (19300 <= puerto <= 19309)
    )


def _clave_canonica_conexion(ip_a: str, puerto_a: int, ip_b: str, puerto_b: int, proto: int) -> tuple:
    extremo_a = (ip_a, puerto_a)
    extremo_b = (ip_b, puerto_b)
    if extremo_a <= extremo_b:
        return (ip_a, puerto_a, ip_b, puerto_b, proto)
    return (ip_b, puerto_b, ip_a, puerto_a, proto)


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
        "tiempos_inactivos", "cerrado_por_bandera", "anclado_midstream",
        "sesion_local_confirmada", "ttls_ida", "ttls_vuelta",
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
        self.anclado_midstream = False
        self.sesion_local_confirmada = False
        self.ttls_ida, self.ttls_vuelta = [], []

    def invertir_direccion(self) -> None:
        self.ip_origen, self.ip_destino = self.ip_destino, self.ip_origen
        self.puerto_origen, self.puerto_destino = self.puerto_destino, self.puerto_origen
        self.clave = (self.ip_origen, self.puerto_origen, self.ip_destino, self.puerto_destino, self.protocolo)
        self.longitudes_ida, self.longitudes_vuelta = self.longitudes_vuelta, self.longitudes_ida
        self.ttls_ida, self.ttls_vuelta = self.ttls_vuelta, self.ttls_ida
        self.iat_ida, self.iat_vuelta = self.iat_vuelta, self.iat_ida
        self.ultimo_tiempo_ida, self.ultimo_tiempo_vuelta = self.ultimo_tiempo_vuelta, self.ultimo_tiempo_ida
        self.psh_ida, self.psh_vuelta = self.psh_vuelta, self.psh_ida
        self.urg_ida, self.urg_vuelta = self.urg_vuelta, self.urg_ida
        self.longitud_cabecera_ida, self.longitud_cabecera_vuelta = self.longitud_cabecera_vuelta, self.longitud_cabecera_ida
        self.ventana_inicial_ida, self.ventana_inicial_vuelta = self.ventana_inicial_vuelta, self.ventana_inicial_ida
        if self.protocolo == 6:
            self.paquetes_datos_ida = sum(1 for x in self.longitudes_ida if x > 0)
            self.segmento_minimo_ida = (
                max(20, int(self.longitud_cabecera_ida // len(self.longitudes_ida)))
                if self.longitudes_ida
                else None
            )
        elif self.protocolo == 17:
            self.paquetes_datos_ida = sum(1 for x in self.longitudes_ida if x > 0)
            self.segmento_minimo_ida = BYTES_CABECERA_UDP if self.longitudes_ida else None
        else:
            self.paquetes_datos_ida = 0
            self.segmento_minimo_ida = None
        self.anclado_midstream = False

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
        ttl_ip: int = 64,
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
            self.fin_activo = max(self.fin_activo, marca_tiempo)

        self.tiempo_ultimo = max(self.tiempo_ultimo, marca_tiempo)
        if self.longitud_primer_paquete is None:
            self.longitud_primer_paquete = longitud_datos

        if es_ida:
            if self.ultimo_tiempo_ida is not None and len(self.iat_ida) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.iat_ida.append(max(marca_tiempo - self.ultimo_tiempo_ida, 0.0) * 1e6)
            self.ultimo_tiempo_ida = marca_tiempo
            if len(self.longitudes_ida) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.longitudes_ida.append(longitud_datos)
            if ttl_ip > 0 and len(self.ttls_ida) < 64:
                self.ttls_ida.append(int(ttl_ip))
        else:
            if self.ultimo_tiempo_vuelta is not None and len(self.iat_vuelta) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.iat_vuelta.append(max(marca_tiempo - self.ultimo_tiempo_vuelta, 0.0) * 1e6)
            self.ultimo_tiempo_vuelta = marca_tiempo
            if len(self.longitudes_vuelta) < MAXIMO_MUESTRAS_POR_FLUJO:
                self.longitudes_vuelta.append(longitud_datos)
            if ttl_ip > 0 and len(self.ttls_vuelta) < 64:
                self.ttls_vuelta.append(int(ttl_ip))

        if proto == 6:
            if es_ida:
                self.longitud_cabecera_ida += cabecera_l4
                self.segmento_minimo_ida = cabecera_l4 if self.segmento_minimo_ida is None else min(self.segmento_minimo_ida, cabecera_l4)
                if self.ventana_inicial_ida == -1 and ventana_tcp >= 0:
                    self.ventana_inicial_ida = ventana_tcp
                if longitud_datos > 0:
                    self.paquetes_datos_ida += 1
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
                    self.banderas_tcp["FIN"] += 1
                if banderas_tcp & 0x02:
                    self.banderas_tcp["SYN"] += 1
                if banderas_tcp & 0x04:
                    self.banderas_tcp["RST"] += 1
                if banderas_tcp & 0x08:
                    self.banderas_tcp["PSH"] += 1
                if banderas_tcp & 0x10:
                    self.banderas_tcp["ACK"] += 1
                if banderas_tcp & 0x20:
                    self.banderas_tcp["URG"] += 1
                if banderas_tcp & 0x40:
                    self.banderas_tcp["ECE"] += 1
                if banderas_tcp & 0x80:
                    self.banderas_tcp["CWR"] += 1
                if banderas_tcp & 0x05:
                    self.cerrado_por_bandera = True

        elif proto == 17:
            if es_ida:
                self.longitud_cabecera_ida += BYTES_CABECERA_UDP
                self.segmento_minimo_ida = BYTES_CABECERA_UDP
                if longitud_datos > 0:
                    self.paquetes_datos_ida += 1
            else:
                self.longitud_cabecera_vuelta += BYTES_CABECERA_UDP

    def actualizar(self, paquete, marca_tiempo: float, es_ida: bool) -> None:
        longitud_datos = _obtener_longitud_datos_utiles(paquete)
        ttl_pkt = int(getattr(paquete[IP], "ttl", 64) or 64) if paquete.haslayer(IP) else 64
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
                ttl_pkt,
            )
        elif paquete.haslayer(UDP):
            self.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, 17, 0, BYTES_CABECERA_UDP, -1, ttl_pkt
            )
        else:
            proto = int(getattr(paquete[IP], "proto", 0)) if paquete.haslayer(IP) else 0
            self.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, proto, 0, 0, -1, ttl_pkt
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
        muestras_ttl = self.ttls_ida if self.ttls_ida else self.ttls_vuelta
        if muestras_ttl:
            ttl_promedio = round(sum(muestras_ttl) / len(muestras_ttl), 1)
            if len(muestras_ttl) > 1:
                media_t = sum(muestras_ttl) / len(muestras_ttl)
                var_t = sum((t - media_t) ** 2 for t in muestras_ttl) / (len(muestras_ttl) - 1)
                ttl_std = round(math.sqrt(max(0.0, var_t)), 2)
            else:
                ttl_std = 0.0
        else:
            ttl_promedio = 64.0
            ttl_std = 0.0

        return {
            "features": self.hacia_vector(),
            "src_ip": str(self.ip_origen),
            "dst_ip": str(self.ip_destino),
            "protocol": self.nombre_protocolo,
            "duration_ms": round(max(self.tiempo_ultimo - self.tiempo_inicio, 0.0) * 1000, 2),
            "total_bytes": int(sum(self.longitudes_ida) + sum(self.longitudes_vuelta)),
            "exported_at": tiempo_exportacion,
            "ttl_avg": ttl_promedio,
            "ttl_std": ttl_std,
            "sesion_local_confirmada": bool(self.sesion_local_confirmada),
        }

    to_record = hacia_registro


# --- 2. Tabla de Gestión de Flujos (LRU) ---
class TablaFlujos:
    MAXIMO_EXTRACCION_POR_CICLO = 10000
    MAXIMO_DIRECCIONES_PINNING = 8192
    TTL_SESION_ACTIVA_SEGUNDOS = 300.0

    def __init__(self) -> None:
        self.flujos: "OrderedDict[tuple, EstadisticasFlujo]" = OrderedDict()
        self.sesiones_activas: "OrderedDict[tuple, dict]" = OrderedDict()
        self.direcciones_conexion = self.sesiones_activas
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
        ttl_ip: int = 64,
    ) -> None:
        clave_ida = (ip_origen, puerto_origen, ip_destino, puerto_destino, proto)
        clave_retorno = (ip_destino, puerto_destino, ip_origen, puerto_origen, proto)
        clave_canonica = _clave_canonica_conexion(ip_origen, puerto_origen, ip_destino, puerto_destino, proto)

        es_origen_local = _es_ip_local_privada(ip_origen)
        es_destino_local = _es_ip_local_privada(ip_destino)
        es_nuevo_syn_puro = (proto == 6 and (banderas_tcp & 0x12) == 0x02)
        es_rst_puro = (proto == 6 and (banderas_tcp & 0x04) != 0 and longitud_datos == 0)

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
                self._exportar_flujo(clave_elegida, cierre_definitivo=False)
                flujo = None

            if flujo is None:
                if len(self.flujos) >= MAXIMO_FLUJOS_ACTIVOS:
                    victima = self._seleccionar_victima_desalojo(marca_tiempo)
                    self._exportar_flujo(victima, cierre_definitivo=False)
                    self.contadores["desalojados"] += 1

                sesion = self.sesiones_activas.get(clave_canonica)
                ttl_sesion = (
                    self.TTL_SESION_ACTIVA_SEGUNDOS
                    if (sesion is not None and sesion.get("sesion_local_confirmada"))
                    else (TIEMPO_INACTIVIDAD_SEGUNDOS * 3.0)
                )
                if (
                    sesion is not None
                    and (marca_tiempo - sesion["ultimo_visto"]) <= ttl_sesion
                    and not es_nuevo_syn_puro
                ):
                    if es_origen_local and not es_destino_local and not es_rst_puro and not _es_ip_local_privada(sesion["clave_direccion"][0]):
                        sesion["clave_direccion"] = clave_ida
                    clave_elegida = sesion["clave_direccion"]
                    es_ida = (clave_ida == clave_elegida)
                    es_midstream = bool(sesion["es_midstream"]) and not bool(sesion["sesion_local_confirmada"])
                    sesion["ultimo_visto"] = max(sesion["ultimo_visto"], marca_tiempo)
                    self.sesiones_activas.move_to_end(clave_canonica)
                else:
                    anclar_local_midstream = (
                        not es_origen_local
                        and es_destino_local
                        and (
                            (proto == 6 and (banderas_tcp & 0x12) != 0x02 and (banderas_tcp & 0x04) == 0)
                            or (proto == 17 and _es_puerto_multimedia_o_web_udp(puerto_origen) and puerto_destino >= 1024)
                        )
                    )
                    if anclar_local_midstream:
                        clave_elegida = clave_retorno
                        es_ida = False
                        es_midstream = True
                    else:
                        clave_elegida = clave_ida
                        es_ida = True
                        es_midstream = False

                    self.sesiones_activas[clave_canonica] = {
                        "clave_direccion": clave_elegida,
                        "ultimo_visto": marca_tiempo,
                        "es_midstream": es_midstream,
                        "pkts_locales_historicos": 0,
                        "sesion_local_confirmada": False,
                    }
                    self.sesiones_activas.move_to_end(clave_canonica)
                    while len(self.sesiones_activas) > self.MAXIMO_DIRECCIONES_PINNING:
                        self.sesiones_activas.popitem(last=False)

                sesion_actual = self.sesiones_activas.get(clave_canonica)
                flujo = EstadisticasFlujo(
                    clave_elegida,
                    marca_tiempo,
                    clave_elegida[0],
                    clave_elegida[1],
                    clave_elegida[2],
                    clave_elegida[3],
                    proto,
                    nombre_protocolo,
                )
                flujo.anclado_midstream = es_midstream
                flujo.sesion_local_confirmada = bool(sesion_actual and sesion_actual["sesion_local_confirmada"])
                self.flujos[clave_elegida] = flujo

            flujo.actualizar_campos_rapidos(
                marca_tiempo, es_ida, longitud_datos, proto, banderas_tcp, cabecera_l4, ventana_tcp, ttl_ip
            )
            self.flujos.move_to_end(clave_elegida)

            sesion_actual = self.sesiones_activas.get(clave_canonica)
            if sesion_actual is not None:
                sesion_actual["ultimo_visto"] = max(sesion_actual["ultimo_visto"], marca_tiempo)
                if es_origen_local and not es_destino_local and not es_rst_puro:
                    sesion_actual["pkts_locales_historicos"] += 1
                    sesion_actual["sesion_local_confirmada"] = True
                    sesion_actual["es_midstream"] = False
                if (
                    len(flujo.longitudes_ida) > 0
                    and len(flujo.longitudes_vuelta) > 0
                    and (proto != 6 or (banderas_tcp & 0x04) == 0)
                ):
                    sesion_actual["es_midstream"] = False
                    if _es_ip_local_privada(flujo.ip_origen) and not _es_ip_local_privada(flujo.ip_destino):
                        sesion_actual["sesion_local_confirmada"] = True
                if sesion_actual["sesion_local_confirmada"]:
                    flujo.sesion_local_confirmada = True
                    flujo.anclado_midstream = False
                self.sesiones_activas.move_to_end(clave_canonica)

            limite_paquetes = PAQUETES_CORTE_TEMPRANO if PAQUETES_CORTE_TEMPRANO > 0 else MAXIMO_MUESTRAS_POR_FLUJO
            if flujo.cerrado_por_bandera:
                self._exportar_flujo(clave_elegida, cierre_definitivo=True)
            elif flujo.total_paquetes >= limite_paquetes:
                self._exportar_flujo(clave_elegida, cierre_definitivo=False)

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
            int(getattr(ip, "ttl", 64) or 64),
        )

    process = procesar_paquete

    def _exportar_flujo(self, clave, cierre_definitivo: bool = False) -> None:
        flujo = self.flujos.pop(clave, None)
        if flujo is not None:
            clave_canonica = _clave_canonica_conexion(
                flujo.ip_origen, flujo.puerto_origen, flujo.ip_destino, flujo.puerto_destino, flujo.protocolo
            )
            sesion = self.sesiones_activas.get(clave_canonica)
            sesion_confirmada = bool(
                flujo.sesion_local_confirmada
                or (sesion is not None and sesion.get("sesion_local_confirmada"))
            )
            if (
                not sesion_confirmada
                and flujo.anclado_midstream
                and (
                    len(flujo.longitudes_ida) == 0
                    or (flujo.banderas_tcp["RST"] >= 1 and flujo.paquetes_datos_ida == 0)
                )
            ):
                flujo.invertir_direccion()
                if sesion is not None:
                    sesion["clave_direccion"] = flujo.clave
                    sesion["es_midstream"] = False

            if cierre_definitivo and not sesion_confirmada:
                self.sesiones_activas.pop(clave_canonica, None)

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
                self._exportar_flujo(clave, cierre_definitivo=True)

            if forzar_todos:
                self.sesiones_activas.clear()
            else:
                ttl_no_confirmada = TIEMPO_INACTIVIDAD_SEGUNDOS * 3.0
                ttl_minimo = min(self.TTL_SESION_ACTIVA_SEGUNDOS, ttl_no_confirmada)
                claves_a_expirar = []
                for clave_ses, sesion in self.sesiones_activas.items():
                    edad = tiempo_actual - sesion["ultimo_visto"]
                    if edad <= ttl_minimo:
                        break
                    ttl_sesion = (
                        self.TTL_SESION_ACTIVA_SEGUNDOS
                        if sesion.get("sesion_local_confirmada")
                        else ttl_no_confirmada
                    )
                    if edad > ttl_sesion and sesion["clave_direccion"] not in self.flujos:
                        claves_a_expirar.append(clave_ses)
                for clave_ses in claves_a_expirar:
                    self.sesiones_activas.pop(clave_ses, None)

    expire = expirar_inactivos

    def extraer_registros(self, max_extraccion: int = MAXIMO_EXTRACCION_POR_CICLO) -> list:
        flujos_listos = []
        with self.bloqueo:
            while self.cola_listos and (max_extraccion <= 0 or len(flujos_listos) < max_extraccion):
                flujos_listos.append(self.cola_listos.popleft())

        tiempo_actual = time.time()
        for flujo in flujos_listos:
            if flujo.total_paquetes > 100:
                registro_logger.info(
                    "[FLUJO >100 PAQ] %s:%d -> %s:%d (%s) | Paquetes=%d (Ida=%d, Vuelta=%d) | Bytes=%d | Duración=%.2fms",
                    flujo.ip_origen,
                    flujo.puerto_origen,
                    flujo.ip_destino,
                    flujo.puerto_destino,
                    flujo.nombre_protocolo,
                    flujo.total_paquetes,
                    len(flujo.longitudes_ida),
                    len(flujo.longitudes_vuelta),
                    sum(flujo.longitudes_ida) + sum(flujo.longitudes_vuelta),
                    max(flujo.tiempo_ultimo - flujo.tiempo_inicio, 0.0) * 1000.0,
                )
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
        self._evento_parada = threading.Event()

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
        limite = time.monotonic() + max(0.1, float(tiempo_espera))
        self._evento_parada.set()
        encolado = False
        try:
            self.cola_envio.put(None, timeout=min(1.0, max(0.05, limite - time.monotonic())))
            encolado = True
        except queue.Full:
            try:
                descartado = self.cola_envio.get_nowait()
                self.cola_envio.task_done()
                if isinstance(descartado, list):
                    with self._bloqueo_estadisticas:
                        self.estadisticas["descartados"] += len(descartado)
            except queue.Empty:
                pass
            try:
                self.cola_envio.put_nowait(None)
                encolado = True
            except queue.Full:
                pass

        restante = max(0.05, limite - time.monotonic())
        if self.is_alive():
            self.join(timeout=restante)
        if not self.is_alive():
            try:
                self.sesion.close()
            except Exception:
                pass
        elif not encolado:
            registro_logger.warning("DespachadorApi no pudo encolar señal de cierre dentro de %.2fs", tiempo_espera)

    stop = detener

    def run(self) -> None:
        max_intentos = 4
        while True:
            lote = self.cola_envio.get()
            try:
                if lote is None:
                    break
                for intento in range(max_intentos):
                    try:
                        respuesta = self.sesion.post(self.url_destino, json={"records": lote}, timeout=(3.05, 15))
                        if respuesta.status_code == 200:
                            try:
                                datos_respuesta = respuesta.json()
                            except ValueError as exc_json:
                                registro_logger.error("Respuesta HTTP 200 con JSON inválido: %s", exc_json)
                                with self._bloqueo_estadisticas:
                                    self.estadisticas["errores"] += 1
                                break
                            if not isinstance(datos_respuesta, dict):
                                registro_logger.error(
                                    "Respuesta HTTP 200 con estructura no-dict (%s); lote ignorado",
                                    type(datos_respuesta).__name__,
                                )
                                with self._bloqueo_estadisticas:
                                    self.estadisticas["errores"] += 1
                                break
                            procesados = int(datos_respuesta.get("processed", len(lote)))
                            ataques = int(datos_respuesta.get("ddos", 0))
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
                        registro_logger.warning(
                            "Error transitorio de API (Código %d, intento %d/%d): %s",
                            respuesta.status_code,
                            intento + 1,
                            max_intentos,
                            respuesta.text[:200],
                        )
                        with self._bloqueo_estadisticas:
                            self.estadisticas["errores"] += 1
                    except requests.RequestException as excepcion:
                        registro_logger.warning(
                            "Servidor API no disponible (intento %d/%d): %s",
                            intento + 1,
                            max_intentos,
                            excepcion,
                        )
                        with self._bloqueo_estadisticas:
                            self.estadisticas["errores"] += 1
                    if intento < max_intentos - 1:
                        if self._evento_parada.wait(0.5 * (2 ** intento)):
                            with self._bloqueo_estadisticas:
                                self.estadisticas["descartados"] += len(lote)
                            break
                else:
                    with self._bloqueo_estadisticas:
                        self.estadisticas["descartados"] += len(lote)
            except Exception as exc_inesperada:
                registro_logger.exception("Error inesperado en DespachadorApi: %s", exc_inesperada)
                with self._bloqueo_estadisticas:
                    self.estadisticas["errores"] += 1
                    if isinstance(lote, list):
                        self.estadisticas["descartados"] += len(lote)
            finally:
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
    registro_logger.info(
        "Sensor NIDS activado | Interfaz: %s | IP Host Local: %s | Filtro BPF: '%s' | Snaplen: %dB | Destino: %s",
        ETIQUETA_INTERFAZ_CAPTURA, IP_LOCAL_HOST, filtro_bpf, SNAPLEN_CAPTURA, URL_LOTE_API
    )
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
