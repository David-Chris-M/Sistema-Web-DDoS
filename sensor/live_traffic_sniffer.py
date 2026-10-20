"""CyberShield - Sensor NIDS 24/7: captura -> flujos bidireccionales -> 80 features CICFlowMeter -> API.

Correcciones de auditoría (verificadas empíricamente contra el CSV de CICIDS2017):
  * Longitudes = bytes de PAYLOAD de transporte (CICFlowMeter), no la trama completa.
  * Desviaciones estándar MUESTRALES (ddof=1) y sin IAT ficticio de 0 en el primer paquete.
  * Contadores de flags BINARIOS (0/1): en CICIDS2017 su máximo es 1; contar por paquete (p. ej. ACK=9)
    generaba valores a >15 desviaciones estándar del entrenamiento.
  * Init_Win_bytes = -1 cuando no hay segmento TCP en ese sentido (UDP siempre -1).
  * Peculiaridades de CICFlowMeter replicadas: 'Packet Length *' duplica el 1.er paquete,
    'Average Packet Size' = suma/(n), 'Down/Up Ratio' entero, Active/Idle con umbral de 5 s.
  * Ciclo de vida de flujo: FIN/RST, inactividad, timeout activo de 120 s (como CICFlowMeter).
  * Tabla LRU O(1): al llenarse se EXPORTA el flujo más antiguo (antes se borraba sin analizar,
    justo durante un SYN flood) y el cálculo de vectores ocurre fuera del hilo de captura.
  * Lotes <= 500 (límite de la API; antes un lote mayor se rechazaba completo con 422).
  * Reintentos con backoff, API key, filtro BPF que excluye el propio tráfico sensor->API.
  * Modo offline (--pcap) para validación pasiva y para re-entrenar con el MISMO extractor.

Limitación honesta: Scapy procesa del orden de miles de paquetes/s. Para enlaces con floods de
>10k pps use NFStream/CICFlowMeter (C) como extractor y conserve este contrato de 80 features.
"""
import argparse
import csv
import logging
import math
import os
import queue
import sys
import threading
import time
from collections import OrderedDict, deque
from urllib.parse import urlparse

import numpy as np
import requests

try:
    from scapy.all import ICMP, IP, TCP, UDP, PcapReader, sniff
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover
    SCAPY_AVAILABLE = False

# Cargar .env automáticamente si existe
_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_file = os.path.join(_base_dir, ".env")
if os.path.exists(_env_file):
    try:
        with open(_env_file, encoding="utf-8") as _fh:
            for _line in _fh:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())
    except Exception:
        pass

API_BATCH_URL = os.getenv("API_BATCH_URL", "http://127.0.0.1:8000/api/predict/batch")
SENSOR_API_KEY = os.getenv("SENSOR_API_KEY", "CyberShield_Pyme_SecureToken_2026")
SNIFF_IFACE = os.getenv("SNIFF_IFACE") or None
IDLE_TIMEOUT = float(os.getenv("FLOW_IDLE_TIMEOUT", "10"))          # s sin paquetes -> exportar
ACTIVE_TIMEOUT = float(os.getenv("FLOW_ACTIVE_TIMEOUT", "120"))     # s duración máx. (CICFlowMeter)
ACTIVITY_TIMEOUT_US = 5_000_000                                      # umbral Active/Idle de CICFlowMeter
EARLY_EXPORT_PACKETS = int(os.getenv("EARLY_EXPORT_PACKETS", "0"))  # 0 = fiel a CICFlowMeter
MAX_ACTIVE_FLOWS = int(os.getenv("MAX_ACTIVE_FLOWS", "20000"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "1.0"))
MAX_BATCH = int(os.getenv("MAX_BATCH", "500"))
UDP_HEADER_BYTES = 20  # valor modal que CICFlowMeter reporta para UDP en CICIDS2017 (no los 8 bytes reales)

log = logging.getLogger("cybershield.sensor")


def _stats(values):
    """(max, min, mean, std muestral) con ceros si no hay datos (convención CICFlowMeter)."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    a = np.asarray(values, dtype=np.float64)
    std = float(a.std(ddof=1)) if a.size > 1 else 0.0
    return float(a.max()), float(a.min()), float(a.mean()), std


def _payload_len(pkt) -> int:
    for layer in (TCP, UDP, ICMP):
        if pkt.haslayer(layer):
            return len(pkt[layer].payload)
    return len(pkt[IP].payload)


class FlowStats:
    __slots__ = ("key", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "proto_name", "start", "last",
                 "first_len", "fwd_len", "bwd_len", "flow_iat", "fwd_iat", "bwd_iat", "last_fwd", "last_bwd",
                 "flags", "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg", "fwd_hdr", "bwd_hdr", "init_win_fwd",
                 "init_win_bwd", "act_data_fwd", "min_seg_fwd", "start_active", "end_active", "actives",
                 "idles", "closed_by_flag")

    def __init__(self, key, ts, src_ip, src_port, dst_ip, dst_port, proto, proto_name):
        self.key = key
        self.src_ip, self.src_port, self.dst_ip, self.dst_port = src_ip, src_port, dst_ip, dst_port
        self.proto, self.proto_name = proto, proto_name
        self.start = self.last = ts
        self.first_len = None
        self.fwd_len, self.bwd_len = [], []
        self.flow_iat, self.fwd_iat, self.bwd_iat = [], [], []
        self.last_fwd = self.last_bwd = None
        self.flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0}
        self.fwd_psh = self.bwd_psh = self.fwd_urg = self.bwd_urg = 0
        self.fwd_hdr = self.bwd_hdr = 0
        self.init_win_fwd = self.init_win_bwd = -1
        self.act_data_fwd = 0
        self.min_seg_fwd = None
        self.start_active = self.end_active = ts
        self.actives, self.idles = [], []
        self.closed_by_flag = False

    @property
    def packets(self):
        return len(self.fwd_len) + len(self.bwd_len)

    def update(self, pkt, ts: float, forward: bool) -> None:
        plen = _payload_len(pkt)
        if self.packets:
            self.flow_iat.append(max(ts - self.last, 0.0) * 1e6)
        gap_us = (ts - self.end_active) * 1e6
        if gap_us > ACTIVITY_TIMEOUT_US:
            if self.end_active > self.start_active:
                self.actives.append((self.end_active - self.start_active) * 1e6)
            self.idles.append(gap_us)
            self.start_active = self.end_active = ts
        else:
            self.end_active = ts
        self.last = ts
        if self.first_len is None:
            self.first_len = plen

        if forward:
            if self.last_fwd is not None:
                self.fwd_iat.append(max(ts - self.last_fwd, 0.0) * 1e6)
            self.last_fwd = ts
            self.fwd_len.append(plen)
        else:
            if self.last_bwd is not None:
                self.bwd_iat.append(max(ts - self.last_bwd, 0.0) * 1e6)
            self.last_bwd = ts
            self.bwd_len.append(plen)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            f = int(tcp.flags)
            hdr = int(tcp.dataofs or 5) * 4
            if forward:
                self.fwd_hdr += hdr
                self.min_seg_fwd = hdr if self.min_seg_fwd is None else min(self.min_seg_fwd, hdr)
                if self.init_win_fwd == -1:
                    self.init_win_fwd = int(tcp.window)
                if plen > 0:
                    self.act_data_fwd += 1
                self.fwd_psh |= bool(f & 0x08)
                self.fwd_urg |= bool(f & 0x20)
            else:
                self.bwd_hdr += hdr
                if self.init_win_bwd == -1:
                    self.init_win_bwd = int(tcp.window)
                self.bwd_psh |= bool(f & 0x08)
                self.bwd_urg |= bool(f & 0x20)
            for bit, name in ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                              (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")):
                if f & bit:
                    self.flags[name] = 1
            if f & 0x05:  # FIN o RST: CICFlowMeter cierra el flujo
                self.closed_by_flag = True
        elif pkt.haslayer(UDP):
            if forward:
                self.fwd_hdr += UDP_HEADER_BYTES
                self.min_seg_fwd = UDP_HEADER_BYTES
            else:
                self.bwd_hdr += UDP_HEADER_BYTES

    def to_vector(self):
        """Vector de 80 características en el orden canónico de entrenamiento."""
        if self.end_active > self.start_active:
            self.actives.append((self.end_active - self.start_active) * 1e6)
        n_f, n_b = len(self.fwd_len), len(self.bwd_len)
        n = n_f + n_b
        fwd_b, bwd_b = float(sum(self.fwd_len)), float(sum(self.bwd_len))
        dur_us = max(self.last - self.start, 0.0) * 1e6
        dur_s = dur_us / 1e6
        rate = (lambda x: x / dur_s) if dur_s > 0 else (lambda x: 0.0)

        fmax, fmin, fmean, fstd = _stats(self.fwd_len)
        bmax, bmin, bmean, bstd = _stats(self.bwd_len)
        pl = ([self.first_len] if self.first_len is not None else []) + self.fwd_len + self.bwd_len
        _, _, pmean, pstd = _stats(pl)
        iat = _stats(self.flow_iat)
        fi = _stats(self.fwd_iat)
        bi = _stats(self.bwd_iat)
        act = _stats(self.actives)
        idl = _stats(self.idles)
        fl = self.flags
        return [
            float(self.src_port), float(self.dst_port), float(self.proto), dur_us,
            float(n_f), float(n_b), fwd_b, bwd_b,
            fmax, fmin, fmean, fstd, bmax, bmin, bmean, bstd,
            rate(fwd_b + bwd_b), rate(float(n)),
            iat[2], iat[3], iat[0], iat[1],
            float(sum(self.fwd_iat)), fi[2], fi[3], fi[0], fi[1],
            float(sum(self.bwd_iat)), bi[2], bi[3], bi[0], bi[1],
            float(self.fwd_psh), float(self.bwd_psh), float(self.fwd_urg), float(self.bwd_urg),
            float(self.fwd_hdr), float(self.bwd_hdr), rate(float(n_f)), rate(float(n_b)),
            fmin, max(fmax, bmax), pmean, pstd, pstd ** 2,
            float(fl["FIN"]), float(fl["SYN"]), float(fl["RST"]), float(fl["PSH"]),
            float(fl["ACK"]), float(fl["URG"]), float(fl["CWR"]), float(fl["ECE"]),
            float(math.floor(n_b / n_f)) if n_f else 0.0,
            float(sum(pl)) / n if n else 0.0, fmean, bmean,
            float(self.fwd_hdr),
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0,                       # Bulk: constantes (0) en CICIDS2017
            float(n_f), fwd_b, float(n_b), bwd_b,                # Subflow = totales (100 % en el dataset)
            float(self.init_win_fwd), float(self.init_win_bwd), float(self.act_data_fwd),
            float(self.min_seg_fwd or 0),
            act[2], act[3], act[0], act[1], idl[2], idl[3], idl[0], idl[1],
        ]

    def to_record(self, exported_at: float) -> dict:
        return {
            "features": self.to_vector(), "src_ip": str(self.src_ip), "dst_ip": str(self.dst_ip),
            "protocol": self.proto_name, "duration_ms": round(max(self.last - self.start, 0.0) * 1000, 2),
            "total_bytes": int(sum(self.fwd_len) + sum(self.bwd_len)), "exported_at": exported_at,
        }


class FlowTable:
    """Tabla LRU ordenada por última actividad: desalojo e inspección de inactivos en O(1)/O(k)."""

    def __init__(self) -> None:
        self.flows: "OrderedDict[tuple, FlowStats]" = OrderedDict()
        self.lock = threading.Lock()
        self.ready: deque = deque()
        self.counters = {"packets": 0, "exported": 0, "evicted": 0}

    def process(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return
        ts = float(pkt.time)
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            sport, dport, pname = pkt[TCP].sport, pkt[TCP].dport, "TCP"
        elif pkt.haslayer(UDP):
            sport, dport, pname = pkt[UDP].sport, pkt[UDP].dport, "UDP"
        else:
            sport, dport, pname = 0, 0, "ICMP" if pkt.haslayer(ICMP) else "OTHER"
        fwd_key = (ip.src, sport, ip.dst, dport, ip.proto)
        rev_key = (ip.dst, dport, ip.src, sport, ip.proto)
        with self.lock:
            self.counters["packets"] += 1
            key, forward = (fwd_key, True) if fwd_key in self.flows else (
                (rev_key, False) if rev_key in self.flows else (None, True))
            flow = self.flows.get(key) if key else None
            if flow is not None and ts - flow.start > ACTIVE_TIMEOUT:
                self._export(key)
                flow, forward = None, True
            if flow is None:
                if len(self.flows) >= MAX_ACTIVE_FLOWS:
                    oldest = next(iter(self.flows))
                    self._export(oldest)
                    self.counters["evicted"] += 1
                key = fwd_key
                flow = FlowStats(key, ts, ip.src, sport, ip.dst, dport, ip.proto, pname)
                self.flows[key] = flow
            flow.update(pkt, ts, forward)
            self.flows.move_to_end(key)
            if flow.closed_by_flag or (EARLY_EXPORT_PACKETS and flow.packets >= EARLY_EXPORT_PACKETS):
                self._export(key)

    def _export(self, key) -> None:
        flow = self.flows.pop(key, None)
        if flow is not None:
            self.ready.append(flow)
            self.counters["exported"] += 1

    def expire(self, now: float, everything: bool = False) -> None:
        with self.lock:
            while self.flows:
                key, flow = next(iter(self.flows.items()))
                if not everything and now - flow.last <= IDLE_TIMEOUT:
                    break
                self._export(key)

    def drain_records(self) -> list:
        """Calcula los vectores FUERA del lock: el hilo de captura nunca espera a numpy."""
        out = []
        now = time.time()
        while self.ready:
            out.append(self.ready.popleft().to_record(now))
        return out


class ApiSender(threading.Thread):
    def __init__(self, url: str, api_key: str) -> None:
        super().__init__(daemon=True, name="api-sender")
        self.url = url
        self.q: queue.Queue = queue.Queue(maxsize=200)
        self.session = requests.Session()
        if api_key:
            self.session.headers["X-API-Key"] = api_key
        self.stats = {"sent": 0, "ddos": 0, "dropped": 0, "errors": 0}

    def submit(self, records: list) -> None:
        for i in range(0, len(records), MAX_BATCH):
            try:
                self.q.put_nowait(records[i:i + MAX_BATCH])
            except queue.Full:
                self.stats["dropped"] += len(records[i:i + MAX_BATCH])
                log.warning("Cola de envío llena: %d flujos descartados", len(records[i:i + MAX_BATCH]))

    def run(self) -> None:
        while True:
            batch = self.q.get()
            if batch is None:
                break
            for attempt in range(4):
                try:
                    r = self.session.post(self.url, json={"records": batch}, timeout=(3.05, 15))
                    if r.status_code == 200:
                        d = r.json()
                        self.stats["sent"] += d["processed"]
                        self.stats["ddos"] += d.get("ddos", 0)
                        if d.get("ddos"):
                            log.warning("ALERTA: %d/%d flujos clasificados DDoS", d["ddos"], d["processed"])
                        break
                    if 400 <= r.status_code < 500 and r.status_code != 429:
                        log.error("Lote rechazado (%d): %s", r.status_code, r.text[:300])
                        self.stats["errors"] += 1
                        break
                except requests.RequestException as exc:
                    log.warning("Backend no disponible (intento %d): %s", attempt + 1, exc)
                time.sleep(0.5 * 2 ** attempt)
            else:
                self.stats["dropped"] += len(batch)
            self.q.task_done()


def flusher(table: FlowTable, sender: ApiSender, stop: threading.Event) -> None:
    last_report = time.time()
    while not stop.wait(FLUSH_INTERVAL):
        table.expire(time.time())
        records = table.drain_records()
        if records:
            sender.submit(records)
        if time.time() - last_report >= 10:
            last_report = time.time()
            log.info("paquetes=%d flujos_activos=%d exportados=%d desalojados=%d | API: enviados=%d ddos=%d "
                     "descartados=%d errores=%d", table.counters["packets"], len(table.flows),
                     table.counters["exported"], table.counters["evicted"], sender.stats["sent"],
                     sender.stats["ddos"], sender.stats["dropped"], sender.stats["errors"])


def default_bpf() -> str:
    u = urlparse(API_BATCH_URL)
    port = u.port or (443 if u.scheme == "https" else 80)
    return os.getenv("BPF_FILTER", f"ip and not (host {u.hostname} and tcp port {port})")


def run_offline(pcap: str, csv_out: str, sender) -> None:
    """Validación pasiva / generación de dataset con el mismo extractor que producción."""
    table = FlowTable()
    writer, fh = None, None
    if csv_out:
        fh = open(csv_out, "w", newline="", encoding="utf-8")
        writer = csv.writer(fh)
        writer.writerow(["src_ip", "dst_ip", "protocol", "duration_ms", "total_bytes"] + [f"f{i}" for i in range(80)])

    def emit(records):
        if writer:
            for r in records:
                writer.writerow([r["src_ip"], r["dst_ip"], r["protocol"], r["duration_ms"], r["total_bytes"]] + r["features"])
        if sender:
            sender.submit(records)

    clock = 0.0
    with PcapReader(pcap) as reader:
        for i, pkt in enumerate(reader):
            table.process(pkt)
            clock = float(pkt.time)
            if i % 5000 == 0:
                table.expire(clock)
                emit(table.drain_records())
    table.expire(clock, everything=True)
    emit(table.drain_records())
    if fh:
        fh.close()
    if sender:
        sender.q.join()
    log.info("PCAP procesado: %d paquetes, %d flujos", table.counters["packets"], table.counters["exported"])


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Sensor NIDS Conv1D (CICFlowMeter-compatible)")
    ap.add_argument("--pcap", help="Procesar un PCAP offline en lugar de capturar en vivo")
    ap.add_argument("--csv-out", help="(con --pcap) Escribir vectores a CSV en lugar de/además de enviarlos")
    ap.add_argument("--no-send", action="store_true", help="No enviar al backend (sólo CSV)")
    args = ap.parse_args()

    if not SCAPY_AVAILABLE:
        log.critical("Scapy no está instalado: pip install -r sensor/requirements.txt")
        sys.exit(1)

    sender = None if args.no_send else ApiSender(API_BATCH_URL, SENSOR_API_KEY)
    if sender:
        sender.start()
    if args.pcap:
        run_offline(args.pcap, args.csv_out, sender)
        return

    if not SENSOR_API_KEY:
        log.warning("SENSOR_API_KEY vacío: sólo funcionará si el backend no exige autenticación")
    table = FlowTable()
    stop = threading.Event()
    threading.Thread(target=flusher, args=(table, sender, stop), daemon=True, name="flusher").start()
    bpf = default_bpf()
    log.info("Sensor iniciado | iface=%s | filtro='%s' | destino=%s", SNIFF_IFACE or "por defecto", bpf, API_BATCH_URL)
    try:
        sniff(iface=SNIFF_IFACE, filter=bpf, prn=table.process, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        table.expire(time.time(), everything=True)
        records = table.drain_records()
        if records and sender:
            sender.submit(records)
            sender.q.join()


if __name__ == "__main__":
    main()