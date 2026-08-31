import time
import numpy as np
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

API_BATCH_URL = "http://127.0.0.1:8000/api/predict/batch"
session = requests.Session()

class FlowStats:
    def __init__(self, start_time):
        self.start_time = start_time
        self.last_time = start_time
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.packet_lengths = []
        self.iat_times = []
        self.protocol = "TCP"

    def update(self, pkt, is_forward=True):
        pkt_len = len(pkt)
        current_time = time.time()

        if self.last_time:
            self.iat_times.append((current_time - self.last_time) * 1e6)
        self.last_time = current_time

        self.packet_lengths.append(pkt_len)
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += pkt_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += pkt_len

        if pkt.haslayer(TCP):
            self.protocol = "TCP"
        elif pkt.haslayer(UDP):
            self.protocol = "UDP"
        elif pkt.haslayer(ICMP):
            self.protocol = "ICMP"

    def to_cicids_vector(self):
        duration = max((self.last_time - self.start_time) * 1e6, 1.0)
        lens = np.array(self.packet_lengths) if self.packet_lengths else np.array([0.0])
        iats = np.array(self.iat_times) if self.iat_times else np.array([0.0])

        features = [
            float(self.fwd_packets),
            float(self.bwd_packets),
            float(self.fwd_bytes),
            float(self.bwd_bytes),
            float(np.max(lens)),
            float(np.min(lens)),
            float(np.mean(lens)),
            float(np.std(lens)),
            float((self.fwd_bytes + self.bwd_bytes) / (duration / 1e6)),
            float((self.fwd_packets + self.bwd_packets) / (duration / 1e6)),
            float(np.mean(iats)),
            float(np.std(iats)),
            float(np.max(iats)),
            float(np.min(iats)),
            float(duration),
            float(self.fwd_bytes / max(self.fwd_packets, 1)),
            float(self.bwd_bytes / max(self.bwd_packets, 1))
        ]

        while len(features) < 80:
            features.append(0.0)

        return features[:80], self.protocol

active_flows = defaultdict(lambda: FlowStats(time.time()))
last_flush_time = time.time()

def process_packet(pkt):
    global last_flush_time
    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    flow_key = (src_ip, dst_ip)

    active_flows[flow_key].update(pkt, is_forward=True)

    if time.time() - last_flush_time >= 1.5:
        flush_and_send_flows()
        last_flush_time = time.time()

def flush_and_send_flows():
    if not active_flows:
        return

    flows_to_process = list(active_flows.items())
    active_flows.clear()

    batch_payload = []
    for flow_key, stats in flows_to_process:
        vector, protocol = stats.to_cicids_vector()
        duration_ms = max((stats.last_time - stats.start_time) * 1000, 1.0)
        total_bytes = stats.fwd_bytes + stats.bwd_bytes

        batch_payload.append({
            "features": vector,
            "src_ip": str(flow_key[0]),
            "dst_ip": str(flow_key[1]),
            "protocol": protocol,
            "duration_ms": round(duration_ms, 2),
            "total_bytes": int(total_bytes)
        })

    try:
        res = session.post(API_BATCH_URL, json={"records": batch_payload}, timeout=3)
        if res.status_code == 200:
            data = res.json()
            print(f"[✓ LOTE] {data['processed']} flujos | Procesado en: {data['batch_time_ms']} ms | Promedio: {data['avg_latency_per_flow_ms']} ms/flujo")
        else:
            print(f"[!] Error del backend HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[!] Error de conexión: {e}")

if __name__ == "__main__":
    print("=" * 65)
    print("  SENSOR NIDS PASIVO EN LOTE (BATCH INFERENCE)")
    print(f"  Enviando telemetría a: {API_BATCH_URL}")
    print("  Presiona Ctrl + C para detener.")
    print("=" * 65)
    sniff(prn=process_packet, store=0)