import asyncio
import json
import logging
import time
from collections import deque
from typing import Deque, Optional, Set, Tuple

import numpy as np
from fastapi import WebSocket

registro_logger = logging.getLogger("cybershield.realtime")


def _calcular_percentil(valores, q: float) -> Optional[float]:
    return round(float(np.percentile(valores, q)), 3) if valores else None


# --- Acumulador de Telemetría y Latencias ---
class Telemetria:
    VENTANA_SEGUNDOS = 10.0

    def __init__(self) -> None:
        self.ms_modelo_por_llamada: Deque[float] = deque(maxlen=500)
        self.ms_modelo_por_flujo: Deque[float] = deque(maxlen=500)
        self.ms_api: Deque[float] = deque(maxlen=500)
        self.ms_extremo_a_extremo: Deque[float] = deque(maxlen=500)
        self._eventos_flujo: Deque[Tuple[float, int]] = deque(maxlen=5000)
        self.mensajes_ws_descartados = 0

    @property
    def model_ms_per_call(self):
        return self.ms_modelo_por_llamada

    @property
    def model_ms_per_flow(self):
        return self.ms_modelo_por_flujo

    @property
    def api_ms(self):
        return self.ms_api

    @property
    def pipeline_ms(self):
        return self.ms_extremo_a_extremo

    @property
    def ws_dropped(self):
        return self.mensajes_ws_descartados

    @ws_dropped.setter
    def ws_dropped(self, valor: int):
        self.mensajes_ws_descartados = valor

    def registrar(self, ms_modelo: float, n_flujos: int, ms_api: float, ms_pipeline: list) -> None:
        self.ms_modelo_por_llamada.append(ms_modelo)
        self.ms_modelo_por_flujo.append(ms_modelo / max(n_flujos, 1))
        self.ms_api.append(ms_api)
        self.ms_extremo_a_extremo.extend(ms_pipeline)
        ahora = time.monotonic()
        self._eventos_flujo.append((ahora, n_flujos))
        self._podar_eventos(ahora)

    record = registrar

    def _podar_eventos(self, ahora: float) -> None:
        while self._eventos_flujo and ahora - self._eventos_flujo[0][0] > self.VENTANA_SEGUNDOS:
            self._eventos_flujo.popleft()

    def rendimiento_flujos_por_segundo(self) -> float:
        self._podar_eventos(time.monotonic())
        return round(sum(n for _, n in self._eventos_flujo) / self.VENTANA_SEGUNDOS, 1)

    throughput = rendimiento_flujos_por_segundo

    def captura_instantanea(self) -> dict:
        m = list(self.ms_modelo_por_llamada)
        f = list(self.ms_modelo_por_flujo)
        a = list(self.ms_api)
        p = list(self.ms_extremo_a_extremo)
        return {
            "inference_latency_ms": round(m[-1], 3) if m else None,
            "inference_p50_ms": _calcular_percentil(m, 50),
            "inference_p95_ms": _calcular_percentil(m, 95),
            "inference_per_flow_p50_ms": _calcular_percentil(f, 50),
            "api_p50_ms": _calcular_percentil(a, 50),
            "api_p95_ms": _calcular_percentil(a, 95),
            "end_to_end_ms": _calcular_percentil(p, 50),
            "end_to_end_p95_ms": _calcular_percentil(p, 95),
            "throughput_fps": self.rendimiento_flujos_por_segundo(),
            "samples": len(m),
            "ws_dropped_messages": self.mensajes_ws_descartados,
        }

    snapshot = captura_instantanea


# --- Gestor de Conexiones WebSocket ---
class GestorConexiones:
    def __init__(self, telemetria: Telemetria, tiempo_espera_envio_s: float = 2.0, max_cola: int = 1000) -> None:
        self.activas: Set[WebSocket] = set()
        self.cola_mensajes: asyncio.Queue = asyncio.Queue(maxsize=max_cola)
        self.tiempo_espera_envio_s = tiempo_espera_envio_s
        self.telemetria = telemetria
        self._tarea_emision: Optional[asyncio.Task] = None

    @property
    def active(self):
        return self.activas

    @property
    def queue(self):
        return self.cola_mensajes

    async def conectar(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.activas.add(websocket)

    connect = conectar

    def desconectar(self, websocket: WebSocket) -> None:
        self.activas.discard(websocket)

    disconnect = desconectar

    def publicar(self, mensaje: dict) -> None:
        if not self.activas:
            return
        try:
            self.cola_mensajes.put_nowait(mensaje)
        except asyncio.QueueFull:
            try:
                self.cola_mensajes.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self.telemetria.mensajes_ws_descartados += 1
            self.cola_mensajes.put_nowait(mensaje)

    publish = publicar

    async def _enviar_individual(self, websocket: WebSocket, texto: str) -> Optional[WebSocket]:
        try:
            await asyncio.wait_for(websocket.send_text(texto), timeout=self.tiempo_espera_envio_s)
            return None
        except Exception:
            return websocket

    async def _bucle_emision(self) -> None:
        while True:
            mensaje = await self.cola_mensajes.get()
            if not self.activas:
                continue
            texto_json = json.dumps(mensaje, default=str)
            desconectados = await asyncio.gather(*(self._enviar_individual(ws, texto_json) for ws in list(self.activas)))
            for ws in desconectados:
                if ws is not None:
                    self.desconectar(ws)

    def iniciar(self) -> None:
        self._tarea_emision = asyncio.create_task(self._bucle_emision(), name="difusor-websocket-telemetria")

    start = iniciar

    async def detener(self) -> None:
        if self._tarea_emision:
            self._tarea_emision.cancel()
            try:
                await self._tarea_emision
            except asyncio.CancelledError:
                pass
            self._tarea_emision = None

    stop = detener


# --- Aliases de Compatibilidad ---
Telemetry = Telemetria
ConnectionManager = GestorConexiones
logger = registro_logger
