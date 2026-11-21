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
    def __init__(
        self,
        telemetria: Telemetria,
        tiempo_espera_envio_s: float = 2.0,
        max_cola: int = 1000,
        max_conexiones: int = 50,
    ) -> None:
        self.activas: Set[WebSocket] = set()
        self._sesiones_ws: dict = {}
        self.cola_mensajes: asyncio.Queue = asyncio.Queue(maxsize=max_cola)
        self.tiempo_espera_envio_s = tiempo_espera_envio_s
        self.max_conexiones = max_conexiones
        self.telemetria = telemetria
        self._tarea_emision: Optional[asyncio.Task] = None

    @property
    def active(self):
        return self.activas

    @property
    def queue(self):
        return self.cola_mensajes

    async def conectar(
        self,
        websocket: WebSocket,
        token_hash: Optional[str] = None,
        expiracion: Optional[float] = None,
    ) -> bool:
        if len(self.activas) >= self.max_conexiones:
            try:
                await websocket.close(code=1013)
            except Exception:
                pass
            return False
        await websocket.accept()
        self.activas.add(websocket)
        self._sesiones_ws[websocket] = {
            "token_hash": token_hash,
            "expiracion": expiracion,
        }
        return True

    connect = conectar

    def desconectar(self, websocket: WebSocket) -> None:
        self.activas.discard(websocket)
        self._sesiones_ws.pop(websocket, None)

    disconnect = desconectar

    async def _cerrar_ws_seguro(self, websocket: WebSocket, code: int = 1001) -> None:
        self.desconectar(websocket)
        try:
            await asyncio.wait_for(websocket.close(code=code), timeout=1.0)
        except Exception:
            pass

    async def cerrar_por_sesion(self, token_hash: str, code: int = 1008) -> int:
        if not token_hash:
            return 0
        objetivos = [
            ws
            for ws, meta in list(self._sesiones_ws.items())
            if meta.get("token_hash") == token_hash
        ]
        for ws in objetivos:
            await self._cerrar_ws_seguro(ws, code=code)
        return len(objetivos)

    async def cerrar_sesiones_expiradas(self, ahora: Optional[float] = None) -> int:
        marca = time.time() if ahora is None else float(ahora)
        expirados = [
            ws
            for ws, meta in list(self._sesiones_ws.items())
            if meta.get("expiracion") is not None and marca > float(meta["expiracion"])
        ]
        for ws in expirados:
            await self._cerrar_ws_seguro(ws, code=1008)
        return len(expirados)

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
            await self.cerrar_sesiones_expiradas()
            if not self.activas:
                continue
            texto_json = json.dumps(mensaje, default=str)
            desconectados = await asyncio.gather(*(self._enviar_individual(ws, texto_json) for ws in list(self.activas)))
            for ws in desconectados:
                if ws is not None:
                    await self._cerrar_ws_seguro(ws, code=1001)

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
        for ws in list(self.activas):
            await self._cerrar_ws_seguro(ws, code=1001)

    stop = detener


# --- Aliases de Compatibilidad ---
Telemetry = Telemetria
ConnectionManager = GestorConexiones
logger = registro_logger
