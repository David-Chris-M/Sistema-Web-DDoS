"""Telemetría medida (sin constantes inventadas) y difusión WebSocket no bloqueante."""
import asyncio
import json
import logging
import time
from collections import deque
from typing import Deque, Optional, Set, Tuple

import numpy as np
from fastapi import WebSocket

logger = logging.getLogger("cybershield.realtime")


def _pct(values, q) -> Optional[float]:
    return round(float(np.percentile(values, q)), 3) if values else None


class Telemetry:
    """Todas las mutaciones ocurren en el hilo del event loop -> sin condiciones de carrera."""

    WINDOW_S = 10.0

    def __init__(self) -> None:
        self.model_ms_per_call: Deque[float] = deque(maxlen=500)   # cómputo Conv1D por invocación
        self.model_ms_per_flow: Deque[float] = deque(maxlen=500)   # amortizado por flujo (lotes)
        self.api_ms: Deque[float] = deque(maxlen=500)              # recepción HTTP -> respuesta (TAPI)
        self.pipeline_ms: Deque[float] = deque(maxlen=500)         # exportación del flujo en sensor -> emisión WS
        self._events: Deque[Tuple[float, int]] = deque()
        self.ws_dropped = 0

    def record(self, model_ms: float, n_flows: int, api_ms: float, pipeline_ms: list) -> None:
        self.model_ms_per_call.append(model_ms)
        self.model_ms_per_flow.append(model_ms / max(n_flows, 1))
        self.api_ms.append(api_ms)
        self.pipeline_ms.extend(pipeline_ms)
        now = time.monotonic()
        self._events.append((now, n_flows))
        self._prune(now)

    def _prune(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self.WINDOW_S:
            self._events.popleft()

    def throughput(self) -> float:
        self._prune(time.monotonic())
        return round(sum(n for _, n in self._events) / self.WINDOW_S, 1)

    def snapshot(self) -> dict:
        m, f, a, p = (list(x) for x in (self.model_ms_per_call, self.model_ms_per_flow, self.api_ms, self.pipeline_ms))
        return {
            "inference_latency_ms": round(m[-1], 3) if m else None,
            "inference_p50_ms": _pct(m, 50), "inference_p95_ms": _pct(m, 95),
            "inference_per_flow_p50_ms": _pct(f, 50),
            "api_p50_ms": _pct(a, 50), "api_p95_ms": _pct(a, 95),
            # Ttotal real: requiere que el sensor envíe 'exported_at' (relojes sincronizados por NTP)
            "end_to_end_ms": _pct(p, 50), "end_to_end_p95_ms": _pct(p, 95),
            "throughput_fps": self.throughput(),
            "samples": len(m),
            "ws_dropped_messages": self.ws_dropped,
        }


class ConnectionManager:
    """Cola + tarea emisora: una petición de inferencia nunca espera a un navegador lento,
    y los sockets muertos se eliminan (antes se acumulaban indefinidamente)."""

    def __init__(self, telemetry: Telemetry, send_timeout_s: float = 2.0, max_queue: int = 1000) -> None:
        self.active: Set[WebSocket] = set()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue)
        self.send_timeout_s = send_timeout_s
        self.telemetry = telemetry
        self._task: Optional[asyncio.Task] = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    def publish(self, message: dict) -> None:
        if not self.active:
            return
        try:
            self.queue.put_nowait(message)
        except asyncio.QueueFull:  # backpressure: descarta el más antiguo, nunca bloquea la ingesta
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self.telemetry.ws_dropped += 1
            self.queue.put_nowait(message)

    async def _send(self, ws: WebSocket, text: str) -> Optional[WebSocket]:
        try:
            await asyncio.wait_for(ws.send_text(text), timeout=self.send_timeout_s)
            return None
        except Exception:
            return ws

    async def _run(self) -> None:
        while True:
            message = await self.queue.get()
            if not self.active:
                continue
            text = json.dumps(message, default=str)
            dead = await asyncio.gather(*(self._send(ws, text) for ws in list(self.active)))
            for ws in dead:
                if ws is not None:
                    self.disconnect(ws)

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="ws-broadcaster")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
