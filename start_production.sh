#!/usr/bin/env bash
# ============================================================
# CYBERSHIELD PYME - SCRIPT DE ARRANQUE EN PRODUCCIÓN (LINUX)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  CYBERSHIELD PYME - NIDS DEFENSIVO CONV1D 24/7"
echo "  Ambiente: Producción Pyme (Lima, Perú)"
echo "=========================================================="

# 1. Cargar variables de entorno
if [ -f .env ]; then
    echo "[*] Cargando configuración desde .env..."
    export $(grep -v '^#' .env | xargs)
fi

# 2. Verificar Python y Dependencias
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" &> /dev/null; then
    echo "[!] Error: No se encontró $PYTHON_BIN. Instale Python 3.10 o 3.11."
    exit 1
fi

echo "[*] Verificando integridad de modelos en ml/models/..."
if [ ! -f "ml/models/ddos_cnn_model.keras" ] || [ ! -f "ml/models/scaler.pkl" ]; then
    echo "[!] Error: Faltan artefactos del modelo en ml/models/."
    exit 1
fi

# 3. Arrancar Servidor FastAPI Uvicorn
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
echo "[*] Iniciando servidor FastAPI en http://$HOST:$PORT ..."
exec "$PYTHON_BIN" -m uvicorn backend.main:app --host "$HOST" --port "$PORT" --workers 1
