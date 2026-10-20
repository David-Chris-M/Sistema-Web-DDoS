@echo off
REM ============================================================
REM CYBERSHIELD PYME - SCRIPT DE ARRANQUE EN WINDOWS SERVER / LOCAL
REM ============================================================
TITLE CyberShield Pyme - Servidor NIDS Conv1D 24/7

echo ==========================================================
echo   CYBERSHIELD PYME - NIDS DEFENSIVO CONV1D 24/7
echo   Ambiente: Produccion Pyme (Lima, Peru)
echo ==========================================================

cd /d "%~dp0"

REM 1. Verificar artefactos de Inteligencia Artificial
if not exist "ml\models\ddos_cnn_model.keras" (
    echo [!] ERROR: No se encontro ml\models\ddos_cnn_model.keras
    pause
    exit /b 1
)

if not exist "ml\models\scaler.pkl" (
    echo [!] ERROR: No se encontro ml\models\scaler.pkl
    pause
    exit /b 1
)

echo [*] Artefactos Conv1D verificados correctamente.
echo [*] Iniciando servidor FastAPI Uvicorn en http://127.0.0.1:8000 ...

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
pause
