@echo off
TITLE CyberShield Pyme - Servidor NIDS Conv1D 24/7

echo ==========================================================
echo   CYBERSHIELD PYME - NIDS DEFENSIVO CONV1D 24/7
echo   Ambiente: Produccion Pyme (Lima, Peru)
echo ==========================================================

cd /d "%~dp0"

REM Verificacion de artefactos del modelo
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

set "PYTHON_CMD=python"
if exist "venv\Scripts\python.exe" set "PYTHON_CMD=venv\Scripts\python.exe"

echo [*] Artefactos Conv1D verificados correctamente.
echo [*] Iniciando Demonio Supervisor 24/7 (Auto-recuperacion + Rotacion de Logs)...

"%PYTHON_CMD%" demonio_servicio.py %*
pause
