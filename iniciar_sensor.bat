@echo off
TITLE CyberShield Pyme - Sensor de Red en Vivo

cd /d "%~dp0"

echo ==========================================================
echo   CYBERSHIELD PYME - SENSOR DE RED EN VIVO (SCAPY)
echo   Capturando paquetes de red en tiempo real...
echo ==========================================================
echo [*] La configuracion (.env) es cargada de forma segura por Python.
echo [*] Presiona Ctrl+C para detener la captura.
echo.

set "PYTHON_CMD=python"
if exist "venv\Scripts\python.exe" set "PYTHON_CMD=venv\Scripts\python.exe"

"%PYTHON_CMD%" -m sensor.capturador_trafico_vivo %*
pause
