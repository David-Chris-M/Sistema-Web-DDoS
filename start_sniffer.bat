@echo off
REM ============================================================
REM CYBERSHIELD PYME - SENSOR NIDS PERIMETRAL EN VIVO (SCAPY)
REM ============================================================
TITLE CyberShield Pyme - Sensor de Red en Vivo

cd /d "%~dp0"

echo ==========================================================
echo   CYBERSHIELD PYME - SENSOR DE RED EN VIVO (SCAPY)
echo   Capturando paquetes de red en tiempo real...
echo ==========================================================

REM Cargar variables de entorno si existe .env
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" if not "%%A:~0,1%"=="#" (
            set "%%A=%%B"
        )
    )
)

echo [*] Enviando telemetria a: http://127.0.0.1:8000/api/predict/batch
echo [*] Presiona Ctrl+C para detener la captura.
echo.

python -m sensor.live_traffic_sniffer
pause
