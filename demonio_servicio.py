import argparse
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.request

from backend.configuracion import DIRECTORIO_BASE, configuracion

NOMBRE_TAREA_WINDOWS = "CyberShield_Pyme_NIDS_24x7"
ARCHIVO_PID_DEMONIO = os.path.join(configuracion.directorio_logs, "cybershield_demonio.pid")
PREFIJO_REGLA_FIREWALL = "CyberShield_Block_"


# --- Configuración de Registro (Logger) ---
def configurar_logger_demonio() -> logging.Logger:
    os.makedirs(configuracion.directorio_logs, exist_ok=True)
    ruta_log = os.path.join(configuracion.directorio_logs, "cybershield_demonio.log")
    formato = "%(asctime)s [%(levelname)s] [cybershield.demonio] %(message)s"

    logger = logging.getLogger("cybershield.demonio")
    logger.setLevel(configuracion.log_level)
    if not logger.handlers:
        manejador_archivo = RotatingFileHandler(
            ruta_log,
            maxBytes=configuracion.tamano_maximo_log_bytes,
            backupCount=configuracion.cantidad_respaldos_log,
            encoding="utf-8",
        )
        manejador_archivo.setFormatter(logging.Formatter(formato))
        logger.addHandler(manejador_archivo)
        if sys.stdout is not None and hasattr(sys.stdout, "write"):
            manejador_consola = logging.StreamHandler(sys.stdout)
            manejador_consola.setFormatter(logging.Formatter(formato))
            logger.addHandler(manejador_consola)
    return logger


logger_demonio = configurar_logger_demonio()


# --- Utilidades de Procesos y Red ---
def _obtener_ejecutable_python_consola() -> str:
    if os.name == "nt" and sys.executable.lower().endswith("pythonw.exe"):
        candidato = os.path.join(os.path.dirname(sys.executable), "python.exe")
        if os.path.exists(candidato):
            return candidato
    return sys.executable


def _abrir_log_consola_oculta_rotado():
    os.makedirs(configuracion.directorio_logs, exist_ok=True)
    ruta_salida = os.path.join(configuracion.directorio_logs, "cybershield_consola_oculta.log")
    max_bytes = max(1024 * 1024, int(configuracion.tamano_maximo_log_bytes))
    try:
        if os.path.exists(ruta_salida) and os.path.getsize(ruta_salida) >= max_bytes:
            respaldo = ruta_salida + ".1"
            if os.path.exists(respaldo):
                os.remove(respaldo)
            os.replace(ruta_salida, respaldo)
    except Exception:
        pass
    return open(ruta_salida, "a", encoding="utf-8")


def _limpiar_reglas_firewall_huerfanas() -> None:
    if os.name != "nt":
        return
    try:
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"Remove-NetFirewallRule -DisplayName '{PREFIJO_REGLA_FIREWALL}*' -ErrorAction SilentlyContinue",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        logger_demonio.info("Limpieza preventiva de reglas %s* ejecutada tras reinicio forzado del API.", PREFIJO_REGLA_FIREWALL)
    except Exception:
        pass


def construir_comando_api(host: str, puerto: int) -> list:
    ejecutable_py = _obtener_ejecutable_python_consola()
    comando = [
        ejecutable_py,
        "-m",
        "uvicorn",
        "backend.principal:aplicacion",
        "--host",
        host,
        "--port",
        str(puerto),
        "--workers",
        "1",
    ]
    cert = configuracion.archivo_certificado_ssl
    key = configuracion.archivo_clave_ssl
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        comando.extend(["--ssl-certfile", cert, "--ssl-keyfile", key])
    return comando


def verificar_salud_http(puerto: int, usar_https: bool) -> bool:
    esquema = "https" if usar_https else "http"
    url = f"{esquema}://127.0.0.1:{puerto}/api/health"
    try:
        contexto = ssl._create_unverified_context() if usar_https else None
        with urllib.request.urlopen(url, timeout=4.0, context=contexto) as respuesta:
            return respuesta.status == 200
    except Exception:
        return False


def _detener_instancia_en_segundo_plano() -> None:
    try:
        import psutil
    except ImportError:
        psutil = None

    if os.path.exists(ARCHIVO_PID_DEMONIO):
        try:
            with open(ARCHIVO_PID_DEMONIO, encoding="utf-8") as f_pid:
                pid_guardado = int(f_pid.read().strip())
            if psutil and psutil.pid_exists(pid_guardado):
                proc_padre = psutil.Process(pid_guardado)
                for hijo in proc_padre.children(recursive=True):
                    try:
                        hijo.terminate()
                    except Exception:
                        pass
                proc_padre.terminate()
                proc_padre.wait(timeout=5)
        except Exception:
            pass
        try:
            os.remove(ARCHIVO_PID_DEMONIO)
        except Exception:
            pass

    if psutil:
        mi_pid = os.getpid()
        try:
            pids_excluidos = {mi_pid} | {p.pid for p in psutil.Process(mi_pid).parents()}
        except Exception:
            pids_excluidos = {mi_pid}
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if proc.info["pid"] in pids_excluidos:
                    continue
                nombre_proc = (proc.info.get("name") or "").lower()
                if "python" not in nombre_proc:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if (
                    "demonio_servicio.py" in cmdline
                    or "backend.principal:aplicacion" in cmdline
                    or "sensor.capturador_trafico_vivo" in cmdline
                ):
                    proc.terminate()
            except Exception:
                pass


# --- Gestión de Servicio (Windows / Linux systemd) ---
def instalar_servicio_windows(con_sensor: bool = False, host: str = "0.0.0.0", puerto: int = 8000) -> int:
    _detener_instancia_en_segundo_plano()
    ruta_script = os.path.abspath(__file__)
    ejecutable_py = _obtener_ejecutable_python_consola()
    partes_extra = ["--oculto"]
    if con_sensor:
        partes_extra.append("--con-sensor")
    if host != "0.0.0.0":
        partes_extra.extend(["--host", host])
    if puerto != 8000:
        partes_extra.extend(["--puerto", str(puerto)])
    argumentos_extra = " " + " ".join(partes_extra)

    ejecutable_w = os.path.join(os.path.dirname(ejecutable_py), "pythonw.exe")
    if not os.path.exists(ejecutable_w):
        ejecutable_w = ejecutable_py
    comando_tarea = f'"{ejecutable_w}" "{ruta_script}"{argumentos_extra}'

    cmd = [
        "schtasks",
        "/Create",
        "/TN",
        NOMBRE_TAREA_WINDOWS,
        "/TR",
        comando_tarea,
        "/SC",
        "ONLOGON",
        "/RL",
        "HIGHEST",
        "/F",
    ]
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    if resultado.returncode != 0:
        logger_demonio.warning(
            "No fue posible registrar la tarea con privilegios elevados (/RL HIGHEST); "
            "reintentando con /RL LIMITED (SOAR/netsh y captura Npcap requieren Administrador)."
        )
        cmd_limitado = [
            "schtasks",
            "/Create",
            "/TN",
            NOMBRE_TAREA_WINDOWS,
            "/TR",
            comando_tarea,
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/F",
        ]
        resultado = subprocess.run(cmd_limitado, capture_output=True, text=True)

    if resultado.returncode == 0:
        logger_demonio.info("Tarea de inicio automático '%s' registrada y activada en Windows (modo invisible pythonw).", NOMBRE_TAREA_WINDOWS)
        subprocess.run(["schtasks", "/Run", "/TN", NOMBRE_TAREA_WINDOWS], capture_output=True, text=True)
    else:
        res_run = subprocess.run(["schtasks", "/Run", "/TN", NOMBRE_TAREA_WINDOWS], capture_output=True, text=True)
        if res_run.returncode == 0:
            logger_demonio.info("Tarea '%s' existente reactivada exitosamente en segundo plano.", NOMBRE_TAREA_WINDOWS)
        else:
            cmd_ps_esc = comando_tarea.replace("'", "''")
            dir_ps_esc = DIRECTORIO_BASE.replace("'", "''")
            cmd_wmi = [
                "powershell",
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                (
                    f"Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                    f"-Arguments @{{CommandLine='{cmd_ps_esc}'; CurrentDirectory='{dir_ps_esc}'}} | Out-Null"
                ),
            ]
            res_wmi = subprocess.run(cmd_wmi, capture_output=True, text=True)
            if res_wmi.returncode != 0:
                banderas_creacion = (
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                )
                args_proceso = [ejecutable_py, ruta_script] + partes_extra
                with _abrir_log_consola_oculta_rotado() as archivo_salida:
                    subprocess.Popen(
                        args_proceso,
                        cwd=DIRECTORIO_BASE,
                        stdin=subprocess.DEVNULL,
                        stdout=archivo_salida,
                        stderr=archivo_salida,
                        creationflags=banderas_creacion,
                    )

    logger_demonio.info("Iniciando motor IA Conv1D y Sensor en segundo plano (sin ventanas)...")
    usar_https = bool(
        configuracion.archivo_certificado_ssl
        and configuracion.archivo_clave_ssl
        and os.path.exists(configuracion.archivo_certificado_ssl)
        and os.path.exists(configuracion.archivo_clave_ssl)
    )
    esquema = "https" if usar_https else "http"
    salud_ok = False
    for _ in range(25):
        time.sleep(1.0)
        if verificar_salud_http(puerto, usar_https):
            salud_ok = True
            break

    if salud_ok:
        logger_demonio.info(
            "LISTO: CyberShield Pyme está corriendo 100%% oculto en segundo plano en %s://localhost:%d. "
            "Puede cerrar TODAS las ventanas de PowerShell.",
            esquema,
            puerto,
        )
        return 0

    logger_demonio.error(
        "El servicio no respondió en %s://127.0.0.1:%d/api/health tras 25s. Revise logs/cybershield_api.log.",
        esquema,
        puerto,
    )
    return 1


def desinstalar_servicio_windows() -> int:
    _detener_instancia_en_segundo_plano()
    subprocess.run(["schtasks", "/End", "/TN", NOMBRE_TAREA_WINDOWS], capture_output=True, text=True)
    cmd = ["schtasks", "/Delete", "/TN", NOMBRE_TAREA_WINDOWS, "/F"]
    resultado = subprocess.run(cmd, capture_output=True, text=True)
    _limpiar_reglas_firewall_huerfanas()
    if resultado.returncode == 0:
        logger_demonio.info("Procesos en segundo plano detenidos y tarea '%s' eliminada.", NOMBRE_TAREA_WINDOWS)
        return 0
    salida = ((resultado.stdout or "") + " " + (resultado.stderr or "")).lower()
    if "no existe" in salida or "cannot find" in salida or "does not exist" in salida:
        logger_demonio.info("Procesos detenidos; la tarea '%s' no existía.", NOMBRE_TAREA_WINDOWS)
        return 0
    logger_demonio.error("Error eliminando tarea '%s': %s", NOMBRE_TAREA_WINDOWS, salida.strip()[:200])
    return resultado.returncode


def generar_unidad_systemd(ruta_destino: str = None) -> str:
    if not ruta_destino:
        ruta_destino = os.path.join(DIRECTORIO_BASE, "cybershield-nids.service")
    ruta_log = os.path.join(configuracion.directorio_logs, "cybershield_demonio.log")
    contenido = f"""[Unit]
Description=CyberShield Pyme - Demonio NIDS Conv1D 24/7
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory="{DIRECTORIO_BASE}"
ExecStart="{sys.executable}" "{os.path.abspath(__file__)}" --con-sensor
Restart=always
RestartSec=5
StandardOutput=append:{ruta_log}
StandardError=append:{ruta_log}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
    with open(ruta_destino, "w", encoding="utf-8") as archivo:
        archivo.write(contenido)
    logger_demonio.info("Archivo de servicio systemd generado en: %s", ruta_destino)
    return ruta_destino


# --- Bucle Supervisor Principal ---
def ejecutar_bucle_supervisor(host: str, puerto: int, con_sensor: bool, oculto: bool = False) -> None:
    _detener_instancia_en_segundo_plano()
    time.sleep(1.0)
    detener_solicitado = False
    proceso_api = None
    proceso_sensor = None

    try:
        with open(ARCHIVO_PID_DEMONIO, "w", encoding="utf-8") as f_pid:
            f_pid.write(str(os.getpid()))
    except Exception:
        pass

    def manejador_senal(signum, _frame):
        nonlocal detener_solicitado
        detener_solicitado = True
        logger_demonio.info("Señal de parada (%s) recibida. Deteniendo procesos supervisados...", signum)

    signal.signal(signal.SIGINT, manejador_senal)
    signal.signal(signal.SIGTERM, manejador_senal)

    usar_https = bool(
        configuracion.archivo_certificado_ssl
        and configuracion.archivo_clave_ssl
        and os.path.exists(configuracion.archivo_certificado_ssl)
        and os.path.exists(configuracion.archivo_clave_ssl)
    )
    comando_api = construir_comando_api(host, puerto)
    ejecutable_py = _obtener_ejecutable_python_consola()
    comando_sensor = [ejecutable_py, "-m", "sensor.capturador_trafico_vivo"]

    kwargs_popen = {"cwd": DIRECTORIO_BASE}
    archivo_consola_hijos = None
    if oculto or (os.name == "nt" and sys.executable.lower().endswith("pythonw.exe")):
        archivo_consola_hijos = _abrir_log_consola_oculta_rotado()
        kwargs_popen["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs_popen["stdin"] = subprocess.DEVNULL
        kwargs_popen["stdout"] = archivo_consola_hijos
        kwargs_popen["stderr"] = archivo_consola_hijos

    fallos_consecutivos_salud = 0
    reinicios_api = 0
    ultimo_sondeo = 0.0

    logger_demonio.info(
        "Demonio Supervisor iniciado | Host: %s:%d | HTTPS: %s | Sensor en vivo: %s | Modo Oculto: %s | Logs: %s",
        host,
        puerto,
        "ACTIVO" if usar_https else "INACTIVO",
        "ACTIVO" if con_sensor else "INACTIVO",
        "SI" if oculto else "NO",
        configuracion.directorio_logs,
    )

    try:
        while not detener_solicitado:
            # 1. Supervisión del Servidor API
            if proceso_api is None or proceso_api.poll() is not None:
                if proceso_api is not None:
                    codigo = proceso_api.returncode
                    reinicios_api += 1
                    espera = min(30, 2 ** min(reinicios_api, 5))
                    logger_demonio.warning(
                        "Proceso API finalizó inesperadamente (código %s). Reiniciando en %ds (intento #%d)...",
                        codigo,
                        espera,
                        reinicios_api,
                    )
                    time.sleep(espera)
                if detener_solicitado:
                    break
                logger_demonio.info("Iniciando proceso Servidor API FastAPI...")
                proceso_api = subprocess.Popen(comando_api, **kwargs_popen)
                fallos_consecutivos_salud = 0
                ultimo_sondeo = time.time() + 12.0

            # 2. Supervisión del Sensor NIDS
            if con_sensor and (proceso_sensor is None or proceso_sensor.poll() is not None):
                if proceso_sensor is not None:
                    logger_demonio.warning(
                        "Proceso Sensor finalizó (código %s). Reiniciando sensor en 3s...",
                        proceso_sensor.returncode,
                    )
                    time.sleep(3)
                if not detener_solicitado:
                    logger_demonio.info("Iniciando proceso Sensor NIDS Scapy...")
                    proceso_sensor = subprocess.Popen(comando_sensor, **kwargs_popen)

            # 3. Verificación de Salud (Watchdog)
            ahora = time.time()
            if ahora - ultimo_sondeo >= 15.0:
                ultimo_sondeo = ahora
                if verificar_salud_http(puerto, usar_https):
                    fallos_consecutivos_salud = 0
                    reinicios_api = 0
                else:
                    fallos_consecutivos_salud += 1
                    logger_demonio.warning(
                        "Sondeo /api/health sin respuesta (%d/3 fallos consecutivos)",
                        fallos_consecutivos_salud,
                    )
                    if fallos_consecutivos_salud >= 3 and proceso_api is not None:
                        logger_demonio.error("Servidor API congelado. Forzando reinicio del proceso hijo...")
                        forzado_kill = False
                        try:
                            proceso_api.terminate()
                            proceso_api.wait(timeout=5)
                        except Exception:
                            try:
                                proceso_api.kill()
                                forzado_kill = True
                            except Exception:
                                pass
                        if forzado_kill:
                            _limpiar_reglas_firewall_huerfanas()
                        proceso_api = None

            time.sleep(1.0)
    finally:
        for nombre, proc in (("Sensor NIDS", proceso_sensor), ("Servidor API", proceso_api)):
            if proc is not None and proc.poll() is None:
                logger_demonio.info("Cerrando %s (PID %d)...", nombre, proc.pid)
                try:
                    proc.terminate()
                    proc.wait(timeout=8)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        if archivo_consola_hijos is not None:
            try:
                archivo_consola_hijos.close()
            except Exception:
                pass
        try:
            if os.path.exists(ARCHIVO_PID_DEMONIO):
                os.remove(ARCHIVO_PID_DEMONIO)
        except Exception:
            pass
        logger_demonio.info("Demonio Supervisor detenido limpiamente.")


# --- Punto de Entrada ---
def principal() -> None:
    analizador = argparse.ArgumentParser(description="Demonio Supervisor 24/7 de CyberShield Pyme")
    analizador.add_argument("--host", default="0.0.0.0", help="Dirección IP de escucha (por defecto 0.0.0.0)")
    analizador.add_argument("--puerto", type=int, default=8000, help="Puerto TCP del servidor (por defecto 8000)")
    analizador.add_argument("--con-sensor", action="store_true", help="Supervisar también el sensor Scapy en vivo")
    analizador.add_argument("--oculto", action="store_true", help="Ejecutar procesos hijos sin ventanas de consola en Windows")
    analizador.add_argument("--instalar-windows", action="store_true", help="Registrar tarea de inicio automático en Windows")
    analizador.add_argument("--desinstalar-windows", action="store_true", help="Eliminar tarea de inicio automático en Windows")
    analizador.add_argument("--generar-systemd", action="store_true", help="Generar unidad cybershield-nids.service para Linux")
    argumentos = analizador.parse_args()

    if argumentos.instalar_windows:
        sys.exit(instalar_servicio_windows(argumentos.con_sensor, host=argumentos.host, puerto=argumentos.puerto))
    if argumentos.desinstalar_windows:
        sys.exit(desinstalar_servicio_windows())
    if argumentos.generar_systemd:
        generar_unidad_systemd()
        sys.exit(0)

    ejecutar_bucle_supervisor(argumentos.host, argumentos.puerto, argumentos.con_sensor, argumentos.oculto)


if __name__ == "__main__":
    principal()
