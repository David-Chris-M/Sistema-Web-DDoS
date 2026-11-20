import ipaddress
import os
import random
import socket
import sys
import time


# --- Configuración de Red ---
def obtener_ip_local() -> str:
    ip_env = (os.getenv("LOCAL_HOST_IP") or "").strip()
    if ip_env:
        return ip_env
    for destino in (("8.8.8.8", 80), ("1.1.1.1", 80)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(destino)
                ip = s.getsockname()[0]
                if ip and not ip.startswith(("127.", "169.254.")):
                    return ip
        except Exception:
            pass
    return "127.0.0.1"


def validar_ip_privada_o_local(ip_str: str) -> str:
    ip_limpia = (ip_str or "").strip()
    try:
        ip_obj = ipaddress.ip_address(ip_limpia)
    except ValueError as exc:
        raise ValueError(f"Dirección IP inválida: '{ip_limpia}'") from exc
    if ip_obj.version != 4 or not (ip_obj.is_private or ip_obj.is_loopback):
        raise ValueError(
            f"Destino rechazado ('{ip_limpia}'): solo se permiten direcciones IPv4 privadas o locales (RFC 1918 / loopback)."
        )
    return str(ip_obj)


IP_LOCAL = obtener_ip_local()
PUERTO_VICTIMA = 9999


def imprimir_banner():
    print("=" * 70)
    print("   CYBERSHIELD PYME - BANCO DE PRUEBAS DE TRÁFICO REAL EN VIVO")
    print("   Detección Temprana con Redes Convolucionales 1D (Conv1D)")
    print("=" * 70)
    print(f" [*] IP Objetivo (Tu PC): {IP_LOCAL}:{PUERTO_VICTIMA}")
    print(f" [*] Monitor en Vivo:    http://localhost:8000/frontend/")
    print("=" * 70)


# --- Generadores de Tráfico ---
def ataque_udp_flood(paquetes=600, cadencia_ms=2):
    destino_valido = validar_ip_privada_o_local(IP_LOCAL)
    print(f"\n[>] Iniciando ATAQUE REAL UDP FLOOD: {paquetes} datagramas hacia {destino_valido}:{PUERTO_VICTIMA}...")

    payload_base = b"CYBERSHIELD_SECURITY_AUDIT_VOLUMETRIC_ATTACK_VECTOR_"
    bytes_totales = 0
    enviados = 0
    t_inicio = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            for i in range(1, paquetes + 1):
                relleno = os.urandom(random.randint(512, 1024))
                datos = payload_base + relleno
                sock.sendto(datos, (destino_valido, PUERTO_VICTIMA))
                enviados = i
                bytes_totales += len(datos)

                if i % 100 == 0 or i == paquetes:
                    transcurrido = max(1e-6, time.perf_counter() - t_inicio)
                    pps = int(i / transcurrido)
                    print(f"  -> [{i}/{paquetes}] paquetes transmitidos | {bytes_totales/1024:.1f} KB | {pps} paq/s")

                if cadencia_ms > 0:
                    time.sleep(cadencia_ms / 1000.0)
        except KeyboardInterrupt:
            print("\n[*] Envío interrumpido por el usuario.")

    duracion_real = max(1e-6, time.perf_counter() - t_inicio)
    duracion_mostrar = round(duracion_real, 3)
    tasa_pps = int(enviados / duracion_real) if enviados > 0 else 0

    print("\n" + "-" * 70)
    print("[+] Envío de prueba finalizado:")
    print(f"    - Paquetes físicos transmitidos: {enviados}")
    print(f"    - Volumen total de red:          {bytes_totales / 1024:.2f} KB")
    print(f"    - Tiempo transcurrido:           {duracion_mostrar} s")
    print(f"    - Tasa de transmisión:           {tasa_pps} paquetes/segundo")
    print("-" * 70)
    print("[*] Revisa ahora tu Monitor en Vivo para verificar la captura del sensor")
    print("    y la clasificación real emitida por el modelo Conv1D.")
    print("=" * 70)


def trafico_benigno_normal(paquetes=50):
    destino_valido = validar_ip_privada_o_local(IP_LOCAL)
    print(f"\n[>] Generando TRÁFICO BENIGNO LEGÍTIMO: {paquetes} solicitudes espaciadas hacia {destino_valido}:{PUERTO_VICTIMA}...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            for i in range(1, paquetes + 1):
                datos = f"PING_BENIGNO_LEGITIMO_SOLICITUD_{i}".encode("utf-8")
                sock.sendto(datos, (destino_valido, PUERTO_VICTIMA))
                if i % 10 == 0:
                    print(f"  -> Mensaje legítimo {i}/{paquetes} enviado...")
                time.sleep(0.12)
        except KeyboardInterrupt:
            print("\n[*] Envío benigno interrumpido por el usuario.")

    print("\n[+] Tráfico benigno enviado. Verifica en el monitor que permanezca sin falsas alarmas.")
    print("=" * 70)


# --- Punto de Entrada ---
def main():
    global IP_LOCAL
    if len(sys.argv) > 2:
        try:
            IP_LOCAL = validar_ip_privada_o_local(sys.argv[2])
        except ValueError as exc:
            print(f"[!] {exc}")
            sys.exit(1)

    imprimir_banner()
    print(" Selecciona el tipo de prueba que deseas ejecutar:")
    print("  [1] Ataque Real UDP Flood Volumétrico (Ráfaga de 600 paquetes a alta velocidad)")
    print("  [2] Ataque Intenso Rápido (1200 paquetes a máxima saturación)")
    print("  [3] Tráfico Benigno Legítimo (50 paquetes espaciados - Valida cero falsos positivos)")
    print("  [4] Salir")
    print("=" * 70)

    if len(sys.argv) > 1:
        opcion = sys.argv[1].strip()
    else:
        try:
            ip_ingresada = input(f" IP del Servidor CyberShield objetivo [Enter para {IP_LOCAL}]: ").strip()
            if ip_ingresada:
                IP_LOCAL = validar_ip_privada_o_local(ip_ingresada)
            else:
                IP_LOCAL = validar_ip_privada_o_local(IP_LOCAL)
            opcion = input(" Ingresa una opción (1, 2, 3 o 4) [Por defecto: 1]: ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Operación cancelada por el usuario.")
            return
        except ValueError as exc:
            print(f"\n[!] {exc}")
            sys.exit(1)

    try:
        IP_LOCAL = validar_ip_privada_o_local(IP_LOCAL)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    if opcion == "1":
        ataque_udp_flood(paquetes=600, cadencia_ms=2)
    elif opcion == "2":
        ataque_udp_flood(paquetes=1200, cadencia_ms=0.5)
    elif opcion == "3":
        trafico_benigno_normal(paquetes=50)
    else:
        print("[*] Operación cancelada.")


if __name__ == "__main__":
    main()
