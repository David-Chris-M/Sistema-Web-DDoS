import os
import random
import socket
import sys
import time


# --- Configuración de Red ---
def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.18.10"


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
    print(f"\n[>] Iniciando ATAQUE REAL UDP FLOOD: {paquetes} datagramas hacia {IP_LOCAL}:{PUERTO_VICTIMA}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    payload_base = b"CYBERSHIELD_SECURITY_AUDIT_VOLUMETRIC_ATTACK_VECTOR_"
    bytes_totales = 0
    t_inicio = time.time()

    for i in range(1, paquetes + 1):
        relleno = os.urandom(random.randint(512, 1024))
        datos = payload_base + relleno
        sock.sendto(datos, (IP_LOCAL, PUERTO_VICTIMA))
        bytes_totales += len(datos)

        if i % 100 == 0 or i == paquetes:
            pps = int(i / max(0.001, time.time() - t_inicio))
            print(f"  -> [{i}/{paquetes}] paquetes transmitidos | {bytes_totales/1024:.1f} KB | {pps} paq/s")

        if cadencia_ms > 0:
            time.sleep(cadencia_ms / 1000.0)

    duracion = round(time.time() - t_inicio, 3)
    sock.close()

    print("\n" + "-" * 70)
    print(f"[+] Ataque completado con éxito:")
    print(f"    - Paquetes físicos transmitidos: {paquetes}")
    print(f"    - Volumen total de red:          {bytes_totales / 1024:.2f} KB")
    print(f"    - Tiempo transcurrido:           {duracion} s")
    print(f"    - Tasa de transmisión:           {int(paquetes / duracion)} paquetes/segundo")
    print("-" * 70)
    print("[*] Revisa ahora tu Monitor en Vivo: el sensor capturó este flujo físico,")
    print("    el modelo Conv1D procesó el lote y activó la alerta roja acústica y visual.")
    print("=" * 70)


def trafico_benigno_normal(paquetes=50):
    print(f"\n[>] Generando TRÁFICO BENIGNO LEGÍTIMO: {paquetes} solicitudes espaciadas...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(1, paquetes + 1):
        datos = f"PING_BENIGNO_LEGITIMO_SOLICITUD_{i}".encode("utf-8")
        sock.sendto(datos, (IP_LOCAL, PUERTO_VICTIMA))
        if i % 10 == 0:
            print(f"  -> Mensaje legítimo {i}/{paquetes} enviado...")
        time.sleep(0.12)

    sock.close()
    print("\n[+] Tráfico benigno enviado. El sistema debe permanecer en RED SEGURA (sin alarmas).")
    print("=" * 70)


# --- Punto de Entrada ---
def main():
    global IP_LOCAL
    if len(sys.argv) > 2:
        IP_LOCAL = sys.argv[2].strip()
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
                IP_LOCAL = ip_ingresada
            opcion = input(" Ingresa una opción (1, 2, 3 o 4) [Por defecto: 1]: ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            opcion = "1"

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
