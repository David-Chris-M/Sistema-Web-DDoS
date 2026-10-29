import datetime
import ipaddress
import os
import socket

# --- Configuración de Rutas ---
DIRECTORIO_BASE = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_CERTS = os.path.join(DIRECTORIO_BASE, "backend", "certs")


def obtener_ip_lan() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# --- Generación de Certificados TLS/HTTPS ---
def generar_certificados() -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise SystemExit(
            "Instale la librería cryptography para generar certificados TLS: pip install cryptography"
        )

    os.makedirs(DIRECTORIO_CERTS, exist_ok=True)
    ruta_cert = os.path.join(DIRECTORIO_CERTS, "cert.pem")
    ruta_key = os.path.join(DIRECTORIO_CERTS, "key.pem")

    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ip_lan = obtener_ip_lan()

    sujeto = emisor = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberShield Pyme NIDS"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    nombres_alternativos = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        ip_obj = ipaddress.IPv4Address(ip_lan)
        if ip_obj not in (ipaddress.IPv4Address("127.0.0.1"),):
            nombres_alternativos.append(x509.IPAddress(ip_obj))
    except ValueError:
        pass

    ahora = datetime.datetime.now(datetime.timezone.utc)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(emisor)
        .public_key(clave_privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - datetime.timedelta(days=1))
        .not_valid_after(ahora + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(nombres_alternativos), critical=False)
        .sign(clave_privada, hashes.SHA256())
    )

    with open(ruta_key, "wb") as f_key:
        f_key.write(
            clave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(ruta_cert, "wb") as f_cert:
        f_cert.write(certificado.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Certificados TLS/HTTPS generados para localhost y {ip_lan}:")
    print(f"     Certificado: {ruta_cert}")
    print(f"     Clave:       {ruta_key}")
    print("Para iniciar Uvicorn con HTTPS:")
    print("  python -m uvicorn backend.principal:aplicacion --host 0.0.0.0 --port 8000 --ssl-keyfile backend/certs/key.pem --ssl-certfile backend/certs/cert.pem")


if __name__ == "__main__":
    generar_certificados()
