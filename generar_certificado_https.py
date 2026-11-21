import datetime
import ipaddress
import os
import socket
import subprocess

# --- Configuración de Rutas ---
DIRECTORIO_BASE = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_CERTS = os.path.join(DIRECTORIO_BASE, "backend", "certs")
VIGENCIA_DIAS_TLS = 365  # <= 398 días exigidos por navegadores modernos


def obtener_ip_lan() -> str:
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


def _restringir_permisos_clave_privada(ruta_key: str) -> None:
    try:
        os.chmod(ruta_key, 0o600)
    except Exception:
        pass
    if os.name == "nt":
        try:
            usuario = os.getenv("USERNAME") or ""
            if usuario:
                subprocess.run(
                    [
                        "icacls",
                        ruta_key,
                        "/inheritance:r",
                        "/grant:r",
                        f"{usuario}:(R,W)",
                        "Administrators:(F)",
                        "SYSTEM:(F)",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
        except Exception:
            pass


# --- Generación de Certificados TLS/HTTPS ---
def generar_certificados(dias_validez: int = VIGENCIA_DIAS_TLS) -> tuple[str, str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        raise SystemExit(
            "Instale la librería cryptography para generar certificados TLS: pip install cryptography"
        )

    dias = max(1, min(int(dias_validez), 397))
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
        if ip_obj != ipaddress.IPv4Address("127.0.0.1"):
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
        .not_valid_before(ahora - datetime.timedelta(minutes=5))
        .not_valid_after(ahora + datetime.timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(nombres_alternativos), critical=False)
        .sign(clave_privada, hashes.SHA256())
    )

    with open(ruta_key, "wb") as f_key:
        f_key.write(
            clave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    _restringir_permisos_clave_privada(ruta_key)

    with open(ruta_cert, "wb") as f_cert:
        f_cert.write(certificado.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] Certificados TLS/HTTPS generados ({dias} días) para localhost y {ip_lan}:")
    print(f"     Certificado: {ruta_cert}")
    print(f"     Clave:       {ruta_key} (permisos restringidos)")
    print("Para activar HTTPS, descomenta SSL_CERTFILE y SSL_KEYFILE en .env y reinicia el servicio.")
    return ruta_cert, ruta_key


if __name__ == "__main__":
    generar_certificados()
