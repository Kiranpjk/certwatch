"""Test fixtures: a throwaway CA and local TLS servers with certificates of chosen validity."""

import ipaddress
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, issuer_cert=None, issuer_key=None, days_valid=90, days_ago=1, sans=("localhost",), ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer_cert.subject if issuer_cert else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_ago))
        .not_valid_after(now - timedelta(days=days_ago) + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        # Python 3.13+ verifies in strict mode, which requires an Authority Key Identifier.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
    if sans:
        names = [
            x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() else x509.DNSName(s)  # noqa: B023
            for s in sans
        ]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def write_pem(path, cert, key=None):
    data = cert.public_bytes(serialization.Encoding.PEM)
    if key is not None:
        data += key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    path.write_bytes(data)
    return str(path)


def serve_tls(certfile):
    """Start a TLS server on 127.0.0.1 that completes handshakes then closes. Returns the port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile)
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=loop, daemon=True).start()
    return srv, port


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    """CA file plus servers: healthy, expiring soon, expired, self-signed, wrong hostname."""
    d = tmp_path_factory.mktemp("pki")
    ca_cert, ca_key = make_cert("Test Root CA", days_valid=3650, sans=(), ca=True)
    cafile = write_pem(d / "ca.pem", ca_cert)
    specs = {
        "healthy": dict(days_valid=90, days_ago=10),  # 80 days left
        "soon": dict(days_valid=90, days_ago=70),  # 20 days left
        "urgent": dict(days_valid=90, days_ago=87),  # 3 days left
        "expired": dict(days_valid=90, days_ago=95),
        "wronghost": dict(sans=("other.example",)),
    }
    servers, ports = [], {}
    for name, kw in specs.items():
        cert, key = make_cert(name, ca_cert, ca_key, **kw)
        srv, ports[name] = serve_tls(write_pem(d / f"{name}.pem", cert, key))
        servers.append(srv)
    cert, key = make_cert("selfsigned")
    srv, ports["selfsigned"] = serve_tls(write_pem(d / "selfsigned.pem", cert, key))
    servers.append(srv)
    yield {"cafile": cafile, "ports": ports}
    for s in servers:
        s.close()
