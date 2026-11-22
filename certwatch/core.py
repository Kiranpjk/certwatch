"""Fetch TLS certificates from many endpoints and classify how close they are to expiry."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

OK, WARNING, CRITICAL, ERROR = "OK", "WARNING", "CRITICAL", "ERROR"
SEVERITY = {OK: 0, WARNING: 1, CRITICAL: 2, ERROR: 2}


@dataclass
class CertResult:
    target: str
    status: str
    days_left: float | None = None
    not_after: str | None = None
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def parse_target(target: str, default_port: int = 443) -> tuple[str, int]:
    """Accept 'host', 'host:port', '[v6]:port' and 'https://host[:port]/path'."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if t.count(":") == 1:
        host, port = t.split(":")
        return host, int(port)
    return t, default_port


def read_targets(lines) -> list[str]:
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        server_name = None if _is_ip(host) else host
        with ctx.wrap_socket(sock, server_hostname=server_name) as tls:
            return tls.getpeercert(binary_form=True)


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


def fetch_cert(host: str, port: int, timeout: float = 5.0, cafile: str | None = None) -> tuple[bytes, str | None]:
    """Return (DER certificate, verification error or None).

    If verification fails we still connect without verification so expiry can be reported.
    """
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        return _handshake(host, port, ctx, timeout), None
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
    insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    return _handshake(host, port, insecure, timeout), verify_error


def _name(name: x509.Name) -> str:
    cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(cn[0].value) if cn else name.rfc4514_string()


def classify(days_left: float, verify_error: str | None, warn_days: float, crit_days: float) -> str:
    if days_left <= crit_days or verify_error:
        return CRITICAL
    if days_left <= warn_days:
        return WARNING
    return OK


def check(
    target: str,
    warn_days: float = 30,
    crit_days: float = 7,
    timeout: float = 5.0,
    cafile: str | None = None,
    now: datetime | None = None,
) -> CertResult:
    now = now or datetime.now(timezone.utc)
    try:
        host, port = parse_target(target)
        der, verify_error = fetch_cert(host, port, timeout, cafile)
        cert = x509.load_der_x509_certificate(der)
    except (OSError, ValueError) as exc:  # DNS, refused, timeout, TLS errors, bad port
        return CertResult(target, ERROR, error=str(exc) or exc.__class__.__name__)

    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).total_seconds() / 86400
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_list = [str(v) for v in sans.get_values_for_type(x509.DNSName)]
        san_list += [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san_list = []
    error = verify_error
    if days_left < 0:
        error = f"expired {-days_left:.0f} day(s) ago"
    return CertResult(
        target=target,
        status=classify(days_left, verify_error, warn_days, crit_days),
        days_left=round(days_left, 1),
        not_after=not_after.isoformat(),
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        sans=san_list,
        error=error,
    )


def check_many(targets: list[str], workers: int = 16, **kwargs) -> list[CertResult]:
    """Check targets concurrently, preserving input order."""
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        return list(pool.map(lambda t: check(t, **kwargs), targets))


def worst(results: list[CertResult]) -> int:
    return max((SEVERITY[r.status] for r in results), default=0)
