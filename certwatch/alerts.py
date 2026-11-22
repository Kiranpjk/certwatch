"""Send alert summaries to Slack (incoming webhook) or e-mail (SMTP)."""

from __future__ import annotations

import json
import smtplib
import urllib.request
from email.message import EmailMessage

from .core import OK, CertResult

ICONS = {"WARNING": ":warning:", "CRITICAL": ":rotating_light:", "ERROR": ":x:"}


def describe(r: CertResult) -> str:
    if r.status == "ERROR":
        return f"{r.target}: could not check ({r.error})"
    if r.days_left < 0:
        return f"{r.target}: {r.status}, EXPIRED on {r.not_after[:10]}"
    detail = f" ({r.error})" if r.error else ""
    return f"{r.target}: {r.status}, expires in {r.days_left:.0f} days on {r.not_after[:10]}{detail}"


def problems(results: list[CertResult], min_status: str = "WARNING") -> list[CertResult]:
    order = ["OK", "WARNING", "CRITICAL"]
    floor = order.index("CRITICAL" if min_status == "CRITICAL" else "WARNING")
    return [r for r in results if r.status != OK and (r.status == "ERROR" or order.index(r.status) >= floor)]


def send_slack(webhook_url: str, items: list[CertResult], timeout: float = 10) -> None:
    lines = [f"{ICONS.get(r.status, '')} {describe(r)}" for r in items]
    payload = {"text": f"*certwatch: {len(items)} certificate problem(s)*\n" + "\n".join(lines)}
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL comes from the operator
        if resp.status >= 300:
            raise RuntimeError(f"Slack webhook returned HTTP {resp.status}")


def build_email(items: list[CertResult], sender: str, recipients: list[str]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[certwatch] {len(items)} certificate problem(s)"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content("\n".join(describe(r) for r in items) + "\n")
    return msg


def send_email(
    items: list[CertResult],
    host: str,
    port: int,
    sender: str,
    recipients: list[str],
    username: str | None = None,
    password: str | None = None,
    starttls: bool = True,
) -> None:
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if starttls:
            smtp.starttls()
        if username:
            smtp.login(username, password or "")
        smtp.send_message(build_email(items, sender, recipients))
