import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from certwatch.alerts import build_email, describe, problems, send_slack
from certwatch.cli import main
from certwatch.core import CRITICAL, ERROR, OK, WARNING, CertResult, check, classify, parse_target, read_targets


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("https://example.com/path", ("example.com", 443)),
        ("https://example.com:9443/x", ("example.com", 9443)),
        ("[::1]:8443", ("::1", 8443)),
        ("[::1]", ("::1", 443)),
    ],
)
def test_parse_target(raw, expected):
    assert parse_target(raw) == expected


def test_read_targets_skips_comments():
    assert read_targets(["# prod", "a.com", "", "b.com:8443  # api", "   "]) == ["a.com", "b.com:8443"]


def test_classify():
    assert classify(80, None, 30, 7) == OK
    assert classify(20, None, 30, 7) == WARNING
    assert classify(3, None, 30, 7) == CRITICAL
    assert classify(80, "self-signed", 30, 7) == CRITICAL


def t(pki, name):
    return f"localhost:{pki['ports'][name]}"


@pytest.mark.parametrize(
    "name,status,days",
    [("healthy", OK, 80), ("soon", WARNING, 20), ("urgent", CRITICAL, 3), ("expired", CRITICAL, -5)],
)
def test_check_against_real_tls_servers(pki, name, status, days):
    r = check(t(pki, name), cafile=pki["cafile"])
    assert r.status == status
    assert abs(r.days_left - days) < 0.1
    assert r.issuer == "Test Root CA" and r.subject == name


def test_expired_has_error_message(pki):
    assert "expired 5 day(s) ago" in check(t(pki, "expired"), cafile=pki["cafile"]).error


def test_untrusted_and_wrong_host_are_critical_but_expiry_still_read(pki):
    r = check(t(pki, "selfsigned"), cafile=pki["cafile"])
    assert r.status == CRITICAL and r.days_left > 80 and "self" in r.error.lower()
    r = check(t(pki, "wronghost"), cafile=pki["cafile"])
    assert r.status == CRITICAL and "hostname" in r.error.lower() and r.sans == ["other.example"]


def test_connection_refused_is_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = check(f"127.0.0.1:{port}", timeout=1)
    assert r.status == ERROR and r.error


def test_problems_filter():
    rs = [CertResult("a", OK), CertResult("b", WARNING), CertResult("c", CRITICAL), CertResult("d", ERROR)]
    assert [r.target for r in problems(rs)] == ["b", "c", "d"]
    assert [r.target for r in problems(rs, "CRITICAL")] == ["c", "d"]


def test_email_body():
    r = CertResult("a.com", WARNING, days_left=12.3, not_after="2026-12-05T00:00:00+00:00")
    msg = build_email([r], "me@x", ["ops@x", "sre@x"])
    assert msg["To"] == "ops@x, sre@x" and "a.com: WARNING, expires in 12 days on 2026-12-05" in msg.get_content()


@pytest.fixture
def slack_server():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/hook", received
    srv.shutdown()


def test_send_slack(slack_server):
    url, received = slack_server
    send_slack(url, [CertResult("x.com", ERROR, error="timed out")])
    assert "x.com: could not check (timed out)" in received[0]["text"]


def test_cli_end_to_end(pki, slack_server, tmp_path, capsys):
    url, received = slack_server
    hosts = tmp_path / "hosts.txt"
    hosts.write_text(f"# test\n{t(pki, 'healthy')}\n{t(pki, 'soon')}\n")
    assert main(["-f", str(hosts), "--cafile", pki["cafile"], "--slack-webhook", url]) == 1
    out = capsys.readouterr().out
    assert out.index(t(pki, "soon")) < out.index(t(pki, "healthy"))  # sorted by days left
    assert len(received) == 1
    assert t(pki, "soon") in received[0]["text"] and t(pki, "healthy") not in received[0]["text"]

    assert main([t(pki, "healthy"), "--cafile", pki["cafile"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["status"] == "OK"
    assert main([t(pki, "urgent"), "--cafile", pki["cafile"]]) == 2


def test_cli_requires_targets(capsys):
    assert main([]) == 3


def test_describe_expired():
    r = CertResult("old.lan", CRITICAL, days_left=-5, not_after="2026-11-17T00:00:00+00:00", error="expired")
    assert describe(r) == "old.lan: CRITICAL, EXPIRED on 2026-11-17"
