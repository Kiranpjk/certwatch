# certwatch

[![CI](https://github.com/Kiranpjk/certwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiranpjk/certwatch/actions/workflows/ci.yml)

Check TLS certificate expiry across many hosts at once, and get a Slack or e-mail alert before
something breaks. One command, one hosts file, cron-friendly exit codes.

## The problem

Auto-renewal (certbot, ACME clients, Plesk, pfSense) fails quietly: a DNS change, a firewall rule
or a stuck renewal job, and nobody finds out until browsers start showing errors. Commercial
monitors cost money per host; internal and home-lab services often aren't monitored at all.

Community threads describing it:

- Let's Encrypt Community, "Certificate expired when it was set to renew" (Oct 2026): a cert on
  a Plesk-hosted domain expired even though auto-renewal was turned on.
  <https://community.letsencrypt.org/t/certificate-expired-when-it-was-set-to-renew/252034>
- Netgate Forum, "ACME not renewing one certificate as scheduled": pfSense renewed every
  certificate except one, which was getting close to expiry without any warning.
  <https://forum.netgate.com/topic/176296/acme-not-renewing-one-certificate-as-scheduled/1>

> Research note: the brief asked for Reddit threads (r/sysadmin, r/homelab). Reddit was not
> reachable from the environment this was built in (blocked by the network proxy, and not
> returned by the search tool), so these are the closest verified public threads.

## What it checks

- Days until `notAfter`: `WARNING` under `--warn` (30) days, `CRITICAL` under `--crit` (7) days or expired.
- Chain and hostname verification (`CRITICAL` on self-signed, unknown issuer or hostname mismatch).
  The expiry date is still read in those cases, by reconnecting without verification.
- Connection problems (DNS, refused, timeout, TLS failure) are reported as `ERROR`.
- Hosts are checked concurrently (`--workers`, default 16), and SNI is sent for hostnames.

## Demo

Real local run. The servers are local TLS endpoints on 127.0.0.1, using certificates from a
throwaway "Homelab Root CA" with different lifetimes (made with the helpers in
`tests/conftest.py`). A tiny local HTTP server stood in for the Slack webhook. (The build
sandbox couldn't make direct TLS connections to public hosts, which is why the endpoints are local.)

```console
$ cat hosts.txt
# homelab services
localhost:9441   # grafana
localhost:9442   # nextcloud
localhost:9443   # vaultwarden
localhost:9444   # old NAS UI
localhost:9445   # proxmox (cert issued for pve.lan)
localhost:9446   # router, self-signed
localhost:9447   # nothing listening

$ certwatch -f hosts.txt --cafile ca.pem --slack-webhook http://127.0.0.1:9900/hook
STATUS      DAYS  EXPIRES     TARGET                           ISSUER                   NOTE
ERROR          -  -           localhost:9447                   -                        [Errno 111] Connection refused
CRITICAL      -5  2026-11-17  localhost:9444                   Homelab Root CA          expired 5 day(s) ago
CRITICAL       4  2026-11-26  localhost:9443                   Homelab Root CA
WARNING       18  2026-12-10  localhost:9442                   Homelab Root CA
OK            80  2027-02-10  localhost:9441                   Homelab Root CA
CRITICAL      89  2027-02-19  localhost:9445                   Homelab Root CA          Hostname mismatch, certificate is not valid for 'localhost'.
CRITICAL      89  2027-02-19  localhost:9446                   router-selfsigned        self-signed certificate
sent Slack alert for 6 target(s)
$ echo $?
2
```

Message received by the webhook:

```text
*certwatch: 6 certificate problem(s)*
:x: localhost:9447: could not check ([Errno 111] Connection refused)
:rotating_light: localhost:9444: CRITICAL, EXPIRED on 2026-11-17
:rotating_light: localhost:9443: CRITICAL, expires in 4 days on 2026-11-26
:warning: localhost:9442: WARNING, expires in 18 days on 2026-12-10
:rotating_light: localhost:9445: CRITICAL, expires in 89 days on 2027-02-19 (Hostname mismatch, certificate is not valid for 'localhost'.)
:rotating_light: localhost:9446: CRITICAL, expires in 89 days on 2027-02-19 (self-signed certificate)
```

JSON output for scripts and dashboards:

```console
$ certwatch localhost:9441 --cafile ca.pem --json
[
  {
    "target": "localhost:9441",
    "status": "OK",
    "days_left": 80.0,
    "not_after": "2027-02-10T23:52:10+00:00",
    "subject": "grafana",
    "issuer": "Homelab Root CA",
    "sans": [
      "localhost"
    ],
    "error": null
  }
]
```

## Install

```bash
pip install git+https://github.com/Kiranpjk/certwatch.git
```

Requires Python 3.10+ and `cryptography`.

## Usage

```bash
certwatch example.com api.example.com:8443 https://shop.example.com/
certwatch -f hosts.txt --warn 21 --crit 5
certwatch -f internal.txt --cafile /etc/ssl/internal-ca.pem   # trust an internal CA
certwatch -f hosts.txt --json > certs.json
```

Exit codes: `0` all OK, `1` at least one WARNING, `2` at least one CRITICAL or ERROR, `3` usage error.
That makes it easy to use from cron, CI or a Nagios/Icinga-style check.

### Alerts

Alerts are only sent when something is wrong (`--alert-on WARNING` by default, or `CRITICAL`).

```bash
# Slack incoming webhook
export CERTWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/...
certwatch -f hosts.txt

# E-mail via SMTP (STARTTLS by default; password only from the environment)
export CERTWATCH_SMTP_PASSWORD=...
certwatch -f hosts.txt --smtp-host smtp.example.com --smtp-user alerts@example.com \
  --email-from alerts@example.com --email-to ops@example.com
```

Daily cron job:

```cron
0 7 * * * CERTWATCH_SLACK_WEBHOOK=https://hooks.slack.com/services/... /usr/local/bin/certwatch -f /etc/certwatch/hosts.txt >/dev/null
```

## Run with Docker

```bash
docker build -t certwatch .
docker run --rm -v "$PWD/hosts.txt:/config/hosts.txt:ro" -e CERTWATCH_SLACK_WEBHOOK certwatch -f hosts.txt
# published image
docker run --rm ghcr.io/kiranpjk/certwatch:main example.com
```

## CI/CD

- `.github/workflows/ci.yml`: `ruff check`, `ruff format --check`, `pytest` on Python 3.10 to 3.13,
  then a Docker build plus `--version` smoke test. The tests start real local TLS servers with
  generated certificates (healthy, expiring, expired, self-signed, wrong hostname) and a local
  webhook receiver, so the whole path is exercised without network access.
- `.github/workflows/release.yml`: on pushes to `main` and `v*` tags, builds a multi-arch
  (amd64/arm64) image and pushes it to `ghcr.io/kiranpjk/certwatch` with the built-in `GITHUB_TOKEN`.
- `.github/dependabot.yml`: weekly updates for pip, GitHub Actions and the Docker base image.

## Development

```bash
pip install -e '.[dev]'
ruff check . && ruff format --check .
pytest -v
```

## License

MIT, see [LICENSE](LICENSE).
