"""Command-line entry point for certwatch."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .alerts import problems, send_email, send_slack
from .core import check_many, read_targets, worst


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certwatch",
        description="Check TLS certificate expiry across many hosts and alert via Slack or e-mail.",
    )
    p.add_argument("targets", nargs="*", help="host, host:port or https:// URL")
    p.add_argument("-f", "--file", help="file with one target per line ('#' comments allowed)")
    p.add_argument("--warn", type=float, default=30, metavar="DAYS", help="warn below this many days (default 30)")
    p.add_argument("--crit", type=float, default=7, metavar="DAYS", help="critical below this many days (default 7)")
    p.add_argument("--timeout", type=float, default=5, help="per-host timeout in seconds (default 5)")
    p.add_argument("--workers", type=int, default=16, help="concurrent checks (default 16)")
    p.add_argument("--cafile", help="extra CA bundle, e.g. for an internal CA")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    a = p.add_argument_group("alerting (only sent when something is wrong)")
    a.add_argument("--alert-on", choices=["WARNING", "CRITICAL"], default="WARNING")
    a.add_argument(
        "--slack-webhook", default=os.environ.get("CERTWATCH_SLACK_WEBHOOK"), help="or $CERTWATCH_SLACK_WEBHOOK"
    )
    a.add_argument("--smtp-host", default=os.environ.get("CERTWATCH_SMTP_HOST"))
    a.add_argument("--smtp-port", type=int, default=int(os.environ.get("CERTWATCH_SMTP_PORT", "587")))
    a.add_argument("--smtp-user", default=os.environ.get("CERTWATCH_SMTP_USER"))
    a.add_argument("--no-starttls", action="store_true", help="plain SMTP (e.g. local relay)")
    a.add_argument("--email-from", default=os.environ.get("CERTWATCH_EMAIL_FROM", "certwatch@localhost"))
    a.add_argument("--email-to", action="append", default=[], metavar="ADDR", help="repeatable")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def print_table(results) -> None:
    print(f"{'STATUS':<9} {'DAYS':>6}  {'EXPIRES':<10}  {'TARGET':<32} {'ISSUER':<24} NOTE")
    for r in results:
        days = f"{r.days_left:.0f}" if r.days_left is not None else "-"
        exp = r.not_after[:10] if r.not_after else "-"
        print(f"{r.status:<9} {days:>6}  {exp:<10}  {r.target[:32]:<32} {(r.issuer or '-')[:24]:<24} {r.error or ''}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            targets += read_targets(fh)
    if not targets:
        print("error: no targets given (pass hosts or -f FILE)", file=sys.stderr)
        return 3

    results = check_many(
        targets,
        workers=args.workers,
        warn_days=args.warn,
        crit_days=args.crit,
        timeout=args.timeout,
        cafile=args.cafile,
    )
    results.sort(key=lambda r: (r.days_left is not None, r.days_left or 0))  # errors first, then soonest expiry
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print_table(results)

    bad = problems(results, args.alert_on)
    if bad and args.slack_webhook:
        try:
            send_slack(args.slack_webhook, bad)
            print(f"sent Slack alert for {len(bad)} target(s)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - alerting must not hide the check result
            print(f"Slack alert failed: {exc}", file=sys.stderr)
    if bad and args.smtp_host and args.email_to:
        try:
            send_email(
                bad,
                args.smtp_host,
                args.smtp_port,
                args.email_from,
                args.email_to,
                args.smtp_user,
                os.environ.get("CERTWATCH_SMTP_PASSWORD"),
                starttls=not args.no_starttls,
            )
            print(f"sent e-mail alert to {', '.join(args.email_to)}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"e-mail alert failed: {exc}", file=sys.stderr)
    return worst(results)


if __name__ == "__main__":
    sys.exit(main())
