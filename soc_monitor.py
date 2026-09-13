#!/usr/bin/env python3
"""
SOC L1 Alert Monitoring & Reporting Tool
==========================================
Monitors alert logs (JSON/CSV) and suspicious emails (.eml), analyzes them
with rule-based detection, and generates a Markdown case report per item.

Usage:
    python soc_monitor.py --scan          # process everything currently in the folders once
    python soc_monitor.py --watch         # keep running, process new files as they appear
    python soc_monitor.py --scan --watch  # scan existing, then keep watching

Folders (see config.py):
    sample_logs/    -> put .json (JSONL, one alert object per line) or .csv alert files here
    sample_emails/  -> put .eml email files here
    reports/        -> generated case reports appear here, plus _index.md
"""

import argparse
import csv
import json
import os
import time

import config
from analyzers import analyze_log_alert, analyze_email
from reporter import write_log_alert_report, write_email_report

PROCESSED_MARKER_DIR = ".processed"


def _mark_processed(path):
    os.makedirs(PROCESSED_MARKER_DIR, exist_ok=True)
    marker = os.path.join(PROCESSED_MARKER_DIR, path.replace(os.sep, "__") + ".done")
    open(marker, "w").close()


def _already_processed(path):
    marker = os.path.join(PROCESSED_MARKER_DIR, path.replace(os.sep, "__") + ".done")
    return os.path.exists(marker)


def process_log_file(path):
    alerts = []
    if path.endswith(".json"):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
    elif path.endswith(".csv"):
        with open(path, newline="") as f:
            alerts.extend(list(csv.DictReader(f)))
    else:
        return

    for alert in alerts:
        findings = analyze_log_alert(alert)
        report_path = write_log_alert_report(alert, findings)
        print(f"  [LOG]   Alert {alert.get('alert_id', '?')}: {findings['severity']} -> {report_path}")


def process_email_file(path):
    findings = analyze_email(path)
    report_path = write_email_report(path, findings)
    print(f"  [EMAIL] {os.path.basename(path)}: {findings['severity']} -> {report_path}")


def scan_once():
    print(f"Scanning {config.LOGS_DIR}/ and {config.EMAILS_DIR}/ ...")
    for fname in sorted(os.listdir(config.LOGS_DIR)):
        fpath = os.path.join(config.LOGS_DIR, fname)
        if os.path.isfile(fpath) and not _already_processed(fpath) and fname.endswith((".json", ".csv")):
            process_log_file(fpath)
            _mark_processed(fpath)

    for fname in sorted(os.listdir(config.EMAILS_DIR)):
        fpath = os.path.join(config.EMAILS_DIR, fname)
        if os.path.isfile(fpath) and not _already_processed(fpath) and fname.endswith(".eml"):
            process_email_file(fpath)
            _mark_processed(fpath)
    print("Scan complete. See reports/_index.md for the case list.")


def watch(poll_seconds=5):
    print(f"Watching {config.LOGS_DIR}/ and {config.EMAILS_DIR}/ for new files (Ctrl+C to stop)...")
    try:
        while True:
            scan_once()
            time.sleep(poll_seconds)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    parser = argparse.ArgumentParser(description="SOC L1 Alert Monitoring & Reporting Tool")
    parser.add_argument("--scan", action="store_true", help="Process all files currently present, once")
    parser.add_argument("--watch", action="store_true", help="Keep running and process new files as they arrive")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds for --watch (default: 5)")
    args = parser.parse_args()

    os.makedirs(config.LOGS_DIR, exist_ok=True)
    os.makedirs(config.EMAILS_DIR, exist_ok=True)
    os.makedirs(config.REPORTS_DIR, exist_ok=True)

    if not args.scan and not args.watch:
        args.scan = True  # default behavior

    if args.scan:
        scan_once()
    if args.watch:
        watch(args.interval)


if __name__ == "__main__":
    main()
