#!/usr/bin/env python3
"""
File: sids.py
Author: Robert Kralle
Project: CYB333_FinalProject_Hybrid_IDS_Honeypot
Due Date: October 26th, 2025

Academic Honesty Statement:
  This code was developed by Robert Kralle for the CYB333 Security Automation Final Project.
  All work is my own, except where I used approved AI tools (ChatGPT, GitHub Copilot, Grammarly)
  for code refinement, documentation clarity, and syntax review. No unauthorized collaboration
  or code reuse occurred.

Purpose:
  Simple IDS that tails the honeypot CSV log and raises alerts for
  port scan patterns and burst connections from the same source IP.
  Alerts are printed to console and appended to a separate alerts log.

Usage:
  python sids.py
  python sids.py --config config.json
  python sids.py --log data/honeypot.log --alerts data/alerts.log \
                 --scan_ports 5 --scan_window 15 --burst_hits 10 --burst_window 10

How it works:
  Reads appended lines from the honeypot CSV log.
  Maintains per-IP sliding windows to track distinct destination ports and total hits.
  Triggers alerts when thresholds are met.

Input CSV Schema:
  ts,src_ip,src_port,dst_port,bytes,preview
"""
import argparse
import collections
import datetime
import json
import os
import time
from typing import Deque, Dict, Tuple

AUTHOR = "Robert Kralle"
PROJECT = "CYB333_FinalProject_Hybrid_IDS_Honeypot"
DUE_DATE = "October 26th, 2025"


def load_config(path: str) -> dict:
    """Loads config and returns defaults if missing."""
    defaults = {
        "log_path": "data/honeypot.log",
        "alert_log_path": "data/alerts.log",
        "sids": {
            "port_scan_threshold_ports": 5,
            "port_scan_window_seconds": 15,
            "burst_conn_threshold": 10,
            "burst_conn_window_seconds": 10
        }
    }
    if not path:
        return defaults
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return {**defaults, **cfg}
    except FileNotFoundError:
        print(f"[!] Config file not found at {path}. Using defaults.")
        return defaults
    except Exception as e:
        print(f"[!] Failed to read config {path}: {e}. Using defaults.")
        return defaults


def ensure_alert_log(alert_log_path: str) -> None:
    """Ensures alerts log directory exists."""
    os.makedirs(os.path.dirname(alert_log_path), exist_ok=True)


def write_alert(alert_log_path: str, message: str) -> None:
    """Writes an alert line with an ISO timestamp and prints it."""
    stamp = datetime.datetime.utcnow().isoformat()
    line = f"{stamp} ALERT {message}\n"
    with open(alert_log_path, "a", encoding="utf-8") as f:
        f.write(line)
    print(line.strip())


def parse_honeypot_line(line: str) -> Tuple[str, int]:
    """
    Parses a CSV line from the honeypot log and returns (src_ip, dst_port).
    Returns a tuple with None if the line is malformed.
    """
    try:
        parts = line.rstrip("\n").split(",", 5)
        if len(parts) < 5:
            return None, None  # type: ignore
        src_ip = parts[1]
        dst_port = int(parts[3])
        return src_ip, dst_port
    except Exception:
        return None, None  # type: ignore


def tail_file(path: str):
    """Generator that yields new lines as the file grows."""
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def parse_args() -> argparse.Namespace:
    """Command-line interface for overrides."""
    p = argparse.ArgumentParser(description="Simple IDS that watches honeypot log and raises alerts")
    p.add_argument("--config", help="Path to JSON config file", default=None)
    p.add_argument("--log", help="Override honeypot log path", default=None)
    p.add_argument("--alerts", help="Override alerts log path", default=None)
    p.add_argument("--scan_ports", type=int, help="Port scan threshold of distinct ports", default=None)
    p.add_argument("--scan_window", type=int, help="Port scan time window in seconds", default=None)
    p.add_argument("--burst_hits", type=int, help="Burst connections threshold", default=None)
    p.add_argument("--burst_window", type=int, help="Burst connections time window in seconds", default=None)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)

    log_path = args.log or cfg.get("log_path", "data/honeypot.log")
    alert_log_path = args.alerts or cfg.get("alert_log_path", "data/alerts.log")

    sids_cfg = cfg.get("sids", {})
    scan_ports = args.scan_ports or sids_cfg.get("port_scan_threshold_ports", 5)
    scan_window = args.scan_window or sids_cfg.get("port_scan_window_seconds", 15)
    burst_hits = args.burst_hits or sids_cfg.get("burst_conn_threshold", 10)
    burst_window = args.burst_window or sids_cfg.get("burst_conn_window_seconds", 10)

    ensure_alert_log(alert_log_path)

    print(f"[INFO] Author: {AUTHOR}")
    print(f"[INFO] Project: {PROJECT}")
    print(f"[INFO] Due Date: {DUE_DATE}")
    print(f"[INFO] Honeypot log: {log_path}")
    print(f"[INFO] Alerts log: {alert_log_path}")
    print(f"[INFO] Thresholds -> scan_ports={scan_ports} scan_window={scan_window}s "
          f"burst_hits={burst_hits} burst_window={burst_window}s")

    per_ip_ports: Dict[str, Deque[Tuple[float, int]]] = collections.defaultdict(collections.deque)
    per_ip_hits: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)

    if not os.path.exists(log_path):
        print("[SIDS] Waiting for honeypot log to be created...")
        while not os.path.exists(log_path):
            time.sleep(0.5)

    print("[SIDS] Monitoring for new events...")
    for line in tail_file(log_path):
        src_ip, dst_port = parse_honeypot_line(line)
        if not src_ip:
            continue

        now = time.time()

        dq_ports = per_ip_ports[src_ip]
        dq_ports.append((now, dst_port))
        while dq_ports and now - dq_ports[0][0] > scan_window:
            dq_ports.popleft()
        distinct_ports = {p for _, p in dq_ports}
        if len(distinct_ports) >= scan_ports:
            write_alert(alert_log_path,
                        f"Possible port scan by {src_ip}. Distinct ports in {scan_window}s >= {scan_ports}")
            dq_ports.clear()

        dq_hits = per_ip_hits[src_ip]
        dq_hits.append(now)
        while dq_hits and now - dq_hits[0] > burst_window:
            dq_hits.popleft()
        if len(dq_hits) >= burst_hits:
            write_alert(alert_log_path,
                        f"Burst connections by {src_ip}. Hits in {burst_window}s >= {burst_hits}")
            dq_hits.clear()


if __name__ == "__main__":
    main()