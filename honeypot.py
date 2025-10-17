#!/usr/bin/env python3
"""
File: honeypot.py
Author: Robert Kralle
Project: CYB333_FinalProject_Hybrid_IDS_Honeypot
Due Date: October 26th, 2025

Academic Honesty Statement:
  This code was developed by Robert Kralle for the CYB333 Security Automation Final Project.
  All work is my own, except where I used approved AI tools (ChatGPT, GitHub Copilot, Grammarly)
  for code refinement, documentation clarity, and syntax review. No unauthorized collaboration
  or code reuse occurred.

Purpose:
  Minimal TCP honeypot for the Hybrid IDS + Honeypot project.
  Listens on configurable TCP ports, accepts connections, sends simple banners,
  and logs each connection as a CSV row. The log is consumed by sids.py.

Usage:
  python honeypot.py
  python honeypot.py --config config.json
  python honeypot.py --bind 127.0.0.1 --ports 8022 8080 33060 --log data/honeypot.log

Security Notes:
  Run on localhost for testing. Do not expose this to public networks.
  Use high ports to avoid privilege requirements.

CSV Schema:
  ts,src_ip,src_port,dst_port,bytes,preview

Exit:
  Ctrl+C to stop.
"""
import argparse
import datetime
import json
import os
import socket
import threading
from typing import List, Tuple

AUTHOR = "Robert Kralle"
PROJECT = "CYB333_FinalProject_Hybrid_IDS_Honeypot"
DUE_DATE = "October 26th, 2025"


def load_config(path: str) -> dict:
    """Loads JSON config if present, otherwise returns sane defaults."""
    defaults = {
        "bind_host": "127.0.0.1",
        "ports": [8022, 8080, 33060],
        "log_path": "data/honeypot.log",
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


def ensure_log_header(log_path: str) -> None:
    """Creates log directory and CSV header if missing."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    if not os.path.exists(log_path):
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("ts,src_ip,src_port,dst_port,bytes,preview\n")


def log_event(log_path: str, addr: Tuple[str, int], dst_port: int, preview: str) -> None:
    """Writes a single CSV row to the honeypot log and prints a concise console line."""
    ts = datetime.datetime.utcnow().isoformat()
    src_ip, src_port = addr
    safe_preview = (preview or "")[:20].replace("\n", "\\n").replace(",", ";")
    line = f"{ts},{src_ip},{src_port},{dst_port},{len(preview or '')},{safe_preview}\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)
    print(f"[HONEYPOT] {src_ip}:{src_port} -> {dst_port}")


def handle_client(conn: socket.socket, addr: Tuple[str, int], dst_port: int, log_path: str) -> None:
    """
    Handles a single inbound connection.
    Sends a tiny banner if configured for the port, then reads up to 256 bytes and logs the event.
    """
    BANNERS = {
        8022: b"SSH-2.0-OpenSSH_8.9p1\r\n",
        8080: b"HTTP/1.1 200 OK\r\nServer: tinyhp\r\nContent-Length: 2\r\n\r\nOK",
        33060: b"\x00"
    }
    try:
        banner = BANNERS.get(dst_port, b"")
        if banner:
            try:
                conn.sendall(banner)
            except Exception:
                pass

        conn.settimeout(1.0)
        try:
            data = conn.recv(256)
            text = data.decode("latin-1", errors="replace")
        except socket.timeout:
            text = ""
        except Exception:
            text = ""
        log_event(log_path, addr, dst_port, text)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def listen_on(host: str, port: int, log_path: str) -> None:
    """Listens on a single TCP port and dispatches a handler thread per connection."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(128)
    print(f"[HONEYPOT] Listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, port, log_path), daemon=True)
        t.start()


def parse_args() -> argparse.Namespace:
    """Command-line interface for override of config values."""
    p = argparse.ArgumentParser(description="Minimal TCP honeypot for Hybrid IDS + Honeypot")
    p.add_argument("--config", help="Path to JSON config file", default=None)
    p.add_argument("--bind", help="Override bind host", default=None)
    p.add_argument("--ports", help="Override ports list", nargs="*", type=int, default=None)
    p.add_argument("--log", help="Override honeypot log path", default=None)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)

    if args.bind:
        cfg["bind_host"] = args.bind
    if args.ports:
        cfg["ports"] = args.ports
    if args.log:
        cfg["log_path"] = args.log

    ensure_log_header(cfg["log_path"])

    print(f"[INFO] Author: {AUTHOR}")
    print(f"[INFO] Project: {PROJECT}")
    print(f"[INFO] Due Date: {DUE_DATE}")
    print(f"[INFO] Log file: {cfg['log_path']}")
    print(f"[INFO] Ports: {cfg['ports']}")

    for p in cfg["ports"]:
        threading.Thread(target=listen_on, args=(cfg["bind_host"], p, cfg["log_path"]), daemon=True).start()

    print("[HONEYPOT] Running. Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[i] Shutting down honeypot.")


if __name__ == "__main__":
    main()