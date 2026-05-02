# Security Training Demo — "System Info" App

> **FOR CORPORATE SECURITY TRAINING PURPOSES ONLY**
>
> This app is designed to demonstrate during training sessions that a
> benign-looking Android application can establish and maintain outbound
> network connections using only standard Android APIs, without triggering
> antivirus or security tool alerts.

---

## What It Does

| Surface | Behavior |
|---------|----------|
| **Visible to user** | Shows device system information (manufacturer, model, Android version, etc.) |
| **Background** | Uses Android `WorkManager` to periodically POST device info as JSON to a configurable server |

### What It Does NOT Do
- No access to contacts, SMS, calls, camera, microphone, location, or files
- No exploitation of any vulnerability
- No downloading or executing remote code
- No privilege escalation
- No data exfiltration beyond basic device model info

---

## How It Works (Training Talking Points)

1. **INTERNET permission** — required by virtually every app; users never think twice about it
2. **WorkManager** — the official Android API for periodic background tasks; survives app restarts and reboots
3. **Standard HTTP POST** — the beacon is just a normal web request indistinguishable from analytics/telemetry
4. **No dangerous permissions** — the app requests nothing that would trigger a warning dialog on install
5. **Looks legitimate** — the UI is a polished "System Info" viewer that provides real value

**Key training message:** Antivirus tools on Android primarily look for known malware signatures, dangerous permission combinations, or exploit behavior. An app that uses only standard APIs and normal permissions to phone home is effectively invisible to these tools.

---

## Setup

### 1. Configure the Server URL

Edit `app/build.gradle.kts` and set your server IP:

```kotlin
buildConfigField("String", "BEACON_URL", "\"http://192.168.1.100:8080/beacon\"")
```

### 2. Start the Listener

On your training server (Kali, laptop, etc.):

```bash
cd server/
python3 server.py 8080
```

### 3. Build the APK

```bash
# From the project root
./gradlew assembleDebug

# APK output:
# app/build/outputs/apk/debug/app-debug.apk
```

### 4. Install on Target Device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

Or transfer the APK and sideload it.

### 5. Run & Observe

- Open "System Info" on the device — it displays device information
- Watch the server terminal for incoming beacons
- Beacons continue in the background even after the app is closed

---

## Example Beacon Output (Server Side)

```
============================================================
  BEACON RECEIVED — 2026-04-24 14:30:22
  Source IP: 192.168.1.50
============================================================
         device: Samsung SM-S928B
        android: 15
            api: 35
    fingerprint: samsung/e3qxeea/e3q:15/...
      timestamp: 1745500222000
            tag: SECURITY_TRAINING_DEMO
============================================================
```

---

## Customization

| Setting | Location | Default |
|---------|----------|---------|
| Server URL | `app/build.gradle.kts` → `BEACON_URL` | `http://YOUR_SERVER_IP:8080/beacon` |
| Beacon interval | `app/build.gradle.kts` → `BEACON_INTERVAL_MINUTES` | `15` minutes |
| App name | `res/values/strings.xml` | "System Info" |

---

## Project Structure

```
SecurityTrainingDemo/
├── app/
│   ├── build.gradle.kts              # App build config (set server URL here)
│   └── src/main/
│       ├── AndroidManifest.xml        # Permissions & app declaration
│       ├── java/.../
│       │   ├── MainActivity.kt        # UI — displays device info
│       │   └── BeaconWorker.kt        # Background beacon sender
│       └── res/
│           ├── layout/activity_main.xml
│           ├── values/                # Strings, colors, themes
│           ├── drawable/              # App icon foreground
│           ├── mipmap-anydpi-v26/     # Adaptive icon
│           └── xml/network_security_config.xml
├── server/
│   └── server.py                      # Python beacon listener
├── build.gradle.kts                   # Root build file
├── settings.gradle.kts
└── README.md
```

---

## Training Discussion Points

1. **Why doesn't antivirus catch this?**
   - The app uses no malware signatures, no exploits, no dangerous permissions
   - Outbound HTTP traffic is identical to legitimate analytics/telemetry
   - WorkManager is a standard Android framework component

2. **What could a real attacker do with this pattern?**
   - Exfiltrate data slowly over time
   - Maintain persistent access ("phone home")
   - Receive commands via server responses (C2 channel)

3. **How to defend against this?**
   - Network monitoring / traffic analysis at the corporate level
   - MDM (Mobile Device Management) with app whitelisting
   - Only install apps from trusted sources / managed Play Store
   - Regular security audits of installed applications
   - DNS filtering to block unknown destinations

---

## Legal Disclaimer

This application is provided strictly for authorized corporate security
training and awareness demonstrations. It must only be installed on
devices you own or have explicit written authorization to test. Misuse
of this tool may violate local, state, federal, or international law.
The authors assume no liability for unauthorized use.
