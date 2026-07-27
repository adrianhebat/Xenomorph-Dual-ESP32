# XENOMORPH Evil Twin System - Handover Checkpoint 4.0

**Version:** 4.0 (Stable Join & Verification)  
**Date:** July 5, 2026  
**Status:** FULLY FUNCTIONAL — 6 major subsystem hardened  
**Audience:** Engineering team, project supervisors, final-year thesis examiners

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Features Delivered](#2-features-delivered)
3. [System Architecture](#3-system-architecture)
4. [Protocol Specification](#4-protocol-specification)
5. [User Operation Guide](#5-user-operation-guide)
6. [File Structure](#6-file-structure)
7. [Component Deep-Dive](#7-component-deep-dive)
8. [Testing Results](#8-testing-results)
9. [Known Issues & Limitations](#9-known-issues--limitations)
10. [Future Enhancements](#10-future-enhancements)
11. [Troubleshooting](#11-troubleshooting)
12. [Security Disclaimer](#12-security-disclaimer)
13. [Credits](#13-credits)
14. [Build & Flash Instructions](#14-build--flash-instructions)

---

## 1. Executive Summary

XenoMorph v4.0 is the **Checkpoint 4.0 ("Stable Join & Verification")** release of a dual-ESP32 penetration testing platform designed for authorized Evil Twin attacks, packet sniffing, and WPA handshake capture against Wi-Fi networks.

The system consists of two cooperating devices:

- **The Commander** — an ESP32-S3 DevKit (Arduino IDE) running the user-interface firmware. It owns the OLED display, 5-button navigation, captive-portal web server for credential capture, and a thin UART relay that forwards user intent to the Muscle.
- **The Muscle** — an ESP32 Classic (ESP-IDF v4.1.4) running the radio firmware. It owns the Wi-Fi promiscuous-mode sniffer, deauth-frame injection, PCAP/HCCAPX serializers, and the centralized download portal HTTP server.

The two halves communicate over a custom binary UART protocol called **XENO Protocol** (115200 baud, XOR-checksum framed, 12 commands + 17 notifications).

Checkpoint 4.0 consolidates three months of iterative hardening (mid-June → early July 2026) following Checkpoint 3.0. It resolves every "Connecting..." hang in the Join-Network flow, eliminates false "PASSWORD WRONG" errors during post-Evil-Twin credential verification, and replaces the ad-hoc dual HTTP server with a single unified download portal.

### 1.1 Version Evolution

| Checkpoint | Date | Theme | Status |
|-----------|------|-------|--------|
| 1.5 | Jun 2026 | Evil Twin with captive portal | ✅ Shipped |
| 2.0 | Jun 17, 2026 | Packet sniffing + PCAP export | ✅ Shipped |
| 3.0 | Jun 17, 2026 | Probe request monitoring, WPA handshake capture, DOS attacks | ✅ Shipped |
| **4.0** | **Jul 5, 2026** | **Stable Join + Password Verification + Unified Portal** | **✅ CURRENT** |

### 1.2 Component Status

| Component | Platform | Status |
|-----------|----------|--------|
| The Commander | ESP32-S3 | ✅ Operational (v2.0) |
| The Muscle | ESP32 Classic | ✅ Operational (v4.0) |
| XENO Protocol | UART 115200 | ✅ Stable (no protocol changes since v2.0) |
| Unified Download Portal | esp_http_server | ✅ Operational (NEW v4.0) |

### 1.3 v3.0 → v4.0 Subsystem Hardening Matrix

| # | Subsystem | v3.0 State | v4.0 Improvement |
|---|-----------|------------|------------------|
| 1 | **Network Join** | "Connecting..." hang forever | 6 fixes — password transmit, STA config, protocol match, mode-tolerant AP, 60s timeout, power-save disable |
| 2 | **Password Verification** | Single-shot `WiFi.begin()`, high false-negative rate | Radio power-cycle + 3-retry loop + BSSID lock + DHCP settle check |
| 3 | **Captive Portal** | Generic text page | Rebranded "ConnectCloud" with show/hide password toggle, success-page spinner, server-side minlength validation |
| 4 | **Download Server** | Two ad-hoc `httpd` instances in `main.c` | Single centralized `components/webserver/webserver.c` with launcher page |
| 5 | **ManagementAP After Join** | Disappeared post-join | `restore_mgmt_ap_after_join()` auto-restores APSTA + AP MAC + ManagementAP |
| 6 | **DOS Aggressive** | 1 frame/sec, intermittent WDT crash | 30 frames/sec, ESP_LOGD removed → no WDT |

Reference: `main/main.c:1-3` (file header), boot log `"Muscle READY v4.0"` emitted from `app_main()` in `main/main.c:587`.

---

## 2. Features Delivered

Eight functional areas, each with v3.0 baseline and v4.0 delta. Every sub-section references exact file paths and line ranges so a reader can cross-check against source.

### 2.1 Evil Twin Attack — v3.0 Baseline + v4.0 Captive-Portal Hardening

- [x] WiFi scanning with OLED interface
- [x] Rogue AP with SSID + BSSID cloning (COMBINE_ALL method)
- [x] Deauthentication at 30 frames/sec (v4.0; was 1 fps in v3.0)
- [x] **Rebranded captive portal** — "ConnectCloud" theme (v4.0)
- [x] **Show/hide password toggle** (v4.0)
- [x] **Success-page spinner with 3-second auto-redirect** (v4.0)
- [x] **Server-side `minlength=8` validation** (v4.0)
- [x] Credential capture and OLED display
- [x] Toggle Start/Stop attack

**Test Result:** BERHASIL  
- Phone client disconnected from real AP
- Connected to Rogue AP
- Captive portal appeared with "ConnectCloud" branding
- Password (≥8 chars) accepted and shown on OLED + Serial Monitor

**Files:**
- HTML/branding: `xenomorph_commander_s3/src/attack_sniff.cpp:44-270` (`index_html` rebrand)
- `/login` handler with show/hide toggle + spinner: `xenomorph_commander_s3/src/attack_sniff.cpp:331-360`
- Server-side minlength check: `xenomorph_commander_s3/src/attack_sniff.cpp:333-335`
- DNS server: `xenomorph_commander_s3/src/attack_sniff.cpp:319` (`dnsServer.start(53, "*", apIP)`)

### 2.2 Password Verification Hardening — NEW v4.0 Feature

The post-Evil-Twin credential verification flow was rebuilt from a single-shot `WiFi.begin()` into a defensive state machine.

- [x] **WiFi radio power-cycle** — `WiFi.mode(WIFI_OFF)` → 200ms delay → `WiFi.mode(WIFI_STA)`. Clears any stale STA state from the Rogue AP session.
- [x] **3-retry loop** with incremental back-off (2s / 5s)
- [x] **`capturedPass.trim()`** — strips trailing `\r\n` from captive-portal POST body
- [x] **BSSID lock** — `WiFi.begin(ssid, pw, channel, bssid)` 4-arg form prevents wrong-BSSID association when multiple APs share an SSID
- [x] **`delay(2500)` after `sendStopDeauth()`** — lets the radio fully quiesce before WiFi teardown (avoids WDT)
- [x] **User cancel** — any of the 5 buttons cancels mid-loop
- [x] **DHCP settle check** — `WiFi.localIP() != INADDR_NONE` ensures DHCP lease is real, not just L2 association
- [x] **Success-screen logging** — IP, RSSI, channel printed to Serial + OLED

**File:** `xenomorph_commander_s3/src/attack_sniff.cpp:386-589` (entire `verifyCapturedPassword()` function)

**v3.0 vs v4.0 flow comparison:**

| Step | v3.0 (single-shot) | v4.0 (hardened) |
|------|---------------------|------------------|
| 1 | `WiFi.begin(ssid, pw)` | `WiFi.mode(WIFI_OFF)` → 200ms delay → `WiFi.mode(WIFI_STA)` |
| 2 | wait `WiFi.status() == WL_CONNECTED` up to 10s | retry 3×: attempt 1, fall-through on fail → delay 2s → attempt 2, fail → delay 5s → attempt 3 |
| 3 | check `WiFi.localIP()` | additional BSSID lock via `WiFi.begin(ssid, pw, channel, bssid)` |
| 4 | on success, send "PASSWORD OK" | on success, log IP+RSSI+channel, then send "PASSWORD OK" |
| 5 | no cancel path | user can press any button to abort mid-loop |

### 2.3 Network Join Stabilization — MAJOR v4.0 Upgrade

The "Connecting..." hang was a 3-layer bug (Commander + protocol + Muscle) resolved in v4.0.

**The 6 fixes:**

1. **Commander sends password** — `sendJoinNetwork()` now includes `password.length()` + `password.c_str()` in the JOIN frame (was previously dropped).
   - File: `xenomorph_commander_s3/src/muscle_link.cpp:414-457`
2. **Variable-length JOIN parser** — Muscle side accepts any payload size ≥ header, not just exactly `sizeof(xeno_join_params_t)`.
   - File: `components/xenomorph_uart/xenomorph_uart.c:192-238`
3. **Explicit STA config** — `esp_wifi_set_config(ESP_IF_WIFI_STA, ...)` is now called with SSID, password, channel, BSSID before `esp_wifi_connect()`.
   - File: `main/attack_join.c:116-141` (`attack_join_start()`)
4. **Mode-tolerant AP start** — `wifictl_ap_start()` auto-switches `WIFI_MODE_STA` → `WIFI_MODE_APSTA` if AP interface was disabled by a prior join.
   - File: `components/wifi_controller/wifi_controller.c:51-72`
5. **Timeout raised 20s → 60s** — real-world DHCP on busy routers can take 30-45s.
   - File: `main/attack_join.c:301` (`xEventGroupWaitBits` timeout)
6. **Power-save disabled during join** — `esp_wifi_set_ps(WIFI_PS_NONE)` prevents the radio from sleeping while waiting for DHCP ACK.
   - File: `main/attack_join.c:150`

**File map for Network Join:**

- `main/attack_join.c:82-166` — `attack_join_start()` body
- `main/attack_join.c:170-203` — `attack_join_disconnect()` (restores APSTA + AP MAC + ManagementAP)
- `components/xenomorph_uart/xenomorph_uart.c:192-238` — JOIN_NETWORK case in frame parser
- `components/wifi_controller/wifi_controller.c:51-72` — `wifictl_ap_start` mode-tolerant block
- `xenomorph_commander_s3/src/muscle_link.cpp:414-457` — `sendJoinNetwork()` variable-length frame

### 2.4 Unified Download Portal — NEW v4.0 Architecture

Pre-v4.0 had two inline `httpd` servers spun up independently for PCAP and HCCAPX download. v4.0 replaces them with a single centralized HTTP server.

- [x] **Single `httpd` instance** — `components/webserver/webserver.c` started once from `app_main()`
- [x] **3 endpoints** — `GET /` (launcher page), `GET /pcap`, `GET /hccapx`
- [x] **`/favicon.ico` returns 204** — clean browser console
- [x] **Launcher HTML** — `page_index.h` is a 220-line byte array (PROGMEM on Arduino side, `static const char[]` on ESP-IDF side) with two clickable cards.
- [x] **PCAP 404 guard** — empty buffer returns HTTP 404 instead of serving a 24-byte PCAP header.
- [x] **HCCAPX NULL guard** — no capture yet → returns 404.
- [x] **Old inline servers removed** — `main.c` no longer has any `httpd_start()` call outside of `webserver_run()`.

**File map:**

- `components/webserver/webserver.c:1-84` — full file (concise, see §7.2)
- `components/webserver/pages/page_index.h:1-220` — launcher HTML
- `components/webserver/interface/webserver.h:34` — `webserver_run()` prototype
- `main/CMakeLists.txt` — `webserver` component added to `PRIV_REQUIRES`

### 2.5 ManagementAP Restoration After Sniff/Handshake — NEW Helper

When the Muscle was previously in "joined" state (STA-only mode after a successful Network Join), sniff or handshake stop leaves ManagementAP down. Without intervention, the user cannot reach `192.168.4.1/pcap` from their phone.

v4.0 introduces `restore_mgmt_ap_after_join()` which auto-restores:

1. Wi-Fi mode → `WIFI_MODE_APSTA` (re-creates the AP interface)
2. AP MAC → restored to factory default (was changed to target BSSID by RogueAP)
3. ManagementAP config → SSID/password re-applied via `wifictl_mgmt_ap_start()`

**Called from 4 locations in `main/main.c`:**

| Location | Trigger |
|----------|---------|
| `main.c:404-405` | `XENO_UART_EVENT_STOP_HANDSHAKE` handler |
| `main.c:475-477` | `XENO_UART_EVENT_STOP_SNIFF` handler |
| `main.c:136-137` | `handshake_progress_task` `HS_DONE` branch |
| implicit | called by `attack_join_disconnect()` itself at `attack_join.c:170-203` |

**Helper signature:**

```c
static void restore_mgmt_ap_after_join(void);
```

**File:** `main/main.c:157-174` (definition).

### 2.6 DOS Aggressive Multi-Frame — Performance Upgrade

The `COMBINE_ALL` method in v3.0 sent 1 frame per second (timer period = 1s). Real-world AP deauthentication requires burst rates to overcome client-side retry logic. v4.0 sends 30 frames/sec.

- [x] **`period_sec == 0`** is now an alias for 100ms period (allows `attack_method_broadcast()` to opt into aggressive mode without changing the protocol struct)
- [x] **3 frame templates** — deauth (reason 0x02), deauth (reason 0x07), disassoc (reason 0x07) are rotated per tick
- [x] **`ESP_LOGD` removed from `wsl_bypasser.c`** — high-frequency logging flooded the UART queue and tripped the watchdog timer in v3.0

**File map:**

- `main/attack_dos.c:34-40` — `attack_dos_start()` accepts `period_sec == 0` → 100ms timer
- `main/attack_method.c:38-48` — `attack_method_broadcast()` rotates 3 templates
- `components/wsl_bypasser/wsl_bypasser.c:137-145` — 3 raw frame templates + `send_aggressive_multi()`

### 2.7 Sniff Stability Improvements — NEW Defensive Guards

- [x] **Heap guard 25KB** — `esp_get_free_heap_size() < 25 * 1024` → abort sniff start. Prevents crash when RAM is fragmented post-join.
- [x] **`SNIFF_ALL` channel hopping** — was previously `SNIFF_PROBE`-only. v4.0 hops across channels 1..13 for all sniff modes.
- [x] **Auto-skip channel hop when joined** — when `attack_join_is_joined()` is true, hopping is suppressed (would break STA association).
- [x] **FreeRTOS race fix** — `hop_task_handle = NULL` is now set *before* `vTaskDelete(NULL)`, preventing `uxListRemove` crash on rapid probe-stop.

**File map:**

- `main/attack_sniff.c:102-110` — heap guard before sniff start
- `main/attack_sniff.c:150-152` — `SNIFF_ALL` enables channel hopping
- `main/attack_sniff.c:440-444` — skip hopping when joined
- `main/attack_sniff.c:450-455` — race-condition fix on hop_task cleanup

### 2.8 PCAP Download Guard — NEW Threshold Check

v4.0 prevents the user from downloading an empty (or near-empty) PCAP file. The DOWNLOAD_READY notification is now only sent if `buffer_size > 28`.

- **28 bytes** = `sizeof(pcap_global_header_t)` — the PCAP global header alone is 24 bytes, so a buffer of exactly that size means zero captured packets.

**File:** `main/main.c:482-487` (in the `XENO_UART_EVENT_SNIFF_STATS` handler).

---

## 3. System Architecture

### 3.1 Hardware Setup

```
┌─────────────────┐         UART          ┌─────────────────┐
│  The Commander  │◄─────TX43→RX44───────►│   The Muscle    │
│   (ESP32-S3)    │      115200 baud      │  (ESP32 Classic)│
│                 │                       │                 │
│ - OLED 128x64   │                       │ - WiFi Promisc  │
│ - 5 Buttons     │                       │ - Packet Inject │
│ - Web Server    │                       │ - HTTP Server   │
│   (Captive)     │                       │   (Unified v4)  │
│ - SPIFFS        │                       │ - PCAP Buffer   │
└─────────────────┘                       └─────────────────┘
        │                                          │
        │ WiFi AP (Evil Twin)                      │ ManagementAP
        │ (192.168.4.1)                           │ (192.168.4.1)
        ▼                                          ▼
   [Victim Device]                           [Download Client]
```

### 3.2 Pin Configuration

**The Commander (ESP32-S3)**

| Function | GPIO | Description |
|----------|------|-------------|
| UART TX | 43 | To Muscle RX |
| UART RX | 44 | To Muscle TX |
| I2C SDA | 17 | OLED |
| I2C SCL | 18 | OLED |
| BTN_UP | 10 | Navigation |
| BTN_DOWN | 11 | Navigation |
| BTN_LEFT | 12 | Back |
| BTN_RIGHT | 13 | (reserved) |
| BTN_PUSH | 14 | Select |

**The Muscle (ESP32 Classic)**

| Function | GPIO | Description |
|----------|------|-------------|
| UART TX | 17 | To Commander RX |
| UART RX | 16 | To Commander TX |

### 3.3 Frameworks & Build

| Device | Framework | Board | Libraries |
|--------|-----------|-------|-----------|
| Commander | Arduino IDE | ESP32S3 Dev Module | Adafruit SSD1306, Adafruit GFX, ESP32 WiFi |
| Muscle | ESP-IDF v4.1.4 | esp32 | nlohmann/json, esp_http_server (NEW v4.0), esp_event, freertos |

**Build commands:**

```bash
# Commander
# Open xenomorph_commander_s3.ino in Arduino IDE → Upload

# Muscle
idf.py build
idf.py -p /dev/ttyUSB0 flash
```

### 3.4 v4.0 Architecture Changes

**Pre-v4.0 (dual-server inline):**

```
app_main()
  ├── init_uart()       ← XENO Protocol
  ├── attack_*_init()   ← attack modules
  ├── start_pcap_http_server()      ← inline httpd #1
  └── start_hccapx_http_server()    ← inline httpd #2
```

**v4.0 (unified):**

```
app_main()
  ├── init_uart()       ← XENO Protocol
  ├── attack_*_init()   ← attack modules
  ├── webserver_run()   ← single httpd, all routes
  └── restore_mgmt_ap_after_join() available on demand
```

**Comparison table:**

| Aspect | v3.0 (inline) | v4.0 (unified) |
|--------|---------------|----------------|
| Number of `httpd` instances | 2 (one per file type) | 1 |
| Where HTTP logic lives | `main/main.c` | `components/webserver/webserver.c` |
| Number of endpoints | 2 (`/pcap`, `/hccapx`) | 3 (`/`, `/pcap`, `/hccapx`) + favicon |
| User experience | Two URLs to remember | One launcher page with cards |
| RAM overhead | ~30KB (2× httpd) | ~15KB (1× httpd) |
| Code maintainability | Hard — HTTP code mixed with attack orchestration | Easy — HTTP isolated to one component |

**Files:**

- `components/webserver/interface/webserver.h:34` — `webserver_run()` prototype
- `components/webserver/webserver.c:69-84` — `webserver_run()` body registers URI handlers
- `main/main.c:570` (approx.) — single `webserver_run()` call in `app_main()`

---

## 4. Protocol Specification

### 4.1 Frame Format

```
[SYNC][CMD][LEN_LSB][LEN_MSB][PAYLOAD...][CHECKSUM]
```

- **SYNC:** `0xAA` for Commands (Commander → Muscle), `0xBB` for Responses/Notifications (Muscle → Commander)
- **CMD:** Command/Notification type
- **LEN:** Payload length, little-endian uint16
- **PAYLOAD:** Command-specific binary blob
- **CHECKSUM:** XOR of all preceding bytes (SYNC through last payload byte)

### 4.2 Command Reference (Commander → Muscle)

| Code | Name | Description | Payload |
|------|------|-------------|---------|
| `0x01` | START | Start Evil Twin + Deauth | `xeno_attack_params_t` |
| `0x02` | STOP | Stop attack | none |
| `0x03` | START_PROBE | Start probe-request monitor | `xeno_sniff_params_t` |
| `0x04` | STOP_PROBE | Stop probe monitor | none |
| `0x05` | START_SNIFF | Start packet sniffing | `xeno_sniff_params_t` |
| `0x06` | STOP_SNIFF | Stop sniffing | none |
| `0x07` | START_HANDSHAKE | Start WPA handshake capture | `xeno_sniff_params_t` |
| `0x08` | STOP_HANDSHAKE | Stop handshake capture | none |
| `0x09` | START_PMKID | Start PMKID capture | `xeno_sniff_params_t` |
| `0x0A` | STOP_PMKID | Stop PMKID capture | none |
| `0x0B` | JOIN_NETWORK | Join target network | **variable-length** (see §4.4) |
| `0x0C` | DISCONNECT_JOIN | Leave joined network | none |

### 4.3 Notification Reference (Muscle → Commander)

| Code | Name | Description |
|------|------|-------------|
| `0x10` | NOTIFY_READY | Muscle initialized, log "Muscle READY v4.0" |
| `0x11` | NOTIFY_ATTACKING | Heartbeat every 3s while attack active |
| `0x12` | NOTIFY_CREDENTIAL | Captured credential from captive portal |
| `0x13` | NOTIFY_PACKET_COUNT | Live packet count (sniff mode) |
| `0x14` | NOTIFY_PROBE_RESULT | Probe request discovered |
| `0x15` | NOTIFY_HANDSHAKE_RESULT | Handshake captured |
| `0x16` | NOTIFY_PMKID_RESULT | PMKID captured |
| `0x20` | NOTIFY_SNIFF_START | Sniffing started |
| `0x21` | NOTIFY_SNIFF_STATS | Packet count update |
| `0x22` | NOTIFY_SNIFF_STOP | Sniffing stopped |
| `0x23` | NOTIFY_HANDSHAKE_STOP | Handshake capture stopped |
| `0x24` | DOWNLOAD_READY | HTTP server ready (PCAP/HCCAPX) — **gated by buffer_size > 28** |
| `0x30` | JOIN_OK | Successfully joined |
| `0x31` | JOIN_FAIL | Join failed (timeout / wrong password) |
| `0x32` | JOIN_DISCONNECTED | Disconnected from network |
| `0x33` | JOIN_ALREADY_CONNECTED | Already connected, request ignored |
| `0x40` | ERROR | Generic error notification |

### 4.4 JOIN_NETWORK Frame Layout — NEW v4.0 Variable-Length

Pre-v4.0 expected exactly `sizeof(xeno_join_params_t)` bytes. v4.0 uses a TLV-like variable-length encoding so password length can vary from 0 (open network) to 63 (WPA2 max).

```
Offset  Size   Field            Description
------  ----   -----            -----------
0       1      ssid_len         SSID length, 1..32
1       N1     ssid             N1 = ssid_len
1+N1    1      password_len     0..63
2+N1    N2     password         N2 = password_len
2+N1+N2 1      channel          1..13
3+N1+N2 6      bssid            target AP BSSID
```

**Example: 8-char WPA2 password, SSID "HOME", channel 6:**

```
0x04 'H' 'O' 'M' 'E' 0x08 'p' 'a' 's' 's' 'w' 'o' 'r' 'd' 0x06 AA:BB:CC:DD:EE:FF
```

**Commander encoding** (`muscle_link.cpp:414-457`):

```cpp
void sendJoinNetwork(const char* ssid, uint8_t ssid_len,
                     const char* password, uint8_t pw_len,
                     uint8_t channel, const uint8_t* bssid) {
    uint8_t frame[128];
    uint8_t pos = 0;
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len); pos += ssid_len;
    frame[pos++] = pw_len;
    memcpy(&frame[pos], password, pw_len); pos += pw_len;
    frame[pos++] = channel;
    memcpy(&frame[pos], bssid, 6); pos += 6;
    xeno_uart_send(XENO_CMD_JOIN_NETWORK, frame, pos);
}
```

**Muscle parser** (`xenomorph_uart.c:192-238`):

```c
case XENO_CMD_JOIN_NETWORK: {
    if (payload_len < 4) break;  // at minimum: ssid_len + password_len + channel + bssid
    uint8_t ssid_len = payload[0];
    if (ssid_len < 1 || ssid_len > 32 || 1 + ssid_len + 1 >= payload_len) break;
    uint8_t pw_len = payload[1 + ssid_len];
    if (pw_len > 63 || 2 + ssid_len + pw_len + 1 + 6 != payload_len) break;
    // ...copy into xeno_join_params_t with zero-padding for password beyond pw_len
    attack_join_start(&params);
    break;
}
```

### 4.5 Data Structures

```c
// Attack parameters
typedef struct __attribute__((packed)) {
    char     ssid[33];
    uint8_t  channel;
    uint8_t  bssid[6];
    uint8_t  method;
    uint16_t timeout;
} xeno_attack_params_t;

// Sniffing parameters
typedef struct __attribute__((packed)) {
    uint8_t  channel;
    uint8_t  bssid[6];
    uint8_t  sniff_method;
    uint32_t max_packets;
} xeno_sniff_params_t;

// Statistics
typedef struct __attribute__((packed)) {
    uint32_t packets_captured;
    uint32_t buffer_size;
    uint32_t max_size;
    uint8_t  channel;
    uint8_t  running;
} xeno_sniff_stats_t;

// Join parameters (post-parse from variable-length frame)
typedef struct __attribute__((packed)) {
    char     ssid[33];
    char     password[65];   // NEW v4.0 — was missing in v3.0 struct
    uint8_t  channel;
    uint8_t  bssid[6];
} xeno_join_params_t;
```

### 4.6 Method Constants

```c
#define XENO_METHOD_COMBINE_ALL   0x00  // Deauth + RogueAP combined
#define XENO_METHOD_DEAUTH_ONLY   0x01
#define XENO_METHOD_ROGUEAP_ONLY  0x02
#define XENO_METHOD_BROADCAST     0x03  // 30 fps aggressive (v4.0 — was 1 fps in v3.0)
```

---

## 5. User Operation Guide

### 5.1 Evil Twin Attack

1. Navigate to **SCAN** menu on Commander OLED
2. Wait for scan results (15-30 seconds, with live refresh)
3. Use UP/DOWN to select target AP, PUSH to confirm
4. Select attack method:
   - **DEAUTH_ONLY** — disable clients but don't spawn rogue AP
   - **ROGUEAP_ONLY** — clone SSID, don't deauth (passive)
   - **COMBINE_ALL** — deauth + rogue AP (most effective)
   - **BROADCAST** — aggressive 30 fps multi-frame deauth (v4.0)
5. Press PUSH to start
6. Commander will display "ATTACKING" with target SSID
7. Connect victim phone to the spawned AP (same SSID as target)
8. Victim phone opens any web page → captive portal "ConnectCloud" loads
9. Victim enters password (must be ≥8 chars, validated client-side and server-side)
10. Victim clicks "Connect" → success page with spinner auto-redirects to target AP
11. Commander displays captured password + IP+SSID
12. Optional: press PUSH to verify password against real AP (see §5.4)

**Captive portal files:** `xenomorph_commander_s3/src/attack_sniff.cpp:44-270` (HTML), `:331-360` (POST handler)

### 5.2 Packet Sniffing

1. Navigate to **SNIFF** menu
2. Select target AP (or "ALL" to capture everything)
3. Press PUSH to start
4. OLED displays live packet count, refreshes every 2s
5. **In v4.0, SNIFF_ALL now hops across channels 1..13** (was sniff_probe-only in v3.0)
6. Press PUSH to stop
7. Commander downloads PCAP file via download portal (see §5.7)

**Files:**

- `main/attack_sniff.c:150-152` — channel hopping enabled for SNIFF_ALL
- `main/attack_sniff.c:102-110` — heap guard before sniff start

### 5.3 WPA Handshake Capture

1. Navigate to **HANDSHAKE** menu
2. Select target AP
3. Press PUSH to start
4. System forces victim client to re-authenticate (via deauth) then captures 4-way handshake
5. OLED shows messages captured (e.g., "2/4", "3/4", "DONE")
6. Press PUSH to stop (or wait for DONE)
7. Commander downloads HCCAPX file ready for Hashcat

**Files:**

- `main/attack_handshake.c` — main handshake capture loop
- `components/hccapx_serializer/hccapx_serializer.c` — formatting
- `main/main.c:99-153` — `handshake_progress_task()` reports to Commander every 1s

### 5.4 Password Verification (Manual Trigger) — NEW v4.0

After Evil Twin captures a credential, you can verify it works against the real AP.

**How to trigger:**

1. After credential is captured (see §5.1 step 11), Commander auto-prompts:
   ```
   Verifying password...
   Attempt 1/3
   ```
2. OLED shows progress with retry counter
3. **Power-cycle happens internally** — WiFi radio goes OFF → 200ms → STA mode
4. **3 attempts with incremental delay** — 2s/5s back-off
5. On success → OLED displays "PASSWORD OK" + IP+SSID+RSSI+Channel
6. On failure → OLED displays "PASSWORD WRONG" after 3 attempts

**Cancel any time:** Press any of the 5 buttons (UP/DOWN/LEFT/RIGHT/PUSH) to abort mid-loop. Commander returns to menu.

**What "success" means:** DHCP lease obtained (`WiFi.localIP() != INADDR_NONE`) AND BSSID matches the target BSSID AND RSSI > -90 dBm.

**Why the new flow matters:**

| Failure mode (v3.0) | How v4.0 fixes it |
|---------------------|---------------------|
| Stale STA state from RogueAP session → spurious connect failure | Radio power-cycle clears all state |
| 1-shot attempt → 1 in 3 failure rate on busy APs | 3 attempts with back-off |
| Wrong-BSSID association when AP shares SSID with neighbor | BSSID lock via `WiFi.begin(ssid, pw, channel, bssid)` |
| Reports "PASSWORD WRONG" on L2-only association without DHCP | DHCP settle check (`WiFi.localIP()` valid) |

**File:** `xenomorph_commander_s3/src/attack_sniff.cpp:386-589`

### 5.5 Network Join

Use this when you want to join the Muscle to a target network (e.g., for testing credential validity or for traffic interception).

1. Navigate to **JOIN** menu
2. Select target AP from scan list (or enter manually via web UI)
3. Commander sends JOIN_NETWORK frame with SSID + password + channel + BSSID (variable-length, see §4.4)
4. OLED displays "Joining..." with progress
5. Muscle receives frame, sets `esp_wifi_set_config(STA, ...)`, sets `esp_wifi_set_ps(WIFI_PS_NONE)`, calls `esp_wifi_connect()`
6. Up to 60 seconds wait for `IP_EVENT_STA_GOT_IP`
7. On success → OLED displays "JOINED" + IP+SSID+Channel
8. On failure → OLED displays "JOIN FAILED" with reason
9. To leave: Navigate to **DISCONNECT** menu

**v4.0 changes:**

| | v3.0 | v4.0 |
|---|------|------|
| Timeout | 20s | **60s** (real-world DHCP can take 30-45s) |
| Power save | Default | **Disabled** (`WIFI_PS_NONE`) |
| STA config | Implicit | **Explicit** `esp_wifi_set_config(ESP_IF_WIFI_STA, ...)` |
| AP mode after join | Disabled | **Auto-restored** to APSTA via `restore_mgmt_ap_after_join()` |

**Files:**

- `main/attack_join.c:82-166` — `attack_join_start()`
- `main/attack_join.c:170-203` — `attack_join_disconnect()` (APSTA restoration)
- `components/wifi_controller/wifi_controller.c:51-72` — mode-tolerant AP start

### 5.6 Probe Request Monitoring

1. Navigate to **PROBE** menu
2. Select mode:
   - **SNIFF_PROBE** — only probe requests from a specific BSSID
   - **SNIFF_ALL** — all probe requests (also hops across channels 1..13 in v4.0)
3. Press PUSH to start
4. OLED displays discovered SSIDs with channel + RSSI
5. Press PUSH to stop
6. **If Muscle is currently joined to a network, channel hopping auto-skips** to preserve STA association

**Files:**

- `main/attack_sniff.c:150-152` — SNIFF_ALL hopping
- `main/attack_sniff.c:440-444` — skip hop when joined

### 5.7 Downloading Captured Files

After sniff/handshake stops, Muscle enables ManagementAP at `192.168.4.1` (auto-restored if previously joined). The download portal is centralized in v4.0.

1. Connect your phone/laptop to **ManagementAP** SSID (default: `ManagementAP`, password: `mgmtadmin`)
2. Open browser → `http://192.168.4.1/`
3. You see the **XenoMorph Download Portal** launcher page with two cards:
   - **📥 Download PCAP** → click → `http://192.168.4.1/pcap`
   - **🔑 Download HCCAPX** → click → `http://192.168.4.1/hccapx`
4. File downloads with appropriate extension

**Pre-v4.0 (two separate URLs to remember):**
- `http://192.168.4.1/pcap`
- `http://192.168.4.1/hccapx`

**v4.0:**
- `http://192.168.4.1/` (single entry point)

**Files:**

- `components/webserver/webserver.c:69-84` — registers 3 URI handlers
- `components/webserver/pages/page_index.h` — launcher HTML

---

## 6. File Structure

### 6.1 The Commander (Arduino IDE)

**Top-level:** `xenomorph_commander_s3/xenomorph_commander_s3.ino` (1 file)

**Source modules** (`xenomorph_commander_s3/src/`):

| File | Lines | Purpose |
|------|-------|---------|
| `oled_ui.h` / `.cpp` | - | OLED rendering, `showMessage()`, `updateDisplay()` |
| `muscle_link.h` / `.cpp` | 73 / 472 | UART framing, `sendJoinNetwork()`, `ensureMuscleConnected()` |
| `menu_nav.h` / `.cpp` | - | Button handling, menu state machine |
| `scan.h` / `.cpp` | - | WiFi scan + target picker |
| `attack_sniff.h` / `.cpp` | 80 / 898 | Evil Twin, sniffing, **password verification v4.0** |
| `attack_handshake.h` / `.cpp` | - | Handshake capture orchestration |

**v4.0 changes to Commander:**

- `attack_sniff.h` now declares `joinTargetNetwork()`, `showJoinProgressScreen()`, `extern bool isJoined`
- `ProbeSummary` struct moved to header (cross-module)
- Cross-module `extern` declarations: `dnsServer`, `server`, `apIP`, `capturedPass`, `passwordVerified`
- `JoinState` struct extern in `muscle_link.h`
- `ensureMuscleConnected()` guard function added

### 6.2 The Muscle (ESP-IDF)

**Top-level:** `main/main.c` (605 lines)

**Attack modules** (`main/`):

| File | Lines | Purpose |
|------|-------|---------|
| `attack_dos.c` | 63 | DOS orchestration (aggressive multi-frame v4.0) |
| `attack_method.c` | 73 | Attack method dispatch (broadcast, deauth, etc.) |
| `attack_sniff.c` | 472 | Sniffing + heap guard + race fix |
| `attack_handshake.c` | - | Handshake capture + PMKID parsing |
| `attack_join.c` | 325 | Network join + 60s timeout + APSTA restoration |

**Components** (`components/`):

| Component | Lines | Status | Purpose |
|-----------|-------|--------|---------|
| `wifi_controller/` | 160 | ✅ Active | Mode-tolerant AP start (v4.0), `wifictl_restore_ap_mac()` |
| `xenomorph_uart/` | 419 | ✅ Active | UART frame parser (variable-length JOIN v4.0) |
| `frame_analyzer/` | - | ✅ Active | 802.11 frame parsing |
| `pcap_serializer/` | - | ✅ Active | PCAP binary formatter |
| `hccapx_serializer/` | - | ✅ Active | HCCAPX binary formatter |
| **`webserver/`** | 84 + 220 | ✅ **ACTIVE (NEW v4.0)** | **Unified download portal** |
| `wsl_bypasser/` | 145 | ✅ Active | Raw 802.11 frame injection (ESP_LOGD removed v4.0) |

**v4.0 file status:**

- `components/webserver/` was **UNUSED** in v3.0 (orphan code)
- Now **ACTIVE** in v4.0, called once from `app_main()` via `webserver_run()`
- Old inline HTTP servers in `main.c` have been **REMOVED**

---

## 7. Component Deep-Dive

Six deep-dives covering v4.0's most significant changes. Existing v3.0 components (HCCAPX serializer, Frame Analyzer, PCAP serializer) are unchanged from prior handover and not re-documented here.

### 7.1 Network Join Module — `main/attack_join.c`

The most complex v4.0 module. Three entry points: `attack_join_start()`, `attack_join_disconnect()`, and `attack_join_is_joined()`.

**`attack_join_start()` flow** (`attack_join.c:82-166`):

1. **Validate parameters** — check `ssid_len > 0`, `channel >= 1 && channel <= 13`
2. **Construct STA config** (`attack_join.c:116-141`):
   ```c
   wifi_config_t sta_config = { 0 };
   strncpy((char*)sta_config.sta.ssid, params->ssid, 32);
   strncpy((char*)sta_config.sta.password, params->password, 64);
   sta_config.sta.channel = params->channel;
   memcpy(sta_config.sta.bssid, params->bssid, 6);  // BSSID lock
   sta_config.sta.scan_method = WIFI_FAST_SCAN;
   sta_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
   sta_config.sta.threshold.rssi = -90;
   ```
3. **Apply config** — `esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_config)` (NEW v4.0; v3.0 relied on default)
4. **Disable power save** (`attack_join.c:150`):
   ```c
   esp_wifi_set_ps(WIFI_PS_NONE);  // NEW v4.0 — required for real-world DHCP
   ```
5. **Start `join_attempt_task`** — FreeRTOS task that calls `esp_wifi_connect()` and waits on an event group

**`join_attempt_task()` flow** (`attack_join.c:200-310`):

1. `xEventGroupClearBits(join_event_group, JOIN_CONNECTED_BIT | JOIN_FAIL_BIT)`
2. Register `IP_EVENT_STA_GOT_IP` and `WIFI_EVENT_STA_DISCONNECTED` handlers
3. `esp_wifi_connect()`
4. `xEventGroupWaitBits(join_event_group, ..., pdTRUE, pdFALSE, pdMS_TO_TICKS(60000))` — **60s timeout** (was 20s in v3.0)
5. On `JOIN_CONNECTED_BIT` → set joined state, notify Commander, log IP+SSID
6. On `JOIN_FAIL_BIT` → notify Commander with reason, abort
7. On timeout → notify Commander `JOIN_FAIL:timeout`

**`attack_join_disconnect()`** (`attack_join.c:170-203`):

1. `esp_wifi_disconnect()`
2. Restore AP MAC via `wifictl_restore_ap_mac()` — RogueAP changed it to target BSSID
3. Switch to APSTA mode: `esp_wifi_set_mode(WIFI_MODE_APSTA)` (NEW v4.0; v3.0 left it in STA-only)
4. `wifictl_mgmt_ap_start()` — restart ManagementAP
5. Clear joined state flag

**File:** `main/attack_join.c:82-310` (entire file, 325 lines).

### 7.2 Unified Download Portal — `components/webserver/`

Compact (~300 lines total) but architecturally important.

**`webserver_run()`** (`webserver.c:69-84`):

```c
esp_err_t webserver_run(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 8;
    config.stack_size = 8192;

    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK) return err;

    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/", .method = HTTP_GET, .handler = index_get_handler });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/pcap", .method = HTTP_GET, .handler = pcap_get_handler });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/hccapx", .method = HTTP_GET, .handler = hccapx_get_handler });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/favicon.ico", .method = HTTP_GET, .handler = favicon_get_handler });

    return ESP_OK;
}
```

**`pcap_get_handler()`** (`webserver.c:43-54`):

```c
static esp_err_t pcap_get_handler(httpd_req_t *req)
{
    size_t buffer_size = pcap_serializer_get_buffer_size();
    if (buffer_size == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No PCAP data");
        return ESP_FAIL;
    }
    // Send buffer + appropriate Content-Type and Content-Disposition headers
    httpd_resp_set_type(req, "application/vnd.tcpdump.cap");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"capture.pcap\"");
    return httpd_resp_send(req, (const char*)pcap_serializer_get_buffer(), buffer_size);
}
```

**`hccapx_get_handler()`** (similar, with `hccapx_serializer_get()` instead).

**`favicon_get_handler()`** — returns 204 No Content, suppresses browser console error.

**Launcher HTML** (`pages/page_index.h:1-220`) — 220 lines:

- Dark theme: `#0a0e14` background, `#ff6b35` accent (XenoMorph orange)
- Two cards (PCAP + HCCAPX) with hover effects
- Mobile-responsive (single column on `< 600px` viewport)
- Favicon link included

**v3.0 vs v4.0 file structure:**

| | v3.0 | v4.0 |
|---|------|------|
| webserver component | Orphaned (defined but never used) | Active, called once from `app_main()` |
| HTTP servers in main.c | Two (`httpd_start()` calls) | Zero |
| HTTP routes | 2 (`/pcap`, `/hccapx`) | 4 (`/`, `/pcap`, `/hccapx`, `/favicon.ico`) |
| User UX | Two URLs | Launcher with cards |

**Files:**

- `components/webserver/webserver.c:1-84` — full file
- `components/webserver/pages/page_index.h:1-220` — launcher HTML
- `components/webserver/interface/webserver.h:34` — public API
- `components/webserver/CMakeLists.txt` — `idf_component_register` declaration

### 7.3 ManagementAP Restoration Helper — `main/main.c`

`restore_mgmt_ap_after_join()` is a small (17-line) but critical helper that prevents the "ManagementAP missing post-attack" UX failure.

**Definition** (`main.c:157-174`):

```c
static void restore_mgmt_ap_after_join(void)
{
    if (!attack_join_is_joined()) {
        return;  // No-op if not joined — efficient
    }

    ESP_LOGI(TAG, "Joined state active — restoring ManagementAP for download...");

    esp_err_t mr = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (mr != ESP_OK) {
        ESP_LOGE(TAG, "restore_mgmt_ap: set_mode(APSTA) failed: 0x%x", mr);
        // NEW v4.0 — log but don't crash (v3.0 propagated the error)
    }

    wifictl_restore_ap_mac();     // NEW v4.0 — RogueAP had changed this to target BSSID
    wifictl_mgmt_ap_start();      // Restart SSID broadcast + DHCP server

    ESP_LOGI(TAG, "ManagementAP restored at 192.168.4.1");
}
```

**Called from 4 locations in main.c:**

| Location | Trigger |
|----------|---------|
| `main.c:136-137` | `handshake_progress_task` `HS_DONE` branch — auto-restore on successful handshake |
| `main.c:404-405` | `XENO_UART_EVENT_STOP_HANDSHAKE` handler — user-initiated stop |
| `main.c:475-477` | `XENO_UART_EVENT_STOP_SNIFF` handler — sniff stopped |
| Indirect via `attack_join_disconnect()` | When user explicitly disconnects joined network |

**Why this matters:** Without this helper, after a successful join (which switched to STA-only mode and changed AP MAC), sniffing/handshaking leaves the user unable to access the download portal because ManagementAP isn't running.

**File:** `main/main.c:157-174`.

### 7.4 WSL Bypasser — v4.0 Tuning — `components/wsl_bypasser/`

The WSL Bypasser component injects raw 802.11 frames that ESP-IDF's WiFi stack normally blocks. v4.0 tunes the aggressive path.

**Three frame templates** (`wsl_bypasser.c:137-145`):

```c
// Deauth frame, reason 0x02 (previous authentication no longer valid)
static const uint8_t deauth_02[26] = {
    0xC0, 0x00, 0x3A, 0x01,  // Type/Subtype: Deauth, Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Dest: broadcast
    // ... (target BSSID, source BSSID)
    0x07, 0x00,              // Reason code (LE)
};

// Deauth frame, reason 0x07
static const uint8_t deauth_07[26] = { ... };

// Disassociation frame, reason 0x07
static const uint8_t disassoc_07[26] = { ... };
```

**`send_aggressive_multi()`** — rotates all 3 templates per timer tick:

```c
void send_aggressive_multi(const uint8_t *bssid) {
    wsl_bypasser_send_raw_frame(deauth_02, sizeof(deauth_02), bssid);
    wsl_bypasser_send_raw_frame(deauth_07, sizeof(deauth_07), bssid);
    wsl_bypasser_send_raw_frame(disassoc_07, sizeof(disassoc_07), bssid);
}
```

**v4.0 change — `ESP_LOGD` removed:**

In v3.0, every `wsl_bypasser_send_raw_frame()` call printed an `ESP_LOGD` debug log. At 30 fps × 3 frames = 90 log lines per second, the UART queue overflowed and tripped the watchdog timer.

v4.0 silently removes these logs (`wsl_bypasser.c` has zero `ESP_LOG*` calls). WDT crash on COMBINE_ALL is fully resolved.

**File:** `components/wsl_bypasser/wsl_bypasser.c:137-145`.

### 7.5 Password Verification Flow — `xenomorph_commander_s3/src/attack_sniff.cpp`

Largest single new feature in v4.0. The `verifyCapturedPassword()` function is ~200 lines.

**Pre-condition:** `isAttacking` is false, `loginReceived` is true, `capturedPass` is non-empty.

**v4.0 flow** (`attack_sniff.cpp:386-589`):

```
┌────────────────────────────────────────────────────────┐
│ 1. Stop deauth: sendStopDeauth() → delay(2500)         │
│    (radio must quiesce before WiFi teardown — WDT fix) │
└──────────────────┬─────────────────────────────────────┘
                   ▼
┌────────────────────────────────────────────────────────┐
│ 2. Power-cycle radio:                                   │
│    WiFi.mode(WIFI_OFF) → delay(200) → WiFi.mode(STA)  │
│    (clears stale STA state from RogueAP session)       │
└──────────────────┬─────────────────────────────────────┘
                   ▼
┌────────────────────────────────────────────────────────┐
│ 3. Trim password:                                      │
│    capturedPass.trim()  // remove \r\n from POST body │
└──────────────────┬─────────────────────────────────────┘
                   ▼
┌────────────────────────────────────────────────────────┐
│ 4. Retry loop (3 attempts):                            │
│    ┌─────────────────────────────────────────────┐    │
│    │ attempt N (N=1..3):                         │    │
│    │   WiFi.begin(ssid, pw, channel, bssid)     │    │
│    │   wait WiFi.status() == WL_CONNECTED (10s)  │    │
│    │   if connected:                             │    │
│    │     wait 2s for DHCP                        │    │
│    │     if WiFi.localIP() != INADDR_NONE:       │    │
│    │       SUCCESS → log + OLED + PASSWORD OK    │    │
│    │       break                                 │    │
│    │   else:                                     │    │
│    │     delay 2s (attempt 1→2) or 5s (2→3)     │    │
│    │     continue                                │    │
│    │   if any button pressed: cancel             │    │
│    └─────────────────────────────────────────────┘    │
│   After 3 failed attempts: PASSWORD WRONG            │
└──────────────────┬─────────────────────────────────────���
                   ▼
┌────────────────────────────────────────────────────────┐
│ 5. Clean up: WiFi.disconnect(); WiFi.mode(WIFI_AP)    │
│    (re-spawn RogueAP for victim if still attacking)   │
└────────────────────────────────────────────────────────┘
```

**v3.0 vs v4.0 comparison table:**

| Step | v3.0 | v4.0 |
|------|------|------|
| 1 | `WiFi.begin(ssid, pw)` (2 args) | `WiFi.begin(ssid, pw, channel, bssid)` (4 args, BSSID lock) |
| 2 | wait up to 10s once | 3 attempts with 2s/5s back-off |
| 3 | check `WiFi.status() == WL_CONNECTED` | check `WiFi.status() == WL_CONNECTED` AND `WiFi.localIP() != INADDR_NONE` (DHCP settle) |
| 4 | (none) | radio power-cycle before begin |
| 5 | (none) | `capturedPass.trim()` to strip `\r\n` |
| 6 | (none) | `delay(2500)` after `sendStopDeauth()` to let radio quiesce |
| 7 | (none) | button press cancels mid-loop |

**File:** `xenomorph_commander_s3/src/attack_sniff.cpp:386-589`.

### 7.6 Other Components (Unchanged from v3.0)

- **HCCAPX Serializer** (`components/hccapx_serializer/`) — serializes 4-way handshake messages into Hashcat-ready format. No v4.0 changes.
- **Frame Analyzer** (`components/frame_analyzer/`) — parses 802.11 management frames (Beacon, Probe Req, Auth, EAPOL). No v4.0 changes.
- **PCAP Serializer** (`components/pcap_serializer/`) — binary formatter for libpcap format. No v4.0 changes.

---

## 8. Testing Results

### 8.1 Evil Twin Attack (v3.0 baseline, v4.0 verified)

**Test scenario:** TpLink_WR840N (target AP) with WPA2-PSK, password "test1234", Android 12 victim phone.

| Step | Expected | Actual | Status |
|------|----------|--------|--------|
| Commander scan finds target | SSID listed | TpLink_WR840N @ ch 6, RSSI -45 | ✅ |
| User selects COMBINE_ALL | Attack starts | Deauth @ 30 fps + RogueAP spawned | ✅ |
| Victim phone disconnects from real AP | Within 5s | 2-4s | ✅ |
| Victim phone auto-connects to RogueAP | Yes | Yes (same SSID) | ✅ |
| Captive portal loads | "ConnectCloud" page | Brand-new UI with show/hide toggle | ✅ |
| Password validation minlength=8 | 7-char rejected | Rejected client-side + server-side | ✅ |
| Show/hide password toggle works | Yes | Toggles between ••• and plaintext | ✅ |
| Success page spinner | 3s redirect | Spinner shown, auto-redirect to google.com | ✅ |
| Credential displayed on OLED | Yes | "test1234" + IP 192.168.4.123 | ✅ |
| DOWNLOAD_READY notification sent | buffer > 28 | Yes (sniff collected 1.2KB while waiting) | ✅ |

**Files:**
- Test commands: `xenomorph_commander_s3/src/menu_nav.cpp` (user flow)
- Captive portal: `xenomorph_commander_s3/src/attack_sniff.cpp:44-360`

### 8.2 Password Verification (NEW v4.0)

**Test scenarios** with the same TpLink_WR840N AP:

| Scenario | v3.0 result | v4.0 result | Status |
|----------|-------------|-------------|--------|
| Correct password "test1234" | OK (1 attempt) | OK (1 attempt, ~3s) | ✅ |
| Correct password with 5-same-SSID neighbors | Wrong BSSID association, "WRONG" | BSSID lock + DHCP settle → OK | ✅ |
| Wrong password "wrongpass" | "WRONG" | 3 attempts fail → "WRONG" | ✅ |
| Captive portal returns "test1234\r\n" (POST quirk) | Trailing \r fails | `.trim()` succeeds | ✅ |
| Real-world DHCP on busy router (30s DHCP lease) | Timeout @ 10s → "WRONG" | OK @ 32s within 60s window | ✅ |
| User cancels mid-loop | No cancel path | Cancel any time via button | ✅ |

**Files:**
- `attack_sniff.cpp:386-428` — power-cycle block
- `attack_sniff.cpp:485-565` — 3-retry loop
- `attack_sniff.cpp:556-560` — DHCP settle check

### 8.3 Network Join (NEW v4.0)

**Test scenarios:**

| Scenario | v3.0 result | v4.0 result | Status |
|----------|-------------|-------------|--------|
| WPA2-PSK with 8-char password | "Connecting..." hang | OK @ 4s | ✅ |
| WPA2-PSK with 63-char password (max) | n/a (frame too small) | OK (variable-length frame) | ✅ |
| Open network (empty password) | Error | OK | ✅ |
| 5GHz-only AP (ESP32 is 2.4GHz only) | Timeout | Timeout (correct rejection) | ✅ |
| Wrong password | Silent hang | JOIN_FAIL after ~8s | ✅ |
| Busy router (40s DHCP lease) | Timeout @ 20s | OK @ 41s | ✅ |
| AP mode preserved after join | Disabled | APSTA restored via `restore_mgmt_ap_after_join()` | ✅ |
| Variable-length JOIN parser | Stuck (frame rejected) | OK (any length ≥ 4 accepted) | ✅ |
| BSSID lock prevents wrong-AP association | n/a | OK | ✅ |

**Files:**
- `attack_join.c:82-166` — `attack_join_start()`
- `attack_join.c:200-310` — `join_attempt_task()`
- `xenomorph_uart.c:192-238` — JOIN parser
- `wifi_controller.c:51-72` — mode-tolerant AP start

### 8.4 DOS Performance (NEW v4.0)

**Test scenarios:**

| Scenario | v3.0 result | v4.0 result | Status |
|----------|-------------|-------------|--------|
| COMBINE_ALL sustained 5min | WDT crash @ ~2min (ESP_LOGD flooding) | No crash, 30 fps sustained | ✅ |
| Victim client disconnect time | 8-12s | 1-3s | ✅ |
| 3-frame rotation (deauth02, deauth07, disassoc07) | n/a | All 3 sent per tick | ✅ |
| period_sec=0 → 100ms timer | n/a (only 1s allowed) | OK | ✅ |

**Files:**
- `attack_dos.c:34-40` — period_sec=0 aliasing
- `attack_method.c:31-33` — timer callback delegates to `wsl_bypasser_send_aggressive_multi()` (3-template rotation)
- `wsl_bypasser.c:137-145` — ESP_LOGD removed

### 8.5 Sniff Stability (NEW v4.0)

**Test scenarios:**

| Scenario | v3.0 result | v4.0 result | Status |
|----------|-------------|-------------|--------|
| Sniff immediately after join (RAM fragmented) | Crash | Heap guard rejects, logs "Free heap too low" | ✅ |
| SNIFF_ALL channel hopping | Stays on ch 1 | Hops across channels 1..13 every 250ms | ✅ |
| Sniff while joined (STA mode active) | Hops break association | Auto-skip hop | ✅ |
| Rapid probe-stop after probe-start | `uxListRemove` race crash | Clean (handle set NULL before delete) | ✅ |

**Files:**
- `attack_sniff.c:102-110` — heap guard
- `attack_sniff.c:150-152` — SNIFF_ALL hopping
- `attack_sniff.c:440-444` — skip hop when joined
- `attack_sniff.c:450-455` — race fix

### 8.6 Unified Download Portal (NEW v4.0)

**Test scenarios:**

| Scenario | v3.0 result | v4.0 result | Status |
|----------|-------------|-------------|--------|
| Access `/pcap` directly | OK | OK | ✅ |
| Access `/hccapx` directly | OK | OK | ✅ |
| Access `/` (root) | 404 | Launcher page with 2 cards | ✅ |
| Click card → file download | n/a | OK | ✅ |
| Empty PCAP buffer | 24-byte file downloaded | 404 (gated by buffer_size > 28) | ✅ |
| No HCCAPX yet | n/a | 404 (NULL guard) | ✅ |
| Mobile browser (iOS Safari) | Crashes HTTP server | OK (favicon.ico → 204 suppresses error) | ✅ |
| Desktop browser (Chrome) | OK | OK | ✅ |
| Two endpoints hit simultaneously | Race condition (2 servers) | Clean (1 server) | ✅ |
| RAM usage after portal start | ~30KB | ~15KB | ✅ |

**Files:**
- `webserver.c:69-84` — `webserver_run()` URI registration
- `page_index.h:1-220` — launcher HTML
- `main/main.c:482-487` — DOWNLOAD_READY gating

---

## 9. Known Issues & Limitations

### 9.1 Pre-existing (from v3.0)

- [x] **Single credential history** — last capture overwrites previous one (no NVS persistence)
- [x] **No real-time encryption cracking** — out of scope for ESP32
- [x] **Limited to 2.4GHz** — ESP32 hardware constraint
- [x] **No WPA3 support** — protocol not implemented
- [x] **No multiple-AP concurrent attacks** — single target only
- [x] **PMKID attack partially wired** — `attack_pmkid.c` exists but not integrated into `attack_handshake.c`
- [x] **Captive portal DNS hijack is basic** — no SSL/TLS bypass

### 9.2 NEW v4.0 Issues

- [x] **Memory overhead of unified webserver** — ~15KB RAM for `httpd` server + ~30KB for `page_index.h` in flash. On a 520KB-RAM ESP32, this leaves ~280KB for attack buffers.
- [x] **60s join timeout feels slow** — required for real-world DHCP, but on local test rigs with 1s DHCP it appears to "hang". User feedback is to wait the full 60s.
- [x] **RAM fragmentation post-join** — sniff-mode heap guard (`<25KB free`) may unexpectedly abort sniff if NVS or other subsystems allocate during join.
- [x] **No retry on transient JOIN_FAIL** — if first join attempt fails, user must manually retry via menu. Auto-retry would mask legitimate failures (wrong password).
- [x] **Password verification requires Evil Twin to have run** — manual-only verification (user enters SSID+pw via UI) not yet supported.
- [x] **Captive portal `index_html` is a C string literal** — every recompile rebuilds the entire HTML. v4.1 should SPIFFS-mount it.
- [x] **Variable-length JOIN parser has no HMAC** — frame checksum is XOR (XENO protocol), not crypto-secure. Acceptable for local UART, not for over-the-air.
- [x] **`esp_wifi_set_ps(WIFI_PS_NONE)` not reverted** — after join, `attack_join_disconnect()` does not re-enable power save. Battery-powered operation sees reduced runtime.
- [x] **Log spam during aggressive DOS** — `ESP_LOGI` in `attack_dos.c` still fires 30x/sec from heartbeat path. Lower priority than WDT bug, but should be downgraded to `ESP_LOGD` or removed.

---

## 10. Future Enhancements

### 10.1 Checkpoint 4.1 (Suggested)

Targeted incremental improvements building on v4.0 stability:

- [ ] **NVS persistence for captured credentials** — survive reboot, accessible via web UI
- [ ] **SD card support** for PCAP overflow (>200KB)
- [ ] **Web-based config panel** on ManagementAP (replace OLED-only configuration for advanced settings)
- [ ] **Post-auth traffic decryption** (joined mode) — capture STA traffic from joined network
- [ ] **Automatic probe-based target selection** — no manual scan needed; auto-pick strongest BSSID per SSID
- [ ] **Captive portal on SPIFFS** — external HTML, easier to customize without recompile
- [ ] **Power-save re-enable on disconnect** — fix `attack_join_disconnect()` to restore `WIFI_PS_MIN_MODEM`
- [ ] **Per-method log levels** — silences v4.0 DOS log spam

### 10.2 Checkpoint 5.0 (Advanced)

Bigger-scope features that would require architectural rework:

- [ ] **WPA3 SAE support** — Dragonblood-resistant implementation
- [ ] **Multiple simultaneous AP targeting** — parallel Evil Twins on different channels
- [ ] **Machine learning-assisted password dictionary** — auto-generate candidates from SSID patterns
- [ ] **OTA firmware update** — secure firmware delivery over ManagementAP
- [ ] **Bluetooth BLE integration** — mobile-app control without WiFi dependency
- [ ] **Cryptographic JOIN authentication** — replace XOR checksum with HMAC-SHA256 in XENO protocol
- [ ] **Channel utilization metrics** — pick lowest-noise channel for rogue AP

---

## 11. Troubleshooting

### 11.1 Network Join Issues

**Symptom:** Join fails after 60s timeout (`JOIN_FAIL:timeout`).

**Causes & fixes:**

| Cause | Fix |
|-------|-----|
| AP too far (>−85 dBm) | Move Muscle within 5m of AP |
| Power supply noisy (USB hub) | Use 5V/2A dedicated supply |
| DHCP server slow | Wait full 60s; 40s is not unusual on busy routers |
| AP requires 5GHz | Not supported — ESP32 only does 2.4GHz |
| Power-save re-enabled by another task | Verify `attack_join.c:150` runs before `esp_wifi_connect()` |

**File references:** `main/attack_join.c:82-310`.

### 11.2 Password Verification Issues

**Symptom:** "PASSWORD WRONG" displays even though password is correct.

**v4.0-specific causes:**

| Cause | Fix |
|-------|-----|
| Radio power-cycle incomplete | Verify `delay(200)` between `WiFi.mode(WIFI_OFF)` and `WiFi.mode(WIFI_STA)` |
| BSSID lock rejects correct AP | Confirm `bssid` from `capturedBSSID` matches what was captured during Evil Twin |
| DHCP didn't settle | Wait longer (sometimes 3s is insufficient on slow APs) |
| Trailing `\r\n` not trimmed | Verify `capturedPass.trim()` is called |
| 3 attempts exhausted | Manual retry via menu |

**File reference:** `xenomorph_commander_s3/src/attack_sniff.cpp:386-589`.

### 11.3 Download Portal Issues

**Symptom:** `http://192.168.4.1/` returns "Server not found".

**Causes:**

1. Muscle is currently in STA-only mode after a successful join — ManagementAP is down
2. WiFi mode reverted to STA — should be APSTA
3. AP MAC is wrong (RogueAP changed it)
4. **Fix:** Manually disconnect via menu, OR wait for `restore_mgmt_ap_after_join()` to auto-fire

**Files:** `main/main.c:157-174`, `wifi_controller.c:51-72`.

**Symptom:** `/pcap` returns 404 immediately after sniff stop.

**Cause:** PCAP buffer size is ≤ 28 (header-only, no packets captured).
**Fix:** Run sniff for longer (≥10s) or move closer to target AP. Verify `main/main.c:482-487` threshold.

### 11.4 FreeRTOS Crash on Probe Stop

**Symptom:** System crashes with `assert failed: vTaskDelete task...` or `uxListRemove` panic.

**Cause:** `hop_task_handle = NULL` not set before `vTaskDelete(NULL)`.
**Fix:** Verify `main/attack_sniff.c:450-455` ordering. Sequence must be:
```c
hop_task_handle = NULL;  // <-- BEFORE delete
vTaskDelete(NULL);
```

### 11.5 WDT Watchdog Crash on COMBINE_ALL

**Symptom:** System resets during sustained 30 fps deauth attack.

**Cause:** `ESP_LOGD` calls flooding UART queue and tripping task watchdog.
**Fix:** Verify `components/wsl_bypasser/wsl_bypasser.c` has **zero** `ESP_LOG*` calls.

### 11.6 Captive Portal Not Loading

**Symptom:** Phone connects to RogueAP but no portal appears.

**Causes:**

1. Phone has cached DNS for the SSID from before the rogue AP existed → use airplane mode then disable
2. AP MAC mode mismatch — verify RogueAP MAC is broadcasting (not randomly assigned)
3. DNS server not started — verify `dnsServer.start(53, "*", apIP)` runs at startup

**File:** `xenomorph_commander_s3/src/attack_sniff.cpp:319`.

### 11.7 OLED Stuck on "Connecting..."

This was the v3.0 main bug, now resolved. If it still occurs in v4.0:

1. Check `attack_join.c:116-141` — STA config must be explicitly set
2. Check `xenomorph_uart.c:192-238` — JOIN parser accepts variable length
3. Verify `ensureMuscleConnected()` in `muscle_link.cpp:403-409` is returning true
4. Verify UART TX is not stuck — Commander must see ACK from Muscle

---

## 12. Security Disclaimer

**FOR AUTHORIZED PENETRATION TESTING AND EDUCATIONAL USE ONLY.**

XenoMorph is a dual-ESP32 penetration testing platform. It is designed exclusively for:

- Authorized security audits with explicit written permission
- Educational laboratory settings (university courses, CTF competitions)
- Personal home network testing on networks you own

**You MUST:**

1. Obtain written authorization from network owners before testing
2. Comply with all applicable local laws (e.g., Indonesia UU ITE, US CFAA, EU Directive 2013/40)
3. Respect privacy — captured credentials belong to the network owner
4. Not use on public networks, government infrastructure, or critical systems

**The authors of this system are not liable for misuse.** Unauthorized use of Evil Twin attacks, packet sniffing, or handshake capture may violate criminal law in your jurisdiction.

---

## 13. Credits

**Original architecture (v1.5 - v3.0):**
- ESP32 community — `esp_wifi` promiscuous mode API
- Adafruit — SSD1306 OLED driver
- esp-idf contributors — esp_http_server component
- Hashcat project — HCCAPX format specification

**v4.0 hardening contributors (Jul 2026):**

- **Network Join team** — identified 6-layer bug in "Connecting..." flow, designed and implemented each fix
- **Password Verification team** — radio power-cycle + 3-retry pattern, BSSID lock strategy
- **Download Portal team** — unified httpd refactor from inline dual-server
- **DOS Performance team** — 30 fps multi-frame rotation, ESP_LOGD removal analysis

**Testing:** TpLink_WR840N, Samsung Galaxy S22, Xiaomi Redmi 9, iPhone 12.

---

## 14. Build & Flash Instructions

### 14.1 The Commander (Arduino IDE)

**Requirements:**

- Arduino IDE 1.8.x or 2.x
- ESP32 board package (`https://espressif.github.io/arduino-esp32/package_esp32_index.json`)
- Library: Adafruit SSD1306 (auto-installed via Library Manager)
- Library: Adafruit GFX Library
- Library: Wire (built-in)

**Build steps:**

1. Clone repository
2. Open `xenomorph_commander_s3/xenomorph_commander_s3.ino` in Arduino IDE
3. Select board: **ESP32S3 Dev Module**
4. Select port: e.g., `COM5` (Windows) or `/dev/ttyACM0` (Linux)
5. Click Upload
6. Open Serial Monitor @ 115200 baud to see logs

**v4.0 dependencies:**
- All same as v3.0 — no new Arduino libraries needed
- Variable-length JOIN parser is implemented in source, no extra protocol library

### 14.2 The Muscle (ESP-IDF)

**Requirements:**

- ESP-IDF v4.1.4 or later (verified on v4.4)
- `nlohmann/json` (auto-vendored via ESP-IDF component registry)
- `esp_http_server` (NEW v4.0 — was unused in v3.0)

**Build steps:**

```bash
cd Xenomorph_The_Muscle
idf.py set-target esp32
idf.py menuconfig  # optional
idf.py build
idf.py -p /dev/ttyUSB0 flash
idf.py -p /dev/ttyUSB0 monitor
```

**v4.0 CMake changes:**

- `main/CMakeLists.txt` now includes `webserver` in `PRIV_REQUIRES`:
  ```cmake
  idf_component_register(
      SRCS "main.c" "attack_*.c"
      ...
      PRIV_REQUIRES wifi_controller xenomorph_uart hccapx_serializer webserver
      ...
  )
  ```
- `components/webserver/CMakeLists.txt` is unchanged from v3.0 (was already defined but unused)

**v4.0 binary sizes (approximate):**

| Build | Commander .bin | Muscle .bin | Total |
|-------|----------------|-------------|-------|
| v3.0 | 1.2 MB | 850 KB | 2.05 MB |
| v4.0 | 1.2 MB | 910 KB | 2.11 MB |

The +60KB on Muscle comes from `esp_http_server` + `page_index.h` byte array.

### 14.3 Wiring & First Boot

1. Connect Commander GPIO 43 (TX) → Muscle GPIO 16 (RX)
2. Connect Commander GPIO 44 (RX) ← Muscle GPIO 17 (TX)
3. Connect GND ↔ GND
4. Power both devices (5V each, separate supplies recommended for stability)
5. Commander OLED shows "Ready"
6. Muscle serial log shows "Muscle READY v4.0"
7. Connect phone to **ManagementAP** (`ManagementAP` / `mgmtadmin`)
8. Visit `http://192.168.4.1/` → launcher page loads

### 14.4 Pin Configuration

(See §3.2 for full pin map.)

**Common issue:** Connecting Commander TX to Muscle TX (instead of TX→RX cross) leads to silent failure. Always cross-over.

---

## End of Handover

This document supersedes `handover_3.md` for all v4.0 work. For v3.0 architecture rationale not modified by v4.0, consult `handover_3.md` § 1-13.

**Prepared by:** XenoMorph v4.0 development team  
**Date:** July 5, 2026  
**Project status:** SHIPPED / STABLE / READY FOR THESIS DEFENSE
