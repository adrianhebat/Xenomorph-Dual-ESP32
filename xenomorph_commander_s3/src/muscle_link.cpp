#include "muscle_link.h"
#include "xenomorph_protocol.h"
#include "oled_ui.h"   // showMessage() for the offline banner
#include "attack_sniff.h" // probeTop, sniffMethod

// ============================================================================
// muscle_link.cpp — UART framing + notification parsing.
//
// This module owns the Muscle connection state machine and writes to state
// owned by attack_sniff (isSniffing, pcapReady, sniffBufferSize, probeTop).
// Including attack_sniff.h here is safe: attack_sniff.h does not include
// muscle_link.h, so there's no circular dependency.
// ============================================================================

bool muscleReady = false;
bool muscleConnected = false;
uint32_t muscleLastSeen = 0;

// Handshake progress state — owned by muscle_link, read by OLED UI.
HandshakeState hsState = { false, 0, 0, 0, false };

// Join state — owned by muscle_link, read by OLED UI.
JoinState joinState = { false, {0,0,0,0}, {0,0,0,0}, {0,0,0,0}, 0 };

// ---------------------------------------------------------------------------
// Cross-module writes — declared in attack_sniff.h (now included above).
// parseMuscleNotification is the master state sink for notifications coming
// from Muscle — it touches sniff state owned by another module.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RX — drain Serial2, frame notifications, dispatch.
// ---------------------------------------------------------------------------
void checkMuscleNotifications() {
  while (Serial2.available()) {
    static uint8_t rx_buf[256];
    static uint16_t rx_pos = 0;

    uint8_t b = Serial2.read();

    if (rx_pos == 0 && b == XENO_SYNC_RSP) {
      rx_buf[rx_pos++] = b;
    } else if (rx_pos > 0) {
      rx_buf[rx_pos++] = b;

      if (rx_pos >= 4) {
        uint16_t payload_len = rx_buf[2] | (rx_buf[3] << 8);
        if (rx_pos >= 5 + payload_len) {
          uint8_t cs = xeno_checksum(rx_buf, rx_pos - 1);
          if (cs == rx_buf[rx_pos - 1]) {
            if (rx_buf[1] >= 0x10) {
              parseMuscleNotification(rx_buf, rx_pos);
            }
          }
          rx_pos = 0;
        }
      }
      if (rx_pos >= sizeof(rx_buf)) rx_pos = 0;
    }
  }
}

void parseMuscleNotification(uint8_t* data, uint16_t len) {
  if (len < 2) return;
  uint8_t notify_type = data[1];

  Serial.printf("[RX] notify=0x%02X len=%u\n", notify_type, len);
  muscleLastSeen = millis();

  switch (notify_type) {
    case XENO_NOTIFY_READY:
      muscleReady = true;
      muscleConnected = true;
      Serial.println("[MUSCLE] Ready!");
      break;

    case XENO_NOTIFY_ATTACKING:
      muscleConnected = true;
      break;

    case XENO_NOTIFY_SNIFF_START:
      isSniffing = true;
      Serial.println("[MUSCLE] Sniffing started");
      break;

    case XENO_NOTIFY_SNIFF_STATS:
      if (len >= 4 + sizeof(xeno_sniff_stats_t)) {
        xeno_sniff_stats_t* stats = (xeno_sniff_stats_t*)&data[4];
        sniffPacketCount = stats->packets_captured;
        sniffBufferSize = stats->buffer_size;
        Serial.printf("[MUSCLE] Sniff stats: %u packets, %u bytes\n",
                      sniffPacketCount, sniffBufferSize);
      }
      break;

    case XENO_NOTIFY_SNIFF_STOP:
      isSniffing = false;
      sniffMethod = 0x00;  // reset
      memset(&probeTop, 0, sizeof(probeTop));
      // PROBE mode tidak menghasilkan PCAP — hanya enable download kalau ada buffer.
      pcapReady = (sniffBufferSize > 0);
      Serial.printf("[MUSCLE] Sniffing stopped, pcapReady=%d (buffer=%u)\n",
                    pcapReady, sniffBufferSize);
      break;

    case XENO_NOTIFY_DOWNLOAD_READY:
      // Muscle: HTTP server siap di ManagementAP 192.168.4.1/pcap
      // Same notification re-used for HCCAPX download (Muscle picks endpoint
      // based on which attack/scan was last completed).
      pcapReady = true;
      hsState.hccapxReady = true;
      Serial.println("[MUSCLE] Download ready (HTTP server up)");
      break;

    case XENO_NOTIFY_HS_START:
      hsState.running = true;
      hsState.messagePair = 0;
      hsState.hccapxReady = false;
      Serial.println("[MUSCLE] Handshake started");
      break;

    case XENO_NOTIFY_HS_PROGRESS:
      if (len >= 4 + sizeof(xeno_handshake_progress_t)) {
        xeno_handshake_progress_t* prog =
          (xeno_handshake_progress_t*)&data[4];
        hsState.messagePair = prog->message_pair;
        hsState.channel = prog->channel;
        hsState.elapsedSec = prog->elapsed_sec;
        Serial.printf("[MUSCLE] HS progress: pair=%d ch=%d t=%us\n",
                      hsState.messagePair, hsState.channel, hsState.elapsedSec);
      }
      break;

    case XENO_NOTIFY_HS_DONE:
      hsState.running = false;
      hsState.messagePair = XENO_HS_COMPLETE;
      hsState.hccapxReady = true;
      Serial.println("[MUSCLE] Handshake COMPLETE!");
      break;

    case XENO_NOTIFY_HS_FAILED:
      hsState.running = false;
      hsState.messagePair = XENO_HS_FAILED;
      Serial.println("[MUSCLE] Handshake FAILED");
      break;

    case XENO_NOTIFY_SNIFF_PROBE_TOP:
      if (len >= 4 + sizeof(xeno_sniff_probe_top_t)) {
        xeno_sniff_probe_top_t* top = (xeno_sniff_probe_top_t*)&data[4];
        memset(&probeTop, 0, sizeof(probeTop));
        strncpy(probeTop.topSsid, top->ssid, 32);
        probeTop.topSsid[32] = '\0';
        memcpy(probeTop.topBssid, top->bssid, 6);
        probeTop.topChannel  = top->channel;
        probeTop.uniqueCount = top->unique_count;
        probeTop.maxCount    = top->max_count;
        Serial.printf("[MUSCLE] PROBE TOP: \"%s\" CH:%d MAC=%02X:%02X:%02X:%02X:%02X:%02X (u=%d, c=%d)\n",
                      probeTop.topSsid, probeTop.topChannel,
                      probeTop.topBssid[0], probeTop.topBssid[1], probeTop.topBssid[2],
                      probeTop.topBssid[3], probeTop.topBssid[4], probeTop.topBssid[5],
                      probeTop.uniqueCount, probeTop.maxCount);
      }
      break;

    // ==================== JOIN NETWORK ====================
    case XENO_NOTIFY_JOIN_OK: {
      joinState.joined = true;
      if (len >= 4 + sizeof(xeno_join_result_t)) {
        xeno_join_result_t* res = (xeno_join_result_t*)&data[4];
        memcpy(joinState.ip, res->ip, 4);
        memcpy(joinState.gateway, res->gateway, 4);
        memcpy(joinState.netmask, res->netmask, 4);
        joinState.rssi = res->rssi;
        Serial.printf("[MUSCLE] JOIN OK! IP=%d.%d.%d.%d GW=%d.%d.%d.%d RSSI=%d\n",
                      res->ip[0], res->ip[1], res->ip[2], res->ip[3],
                      res->gateway[0], res->gateway[1], res->gateway[2], res->gateway[3],
                      res->rssi);
      }
      break;
    }
    case XENO_NOTIFY_JOIN_FAIL: {
      joinState.joined = false;
      memset(&joinState, 0, sizeof(joinState));
      Serial.println("[MUSCLE] JOIN FAILED");
      break;
    }
  }
}

void checkMuscleConnection() {
  if (millis() - muscleLastSeen > MUSCLE_TIMEOUT_MS) {
    if (muscleConnected) {
      muscleConnected = false;
      muscleReady = false;
      Serial.println("[MUSCLE] Connection LOST!");
    }
  }
}

// ---------------------------------------------------------------------------
// TX — framed protocol commands.
// Frame layout: SYNC | CMD | len_lo | len_hi | payload... | checksum
// Checksum is XOR over all preceding bytes.
// ---------------------------------------------------------------------------
void sendStartDeauth(const String& ssid, uint8_t channel, const uint8_t* bssid,
                     uint8_t method, uint16_t timeout) {
  uint8_t frame[512];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_START;

  uint16_t payload_len_pos = pos;
  pos += 2;

  frame[pos++] = ssid.length();
  memcpy(&frame[pos], ssid.c_str(), ssid.length());
  pos += ssid.length();

  frame[pos++] = channel;
  memcpy(&frame[pos], bssid, 6);
  pos += 6;

  frame[pos++] = method;
  frame[pos++] = timeout & 0xFF;
  frame[pos++] = (timeout >> 8) & 0xFF;

  uint16_t payload_len = pos - payload_len_pos - 2;
  frame[payload_len_pos] = payload_len & 0xFF;
  frame[payload_len_pos + 1] = (payload_len >> 8) & 0xFF;

  uint8_t cs = xeno_checksum(frame, pos);
  frame[pos++] = cs;

  Serial2.write(frame, pos);
  Serial2.flush();
}

void sendStopDeauth() {
  uint8_t frame[8];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_STOP;
  frame[pos++] = 0x00;
  frame[pos++] = 0x00;
  frame[pos++] = xeno_checksum(frame, 4);

  Serial2.write(frame, pos);
  Serial2.flush();
}

void sendStartSniff(uint8_t channel, const uint8_t* bssid, uint8_t method) {
  uint8_t frame[512];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_START_SNIFF;

  uint16_t payload_len_pos = pos;
  pos += 2;

  frame[pos++] = channel;
  uint8_t zero_bssid[6] = {0};
  memcpy(&frame[pos], bssid ? bssid : zero_bssid, 6);
  pos += 6;
  frame[pos++] = method;  // 0x00=ALL, 0x03=PROBE
  frame[pos++] = 0xFF;    // max_packets (unlimited)
  frame[pos++] = 0xFF;
  frame[pos++] = 0xFF;
  frame[pos++] = 0xFF;

  uint16_t payload_len = pos - payload_len_pos - 2;
  frame[payload_len_pos] = payload_len & 0xFF;
  frame[payload_len_pos + 1] = (payload_len >> 8) & 0xFF;

  uint8_t cs = xeno_checksum(frame, pos);
  frame[pos++] = cs;

  Serial2.write(frame, pos);
  Serial2.flush();

  Serial.printf("TX START_SNIFF CH=%d METHOD=%d\n", channel, method);
}

void sendStopSniff() {
  uint8_t frame[8];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_STOP_SNIFF;
  frame[pos++] = 0x00;
  frame[pos++] = 0x00;
  frame[pos++] = xeno_checksum(frame, 4);

  Serial2.write(frame, pos);
  Serial2.flush();
}

void requestPcapSize() {
  uint8_t frame[8];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_PCAP_SIZE;
  frame[pos++] = 0x00;
  frame[pos++] = 0x00;
  frame[pos++] = xeno_checksum(frame, 4);

  Serial2.write(frame, pos);
  Serial2.flush();
}

void requestPcapChunk(uint32_t offset, uint16_t chunkSize) {
  uint8_t frame[16];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_PCAP_CHUNK;

  uint16_t payload_len_pos = pos;
  pos += 2;

  frame[pos++] = offset & 0xFF;
  frame[pos++] = (offset >> 8) & 0xFF;
  frame[pos++] = (offset >> 16) & 0xFF;
  frame[pos++] = (offset >> 24) & 0xFF;
  frame[pos++] = chunkSize & 0xFF;
  frame[pos++] = (chunkSize >> 8) & 0xFF;

  uint16_t payload_len = pos - payload_len_pos - 2;
  frame[payload_len_pos] = payload_len & 0xFF;
  frame[payload_len_pos + 1] = (payload_len >> 8) & 0xFF;

  uint8_t cs = xeno_checksum(frame, pos);
  frame[pos++] = cs;

  Serial2.write(frame, pos);
  Serial2.flush();
}

// ---------------------------------------------------------------------------
// Handshake TX — mirror of sendStartDeauth layout but with
// XENO_CMD_START_HANDSHAKE / XENO_CMD_STOP_HANDSHAKE.
// ---------------------------------------------------------------------------
void sendStartHandshake(const String& ssid, uint8_t channel, const uint8_t* bssid,
                        uint8_t method, uint16_t timeout) {
  uint8_t frame[512];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_START_HANDSHAKE;

  uint16_t payload_len_pos = pos;
  pos += 2;

  frame[pos++] = ssid.length();
  memcpy(&frame[pos], ssid.c_str(), ssid.length());
  pos += ssid.length();

  frame[pos++] = channel;
  memcpy(&frame[pos], bssid, 6);
  pos += 6;

  frame[pos++] = method;
  frame[pos++] = timeout & 0xFF;
  frame[pos++] = (timeout >> 8) & 0xFF;

  uint16_t payload_len = pos - payload_len_pos - 2;
  frame[payload_len_pos] = payload_len & 0xFF;
  frame[payload_len_pos + 1] = (payload_len >> 8) & 0xFF;

  uint8_t cs = xeno_checksum(frame, pos);
  frame[pos++] = cs;

  Serial2.write(frame, pos);
  Serial2.flush();

  Serial.printf("TX START_HANDSHAKE SSID=%s CH=%d METHOD=%d TIMEOUT=%u\n",
                ssid.c_str(), channel, method, timeout);
}

void sendStopHandshake() {
  uint8_t frame[8];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_STOP_HANDSHAKE;
  frame[pos++] = 0x00;
  frame[pos++] = 0x00;
  frame[pos++] = xeno_checksum(frame, 4);

  Serial2.write(frame, pos);
  Serial2.flush();
}

// ---------------------------------------------------------------------------
// ensureMuscleConnected — front gate for any action that needs the radio.
// Returns true if the link is healthy (connected + recent heartbeat).
// Otherwise flashes ICON_OFFLINE on the OLED and returns false so the caller
// can abort cleanly without reaching for a radio that's not there.
// ---------------------------------------------------------------------------
bool ensureMuscleConnected() {
  if (muscleConnected && (millis() - muscleLastSeen) < MUSCLE_TIMEOUT_MS) {
    return true;
  }
  showMessage(ICON_OFFLINE, "MUSCLE OFFLINE!", 1200);
  return false;
}

// ---------------------------------------------------------------------------
// Join Network TX
// ---------------------------------------------------------------------------
void sendJoinNetwork(const String& ssid, uint8_t channel, const uint8_t* bssid, const String& password) {
  uint8_t frame[128];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_JOIN_NETWORK;

  uint16_t payload_len_pos = pos;
  pos += 2;

  // SSID (with length byte)
  uint8_t ssid_len = ssid.length();
  frame[pos++] = ssid_len;
  memcpy(&frame[pos], ssid.c_str(), ssid_len);
  pos += ssid_len;

  // Password (with length byte)
  uint8_t pw_len = password.length();
  frame[pos++] = pw_len;
  if (pw_len > 0 && password.c_str()) {
    memcpy(&frame[pos], password.c_str(), pw_len);
    pos += pw_len;
  }

  // Channel
  frame[pos++] = channel;

  // BSSID (6 bytes)
  uint8_t zero_bssid[6] = {0};
  memcpy(&frame[pos], bssid ? bssid : zero_bssid, 6);
  pos += 6;

  uint16_t payload_len = pos - payload_len_pos - 2;
  frame[payload_len_pos] = payload_len & 0xFF;
  frame[payload_len_pos + 1] = (payload_len >> 8) & 0xFF;

  uint8_t cs = xeno_checksum(frame, pos);
  frame[pos++] = cs;

  Serial2.write(frame, pos);
  Serial2.flush();

  Serial.printf("TX JOIN_NETWORK SSID=\"%s\" PW=\"%s\" CH=%d\n", ssid.c_str(), password.c_str(), channel);
}

void sendDisconnectSta() {
  uint8_t frame[8];
  uint16_t pos = 0;

  frame[pos++] = XENO_SYNC_CMD;
  frame[pos++] = XENO_CMD_DISCONNECT_STA;
  frame[pos++] = 0x00;
  frame[pos++] = 0x00;
  frame[pos++] = xeno_checksum(frame, 4);

  Serial2.write(frame, pos);
  Serial2.flush();

  Serial.println("TX DISCONNECT_STA");
}