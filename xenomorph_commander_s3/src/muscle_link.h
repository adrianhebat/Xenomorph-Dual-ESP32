#ifndef XENO_MUSCLE_LINK_H
#define XENO_MUSCLE_LINK_H

#include <Arduino.h>
#include "xenomorph_protocol.h"

// UART pins for the Commander <-> Muscle link (Serial2).
#define UART_TX_PIN 43
#define UART_RX_PIN 44

// How long without a heartbeat before we declare Muscle offline.
#define MUSCLE_TIMEOUT_MS 15000

// Connection state shared with the rest of the firmware.
extern bool muscleReady;
extern bool muscleConnected;
extern uint32_t muscleLastSeen;

// ---------------------------------------------------------------------------
// RX side — drain Serial2 and dispatch notifications.
// ---------------------------------------------------------------------------
void checkMuscleNotifications();
void parseMuscleNotification(uint8_t* data, uint16_t len);
void checkMuscleConnection();

// ---------------------------------------------------------------------------
// TX side — framed protocol commands. All return void; success/failure is
// observed later via the notification stream.
// ---------------------------------------------------------------------------
void sendStartDeauth(const String& ssid, uint8_t channel, const uint8_t* bssid,
                     uint8_t method, uint16_t timeout);
void sendStopDeauth();
void sendStartSniff(uint8_t channel, const uint8_t* bssid, uint8_t method);
void sendStopSniff();
void requestPcapSize();
void requestPcapChunk(uint32_t offset, uint16_t chunkSize);
void sendStartHandshake(const String& ssid, uint8_t channel, const uint8_t* bssid,
                        uint8_t method, uint16_t timeout);
void sendStopHandshake();

// ---------------------------------------------------------------------------
// Join Network TX/RX — sends XENO_CMD_JOIN_NETWORK, receives JOIN_OK/FAIL
// ---------------------------------------------------------------------------
void sendJoinNetwork(const String& ssid, uint8_t channel, const uint8_t* bssid, const String& password);
void sendDisconnectSta();

// Join result state (set by parseMuscleNotification, read by UI)
struct JoinState {
  bool joined;           // true when JOIN_OK received
  uint8_t  ip[4];
  uint8_t  gateway[4];
  uint8_t  netmask[4];
  int8_t   rssi;
};
extern JoinState joinState;

// Handshake progress state (set by parseMuscleNotification, read by OLED UI).
struct HandshakeState {
  bool     running;
  uint8_t  messagePair;     // 0..4, 0xFE complete, 0xFF failed
  uint8_t  channel;
  uint16_t elapsedSec;
  bool     hccapxReady;
};
extern HandshakeState hsState;

// ---------------------------------------------------------------------------
// Guard — call before any action that requires the Muscle radio. Returns true
// if the link is up, otherwise flashes "MUSCLE OFFLINE!" on the OLED and
// returns false so the caller can abort.
// ---------------------------------------------------------------------------
bool ensureMuscleConnected();

#endif // XENO_MUSCLE_LINK_H