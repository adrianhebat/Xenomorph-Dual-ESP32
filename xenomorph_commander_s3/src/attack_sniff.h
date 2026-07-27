#ifndef XENO_ATTACK_SNIFF_H
#define XENO_ATTACK_SNIFF_H

#include <Arduino.h>
#include <DNSServer.h>
#include <WebServer.h>

// ============================================================================
// attack_sniff.h — Evil twin + sniffing + info screens + captive portal.
//
// This module owns the bulk of the firmware's state and most of the network
// servers. It deliberately does NOT include oled_ui.h or scan.h here:
//   - Functions that need OLED primitives are declared with C-string params,
//     so consumers in the .ino can pass them.
//   - The .cpp includes oled_ui.h / scan.h / muscle_link.h directly.
//
// Cross-module state lives as extern below so other modules can read it
// without dragging this header's dependencies.
// ============================================================================

// Captive-portal / ManagementAP network config (defined in .cpp).
extern const byte DNS_PORT;
extern IPAddress apIP;
extern DNSServer  dnsServer;
extern WebServer  server;

// Attack lifecycle.
extern bool     isAttacking;
extern uint32_t attackStartTime;
extern String   capturedPass;
extern bool     loginReceived;
extern bool     passwordVerified;

// Sniff lifecycle.
extern bool     isSniffing;
extern uint32_t sniffPacketCount;
extern uint32_t sniffBufferSize;
extern uint8_t  sniffMethod;   // 0x00=ALL/EAPOL, 0x03=PROBE
extern bool     pcapReady;

// Join state.
extern bool isJoined;

// PROBE summary (updated by XENO_NOTIFY_SNIFF_PROBE_TOP).
struct ProbeSummary {
  char     topSsid[33];
  uint8_t  topBssid[6];
  uint8_t  topChannel;
  uint8_t  uniqueCount;
  uint8_t  maxCount;
};
extern ProbeSummary probeTop;

// ---------------------------------------------------------------------------
// Evil twin
// ---------------------------------------------------------------------------
void startEvilTwin();
void stopAttack();
void verifyCapturedPassword();

// ---------------------------------------------------------------------------
// Join Network
// ---------------------------------------------------------------------------
void joinTargetNetwork();
void showJoinProgressScreen();

// ---------------------------------------------------------------------------
// Sniffing
// ---------------------------------------------------------------------------
void startSniffing();
void startProbeMode();
void stopSniffing();
void downloadPcap();

// ---------------------------------------------------------------------------
// Info screens
// ---------------------------------------------------------------------------
void showCredentials();
void showSystemInfo();

#endif // XENO_ATTACK_SNIFF_H