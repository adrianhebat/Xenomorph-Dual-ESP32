#include "scan.h"
#include "oled_ui.h"
#include "menu_nav.h"   // BTN_UP, BTN_DOWN, BTN_LEFT, BTN_PUSH
#include "attack_sniff.h" // targetIndex, targetSSID, targetChannel
#include <WiFi.h>

// ============================================================================
// scan.cpp — WiFi scan + interactive target picker.
//
// Owns the discovered* arrays and target selection state. Other modules
// (attack_sniff, updateDisplay in the .ino) read these as inputs.
//
// Module-boundary wiring for the RSSI right-column callback: instead of
// writing the oled_ui.cpp file-statics directly, we call oled_setRssiSource()
// which lives in oled_ui.h. This keeps scan and oled_ui decoupled.
// ============================================================================

String discoveredSSIDs[SCAN_MAX_NETWORKS];
int    discoveredRSSI[SCAN_MAX_NETWORKS];
uint8_t discoveredChannels[SCAN_MAX_NETWORKS];
uint8_t discoveredBSSID[SCAN_MAX_NETWORKS][6];

int  discoveredCount   = 0;
int  targetIndex       = 0;
bool targetScanned     = false;
int  scanScrollOffset  = 0;

void scanTargetNetworks() {
  // Brief pre-loader, then run scan in the background via the picker loop.
  drawStatusScreen(ICON_SNIFF, "SCANNING", "PLS WAIT", 1200);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  int n = WiFi.scanNetworks(false, true);
  discoveredCount = (n > SCAN_MAX_NETWORKS) ? SCAN_MAX_NETWORKS : n;

  for (int i = 0; i < discoveredCount; i++) {
    discoveredSSIDs[i] = WiFi.SSID(i);
    discoveredRSSI[i] = WiFi.RSSI(i);
    discoveredChannels[i] = WiFi.channel(i);
    memcpy(discoveredBSSID[i], WiFi.BSSID(i), 6);
  }
  WiFi.scanDelete();
  targetScanned = (discoveredCount > 0);

  if (discoveredCount == 0) {
    showMessage(ICON_ERR, "NO NETWORKS!", 1500);
    return;
  }

  int pick = 0;
  scanScrollOffset = 0;

  // Parallel char buffer for discoveredSSIDs — String to const char* conversion
  // happens every frame so we don't hold dangling pointers.
  char ssidBuf[SCAN_MAX_NETWORKS][17];
  const char* ssidPtrs[SCAN_MAX_NETWORKS];

  // Wire RSSI callback through the oled_ui module boundary.
  oled_setRssiSource(discoveredRSSI, discoveredCount);

  while (true) {
    // Rebuild C-string pointers from String array each frame
    for (int i = 0; i < discoveredCount; i++) {
      String s = discoveredSSIDs[i];
      if (s.length() > 16) s = s.substring(0, 16);
      strncpy(ssidBuf[i], s.c_str(), 16);
      ssidBuf[i][16] = 0;
      ssidPtrs[i] = ssidBuf[i];
    }

    char title[24];
    snprintf(title, sizeof(title), "TARGET %d/%d", pick + 1, discoveredCount);
    drawScrollableListEx(ssidPtrs, discoveredCount, pick, scanScrollOffset,
                         title, NULL, "PUSH=OK LEFT=BK", rssiRightFn);

    if (digitalRead(BTN_UP) == LOW) {
      pick = (pick - 1 + discoveredCount) % discoveredCount;
      delay(200);
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      pick = (pick + 1) % discoveredCount;
      delay(200);
    }
    if (digitalRead(BTN_PUSH) == LOW) {
      targetIndex = pick;
      targetScanned = true;
      delay(200);
      oled_setRssiSource(NULL, 0);
      updateDisplay();
      return;
    }
    if (digitalRead(BTN_LEFT) == LOW) {
      delay(200);
      oled_setRssiSource(NULL, 0);
      updateDisplay();
      return;
    }
  }
}