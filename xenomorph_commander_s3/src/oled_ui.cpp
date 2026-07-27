#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "oled_ui.h"
#include "muscle_link.h"  // muscleConnected
#include "menu_nav.h"     // currentMenu, menuIndex, MenuState, BTN_*
#include "scan.h"         // discoveredSSIDs, discoveredCount, targetIndex, targetScanned
#include "attack_sniff.h" // isAttacking, isSniffing, passwordVerified, attackStartTime,
                          // sniffPacketCount, sniffBufferSize, pcapReady, sniffMethod,
                          // probeTop
#include "attack_handshake.h"
#include "xenomorph_protocol.h"

// ============================================================================
// oled_ui.cpp — OLED display primitives for the Commander.
// All Cyberdeck frame/header/footer/list rendering lives here. This module
// owns the single display instance and exposes two setters so other modules
// can drive the loading-dots animation and the RSSI right-column callback
// without poking at file-static globals directly.
// ============================================================================

// Single OLED instance (extern'd via oled_ui.h).
Adafruit_SSD1306 display(XENO_SCREEN_WIDTH, XENO_SCREEN_HEIGHT, &Wire, -1);

// File-static state used by drawLoadingDots / tickDots.
static uint8_t dotPhase = 0;

// File-static state shared with drawScrollableListEx via rssiRightFn callback.
// Set by scan.cpp via oled_setRssiSource() at scan start; cleared (NULL/0) on
// scan exit.
static int* g_scanRssi = NULL;
static int g_scanCount = 0;

// Horizontal-scroll cursor for PROBE_STATUS rows (SSID + MAC). Set by
// handleProbeScroll(), reset by resetProbeScroll(). Read by updateDisplay().
// Declared at file scope (not inside updateDisplay()) so both the read site
// inside updateDisplay() and the write site in handleProbeScroll() share the
// same variable.
static int8_t probeScrollOffset = 0;

// ---------------------------------------------------------------------------
// Setters exposed for other modules
// ---------------------------------------------------------------------------
void oled_setRssiSource(const int* rssiArr, int count) {
  g_scanRssi = const_cast<int*>(rssiArr);
  g_scanCount = count;
}

void oled_resetDots() {
  dotPhase = 0;
}

// ---------------------------------------------------------------------------
// Cyberdeck UI helpers
// ---------------------------------------------------------------------------

// Outer 1-px frame + 4 corner accents (small L-shapes at each corner)
//  -> 7 draw calls total, very cheap. Gives "panel mounted in chassis" look.
void drawFrame() {
  display.drawRect(FRAME_X, FRAME_Y, FRAME_W, FRAME_H, WHITE);
  // Top-left L
  display.drawLine(2, 2, 5, 2, WHITE);
  display.drawLine(2, 2, 2, 5, WHITE);
  // Top-right inverted L
  display.drawLine(125, 2, 122, 2, WHITE);
  display.drawLine(125, 2, 125, 5, WHITE);
  // Bottom-left inverted L (mirrored vertically)
  display.drawLine(2, 61, 2, 58, WHITE);
  display.drawLine(2, 61, 5, 61, WHITE);
  // Bottom-right L (mirrored)
  display.drawLine(125, 61, 122, 61, WHITE);
  display.drawLine(125, 61, 125, 58, WHITE);
}

// Title left-justified, connection indicator right-justified, 1-px line below.
void drawHeader(const char* title) {
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(CONTENT_X, HEADER_Y);
  display.print(title);

  // Connection indicator at top-right
  display.setCursor(XENO_SCREEN_WIDTH - 18, HEADER_Y);
  display.print(muscleConnected ? "[M]" : "[X]");

  // Separator line under header
  display.drawLine(CONTENT_X, HEADER_LINE_Y, XENO_SCREEN_WIDTH - CONTENT_X - 1, HEADER_LINE_Y, WHITE);
}

// 1-px line above footer, then status text. Right text right-aligned.
void drawFooter(const char* left, const char* right) {
  display.drawLine(CONTENT_X, FOOTER_LINE_Y, XENO_SCREEN_WIDTH - CONTENT_X - 1, FOOTER_LINE_Y, WHITE);

  display.setTextSize(1);
  display.setTextColor(WHITE);

  if (left) {
    display.setCursor(CONTENT_X, FOOTER_Y);
    display.print(left);
  }
  if (right) {
    int rightLen = strlen(right);
    int rightX = XENO_SCREEN_WIDTH - CONTENT_X - (rightLen * CHAR_W);
    if (rightX < CONTENT_X) rightX = CONTENT_X;
    display.setCursor(rightX, FOOTER_Y);
    display.print(right);
  }
}

// Center text horizontally at given y. Text size 1 or 2.
void drawCenteredText(int y, const char* text, uint8_t size) {
  display.setTextSize(size);
  display.setTextColor(WHITE);
  int textW = strlen(text) * CHAR_W * size;
  int x = (XENO_SCREEN_WIDTH - textW) / 2;
  if (x < 0) x = 0;
  display.setCursor(x, y);
  display.print(text);
}

// Loading dots animation — call every ~250 ms from a polling loop.
void drawLoadingDots(int y, const char* prefix) {
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(CONTENT_X, y);
  display.print(prefix);
  // 3 boxes, phase 0..3 — last one is empty in phase 0, filled progressively
  int px = CONTENT_X + strlen(prefix) * CHAR_W + 2;
  for (int i = 0; i < 3; i++) {
    display.fillRect(px + i * 6, y + 6, 4, 2, (i < (dotPhase + 1)) ? WHITE : BLACK);
  }
}
void tickDots() {
  dotPhase = (dotPhase + 1) % 3;
}

// Status screen — frame + big icon + 1-2 body lines + auto-return or wait LEFT.
//   autoMs == 0  -> blocking: wait for BTN_LEFT (use for info screens user reads)
//   autoMs  > 0  -> non-blocking: return after autoMs, also early-return on LEFT
void drawStatusScreen(const char* icon, const char* line1, const char* line2, uint32_t autoMs) {
  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_IDLE " STATUS");
  // Big icon centered at y=14 (size 2 -> 16 px tall, fits in body band)
  drawCenteredText(14, icon, 2);
  // Body lines — laid out in y=36 and y=46 so they sit cleanly between
  // the icon (ends at y~29) and the footer separator (y=54).
  display.setTextSize(1);
  display.setTextColor(WHITE);
  if (line1) {
    int textW = strlen(line1) * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - textW) / 2, 36);
    display.print(line1);
  }
  if (line2) {
    int textW = strlen(line2) * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - textW) / 2, 46);
    display.print(line2);
  }
  drawFooter(NULL, "LEFT=BACK");
  display.display();

  if (autoMs > 0) {
    // Non-blocking — auto-return. LEFT bails early.
    uint32_t start = millis();
    while (millis() - start < autoMs) {
      if (digitalRead(BTN_LEFT) == LOW) {
        delay(200);
        return;
      }
      delay(10);
    }
  } else {
    // Blocking — user must press LEFT to continue.
    while (digitalRead(BTN_LEFT) == HIGH) {
      delay(10);
    }
    delay(200);
  }
}

// Callback used by drawScrollableListEx when scan wants RSSI shown on the right.
// Reads from file-statics set by scan.cpp via oled_setRssiSource().
void rssiRightFn(int idx, char* out, size_t outLen) {
  if (!g_scanRssi || idx < 0 || idx >= g_scanCount) {
    out[0] = 0;
    return;
  }
  snprintf(out, outLen, "%ddBm", g_scanRssi[idx]);
}

void drawScrollableListEx(const char* const* items, int count,
                          int selected, int scrollOff,
                          const char* title,
                          const char* footerLeft, const char* footerRight,
                          RowRightFn rightFn) {
  // Clamp scrollOffset so selected is always visible
  if (selected < 0) selected = 0;
  if (selected >= count) selected = count - 1;
  if (scrollOff < 0) scrollOff = 0;
  if (selected < scrollOff) scrollOff = selected;
  if (selected >= scrollOff + ROWS_VISIBLE) scrollOff = selected - ROWS_VISIBLE + 1;
  int maxOff = count - ROWS_VISIBLE;
  if (maxOff < 0) maxOff = 0;
  if (scrollOff > maxOff) scrollOff = maxOff;

  display.clearDisplay();
  drawFrame();
  drawHeader(title);

  display.setTextSize(1);
  // Draw rows
  for (int row = 0; row < ROWS_VISIBLE; row++) {
    int idx = scrollOff + row;
    if (idx >= count) break;
    int y = BODY_Y0 + row * ROW_H;
    bool isSel = (idx == selected);

    if (isSel) {
      // Filled bar + black text (monochrome invert)
      display.fillRect(CONTENT_X, y, CONTENT_W, ROW_H - 1, WHITE);
      display.setTextColor(BLACK, WHITE);
      display.setCursor(CONTENT_X + 2, y + 1);
      display.print('>');
      display.setCursor(CONTENT_X + 10, y + 1);
      display.print(items[idx]);
      // Right column (if any)
      if (rightFn) {
        char buf[8];
        buf[0] = 0;
        rightFn(idx, buf, sizeof(buf));
        if (buf[0]) {
          int blen = strlen(buf);
          display.setCursor(CONTENT_X + CONTENT_W - blen * CHAR_W - 8, y + 1);
          display.print(buf);
        }
      }
      display.setCursor(CONTENT_X + CONTENT_W - 8, y + 1);
      display.print('<');
      display.setTextColor(WHITE);
    } else {
      display.setTextColor(WHITE);
      // Empty gutter so text doesn't reflow when selection moves
      display.setCursor(CONTENT_X + 2, y + 1);
      display.print(' ');
      display.setCursor(CONTENT_X + 10, y + 1);
      display.print(items[idx]);
      if (rightFn) {
        char buf[8];
        buf[0] = 0;
        rightFn(idx, buf, sizeof(buf));
        if (buf[0]) {
          int blen = strlen(buf);
          display.setCursor(CONTENT_X + CONTENT_W - blen * CHAR_W - 8, y + 1);
          display.print(buf);
        }
      }
      display.setCursor(CONTENT_X + CONTENT_W - 8, y + 1);
      display.print(' ');
    }
  }

  // Scrollbar (only if list is longer than window)
  if (count > ROWS_VISIBLE) {
    int trackY = BODY_Y0 + 1;
    int trackH = ROWS_VISIBLE * ROW_H - 3;       // -3 = breathing room
    int thumbH = (trackH * ROWS_VISIBLE) / count;
    if (thumbH < 3) thumbH = 3;
    int travel = trackH - thumbH;
    int thumbY = trackY;
    if (maxOff > 0) {
      thumbY = trackY + (travel * scrollOff) / maxOff;
    }
    // Clear track first (overwrite any leftover pixels)
    display.fillRect(SCROLLBAR_X, trackY, 2, trackH, BLACK);
    display.fillRect(SCROLLBAR_X, thumbY, 2, thumbH, WHITE);
  }

  drawFooter(footerLeft, footerRight);
  display.display();
}

// Convenience overload without right column
void drawScrollableList(const char* const* items, int count,
                        int selected, int scrollOff,
                        const char* title,
                        const char* footerLeft, const char* footerRight) {
  drawScrollableListEx(items, count, selected, scrollOff, title, footerLeft, footerRight, NULL);
}

// ============================================================================
// High-level helpers — formerly lived in xenomorph_commander_s3.ino.
// ============================================================================

// showMessage — thin wrapper over drawStatusScreen. Used by every module to
// flash a status icon + message to the user. If autoMs > 0, redraw the
// underlying menu afterward so the message doesn't sit on top forever.
void showMessage(const char* icon, const char* msg, uint32_t autoMs) {
  drawStatusScreen(icon, msg, NULL, autoMs);
  if (autoMs > 0) {
    display.setTextSize(1);
    updateDisplay();
  }
}

// updateDisplay — the universal state reader. Lives here (the view layer)
// because it reads globals from every state-owning module. Centralizing it
// in the UI module is cheaper than making every state module depend on every
// other module + the UI primitives.
void updateDisplay() {
  switch (currentMenu) {
    case MENU_MAIN: {
      const char* items[MAIN_MENU_COUNT] = {
        "[ EVIL TWIN ]",
        "[ SNIFFING ]",
        "[ HANDSHAKE ]",
        "[ SYSTEM INFO ]"
      };
      const char* footerRight = muscleConnected ? ICON_OK " ONLINE" : ICON_OFFLINE " OFFLINE";
      const char* footerLeft = NULL;
      if (hsState.running) {
        footerLeft = ICON_SNIFF " HS RUN";
      } else if (isSniffing) {
        char buf[24];
        snprintf(buf, sizeof(buf), "Pkt:%u", sniffPacketCount);
        footerLeft = buf;
        footerRight = ICON_SNIFF " SNIFF";
      } else if (isAttacking) {
        footerLeft = ICON_ATTACK " ATTACKING";
      }
      drawScrollableList(items, MAIN_MENU_COUNT, menuIndex, 0,
                         "XENOMORPH v2.0", footerLeft, footerRight);
      break;
    }

    case MENU_EVIL_TWIN: {
      const char* items[EVIL_COUNT] = {
        "[ SCAN TARGET ]",
        isAttacking ? "[ STOP ATTACK ]" : "[ START ATTACK ]",
        "[ JOIN NETWORK ]",
        "[ CREDENTIALS ]",
        "[ BACK ]"
      };
      const char* footerLeft = NULL;
      const char* footerRight = NULL;
      if (passwordVerified) {
        footerLeft = ICON_OK " VERIFIED";
        footerRight = ICON_OK " PASS OK";
      } else if (isAttacking) {
        char buf[16];
        uint32_t elapsed = (millis() - attackStartTime) / 1000;
        snprintf(buf, sizeof(buf), "T:%us", (unsigned)elapsed);
        footerLeft = ICON_ATTACK " ATTACKING";
        footerRight = buf;
      } else if (targetScanned && discoveredCount > 0) {
        char buf[24];
        String ssid = discoveredSSIDs[targetIndex];
        if (ssid.length() > 14) ssid = ssid.substring(0, 14);
        snprintf(buf, sizeof(buf), "Tgt:%s", ssid.c_str());
        footerLeft = buf;
      } else {
        footerLeft = ICON_NOTARGET " NO TARGET";
      }
      drawScrollableList(items, EVIL_COUNT, menuIndex, 0,
                         "EVIL TWIN MODE", footerLeft, footerRight);
      break;
    }

    case MENU_SNIFFING: {
      const char* items[SNIFF_COUNT] = {
        "[ SELECT TARGET ]",
        "[ START SNIFF ]",
        isJoined ? "[ PROBE:LOCKED ]" : "[ START PROBE ]",
        "[ STOP SNIFF ]",
        "[ DOWNLOAD PCAP ]",
        "[ BACK ]"
      };
      const char* footerLeft = NULL;
      const char* footerRight = NULL;
      if (isSniffing) {
        char bufL[20], bufR[20];
        if (sniffMethod == XENO_SNIFF_PROBE) {
          snprintf(bufL, sizeof(bufL), "Prb:%u", (unsigned)probeTop.uniqueCount);
          snprintf(bufR, sizeof(bufR), "%s", probeTop.topSsid[0] ? probeTop.topSsid : "--");
          if (strlen(bufR) > 14) bufR[14] = '\0';
        } else {
          snprintf(bufL, sizeof(bufL), "Pkt:%u", sniffPacketCount);
          snprintf(bufR, sizeof(bufR), "Buf:%u", (unsigned)sniffBufferSize);
        }
        footerLeft = bufL;
        footerRight = bufR;
      } else if (pcapReady) {
        footerLeft = ICON_OK " PCAP READY";
      } else if (targetScanned && discoveredCount > 0) {
        char buf[24];
        String ssid = discoveredSSIDs[targetIndex];
        if (ssid.length() > 14) ssid = ssid.substring(0, 14);
        snprintf(buf, sizeof(buf), "Tgt:%s", ssid.c_str());
        footerLeft = buf;
      } else {
        footerLeft = ICON_IDLE " READY";
      }
      drawScrollableList(items, SNIFF_COUNT, menuIndex, 0,
                         "SNIFFING MODE", footerLeft, footerRight);
      break;
    }

    case MENU_HANDSHAKE: {
      const char* items[HS_COUNT] = {
        "[ SELECT TARGET ]",
        getHandshakeMethodLabel(),
        hsState.running ? "[ STOP ATTACK ]" : "[ START ATTACK ]",
        "[ DOWNLOAD HCCAPX ]",
        "[ BACK ]"
      };
      const char* footerLeft = NULL;
      const char* footerRight = NULL;
      if (hsState.running) {
        // Short left-only footer to avoid column overlap on 128px display
        char buf[24];
        snprintf(buf, sizeof(buf), ICON_SNIFF " MP:%d T:%us", hsState.messagePair, hsState.elapsedSec);
        footerLeft = buf;
      } else if (hsState.hccapxReady) {
        footerLeft = ICON_OK " HCCAPX READY";
      } else if (targetScanned && discoveredCount > 0) {
        char buf[24];
        String ssid = discoveredSSIDs[targetIndex];
        if (ssid.length() > 14) ssid = ssid.substring(0, 14);
        snprintf(buf, sizeof(buf), "Tgt:%s", ssid.c_str());
        footerLeft = buf;
      } else {
        footerLeft = ICON_IDLE " READY";
      }
      drawScrollableList(items, HS_COUNT, menuIndex, 0,
                         "HANDSHAKE CAPTURE", footerLeft, footerRight);
      break;
    }

    case MENU_PROBE_STATUS: {
      display.clearDisplay();
      drawFrame();
      drawHeader(ICON_SNIFF " PROBE MODE");
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.setTextWrap(false);

      // Baris 1: MODE + CHANNEL (fixed)
      display.setCursor(CONTENT_X, 10);
      display.printf("MODE: PROBE  CH:%d", probeTop.topChannel);

      // Baris 2: STATUS (fixed)
      display.setCursor(CONTENT_X, 20);
      display.print(isSniffing ? "STATUS: RUNNING" : "STATUS: STOPPED");

      // Baris 3: PROBES count (fixed)
      display.setCursor(CONTENT_X, 30);
      display.printf("PROBES: %d UNIQUE", probeTop.uniqueCount);

      // Baris 4: TOP SSID (scrollable horizontally)
      display.setCursor(CONTENT_X - probeScrollOffset * CHAR_W, 40);
      display.print("TOP: \"");
      if (probeTop.topSsid[0]) {
        display.print(probeTop.topSsid);
      } else {
        display.print("--");
      }
      display.print("\"");

      // Baris 5: Full MAC address (scrollable horizontally)
      display.setCursor(CONTENT_X - probeScrollOffset * CHAR_W, 50);
      if (probeTop.topBssid[0] || probeTop.topBssid[1]) {
        char macStr[20];
        snprintf(macStr, sizeof(macStr), "MAC:%02X:%02X:%02X:%02X:%02X:%02X",
                 probeTop.topBssid[0], probeTop.topBssid[1], probeTop.topBssid[2],
                 probeTop.topBssid[3], probeTop.topBssid[4], probeTop.topBssid[5]);
        display.print(macStr);
      } else {
        display.print("MAC:--:--:--:--:--:--");
      }

      drawFooter(NULL, "LEFT=BACK");
      display.display();
      break;
    }
  }
}

// =====================================================================
// Probe scroll helpers (used by MENU_PROBE_STATUS)
// =====================================================================

void resetProbeScroll() {
  probeScrollOffset = 0;
}

// Compute the longer of the two scrollable rows (TOP SSID vs MAC) so we cap
// scroll at the worst case. Char count = strlen(label) + prefixes.
static int8_t probeScrollMax() {
  int16_t ssidLen = strlen(probeTop.topSsid);
  int16_t macLen  = 17;  // XX:XX:XX:XX:XX:XX
  int16_t max     = ssidLen > macLen ? ssidLen : macLen;
  // content width = 124 px / 6 px-per-char ≈ 20 chars visible
  // extra chars beyond visible window = max - 20
  int16_t extra = max - 20;
  if (extra < 0) extra = 0;
  if (extra > 30) extra = 30;  // hard cap so we never scroll to nowhere
  return (int8_t)extra;
}

void handleProbeScroll(int8_t direction) {
  int8_t max = probeScrollMax();
  probeScrollOffset += direction;
  if (probeScrollOffset < 0)  probeScrollOffset = 0;
  if (probeScrollOffset > max) probeScrollOffset = max;
  updateDisplay();
}