#include "attack_handshake.h"
#include "oled_ui.h"
#include "muscle_link.h"
#include "scan.h"
#include "menu_nav.h"   // BTN_* pins
#include "xenomorph_protocol.h"

// ============================================================================
// attack_handshake.cpp — Commander-side handshake controller.
//
// Owns: handshake method selection. Sends CMD_START_HANDSHAKE /
// CMD_STOP_HANDSHAKE to the Muscle. Live progress is driven by notifications
// parsed in muscle_link.cpp (see hsState). The OLED UI in oled_ui.cpp reads
// hsState directly to render the live counter on the HANDSHAKE menu screen.
// ============================================================================

// Method state — cycled by cycleHandshakeMethod(), persisted across screens.
static uint8_t currentMethod = XENO_HS_METHOD_PASSIVE;

uint8_t getHandshakeMethodCode() {
  return currentMethod;
}

const char* getHandshakeMethodLabel() {
  switch (currentMethod) {
    case XENO_HS_METHOD_PASSIVE:   return "[ METHOD: PASSIVE ]";
    case XENO_HS_METHOD_BROADCAST: return "[ METHOD: BROADCAST ]";
    case XENO_HS_METHOD_ROGUE_AP:  return "[ METHOD: ROGUE AP ]";
    default:                       return "[ METHOD: ? ]";
  }
}

void cycleHandshakeMethod() {
  if (hsState.running) {
    showMessage(ICON_ERR, "STOP FIRST!", 1200);
    return;
  }

  switch (currentMethod) {
    case XENO_HS_METHOD_PASSIVE:   currentMethod = XENO_HS_METHOD_BROADCAST; break;
    case XENO_HS_METHOD_BROADCAST: currentMethod = XENO_HS_METHOD_ROGUE_AP;  break;
    case XENO_HS_METHOD_ROGUE_AP:  currentMethod = XENO_HS_METHOD_PASSIVE;   break;
    default:                       currentMethod = XENO_HS_METHOD_PASSIVE;   break;
  }
  updateDisplay();
}

// ---------------------------------------------------------------------------
// startHandshake
// Sends XENO_CMD_START_HANDSHAKE to Muscle with the currently selected
// target + method. Muscle replies via XENO_NOTIFY_HS_START when it has
// actually started sniffing.
// ---------------------------------------------------------------------------
void startHandshake() {
  if (!ensureMuscleConnected()) return;

  if (!targetScanned || discoveredCount == 0) {
    showMessage(ICON_ERR, "NO TARGET!", 1500);
    return;
  }

  if (hsState.running) {
    showMessage(ICON_ERR, "ALREADY RUNNING", 1500);
    return;
  }

  String ssid = discoveredSSIDs[targetIndex];
  uint8_t channel = discoveredChannels[targetIndex];
  uint8_t bssid[6];
  memcpy(bssid, discoveredBSSID[targetIndex], 6);

  // Reset progress state — Muscle will overwrite with notifications.
  hsState.running     = false;
  hsState.messagePair = 0;
  hsState.channel     = channel;
  hsState.elapsedSec  = 0;
  hsState.hccapxReady = false;

  // Brief deploy screen
  char buf[24];
  snprintf(buf, sizeof(buf), "CH:%d", channel);

  {
    display.clearDisplay();
    drawFrame();
    drawHeader(ICON_ATTACK " DEPLOY");
    drawCenteredText(14, ICON_ATTACK, 2);
    int w = strlen(buf) * CHAR_W;
    display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 40);
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.print(buf);
    drawFooter(NULL, "PLS WAIT");
    display.display();
    delay(800);
  }

  // 300s default timeout — same as evil twin.
  sendStartHandshake(ssid, channel, bssid, currentMethod, 300);
  Serial.printf("[HS] start SSID=%s CH=%d method=%d\n",
                ssid.c_str(), channel, currentMethod);
}

// ---------------------------------------------------------------------------
// stopHandshake
// Sends XENO_CMD_STOP_HANDSHAKE and waits up to 3s for Muscle to send
// XENO_NOTIFY_HS_DONE / XENO_NOTIFY_HS_FAILED. On complete, hsState will
// have hccapxReady=true and messagePair=XENO_HS_COMPLETE so the user can
// pull the file via /hccapx.
// ---------------------------------------------------------------------------
void stopHandshake() {
  if (!hsState.running && hsState.messagePair != XENO_HS_COMPLETE &&
      hsState.messagePair != XENO_HS_FAILED) {
    showMessage(ICON_OFFLINE, "NOT RUNNING", 1500);
    return;
  }

  sendStopHandshake();

  uint32_t start = millis();
  oled_resetDots();
  uint32_t lastDot = 0;

  // Drain notifications for up to 3s while animating dots.
  while (millis() - start < 3000) {
    checkMuscleNotifications();
    if (!hsState.running) break;

    if (millis() - lastDot > 250) {
      tickDots();
      lastDot = millis();
      display.clearDisplay();
      drawFrame();
      drawHeader(ICON_SNIFF " STOP");
      drawCenteredText(14, ICON_SNIFF, 2);
      drawLoadingDots(40, "STOPPING");
      drawFooter(NULL, "LEFT=BACK");
      display.display();
    }
    delay(10);
  }

  if (hsState.messagePair == XENO_HS_COMPLETE) {
    showMessage(ICON_OK, "HS CAPTURED!", 2000);
  } else if (hsState.messagePair == XENO_HS_FAILED) {
    showMessage(ICON_ERR, "HS FAILED", 2000);
  } else {
    Serial.println("[HS] stop timeout");
    hsState.running = false;
    showMessage(ICON_ERR, "STOPPED (T/O)", 1500);
  }
}

// ---------------------------------------------------------------------------
// showHandshakeProgress
// Called from updateDisplay() footer hint when running. Renders a fresh
// frame with method / channel / pair / elapsed on every call.
// ---------------------------------------------------------------------------
void showHandshakeProgress() {
  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_SNIFF " HANDSHAKE");

  display.setTextSize(1);
  display.setTextColor(WHITE);

  // Method line
  display.setCursor(CONTENT_X, 14);
  display.print("Method: ");
  switch (currentMethod) {
    case XENO_HS_METHOD_PASSIVE:   display.print("PASSIVE");   break;
    case XENO_HS_METHOD_BROADCAST: display.print("BROADCAST"); break;
    case XENO_HS_METHOD_ROGUE_AP:  display.print("ROGUE AP");  break;
    default:                       display.print("?");         break;
  }

  // Channel
  char buf[24];
  snprintf(buf, sizeof(buf), "CH:%d", hsState.channel);
  display.setCursor(CONTENT_X, 24);
  display.print(buf);

  // Message pair progress — render as M1..M4 dots.
  display.setCursor(CONTENT_X, 36);
  display.print("Pair: ");
  uint8_t mp = hsState.messagePair;
  if (mp == XENO_HS_FAILED) {
    display.print("FAILED");
  } else if (mp == XENO_HS_COMPLETE) {
    display.print("COMPLETE");
  } else {
    // mp values 0..5 map to 0..4 visible messages per hccapx semantics.
    uint8_t visible = (mp >= 4) ? 4 : mp;
    for (int i = 0; i < 4; i++) {
      display.print(i < visible ? "O" : ".");
    }
    display.print(" M");
  }

  // Elapsed seconds
  snprintf(buf, sizeof(buf), "T:%us", hsState.elapsedSec);
  display.setCursor(CONTENT_X, 46);
  display.print(buf);

  drawFooter(NULL, "LEFT=BACK");
  display.display();
}

// ---------------------------------------------------------------------------
// downloadHccapx
// Same UX as downloadPcap(): shows the URL on screen, waits for any button.
// ---------------------------------------------------------------------------
void downloadHccapx() {
  if (!hsState.hccapxReady) {
    showMessage(ICON_OFFLINE, "NO HCCAPX", 1500);
    return;
  }

  display.clearDisplay();
  drawFrame();
  drawHeader(ICON_OK " HS READY");
  drawCenteredText(12, ICON_OK, 2);

  display.setTextSize(1);
  display.setTextColor(WHITE);

  const char* line1 = "Connect to:";
  const char* line2 = "192.168.4.1";
  const char* line3 = "/hccapx";

  int w;
  w = strlen(line1) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 28); display.print(line1);
  w = strlen(line2) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 38); display.print(line2);
  w = strlen(line3) * CHAR_W; display.setCursor((XENO_SCREEN_WIDTH - w) / 2, 46); display.print(line3);

  drawFooter(NULL, "ANY=BACK");
  display.display();

  while (digitalRead(BTN_LEFT) == HIGH &&
         digitalRead(BTN_RIGHT) == HIGH &&
         digitalRead(BTN_PUSH) == HIGH &&
         digitalRead(BTN_UP) == HIGH &&
         digitalRead(BTN_DOWN) == HIGH) {
    delay(10);
  }
  delay(200);
  updateDisplay();
}