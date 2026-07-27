// ============================================================
// XENOMORPH COMMANDER v2.0 - REFACTORED
// Skinny entry point: just setup() and loop(). All real logic lives under
// src/ — split by concern:
//   src/oled_ui.h/.cpp       — OLED rendering, showMessage(), updateDisplay()
//   src/muscle_link.h/.cpp   — UART framing, ensureMuscleConnected()
//   src/menu_nav.h/.cpp      — button handling, menu state machine
//   src/scan.h/.cpp          — WiFi scan + target picker
//   src/attack_sniff.h/.cpp  — evil twin, sniffing, captive portal
// ============================================================

#include <Arduino.h>
#include <Wire.h>
#include <SPIFFS.h>

#include "xenomorph_protocol.h"
#include "src/oled_ui.h"
#include "src/muscle_link.h"
#include "src/menu_nav.h"
#include "src/scan.h"
#include "src/attack_sniff.h"
#include "src/attack_handshake.h"

// ---------------------------------------------------------------------------
// setup() — bring up the peripherals, splash the OLED, render the first frame.
// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  Serial2.begin(115200, SERIAL_8N1, UART_RX_PIN, UART_TX_PIN);
  Wire.begin(17, 18);

  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount Failed");
  } else {
    Serial.println("SPIFFS Mounted OK");
  }

  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_LEFT, INPUT_PULLUP);
  pinMode(BTN_RIGHT, INPUT_PULLUP);
  pinMode(BTN_PUSH, INPUT_PULLUP);

  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("OLED SSD1306 failed"));
  }

  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setCursor(8, 25);
  display.setTextSize(1);
  display.println("XENOMORPH COMMANDER");
  display.setCursor(35, 40);
  display.println("v2.0 S3");
  display.display();
  delay(2000);

  updateDisplay();
}

// ---------------------------------------------------------------------------
// loop() — drain the UART, run the menu state machine, serve any in-progress
// attack's captive portal. Everything else (state changes, OLED redraws) is
// pushed by the modules themselves when their state mutates.
// ---------------------------------------------------------------------------
void loop() {
  checkMuscleNotifications();
  checkMuscleConnection();

  // Trigger verification after login capture
  if (isAttacking && loginReceived) {
    loginReceived = false;
    verifyCapturedPassword();
    return;
  }

  // Continue normal attack handling
  if (isAttacking) {
    dnsServer.processNextRequest();
    server.handleClient();
  }

  // Live-refresh PROBE status screen at 2Hz while sniffing (after 3s settling)
  if (currentMenu == MENU_PROBE_STATUS && isSniffing) {
    static uint32_t lastTick = 0;
    static uint32_t settleUntil = 0;
    if (settleUntil == 0) settleUntil = millis() + 3000;
    if (millis() > settleUntil && millis() - lastTick > 500) {
      lastTick = millis();
      updateDisplay();
    }
  }

  handleNavigation();
}
