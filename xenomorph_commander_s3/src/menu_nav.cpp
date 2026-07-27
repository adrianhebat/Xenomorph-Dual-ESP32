#include "menu_nav.h"
#include "oled_ui.h"
#include "scan.h"
#include "attack_sniff.h"
#include "attack_handshake.h"
#include "muscle_link.h"

// ============================================================================
// menu_nav.cpp — menu state, button polling, and dispatcher.
//
// executeMenu() is the universal hub: every functional module's "user picked
// this menu item" entry point is wired here. Including scan.h,
// attack_sniff.h and attack_handshake.h is unavoidable — the menu cannot
// dispatch to functions it can't see. updateDisplay() lives in the .ino
// because it reads state from every module.
// ============================================================================

MenuState currentMenu = MENU_MAIN;
int menuIndex = 0;

const int MAIN_MENU_COUNT = 4;
const int EVIL_COUNT      = 5;
const int SNIFF_COUNT     = 6;
const int HS_COUNT        = 5;

// Original .ino also had these as globals. They were declared but never read
// cross-module (updateDisplay inlines the same literals). Keeping them
// file-static here so they exist for any future external reader without
// leaking as module surface.
static String mainMenuItems[] = { "[ EVIL TWIN ]", "[ SNIFFING ]", "[ HANDSHAKE ]", "[ SYSTEM INFO ]" };
static String evilTwinItems[] = { "[ SELECT TARGET ]", "[ START ATTACK ]", "[ JOIN NETWORK ]",
                                  "[ SHOW CREDENTIALS ]", "[ BACK ]" };
static String sniffingItems[] = { "[ SELECT TARGET ]", "[ START SNIFF ]", "[ START PROBE ]",
                                  "[ STOP SNIFF ]", "[ DOWNLOAD PCAP ]", "[ BACK ]" };
static String handshakeItems[] = { "[ SELECT TARGET ]", "[ METHOD: PASSIVE ]",
                                   "[ START ATTACK ]", "[ DOWNLOAD HCCAPX ]", "[ BACK ]" };

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
void handleNavigation() {
  if (currentMenu == MENU_PROBE_STATUS) {
    // UP/DOWN scrolls SSID+MAC horizontally (LEFT=BACK for escape)
    if (digitalRead(BTN_UP) == LOW) {
      handleProbeScroll(-1);
      delay(200);
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      handleProbeScroll(1);
      delay(200);
    }
    if (digitalRead(BTN_PUSH) == LOW) {
      executeMenu();
      delay(200);
    }
    if (digitalRead(BTN_LEFT) == LOW) {
      goBack();
      delay(200);
    }
    return;
  }

  if (digitalRead(BTN_UP) == LOW) {
    navigateUp();
    delay(200);
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    navigateDown();
    delay(200);
  }
  if (digitalRead(BTN_PUSH) == LOW) {
    executeMenu();
    delay(200);
  }
  if (digitalRead(BTN_LEFT) == LOW) {
    goBack();
    delay(200);
  }
}

void navigateUp() {
  int maxItems = getCurrentMenuCount();
  menuIndex = (menuIndex - 1 + maxItems) % maxItems;
  updateDisplay();
}

void navigateDown() {
  int maxItems = getCurrentMenuCount();
  menuIndex = (menuIndex + 1) % maxItems;
  updateDisplay();
}

int getCurrentMenuCount() {
  switch (currentMenu) {
    case MENU_MAIN:       return MAIN_MENU_COUNT;
    case MENU_EVIL_TWIN:  return EVIL_COUNT;
    case MENU_SNIFFING:   return SNIFF_COUNT;
    case MENU_HANDSHAKE:  return HS_COUNT;
    case MENU_PROBE_STATUS: return 1;  // No-op nav, only LEFT=BACK works
    default:              return 0;
  }
}

void goBack() {
  if (currentMenu == MENU_PROBE_STATUS) {
    // PROBE status screen → kembali ke SNIFFING menu
    currentMenu = MENU_SNIFFING;
    menuIndex = 0;
    updateDisplay();
  } else if (currentMenu != MENU_MAIN) {
    currentMenu = MENU_MAIN;
    menuIndex = 0;
    updateDisplay();
  }
}

void executeMenu() {
  switch (currentMenu) {
    case MENU_MAIN:
      switch (menuIndex) {
        case 0:
          currentMenu = MENU_EVIL_TWIN;
          menuIndex = 0;
          break;
        case 1:
          currentMenu = MENU_SNIFFING;
          menuIndex = 0;
          break;
        case 2:
          currentMenu = MENU_HANDSHAKE;
          menuIndex = 0;
          break;
        case 3: showSystemInfo(); break;
      }
      updateDisplay();
      break;

    case MENU_EVIL_TWIN:
      switch (menuIndex) {
        case 0: scanTargetNetworks(); break;
        case 1:
          if (isAttacking) {
            stopAttack();
          } else {
            startEvilTwin();
          }
          break;
        case 2:
          if (passwordVerified) {
            joinTargetNetwork();
          } else {
            showMessage(ICON_ERR, "VERIFY FIRST!", 1500);
          }
          break;
        case 3: showCredentials(); break;
        case 4: goBack(); break;
      }
      break;

    case MENU_SNIFFING:
      switch (menuIndex) {
        case 0: scanTargetNetworks(); break;
        case 1: startSniffing(); break;
        case 2:
          if (isJoined) {
            showMessage(ICON_OFFLINE, "PROBE:LOCKED!", 1500);
          } else {
            startProbeMode();
            // Always enter PROBE_STATUS — the sniffing confirmation arrived
            // (or will arrive shortly) over UART. The 2Hz refresh in loop()
            // handles the isSniffing toggle for the live data.
            currentMenu = MENU_PROBE_STATUS;
            menuIndex = 0;
            updateDisplay();
          }
          break;
        case 3: stopSniffing(); break;
        case 4: downloadPcap(); break;
        case 5: goBack(); break;
      }
      break;

    case MENU_HANDSHAKE:
      switch (menuIndex) {
        case 0: scanTargetNetworks(); break;
        case 1: cycleHandshakeMethod(); break;     // Toggles PASSIVE → BROADCAST → ROGUE_AP → PASSIVE
        case 2:
          if (hsState.running) {
            stopHandshake();
          } else {
            startHandshake();
          }
          break;
        case 3: downloadHccapx(); break;
        case 4: goBack(); break;
      }
      break;
  }
}