#ifndef XENO_MENU_NAV_H
#define XENO_MENU_NAV_H

#include <Arduino.h>

// Button pins (active-low, INPUT_PULLUP).
const int BTN_UP    = 10;
const int BTN_DOWN  = 11;
const int BTN_LEFT  = 12;
const int BTN_RIGHT = 13;
const int BTN_PUSH  = 14;

// Menu state machine.
enum MenuState {
  MENU_MAIN,
  MENU_EVIL_TWIN,
  MENU_SNIFFING,
  MENU_HANDSHAKE,
  MENU_SCANNING,
  MENU_PROBE_STATUS,
  MENU_JOIN_PROGRESS
};

extern MenuState currentMenu;
extern int menuIndex;

// Item counts for each menu screen. Defined in menu_nav.cpp.
extern const int MAIN_MENU_COUNT;
extern const int EVIL_COUNT;
extern const int SNIFF_COUNT;
extern const int HS_COUNT;  // Handshake menu item count

// ---------------------------------------------------------------------------
// Navigation — called once per loop from the .ino.
// ---------------------------------------------------------------------------
void handleNavigation();
void navigateUp();
void navigateDown();
void goBack();
void executeMenu();
int getCurrentMenuCount();

#endif // XENO_MENU_NAV_H