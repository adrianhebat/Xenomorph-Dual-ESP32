#ifndef XENO_OLED_UI_H
#define XENO_OLED_UI_H

#include <Arduino.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// Layout OLED (128x64, Adafruit_GFX font default 6x8 size 1)
//   Frame border: outer rect + 4 corner accents
//   y=0..7      : header band (title + connection indicator)
//   y=8         : 1-px separator under header
//   y=10..54    : body band (5 rows of 9 px = 45 px) — scrollable
//   y=54        : 1-px separator above footer
//   y=56..62    : footer band (status + hints)

#define FRAME_X       0
#define FRAME_Y       0
#define FRAME_W       128
#define FRAME_H       64

#define HEADER_Y       0
#define HEADER_LINE_Y  8

#define BODY_Y0        10
#define ROW_H          9
#define ROWS_VISIBLE   5

#define FOOTER_LINE_Y  54
#define FOOTER_Y       56

#define CONTENT_X      2
#define CONTENT_W      124
#define SCROLLBAR_X    126

#define CHAR_W         6
#define CHAR_H         8

// OLED panel dimensions (must be defined before any use of Adafruit_SSD1306
// constructors that take width/height). XENO_-prefixed to avoid clashing with
// any future library-side definitions.
#define XENO_SCREEN_WIDTH  128
#define XENO_SCREEN_HEIGHT 64

// Status icons (4-char bracket style — fit in footer)
#define ICON_ATTACK    "[!] "
#define ICON_SNIFF     "[#] "
#define ICON_OK        "[OK]"
#define ICON_IDLE      "[--]"
#define ICON_NOTARGET  "[?] "
#define ICON_OFFLINE   "[X] "
#define ICON_ERR       "[X] "
#define ICON_JOIN      "[J] "

// Callback signature used by drawScrollableListEx to render a right column.
typedef void (*RowRightFn)(int idx, char* out, size_t outLen);

// Single OLED instance owned by oled_ui.cpp.
extern Adafruit_SSD1306 display;

// ---------------------------------------------------------------------------
// Cyberdeck UI primitives (pure display — no state writes outside this module)
// ---------------------------------------------------------------------------
void drawFrame();
void drawHeader(const char* title);
void drawFooter(const char* left, const char* right);
void drawCenteredText(int y, const char* text, uint8_t size);
void drawStatusScreen(const char* icon, const char* line1, const char* line2, uint32_t autoMs);
void drawLoadingDots(int y, const char* prefix);
void tickDots();

// ---------------------------------------------------------------------------
// Scrollable list — the workhorse
//   items      : array of C-string labels
//   count      : total item count
//   selected   : currently highlighted index in [0, count)
//   scrollOff  : index of topmost visible row
//   title      : header text
//   footerLeft / footerRight : status line
//   rightFn    : optional callback to render right column (e.g. RSSI)
// ---------------------------------------------------------------------------
void drawScrollableListEx(const char* const* items, int count,
                          int selected, int scrollOff,
                          const char* title,
                          const char* footerLeft, const char* footerRight,
                          RowRightFn rightFn);

void drawScrollableList(const char* const* items, int count,
                        int selected, int scrollOff,
                        const char* title,
                        const char* footerLeft, const char* footerRight);

// Right-column renderer used by scan.cpp's picker to show RSSI next to each
// SSID. Reads from the source set by oled_setRssiSource(); outputs an empty
// string when no source is wired.
void rssiRightFn(int idx, char* out, size_t outLen);

// ---------------------------------------------------------------------------
// Module-boundary setters — used by other modules to drive internal UI state
// without exposing file-static globals.
// ---------------------------------------------------------------------------
void oled_setRssiSource(const int* rssiArr, int count);  // pass NULL/0 to detach
void oled_resetDots();                                   // resets loading-dots phase

// ---------------------------------------------------------------------------
// High-level UI helpers — formerly lived in xenomorph_commander_s3.ino.
// Moved here so any module can flash a status message or trigger a full
// redraw without depending on the .ino translation unit. The .ino's loop()
// no longer needs to forward-declare them.
// ---------------------------------------------------------------------------
void showMessage(const char* icon, const char* msg, uint32_t autoMs);
void updateDisplay();

// Horizontal-scroll helpers for MENU_PROBE_STATUS SSID/MAC rows.
// direction is +1 (scroll right, reveal right side) or -1 (scroll left).
void handleProbeScroll(int8_t direction);
void resetProbeScroll();

#endif // XENO_OLED_UI_H
