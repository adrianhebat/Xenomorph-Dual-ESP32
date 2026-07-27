#ifndef XENO_SCAN_H
#define XENO_SCAN_H

#include <Arduino.h>

// Maximum networks the picker holds at once.
#define SCAN_MAX_NETWORKS 20

// Scan results — populated by scanTargetNetworks(), read by startEvilTwin(),
// startSniffing(), startProbeMode(), verifyCapturedPassword(), and by
// updateDisplay() in the .ino to render target names in footers.
extern String discoveredSSIDs[SCAN_MAX_NETWORKS];
extern int    discoveredRSSI[SCAN_MAX_NETWORKS];
extern uint8_t discoveredChannels[SCAN_MAX_NETWORKS];
extern uint8_t discoveredBSSID[SCAN_MAX_NETWORKS][6];

extern int  discoveredCount;
extern int  targetIndex;
extern bool targetScanned;
extern int  scanScrollOffset;

// Blocking: scans WiFi networks, then enters the picker loop until the user
// picks a target or backs out. On return, targetIndex/targetScanned reflect
// the choice.
void scanTargetNetworks();

#endif // XENO_SCAN_H