#ifndef XENO_ATTACK_HANDSHAKE_H
#define XENO_ATTACK_HANDSHAKE_H

#include <Arduino.h>
#include "xenomorph_protocol.h"

// ============================================================================
// attack_handshake.h — Commander-side controller for WPA/WPA2 handshake
// capture on the Muscle.
//
// State lives in muscle_link (hsState) — handshake progress comes from
// Muscle via UART notifications and is read directly by the OLED module.
// ============================================================================

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
void startHandshake();
void stopHandshake();

// Method cycle: PASSIVE -> BROADCAST -> ROGUE_AP -> PASSIVE.
// Updates the label shown in the menu (re-renders via updateDisplay()).
void cycleHandshakeMethod();

// Returns the current method label (lifetime: until next cycleHandshakeMethod).
const char* getHandshakeMethodLabel();

// Returns the current XENO_HS_METHOD_* code.
uint8_t getHandshakeMethodCode();

// ---------------------------------------------------------------------------
// User-facing screens
// ---------------------------------------------------------------------------

// Shows live capture progress (method / channel / message pair / elapsed).
// Blocks on a button press (LEFT) before returning.
void showHandshakeProgress();

// Shows the HCCAPX download screen — same visual style as downloadPcap() but
// points the user at /hccapx.
void downloadHccapx();

#endif // XENO_ATTACK_HANDSHAKE_H