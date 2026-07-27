/**
 * @file wsl_bypasser.h
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Provides interface for Wi-Fi Stack Libraries bypasser
 * 
 * This component bypasses blocking mechanism that doesn't allow sending some arbitrary 802.11 frames like deauth etc.
 */
#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include "esp_wifi_types.h"

/**
 * @brief Sends frame in frame_buffer using esp_wifi_80211_tx but bypasses blocking mechanism
 * 
 * @param frame_buffer 
 * @param size size of frame buffer
 */
void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);

/**
 * @brief Sends deauthentication frame with forged source AP from given ap_record
 *
 * This will send deauthentication frame acting as frame from given AP, and destination will be broadcast
 * MAC address - \c ff:ff:ff:ff:ff:ff
 *
 * @param ap_record AP record with valid AP information
 */
void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record);

/**
 * @brief Sends disassociation frame with forged source AP from given ap_record
 *
 * Used as alternative to deauth to bypass pattern-based filtering in modern drivers
 * (e.g. Realtek Wireless Connection Manager on Windows 10/11).
 * Destination will be broadcast MAC address - \c ff:ff:ff:ff:ff:ff.
 *
 * @param ap_record AP record with valid AP information
 */
void wsl_bypasser_send_disassoc_frame(const wifi_ap_record_t *ap_record);

/**
 * @brief Sends deauth frame with custom reason code to evade reason-code filtering
 *
 * Supports reason codes 0x01 (Unspecified), 0x02 (Previous auth invalid),
 * 0x07 (Class 3 frame from nonassociated STA), or any other reason by dynamic
 * modification. Rotating reason codes prevents driver-level whitelisting.
 *
 * @param ap_record AP record with valid AP information
 * @param reason_code 802.11 reason code (1 byte). Common values: 0x01, 0x02, 0x04, 0x07
 */
void wsl_bypasser_send_deauth_with_reason(const wifi_ap_record_t *ap_record, uint8_t reason_code);

/**
 * @brief Sends aggressive multi-frame attack — deauth (reason 2) + deauth (reason 7) + disassoc
 *
 * Three frames per call. Designed to bypass broadcast-deauth filtering in Realtek/Intel drivers.
 * High CPU efficiency — uses single-pass memcpy and shares BSSID patch logic.
 *
 * @param ap_record AP record with valid AP information
 */
void wsl_bypasser_send_aggressive_multi(const wifi_ap_record_t *ap_record);

#endif