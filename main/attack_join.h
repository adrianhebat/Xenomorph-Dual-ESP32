/**
 * @file attack_join.h
 * @brief Network join module — ESP32 joins AP as STA with captured password.
 *
 * Usage:
 *   1. attack_join_init()          — register event handlers
 *   2. attack_join_start(params)   — connect to AP with password
 *   3. Check notification JOIN_OK/FAIL from MUSCLE
 *   4. attack_join_get_result()    — IP info
 *   5. attack_join_disconnect()    — leave network
 */
#ifndef ATTACK_JOIN_H
#define ATTACK_JOIN_H

#include <stdint.h>
#include "esp_err.h"
#include "xenomorph_protocol.h"

/**
 * @brief Initialize join module.
 *        Registers WiFi/IP event handlers. Must be called once at startup.
 */
void attack_join_init(void);

/**
 * @brief Start joining the target AP.
 *
 * Stops any running attack or sniff operation before switching to STA mode.
 * Connection is attempted in a background task; completion notified via
 * XENO_NOTIFY_JOIN_OK or XENO_NOTIFY_JOIN_FAIL.
 *
 * @param params  SSID, BSSID, password, channel of target AP.
 * @return ESP_OK on success, ESP_ERR_INVALID_STATE if already joining/joined.
 */
esp_err_t attack_join_start(const xeno_join_params_t *params);

/**
 * @brief Disconnect from the joined AP.
 *        Resets join state so a new join can be attempted.
 */
esp_err_t attack_join_disconnect(void);

/**
 * @brief Check whether the join succeeded.
 * @return true if CONNECTED + GOT_IP received.
 */
bool attack_join_is_joined(void);

/**
 * @brief Check whether a join attempt is in progress.
 * @return true if connecting…
 */
bool attack_join_is_joining(void);

/**
 * @brief Get connection result (IP, gateway, RSSI).
 * @return Pointer to last result (valid until next join attempt).
 */
const xeno_join_result_t *attack_join_get_result(void);

#endif // ATTACK_JOIN_H
