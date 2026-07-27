/**
 * @file attack_join.c
 * @brief Network join module — ESP32 joins target AP as STA with given password.
 *
 * Flow:
 *   1. Cancel all ongoing attacks/sniffs
 *   2. Switch AP mode to STA only
 *   3. Call wifictl_sta_connect_to_ap()
 *   4. Wait for WL_CONNECTED or timeout (15s)
 *   5. Collect IP info + RSSI → notify Commander via UART
 *   6. Either JOIN_OK or JOIN_FAIL
 */

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "lwip/netdb.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "attack.h"
#include "attack_dos.h"
#include "attack_sniff.h"
#include "attack_join.h"
#include "wifi_controller.h"
#include "xenomorph_uart.h"

static const char *TAG = "main:attack_join";

/* Internal state */
static bool joining        = false;
static bool joined         = false;
static char join_ssid[XENO_MAX_SSID_LEN + 1] = {0};
static uint8_t join_bssid[6] = {0};
static uint8_t join_channel = 0;

/* Result data */
static xeno_join_result_t join_result = {
    .ip = {0, 0, 0, 0},
    .gateway = {0, 0, 0, 0},
    .netmask = {0, 0, 0, 0},
    .rssi = 0
};

/* Internal event group for connection completion */
static EventGroupHandle_t join_evt_group = NULL;

#define JOIN_EVT_CONNECTED  BIT0
#define JOIN_EVT_FAILED     BIT1

/* Forward declarations */
static void join_connection_event_handler(void *arg, esp_event_base_t event_base,
                                          int32_t event_id, void *event_data);
static void join_attempt_task(void *pvParameter);

/* ========== Public API ========== */

void attack_join_init(void)
{
    /* Create event group if not already done */
    if (join_evt_group == NULL) {
        join_evt_group = xEventGroupCreate();
        if (join_evt_group) {
            ESP_LOGI(TAG, "Join event group created");
        }
    }

    /* Register WiFi events */
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START,
                               &join_connection_event_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
                               &join_connection_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                               &join_connection_event_handler, NULL);
}

esp_err_t attack_join_start(const xeno_join_params_t *params)
{
    if (joining || joined) {
        ESP_LOGW(TAG, "Already joining/joined — disconnect first");
        return ESP_ERR_INVALID_STATE;
    }

    /* Copy parameters */
    memset(join_ssid, 0, sizeof(join_ssid));
    memset(join_bssid, 0, sizeof(join_bssid));
    memcpy(join_ssid, params->ssid, strlen(params->ssid));
    join_ssid[strlen(params->ssid)] = '\0';
    memcpy(join_bssid, params->bssid, 6);
    join_channel = params->channel;

    joining = true;
    joined = false;

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "JOIN ATTEMPT: %s (ch=%d)", join_ssid, join_channel);
    ESP_LOGI(TAG, "BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             join_bssid[0], join_bssid[1], join_bssid[2],
             join_bssid[3], join_bssid[4], join_bssid[5]);
    ESP_LOGI(TAG, "PASSWORD: '%s'", params->password);
    ESP_LOGI(TAG, "========================================");

    /* Clear result */
    memset(&join_result, 0, sizeof(join_result));
    join_result.rssi = -128; /* Invalid default */

    /* Clear event bits before launching */
    xEventGroupClearBits(join_evt_group, JOIN_EVT_CONNECTED | JOIN_EVT_FAILED);

    /* Set STA config with SSID + password + BSSID + channel */
    wifi_config_t sta_config = {0};
    size_t ssid_len = strlen(params->ssid);
    if (ssid_len > 32) ssid_len = 32;
    memcpy(sta_config.sta.ssid, params->ssid, ssid_len);
    sta_config.sta.ssid[ssid_len] = '\0';

    size_t pw_len = strlen(params->password);
    if (pw_len > 63) pw_len = 63;
    memcpy(sta_config.sta.password, params->password, pw_len);
    sta_config.sta.password[pw_len] = '\0';

    sta_config.sta.bssid_set = 1;  // Enable BSSID filtering (connect to specific AP)
    memcpy(sta_config.sta.bssid, join_bssid, 6);
    sta_config.sta.channel = join_channel;
    sta_config.sta.scan_method = WIFI_FAST_SCAN;  // Don't scan, just connect

    ESP_LOGI(TAG, "Setting STA config: SSID='%s' PW='%s' CH=%d",
             params->ssid, params->password, join_channel);

    esp_err_t ret = esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set STA config: %d", ret);
        joining = false;
        xeno_uart_send_notification(XENO_NOTIFY_JOIN_FAIL, NULL, 0);
        return ret;
    }

    /* Set channel explicitly */
    esp_wifi_set_channel(join_channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(100));  // Let channel settle

    /* Disable power-save during join. Otherwise ESP32 enters MIN_MODEM and
     * duty-cycles the radio, which delays DHCP DISCOVER/OFFER and ARP,
     * masquerading as a join failure on busy/legacy APs. */
    esp_wifi_set_ps(WIFI_PS_NONE);

    /* Now connect */
    ret = esp_wifi_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_connect() failed: %d", ret);
        joining = false;
        xeno_uart_send_notification(XENO_NOTIFY_JOIN_FAIL, NULL, 0);
        return ret;
    }
    ESP_LOGI(TAG, "esp_wifi_connect() issued — waiting for connection...");

    /* Launch timeout watcher in background task */
    xTaskCreate(join_attempt_task, "join_attempt", 4096, NULL, 6, NULL);

    return ESP_OK;
}

esp_err_t attack_join_disconnect(void)
{
    if (!joined && !joining) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Disconnecting from %s...", join_ssid);

    wifictl_sta_disconnect();

    /* Re-enable default power-save (we disabled it during join) */
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    /* Restore APSTA mode so AP+services resume */
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    /* Restore original AP MAC (may have been changed by RogueAP earlier) */
    wifictl_restore_ap_mac();

    /* Restart ManagementAP so user can reach 192.168.4.1 again */
    wifictl_mgmt_ap_start();

    joining = false;
    joined  = false;

    /* Clear result */
    memset(&join_result, 0, sizeof(join_result));
    join_result.rssi = 0;

    memset(join_ssid, 0, sizeof(join_ssid));
    memset(join_bssid, 0, sizeof(join_bssid));
    join_channel = 0;

    ESP_LOGI(TAG, "Disconnected — APSTA mode restored");
    return ESP_OK;
}

bool attack_join_is_joined(void)
{
    return joined;
}

bool attack_join_is_joining(void)
{
    return joining;
}

const xeno_join_result_t *attack_join_get_result(void)
{
    return &join_result;
}

/* ========== Internal ========== */

static void join_connection_event_handler(void *arg, esp_event_base_t event_base,
                                          int32_t event_id, void *event_data)
{
    if (!joining && !joined) {
        return;
    }

    switch (event_id) {
    case WIFI_EVENT_STA_START:
        ESP_LOGI(TAG, "STA interface started");
        esp_wifi_connect();
        break;

    case WIFI_EVENT_STA_CONNECTED: {
        ESP_LOGI(TAG, "Connected to AP");
        break;
    }

    case WIFI_EVENT_STA_DISCONNECTED: {
        ESP_LOGI(TAG, "Disconnected from AP");

        if (joining) {
            /* esp_wifi_connect() will retry internally, but our timeout
               will catch it. Signal JOIN_FAILED when timeout fires. */
        }
        break;
    }

    case IP_EVENT_STA_GOT_IP: {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)event_data;

        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&evt->ip_info.ip));

        if (joining) {
            /* We got IP — connection successful! */
            joining = false;
            joined  = true;

            /* Fill result — ip_addr_t.addr adalah uint32_t, cast ke uint8_t* untuk memcpy 4 bytes */
            memcpy(join_result.ip, (uint8_t *)&evt->ip_info.ip.addr, 4);
            memcpy(join_result.gateway, (uint8_t *)&evt->ip_info.gw.addr, 4);
            memcpy(join_result.netmask, (uint8_t *)&evt->ip_info.netmask.addr, 4);

            /* Get RSSI using v4.1.4 API */
            wifi_ap_record_t ap_rec;
            if (esp_wifi_sta_get_ap_info(&ap_rec) == ESP_OK) {
                join_result.rssi = (int8_t)ap_rec.rssi;
                ESP_LOGI(TAG, "RSSI: %d dBm", (int)ap_rec.rssi);
            }

            /* Send JOIN_OK notification */
            xeno_uart_send_notification(XENO_NOTIFY_JOIN_OK,
                                        (uint8_t *)&join_result,
                                        sizeof(join_result));

            ESP_LOGI(TAG, "========================================");
            ESP_LOGI(TAG, "JOINED NETWORK: %s", join_ssid);
            ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&evt->ip_info.ip));
            ESP_LOGI(TAG, "GW: " IPSTR, IP2STR(&evt->ip_info.gw));
            ESP_LOGI(TAG, "RSSI: %d", (int)join_result.rssi);
            ESP_LOGI(TAG, "========================================");

            /* Notify via event group — timeout task will stop */
            xEventGroupSetBits(join_evt_group, JOIN_EVT_CONNECTED);
        }

        break;
    }
    }
}

static void join_attempt_task(void *pvParameter)
{
    /* Wait for GOT_IP or timeout.
     * DHCP on real-world routers (especially busy/legacy gear) can legitimately
     * take 30–60 s. The previous 20 s timeout caused false JOIN_FAIL on
     * networks like AIRINE where DHCP takes ~43 s. */
    EventBits_t bits = xEventGroupWaitBits(join_evt_group,
                                           JOIN_EVT_CONNECTED | JOIN_EVT_FAILED,
                                           pdFALSE, pdFALSE, pdMS_TO_TICKS(60000));

    if (bits & JOIN_EVT_CONNECTED) {
        /* Already handled — success notification sent */
        goto cleanup;
    }

    /* Timeout — force failure */
    if (joining) {
        joining = false;
        joined  = false;

        /* True failure — send JOIN_FAIL */
        ESP_LOGE(TAG, "JOIN FAILED — timeout or wrong password for %s", join_ssid);

        xeno_uart_send_notification(XENO_NOTIFY_JOIN_FAIL,
                                    (uint8_t *)&join_result,
                                    sizeof(join_result));
    }

cleanup:
    joining = false;
    xEventGroupClearBits(join_evt_group, JOIN_EVT_CONNECTED | JOIN_EVT_FAILED);
    vTaskDelete(NULL);
}
