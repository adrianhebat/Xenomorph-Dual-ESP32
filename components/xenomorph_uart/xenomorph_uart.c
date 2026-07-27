/**
 * @file xenomorph_uart.c
 * @author adrian (github.com/adrianhebat)
 * @date 2026-07-24
 * @copyright Copyright (c) 2026
 * 
 * @brief Implements UART Protocol
 */
#include "xenomorph_uart.h"
#include "xenomorph_protocol.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "string.h"

static const char* TAG = "xeno_uart";

ESP_EVENT_DEFINE_BASE(XENO_UART_EVENTS);

static QueueHandle_t uart_queue;
static TaskHandle_t uart_task_handle = NULL;

static void uart_event_task(void *pvParameters) {
    uart_event_t event;
    uint8_t rx_buf[XENO_UART_BUF_SIZE];
    uint16_t rx_pos = 0;
    int len;
    
    while (1) {
        if (xQueueReceive(uart_queue, &event, portMAX_DELAY)) {
            switch (event.type) {
                case UART_DATA:
                    len = uart_read_bytes(XENO_UART_NUM, rx_buf + rx_pos, 
                                             XENO_UART_BUF_SIZE - rx_pos, 0);
                    if (len > 0) {
                        rx_pos += len;
                        
                        if (rx_pos >= 4) {
                            uint16_t sync_pos = 0;
                            while (sync_pos < rx_pos && rx_buf[sync_pos] != XENO_SYNC_CMD) {
                                sync_pos++;
                            }
                            
                            if (sync_pos > 0) {
                                memmove(rx_buf, rx_buf + sync_pos, rx_pos - sync_pos);
                                rx_pos -= sync_pos;
                            }
                            
                            if (rx_pos >= 4) {
                                uint16_t payload_len = rx_buf[2] | (rx_buf[3] << 8);
                                uint16_t frame_len = 4 + payload_len + 1;
                                
                                if (rx_pos >= frame_len) {
                                    uint8_t cs = xeno_checksum(rx_buf, frame_len - 1);
                                    if (cs == rx_buf[frame_len - 1]) {
                                        uint8_t cmd_type = rx_buf[1];
                                        
                                        switch (cmd_type) {
                                            case XENO_CMD_START: {
                                                xeno_attack_params_t params;
                                                memset(&params, 0, sizeof(params));
                                                
                                                uint8_t ssid_len = rx_buf[4];
                                                if (ssid_len > 32) ssid_len = 32;
                                                
                                                memcpy(params.ssid, &rx_buf[5], ssid_len);
                                                params.ssid[ssid_len] = '\0';
                                                params.channel = rx_buf[5 + ssid_len];
                                                memcpy(params.bssid, &rx_buf[6 + ssid_len], 6);
                                                params.method = rx_buf[12 + ssid_len];
                                                params.timeout = rx_buf[13 + ssid_len] | 
                                                               (rx_buf[14 + ssid_len] << 8);
                                                
                                                ESP_LOGI(TAG, "START_DEAUTH: %s CH%d", params.ssid, params.channel);
                                                
                                                esp_event_post(XENO_UART_EVENTS, 
                                                              XENO_UART_EVENT_START_ATTACK,
                                                              &params, sizeof(params), 
                                                              portMAX_DELAY);
                                                
                                                xeno_uart_send_status(XENO_STATUS_OK, "Attack started");
                                                break;
                                            }
                                            
                                            case XENO_CMD_STOP: {
                                                ESP_LOGI(TAG, "STOP_DEAUTH");
                                                esp_event_post(XENO_UART_EVENTS,
                                                              XENO_UART_EVENT_STOP_ATTACK,
                                                              NULL, 0, portMAX_DELAY);
                                                xeno_uart_send_status(XENO_STATUS_OK, "Attack stopped");
                                                break;
                                            }
                                            
                                            case XENO_CMD_STATUS: {
                                                esp_event_post(XENO_UART_EVENTS,
                                                              XENO_UART_EVENT_STATUS_REQ,
                                                              NULL, 0, portMAX_DELAY);
                                                break;
                                            }
                                            
                                            // NEW: Sniffing commands
                                            case XENO_CMD_START_SNIFF: {
                                                xeno_sniff_params_t params;
                                                memset(&params, 0, sizeof(params));
                                                
                                                if (payload_len >= sizeof(xeno_sniff_params_t)) {
                                                    memcpy(&params, &rx_buf[4], sizeof(params));
                                                } else if (payload_len >= 8) {
                                                    // Minimal: channel(1) + bssid(6) + method(1)
                                                    params.channel = rx_buf[4];
                                                    memcpy(params.bssid, &rx_buf[5], 6);
                                                    params.sniff_method = rx_buf[11];
                                                    params.max_packets = 0;
                                                }
                                                
                                                ESP_LOGI(TAG, "START_SNIFF: CH%d method=%d", 
                                                         params.channel, params.sniff_method);
                                                
                                                esp_event_post(XENO_UART_EVENTS,
                                                              XENO_UART_EVENT_START_SNIFF,
                                                              &params, sizeof(params),
                                                              portMAX_DELAY);
                                                
                                                xeno_uart_send_status(XENO_STATUS_OK, "Sniffing started");
                                                break;
                                            }
                                            
                                            case XENO_CMD_STOP_SNIFF: {
                                                ESP_LOGI(TAG, "STOP_SNIFF");
                                                esp_event_post(XENO_UART_EVENTS,
                                                              XENO_UART_EVENT_STOP_SNIFF,
                                                              NULL, 0, portMAX_DELAY);
                                                // Response akan dikirim setelah sniffing berhenti
                                                break;
                                            }
                                            
                                            case XENO_CMD_PCAP_SIZE: {
                                                ESP_LOGI(TAG, "PCAP_SIZE request");
                                                esp_event_post(XENO_UART_EVENTS,
                                                              XENO_UART_EVENT_PCAP_SIZE,
                                                              NULL, 0, portMAX_DELAY);
                                                break;
                                            }
                                            
                                            case XENO_CMD_PCAP_CHUNK: {
                                                xeno_pcap_req_t req;
                                                if (payload_len >= sizeof(req)) {
                                                    memcpy(&req, &rx_buf[4], sizeof(req));
                                                    ESP_LOGD(TAG, "PCAP_CHUNK: offset=%u size=%d",
                                                             (unsigned int)req.offset, req.chunk_size);

                                                    esp_event_post(XENO_UART_EVENTS,
                                                                  XENO_UART_EVENT_PCAP_CHUNK,
                                                                  &req, sizeof(req),
                                                                  portMAX_DELAY);
                                                } else {
                                                    xeno_uart_send_status(XENO_STATUS_ERR, "Invalid chunk request");
                                                }
                                                break;
                                            }

                                            case XENO_CMD_START_HANDSHAKE: {
                                                xeno_handshake_params_t params;
                                                memset(&params, 0, sizeof(params));

                                                uint8_t ssid_len = rx_buf[4];
                                                if (ssid_len > 32) ssid_len = 32;

                                                memcpy(params.ssid, &rx_buf[5], ssid_len);
                                                params.ssid[ssid_len] = '\0';
                                                params.channel = rx_buf[5 + ssid_len];
                                                memcpy(params.bssid, &rx_buf[6 + ssid_len], 6);
                                                params.method  = rx_buf[12 + ssid_len];
                                                params.timeout = rx_buf[13 + ssid_len] |
                                                                (rx_buf[14 + ssid_len] << 8);

                                                ESP_LOGI(TAG, "START_HANDSHAKE: %s CH%d method=%d timeout=%u",
                                                         params.ssid, params.channel,
                                                         params.method, params.timeout);

                                                esp_event_post(XENO_UART_EVENTS,
                                                               XENO_UART_EVENT_START_HANDSHAKE,
                                                               &params, sizeof(params),
                                                               portMAX_DELAY);

                                                xeno_uart_send_status(XENO_STATUS_OK, "Handshake started");
                                                break;
                                            }

                                            case XENO_CMD_STOP_HANDSHAKE: {
                                                ESP_LOGI(TAG, "STOP_HANDSHAKE");
                                                esp_event_post(XENO_UART_EVENTS,
                                                               XENO_UART_EVENT_STOP_HANDSHAKE,
                                                               NULL, 0, portMAX_DELAY);
                                                xeno_uart_send_status(XENO_STATUS_OK, "Handshake stop requested");
                                                break;
                                            }

                                            // Network join commands
                                            case XENO_CMD_JOIN_NETWORK: {
                                                /* Variable-length layout:
                                                 *   [0] ssid_len (1 byte)
                                                 *   [1..ssid_len] SSID
                                                 *   [1+ssid_len] pw_len (1 byte)
                                                 *   [2+ssid_len .. 1+ssid_len+pw_len] password
                                                 *   [2+ssid_len+pw_len] channel (1 byte)
                                                 *   [+6] BSSID (6 bytes)
                                                 * Minimum: 1 + 1 + 1 + 6 = 9 bytes
                                                 */
                                                if (payload_len >= 9) {
                                                    xeno_join_params_t params;
                                                    memset(&params, 0, sizeof(params));

                                                    uint16_t p = 0;
                                                    uint8_t ssid_len = rx_buf[4 + p++];
                                                    if (ssid_len > 32) ssid_len = 32;
                                                    memcpy(params.ssid, &rx_buf[4 + p], ssid_len);
                                                    params.ssid[ssid_len] = '\0';
                                                    p += ssid_len;

                                                    uint8_t pw_len = rx_buf[4 + p++];
                                                    if (pw_len > 64) pw_len = 64;
                                                    if (p + pw_len <= payload_len - 7) {  // -7 for channel+BSSID
                                                        memcpy(params.password, &rx_buf[4 + p], pw_len);
                                                        params.password[pw_len] = '\0';
                                                        p += pw_len;
                                                    }

                                                    params.channel = rx_buf[4 + p++];
                                                    memcpy(params.bssid, &rx_buf[4 + p], 6);
                                                    p += 6;

                                                    ESP_LOGI(TAG, "JOIN_NETWORK: '%s' pw='%s' ch=%d BSSID=%02X:%02X:%02X:%02X:%02X:%02X",
                                                             params.ssid, params.password,
                                                             params.channel,
                                                             params.bssid[0], params.bssid[1], params.bssid[2],
                                                             params.bssid[3], params.bssid[4], params.bssid[5]);

                                                    esp_event_post(XENO_UART_EVENTS,
                                                                   XENO_UART_EVENT_JOIN_NETWORK,
                                                                   &params, sizeof(params),
                                                                   portMAX_DELAY);
                                                } else {
                                                    xeno_uart_send_status(XENO_STATUS_ERR, "Invalid join params");
                                                }
                                                break;
                                            }

                                            case XENO_CMD_DISCONNECT_STA: {
                                                ESP_LOGI(TAG, "DISCONNECT_STA");
                                                esp_event_post(XENO_UART_EVENTS,
                                                               XENO_UART_EVENT_DISCONNECT_STA,
                                                               NULL, 0, portMAX_DELAY);
                                                xeno_uart_send_status(XENO_STATUS_OK, "Disconnect requested");
                                                break;
                                            }

                                            default:
                                                ESP_LOGW(TAG, "Unknown command: 0x%02X", cmd_type);
                                                xeno_uart_send_status(XENO_STATUS_ERR, "Unknown command");
                                                break;
                                        }
                                    } else {
                                        ESP_LOGE(TAG, "Checksum error");
                                    }
                                    
                                    memmove(rx_buf, rx_buf + frame_len, rx_pos - frame_len);
                                    rx_pos -= frame_len;
                                }
                            }
                        }
                    }
                    break;
                    
                case UART_FIFO_OVF:
                    ESP_LOGW(TAG, "UART FIFO overflow");
                    uart_flush_input(XENO_UART_NUM);
                    rx_pos = 0;
                    break;
                    
                case UART_BUFFER_FULL:
                    ESP_LOGW(TAG, "UART buffer full");
                    uart_flush_input(XENO_UART_NUM);
                    rx_pos = 0;
                    break;
                    
                default:
                    break;
            }
        }
    }
}

esp_err_t xeno_uart_init(void) {
    ESP_LOGI(TAG, "Initializing XenoMorph UART...");
    
    uart_config_t uart_config = {
        .baud_rate = XENO_UART_BAUDRATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    
    ESP_ERROR_CHECK(uart_param_config(XENO_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(XENO_UART_NUM, XENO_UART_TX_PIN, XENO_UART_RX_PIN, 
                                  UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(XENO_UART_NUM, XENO_UART_BUF_SIZE * 2, 
                                         XENO_UART_BUF_SIZE * 2, 10, &uart_queue, 0));
    
    xTaskCreate(uart_event_task, "xeno_uart_task", 4096, NULL, 5, &uart_task_handle);
    
    ESP_LOGI(TAG, "UART initialized on GPIO%d(TX)/GPIO%d(RX)", XENO_UART_TX_PIN, XENO_UART_RX_PIN);
    return ESP_OK;
}

esp_err_t xeno_uart_send_status(uint8_t status, const char* message) {
    uint8_t frame[128];
    uint16_t pos = 0;
    
    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = status;
    
    uint16_t msg_len = message ? strlen(message) : 0;
    if (msg_len > 64) msg_len = 64;
    
    frame[pos++] = msg_len & 0xFF;
    frame[pos++] = (msg_len >> 8) & 0xFF;
    
    if (message && msg_len > 0) {
        memcpy(&frame[pos], message, msg_len);
        pos += msg_len;
    }
    
    uint8_t cs = xeno_checksum(frame, pos);
    frame[pos++] = cs;
    
    int ret = uart_write_bytes(XENO_UART_NUM, (const char*)frame, pos);
    ESP_LOGD(TAG, "Sent status 0x%02X, len=%d", status, pos);
    return (ret == pos) ? ESP_OK : ESP_FAIL;
}

// NEW: Send notification with payload
esp_err_t xeno_uart_send_notification(uint8_t notify_type, const uint8_t* payload, uint16_t payload_len) {
    uint8_t frame[XENO_UART_BUF_SIZE];
    uint16_t pos = 0;
    
    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = notify_type;
    frame[pos++] = payload_len & 0xFF;
    frame[pos++] = (payload_len >> 8) & 0xFF;
    
    if (payload && payload_len > 0) {
        memcpy(&frame[pos], payload, payload_len);
        pos += payload_len;
    }
    
    uint8_t cs = xeno_checksum(frame, pos);
    frame[pos++] = cs;
    
    int ret = uart_write_bytes(XENO_UART_NUM, (const char*)frame, pos);
    ESP_LOGD(TAG, "Sent notification 0x%02X, len=%d", notify_type, pos);
    return (ret == pos) ? ESP_OK : ESP_FAIL;
}

// NEW: Send PCAP chunk
esp_err_t xeno_uart_send_pcap_chunk(uint32_t offset, const uint8_t* data, uint16_t len, bool is_last) {
    uint8_t frame[XENO_UART_BUF_SIZE];
    uint16_t pos = 0;
    
    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = XENO_NOTIFY_PCAP_DATA;
    
    // Payload: offset(4) + len(2) + is_last(1) + data(len)
    uint16_t payload_len = 4 + 2 + 1 + len;
    frame[pos++] = payload_len & 0xFF;
    frame[pos++] = (payload_len >> 8) & 0xFF;
    
    // Offset
    frame[pos++] = offset & 0xFF;
    frame[pos++] = (offset >> 8) & 0xFF;
    frame[pos++] = (offset >> 16) & 0xFF;
    frame[pos++] = (offset >> 24) & 0xFF;
    
    // Length
    frame[pos++] = len & 0xFF;
    frame[pos++] = (len >> 8) & 0xFF;
    
    // Is last
    frame[pos++] = is_last ? 1 : 0;
    
    // Data
    if (data && len > 0) {
        memcpy(&frame[pos], data, len);
        pos += len;
    }
    
    uint8_t cs = xeno_checksum(frame, pos);
    frame[pos++] = cs;
    
    int ret = uart_write_bytes(XENO_UART_NUM, (const char*)frame, pos);
    ESP_LOGD(TAG, "Sent PCAP chunk offset=%u len=%d last=%d", (unsigned int)offset, len, is_last);
    return (ret == pos) ? ESP_OK : ESP_FAIL;
}

esp_err_t xeno_uart_send_response(uint8_t status, const uint8_t* payload, uint16_t payload_len) {
    uint8_t frame[512];
    uint16_t pos = 0;
    
    frame[pos++] = XENO_SYNC_RSP;
    frame[pos++] = status;
    frame[pos++] = payload_len & 0xFF;
    frame[pos++] = (payload_len >> 8) & 0xFF;
    
    if (payload && payload_len > 0) {
        memcpy(&frame[pos], payload, payload_len);
        pos += payload_len;
    }
    
    uint8_t cs = xeno_checksum(frame, pos);
    frame[pos++] = cs;
    
    int ret = uart_write_bytes(XENO_UART_NUM, (const char*)frame, pos);
    uart_wait_tx_done(XENO_UART_NUM, pdMS_TO_TICKS(100));
    
    return (ret == pos) ? ESP_OK : ESP_FAIL;
}