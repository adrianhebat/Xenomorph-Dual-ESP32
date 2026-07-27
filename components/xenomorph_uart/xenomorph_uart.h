#ifndef XENOMORPH_UART_H
#define XENOMORPH_UART_H

#include <stdint.h>
#include "esp_err.h"
#include "esp_event.h"

// UART configuration
#define XENO_UART_NUM       UART_NUM_2
#define XENO_UART_TX_PIN    GPIO_NUM_17
#define XENO_UART_RX_PIN    GPIO_NUM_16
#define XENO_UART_BAUDRATE  115200
#define XENO_UART_BUF_SIZE  512

// Event base untuk komunikasi dengan attack handler
ESP_EVENT_DECLARE_BASE(XENO_UART_EVENTS);

// Event types - EXTENDED
typedef enum {
    XENO_UART_EVENT_START_ATTACK,
    XENO_UART_EVENT_STOP_ATTACK,
    XENO_UART_EVENT_STATUS_REQ,
    XENO_UART_EVENT_START_SNIFF,    // NEW
    XENO_UART_EVENT_STOP_SNIFF,     // NEW
    XENO_UART_EVENT_PCAP_SIZE,      // NEW
    XENO_UART_EVENT_PCAP_CHUNK,     // NEW
    XENO_UART_EVENT_START_HANDSHAKE,
    XENO_UART_EVENT_STOP_HANDSHAKE,
    XENO_UART_EVENT_JOIN_NETWORK,
    XENO_UART_EVENT_DISCONNECT_STA
} xeno_uart_event_t;

/**
 * @brief Initialize UART communication with The Commander
 */
esp_err_t xeno_uart_init(void);

/**
 * @brief Send status response to The Commander
 */
esp_err_t xeno_uart_send_status(uint8_t status, const char* message);

/**
 * @brief Send notification with payload to The Commander (NEW)
 */
esp_err_t xeno_uart_send_notification(uint8_t notify_type, const uint8_t* payload, uint16_t payload_len);

/**
 * @brief Send PCAP data chunk to The Commander (NEW)
 */
esp_err_t xeno_uart_send_pcap_chunk(uint32_t offset, const uint8_t* data, uint16_t len, bool is_last);

esp_err_t xeno_uart_send_response(uint8_t status, const uint8_t* payload, uint16_t payload_len);

#endif // XENOMORPH_UART_H