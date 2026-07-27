#ifndef XENOMORPH_PROTOCOL_H
#define XENOMORPH_PROTOCOL_H

#include <stdint.h>

// Sync markers
#define XENO_SYNC_CMD       0xAA
#define XENO_SYNC_RSP       0xBB

// Command types
#define XENO_CMD_START          0x01
#define XENO_CMD_STOP           0x02
#define XENO_CMD_STATUS         0x03
#define XENO_CMD_START_SNIFF    0x05
#define XENO_CMD_STOP_SNIFF     0x06
#define XENO_CMD_PCAP_SIZE      0x07
#define XENO_CMD_PCAP_CHUNK     0x08
#define XENO_CMD_START_HANDSHAKE  0x09
#define XENO_CMD_STOP_HANDSHAKE   0x0A
#define XENO_CMD_JOIN_NETWORK     0x0B
#define XENO_CMD_DISCONNECT_STA   0x0C

// Response status
#define XENO_STATUS_OK          0x00
#define XENO_STATUS_ERR         0x01
#define XENO_STATUS_RUN         0x02
#define XENO_STATUS_IDLE        0x03

// Notification types
#define XENO_NOTIFY_READY       0x10
#define XENO_NOTIFY_ATTACKING   0x11
#define XENO_NOTIFY_STATS       0x12
#define XENO_NOTIFY_ERROR       0x1F
#define XENO_NOTIFY_SNIFF_START 0x20
#define XENO_NOTIFY_SNIFF_STATS 0x21
#define XENO_NOTIFY_SNIFF_STOP  0x22
#define XENO_NOTIFY_PCAP_DATA   0x23
#define XENO_NOTIFY_DOWNLOAD_READY 0x24
#define XENO_NOTIFY_HS_START    0x30
#define XENO_NOTIFY_HS_PROGRESS 0x31
#define XENO_NOTIFY_HS_DONE     0x32
#define XENO_NOTIFY_HS_FAILED   0x33
#define XENO_NOTIFY_SNIFF_PROBE_TOP 0x34   // Probe top SSID + unique count
// Network join notifications
#define XENO_NOTIFY_JOIN_OK     0x40
#define XENO_NOTIFY_JOIN_FAIL   0x41

// Attack methods
#define XENO_METHOD_COMBINE     0x02

// Sniffing methods
#define XENO_SNIFF_ALL          0x00
#define XENO_SNIFF_EAPOL        0x01
#define XENO_SNIFF_DATA         0x02
#define XENO_SNIFF_PROBE        0x03

// Handshake capture methods
#define XENO_HS_METHOD_PASSIVE   0x00
#define XENO_HS_METHOD_BROADCAST 0x01
#define XENO_HS_METHOD_ROGUE_AP  0x02

// Handshake message-pair completion codes (mirrors hccapx message_pair)
#define XENO_HS_MSG_M1   1
#define XENO_HS_MSG_M2   2
#define XENO_HS_MSG_M3   3
#define XENO_HS_MSG_M4   4
#define XENO_HS_COMPLETE 0xFE
#define XENO_HS_FAILED   0xFF

// Protocol limits
#define XENO_MAX_SSID_LEN       32
#define XENO_MAX_PAYLOAD        512

// Structures
typedef struct __attribute__((packed)) {
    char ssid[33];
    uint8_t channel;
    uint8_t bssid[6];
    uint8_t method;
    uint16_t timeout;
} xeno_attack_params_t;

typedef struct __attribute__((packed)) {
    uint8_t channel;
    uint8_t bssid[6];
    uint8_t sniff_method;
    uint32_t max_packets;
} xeno_sniff_params_t;

typedef struct __attribute__((packed)) {
    uint32_t packets_captured;
    uint32_t buffer_size;
    uint32_t max_size;
    uint8_t  channel;
    uint8_t  running;
    uint8_t  active_probes;   // Probe mode: unique SSID with count >= 2
} xeno_sniff_stats_t;

typedef struct __attribute__((packed)) {
    uint32_t offset;
    uint16_t chunk_size;
} xeno_pcap_req_t;

typedef struct __attribute__((packed)) {
    char     ssid[33];
    uint8_t  channel;
    uint8_t  bssid[6];
    uint8_t  method;
    uint16_t timeout;
} xeno_handshake_params_t;

typedef struct __attribute__((packed)) {
    uint8_t  message_pair;
    uint8_t  channel;
    uint16_t elapsed_sec;
    uint8_t  ready;
} xeno_handshake_progress_t;

typedef struct __attribute__((packed)) {
    char     ssid[33];   // Top SSID (highest count)
    uint8_t  bssid[6];   // BSSID/MAC of top SSID AP
    uint8_t  channel;    // Current hop channel
    uint8_t  unique_count; // Total unique SSIDs seen
    uint8_t  max_count;    // Count of top SSID
} xeno_sniff_probe_top_t;

// Join network parameters
typedef struct __attribute__((packed)) {
    char     ssid[33];
    uint8_t  bssid[6];
    char     password[65];   // WPA2 max 63 chars
    uint8_t  channel;
} xeno_join_params_t;

// Join network result (sent back to Commander)
typedef struct __attribute__((packed)) {
    uint8_t  ip[4];
    uint8_t  gateway[4];
    uint8_t  netmask[4];
    int8_t   rssi;
} xeno_join_result_t;

// Checksum helper
#ifdef __cplusplus
extern "C" {
#endif

static inline uint8_t xeno_checksum(const uint8_t* data, uint16_t len) {
    uint8_t cs = 0;
    for (uint16_t i = 0; i < len; i++) {
        cs ^= data[i];
    }
    return cs;
}

#ifdef __cplusplus
}
#endif

#endif // XENOMORPH_PROTOCOL_H