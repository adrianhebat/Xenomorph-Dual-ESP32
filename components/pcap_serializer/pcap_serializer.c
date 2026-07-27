/**
 * @file pcap_serializer.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 *
 * @brief Implementation of PCAP serializer.
 *
 * Buffer dialokasikan awal sebesar global header (28 bytes), lalu
 * diperbesar incrementally via realloc per frame. Guardrail di-set
 * di PCAP_GUARD_SIZE — jika buffer melebihi batas, log warning.
 * Buffer tetap boleh tumbuh melewati guardrail selama heap cukup,
 * tapi akan di-reset otomatis di pcap_serializer_init() berikutnya.
 */
#include "pcap_serializer.h"

#include <stdint.h>
#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

static const char *TAG = "pcap_serializer";


/**
 * @brief Constants according to reference
 *
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
//@{
#define SNAPLEN 65535
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4
//@}

/**
 * @brief Constants according to reference
 *
 * @see Ref: http://www.tcpdump.org/linktypes.html (LINKTYPE_IEEE802_11)
 */
#define LINKTYPE_IEEE802_11 105

/**
 * @brief Guardrail — log warning jika buffer melebihi ukuran ini.
 *
 * Pada ESP32 (tanpa PSRAM) heap terbatas, tapi realloc incremental
 * bisa tumbuh sampai > 200KB. Guardrail ini mencegah buffer tumbuh
 * terlalu besar tanpa benar-benar menghentikan operasi.
 */
#define PCAP_GUARD_SIZE 60000

static unsigned pcap_size = 0;
static uint8_t *pcap_buffer = NULL;

uint8_t *pcap_serializer_init(){
    // Make sure memory from previous capture is freed
    free(pcap_buffer);
    // Start with global header only (28 bytes)
    pcap_buffer = (uint8_t *)malloc(sizeof(pcap_global_header_t));
    if (pcap_buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate initial PCAP buffer");
        pcap_size = 0;
        return NULL;
    }
    // Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
    pcap_global_header_t pcap_global_header = {
        .magic_number = PCAP_MAGIC_NUMBER,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN,
        .network = LINKTYPE_IEEE802_11
    };
    pcap_size = sizeof(pcap_global_header_t);
    memcpy(pcap_buffer, &pcap_global_header, sizeof(pcap_global_header_t));
    return pcap_buffer;
}

void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec){
    if(size == 0){
        ESP_LOGD(TAG, "Frame size is 0. Not appending anything.");
        return;
    }
    // Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#record-packet-header
    // Stored packet/frame cannot be larger than SNAPLEN
    if(size > SNAPLEN){
        size = SNAPLEN;
    }
    pcap_record_header_t pcap_record_header = {
        .ts_sec = ts_usec / 1000000,
        .ts_usec = ts_usec % 1000000,
        .incl_len = size,
        .orig_len = size,
    };

    unsigned frame_total = sizeof(pcap_record_header_t) + size;
    /* Hard cap: refuse to grow past PCAP_GUARD_SIZE. Without this, after
     * join_network() the netif stack holds enough heap to make incremental
     * realloc fail repeatedly, flooding UART and eventually corrupting
     * FreeRTOS task lists (vTaskDelete -> uxListRemove crash). */
    if (pcap_size + frame_total > PCAP_GUARD_SIZE) {
        static uint32_t drop_count = 0;
        if ((drop_count++ % 100) == 0) {
            ESP_LOGW(TAG, "PCAP buffer full (%u / %u bytes), dropping frames (total dropped: %u)",
                     pcap_size, PCAP_GUARD_SIZE, drop_count);
        }
        return;
    }
    uint8_t *new_buf = realloc(pcap_buffer, pcap_size + frame_total);
    if (new_buf == NULL) {
        /* Throttled log: only log every 50 failures to avoid flooding UART
         * and corrupting FreeRTOS heap under low-memory conditions. */
        static uint32_t drop_count = 0;
        if ((drop_count++ % 50) == 0) {
            ESP_LOGE(TAG, "realloc failed for PCAP buffer (current: %u bytes, need +%u bytes, total dropped: %u)",
                     pcap_size, frame_total, drop_count);
        }
        return;
    }
    memcpy(&new_buf[pcap_size], &pcap_record_header, sizeof(pcap_record_header_t));
    memcpy(&new_buf[pcap_size + sizeof(pcap_record_header_t)], buffer, size);
    pcap_buffer = new_buf;
    pcap_size += frame_total;
}

void pcap_serializer_deinit(){
    free(pcap_buffer);
    pcap_buffer = NULL;
    pcap_size = 0;
}

unsigned pcap_serializer_get_size(){
    return pcap_size;
}

uint8_t *pcap_serializer_get_buffer(){
    return pcap_buffer;
}