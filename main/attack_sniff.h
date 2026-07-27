/**
 * @file attack_sniff.h
 * @brief Sniffing attack module for XenoMorph
 */

#ifndef ATTACK_SNIFF_H
#define ATTACK_SNIFF_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * @brief Initialize sniffing attack module
 */
void attack_sniff_init(void);

/**
 * @brief Start packet sniffing
 * @param channel: WiFi channel to sniff
 * @param bssid: Target BSSID (NULL or zeros for all)
 * @param method: 0=ALL, 1=EAPOL, 2=DATA
 * @param max_packets: Max packets to capture (0 = unlimited)
 * @return ESP_OK on success
 */
esp_err_t attack_sniff_start(uint8_t channel, const uint8_t* bssid, uint8_t method, uint32_t max_packets);

/**
 * @brief Stop sniffing and return statistics
 * @param out_packets: Output packet count
 * @param out_buffer_size: Output PCAP buffer size
 * @return ESP_OK on success
 */
esp_err_t attack_sniff_stop(uint32_t* out_packets, uint32_t* out_buffer_size);

/**
 * @brief Check if sniffing is running
 */
bool attack_sniff_is_running(void);

/**
 * @brief Get current statistics
 */
void attack_sniff_get_stats(uint32_t* packets, uint32_t* buffer_size, uint32_t* max_size);

/**
 * @brief Read a chunk of PCAP buffer
 * @param offset: Buffer offset
 * @param buffer: Output buffer (must be at least chunk_size)
 * @param chunk_size: Max bytes to read
 * @param out_read: Actual bytes read
 * @param out_is_last: Set to true if this is the last chunk
 * @return ESP_OK on success
 */
esp_err_t attack_sniff_read_chunk(uint32_t offset, uint8_t* buffer, uint16_t chunk_size,
                                  uint16_t* out_read, bool* out_is_last);

/**
 * @brief Get pointer to full PCAP buffer (for direct access)
 * @param out_size: Output buffer size
 * @return Pointer to buffer, NULL if not available
 */
uint8_t* attack_sniff_get_buffer(uint32_t* out_size);

// NEW: Probe tracking (size matches xenomorph_sniff_stats_t)
#define MAX_PROBES 50

typedef struct {
    char ssid[33];
    uint8_t mac[6];
    uint32_t count;
    uint32_t last_seen;
} probe_entry_t;

// NEW: Functions
int attack_sniff_get_probe_count(void);
const probe_entry_t* attack_sniff_get_probe_list(void);

/**
 * @brief Get the top SSID probe entry (highest count)
 * @param out_ssids: Output array of top probe entries (caller allocates)
 * @param count: In/out: max entries, actual entries written
 * @param max_entries: Max entries to fill
 * @note Sorting done by count descending; ties broken alphabetically
 */
void attack_sniff_get_top_probes(probe_entry_t* out_ssids, int* count, int max_entries);

#endif // ATTACK_SNIFF_H