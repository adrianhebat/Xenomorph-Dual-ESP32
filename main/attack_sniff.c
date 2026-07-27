/**
 * @file attack_sniff.c
 * @brief Sniffing attack implementation with PROBE mode
 */

#include "attack_sniff.h"
#include "attack_join.h"
#include "sniffer.h"
#include "wifi_controller.h"
#include "pcap_serializer.h"
#include "frame_analyzer.h"
#include "xenomorph_protocol.h"
#include "xenomorph_uart.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_heap_caps.h"
#include "string.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG "attack_sniff"

static bool sniffing_running = false;
static uint8_t target_channel = 0;
static uint8_t filter_method = 0;
static uint32_t captured_packets = 0;
static uint32_t max_packets_limit = 0;
static uint8_t target_bssid[6] = {0};

// NEW: Probe tracking
#define MAX_PROBES 50
// probe_entry_t dideklarasikan di attack_sniff.h
static probe_entry_t probe_list[MAX_PROBES];
static int probe_count = 0;

static TaskHandle_t stats_task_handle = NULL;
static void stats_task(void* pvParameters);
static void sniff_event_handler(void* args, esp_event_base_t event_base,
                                 int32_t event_id, void* event_data);

// Channel hopping (PROBE mode only): rotate channel 1..13 setiap HOP_PERIOD_MS
// sehingga probe request dari device di channel manapun bisa tertangkap.
#define PROBE_THRESHOLD_COUNT 1
#define HOP_PERIOD_MS         250
#define HOP_CHANNEL_MIN       1
#define HOP_CHANNEL_MAX       13
static TaskHandle_t hop_task_handle = NULL;
static uint8_t     hop_channel_idx = 0;     // index ke array [1..13]
static void hop_task(void* pvParameters);
static void hop_start(void);
static void hop_stop(void);

// NEW: Helper untuk cari/tambah probe entry
// Setiap probe request yang match akan ditambahkan ke list sejak probe pertama
// (untuk tracking SSID yang lewat). Entry dianggap "ACTIVE" saat count >= 2,
// dilaporkan via xeno_sniff_stats_t.active_probes untuk filtering noise.
static void add_probe(const char* ssid, const uint8_t* mac) {
    // Cek apakah sudah ada
    for (int i = 0; i < probe_count; i++) {
        if (strcmp(probe_list[i].ssid, ssid) == 0) {
            probe_list[i].count++;
            probe_list[i].last_seen = xTaskGetTickCount() / configTICK_RATE_HZ;
            if (probe_list[i].count == PROBE_THRESHOLD_COUNT) {
                ESP_LOGI(TAG, "PROBE ACTIVE: '%s' from %02X:%02X:%02X:%02X:%02X:%02X",
                         ssid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            return;
        }
    }

    // Tambah entry baru
    if (probe_count < MAX_PROBES) {
        strncpy(probe_list[probe_count].ssid, ssid, 32);
        memcpy(probe_list[probe_count].mac, mac, 6);
        probe_list[probe_count].count = 1;
        probe_list[probe_count].last_seen = xTaskGetTickCount() / configTICK_RATE_HZ;
        probe_count++;

        ESP_LOGI(TAG, "NEW PROBE: '%s' from %02X:%02X:%02X:%02X:%02X:%02X",
                 ssid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void attack_sniff_init(void) {
    ESP_LOGI(TAG, "Initializing sniffing attack module");
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, ESP_EVENT_ANY_ID,
                                               &sniff_event_handler, NULL));
    probe_count = 0;
    memset(probe_list, 0, sizeof(probe_list));
}

esp_err_t attack_sniff_start(uint8_t channel, const uint8_t* bssid, 
                               uint8_t method, uint32_t max_packets) {
    if (sniffing_running) {
        ESP_LOGW(TAG, "Sniffing already running");
        return ESP_ERR_INVALID_STATE;
    }
    
    ESP_LOGI(TAG, "Starting sniff on channel %d, method=%d", channel, method);

    /* Defensive: if we're already low on heap (e.g. after join_network which
     * loads the netif stack), abort sniff rather than risk crash when
     * later tasks try to allocate during streaming. */
    size_t free_heap = esp_get_free_heap_size();
    if (free_heap < 25000) {
        ESP_LOGE(TAG, "Insufficient free heap (%u bytes) to start sniffing safely. Aborting.",
                 (unsigned)free_heap);
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Free heap before sniff start: %u bytes", (unsigned)free_heap);

    target_channel = channel;
    filter_method = method;
    max_packets_limit = max_packets;
    captured_packets = 0;
    probe_count = 0;  // NEW: Reset probe list
    memset(probe_list, 0, sizeof(probe_list));
    
    if (bssid) {
        memcpy(target_bssid, bssid, 6);
    } else {
        memset(target_bssid, 0, 6);
    }
    
    uint8_t* pcap_buf = pcap_serializer_init();
    if (!pcap_buf) {
        ESP_LOGE(TAG, "Failed to init PCAP buffer");
        return ESP_FAIL;
    }
    
    // Set filter berdasarkan method
    switch (method) {
        case XENO_SNIFF_EAPOL:
            wifictl_sniffer_filter_frame_types(false, true, false);
            break;
        case XENO_SNIFF_DATA:
            wifictl_sniffer_filter_frame_types(true, false, false);
            break;
        case XENO_SNIFF_PROBE:  // NEW
            wifictl_sniffer_filter_frame_types(false, true, false); // Management frames
            break;
        default:
            wifictl_sniffer_filter_frame_types(true, true, false);
            break;
    }
    
    wifictl_sniffer_start(channel);  // pakai channel dari user (bukan hardcode 1)
    // Channel hopping aktif untuk PROBE dan ALL supaya coverage area luas
    if (method == XENO_SNIFF_PROBE || method == XENO_SNIFF_ALL) {
        hop_start();
    }
    sniffing_running = true;

    xTaskCreate(stats_task, "sniff_stats", 4096, NULL, 5, &stats_task_handle);

    xeno_uart_send_notification(XENO_NOTIFY_SNIFF_START, NULL, 0);

    ESP_LOGI(TAG, "Sniffing started (method=%d)", method);
    return ESP_OK;
}

esp_err_t attack_sniff_stop(uint32_t* out_packets, uint32_t* out_buffer_size) {
    if (!sniffing_running) {
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Stopping sniffing");

    sniffing_running = false;
    hop_stop();                 // hentikan hop task dulu agar tidak set channel saat shutdown
    wifictl_sniffer_stop();

    if (stats_task_handle) {
        vTaskDelete(stats_task_handle);
        stats_task_handle = NULL;
    }

    uint32_t final_packets = captured_packets;
    uint32_t final_buffer  = pcap_serializer_get_size();

    xeno_sniff_stats_t stats = {
        .packets_captured = final_packets,
        .buffer_size      = final_buffer,
        .max_size         = 200000,
        .channel          = target_channel,
        .running          = 0,
        .active_probes    = 0,
    };
    xeno_uart_send_notification(XENO_NOTIFY_SNIFF_STOP,
                                (uint8_t*)&stats, sizeof(stats));

    if (out_packets) *out_packets = final_packets;
    if (out_buffer_size) *out_buffer_size = final_buffer;

    ESP_LOGI(TAG, "Sniffing stopped: %u packets, %u bytes, %d probes",
             final_packets, final_buffer, probe_count);
    return ESP_OK;
}

bool attack_sniff_is_running(void) {
    return sniffing_running;
}

void attack_sniff_get_stats(uint32_t* packets, uint32_t* buffer_size, uint32_t* max_size) {
    if (packets) *packets = captured_packets;
    if (buffer_size) *buffer_size = pcap_serializer_get_size();
    if (max_size) *max_size = 0;  // 0 = unlimited (grow via realloc)
}

// NEW: Get probe count
int attack_sniff_get_probe_count(void) {
    return probe_count;
}

// NEW: Get probe list
const probe_entry_t* attack_sniff_get_probe_list(void) {
    return probe_list;
}

// NEW: Get top N probe entries sorted by count descending
void attack_sniff_get_top_probes(probe_entry_t* out_ssids, int* count, int max_entries) {
    if (!out_ssids || !count) return;
    int n = *count;
    if (n > max_entries) n = max_entries;
    if (n > probe_count) n = probe_count;

    // Copy top candidates by iterating 'n' times and picking highest
    static bool used[MAX_PROBES] = {0};
    memset(used, 0, sizeof(used));

    int written = 0;
    for (int i = 0; i < n && written < n; i++) {
        int best = -1;
        uint32_t best_count = 0;
        for (int j = 0; j < probe_count; j++) {
            if (used[j]) continue;
            if (best == -1 || probe_list[j].count > best_count) {
                best = j;
                best_count = probe_list[j].count;
            }
        }
        if (best == -1) break;
        used[best] = true;
        out_ssids[written] = probe_list[best];
        written++;
    }
    *count = written;
}

esp_err_t attack_sniff_read_chunk(uint32_t offset, uint8_t* buffer, uint16_t chunk_size,
                                  uint16_t* out_read, bool* out_is_last) {
    if (!buffer || !out_read || !out_is_last) return ESP_ERR_INVALID_ARG;
    
    uint8_t* pcap_buf = pcap_serializer_get_buffer();
    uint32_t pcap_size = pcap_serializer_get_size();
    
    if (!pcap_buf || offset >= pcap_size) {
        *out_read = 0;
        *out_is_last = true;
        return ESP_ERR_INVALID_STATE;
    }
    
    uint32_t remaining = pcap_size - offset;
    uint16_t to_read = (remaining < chunk_size) ? remaining : chunk_size;
    
    memcpy(buffer, pcap_buf + offset, to_read);
    *out_read = to_read;
    *out_is_last = (offset + to_read) >= pcap_size;
    
    return ESP_OK;
}

static void sniff_event_handler(void* args, esp_event_base_t event_base, 
                                 int32_t event_id, void* event_data) {
    if (!sniffing_running) return;
    
    wifi_promiscuous_pkt_t* frame = (wifi_promiscuous_pkt_t*)event_data;
    uint16_t len = frame->rx_ctrl.sig_len;
    
    // NEW: PROBE REQUEST FILTER
    if (filter_method == XENO_SNIFF_PROBE) {
        if (len < 24) return;
        
        uint8_t* payload = frame->payload;
        uint8_t frame_ctrl = payload[0];
        uint8_t type = (frame_ctrl >> 2) & 0x3;      // 0 = Management
        uint8_t subtype = (frame_ctrl >> 4) & 0xF;   // 4 = Probe Request
        
        // Cek apakah Probe Request
        if (type != 0 || subtype != 4) {
            return;
        }
        
        // Extract Source MAC (SA) - offset 10
        uint8_t* sa = payload + 10;
        
        // Parse SSID dari Probe Request
        char ssid[33] = {0};
        int ssid_len = 0;
        
        // SSID element mulai setelah header 24 bytes
        int pos = 24;
        while (pos < len - 2) {
            uint8_t elem_id = payload[pos];
            uint8_t elem_len = payload[pos + 1];
            
            if (elem_id == 0) { // SSID element
                ssid_len = elem_len;
                if (ssid_len > 0 && ssid_len <= 32) {
                    memcpy(ssid, &payload[pos + 2], ssid_len);
                    ssid[ssid_len] = '\0';
                }
                break;
            }
            
            pos += 2 + elem_len;
            if (pos >= len) break;
        }
        
        // Tambah ke list
        add_probe(ssid_len > 0 ? ssid : "*Hidden/Empty*", sa);
        captured_packets++;
        
        return; // Tidak simpan ke PCAP untuk mode PROBE
    }
    
    // Existing filters...
    if (max_packets_limit > 0 && captured_packets >= max_packets_limit) {
        ESP_LOGI(TAG, "Max packets reached: %u", captured_packets);
        return;
    }
    
    // BSSID filter (kalau ada)
    if (memcmp(target_bssid, "\x00\x00\x00\x00\x00\x00", 6) != 0) {
        if (len > 24) {
            uint8_t* addr1 = frame->payload + 4;
            uint8_t* addr2 = frame->payload + 10;
            uint8_t* addr3 = frame->payload + 16;
            
            if (memcmp(addr1, target_bssid, 6) != 0 &&
                memcmp(addr2, target_bssid, 6) != 0 &&
                memcmp(addr3, target_bssid, 6) != 0) {
                return;
            }
        }
    }
    
    // Append ke PCAP untuk mode lain
    pcap_serializer_append_frame(frame->payload, len, frame->rx_ctrl.timestamp);
    captured_packets++;
}

static void stats_task(void* pvParameters) {
    uint8_t probe_top_counter = 0;  // tick down dari 3 → 6 detik (tiap loop = 2s)
    while (sniffing_running) {
        if (filter_method == XENO_SNIFF_PROBE) {
            // Hitung jumlah SSID unik dengan count >= THRESHOLD (active)
            uint8_t active_probes = 0;
            for (int i = 0; i < probe_count; i++) {
                if (probe_list[i].count >= PROBE_THRESHOLD_COUNT) {
                    active_probes++;
                }
            }

            xeno_sniff_stats_t stats = {
                .packets_captured = captured_packets,
                .buffer_size      = 0,
                .max_size         = MAX_PROBES,
                .channel          = (uint8_t)(HOP_CHANNEL_MIN + hop_channel_idx),
                .running          = 1,
                .active_probes    = active_probes
            };

            xeno_uart_send_notification(XENO_NOTIFY_SNIFF_STATS,
                                        (uint8_t*)&stats, sizeof(stats));

            // Kirim top-SSID summary setiap ~6 detik (counter == 0)
            if (probe_top_counter == 0) {
                probe_entry_t top[1];
                int n = 1;
                attack_sniff_get_top_probes(top, &n, 1);
                if (n > 0) {
                    xeno_sniff_probe_top_t top_notif = {
                        .ssid         = {0},
                        .bssid        = {0,0,0,0,0,0},
                        .channel      = (uint8_t)(HOP_CHANNEL_MIN + hop_channel_idx),
                        .unique_count = (uint8_t)probe_count,
                        .max_count    = (uint8_t)(top[0].count > 255 ? 255 : top[0].count)
                    };
                    strncpy(top_notif.ssid, top[0].ssid, 32);
                    top_notif.ssid[32] = '\0';
                    memcpy(top_notif.bssid, top[0].mac, 6);
                    xeno_uart_send_notification(XENO_NOTIFY_SNIFF_PROBE_TOP,
                                                (uint8_t*)&top_notif, sizeof(top_notif));
                }
            }
            probe_top_counter = (probe_top_counter + 1) % 3;
        } else {
            // Untuk mode ALL dengan hopping aktif, channel aktual = channel yang sedang di-hop.
            // Untuk mode EAPOL/DATA single-channel, pakai target_channel.
            uint8_t current_ch;
            if (hop_task_handle != NULL) {
                current_ch = (uint8_t)(HOP_CHANNEL_MIN + hop_channel_idx);
            } else {
                current_ch = target_channel;
            }

            xeno_sniff_stats_t stats = {
                .packets_captured = captured_packets,
                .buffer_size      = pcap_serializer_get_size(),
                .max_size         = pcap_serializer_get_size(),
                .channel          = current_ch,
                .running          = 1,
                .active_probes    = 0
            };

            xeno_uart_send_notification(XENO_NOTIFY_SNIFF_STATS,
                                        (uint8_t*)&stats, sizeof(stats));
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    stats_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Channel Hopping — passive area-wide probe capture                  */
/* ------------------------------------------------------------------ */

// Array channel 1..13 (semua channel WiFi 2.4 GHz)
#define HOP_CHANNEL_COUNT (HOP_CHANNEL_MAX - HOP_CHANNEL_MIN + 1)
static const uint8_t hop_channels[HOP_CHANNEL_COUNT] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
};

static void hop_task(void* pvParameters) {
    while (sniffing_running) {
        // STOP hopping if we've joined a network — lock on that AP's channel
        if (attack_join_is_joined()) {
            ESP_LOGI(TAG, "hop_task: network already joined, exiting hop loop");
            break;
        }
        uint8_t ch = hop_channels[hop_channel_idx];
        wifictl_set_channel(ch);
        hop_channel_idx = (hop_channel_idx + 1) % HOP_CHANNEL_COUNT;
        vTaskDelay(pdMS_TO_TICKS(HOP_PERIOD_MS));
    }
    /* Reset handle BEFORE deleting self so hop_stop() doesn't see a stale
     * handle and try to re-delete us — that path crashes FreeRTOS with
     * "uxListRemove" inside vTaskDelete. */
    hop_task_handle = NULL;
    vTaskDelete(NULL);
}

static void hop_start(void) {
    if (attack_join_is_joined()) {
        ESP_LOGI(TAG, "hop_start: network already joined, skipping channel hopping");
        return;
    }
    ESP_LOGI(TAG, "Channel hopping enabled (%dms per channel)", HOP_PERIOD_MS);
    hop_channel_idx = 0;
    hop_task_handle = NULL;  /* Reset in case a previous hop task self-deleted */
    xTaskCreate(hop_task, "sniff_hop", 2048, NULL, 4, &hop_task_handle);
}

static void hop_stop(void) {
    if (hop_task_handle) {
        vTaskDelete(hop_task_handle);
        hop_task_handle = NULL;
    }
}