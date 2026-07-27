/**
 * @file webserver.c
 *
 * @brief HTTP download portal for XenoMorph Muscle.
 *
 * Implements a single httpd instance on port 80 that exposes the captured
 * artifacts produced by the other components:
 *   GET /        launcher page (static HTML in pages/page_index.h)
 *   GET /pcap    PCAP buffer from pcap_serializer
 *   GET /hccapx  HCCAPX blob from hccapx_serializer
 *
 * Replaces an earlier dual-server setup that lived inline in main.c.
 * Pcap is rejected with 404 when the buffer is empty so users don't pull
 * an uninitialised file (28-byte global header only).
 */
#include "webserver.h"

#include <stdint.h>

#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_log.h"

#include "pcap_serializer.h"
#include "hccapx_serializer.h"

#include "pages/page_index.h"

static const char *TAG = "webserver";

/**
 * @brief Return empty 204 for favicon requests (browser auto-fetches this).
 */
static esp_err_t uri_favicon_get(httpd_req_t *req) {
    return httpd_resp_send(req, NULL, 0);  // 204 No Content
}

static esp_err_t uri_root_get(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)page_index, page_index_len);
}

static esp_err_t uri_pcap_get(httpd_req_t *req) {
    uint32_t size = pcap_serializer_get_size();
    if (size == 0) {
        ESP_LOGW(TAG, "PCAP download requested but buffer is empty");
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "PCAP not ready — run SNIFFING first");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Serving PCAP (%u bytes)", size);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"capture.pcap\"");
    return httpd_resp_send(req, (const char *)pcap_serializer_get_buffer(), size);
}

static esp_err_t uri_hccapx_get(httpd_req_t *req) {
    hccapx_t *hccapx = hccapx_serializer_get();
    if (hccapx == NULL) {
        ESP_LOGW(TAG, "HCCAPX download requested but buffer is NULL");
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "HCCAPX not ready — run HANDSHAKE first");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Serving HCCAPX (mp=%u)", hccapx->message_pair);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"capture.hccapx\"");
    return httpd_resp_send(req, (const char *)hccapx, sizeof(hccapx_t));
}

void webserver_run() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(httpd_start(&server, &config));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/", .method = HTTP_GET, .handler = uri_root_get, .user_ctx = NULL}));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/favicon.ico", .method = HTTP_GET, .handler = uri_favicon_get, .user_ctx = NULL}));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/pcap", .method = HTTP_GET, .handler = uri_pcap_get, .user_ctx = NULL}));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/hccapx", .method = HTTP_GET, .handler = uri_hccapx_get, .user_ctx = NULL}));

    ESP_LOGI(TAG, "Download portal listening on port %d (/, /pcap, /hccapx)", config.server_port);
}
