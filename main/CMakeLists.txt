idf_component_register(
    SRCS 
        "main.c"
        "attack.c"
        "attack_dos.c"
        "attack_handshake.c"
        "attack_join.c"
        "attack_method.c"
        "attack_pmkid.c"
        "attack_sniff.c"
    INCLUDE_DIRS 
        "."
    REQUIRES 
        wifi_controller
        webserver          # Bisa dihapus kalau tidak dipakai
        frame_analyzer
        wsl_bypasser
        pcap_serializer
        hccapx_serializer
        xenomorph_uart
        esp_http_server    # TAMBAH INI
)