# Test-only packet-path profiling counters (ml_perf.h): linked only into an
# image built with TSR_PERF_PROFILE=1, so release images are unchanged.
set(ML_PERF_SRCS)
if("$ENV{TSR_PERF_PROFILE}" STREQUAL "1")
    set(ML_PERF_SRCS "src/ml_perf.c")
endif()
# ESP32-S3 Poly1305 block function in assembly (checked against the C code
# before first use; see poly1305-donna-32.h).
set(WG_ASM_SRCS)
if(IDF_TARGET STREQUAL "esp32s3")
    set(WG_ASM_SRCS "src/crypto/refc/poly1305_xtensa.S")
endif()

idf_component_register(
    SRCS
        "src/wireguard.c"
        "src/wireguardif.c"
        ${ML_PERF_SRCS}
        "src/crypto.c"
        "src/wireguard-platform-esp32.c"
        "src/crypto/refc/blake2s.c"
        "src/crypto/refc/chacha20.c"
        "src/crypto/refc/chacha20poly1305.c"
        "src/crypto/refc/poly1305-donna.c"
        ${WG_ASM_SRCS}
        "src/crypto/refc/x25519.c"
    INCLUDE_DIRS
        "src"
        "src/crypto/refc"
    REQUIRES
        lwip
        esp_timer
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WIREGUARD_CRYPTO_REFC=1
)

# Disable stringop-overread warning for x25519.c (false positive in GCC array bounds check)
set_source_files_properties(
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread"
)
