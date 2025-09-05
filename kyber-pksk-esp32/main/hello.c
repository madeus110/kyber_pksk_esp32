#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"
#include "esp_timer.h"
#include "hal/gpio_types.h"
#include "driver/gpio.h"

#define TRIGGER_GPIO 4

static inline void trigger_high(void) {
    gpio_set_level(TRIGGER_GPIO, 1);
}

static inline void trigger_low(void) {
    gpio_set_level(TRIGGER_GPIO, 0);
}

void fingerprint_shake256_hex(const uint8_t *input, size_t input_len, char *output_hex) {
    uint8_t hash[32];
    shake256(hash, sizeof(hash), input, input_len);
    for (size_t i = 0; i < sizeof(hash); i++) {
        sprintf(output_hex + (i * 2), "%02X", hash[i]);
    }
    output_hex[64] = '\0';
}

int hello_serialise(void) {
    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    uint8_t pk_copy[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk_copy[KYBER_INDCPA_SECRETKEYBYTES];
    char pk_fp[65], sk_fp[65];

    gpio_reset_pin(TRIGGER_GPIO);
    gpio_set_direction(TRIGGER_GPIO, GPIO_MODE_OUTPUT);

    // --- Seed load ---
    trigger_high();
    printf("[SYNC] BEGIN_SEED\n");
    volatile uint8_t seed[32] = {
        0x06,0x15,0x50,0x23,0x4D,0x15,0x8C,0x5E,
        0xC9,0x55,0x95,0xFE,0x04,0xEF,0x7A,0x25,
        0x76,0x7F,0x2E,0x24,0xCC,0x2B,0xC4,0x79,
        0xD0,0x9D,0x86,0xDC,0x9A,0xBC,0xFD,0x6F
    };
    printf("[SYNC] END_SEED\n");
    trigger_low();

    // --- KeyGen ---
    int64_t t0 = esp_timer_get_time();
    printf("[SYNC] BEGIN_KEYGEN\n");
    trigger_high();
    indcpa_keypair_derand((uint8_t*)pk, (uint8_t*)sk, (uint8_t*)seed);
    trigger_low();
    printf("[SYNC] END_KEYGEN\n");
    int64_t t1 = esp_timer_get_time();

    // --- Pack / serialization ---
    int64_t t_pack0 = esp_timer_get_time();
    printf("[SYNC] BEGIN_PACK\n");
    trigger_high();
    memcpy(pk_copy, (const void*)pk, KYBER_INDCPA_PUBLICKEYBYTES);
    memcpy(sk_copy, (const void*)sk, KYBER_INDCPA_SECRETKEYBYTES);
    trigger_low();
    printf("[SYNC] END_PACK\n");
    int64_t t_pack1 = esp_timer_get_time();

    // --- Fingerprints ---
    printf("[SYNC] BEGIN_FINGERPRINT\n");
    trigger_high();
    fingerprint_shake256_hex(pk_copy, KYBER_INDCPA_PUBLICKEYBYTES, pk_fp);
    fingerprint_shake256_hex(sk_copy, KYBER_INDCPA_SECRETKEYBYTES, sk_fp);
    trigger_low();
    printf("[SYNC] END_FINGERPRINT\n");

    printf("PK Fingerprint: %s\n", pk_fp);
    printf("SK Fingerprint: %s\n", sk_fp);
    printf("KeyGen time: %lld us\n", (long long)(t1 - t0));
    printf("Pack time: %lld us\n", (long long)(t_pack1 - t_pack0));

    return 0;
}

// -------------------- Punto de entrada ESP32 --------------------
void app_main(void) {
    // Ejecuta tu función principal
    hello_serialise();

 
}

