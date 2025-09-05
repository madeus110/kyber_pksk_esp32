// File: components/kyber/src/randombytes.c
#include <stdint.h>
#include <stddef.h>
#include "fips202.h"   // Incluye las funciones SHAKE128 de tu versión

// Estado global para SHAKE128
static keccak_state state;

// Inicializa el generador con una semilla
void randombytes_init(const uint8_t *seed, size_t seedlen) {
    pqcrystals_kyber_fips202_ref_shake128_init(&state);
    pqcrystals_kyber_fips202_ref_shake128_absorb(&state, seed, seedlen);
    pqcrystals_kyber_fips202_ref_shake128_finalize(&state);
}

// Genera bytes aleatorios
void randombytes(uint8_t *buf, size_t buflen) {
    // SHAKE128 genera bloques de 168 bytes
    size_t nblocks = (buflen + 167) / 168; // redondea hacia arriba
    pqcrystals_kyber_fips202_ref_shake128_squeezeblocks(buf, nblocks, &state);
}

