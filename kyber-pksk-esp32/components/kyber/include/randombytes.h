#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <stddef.h>

void randombytes_init(const uint8_t *seed, size_t seedlen);
void randombytes(uint8_t *buf, size_t buflen);

#endif

