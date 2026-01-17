#include "hash.h"
#include <stdlib.h>
#include <string.h>

// 简单的 64-bit FNV-1a 哈希 + 混洗增强
static uint64_t fnv1a_64(const unsigned char *data, size_t len) {
    const uint64_t FNV_OFFSET = 1469598103934665603ULL;
    const uint64_t FNV_PRIME  = 1099511628211ULL;
    uint64_t hash = FNV_OFFSET;

    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    // 混洗扩散
    hash ^= hash >> 32;
    hash *= 0x9E3779B97F4A7C15ULL;
    hash ^= hash >> 28;
    hash *= 0xBF58476D1CE4E5B9ULL;
    hash ^= hash >> 33;
    return hash;
}

uint64_t hash48_compute(const mpz_t x) {
    size_t nbytes = (mpz_sizeinbase(x, 2) + 7) / 8;
    if (nbytes == 0) return 0;

    unsigned char *buf = malloc(nbytes);
    if (!buf) return 0;
    mpz_export(buf, NULL, 1, 1, 0, 0, x);

    uint64_t h = fnv1a_64(buf, nbytes) & ((1ULL << 48) - 1);
    free(buf);
    return h;
}

void hash48_append(mpz_t result, const mpz_t x) {
    uint64_t h = hash48_compute(x);
    mpz_mul_2exp(result, x, 48);   // result = x << 48
    mpz_add_ui(result, result, h); // result = (x << 48) + h
}

int hash48_verify(const mpz_t x_with_hash) {
    mpz_t mask, base, lowbits;
    mpz_inits(mask, base, lowbits, NULL);

    // mask = 2^48 - 1
    mpz_set_ui(mask, 1);
    mpz_mul_2exp(mask, mask, 48);
    mpz_sub_ui(mask, mask, 1);

    // 提取低48位
    mpz_and(lowbits, x_with_hash, mask);

    // base = x' >> 48
    mpz_fdiv_q_2exp(base, x_with_hash, 48);

    // 计算期望哈希
    uint64_t expected = hash48_compute(base);
    uint64_t actual   = mpz_get_ui(lowbits);

    mpz_clears(mask, base, lowbits, NULL);
    return (expected == actual);
}

void hash48_strip(mpz_t out, const mpz_t x_with_hash) {
    mpz_fdiv_q_2exp(out, x_with_hash, 48); // out = x' >> 48
}

