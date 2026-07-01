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

    uint64_t h = fnv1a_64(buf, nbytes) & ((1ULL << HASH_TAG_BITS) - 1);
    free(buf);
    return h;
}

uint64_t hash48_compute_u64(uint64_t x) {
    unsigned char buf[sizeof(x)];
    size_t start = sizeof(x);

    if (x == 0) {
        return fnv1a_64((const unsigned char *)"\0", 1) &
               ((1ULL << HASH_TAG_BITS) - 1);
    }

    while (start > 0) {
        start--;
        buf[start] = (unsigned char)(x & 0xff);
        x >>= 8;
        if (x == 0) {
            break;
        }
    }

    return fnv1a_64(buf + start, sizeof(x) - start) &
           ((1ULL << HASH_TAG_BITS) - 1);
}

static uint64_t mpz_get_uint64(const mpz_t x)
{
    uint64_t out = 0;
    size_t count = 0;

    mpz_export(&out, &count, -1, sizeof(out), 0, 0, x);
    return out;
}

void hash48_append(mpz_t result, const mpz_t x) {
    uint64_t h = hash48_compute(x);
    mpz_t h_mpz;

    mpz_mul_2exp(result, x, HASH_TAG_BITS);
    mpz_init(h_mpz);
    mpz_import(h_mpz, 1, -1, sizeof(h), 0, 0, &h);
    mpz_add(result, result, h_mpz);
    mpz_clear(h_mpz);
}

int hash48_verify(const mpz_t x_with_hash) {
    mpz_t mask, base, lowbits;
    mpz_inits(mask, base, lowbits, NULL);

    // mask = 2^48 - 1
    mpz_set_ui(mask, 1);
    mpz_mul_2exp(mask, mask, HASH_TAG_BITS);
    mpz_sub_ui(mask, mask, 1);
    mpz_and(lowbits, x_with_hash, mask);

    // 提取低48位
    mpz_and(lowbits, x_with_hash, mask);

    // base = x' >> 48
    mpz_fdiv_q_2exp(base, x_with_hash, HASH_TAG_BITS);

    // 计算期望哈希
    uint64_t expected = hash48_compute(base);
    uint64_t actual   = mpz_get_uint64(lowbits);

    mpz_clears(mask, base, lowbits, NULL);
    return (expected == actual);
}

void hash48_strip(mpz_t out, const mpz_t x_with_hash) {
    mpz_fdiv_q_2exp(out, x_with_hash, HASH_TAG_BITS);
}
