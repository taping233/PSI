#include "dataset.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void dataset_generate(mpz_t *data, unsigned int n, unsigned int m, unsigned long seed) {
    size_t len = 1ULL << n;

    gmp_randstate_t state;
    gmp_randinit_default(state);
    if (seed == 0)
        gmp_randseed_ui(state, (unsigned long)time(NULL));
    else
        gmp_randseed_ui(state, seed);

    for (size_t i = 0; i < len; ++i) {
        mpz_init(data[i]);
        mpz_urandomb(data[i], state, m); // 生成 m-bit 随机整数
    }

    gmp_randclear(state);
}

void dataset_free(mpz_t *data, unsigned int n) {
    size_t len = 1ULL << n;
    for (size_t i = 0; i < len; ++i)
        mpz_clear(data[i]);
}

void dataset_print(mpz_t *data, unsigned int n, size_t k) {
    size_t len = 1ULL << n;
    if (k > len) k = len;
    printf("=== 数据集 (前 %zu 项) ===\n", k);
    for (size_t i = 0; i < k; ++i)
        gmp_printf("data[%zu] = %Zd\n", i, data[i]);
}

