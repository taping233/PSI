#include "beaver.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>

// 生成 [-2^(m_bit-1), 2^(m_bit-1)-1] 的随机整数
static void rand_int_mpz(mpz_t r, unsigned int m_bit, gmp_randstate_t state) {
    mpz_t limit;
    mpz_init(limit);

    mpz_ui_pow_ui(limit, 2, m_bit - 1);
    mpz_urandomb(r, state, m_bit);
    mpz_sub(r, r, limit);

    mpz_clear(limit);
}

// 生成降幂序的 Beaver 多项式三元组
void beaver_generate(mpz_t **A,
                     mpz_t **B,
                     mpz_t **C,
                     size_t n,
                     unsigned int m_bit,
                     unsigned long seed)
{
    if (!A || !B || !C) {
        fprintf(stderr, "beaver_generate: null pointer input\n");
        exit(EXIT_FAILURE);
    }
    if (n == 0) {
        fprintf(stderr, "beaver_generate: n cannot be zero\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0)
        seed = (unsigned long)time(NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    *A = malloc(sizeof(mpz_t) * n);
    *B = malloc(sizeof(mpz_t) * n);
    *C = malloc(sizeof(mpz_t) * (2 * n - 1));
    if (!*A || !*B || !*C) {
        fprintf(stderr, "beaver_generate: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < n; ++i) {
        mpz_init((*A)[i]);
        mpz_init((*B)[i]);
    }
    for (size_t i = 0; i < 2 * n - 1; ++i)
        mpz_init((*C)[i]);

    // 生成随机多项式 A, B（降幂）
    for (size_t i = 0; i < n; ++i) {
        rand_int_mpz((*A)[i], m_bit, state);
        rand_int_mpz((*B)[i], m_bit, state);
    }

    // 初始化 C = 0
    for (size_t i = 0; i < 2 * n - 1; ++i)
        mpz_set_ui((*C)[i], 0);

    // 朴素多项式乘法 (降幂序)
    // 若 A[0] 对应 x^(n-1)，则：
    // C[k] = sum_{i+j=k} (A[i]*B[j])
    // 其中 C[0] 为最高次项系数，C[2n-2] 为常数项
    mpz_t temp;
    mpz_init(temp);

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            size_t idx = i + j;  // 高次在前
            mpz_mul(temp, (*A)[i], (*B)[j]);
            mpz_add((*C)[idx], (*C)[idx], temp);
        }
    }

    mpz_clear(temp);
    gmp_randclear(state);
}

// 打印多项式（降幂序）
void beaver_print(const char *name, mpz_t *P, size_t k) {
    if (!P) return;
    printf("%s(x):\n", name);
    for (size_t i = 0; i < k; ++i) {
        size_t degree = k - 1 - i; // 从最高次打印到常数项
        gmp_printf("  [x^%zu] = %Zd\n", degree, P[i]);
    }
}

// 释放多项式内存
void beaver_free(mpz_t *A, mpz_t *B, mpz_t *C, size_t n) {
    if (A) {
        for (size_t i = 0; i < n; ++i)
            mpz_clear(A[i]);
        free(A);
    }
    if (B) {
        for (size_t i = 0; i < n; ++i)
            mpz_clear(B[i]);
        free(B);
    }
    if (C) {
        for (size_t i = 0; i < 2 * n - 1; ++i)
            mpz_clear(C[i]);
        free(C);
    }
}

