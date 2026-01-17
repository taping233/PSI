#include "crt_gmp.h"
#include <stdlib.h>
#include <stdio.h>

// 经典 Garner / 逐步合并法实现
// 假设 moduli 两两互素

void crt_combine(mpz_t result,
                 mpz_t M_out,
                 mpz_t *remainders,
                 mpz_t *moduli,
                 size_t n)
{
    if (n == 0) {
        mpz_set_ui(result, 0);
        if (M_out) mpz_set_ui(M_out, 1);
        return;
    }

    // 初始化
    mpz_t M, Mi, t, inv;
    mpz_inits(M, Mi, t, inv, NULL);

    // result = r0, M = m0
    mpz_set(result, remainders[0]);
    mpz_set(M, moduli[0]);

    for (size_t i = 1; i < n; ++i) {
        // Mi = M_i
        // diff = (r_i - result) mod m_i
        mpz_sub(t, remainders[i], result);
        mpz_mod(t, t, moduli[i]);

        // inv = M^{-1} mod m_i
        if (mpz_invert(inv, M, moduli[i]) == 0) {
            fprintf(stderr, "Error: moduli[%zu] and previous product are not coprime!\n", i);
            exit(EXIT_FAILURE);
        }

        // t = diff * inv mod m_i
        mpz_mul(t, t, inv);
        mpz_mod(t, t, moduli[i]);

        // result = result + M * t
        mpz_mul(Mi, M, t);
        mpz_add(result, result, Mi);

        // M *= m_i
        mpz_mul(M, M, moduli[i]);

        // 保证 result < M
        mpz_mod(result, result, M);
    }

    if (M_out) mpz_set(M_out, M);

    mpz_clears(M, Mi, t, inv, NULL);
}

