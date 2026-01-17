#include "modsystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

void modsystem_init_auto(ModSystem *sys, unsigned int M_bits, unsigned long seed)
{
    if (!sys) return;

    // --- 初始化随机状态 ---
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed ? seed : (unsigned long)time(NULL));

    // --- 生成大模数 M ---
    mpz_init(sys->M);
    mpz_urandomb(sys->M, state, M_bits);
    // 确保是奇数且大于 2^(M_bits - 1)
    mpz_setbit(sys->M, M_bits - 1);
    if (mpz_even_p(sys->M)) mpz_add_ui(sys->M, sys->M, 1);
    // 可选：调整为素数
    mpz_nextprime(sys->M, sys->M);

    // --- 估算需要多少个 20bit 小模数 ---
    size_t count_est = (size_t)ceil((double)M_bits / 20.0) + 2;
    sys->m_list = malloc(sizeof(mpz_t) * count_est);
    if (!sys->m_list) {
        fprintf(stderr, "[ModSystem] 内存分配失败。\n");
        exit(EXIT_FAILURE);
    }

    mpz_t product;
    mpz_init_set_ui(product, 1);
    sys->m_count = 0;

    for (size_t i = 0; i < count_est; ++i) {
        mpz_init(sys->m_list[i]);

        // 生成 20-bit 素数
        mpz_urandomb(sys->m_list[i], state, 20);
        mpz_nextprime(sys->m_list[i], sys->m_list[i]);

        // 确保互素
        for (size_t j = 0; j < i; ++j) {
            mpz_t gcd;
            mpz_init(gcd);
            mpz_gcd(gcd, sys->m_list[i], sys->m_list[j]);
            if (mpz_cmp_ui(gcd, 1) != 0) {
                mpz_urandomb(sys->m_list[i], state, 20);
                mpz_nextprime(sys->m_list[i], sys->m_list[i]);
                j = (size_t)-1; // 重检
            }
            mpz_clear(gcd);
        }

        // 更新乘积
        mpz_mul(product, product, sys->m_list[i]);
        sys->m_count++;

        // 如果乘积已超过 M，退出
        if (mpz_cmp(product, sys->M) > 0)
            break;
    }

    gmp_printf("[ModSystem] 自动生成 %u-bit 大模数 M。\n", M_bits);
    gmp_printf("[ModSystem] 生成 %zu 个 20-bit 小模数，总积已超过 M。\n", sys->m_count);

    mpz_clear(product);
    gmp_randclear(state);
}


void modsystem_free(ModSystem *sys)
{
    if (!sys) return;
    for (size_t i = 0; i < sys->m_count; ++i)
        mpz_clear(sys->m_list[i]);
    free(sys->m_list);
    mpz_clear(sys->M);
}

void modsystem_print(const ModSystem *sys)
{
    if (!sys) return;
    printf("==== ModSystem 状态 ====\n");
    gmp_printf("大模数 M = %Zd\n", sys->M);
    printf("小模数数量: %zu\n", sys->m_count);
    for (size_t i = 0; i < sys->m_count; ++i) {
        gmp_printf("  m[%zu] = %Zd\n", i, sys->m_list[i]);
    }
    printf("========================\n");
}
