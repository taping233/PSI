#include "modsystem.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define FFT_FRIENDLY_ORDER 2048UL
#define CRT_MULTIPLICATION_TERMS 2048UL

static unsigned int ceil_log2_ulong(unsigned long x)
{
    unsigned int bits = 0;
    unsigned long v = 1;

    while (v < x) {
        v <<= 1;
        bits++;
    }

    return bits;
}

static void generate_fft_friendly_prime(mpz_t out,
                                        unsigned int bits,
                                        unsigned long order,
                                        gmp_randstate_t state)
{
    mpz_t k;
    unsigned int order_bits = 0;
    unsigned int k_bits;

    while ((1UL << order_bits) < order) {
        order_bits++;
    }

    k_bits = (bits > order_bits) ? (bits - order_bits) : 2;

    mpz_init(k);

    for (;;) {
        mpz_urandomb(k, state, k_bits);
        if (k_bits > 1) {
            mpz_setbit(k, k_bits - 1);
        }

        mpz_mul_ui(out, k, order);
        mpz_add_ui(out, out, 1);

        while (mpz_probab_prime_p(out, 25) == 0) {
            mpz_add_ui(out, out, order);
        }

        if (mpz_fdiv_ui(out, order) == 1 &&
            mpz_sizeinbase(out, 2) >= bits) {
            break;
        }
    }

    mpz_clear(k);
}

static void modsystem_init_auto_ordered(ModSystem *sys, unsigned int M_bits,
                                        unsigned long fft_order,
                                        unsigned long seed)
{
    if (!sys) {
        return;
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed ? seed : (unsigned long)time(NULL));

    mpz_init(sys->M);
    generate_fft_friendly_prime(sys->M, M_bits, fft_order, state);

    size_t count_est =
        (size_t)ceil((double)(2 * M_bits + 12) / 20.0) + 2;
    sys->m_list = malloc(sizeof(mpz_t) * count_est);
    if (!sys->m_list) {
        fprintf(stderr, "[ModSystem] 鍐呭瓨鍒嗛厤澶辫触銆俓n");
        exit(EXIT_FAILURE);
    }

    mpz_t product;
    mpz_t target_product;
    unsigned int order_bits = ceil_log2_ulong(fft_order);
    unsigned int small_mod_bits = order_bits + 8;
    if (small_mod_bits < 20) {
        small_mod_bits = 20;
    }

    mpz_init_set_ui(product, 1);
    mpz_init(target_product);
    mpz_mul(target_product, sys->M, sys->M);
    mpz_mul_ui(target_product, target_product, fft_order);
    sys->m_count = 0;

    for (size_t i = 0; i < count_est; ++i) {
        mpz_init(sys->m_list[i]);
        generate_fft_friendly_prime(sys->m_list[i], small_mod_bits,
                                    fft_order, state);

        for (size_t j = 0; j < i; ++j) {
            mpz_t gcd;
            mpz_init(gcd);
            mpz_gcd(gcd, sys->m_list[i], sys->m_list[j]);
            if (mpz_cmp_ui(gcd, 1) != 0) {
                generate_fft_friendly_prime(sys->m_list[i], small_mod_bits,
                                            fft_order, state);
                j = (size_t)-1;
            }
            mpz_clear(gcd);
        }

        mpz_mul(product, product, sys->m_list[i]);
        sys->m_count++;

        if (mpz_cmp(product, target_product) > 0) {
            break;
        }
    }

    gmp_printf("[ModSystem] 鑷姩鐢熸垚 %u-bit 澶фā鏁?M銆俓n", M_bits);
    gmp_printf("[ModSystem] 鐢熸垚 %zu 涓?20-bit 灏忔ā鏁帮紝鎬荤Н宸茶秴杩?M銆俓n",
               sys->m_count);

    mpz_clear(product);
    mpz_clear(target_product);
    gmp_randclear(state);
}

void modsystem_init_auto(ModSystem *sys, unsigned int M_bits,
                         unsigned long seed)
{
    modsystem_init_auto_ordered(sys, M_bits, FFT_FRIENDLY_ORDER, seed);
}

void modsystem_init_auto_with_order(ModSystem *sys, unsigned int M_bits,
                                    unsigned long fft_order,
                                    unsigned long seed)
{
    modsystem_init_auto_ordered(sys, M_bits, fft_order, seed);
}

void modsystem_free(ModSystem *sys)
{
    if (!sys) {
        return;
    }

    for (size_t i = 0; i < sys->m_count; ++i) {
        mpz_clear(sys->m_list[i]);
    }

    free(sys->m_list);
    sys->m_list = NULL;
    sys->m_count = 0;
    mpz_clear(sys->M);
}

void modsystem_print(const ModSystem *sys)
{
    if (!sys) {
        return;
    }

    printf("==== ModSystem 鐘舵€?====\n");
    gmp_printf("澶фā鏁?M = %Zd\n", sys->M);
    printf("灏忔ā鏁版暟閲? %zu\n", sys->m_count);
    for (size_t i = 0; i < sys->m_count; ++i) {
        gmp_printf("  m[%zu] = %Zd\n", i, sys->m_list[i]);
    }
    printf("========================\n");
}

void modsystem_init_with_order(ModSystem *mods, mpz_t p,
                               unsigned long fft_order,
                               unsigned int seed)
{
    if (!mods) {
        return;
    }

    mpz_init_set(mods->M, p);

    unsigned int M_bits = (unsigned int)mpz_sizeinbase(p, 2);
    size_t count_est =
        (size_t)ceil((double)(2 * M_bits + 12) / 20.0) + 4;
    mods->m_list = malloc(sizeof(mpz_t) * count_est);
    if (!mods->m_list) {
        fprintf(stderr, "[ModSystem] allocation failed\n");
        exit(EXIT_FAILURE);
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    mpz_t product;
    mpz_t target_product;
    mpz_init_set_ui(product, 1);
    mpz_init(target_product);
    mpz_mul(target_product, mods->M, mods->M);
    mpz_mul_ui(target_product, target_product, fft_order);

    unsigned int order_bits = ceil_log2_ulong(fft_order);
    unsigned int small_mod_bits = order_bits + 8;
    if (small_mod_bits < 20) {
        small_mod_bits = 20;
    }

    mods->m_count = 0;
    for (size_t i = 0; i < count_est; ++i) {
        mpz_init(mods->m_list[i]);
        generate_fft_friendly_prime(mods->m_list[i], small_mod_bits,
                                    fft_order, state);

        for (size_t j = 0; j < i; ++j) {
            mpz_t gcd;
            mpz_init(gcd);
            mpz_gcd(gcd, mods->m_list[i], mods->m_list[j]);
            if (mpz_cmp_ui(gcd, 1) != 0) {
                generate_fft_friendly_prime(mods->m_list[i], small_mod_bits,
                                            fft_order, state);
                j = (size_t)-1;
            }
            mpz_clear(gcd);
        }

        mpz_mul(product, product, mods->m_list[i]);
        mods->m_count++;

        if (mpz_cmp(product, target_product) > 0) {
            break;
        }
    }

    mpz_clear(product);
    mpz_clear(target_product);
    gmp_randclear(state);
    srand(seed);
}

void modsystem_init(ModSystem *mods, mpz_t p, unsigned int seed)
{
    if (!mods) {
        return;
    }

    mpz_init_set(mods->M, p);

    unsigned int M_bits = (unsigned int)mpz_sizeinbase(p, 2);
    size_t count_est =
        (size_t)ceil((double)(2 * M_bits + 12) / 20.0) + 2;
    mods->m_list = malloc(sizeof(mpz_t) * count_est);
    if (!mods->m_list) {
        fprintf(stderr, "[ModSystem] 鍐呭瓨鍒嗛厤澶辫触銆俓n");
        exit(EXIT_FAILURE);
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    mpz_t product;
    mpz_t target_product;
    mpz_init_set_ui(product, 1);
    mpz_init(target_product);
    mpz_mul(target_product, mods->M, mods->M);
    mpz_mul_ui(target_product, target_product, CRT_MULTIPLICATION_TERMS);
    mods->m_count = 0;

    for (size_t i = 0; i < count_est; ++i) {
        mpz_init(mods->m_list[i]);
        generate_fft_friendly_prime(mods->m_list[i], 20,
                                    FFT_FRIENDLY_ORDER, state);

        for (size_t j = 0; j < i; ++j) {
            mpz_t gcd;
            mpz_init(gcd);
            mpz_gcd(gcd, mods->m_list[i], mods->m_list[j]);
            if (mpz_cmp_ui(gcd, 1) != 0) {
                generate_fft_friendly_prime(mods->m_list[i], 20,
                                            FFT_FRIENDLY_ORDER, state);
                j = (size_t)-1;
            }
            mpz_clear(gcd);
        }

        mpz_mul(product, product, mods->m_list[i]);
        mods->m_count++;

        if (mpz_cmp(product, target_product) > 0) {
            break;
        }
    }

    mpz_clear(product);
    mpz_clear(target_product);
    gmp_randclear(state);

    srand(seed);
}
