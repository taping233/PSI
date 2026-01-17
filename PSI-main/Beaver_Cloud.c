#include "Beaver_Cloud.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

// -----------------------------
// 初始化云平台
// -----------------------------
void beaver_cloud_init(BeaverCloud *cloud, unsigned int m_bit, unsigned long seed, size_t n) {
    if (!cloud || m_bit == 0) {
        fprintf(stderr, "beaver_cloud_init: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0) seed = (unsigned long)time(NULL);
    cloud->m_bit = m_bit;

    // 仅初始化空桶结构，不生成随机根或多项式
    bucket_init(&cloud->original.beaver_A, n, m_bit);
    bucket_init(&cloud->original.beaver_B, n, m_bit);
    result_bucket_init(&cloud->original.beaver_C, n);

    // 初始化 RSA / AES 环境
    cloud->rsa_ctx = malloc(sizeof(RSAContext));
    rsa_generate_mem(cloud->rsa_ctx);

    if (aes_init_mem(&cloud->aes_ctx) != 1) {
        fprintf(stderr, "AES 密钥生成失败\n");
        exit(EXIT_FAILURE);
    }

    memset(&cloud->aes_ctx, 0, sizeof(AESContext));
}

// -----------------------------
// 初始化 AES 密钥
// -----------------------------
void beaver_cloud_set_aes(BeaverCloud *cloud, const unsigned char *key, const unsigned char *iv)
{
    if (!cloud || !key || !iv) return;
    memcpy(cloud->aes_ctx.key, key, 32);
    memcpy(cloud->aes_ctx.iv, iv, 16);
}

// -----------------------------
// 打印云平台状态
// -----------------------------
void beaver_cloud_print(const BeaverCloud *cloud) {
    if (!cloud) return;

    printf("\n=== Beaver Cloud Platform ===\n");
    printf("模长: %u bits\n", cloud->m_bit);
    printf("AES: %s\n", cloud->aes_ctx.key[0] ? "已加载" : "未加载");

    printf("\n原始 A 桶（示例前 5 项）:\n");
    bucket_print_poly(&cloud->original.beaver_A, 1, 5);
}

// -----------------------------
// 释放所有资源
// -----------------------------
void beaver_cloud_free(BeaverCloud *cloud) {
    if (!cloud) return;

    bucket_free(&cloud->original.beaver_A);
    bucket_free(&cloud->original.beaver_B);
    result_bucket_free(&cloud->original.beaver_C);

    EVP_PKEY_free(cloud->rsa_ctx->pkey);
    free(cloud->rsa_ctx);
    memset(&cloud->aes_ctx, 0, sizeof(AESContext));
}


// -------------------------------------------------------
// 生成 Beaver 多项式三元组
// -------------------------------------------------------
void beaver_cloud_generate_triplets(BeaverCloud *cloud, unsigned long seed, const mpz_t M, size_t n) {
    if (!cloud) {
        fprintf(stderr, "beaver_cloud_generate_triplets: null cloud\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0)
        seed = (unsigned long)time(NULL);

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    printf("[*] 生成多项式Beaver三元组中 (seed=%lu)...\n", seed);

    mpz_t temp;
    mpz_init(temp);
    // ========== 1️⃣ 生成原始 Beaver 三元组 ==========
    for (size_t i = 0; i < n; i++){
        for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
            mpz_urandomb(temp, state, 20);
            mpz_set(cloud->original.beaver_A.buckets[i].coeffs[j],temp); 
            mpz_urandomb(temp, state, 20);
            mpz_set(cloud->original.beaver_B.buckets[i].coeffs[j],temp);   
        }    
    }
    
    gmp_randclear(state);

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
            mpz_set_ui(cloud->original.beaver_C.result_buckets[i].coeffs[j], 0);

        for (size_t p = 0; p < BUCKET_POLY_LEN; ++p) {
            for (size_t q = 0; q < BUCKET_POLY_LEN; ++q) {
                size_t idx = p + q;
                if (idx < RESULT_POLY_LEN) {
                    mpz_t tmp;
                    mpz_init(tmp);
                    mpz_mul(tmp, cloud->original.beaver_A.buckets[i].coeffs[p], cloud->original.beaver_B.buckets[i].coeffs[q]);
                    mpz_add(cloud->original.beaver_C.result_buckets[i].coeffs[idx], cloud->original.beaver_C.result_buckets[i].coeffs[idx], tmp);
                    mpz_clear(tmp);
                }
            }
        }
    }

    mpz_clear(temp);
    printf("[✓] Beaver多项式三元组生成完毕\n");
}
