#include "PSI_Cloud.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// ==========================
// 初始化单个用户条目
// ==========================
void psi_cloud_alloc_user(PSIUserEntry *entry, unsigned int k, unsigned int m_bit, unsigned long seed) {
    if (!entry) return;

    entry->k = k;
    entry->m_bit = m_bit;

    // --- 初始化用户 ID ---
    mpz_init(entry->user_id);
    // --- 初始化空桶结构 ---
    bucket_init(&entry->H_P, k, m_bit);
    bucket_init(&entry->H_W, k, m_bit);
    bucket_init(&entry->H_Beaver_a, k, m_bit);
    bucket_init(&entry->H_Beaver_b, k, m_bit);
    result_bucket_init(&entry->H_Beaver_c, k);
    result_bucket_init(&entry->PSI_result, k);
}

// ==========================
// 初始化云平台
// ==========================
void psi_cloud_init(PSICloud *cloud, size_t user_count, unsigned int k, unsigned int m_bit, unsigned long seed) {
    if (!cloud) return;

    cloud->user_count = user_count;
    cloud->users = calloc(user_count, sizeof(PSIUserEntry));

    // --- 密钥初始化 ---
    cloud->rsa_ctx = malloc(sizeof(RSAContext));
    rsa_generate_mem(cloud->rsa_ctx);
    
    if (!aes_generate_mem(&cloud->aes_internal))
        fprintf(stderr, "[PSI Cloud Init] AES 密钥生成失败！\n");

    // --- 初始化用户结构 ---
    for (size_t i = 0; i < user_count; ++i)
        psi_cloud_alloc_user(&cloud->users[i], k, m_bit, seed + (i * 10));

    printf("[PSI Cloud Init] 初始化完成：共 %zu 个用户，每个用户 %u 个桶。\n", user_count, k);
}

// ==========================
// 打印云平台状态
// ==========================
void psi_cloud_print_status(const PSICloud *cloud) {
    if (!cloud) return;

    printf("\n=== PSI Cloud 状态 ===\n");
    printf("用户数量: %zu\n", cloud->user_count);

    for (size_t i = 0; i < cloud->user_count; ++i) {
        printf("-- 用户 #%zu --\n", i);
        gmp_printf("  User ID = %Zd\n", cloud->users[i].user_id);
        printf("  桶数量: %u, 位宽: %u\n", cloud->users[i].k, cloud->users[i].m_bit);
    }
}

// ==========================
// 释放云平台资源
// ==========================
void psi_cloud_free(PSICloud *cloud) {
    if (!cloud) return;

    EVP_PKEY_free(cloud->rsa_ctx->pkey);
    free(cloud->rsa_ctx);

    for (size_t i = 0; i < cloud->user_count; ++i) {
        PSIUserEntry *u = &cloud->users[i];

        bucket_free(&u->H_P);
        bucket_free(&u->H_W);
        bucket_free(&u->H_Beaver_a);
        bucket_free(&u->H_Beaver_b);
        result_bucket_free(&u->H_Beaver_c);
        result_bucket_free(&u->PSI_result);

        mpz_clear(u->user_id);
    }

    free(cloud->users);
    printf("[PSI Cloud] 所有用户及资源已释放。\n");
}

