#include "Verify.h"
#include "hash.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// -----------------------------
// 辅助函数：生成桶打乱表
// -----------------------------
static void verify_generate_shuffle_table(Verify *verify, unsigned long seed) {
    if (!verify || verify->k == 0) return;

    verify->shuffle_table = malloc(sizeof(size_t) * verify->k);
    if (!verify->shuffle_table) {
        fprintf(stderr, "[Verify Init] malloc failed for shuffle_table\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < verify->k; ++i)
        verify->shuffle_table[i] = i;

    srand((unsigned int)seed);
    for (size_t i = verify->k - 1; i > 0; --i) {
        size_t j = rand() % (i + 1);
        size_t tmp = verify->shuffle_table[i];
        verify->shuffle_table[i] = verify->shuffle_table[j];
        verify->shuffle_table[j] = tmp;
    }

    printf("[Verify Init] 已生成桶打乱表（长度=%u）。\n", verify->k);
}

// -----------------------------
// 验证方初始化
// -----------------------------
void verify_init(Verify *verify, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed) {
    if (!verify) return;

    verify->n = n;
    verify->m_bit = m_bit;
    verify->k = k;

    // --- 1️⃣ 生成本地数据集 ---
    size_t data_len = 1UL << n;
    verify->data = malloc(sizeof(mpz_t) * data_len);
    if (!verify->data) {
        fprintf(stderr, "[Verify Init] malloc failed for data\n");
        exit(EXIT_FAILURE);
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    if (seed == 0)
        seed = (unsigned long)time(NULL);
    gmp_randseed_ui(state, seed);

    for (size_t i = 0; i < data_len; ++i) {
        mpz_init(verify->data[i]);
        mpz_urandomb(verify->data[i], state, m_bit);
    }

    // --- 2️⃣ 初始化桶结构 ---
    // 随机根桶 H_r
    bucket_generate(&verify->H_r, k, m_bit, seed + 1);

    // 数据桶 H_P（拷贝 H_r 根）
    bucket_init(&verify->H_P, k, m_bit);
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j < BUCKET_ROOTS; ++j)
            mpz_set(verify->H_P.buckets[i].roots[j], verify->H_r.buckets[i].roots[j]);
        verify->H_P.buckets[i].element_num = 0;
    }

    // 为 H_P 生成随机 tag
    gmp_randstate_t tag_state;
    gmp_randinit_default(tag_state);
    gmp_randseed_ui(tag_state, seed + 20);
    for (size_t i = 0; i < verify->H_P.count; ++i)
        mpz_urandomb(verify->H_P.buckets[i].tag, tag_state, 128);
    gmp_randclear(tag_state);
    printf("[Verify Init] 已为数据桶分配随机标识 tag（128-bit）。\n");

    // 随机掩码桶 H_W
    bucket_generate(&verify->H_W, k, m_bit, seed + 3);
    for (size_t i = 0; i < k; ++i)
        verify->H_W.buckets[i].element_num = 0;

    // Beaver 三元组桶（初始化为空）
    bucket_init(&verify->H_Beaver_a, k, m_bit);
    bucket_init(&verify->H_Beaver_b, k, m_bit);
    result_bucket_init(&verify->H_Beaver_c, k);

    // 结果桶集合
    result_bucket_init(&verify->result_user, k);
    result_bucket_init(&verify->result_cloud, k);
    result_bucket_init(&verify->result_merged, k);

    // --- 3️⃣ 生成密钥体系 ---
    verify->rsa_ctx = malloc(sizeof(RSAContext));
    rsa_generate_mem(verify->rsa_ctx);


    if (aes_generate_mem(&verify->aes_psi) != 1)
        fprintf(stderr, "[Verify Init] AES(PSI) 密钥生成失败！\n");

    if (aes_generate_mem(&verify->aes_verify) != 1)
        fprintf(stderr, "[Verify Init] AES(Verify) 密钥生成失败！\n");

    gmp_randclear(state);

    printf("[Verify Init] 数据规模 = 2^%u = %zu, 位宽 = %u, 桶数 = %u\n",
           n, data_len, m_bit, k);
    printf("[Verify Init] 桶构建完成：H_P 与 H_r 同根，H_W 与 H_Beaver 独立生成。\n");

    // --- 4️⃣ 生成桶打乱表 ---
    verify_generate_shuffle_table(verify, seed + 9);
}

// -----------------------------
// 构建数据桶：H_P 由 H_r 展开
// -----------------------------
void verify_build_buckets(Verify *verify, const mpz_t M) {
    if (!verify) return;

    printf("[Verify] 构建数据桶 H_P ...\n");

    bucket_expand(&verify->H_P, M);

    for (size_t i = 0; i < verify->k; ++i)
        verify->H_P.buckets[i].element_num = 0;

    printf("[Verify] H_P 构建完成，共 %u 个桶。\n", verify->k);
}

// -----------------------------
// 在指定桶中插入数据（根）
// -----------------------------
void verify_insert_data(Verify *verify, size_t bucket_idx, const mpz_t data, const mpz_t M) {
    if (!verify || bucket_idx >= verify->k) {
        fprintf(stderr, "[verify_insert_data] 参数错误。\n");
        return;
    }

    Bucket *poly_bucket = &verify->H_P.buckets[bucket_idx];
    Bucket *root_bucket = &verify->H_r.buckets[bucket_idx];

    if (poly_bucket->element_num >= BUCKET_ROOTS) {
        fprintf(stderr, "[verify_insert_data] 桶 %zu 已满。\n", bucket_idx);
        return;
    }

    size_t r_idx = poly_bucket->element_num;
    mpz_t r_out;
    mpz_init_set(r_out, root_bucket->roots[r_idx]);

    mpz_t r_in;
    mpz_init_set(r_in, data);

    // printf("[Verify] 桶 %zu: 插入数据 → 替换根 #%zu。\n", bucket_idx, r_idx);

    // 使用降幂形式替换
    bucket_replace_root(poly_bucket->coeffs, BUCKET_ROOTS, r_out, r_in, M);

    // 更新根表
    mpz_set(root_bucket->roots[r_idx], r_in);
    mpz_set(poly_bucket->roots[r_idx], r_in);

    poly_bucket->element_num++;

    mpz_clears(r_out, r_in, NULL);
}


// -----------------------------
// 在指定桶中删除数据（根）
// -----------------------------
void verify_delete_data(Verify *verify, size_t bucket_idx, const mpz_t data, const mpz_t M) {
    if (!verify || bucket_idx >= verify->k) {
        fprintf(stderr, "[verify_delete_data] 参数错误。\n");
        return;
    }

    Bucket *poly_bucket = &verify->H_P.buckets[bucket_idx];
    Bucket *root_bucket = &verify->H_r.buckets[bucket_idx];

    if (poly_bucket->element_num == 0) {
        fprintf(stderr, "[verify_delete_data] 桶 %zu 为空。\n", bucket_idx);
        return;
    }

    size_t r_idx = (size_t)-1;
    for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
        if (mpz_cmp(root_bucket->roots[j], data) == 0) {
            r_idx = j;
            break;
        }
    }

    if (r_idx == (size_t)-1) {
        fprintf(stderr, "[verify_delete_data] 未找到指定数据。\n");
        return;
    }

    // 随机生成新的空根替代
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) + bucket_idx);

    mpz_t r_rand;
    mpz_init(r_rand);
    mpz_urandomb(r_rand, state, verify->m_bit);

    printf("[Verify] 桶 %zu: 删除数据 → 替换根 #%zu。\n", bucket_idx, r_idx);

    bucket_replace_root(poly_bucket->coeffs, BUCKET_ROOTS, data, r_rand, M);

    // 更新根表
    mpz_set(root_bucket->roots[r_idx], r_rand);
    mpz_set(poly_bucket->roots[r_idx], r_rand);

    poly_bucket->element_num--;

    mpz_clear(r_rand);
    gmp_randclear(state);
}

// -----------------------------
// 数据集中元素插入桶中
// -----------------------------
void verify_insert_dataset(Verify *verify, const mpz_t M) {
    if (!verify || !verify->data || !verify->H_P.buckets) {
        fprintf(stderr, "[Verify Insert] 无效参数或未初始化结构。\n");
        return;
    }

    size_t total = (1UL << verify->n);
    printf("[Verify Insert] 开始插入 %zu 个数据到 %u 个桶中...\n",
           total, verify->k);

    mpz_t s_tagged;
    mpz_init(s_tagged);

    for (size_t i = 0; i < total; ++i) {
        // 1️⃣ 计算哈希值 h(s)
        uint64_t h = hash48_compute(verify->data[i]);

        // 2️⃣ 计算桶号
        size_t bucket_idx = h % verify->k;

        // 3️⃣ 生成带哈希的扩展数据 s' = (s << 48) | h(s)
        hash48_append(s_tagged, verify->data[i]);

        // 4️⃣ 插入数据
        verify_insert_data(verify, bucket_idx, s_tagged, M);

        // 打印进度
        // if ((i + 1) % 10000 == 0)
        //    printf("  已插入 %zu / %zu 条数据...\n", i + 1, total);
    }

    mpz_clear(s_tagged);
    printf("[Verify Insert] 全部数据插入完成。\n");
}

// -----------------------------
// 打印验证方状态报告
// -----------------------------
void verify_print_report(const Verify *verify) {
    if (!verify) return;

    printf("\n========== [Verify Report] ==========\n");
    printf("数据规模：2^%u\n", verify->n);
    printf("桶数量：%u\n", verify->k);
    printf("位宽：%u bits\n", verify->m_bit);
    
    printf("AES(PSI)：%s\n", verify->aes_psi.key[0] ? "已加载" : "未加载");
    printf("AES(Verify)：%s\n", verify->aes_verify.key[0] ? "已加载" : "未加载");

    printf("桶打乱表前 10 项：");
    for (size_t i = 0; i < (verify->k < 10 ? verify->k : 10); ++i)
        printf("%zu ", verify->shuffle_table[i]);
    printf("\n=====================================\n");
}

// -----------------------------
// 释放所有资源
// -----------------------------
void verify_free(Verify *verify) {
    if (!verify) return;

    size_t data_len = 1UL << verify->n;
    for (size_t i = 0; i < data_len; ++i)
        mpz_clear(verify->data[i]);
    free(verify->data);

    bucket_free(&verify->H_P);
    bucket_free(&verify->H_W);
    bucket_free(&verify->H_r);
    bucket_free(&verify->H_Beaver_a);
    bucket_free(&verify->H_Beaver_b);

    result_bucket_free(&verify->H_Beaver_c);
    result_bucket_free(&verify->result_user);
    result_bucket_free(&verify->result_cloud);
    result_bucket_free(&verify->result_merged);

    EVP_PKEY_free(verify->rsa_ctx->pkey);
    free(verify->rsa_ctx);

    memset(&verify->aes_psi, 0, sizeof(AESContext));
    memset(&verify->aes_verify, 0, sizeof(AESContext));

    if (verify->shuffle_table)
        free(verify->shuffle_table);


    printf("[Verify] 资源释放完成。\n");
}

