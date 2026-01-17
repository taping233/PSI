#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ===========================
// Client 初始化
// ===========================
// 初始化用户数据与密钥
void client_init(Client *cli, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed, int id) {
    if (!cli) return;

    cli->n = n;
    cli->m_bit = m_bit;
    cli->k = k;

    // --- 1️⃣ 生成本地数据集 ---
    size_t data_len = 1UL << n;
    cli->data = malloc(sizeof(mpz_t) * data_len);
    if (!cli->data) {
        fprintf(stderr, "[Client Init] malloc failed for data\n");
        exit(EXIT_FAILURE);
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    if (seed == 0)
        seed = (unsigned long)time(NULL);
    gmp_randseed_ui(state, seed);

    for (size_t i = 0; i < data_len; ++i) {
        mpz_init(cli->data[i]);
        mpz_urandomb(cli->data[i], state, m_bit);
    }
    
    // --- 初始化用户 ID ---
    cli->user_id = id;

    // --- 2️⃣ 初始化桶结构 ---

    // ✅ 随机根桶 H_r（核心随机性来源）
    bucket_generate(&cli->H_r, k, m_bit, seed + 1);

    // ✅ 数据桶 H_P：复制随机根，不重新生成
    bucket_init(&cli->H_P, k, m_bit);
    for (size_t i = 0; i < k; ++i) {
        // 拷贝随机根
        for (size_t j = 0; j < BUCKET_ROOTS; ++j)
            mpz_set(cli->H_P.buckets[i].roots[j], cli->H_r.buckets[i].roots[j]);

        cli->H_P.buckets[i].element_num = 0;
    }
    // 仅为 H_P（数据桶）生成随机标识
    gmp_randstate_t tag_state;
    gmp_randinit_default(tag_state);
    gmp_randseed_ui(tag_state, seed + 20);

    for (size_t i = 0; i < cli->H_P.count; ++i) {
        mpz_urandomb(cli->H_P.buckets[i].tag, tag_state, 128);
    }
    gmp_randclear(tag_state);
    printf("[Client Init] 已为数据桶分配随机标识 tag（128-bit）。\n");
    
    

    // ✅ 随机掩码桶 H_W
    bucket_generate(&cli->H_W, k, m_bit, seed + 3);
    for (size_t i = 0; i < k; ++i)
        cli->H_W.buckets[i].element_num = 0;

    // ✅ Beaver 三元组桶 H_Beaver（预留空间，内容待云端分发）
    bucket_init(&cli->H_Beaver_a, k, m_bit);
    bucket_init(&cli->H_Beaver_b, k, m_bit);
    result_bucket_init(&cli->H_Beaver_c, k);
    
    // --- 3️⃣ 初始化密钥体系 ---
    cli->rsa_ctx = malloc(sizeof(RSAContext));
    rsa_generate_mem(cli->rsa_ctx);

    if (aes_generate_mem(&cli->aes_psi) != 1)
        fprintf(stderr, "[Client Init] AES(PSI) 密钥生成失败！\n");

    if (aes_generate_mem(&cli->aes_verify) != 1)
        fprintf(stderr, "[Client Init] AES(Verify) 密钥生成失败！\n");

    gmp_randclear(state);

    printf("[Client Init] 数据规模 = 2^%u = %zu, 位宽 = %u, 桶数 = %u\n",
           n, data_len, m_bit, k);
    printf("[Client Init] 桶构建完成：H_P 与 H_r 同根，H_W 与 H_Beaver 独立生成。\n");
    
    //生成桶打乱表
    client_generate_shuffle_table(cli, seed + 9);

}

// ===========================
// Client 生成数据桶
// ===========================
// 构建数据桶（用随机根展开多项式）
void client_build_buckets(Client *cli, const mpz_t M) {
    if (!cli) return;

    printf("[Client] 构建数据桶 H_P ...\n");

    // H_P 的随机根已在 client_init() 时从 H_r 拷贝
    // 直接展开成多项式即可
      bucket_expand(&cli->H_P, M);

    printf("[Client] H_P 构建完成，共 %u 个桶。\n", cli->k);
}

// -----------------------------
// 在指定桶中插入数据（根）
// -----------------------------
void client_insert_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M) {
    if (!cli || bucket_idx >= cli->k) {
        fprintf(stderr, "[client_insert_data] 参数错误。\n");
        return;
    }

    Bucket *poly_bucket = &cli->H_P.buckets[bucket_idx];
    Bucket *root_bucket = &cli->H_r.buckets[bucket_idx];

    if (poly_bucket->element_num >= BUCKET_ROOTS) {
        fprintf(stderr, "[client_insert_data] 桶 %zu 已满。\n", bucket_idx);
        return;
    }

    // 找一个“空”的随机根（默认是最前面的）
    size_t r_idx = poly_bucket->element_num;
    mpz_t r_out;
    mpz_init_set(r_out, root_bucket->roots[r_idx]);

    // r_in 为待插入数据（这里认为 data 就是新根）
    mpz_t r_in;
    mpz_init_set(r_in, data);

    // printf("[Client] 桶 %zu: 插入数据 → 替换根 #%zu。\n", bucket_idx, r_idx);

    // 多项式替换
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
void client_delete_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M) {
    if (!cli || bucket_idx >= cli->k) {
        fprintf(stderr, "[client_delete_data] 参数错误。\n");
        return;
    }

    Bucket *poly_bucket = &cli->H_P.buckets[bucket_idx];
    Bucket *root_bucket = &cli->H_r.buckets[bucket_idx];

    if (poly_bucket->element_num == 0) {
        fprintf(stderr, "[client_delete_data] 桶 %zu 为空。\n", bucket_idx);
        return;
    }

    // 找到数据对应的根
    size_t r_idx = (size_t)-1;
    for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
        if (mpz_cmp(root_bucket->roots[j], data) == 0) {
            r_idx = j;
            break;
        }
    }

    if (r_idx == (size_t)-1) {
        fprintf(stderr, "[client_delete_data] 未找到指定数据。\n");
        return;
    }

    // 随机生成一个新的“空”根，替换掉该数据
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL) + bucket_idx);

    mpz_t r_rand;
    mpz_init(r_rand);
    mpz_urandomb(r_rand, state, cli->m_bit);

    printf("[Client] 桶 %zu: 删除数据 → 替换根 #%zu。\n", bucket_idx, r_idx);

    // 多项式替换
    bucket_replace_root(poly_bucket->coeffs, BUCKET_ROOTS, data, r_rand, M);

    // 更新根表
    mpz_set(root_bucket->roots[r_idx], r_rand);
    mpz_set(poly_bucket->roots[r_idx], r_rand);

    poly_bucket->element_num--;
    mpz_clears(r_rand, NULL);
    gmp_randclear(state);
}

// 生成桶打乱表（Fisher–Yates 洗牌，但不实际重排桶）
// 用于传输时重新映射桶索引
void client_generate_shuffle_table(Client *cli, unsigned long seed) {
    if (!cli || cli->k == 0) return;

    cli->shuffle_table = malloc(sizeof(size_t) * cli->k);
    if (!cli->shuffle_table) {
        fprintf(stderr, "client_generate_shuffle_table: malloc failed\n");
        exit(EXIT_FAILURE);
    }

    // 初始化表 [0, 1, 2, ..., k-1]
    for (size_t i = 0; i < cli->k; ++i)
        cli->shuffle_table[i] = i;

    // 使用 Fisher–Yates 算法随机打乱
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed ? seed : (unsigned long)time(NULL));

    for (ssize_t i = cli->k - 1; i > 0; --i) {
        mpz_t rand_val, bound;
        mpz_inits(rand_val, bound, NULL);
        mpz_set_ui(bound, i + 1);
        mpz_urandomm(rand_val, state, bound);
        size_t j = mpz_get_ui(rand_val);
        mpz_clears(rand_val, bound, NULL);

        size_t tmp = cli->shuffle_table[i];
        cli->shuffle_table[i] = cli->shuffle_table[j];
        cli->shuffle_table[j] = tmp;
    }

    gmp_randclear(state);

    printf("[Client Init] 桶打乱表已生成（未实际打乱内存顺序）。\n");
}


// 生成数据桶
void client_generate_P_BUCKET(Client *cli){

    size_t total = (1UL << cli->n);
    printf("[Client Insert] 开始将 %zu 个数据插入到 %u 个桶中...\n", total, cli->k);

    mpz_t s_tagged;
    mpz_init(s_tagged);
    
    // 初始化元素数
    for (size_t i = 0; i < cli->k; ++i)
        cli->H_P.buckets[i].element_num = 0;

    for (size_t i = 0; i < total; ++i){

        // 1️⃣ 计算哈希值并映射桶
        uint64_t h = hash48_compute(cli->data[i]);
        size_t bucket_idx = h % cli->k;

        // 2️⃣ 附加哈希到数据
        hash48_append(s_tagged, cli->data[i]);
    
        // 3️⃣ 插入数据
        if (!cli || bucket_idx >= cli->k) {
            fprintf(stderr, "[client_insert_data] 参数错误。\n");
            return;
        }

        mpz_set(cli->H_P.buckets[bucket_idx].roots[cli->H_P.buckets[bucket_idx].element_num], s_tagged);
        cli->H_P.buckets[bucket_idx].element_num += 1;

    }

    mpz_clear(s_tagged);
    printf("[Client Insert] 全部数据插入完成。\n");
}



// 将数据从数据集中插入到桶中
void client_insert_dataset(Client *cli, const mpz_t M) {
    if (!cli || !cli->data || !cli->H_P.buckets) {
        fprintf(stderr, "[Client Insert] 无效参数或未初始化的桶结构\n");
        return;
    }

    size_t total = (1UL << cli->n);
    printf("[Client Insert] 开始将 %zu 个数据插入到 %u 个桶中...\n",
           total, cli->k);

    mpz_t s_tagged;
    mpz_init(s_tagged);

    for (size_t i = 0; i < total; ++i) {
        // 1️⃣ 计算哈希值并映射桶
        uint64_t h = hash48_compute(cli->data[i]);
        size_t bucket_idx = h % cli->k;

        // 2️⃣ 附加哈希到数据
        hash48_append(s_tagged, cli->data[i]);

        // 3️⃣ 插入数据（利用 client_insert_data 函数）
        client_insert_data(cli, bucket_idx, s_tagged, M);

        //if ((i + 1) % 10000 == 0)
        //    printf("  已插入 %zu / %zu 条数据...\n", i + 1, total);
    }

    mpz_clear(s_tagged);
    printf("[Client Insert] 全部数据插入完成。\n");
}

// ===========================
// Client 释放
// ===========================
// 释放内存
void client_free(Client *cli) {
    if (!cli) return;

    size_t data_len = 1UL << cli->n;
    for (size_t i = 0; i < data_len; ++i)
        mpz_clear(cli->data[i]);
    free(cli->data);

    bucket_free(&cli->H_P);
    bucket_free(&cli->H_W);
    bucket_free(&cli->H_r);

    EVP_PKEY_free(cli->rsa_ctx->pkey);
    free(cli->rsa_ctx);
    
    bucket_free(&cli->H_Beaver_a);
    bucket_free(&cli->H_Beaver_b);
    result_bucket_free(&cli->H_Beaver_c);
    result_bucket_free(&cli->PSI_result);

}

// ===========================
// Client 摘要打印
// ===========================
void client_print_summary(const Client *cli)
{
    if (!cli) return;

    printf("=== Client 信息摘要 ===\n");
    printf("数据集规模: 2^%u = %zu\n", cli->n, (size_t)1 << cli->n);
    printf("数据位宽: %u bit\n", cli->m_bit);
    printf("桶数量: %u\n", cli->k);
    printf("RSA 密钥: 2048 bit (in-memory)\n");
    printf("AES 密钥: 256 bit × 2 (PSI / Verify)\n");
    printf("=======================\n\n");
}
