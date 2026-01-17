#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// -----------------------------
// 【模块化优化】抽离通用辅助函数（避免重复）
// -----------------------------

/**
 * 统一错误处理函数：打印错误信息并退出
 * @param msg 错误描述
 */
static void handle_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

/**
 * 安全内存分配：封装malloc+NULL检查
 * @param size 分配大小
 * @param err_msg 错误提示
 * @return 分配成功的内存指针
 */
static void *safe_malloc(size_t size, const char *err_msg) {
    void *ptr = malloc(size);
    if (!ptr) handle_error(err_msg);
    return ptr;
}

/**
 * 初始化GMP随机数状态
 * @param state 随机数状态指针
 * @param seed 随机种子（0则用当前时间）
 * @param prefix 日志前缀（用于区分不同场景）
 */
static void gmp_rand_init(gmp_randstate_t *state, unsigned long seed, const char *prefix) {
    gmp_randinit_default(*state);
    unsigned long final_seed = (seed == 0) ? (unsigned long)time(NULL) : seed;
    gmp_randseed_ui(*state, final_seed);
    // 可选日志：printf("[%s] 随机数种子: %lu\n", prefix, final_seed);
}

/**
 * 检查桶是否已满
 * @param bucket 桶指针
 * @param bucket_idx 桶索引（用于日志）
 * @return 满返回1，未满返回0
 */
static int is_bucket_full(const Bucket *bucket, size_t bucket_idx) {
    if (bucket->element_num >= BUCKET_ROOTS) {
        fprintf(stderr, "[Client] 桶 %zu 已满（最大容量：%d），无法插入新数据\n", 
                bucket_idx, BUCKET_ROOTS);
        return 1;
    }
    return 0;
}

// -----------------------------
// 原有函数优化（保持接口，修复逻辑，精简冗余）
// -----------------------------

// ===========================
// Client 初始化
// ===========================
void client_init(Client *cli, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed, int id) {
    if (!cli) {
        handle_error("[Client Init] cli指针为空");
        return;
    }

    // 初始化基础参数
    cli->n = n;
    cli->m_bit = m_bit;
    cli->k = k;
    cli->user_id = id;
    cli->shuffle_table = NULL;
    cli->rsa_ctx = NULL;
    // 初始化PSI_result（修复free时的野指针问题）
    memset(&cli->PSI_result, 0, sizeof(Result_BucketSet));

    // --- 1️⃣ 生成本地数据集 ---
    size_t data_len = 1UL << n;
    cli->data = safe_malloc(sizeof(mpz_t) * data_len, "[Client Init] malloc failed for data");

    gmp_randstate_t state;
    gmp_rand_init(&state, seed, "Client Data Generate");

    for (size_t i = 0; i < data_len; ++i) {
        mpz_init(cli->data[i]);
        mpz_urandomb(cli->data[i], state, m_bit);
    }
    gmp_randclear(state);

    // --- 2️⃣ 初始化桶结构 ---
    // ✅ 随机根桶 H_r（核心随机性来源）
    bucket_generate(&cli->H_r, k, m_bit, seed + 1);

    // ✅ 数据桶 H_P：复制随机根，不重新生成
    bucket_init(&cli->H_P, k, m_bit);
    for (size_t i = 0; i < k; ++i) {
        // 拷贝随机根
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_set(cli->H_P.buckets[i].roots[j], cli->H_r.buckets[i].roots[j]);
        }
        cli->H_P.buckets[i].element_num = 0;
    }

    // 仅为 H_P（数据桶）生成随机标识（128-bit）
    gmp_randstate_t tag_state;
    gmp_rand_init(&tag_state, seed + 20, "Client H_P Tag Generate");
    for (size_t i = 0; i < cli->H_P.count; ++i) {
        mpz_urandomb(cli->H_P.buckets[i].tag, tag_state, TAG_BIT_LEN);
    }
    gmp_randclear(tag_state);
    printf("[Client Init] 已为数据桶分配随机标识 tag（%d-bit）。\n", TAG_BIT_LEN);

    // ✅ 随机掩码桶 H_W
    bucket_generate(&cli->H_W, k, m_bit, seed + 3);
    for (size_t i = 0; i < k; ++i) {
        cli->H_W.buckets[i].element_num = 0;
    }

    // ✅ Beaver 三元组桶（预留空间）
    bucket_init(&cli->H_Beaver_a, k, m_bit);
    bucket_init(&cli->H_Beaver_b, k, m_bit);
    result_bucket_init(&cli->H_Beaver_c, k);

    // --- 3️⃣ 初始化密钥体系 ---
    cli->rsa_ctx = safe_malloc(sizeof(RSAContext), "[Client Init] malloc failed for RSAContext");
    rsa_generate_mem(cli->rsa_ctx);

    if (aes_generate_mem(&cli->aes_psi) != 1) {
        fprintf(stderr, "[Client Init] AES(PSI) 密钥生成失败！\n");
        // 释放已分配的RSA资源，避免内存泄漏
        EVP_PKEY_free(cli->rsa_ctx->pkey);
        free(cli->rsa_ctx);
        exit(EXIT_FAILURE);
    }

    if (aes_generate_mem(&cli->aes_verify) != 1) {
        fprintf(stderr, "[Client Init] AES(Verify) 密钥生成失败！\n");
        // 释放已分配的资源
        EVP_PKEY_free(cli->rsa_ctx->pkey);
        free(cli->rsa_ctx);
        exit(EXIT_FAILURE);
    }

    printf("[Client Init] 数据规模 = 2^%u = %zu, 位宽 = %u, 桶数 = %u\n",
           n, data_len, m_bit, k);
    printf("[Client Init] 桶构建完成：H_P 与 H_r 同根，H_W 与 H_Beaver 独立生成。\n");

    // 生成桶打乱表
    client_generate_shuffle_table(cli, seed + 9);
}

// ===========================
// Client 生成数据桶
// ===========================
void client_build_buckets(Client *cli, const mpz_t M) {
    if (!cli) {
        handle_error("[Client Build] cli指针为空");
        return;
    }

    printf("[Client] 构建数据桶 H_P ...\n");
    // H_P 的随机根已拷贝，直接展开成多项式
    bucket_expand(&cli->H_P, M);
    printf("[Client] H_P 构建完成，共 %u 个桶。\n", cli->k);
}

// -----------------------------
// 在指定桶中插入数据（根）
// -----------------------------
void client_insert_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M) {
    if (!cli || bucket_idx >= cli->k) {
        handle_error("[client_insert_data] 参数错误（cli为空或桶索引越界）");
        return;
    }

    Bucket *poly_bucket = &cli->H_P.buckets[bucket_idx];
    Bucket *root_bucket = &cli->H_r.buckets[bucket_idx];

    // 检查桶是否已满
    if (is_bucket_full(poly_bucket, bucket_idx)) {
        return;
    }

    // 找空的随机根位置
    size_t r_idx = poly_bucket->element_num;
    mpz_t r_out, r_in;
    mpz_inits(r_out, r_in, NULL);
    mpz_set(r_out, root_bucket->roots[r_idx]);
    mpz_set(r_in, data);

    // 多项式替换根
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
        handle_error("[client_delete_data] 参数错误（cli为空或桶索引越界）");
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
        fprintf(stderr, "[client_delete_data] 桶 %zu 中未找到指定数据。\n", bucket_idx);
        return;
    }

    // 生成高随机性的新根（修复seed随机性不足问题）
    gmp_randstate_t state;
    gmp_rand_init(&state, (unsigned long)time(NULL) + bucket_idx + cli->user_id, "Client Delete Random");
    mpz_t r_rand;
    mpz_init(r_rand);
    mpz_urandomb(r_rand, state, cli->m_bit);
    gmp_randclear(state);

    printf("[Client] 桶 %zu: 删除数据 → 替换根 #%zu。\n", bucket_idx, r_idx);

    // 多项式替换
    bucket_replace_root(poly_bucket->coeffs, BUCKET_ROOTS, data, r_rand, M);

    // 更新根表
    mpz_set(root_bucket->roots[r_idx], r_rand);
    mpz_set(poly_bucket->roots[r_idx], r_rand);

    poly_bucket->element_num--;
    mpz_clear(r_rand);
}

// -----------------------------
// 生成桶打乱表（Fisher–Yates 洗牌）
// -----------------------------
void client_generate_shuffle_table(Client *cli, unsigned long seed) {
    if (!cli || cli->k == 0) return;

    cli->shuffle_table = safe_malloc(sizeof(size_t) * cli->k, "client_generate_shuffle_table: malloc failed");

    // 初始化表 [0, 1, 2, ..., k-1]
    for (size_t i = 0; i < cli->k; ++i) {
        cli->shuffle_table[i] = i;
    }

    // Fisher–Yates 洗牌（高随机性）
    gmp_randstate_t state;
    gmp_rand_init(&state, seed, "Client Shuffle Table");

    for (ssize_t i = cli->k - 1; i > 0; --i) {
        mpz_t rand_val, bound;
        mpz_inits(rand_val, bound, NULL);
        mpz_set_ui(bound, i + 1);
        mpz_urandomm(rand_val, state, bound);
        size_t j = mpz_get_ui(rand_val);
        mpz_clears(rand_val, bound, NULL);

        // 交换元素
        size_t tmp = cli->shuffle_table[i];
        cli->shuffle_table[i] = cli->shuffle_table[j];
        cli->shuffle_table[j] = tmp;
    }

    gmp_randclear(state);
    printf("[Client Init] 桶打乱表已生成（未实际打乱内存顺序）。\n");
}

// -----------------------------
// 核心插入逻辑：抽离重复代码（消除冗余）
// -----------------------------
static void client_generate_P_BUCKET(Client *cli) {
    if (!cli) {
        handle_error("[client_generate_P_BUCKET] cli指针为空");
        return;
    }

    size_t total = (1UL << cli->n);
    printf("[Client Insert] 开始将 %zu 个数据插入到 %u 个桶中...\n", total, cli->k);

    mpz_t s_tagged;
    mpz_init(s_tagged);
    
    // 重置元素数
    for (size_t i = 0; i < cli->k; ++i) {
        cli->H_P.buckets[i].element_num = 0;
    }

    for (size_t i = 0; i < total; ++i) {
        // 1️⃣ 计算哈希值并映射桶
        uint64_t h = hash48_compute(cli->data[i]);
        size_t bucket_idx = h % cli->k;

        // 检查桶索引合法性
        if (bucket_idx >= cli->k) {
            fprintf(stderr, "[Client Insert] 桶索引 %zu 越界（最大：%u），跳过数据 %zu\n",
                    bucket_idx, cli->k - 1, i);
            continue;
        }

        // 2️⃣ 附加哈希到数据
        hash48_append(s_tagged, cli->data[i]);
    
        // 3️⃣ 检查桶是否已满，避免数组越界
        if (is_bucket_full(&cli->H_P.buckets[bucket_idx], bucket_idx)) {
            fprintf(stderr, "[Client Insert] 数据 %zu 无法插入桶 %zu（桶已满）\n", i, bucket_idx);
            continue;
        }

        // 4️⃣ 安全赋值根
        mpz_set(cli->H_P.buckets[bucket_idx].roots[cli->H_P.buckets[bucket_idx].element_num], s_tagged);
        cli->H_P.buckets[bucket_idx].element_num += 1;
    }

    mpz_clear(s_tagged);
    printf("[Client Insert] 全部数据插入完成（部分数据可能因桶满跳过）。\n");
}

// -----------------------------
// 插入整个数据集到桶中（复用核心逻辑）
// -----------------------------
void client_insert_dataset(Client *cli, const mpz_t M) {
    if (!cli || !cli->data || !cli->H_P.buckets) {
        handle_error("[Client Insert] 无效参数或未初始化的桶结构");
        return;
    }

    // 先调用核心插入逻辑完成根赋值
    client_generate_P_BUCKET(cli);

    // 再遍历桶完成多项式替换（原逻辑的补充）
    size_t total = (1UL << cli->n);
    printf("[Client Insert] 开始替换桶多项式根（共 %zu 个数据）...\n", total);

    mpz_t s_tagged;
    mpz_init(s_tagged);

    for (size_t i = 0; i < total; ++i) {
        uint64_t h = hash48_compute(cli->data[i]);
        size_t bucket_idx = h % cli->k;
        if (bucket_idx >= cli->k) continue;

        hash48_append(s_tagged, cli->data[i]);
        // 调用插入函数完成多项式替换
        client_insert_data(cli, bucket_idx, s_tagged, M);
    }

    mpz_clear(s_tagged);
    printf("[Client Insert] 数据集插入+多项式替换完成。\n");
}

// ===========================
// Client 释放（修复野指针，完整清理）
// ===========================
void client_free(Client *cli) {
    if (!cli) return;

    // 释放数据集
    if (cli->data) {
        size_t data_len = 1UL << cli->n;
        for (size_t i = 0; i < data_len; ++i) {
            mpz_clear(cli->data[i]);
        }
        free(cli->data);
        cli->data = NULL;
    }

    // 释放桶结构
    bucket_free(&cli->H_P);
    bucket_free(&cli->H_W);
    bucket_free(&cli->H_r);
    bucket_free(&cli->H_Beaver_a);
    bucket_free(&cli->H_Beaver_b);
    result_bucket_free(&cli->H_Beaver_c);
    result_bucket_free(&cli->PSI_result); // 现在初始化过，可安全释放

    // 释放打乱表
    if (cli->shuffle_table) {
        free(cli->shuffle_table);
        cli->shuffle_table = NULL;
    }

    // 释放密钥
    if (cli->rsa_ctx) {
        EVP_PKEY_free(cli->rsa_ctx->pkey);
        free(cli->rsa_ctx);
        cli->rsa_ctx = NULL;
    }

    printf("[Client Free] 所有资源已释放。\n");
}

// ===========================
// Client 摘要打印
// ===========================
void client_print_summary(const Client *cli) {
    if (!cli) return;

    printf("=== Client 信息摘要 ===\n");
    printf("用户ID: %d\n", cli->user_id);
    printf("数据集规模: 2^%u = %zu\n", cli->n, (size_t)1 << cli->n);
    printf("数据位宽: %u bit\n", cli->m_bit);
    printf("桶数量: %u\n", cli->k);
    printf("RSA 密钥: %d bit (in-memory)\n", RSA_KEY_BITS);
    printf("AES 密钥: %d bit × 2 (PSI / Verify)\n", AES_KEY_BITS);
    printf("=======================\n\n");
}
