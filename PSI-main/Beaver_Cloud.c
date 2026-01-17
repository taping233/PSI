#include "Beaver_Cloud.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>

// -----------------------------
// 【模块化优化】抽离通用辅助函数
// -----------------------------

/**
 * 统一错误处理：打印信息并退出，确保资源清理
 * @param msg 错误描述
 */
static void beaver_handle_error(const char *msg) {
    fprintf(stderr, "Beaver Cloud Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/**
 * 安全内存分配：封装malloc+NULL检查
 * @param size 分配大小
 * @param err_msg 错误提示
 */
static void *beaver_safe_malloc(size_t size, const char *err_msg) {
    void *ptr = malloc(size);
    if (!ptr) beaver_handle_error(err_msg);
    return ptr;
}

/**
 * 初始化GMP随机数状态
 * @param state 随机数状态指针
 * @param seed 随机种子（0则用当前时间）
 * @param prefix 日志前缀
 */
static void beaver_rand_init(gmp_randstate_t *state, unsigned long seed, const char *prefix) {
    gmp_randinit_default(*state);
    unsigned long final_seed = (seed == 0) ? (unsigned long)time(NULL) : seed;
    gmp_randseed_ui(*state, final_seed);
    printf("[%s] 随机种子: %lu\n", prefix, final_seed);
}

/**
 * 检查桶索引是否合法（避免越界）
 * @param cloud 云平台指针
 * @param idx 桶索引
 * @param n 桶总数
 * @return 合法返回1，非法退出
 */
static int beaver_check_bucket_idx(const BeaverCloud *cloud, size_t idx, size_t n) {
    if (idx >= n) {
        fprintf(stderr, "桶索引%zu越界（总数%zu）\n", idx, n);
        beaver_handle_error("桶索引越界");
    }
    if (!cloud->original.beaver_A.buckets || !cloud->original.beaver_B.buckets) {
        beaver_handle_error("桶结构未初始化");
    }
    return 1;
}

/**
 * 多项式乘法核心逻辑：C(x) = A(x) * B(x)
 * @param C_coeffs 结果多项式系数数组
 * @param A_coeffs 输入多项式A系数数组
 * @param B_coeffs 输入多项式B系数数组
 * @param M 模数（预留）
 */
static void beaver_poly_mult(mpz_t *C_coeffs, 
                             const mpz_t *A_coeffs, 
                             const mpz_t *B_coeffs,
                             const mpz_t M) {
    // 初始化结果为0
    for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
        mpz_set_ui(C_coeffs[j], 0);
    }

    // 多项式乘法：A(x)*B(x) = Σ(p+q=k) A_p * B_q
    mpz_t tmp;
    mpz_init(tmp); // 仅初始化一次，避免频繁init/clear
    for (size_t p = 0; p < BUCKET_POLY_LEN; ++p) {
        for (size_t q = 0; q < BUCKET_POLY_LEN; ++q) {
            size_t idx = p + q;
            if (idx < RESULT_POLY_LEN) {
                mpz_mul(tmp, A_coeffs[p], B_coeffs[q]);
                mpz_add(C_coeffs[idx], C_coeffs[idx], tmp);
                // 预留：若需要模运算，此处可加 mpz_mod(C_coeffs[idx], C_coeffs[idx], M);
            }
        }
    }
    mpz_clear(tmp); // 统一清理
}

// -----------------------------
// 原有函数优化（保持接口，修复逻辑，精简冗余）
// -----------------------------

// -----------------------------
// 初始化云平台
// -----------------------------
void beaver_cloud_init(BeaverCloud *cloud, unsigned int m_bit, unsigned long seed, size_t n) {
    // 基础参数校验
    if (!cloud || m_bit == 0 || n == 0) {
        beaver_handle_error("初始化参数无效（cloud为空/位宽为0/桶数为0）");
    }

    // 初始化基础属性
    memset(cloud, 0, sizeof(BeaverCloud)); // 先清空整体结构
    cloud->m_bit = m_bit;
    cloud->rsa_ctx = NULL;

    // 初始化Beaver三元组桶结构
    bucket_init(&cloud->original.beaver_A, n, m_bit);
    bucket_init(&cloud->original.beaver_B, n, m_bit);
    result_bucket_init(&cloud->original.beaver_C, n);

    // 初始化RSA密钥上下文
    cloud->rsa_ctx = beaver_safe_malloc(sizeof(RSAContext), "RSA上下文分配失败");
    rsa_generate_mem(cloud->rsa_ctx);

    // 初始化AES上下文（修复：先memset再初始化，避免覆盖）
    memset(&cloud->aes_ctx, 0, sizeof(AESContext));
    if (aes_init_mem(&cloud->aes_ctx) != 1) {
        fprintf(stderr, "AES密钥生成失败\n");
        // 释放已分配的RSA资源
        EVP_PKEY_free(cloud->rsa_ctx->pkey);
        free(cloud->rsa_ctx);
        exit(EXIT_FAILURE);
    }

    printf("[Beaver Cloud Init] 初始化完成：位宽%u，桶数%zu\n", m_bit, n);
}

// -----------------------------
// 设置 AES 密钥
// -----------------------------
void beaver_cloud_set_aes(BeaverCloud *cloud, const unsigned char *key, const unsigned char *iv) {
    if (!cloud || !key || !iv) {
        fprintf(stderr, "AES密钥设置失败：参数为空\n");
        return;
    }
    memcpy(cloud->aes_ctx.key, key, 32);
    memcpy(cloud->aes_ctx.iv, iv, 16);
    printf("[Beaver Cloud] AES密钥已加载\n");
}

// -----------------------------
// 打印云平台状态
// -----------------------------
void beaver_cloud_print(const BeaverCloud *cloud) {
    if (!cloud) return;

    printf("\n=== Beaver Cloud Platform ===\n");
    printf("模长: %u bits\n", cloud->m_bit);
    printf("AES: %s\n", cloud->aes_ctx.key[0] ? "已加载" : "未加载");
    printf("RSA: %s\n", cloud->rsa_ctx ? "已初始化" : "未初始化");

    printf("\n原始 A 桶（示例前 5 项）:\n");
    bucket_print_poly(&cloud->original.beaver_A, 1, 5);
}

// -----------------------------
// 释放所有资源
// -----------------------------
void beaver_cloud_free(BeaverCloud *cloud) {
    if (!cloud) return;

    // 释放Beaver三元组桶
    bucket_free(&cloud->original.beaver_A);
    bucket_free(&cloud->original.beaver_B);
    result_bucket_free(&cloud->original.beaver_C);

    // 安全释放RSA（检查NULL）
    if (cloud->rsa_ctx) {
        EVP_PKEY_free(cloud->rsa_ctx->pkey);
        free(cloud->rsa_ctx);
        cloud->rsa_ctx = NULL;
    }

    // 清空AES上下文（安全起见）
    memset(&cloud->aes_ctx, 0, sizeof(AESContext));

    printf("[Beaver Cloud] 所有资源已释放\n");
}

// -------------------------------------------------------
// 生成 Beaver 多项式三元组
// -------------------------------------------------------
void beaver_cloud_generate_triplets(BeaverCloud *cloud, unsigned long seed, const mpz_t M, size_t n) {
    // 基础参数校验
    if (!cloud) beaver_handle_error("cloud指针为空");
    if (n == 0) beaver_handle_error("桶数量不能为0");
    if (M && mpz_sgn(M) <= 0) {
        fprintf(stderr, "模数M无效（必须为正整数）\n");
        beaver_handle_error("模数M非法");
    }

    // 初始化随机数状态
    gmp_randstate_t state;
    beaver_rand_init(&state, seed, "Beaver Triplet Generate");

    printf("[*] 生成多项式Beaver三元组中...\n");

    // ========== 1️⃣ 生成A(x)、B(x)的随机系数 ==========
    mpz_t temp;
    mpz_init(temp);
    for (size_t i = 0; i < n; i++) {
        beaver_check_bucket_idx(cloud, i, n); // 检查桶索引
        for (size_t j = 0; j < BUCKET_POLY_LEN; j++) {
            // 修复：使用配置的m_bit生成随机数，而非固定20位
            mpz_urandomb(temp, state, cloud->m_bit);
            mpz_set(cloud->original.beaver_A.buckets[i].coeffs[j], temp);
            
            mpz_urandomb(temp, state, cloud->m_bit);
            mpz_set(cloud->original.beaver_B.buckets[i].coeffs[j], temp);
        }
    }
    mpz_clear(temp);
    gmp_randclear(state);

    // ========== 2️⃣ 计算C(x) = A(x) * B(x) ==========
    for (size_t i = 0; i < n; ++i) {
        beaver_check_bucket_idx(cloud, i, n); // 检查桶索引
        // 调用封装的多项式乘法函数
        beaver_poly_mult(cloud->original.beaver_C.result_buckets[i].coeffs,
                         cloud->original.beaver_A.buckets[i].coeffs,
                         cloud->original.beaver_B.buckets[i].coeffs,
                         M);
    }

    printf("[✓] Beaver多项式三元组生成完毕（共%zu个桶）\n", n);
}
