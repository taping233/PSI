#ifndef VERIFY_H
#define VERIFY_H

#include "bucket.h"
#include "crypt.h"

// ===========================
//   Verify 结构定义
// ===========================
typedef struct {
    // --- 数据部分 ---
    mpz_t *data;            // 数据集
    unsigned int n;         // 数据规模指数（数据长度 = 2^n）
    unsigned int m_bit;     // 单个数据位宽
    unsigned int k;         // 桶数量

    // --- 桶结构 ---
    BucketSet H_P;          // 数据桶集合
    BucketSet H_W;          // 随机掩码桶集合
    BucketSet H_r;          // 随机根桶集合
    BucketSet H_Beaver_a;   // Beaver 三元组桶集合 a_0(x)
    BucketSet H_Beaver_b;   // Beaver 三元组桶集合 b_0(x)
    Result_BucketSet H_Beaver_c;   // Beaver 三元组桶集合 c_0(x)
    size_t *shuffle_table;  // 桶随机打乱顺序表

    // --- 结果桶集合 ---
    Result_BucketSet result_user;     // 用户端计算结果
    Result_BucketSet result_cloud;    // 云平台计算结果
    Result_BucketSet result_merged;   // 合并后结果（用户 + 云端）

    // --- 密钥 ---
    RSAContext *rsa_ctx;     // RSA-2048 内存密钥
    AESContext aes_psi;     // AES-256 (PSI 平台)
    AESContext aes_verify;  // AES-256 (验证方)
} Verify;

// ===========================
//   核心函数接口
// ===========================

// 初始化验证方（生成数据集、桶与密钥）
void verify_init(Verify *verify, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed);

// 构建数据桶（H_P 由 H_r 随机根展开）
void verify_build_buckets(Verify *verify, const mpz_t M);

// 打印验证方状态报告
void verify_print_report(const Verify *verify);

void verify_insert_data(Verify *verify, size_t bucket_idx, const mpz_t data, const mpz_t M);

void verify_delete_data(Verify *verify, size_t bucket_idx, const mpz_t data, const mpz_t M);

void verify_insert_dataset(Verify *verify, const mpz_t M);

// 释放所有资源
void verify_free(Verify *verify);

#endif // VERIFY_H

