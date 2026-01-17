#ifndef CLIENT_H
#define CLIENT_H

#include <gmp.h>
#include "bucket.h"
#include "dataset.h"
#include "crypt.h"
#include "hash.h"

// 宏定义规范化：消除硬编码魔法数
#define TAG_BIT_LEN          128    // 桶tag的比特长度
#define RSA_KEY_BITS         2048   // RSA密钥比特长度
#define AES_KEY_BITS         256    // AES密钥比特长度

// ===========================
//   Client 结构定义
// ===========================
typedef struct {
    // --- 数据部分 ---
    mpz_t *data;            // 数据集
    unsigned int n;         // 数据规模指数（数据长度 = 2^n）
    unsigned int m_bit;     // 单个数据位宽
    unsigned int k;         // 桶数量
    int user_id;            // 用户唯一标识

    // --- 桶结构 ---
    BucketSet H_P;          // 数据桶集合
    BucketSet H_W;          // 随机掩码桶集合
    BucketSet H_r;          // 存储数据桶随机根
    BucketSet H_Beaver_a;   // Beaver三元组桶集合a_0(x)
    BucketSet H_Beaver_b;   // Beaver三元组桶集合b_0(x)
    Result_BucketSet H_Beaver_c; // Beaver三元组桶集合c_0(x)
    size_t *shuffle_table;  // 长度 = k，用于记录桶的随机打乱顺序
    
    Result_BucketSet PSI_result; // 用于存放用户计算完后的结果

    // --- 密钥 ---
    RSAContext *rsa_ctx;    // RSA-2048 内存密钥
    AESContext aes_psi;     // AES-256 (PSI平台)
    AESContext aes_verify;  // AES-256 (验证方)
} Client;

// ===========================
//   函数接口声明（完全兼容原接口）
// ===========================
void client_init(Client *cli, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed, int id);
void client_build_buckets(Client *cli, const mpz_t M);
void client_insert_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M);
void client_insert_dataset(Client *cli, const mpz_t M);
void client_delete_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M);
void client_generate_shuffle_table(Client *cli, unsigned long seed);
void client_free(Client *cli);
void client_print_summary(const Client *cli);

// 内部复用函数（static，对外不可见）
static void client_generate_P_BUCKET(Client *cli);

#endif // CLIENT_H
