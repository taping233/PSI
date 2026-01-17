#ifndef CLIENT_H
#define CLIENT_H

#include <gmp.h>
#include "bucket.h"
#include "dataset.h"
#include "crypt.h"
#include "hash.h"

// ===========================
//   Client 结构定义
// ===========================
typedef struct {
    // --- 数据部分 ---
    mpz_t *data;            // 数据集
    unsigned int n;         // 数据规模指数（数据长度 = 2^n）
    unsigned int m_bit;     // 单个数据位宽
    unsigned int k;         // 桶数量
    int user_id;          // 用户唯一标识

    // --- 桶结构 ---
    BucketSet H_P;          // 数据桶集合
    BucketSet H_W;          // 随机掩码桶集合
    BucketSet H_r;          // 存储数据桶随机根
    BucketSet H_Beaver_a;     // Beaver三元组桶集合a_0(x)
    BucketSet H_Beaver_b;     // Beaver三元组桶集合b_0(x)
    Result_BucketSet H_Beaver_c;     // Beaver三元组桶集合c_0(x)
    size_t *shuffle_table;    // 长度 = k，用于记录桶的随机打乱顺序
    
    
    Result_BucketSet PSI_result; // 用于存放用户计算完后的结果


    // --- 密钥 ---
    RSAContext *rsa_ctx;     // RSA-2048 内存密钥
    AESContext aes_psi;     // AES-256 (PSI平台)
    AESContext aes_verify;  // AES-256 (验证方)
} Client;

// ===========================
//   函数接口声明
// ===========================

// 初始化 Client：生成数据集、桶、密钥
void client_init(Client *cli, unsigned int n, unsigned int m_bit, unsigned int k, unsigned long seed, int id);


// 用户生成数据桶 H_P 的过程：
// 根据桶内随机根展开多项式 P(x) = ∏(x - r_i)
void client_build_buckets(Client *cli, const mpz_t M);

// 向指定桶插入一个数据（根）
// bucket_idx : 桶编号
// r_in       : 插入数据（GMP整数）
void client_insert_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M);

// 插入整个数据集到桶中
void client_insert_dataset(Client *cli, const mpz_t M);

// 从指定桶删除一个数据（根）
// bucket_idx : 桶编号
// r_out      : 要删除的数据（GMP整数）
void client_delete_data(Client *cli, size_t bucket_idx, const mpz_t data, const mpz_t M);


// 生成桶打乱表（Fisher–Yates 洗牌，但不实际重排桶）
// 用于传输时重新映射桶索引
void client_generate_shuffle_table(Client *cli, unsigned long seed);

// 释放 Client 资源
void client_free(Client *cli);

// 打印摘要信息
void client_print_summary(const Client *cli);

#endif // CLIENT_H

