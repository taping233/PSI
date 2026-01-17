#ifndef PSI_CLOUD_H
#define PSI_CLOUD_H

#include <gmp.h>
#include <stddef.h>
#include "crypt.h"
#include "bucket.h"

// ==========================
// PSI 云平台用户条目结构
// ==========================
typedef struct {
    mpz_t user_id;               // 用户唯一标识
    unsigned int k;              // 桶数量
    unsigned int m_bit;          // 桶内位宽

    // --- 用户对应桶 ---
    BucketSet H_P;               // 用户数据桶（隐私多项式）
    BucketSet H_W;               // 用户随机掩码桶
    BucketSet H_Beaver_a;        // 用户 Beaver 三元组桶 a_1(x)
    BucketSet H_Beaver_b;        // 用户 Beaver 三元组桶 b_1(x)
    Result_BucketSet H_Beaver_c;        // 用户 Beaver 三元组桶 c_1(x)
    
    // --- 用户结果存放桶 ---
    Result_BucketSet PSI_result; // 用于存放云平台计算完后的结果
    
} PSIUserEntry;

// ==========================
// PSI 云平台主结构
// ==========================
typedef struct {
    RSAContext *rsa_ctx;          // 云平台 RSA 密钥
    AESContext aes_internal;     // 云平台 AES 密钥（用于内部通信）

    PSIUserEntry *users;         // 用户数组
    size_t user_count;           // 已注册用户数量
} PSICloud;

// ==========================
// 函数接口声明
// ==========================
void psi_cloud_init(PSICloud *cloud, size_t user_count, unsigned int k, unsigned int m_bit, unsigned long seed);
void psi_cloud_alloc_user(PSIUserEntry *entry, unsigned int k, unsigned int m_bit, unsigned long seed);
void psi_cloud_print_status(const PSICloud *cloud);
void psi_cloud_free(PSICloud *cloud);

#endif // PSI_CLOUD_H

