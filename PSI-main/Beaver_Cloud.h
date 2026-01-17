#ifndef BEAVER_CLOUD_H
#define BEAVER_CLOUD_H

#include "bucket.h"
#include "crypt.h"   // 新增加密模块引用

typedef struct {
    BucketSet beaver_A;
    BucketSet beaver_B;
    Result_BucketSet beaver_C;
} BeaverTripletSet;

typedef struct {
    
    BeaverTripletSet original;  // 原始 Beaver 三元组
    RSAContext *rsa_ctx;         // 云平台 RSA 密钥上下文
    AESContext aes_ctx;         // 云平台 AES 会话密钥上下文

    unsigned int m_bit;         // 模长
} BeaverCloud;

// 初始化云平台（生成 Beaver 三元组 + RSA 密钥）
void beaver_cloud_init(BeaverCloud *cloud, unsigned int m_bit, unsigned long seed, size_t n);

// 打印云平台信息（包括密钥状态）
void beaver_cloud_print(const BeaverCloud *cloud);

// 设置 AES 密钥（由外部传入）
void beaver_cloud_set_aes(BeaverCloud *cloud, const unsigned char *key, const unsigned char *iv);
                          
// 生成 Beaver 三元组（降幂多项式形式）
// 包含原始生成 + 用户 / PSI 拆分
void beaver_cloud_generate_triplets(BeaverCloud *cloud, unsigned long seed, const mpz_t M, size_t n);

// 释放云平台资源
void beaver_cloud_free(BeaverCloud *cloud);

#endif // BEAVER_CLOUD_H

