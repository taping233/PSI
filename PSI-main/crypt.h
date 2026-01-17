#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

// 内存中的 RSA 上下文
typedef struct {
    RSA *rsa;              // RSA 密钥结构（2048位）
    EVP_PKEY *pkey;        // 通用 EVP 封装
} RSAContext;

// 内存中的 AES 上下文
typedef struct {
    unsigned char key[32]; // AES-256 key
    unsigned char iv[16];  // 初始化向量
} AESContext;

// ---------- RSA ----------
//创建RSA密钥
int rsa_generate_mem(RSAContext *ctx);

// 释放RSA密钥
void rsa_free_mem(RSAContext *ctx);

// RSA 加密+解密 发送 AES 密钥
int rsa_transfer_aes_key(RSAContext *A, AESContext *A_AES, const AESContext *B_AES);

// ---------- AES ----------

// AES初始化密钥
int aes_init_mem(AESContext *ctx);

// AES生成密钥
int aes_generate_mem(AESContext *ctx);

// 使用示例：unsigned char enc_buf[4096];
//          int enc_len = 0;
//          aes_encrypt_mpz_buf(&ctx, input, enc_buf, sizeof(enc_buf), &enc_len)
// AES加密大整数
int aes_encrypt_mpz_buf(const AESContext *ctx, const mpz_t input, unsigned char *out_buf, int out_buf_size, int *out_len);


// 使用示例：unsigned char enc_buf[4096];
//          int enc_len = 0;
//          aes_decrypt_mpz_buf(&ctx, enc_buf, enc_len, output)
// AES解密大整数
int aes_decrypt_mpz_buf(const AESContext *ctx, const unsigned char *in_buf, int in_len, mpz_t output);



// ---------- Utility ----------
int crypto_random_bytes(unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // CRYPT_H

