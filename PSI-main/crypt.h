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

// ================= 常量宏定义（统一管理，便于维护） =================
#define RSA_KEY_BITS       2048    // RSA密钥位数
#define RSA_ENC_BUF_SIZE   (RSA_KEY_BITS / 8)  // RSA加密输出缓冲区大小（2048位=256字节）
#define AES_KEY_SIZE       32      // AES-256密钥长度
#define AES_IV_SIZE        16      // AES-CBC IV长度
#define AES_CIPHER_TYPE    EVP_aes_256_cbc()   // AES加密算法类型
#define RSA_PADDING_MODE   RSA_PKCS1_OAEP_PADDING  // RSA填充模式

// ================= 上下文结构体（保持原有定义，补充注释） =================
/**
 * RSA上下文（内存版）
 * rsa: RSA密钥结构，由EVP_PKEY托管，释放时无需单独free
 * pkey: 通用EVP密钥封装，统一管理密钥生命周期
 */
typedef struct {
    RSA *rsa;              // RSA密钥结构（RSA_KEY_BITS位）
    EVP_PKEY *pkey;        // 通用EVP封装（自动管理RSA内存）
} RSAContext;

/**
 * AES上下文（内存版）
 * key: AES-256密钥（32字节）
 * iv: 初始化向量（16字节）
 */
typedef struct {
    unsigned char key[AES_KEY_SIZE]; // AES-256 key
    unsigned char iv[AES_IV_SIZE];   // 初始化向量
} AESContext;

// ================= 函数声明（按模块拆分，补充参数/返回值注释） =================

/**
 * 通用工具：生成加密安全的随机字节
 * @param buf 输出缓冲区
 * @param len 需要生成的字节数
 * @return 1=成功，0=失败
 */
int crypto_random_bytes(unsigned char *buf, size_t len);

// ---------- RSA 模块 ----------
/**
 * 创建RSA密钥（2048位）
 * @param ctx RSA上下文指针（必须非NULL）
 * @return 1=成功，0=失败
 */
int rsa_generate_mem(RSAContext *ctx);

/**
 * 释放RSA上下文资源
 * @param ctx RSA上下文指针（可为NULL，内部做判空）
 */
void rsa_free_mem(RSAContext *ctx);

/**
 * RSA传输AES密钥（B用A的公钥加密AES密钥，A用私钥解密）
 * @param A A的RSA上下文（含私钥）
 * @param A_AES A的AES上下文（存储解密后的密钥/IV）
 * @param B_AES B的AES上下文（提供待传输的密钥/IV）
 * @return 1=成功，0=失败
 */
int rsa_transfer_aes_key(RSAContext *A, AESContext *A_AES, const AESContext *B_AES);

// ---------- AES 模块 ----------
/**
 * 初始化AES上下文（清空密钥/IV）
 * @param ctx AES上下文指针（必须非NULL）
 * @return 1=成功，0=失败
 */
int aes_init_mem(AESContext *ctx);

/**
 * 生成AES-256随机密钥和IV
 * @param ctx AES上下文指针（必须非NULL）
 * @return 1=成功，0=失败
 */
int aes_generate_mem(AESContext *ctx);

/**
 * AES加密GMP大整数（AES-256-CBC）
 * @param ctx AES上下文（含密钥/IV）
 * @param input 待加密的GMP大整数
 * @param out_buf 输出加密数据的缓冲区
 * @param out_buf_size 输出缓冲区大小（字节）
 * @param out_len 实际输出的加密数据长度（输出参数）
 * @return 1=成功，0=失败
 */
int aes_encrypt_mpz_buf(const AESContext *ctx, const mpz_t input, 
                        unsigned char *out_buf, int out_buf_size, int *out_len);

/**
 * AES解密GMP大整数（AES-256-CBC）
 * @param ctx AES上下文（含密钥/IV）
 * @param in_buf 加密数据缓冲区
 * @param in_len 加密数据长度（字节）
 * @param output 解密后的GMP大整数（输出参数）
 * @return 1=成功，0=失败
 */
int aes_decrypt_mpz_buf(const AESContext *ctx, const unsigned char *in_buf, 
                        int in_len, mpz_t output);

#ifdef __cplusplus
}
#endif

#endif // CRYPT_H
