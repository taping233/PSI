#include "crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 调试宏（生产环境可注释）
#define CRYPT_DEBUG 1
#if CRYPT_DEBUG
#define LOG_DEBUG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt, ##__VA_ARGS__)
#endif

// ---------- Utility 模块 ----------
int crypto_random_bytes(unsigned char *buf, size_t len) {
    // 入参校验
    if (buf == NULL || len == 0) {
        LOG_ERROR("crypto_random_bytes: 无效参数（buf=NULL或len=0）\n");
        return 0;
    }

    if (RAND_bytes(buf, (int)len) != 1) {
        LOG_ERROR("crypto_random_bytes: 生成随机字节失败\n");
        return 0;
    }
    return 1;
}

// ---------- RSA 模块 ----------
int rsa_generate_mem(RSAContext *ctx) {
    // 入参校验
    if (ctx == NULL) {
        LOG_ERROR("rsa_generate_mem: ctx为NULL\n");
        return 0;
    }

    // 初始化上下文（避免野指针）
    ctx->rsa = NULL;
    ctx->pkey = NULL;

    BIGNUM *bn = BN_new();
    if (bn == NULL) {
        LOG_ERROR("rsa_generate_mem: BN_new失败\n");
        return 0;
    }

    // 设置公钥指数为RSA_F4（65537）
    if (!BN_set_word(bn, RSA_F4)) {
        LOG_ERROR("rsa_generate_mem: BN_set_word失败\n");
        BN_free(bn);
        return 0;
    }

    // 创建RSA结构体并生成密钥
    ctx->rsa = RSA_new();
    if (ctx->rsa == NULL || !RSA_generate_key_ex(ctx->rsa, RSA_KEY_BITS, bn, NULL)) {
        LOG_ERROR("rsa_generate_mem: RSA_generate_key_ex失败\n");
        BN_free(bn);
        RSA_free(ctx->rsa);
        ctx->rsa = NULL;
        return 0;
    }

    // 封装到EVP_PKEY
    ctx->pkey = EVP_PKEY_new();
    if (ctx->pkey == NULL || !EVP_PKEY_assign_RSA(ctx->pkey, ctx->rsa)) {
        LOG_ERROR("rsa_generate_mem: EVP_PKEY_assign_RSA失败\n");
        BN_free(bn);
        RSA_free(ctx->rsa);
        EVP_PKEY_free(ctx->pkey);
        ctx->rsa = NULL;
        ctx->pkey = NULL;
        return 0;
    }

    BN_free(bn);
    LOG_DEBUG("rsa_generate_mem: RSA密钥生成成功（%d位）\n", RSA_KEY_BITS);
    return 1;
}

void rsa_free_mem(RSAContext *ctx) {
    if (ctx == NULL) return;
    // EVP_PKEY_free会自动释放关联的RSA结构体，无需单独free ctx->rsa
    if (ctx->pkey != NULL) {
        EVP_PKEY_free(ctx->pkey);
        ctx->pkey = NULL;
    }
    ctx->rsa = NULL; // 置空避免野指针
}

int rsa_transfer_aes_key(RSAContext *A, AESContext *A_AES, const AESContext *B_AES) {
    // 全量入参校验（修复原代码未检查A_AES/B_AES的问题）
    if (A == NULL) {
        LOG_ERROR("rsa_transfer_aes_key: A(RSAContext)为NULL\n");
        return 0;
    }
    if (A_AES == NULL) {
        LOG_ERROR("rsa_transfer_aes_key: A_AES(AESContext)为NULL\n");
        return 0;
    }
    if (B_AES == NULL) {
        LOG_ERROR("rsa_transfer_aes_key: B_AES(AESContext)为NULL\n");
        return 0;
    }
    if (A->rsa == NULL) {
        LOG_ERROR("rsa_transfer_aes_key: A->rsa为空（未生成RSA密钥）\n");
        return 0;
    }

    // 修复原代码打印错误：打印A（结构体地址）而非& A（指针参数地址）
    LOG_DEBUG("RSAContext: %p, rsa=%p, pkey=%p\n", (void*)A, (void*)A->rsa, (void*)A->pkey);
    LOG_DEBUG("RSAContext size: %zu bytes\n", sizeof(RSAContext));
    LOG_DEBUG("RSA key size: %d bits\n", RSA_bits(A->rsa));

    // 使用宏定义替代硬编码（256字节=2048位RSA加密输出长度）
    unsigned char encrypted_key[RSA_ENC_BUF_SIZE] = {0};
    int enc_len, dec_len;

    // Step 1: B用A的公钥加密自己的AES密钥
    enc_len = RSA_public_encrypt(sizeof(B_AES->key), B_AES->key,
                                 encrypted_key, A->rsa, RSA_PADDING_MODE);
    if (enc_len == -1) {
        LOG_ERROR("rsa_transfer_aes_key: RSA公钥加密失败\n");
        return 0;
    }

    // Step 2: A用自己的私钥解密AES密钥
    dec_len = RSA_private_decrypt(enc_len, encrypted_key,
                                  A_AES->key, A->rsa, RSA_PADDING_MODE);
    if (dec_len == -1) {
        LOG_ERROR("rsa_transfer_aes_key: RSA私钥解密失败\n");
        return 0;
    }
    // 验证解密长度是否匹配AES密钥长度（避免解密错误）
    if (dec_len != sizeof(A_AES->key)) {
        LOG_ERROR("rsa_transfer_aes_key: 解密密钥长度错误（预期%d，实际%d）\n",
                  (int)sizeof(A_AES->key), dec_len);
        return 0;
    }

    // Step 3: 同步IV（由B生成并共享）
    memcpy(A_AES->iv, B_AES->iv, sizeof(B_AES->iv));

    LOG_DEBUG("rsa_transfer_aes_key: AES密钥传输成功\n");
    return 1;
}

// ---------- AES 模块 ----------
int aes_init_mem(AESContext *ctx) {
    // 修复原代码致命错误：memset(&ctx → memset(ctx)
    if (ctx == NULL) {
        LOG_ERROR("aes_init_mem: ctx为NULL\n");
        return 0;
    }
    // 清空AES上下文（密钥+IV）
    memset(ctx, 0, sizeof(AESContext));
    return 1;
}

int aes_generate_mem(AESContext *ctx) {
    if (ctx == NULL) {
        LOG_ERROR("aes_generate_mem: ctx为NULL\n");
        return 0;
    }

    // 生成随机密钥和IV
    if (!crypto_random_bytes(ctx->key, sizeof(ctx->key))) {
        LOG_ERROR("aes_generate_mem: 生成AES密钥失败\n");
        return 0;
    }
    if (!crypto_random_bytes(ctx->iv, sizeof(ctx->iv))) {
        LOG_ERROR("aes_generate_mem: 生成AES IV失败\n");
        return 0;
    }

    LOG_DEBUG("aes_generate_mem: AES密钥/IV生成成功\n");
    return 1;
}

int aes_encrypt_mpz_buf(const AESContext *ctx, const mpz_t input,
                        unsigned char *out_buf, int out_buf_size, int *out_len) {
    // 全量入参校验（修复原代码未校验的问题）
    if (ctx == NULL || input == NULL || out_buf == NULL || out_len == NULL) {
        LOG_ERROR("aes_encrypt_mpz_buf: 无效参数（NULL）\n");
        return 0;
    }
    if (out_buf_size <= 0) {
        LOG_ERROR("aes_encrypt_mpz_buf: 输出缓冲区大小无效（%d）\n", out_buf_size);
        return 0;
    }

    // 将GMP大整数转为二进制字节流
    size_t bin_len = (mpz_sizeinbase(input, 2) + 7) / 8;
    unsigned char *bin = malloc(bin_len);
    if (bin == NULL) {
        LOG_ERROR("aes_encrypt_mpz_buf: 分配二进制缓冲区失败（%zu字节）\n", bin_len);
        return 0;
    }
    mpz_export(bin, NULL, 1, 1, 0, 0, input);

    // 初始化EVP加密上下文
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (cipher == NULL) {
        LOG_ERROR("aes_encrypt_mpz_buf: EVP_CIPHER_CTX_new失败\n");
        free(bin);
        return 0;
    }

    // 初始化加密算法（AES-256-CBC）
    if (!EVP_EncryptInit_ex(cipher, AES_CIPHER_TYPE, NULL, ctx->key, ctx->iv)) {
        LOG_ERROR("aes_encrypt_mpz_buf: EVP_EncryptInit_ex失败\n");
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }

    // 执行加密
    int len = 0, ciphertext_len = 0;
    if (!EVP_EncryptUpdate(cipher, out_buf, &len, bin, bin_len)) {
        LOG_ERROR("aes_encrypt_mpz_buf: EVP_EncryptUpdate失败\n");
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }
    ciphertext_len = len;

    // 完成加密（处理填充）
    if (!EVP_EncryptFinal_ex(cipher, out_buf + len, &len)) {
        LOG_ERROR("aes_encrypt_mpz_buf: EVP_EncryptFinal_ex失败（填充错误？）\n");
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }
    ciphertext_len += len;

    // 检查缓冲区是否足够
    if (ciphertext_len > out_buf_size) {
        LOG_ERROR("aes_encrypt_mpz_buf: 输出缓冲区太小（需要%d，实际%d）\n",
                  ciphertext_len, out_buf_size);
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }

    // 输出实际加密长度
    *out_len = ciphertext_len;

    // 释放资源
    EVP_CIPHER_CTX_free(cipher);
    free(bin);

    LOG_DEBUG("aes_encrypt_mpz_buf: 加密成功（明文%zu字节，密文%d字节）\n", bin_len, ciphertext_len);
    return 1;
}

int aes_decrypt_mpz_buf(const AESContext *ctx, const unsigned char *in_buf,
                        int in_len, mpz_t output) {
    // 全量入参校验
    if (ctx == NULL || in_buf == NULL || output == NULL) {
        LOG_ERROR("aes_decrypt_mpz_buf: 无效参数（NULL）\n");
        return 0;
    }
    if (in_len <= 0) {
        LOG_ERROR("aes_decrypt_mpz_buf: 加密数据长度无效（%d）\n", in_len);
        return 0;
    }

    // 初始化EVP解密上下文
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (cipher == NULL) {
        LOG_ERROR("aes_decrypt_mpz_buf: EVP_CIPHER_CTX_new失败\n");
        return 0;
    }

    // 初始化解密算法（AES-256-CBC）
    if (!EVP_DecryptInit_ex(cipher, AES_CIPHER_TYPE, NULL, ctx->key, ctx->iv)) {
        LOG_ERROR("aes_decrypt_mpz_buf: EVP_DecryptInit_ex失败\n");
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }

    // 分配明文缓冲区（最大长度=密文长度）
    unsigned char *plaintext = malloc(in_len);
    if (plaintext == NULL) {
        LOG_ERROR("aes_decrypt_mpz_buf: 分配明文缓冲区失败（%d字节）\n", in_len);
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }

    // 执行解密
    int len = 0, plaintext_len = 0;
    if (!EVP_DecryptUpdate(cipher, plaintext, &len, in_buf, in_len)) {
        LOG_ERROR("aes_decrypt_mpz_buf: EVP_DecryptUpdate失败\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }
    plaintext_len = len;

    // 完成解密（处理填充）
    if (!EVP_DecryptFinal_ex(cipher, plaintext + len, &len)) {
        LOG_ERROR("aes_decrypt_mpz_buf: EVP_DecryptFinal_ex失败（密钥/IV错误？填充错误？）\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }
    plaintext_len += len;

    // 将二进制字节流转为GMP大整数
    mpz_import(output, plaintext_len, 1, 1, 0, 0, plaintext);

    // 释放资源
    free(plaintext);
    EVP_CIPHER_CTX_free(cipher);

    LOG_DEBUG("aes_decrypt_mpz_buf: 解密成功（密文%d字节，明文%d字节）\n", in_len, plaintext_len);
    return 1;
}
