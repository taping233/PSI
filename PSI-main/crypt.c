#include "crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---------- Utility ----------
int crypto_random_bytes(unsigned char *buf, size_t len) {
    return RAND_bytes(buf, (int)len) == 1;
}

// ---------- RSA ----------

//创建RSA密钥
int rsa_generate_mem(RSAContext *ctx) {
    if (!ctx) return 0;
    ctx->rsa = NULL;
    ctx->pkey = NULL;

    BIGNUM *bn = BN_new();
    if (!bn) return 0;
    BN_set_word(bn, RSA_F4);

    ctx->rsa = RSA_new();
    if (!RSA_generate_key_ex(ctx->rsa, 2048, bn, NULL)) {
        BN_free(bn);
        return 0;
    }

    ctx->pkey = EVP_PKEY_new();
    if (!ctx->pkey || !EVP_PKEY_assign_RSA(ctx->pkey, ctx->rsa)) {
        RSA_free(ctx->rsa);
        BN_free(bn);
        return 0;
    }

    BN_free(bn);
    return 1;
}

// RSA释放密钥
void rsa_free_mem(RSAContext *ctx) {
    if (!ctx) return;
    if (ctx->pkey) EVP_PKEY_free(ctx->pkey);
    ctx->rsa = NULL;
    ctx->pkey = NULL;
}

// RSA 加密+解密 AES 密钥
int rsa_transfer_aes_key(RSAContext *A, AESContext *A_AES, const AESContext *B_AES) {

    if (!A) {
        fprintf(stderr, "❌ A 为 NULL\n");
        abort();
    }

    printf("🔍 RSAContext: %p, rsa=%p, pkey=%p\n", (void*)A, (void*)A->rsa, (void*)A->pkey);
    printf("RSAContext addr=%p, size=%zu\n", (void*) &A, sizeof(RSAContext));


    if (!A->rsa) {
        fprintf(stderr, "❌ RSAContext->rsa 为空\n");
        abort();
    }

    printf("🔍 RSA key size: %d bits\n", RSA_bits(A->rsa));

    unsigned char encrypted_key[256] = {0};
    int enc_len, dec_len;

    // Step 1: B 用 A 的公钥加密自己的 AES 密钥
    enc_len = RSA_public_encrypt(sizeof(B_AES->key), B_AES->key,
                                 encrypted_key, A->rsa, RSA_PKCS1_OAEP_PADDING);
    if (enc_len == -1) {
        fprintf(stderr, "RSA 公钥加密失败。\n");
        return 0;
    }

    // Step 2: A 用自己的私钥解密 AES 密钥
    dec_len = RSA_private_decrypt(enc_len, encrypted_key,
                                  A_AES->key, A->rsa, RSA_PKCS1_OAEP_PADDING);
    if (dec_len == -1) {
        fprintf(stderr, "RSA 私钥解密失败。\n");
        return 0;
    }

    // Step 3: 同步 IV（由 B 生成并共享）
    memcpy(A_AES->iv, B_AES->iv, sizeof(B_AES->iv));

    return 1;
}
// ---------- AES ----------

// 初始化AES密钥文件，不生成密钥。
int aes_init_mem(AESContext *ctx){
    memset(&ctx, 0, sizeof(ctx));
    return 1;
}

// 创建AES密钥文件
int aes_generate_mem(AESContext *ctx) {
    if (!ctx) return 0;
    if (!crypto_random_bytes(ctx->key, sizeof(ctx->key))) return 0;
    if (!crypto_random_bytes(ctx->iv, sizeof(ctx->iv))) return 0;
    return 1;
}

// ================= AES 加密 GMP 大整数 =================
int aes_encrypt_mpz_buf(const AESContext *ctx, const mpz_t input, unsigned char *out_buf, int out_buf_size, int *out_len){
    size_t bin_len = (mpz_sizeinbase(input, 2) + 7) / 8;
    unsigned char *bin = malloc(bin_len);
    if (!bin) return 0;

    mpz_export(bin, NULL, 1, 1, 0, 0, input);

    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (!cipher) { free(bin); return 0; }

    if (!EVP_EncryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }

    int len = 0, ciphertext_len = 0;

    if (!EVP_EncryptUpdate(cipher, out_buf, &len, bin, bin_len)) {
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(cipher, out_buf + len, &len)) {
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }
    ciphertext_len += len;

    if (ciphertext_len > out_buf_size) {
        fprintf(stderr, "❌ 缓冲区太小，至少需要 %d 字节\n", ciphertext_len);
        EVP_CIPHER_CTX_free(cipher);
        free(bin);
        return 0;
    }

    *out_len = ciphertext_len;

    EVP_CIPHER_CTX_free(cipher);
    free(bin);
    return 1;
}

// ================= AES 解密 GMP 大整数 =================

int aes_decrypt_mpz_buf(const AESContext *ctx, const unsigned char *in_buf, int in_len, mpz_t output){
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (!cipher) return 0;

    if (!EVP_DecryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, ctx->key, ctx->iv)) {
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }

    unsigned char *plaintext = malloc(in_len);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }

    int len = 0, plaintext_len = 0;
    if (!EVP_DecryptUpdate(cipher, plaintext, &len, in_buf, in_len)) {
        free(plaintext);
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(cipher, plaintext + len, &len)) {
        free(plaintext);
        EVP_CIPHER_CTX_free(cipher);
        return 0;
    }
    plaintext_len += len;

    mpz_import(output, plaintext_len, 1, 1, 0, 0, plaintext);

    free(plaintext);
    EVP_CIPHER_CTX_free(cipher);
    return 1;
}
