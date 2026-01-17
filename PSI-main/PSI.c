#include "PSI.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


// 生成计时点

clock_t  t_begin, t_end;

// 示例 
// t_begin = clock();
// t_end = clock();
// printf("单个用户初始化耗时：%.3f 秒\n", (double)(t_end - t_begin)/CLOCKS_PER_SEC);

// ===========================
// 阶段 1：AES 会话密钥同步
// ===========================
//
// 云平台统一分发 (AES key + IV)，
// 各方用自己的 RSA 私钥解密后保存。
// 这样可以保证各方之间 AES 加解密完全互通。
//
// 调用示例
// Client *client_list[MAX_CLIENTS] = {clientA, clientB, clientC};
// psi_sync_all_clients(cloud, client_list, 3, verify, beaver);

void psi_sync_all_clients(PSICloud *cloud, Client *clients[], size_t client_count, Verify *verify, BeaverCloud *beaver)
{
    if (!cloud) {
        fprintf(stderr, "[PSI] 无效的云平台结构。\n");
        return;
    }

    printf("[PSI] 阶段 1：AES 会话密钥同步开始。\n");

    int client_num = client_count;   // 记录用户数量

    // =====================================================
    // 1️⃣ 分发给 Client
    // =====================================================
    
    // 多线程优化
    #pragma omp parallel for
    for (size_t i = 0; i < client_num; i++){
        if (clients[i]) {           
            // RSA 加密+解密 发送 AES 密钥
            rsa_transfer_aes_key(clients[i]->rsa_ctx, &clients[i]->aes_psi, &cloud->aes_internal);
            printf("[PSI] AES 会话密钥同步给 Client %d 成功。\n", i);
        }
    }
    
    // =====================================================
    // 2️⃣ 分发给 Verify
    // =====================================================
    if (verify) {    
        // RSA 加密+解密 发送 AES 密钥
        rsa_transfer_aes_key(verify->rsa_ctx, &verify->aes_psi, &cloud->aes_internal);
        printf("[PSI] AES 会话密钥同步给 Verify 成功。\n");
    }

    // =====================================================
    // 3️⃣ 分发给 BeaverCloud
    // =====================================================
    if (beaver) {
        rsa_transfer_aes_key(beaver->rsa_ctx, &beaver->aes_ctx, &cloud->aes_internal);
        printf("[PSI] AES 会话密钥同步给 BeaverCloud 成功。\n");

    }

    // printf("[PSI] 阶段 1：AES 会话密钥同步完成。\n");
}



// ===============================
// 用户上传桶 
// ===============================
void Clients_send_encrypted_buckets(Client *clients[], int client_count, PSICloud *cloud, mpz_t M)
{

    if (!clients || !cloud) {
        fprintf(stderr, "[PSI] 参数错误。\n");
        return;
    }

    // 计算单个数据的字节数
    size_t bit_size = mpz_sizeinbase(M, 2);
    size_t coeff_bytes = (bit_size + 7) / 8;

    // 计算每个组里能包含多少个数据
    size_t group_size = MAX(1, 16 / coeff_bytes); 
    if (group_size < 1) group_size = 1;

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    //中间参数
    // mpz_t temp_p0, temp_p1, temp_w0, temp_w1;
    // mpz_inits(temp_p0, temp_p1, temp_w0, temp_w1, NULL);

    printf("[PSI] 用户开始发送桶...\n");

    for (size_t t = 0; t < client_count; t++){
        // 多线程并行
        #pragma omp parallel for
        for (size_t i = 0; i < clients[t]->k; ++i) {
            size_t shuffled_idx = clients[t]->shuffle_table[i];
            Bucket *srcP = &clients[t]->H_P.buckets[i];
            Bucket *srcW = &clients[t]->H_W.buckets[i];
            Bucket *dstP = &cloud->users[clients[t]->user_id].H_P.buckets[shuffled_idx];
            Bucket *dstW = &cloud->users[clients[t]->user_id].H_W.buckets[shuffled_idx];
            
            // 临时存放中间变量的数据桶
            mpz_t temp_0[BUCKET_POLY_LEN];
            mpz_t temp_1[BUCKET_POLY_LEN];

            // 初始化中间变量数据桶
            for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
                mpz_init(temp_0[j]);
                mpz_init(temp_1[j]);
            }

            // -----------------------
            // 按打乱表将数据P桶传输到云平台
            // -----------------------

            // 将数据P桶拆为两份
            for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
                
                // 为P0先赋一个随机值
                mpz_urandomb(temp_0[j], state, clients[t]->m_bit);
                
                // 让P0 mod M
                mpz_mod(temp_0[j], temp_0[j], M);

                // 计算P1
                mpz_sub(temp_1[j], srcP->coeffs[j], temp_0[j]);

                // 让P1 mod M 
                mpz_mod(temp_1[j], temp_1[j], M);

                // 将P0 赋值给用户数据桶
                mpz_set(srcP->coeffs[j], temp_0[j]);
            }

            // 多线程操作
            // #pragma omp parallel for
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {

                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, temp_1[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将P桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(dstP->coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(dstP->coeffs[j + g], dstP->coeffs[j + g], M);
                    offset += coeff_bytes;
                }

                mpz_clears(mpz_pack, mpz_unpack, NULL);

            }

            // -----------------------
            // 按打乱表将数据W桶传输到云平台
            // -----------------------

            // 将数据W桶拆为两份
            for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
                
                // 为P0先赋一个随机值
                mpz_urandomb(temp_0[j], state, clients[t]->m_bit);
                
                // 让P0 mod M
                mpz_mod(temp_0[j], temp_0[j], M);

                // 计算P1
                mpz_sub(temp_1[j], srcW->coeffs[j], temp_0[j]);

                // 让P1 mod M 
                mpz_mod(temp_1[j], temp_1[j], M);

                // 将P0 赋值给用户数据桶
                mpz_set(srcW->coeffs[j], temp_0[j]);
            }


            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {

                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;
                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, temp_1[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);

            
                //将W桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(dstW->coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(dstW->coeffs[j + g], dstW->coeffs[j + g], M);
                    offset += coeff_bytes;
                }

            }

            // 释放中间变量数组
            for (size_t j = 0; j < BUCKET_POLY_LEN; j++) {
                mpz_clear(temp_0[j]);
                mpz_clear(temp_1[j]);
            }

            // 将P桶的标识传输（顺序已经打乱）
            unsigned char enc_buf_tag[4096];
            int enc_len_tag = 0;
            aes_encrypt_mpz_buf(&clients[t]->aes_psi, srcP->tag, enc_buf_tag, sizeof(enc_buf_tag), &enc_len_tag);
            aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf_tag, enc_len_tag, dstP->tag);

        }
    }

    gmp_randclear(state);
    printf("[PSI] 用户桶发送完成（已打乱并存入云平台）。\n");
}

// ===========================================
// 验证方上传桶
// ===========================================
void psi_send_encrypted_buckets_verify(Verify *verify, PSICloud *cloud, mpz_t M)
{
    if (!verify || !cloud) {
        fprintf(stderr, "[PSI] 参数错误。\n");
        return;
    }
    
    // 计算单个数据的字节数
    size_t bit_size = mpz_sizeinbase(M, 2);
    size_t coeff_bytes = (bit_size + 7) / 8;

    // 计算每个组里能包含多少个数据
    size_t group_size = MAX(1, 16 / coeff_bytes); 
    if (group_size < 1) group_size = 1;

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));
    
    // 临时存放中间变量的数据桶
    mpz_t temp_0[BUCKET_POLY_LEN];
    mpz_t temp_1[BUCKET_POLY_LEN];

    // 初始化中间变量数据桶
    for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
        mpz_init(temp_0[j]);
        mpz_init(temp_1[j]);
    }

    printf("[PSI] 验证方开始发送桶...\n");

    // 多线程并行
    #pragma omp parallel for
    for (size_t i = 0; i < verify->k; ++i) {
        size_t shuffled_idx = verify->shuffle_table[i];
        Bucket *srcP = &verify->H_P.buckets[i];
        Bucket *srcW = &verify->H_W.buckets[i];
        Bucket *dstP = &cloud->users[0].H_P.buckets[shuffled_idx];  // 验证方存到 cloud->users[0]
        Bucket *dstW = &cloud->users[0].H_W.buckets[shuffled_idx];

        // 将数据P桶拆为两份
        for (size_t j = 0; j < BUCKET_POLY_LEN; j++){
                
            // 为P0先赋一个随机值
            mpz_urandomb(temp_0[j], state, verify->m_bit);
                
            // 让P0 mod M
            mpz_mod(temp_0[j], temp_0[j], M);

            // 计算P1
            mpz_sub(temp_1[j], srcP->coeffs[j], temp_0[j]);

            // 让P1 mod M 
            mpz_mod(temp_1[j], temp_1[j], M);

            // 将P0 赋值给用户数据桶
            mpz_set(srcP->coeffs[j], temp_0[j]);
        }
        
        // -----------------------
        // 按打乱表传输P桶到云平台
        // -----------------------
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {

                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, temp_1[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将P桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(dstP->coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(dstP->coeffs[j + g], dstP->coeffs[j + g], M);
                    offset += coeff_bytes;
                }
                
                mpz_clears(mpz_pack, mpz_unpack, NULL);
        }

        // -----------------------
        // 按打乱表将数据W桶传输到云平台
        // -----------------------

        // 将数据W桶拆为两份
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size){
                
            // 为W0先赋一个随机值
            mpz_urandomb(temp_0[j], state, verify->m_bit);
                
            // 让W0 mod M
            mpz_mod(temp_0[j], temp_0[j], M);

            // 计算W1
            mpz_sub(temp_1[j], srcW->coeffs[j], temp_0[j]);

            // 让W1 mod M 
            mpz_mod(temp_1[j], temp_1[j], M);

            // 将W0 赋值给用户数据桶
            mpz_set(srcW->coeffs[j], temp_0[j]);
        }


        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {

            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;
            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, temp_1[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);

            
            //将W桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(dstW->coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(dstW->coeffs[j + g], dstW->coeffs[j + g], M);
                offset += coeff_bytes;
            }

        }

        // 将P桶的标识传输（顺序已经打乱）
        unsigned char enc_buf_tag[4096];
        int enc_len_tag = 0;

        aes_encrypt_mpz_buf(&verify->aes_psi, srcP->tag, enc_buf_tag, sizeof(enc_buf_tag), &enc_len_tag);
        aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf_tag, enc_len_tag, dstP->tag);
    }

    
    gmp_randclear(state);
    printf("[PSI] 验证方桶发送完成（已打乱并写入云平台）。\n");
}



// ===========================================================
//   BeaverCloud → 分发三元组给 用户/验证方 与 PSI 云平台
//   （带 AES 加密解密模拟 + 桶顺序打乱）不并行
// ===========================================================
void beaver_cloud_distribute_to_client(BeaverCloud *cloud, Client *clients[], size_t client_count, PSICloud *psi_cloud, Verify *verify, const mpz_t M){

    printf("[BeaverCloud] 开始向用户/验证方与 PSI 云平台分发 Beaver 三元组...\n");

    // 计算单个数据的字节数
    size_t bit_size = mpz_sizeinbase(M, 2);
    size_t coeff_bytes = (bit_size + 7) / 8;

    // 计算每个组里能包含多少个数据
    size_t group_size = MAX(1, 16 / coeff_bytes); 
    if (group_size < 1) group_size = 1;

    //临时参数
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    size_t k = cloud->original.beaver_A.count;

    // 注意：PSI Cloud 的 Beaver 桶已在 psi_cloud_init 中初始化，无需重复初始化

    // --- 临时随机拆分 ---
    BucketSet A0_set, B0_set, A1_set, B1_set;
    Result_BucketSet C0_set, C1_set;
    bucket_init(&A0_set, verify->k, cloud->m_bit);
    bucket_init(&B0_set, verify->k, cloud->m_bit);
    bucket_init(&A1_set, verify->k, cloud->m_bit);
    bucket_init(&B1_set, verify->k, cloud->m_bit);
    result_bucket_init(&C0_set, verify->k);
    result_bucket_init(&C1_set, verify->k);
    
    // 使用第一个桶作为临时存储
    Bucket *A0 = &A0_set.buckets[0];
    Bucket *B0 = &B0_set.buckets[0];
    Bucket *A1 = &A1_set.buckets[0];
    Bucket *B1 = &B1_set.buckets[0];
    Result_Bucket *C0 = &C0_set.result_buckets[0];
    Result_Bucket *C1 = &C1_set.result_buckets[0];
    
    //遍历所有用户进行多项式三元组的分发
    for (size_t t = 0; t < client_count; t++){
        
        // Beaver云平台生成多项式Beaver三元组
        beaver_cloud_generate_triplets(cloud, 127, M, clients[t]->k);
        // 遍历每个桶生成并分发
        for (size_t i = 0; i < k; ++i) {
            Bucket *A = &cloud->original.beaver_A.buckets[i];
            Bucket *B = &cloud->original.beaver_B.buckets[i];
            Result_Bucket *C = &cloud->original.beaver_C.result_buckets[i];


            // 生成A0，A1，B0，B1
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_urandomb(A1->coeffs[j], state, cloud->m_bit);
                mpz_urandomb(B1->coeffs[j], state, cloud->m_bit);
                mpz_sub(A0->coeffs[j], A->coeffs[j], A1->coeffs[j]);
                mpz_sub(B0->coeffs[j], B->coeffs[j], B1->coeffs[j]);
            }
            
            // 生成C0，C1
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_urandomb(C1->coeffs[j], state, cloud->m_bit);
                mpz_sub(C0->coeffs[j], C->coeffs[j], C1->coeffs[j]);
            }
            
            // 用户拿到属于自己的多项式三元组中的A0
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size){
                
                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, A0->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //加密并传输A0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(clients[t]->H_Beaver_a.buckets[i].coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(clients[t]->H_Beaver_a.buckets[i].coeffs[j + g], clients[t]->H_Beaver_a.buckets[i].coeffs[j + g], M);
                    offset += coeff_bytes;
                }
                
            }

            // 用户拿到属于自己的多项式三元组中的B0
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size){
                
                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;


                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, B0->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //加密并传输B0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(clients[t]->H_Beaver_b.buckets[i].coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(clients[t]->H_Beaver_b.buckets[i].coeffs[j+g], clients[t]->H_Beaver_b.buckets[i].coeffs[j + g], M);
                    offset += coeff_bytes;
                }
                
            }
            
            // 用户拿到属于自己的C0
            for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, C0->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //Beaver云平台侧加密待传输的 C0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                //用户侧解密并存储 C0
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(clients[t]->H_Beaver_c.result_buckets[i].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(clients[t]->H_Beaver_b.buckets[i].coeffs[j+g], clients[t]->H_Beaver_c.result_buckets[i].coeffs[j+g], M);
                    offset += coeff_bytes;
                }
            }
            
            // --- 根据用户打乱表存入桶 ---
            size_t user_idx = clients[t]->shuffle_table[i];

            // PSI 云端拿到自己的A1
            for (size_t j = 0; j < BUCKET_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, A1->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //加密并传输A1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[user_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[user_idx].coeffs[j+g], psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[user_idx].coeffs[j+g], M);
                    offset += coeff_bytes;
                }

            }

            // PSI 云端拿到自己的B1
            for (size_t j = 0; j < BUCKET_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, B1->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //加密并传输A1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[user_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[user_idx].coeffs[j+g], psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[user_idx].coeffs[j+g], M);
                    offset += coeff_bytes;
                }

            }

            // PSI云平台侧拿到自己的C1
            for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){
                
                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, C1->coeffs[j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //加密并传输A1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; g++) {
                    mpz_import(psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[user_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[user_idx].coeffs[j+g], psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[user_idx].coeffs[j+g], M);
                    offset += coeff_bytes;
                }
            }
        }

    }
    printf("[BeaverCloud] 三元组分发完成（用户 + PSI 云平台）。\n");

    // 验证方拿到自己的Beaver多项式三元组
    // Beaver云平台生成多项式三元组
    beaver_cloud_generate_triplets(cloud, 125, M, verify->k);

    // 遍历每个桶生成并分发
    for (size_t i = 0; i < k; ++i) {
        Bucket *A = &cloud->original.beaver_A.buckets[i];
        Bucket *B = &cloud->original.beaver_B.buckets[i];
        Result_Bucket *C = &cloud->original.beaver_C.result_buckets[i];

        // 生成待传输的A0，A1, B0，B1
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_urandomb(A1->coeffs[j], state, cloud->m_bit);
            mpz_urandomb(B1->coeffs[j], state, cloud->m_bit);
            mpz_sub(A0->coeffs[j], A->coeffs[j], A1->coeffs[j]);
            mpz_sub(B0->coeffs[j], B->coeffs[j], B1->coeffs[j]);
        }

        // 生成待传输的C0，C1
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_urandomb(C1->coeffs[j], state, cloud->m_bit);
            mpz_sub(C0->coeffs[j], C->coeffs[j], C1->coeffs[j]);
        }
            
        // 验证方拿到属于自己的A0
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size){
                
            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, A0->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //加密并传输A0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(verify->H_Beaver_a.buckets[i].coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(verify->H_Beaver_a.buckets[i].coeffs[j + g], verify->H_Beaver_a.buckets[i].coeffs[j + g], M);
                offset += coeff_bytes;
            }
        }


        // 验证方拿到属于自己的B0
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size){
                
            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, B0->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //加密并传输B0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(verify->H_Beaver_b.buckets[i].coeffs[j + g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(verify->H_Beaver_b.buckets[i].coeffs[j + g], verify->H_Beaver_b.buckets[i].coeffs[j + g], M);
                offset += coeff_bytes;
            }
        }

        // 验证方拿到自己的C0
        for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){

            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, C0->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //Beaver云平台侧加密待传输的 C0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            //用户侧解密并存储 C0
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(verify->H_Beaver_c.result_buckets[i].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(verify->H_Beaver_b.buckets[i].coeffs[j+g], verify->H_Beaver_c.result_buckets[i].coeffs[j+g], M);
                offset += coeff_bytes;
            }
        }

        
            
        // --- 根据验证方打乱表存入桶 ---
        size_t verify_idx = verify->shuffle_table[i];

        // PSI 云端拿到自己的A1
        for (size_t j = 0; j < BUCKET_POLY_LEN; j += group_size){

            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, A1->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //加密并传输A1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(psi_cloud->users[clients[0]->user_id].H_Beaver_a.buckets[verify_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(psi_cloud->users[clients[0]->user_id].H_Beaver_a.buckets[verify_idx].coeffs[j+g], psi_cloud->users[clients[0]->user_id].H_Beaver_a.buckets[verify_idx].coeffs[j+g], M);
                offset += coeff_bytes;
            }
        }

        // PSI 云端拿到自己的B1
        for (size_t j = 0; j < BUCKET_POLY_LEN; j += group_size){

            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, B1->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //加密并传输A1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(psi_cloud->users[clients[0]->user_id].H_Beaver_b.buckets[verify_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(psi_cloud->users[clients[0]->user_id].H_Beaver_b.buckets[verify_idx].coeffs[j+g], psi_cloud->users[clients[0]->user_id].H_Beaver_b.buckets[verify_idx].coeffs[j+g], M);
                offset += coeff_bytes;
            }
        }

        // PSI云平台侧拿到自己的C1
        for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){
                
            // 初始化加密相关中间态
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, C1->coeffs[j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            //加密并传输A1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; g++) {
                mpz_import(psi_cloud->users[clients[0]->user_id].H_Beaver_c.result_buckets[verify_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(psi_cloud->users[clients[0]->user_id].H_Beaver_c.result_buckets[verify_idx].coeffs[j+g], psi_cloud->users[clients[0]->user_id].H_Beaver_c.result_buckets[verify_idx].coeffs[j+g], M);
                offset += coeff_bytes;
            }
        }
    }

    printf("[BeaverCloud] 三元组分发完成（验证方 + PSI 云平台）。\n");
    
    bucket_free(&A0_set);
    bucket_free(&B0_set);
    bucket_free(&A1_set);
    bucket_free(&B1_set);
    result_bucket_free(&C0_set);
    result_bucket_free(&C1_set);

    gmp_randclear(state);
    
}


// ===========================================================
//   FFT方法计算多个小模数下的多项式乘法 （已并行）
// ===========================================================
void poly_modular_fft_compute(mpz_t *result, const mpz_t *polyA, const mpz_t *polyB, size_t lenA, size_t lenB, const ModSystem *mods, int op_type)
{
    size_t L = (op_type == 2) ? (lenA + lenB - 1) : lenA;
    size_t nmods = mods->m_count;

    mpz_t *remainders = malloc(sizeof(mpz_t) * nmods);
    mpz_t *moduli     = malloc(sizeof(mpz_t) * nmods);
    for (size_t i = 0; i < nmods; ++i) {
        mpz_init(remainders[i]);
        mpz_init_set(moduli[i], mods->m_list[i]);
    }

    // 临时数组存储每个小模数的结果
    mpz_t **partial_results = malloc(sizeof(mpz_t*) * nmods);
    for (size_t i = 0; i < nmods; ++i) {
        partial_results[i] = malloc(sizeof(mpz_t) * L);
        for (size_t j = 0; j < L; ++j)
            mpz_init(partial_results[i][j]);
    }

    // 逐小模数计算
    #pragma omp parallel for
    for (size_t idx = 0; idx < nmods; ++idx) {
        unsigned long m = mpz_get_ui(mods->m_list[idx]);

        // 转为 double 形式
        long double *A = calloc(lenA, sizeof(long double));
        long double *B = calloc(lenB, sizeof(long double));
        long double *Res = calloc(L, sizeof(long double));

        for (size_t j = 0; j < lenA; ++j)
            A[j] = fmodl((long double)mpz_fdiv_ui(polyA[j], m), (long double)m);
        for (size_t j = 0; j < lenB; ++j)
            B[j] = fmodl((long double)mpz_fdiv_ui(polyB[j], m), (long double)m);

        // 运算
        if (op_type == 0) {
            for (size_t j = 0; j < lenA; ++j)
                Res[j] = fmodl(A[j] + B[j], m);
        } else if (op_type == 1) {
            for (size_t j = 0; j < lenA; ++j)
                Res[j] = fmodl(A[j] - B[j] + m, m);
        } else if (op_type == 2) {
            poly_multiply_scaled(A, lenA, B, lenB, (long double)m, Res);
            for (size_t j = 0; j < L; ++j)
                Res[j] = fmodl(Res[j], m);
        }

        // 转回 GMP
        for (size_t j = 0; j < L; ++j)
            mpz_set_ui(partial_results[idx][j], (unsigned long)Res[j]);

        free(A); free(B); free(Res);
    }

    // 合并每个系数（CRT）
    for (size_t j = 0; j < L; ++j) {
        for (size_t i = 0; i < nmods; ++i)
            mpz_set(remainders[i], partial_results[i][j]);

        crt_combine(result[j], mods->M, remainders, moduli, nmods);
    }

    // 清理内存
    for (size_t i = 0; i < nmods; ++i) {
        for (size_t j = 0; j < L; ++j)
            mpz_clear(partial_results[i][j]);
        free(partial_results[i]);
        mpz_clear(remainders[i]);
        mpz_clear(moduli[i]);
    }
    free(partial_results);
    free(remainders);
    free(moduli);
}



// ===========================================================
//   计算多项式Beaver三元组结果
// ===========================================================
void beaver_compute_multiplication(Client *clients[], int client_count, PSICloud *psi_cloud, Verify *verify, const ModSystem *mods){

    //获得表长
    size_t k = clients[0]->k;
    
    //初始化逆打乱表
    size_t *inv_shuffle = malloc(sizeof(size_t) * k);

    // 计算单个数据的字节数
    size_t bit_size = mpz_sizeinbase(mods->M, 2);
    size_t coeff_bytes = (bit_size + 7) / 8;

    // 计算每个组里能包含多少个数据
    size_t group_size = MAX(1, 16 / coeff_bytes); 
    if (group_size < 1) group_size = 1;

    printf("[Beaver] 开始计算 Beaver 乘法阶段...\n");

    //遍历每个用户
    for (size_t t = 0; t < client_count; t++){
        // 初始化结果桶
        result_bucket_init(&clients[t]->PSI_result, k);
        result_bucket_init(&psi_cloud->users[clients[t]->user_id].PSI_result, k);

         // ---------- Step 0: 构造逆打乱表 ----------
        for (size_t i = 0; i < k; ++i)
            inv_shuffle[clients[t]->shuffle_table[i]] = i;
        
        // ---------- Step 1: 用户计算 d0(x), e0(x) ----------
        mpz_t **d0 = malloc(sizeof(mpz_t*) * k);
        mpz_t **e0 = malloc(sizeof(mpz_t*) * k);

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t i = 0; i < k; ++i) {
            d0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(d0[i][j]);
                mpz_init(e0[i][j]);
                mpz_sub(d0[i][j], clients[t]->H_P.buckets[i].coeffs[j], clients[t]->H_Beaver_a.buckets[i].coeffs[j]);
                mpz_sub(e0[i][j], clients[t]->H_W.buckets[i].coeffs[j], clients[t]->H_Beaver_b.buckets[i].coeffs[j]);
                mpz_mod(d0[i][j], d0[i][j], mods->M);
                mpz_mod(e0[i][j], e0[i][j], mods->M);
            }
        }

        // ---------- Step 2: 打乱并“发送” d0,e0 到云端 ----------
        mpz_t **recv_d0 = malloc(sizeof(mpz_t*) * k);
        mpz_t **recv_e0 = malloc(sizeof(mpz_t*) * k);

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t i = 0; i < k; ++i) {
            size_t s = clients[t]->shuffle_table[i];
            recv_d0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            recv_e0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            // 初始化接收桶
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(recv_d0[s][j]);
                mpz_init(recv_e0[s][j]);
            }

            // 将d0传输到接收桶中
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, d0[i][j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将d0桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(recv_d0[s][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(recv_d0[s][j+g], recv_d0[s][j+g], mods->M);
                    offset += coeff_bytes;
                }
                
                mpz_clears(mpz_pack, mpz_unpack, NULL);
            }

            // 将e0传输到接收桶中
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, e0[i][j + g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将e0桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(recv_e0[s][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(recv_e0[s][j+g], recv_e0[s][j+g], mods->M);
                    offset += coeff_bytes;
                }
                
                mpz_clears(mpz_pack, mpz_unpack, NULL);
            }
        }

        // ---------- Step 3: 云端计算 d(x), e(x) ----------
        mpz_t **d_cloud = malloc(sizeof(mpz_t*) * k);
        mpz_t **e_cloud = malloc(sizeof(mpz_t*) * k);

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t s = 0; s < k; ++s) {
            Bucket *P1 = &psi_cloud->users[clients[t]->user_id].H_P.buckets[s];
            Bucket *W1 = &psi_cloud->users[clients[t]->user_id].H_W.buckets[s];
            Bucket *a1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[s];
            Bucket *b1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[s];

            d_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);

            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(d_cloud[s][j]);
                mpz_init(e_cloud[s][j]);
                mpz_sub(d_cloud[s][j], P1->coeffs[j], a1->coeffs[j]); // d1
                mpz_sub(e_cloud[s][j], W1->coeffs[j], b1->coeffs[j]); // e1
                mpz_add(d_cloud[s][j], d_cloud[s][j], recv_d0[s][j]); // + d0’
                mpz_add(e_cloud[s][j], e_cloud[s][j], recv_e0[s][j]); // + e0’
                mpz_mod(d_cloud[s][j], d_cloud[s][j], mods->M);
                mpz_mod(e_cloud[s][j], e_cloud[s][j], mods->M);
            }
        }

        
        // ---------- Step 4: 用户端逆打乱恢复 d,e ----------
        mpz_t **d_user = malloc(sizeof(mpz_t*) * k);
        mpz_t **e_user = malloc(sizeof(mpz_t*) * k);

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t i = 0; i < k; ++i) {
            size_t s = clients[t]->shuffle_table[i];
            d_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            // 初始化接收桶
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(d_user[i][j]);
                mpz_init(e_user[i][j]);
            }

            // 将d传输到用户接收桶中
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, d_cloud[s][j+g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将d0桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(d_user[i][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(d_user[i][j+g], d_user[i][j+g], mods->M);
                    offset += coeff_bytes;
                }
                
                mpz_clears(mpz_pack, mpz_unpack, NULL);
            }

            // 将e传输到接收桶中
            for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, e_cloud[s][j+g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                // 将e0桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(e_user[i][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(e_user[i][j+g], e_user[i][j+g], mods->M);
                    offset += coeff_bytes;
                }
                
                mpz_clears(mpz_pack, mpz_unpack, NULL);
            }

        }
    
        // ---------- Step 5: 各方计算 PSI 结果 ----------
        
        // 设置计时点
        t_begin = clock();

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t i = 0; i < k; ++i) {
            // 本地侧
            Bucket *a0 = &clients[t]->H_Beaver_a.buckets[i];
            Bucket *b0 = &clients[t]->H_Beaver_b.buckets[i];
            Result_Bucket *c0 = &clients[t]->H_Beaver_c.result_buckets[i];
            Result_Bucket *res_local = &clients[t]->PSI_result.result_buckets[i];

            poly_modular_fft_compute(res_local->coeffs, d_user[i], b0->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            poly_modular_fft_compute(res_local->coeffs, e_user[i], a0->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_add(res_local->coeffs[j], res_local->coeffs[j], c0->coeffs[j]);
                mpz_mod(res_local->coeffs[j], res_local->coeffs[j], mods->M);
            }
        }

        t_end = clock();
        printf("用户%d计算PSI耗时：%.3f 秒\n", t, (double)(t_end - t_begin)/CLOCKS_PER_SEC);

        // ---------- Step 5: 云端侧计算 PSI 结果（d,e 重新打乱后对齐） ----------
    
        // 云端在打乱顺序下计算结果

        // 设置计时点
        t_begin = clock();

        // 多项式并行
        #pragma omp parallel for schedule(dynamic)
        for (size_t s = 0; s < k; ++s) {
            Bucket *a1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[s];
            Bucket *b1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[s];
            Result_Bucket *c1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[s];
            Result_Bucket *res_cloud = &psi_cloud->users[clients[t]->user_id].PSI_result.result_buckets[s];

            // 重新初始化结果桶
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
                mpz_set_ui(res_cloud->coeffs[j], 0);

            poly_modular_fft_compute(res_cloud->coeffs, d_cloud[s], b1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            poly_modular_fft_compute(res_cloud->coeffs, e_cloud[s], a1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);

            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_add(res_cloud->coeffs[j], res_cloud->coeffs[j], c1->coeffs[j]);
                mpz_mod(res_cloud->coeffs[j], res_cloud->coeffs[j], mods->M);
            }

            mpz_set(res_cloud->tag, c1->tag); // tag 同步


        }
        
        t_end = clock();
        printf("PSI云平台计算用户%dPSI耗时：%.3f 秒\n", t, (double)(t_end - t_begin)/CLOCKS_PER_SEC);

        printf("[Beaver] 云平台计算用户%d的 PSI 结果完成。\n", t);
        
        // 清理本用户的临时变量
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_clear(d0[i][j]);
                mpz_clear(e0[i][j]);
                mpz_clear(d_user[i][j]);
                mpz_clear(e_user[i][j]);
                mpz_clear(recv_d0[i][j]);
                mpz_clear(recv_e0[i][j]);
            }
            free(d0[i]); free(e0[i]); free(d_user[i]); free(e_user[i]);
            free(recv_d0[i]); free(recv_e0[i]);
        }
        free(d0); free(e0); free(d_user); free(e_user);
        free(recv_d0); free(recv_e0);
        
        for (size_t s = 0; s < k; ++s) {
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_clear(d_cloud[s][j]);
                mpz_clear(e_cloud[s][j]);
            }
            free(d_cloud[s]); free(e_cloud[s]);
        }
        free(d_cloud); free(e_cloud);
    }
    
    // 释放逆打乱表（在所有用户处理完后）
    free(inv_shuffle);

    printf("[Verify] 开始计算 Beaver 乘法阶段...\n");
    
    if (! verify || !psi_cloud || !mods) {
        fprintf(stderr, "[Verify] 参数错误。\n");
        return;
    }

    // 初始化结果桶
    result_bucket_init(&verify->result_user, k);
    result_bucket_init(&psi_cloud->users[0].PSI_result, k);
    
    // ---------- Step 0: 构造逆打乱表 ----------
    inv_shuffle = malloc(sizeof(size_t) * k);
    for (size_t i = 0; i < k; ++i)
        inv_shuffle[verify->shuffle_table[i]] = i;
    
    // ---------- Step 1: 验证方计算 d0(x), e0(x) ----------
    mpz_t **d0 = malloc(sizeof(mpz_t*) * k);
    mpz_t **e0 = malloc(sizeof(mpz_t*) * k);

    // 多线程并行
    #pragma omp parallel for schedule(dynamic)
    for (size_t i = 0; i < k; ++i) {
        d0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(d0[i][j]);
            mpz_init(e0[i][j]);
            mpz_sub(d0[i][j], verify->H_P.buckets[i].coeffs[j], verify->H_Beaver_a.buckets[i].coeffs[j]);
            mpz_sub(e0[i][j], verify->H_W.buckets[i].coeffs[j], verify->H_Beaver_b.buckets[i].coeffs[j]);
            mpz_mod(d0[i][j], d0[i][j], mods->M);
            mpz_mod(e0[i][j], e0[i][j], mods->M);
        }
    }

    // ---------- Step 2: 打乱并“发送” d0,e0 到云端 ----------
    mpz_t **recv_d0 = malloc(sizeof(mpz_t*) * k);
    mpz_t **recv_e0 = malloc(sizeof(mpz_t*) * k);

    // 多线程并行
    #pragma omp parallel for schedule(dynamic)
    for (size_t i = 0; i < k; ++i) {
        size_t s = verify->shuffle_table[i];
        recv_d0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        recv_e0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        // 初始化接收桶
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(recv_d0[s][j]);
            mpz_init(recv_e0[s][j]);
        }

        // 将d0传输到接收桶中
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, d0[i][j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            // 将d0桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(recv_d0[s][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(recv_d0[s][j+g], recv_d0[s][j+g], mods->M);
                offset += coeff_bytes;
            }
                
            mpz_clears(mpz_pack, mpz_unpack, NULL);
        }

        // 将e0传输到接收桶中
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, e0[i][j + g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            // 将e0桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(recv_e0[s][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(recv_e0[s][j+g], recv_e0[s][j+g], mods->M);
                offset += coeff_bytes;
            }
            mpz_clears(mpz_pack, mpz_unpack, NULL);
        }
    }
    
    // ---------- Step 3: 云端计算 d(x), e(x) ----------
    mpz_t **d_cloud = malloc(sizeof(mpz_t*) * k);
    mpz_t **e_cloud = malloc(sizeof(mpz_t*) * k);

    // 多线程并行
    #pragma omp parallel for schedule(dynamic)
    for (size_t s = 0; s < k; ++s) {
        Bucket *P1 = &psi_cloud->users[0].H_P.buckets[s];
        Bucket *W1 = &psi_cloud->users[0].H_W.buckets[s];
        Bucket *a1 = &psi_cloud->users[0].H_Beaver_a.buckets[s];
        Bucket *b1 = &psi_cloud->users[0].H_Beaver_b.buckets[s];

        d_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);

        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(d_cloud[s][j]);
            mpz_init(e_cloud[s][j]);
            mpz_sub(d_cloud[s][j], P1->coeffs[j], a1->coeffs[j]); // d1
            mpz_sub(e_cloud[s][j], W1->coeffs[j], b1->coeffs[j]); // e1
            mpz_add(d_cloud[s][j], d_cloud[s][j], recv_d0[s][j]); // + d0’
            mpz_add(e_cloud[s][j], e_cloud[s][j], recv_e0[s][j]); // + e0’
            mpz_mod(d_cloud[s][j], d_cloud[s][j], mods->M);
            mpz_mod(e_cloud[s][j], e_cloud[s][j], mods->M);
        }
    }

    // ---------- Step 4: 验证方逆打乱恢复 d,e ----------
    mpz_t **d_verify = malloc(sizeof(mpz_t*) * k);
    mpz_t **e_verify = malloc(sizeof(mpz_t*) * k);

    for (size_t i = 0; i < k; ++i) {
        size_t s = verify->shuffle_table[i];
        d_verify[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e_verify[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        // 初始化接收桶
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(d_verify[i][j]);
            mpz_init(e_verify[i][j]);
        }

        // 将d传输到验证方接收桶中
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, d_cloud[s][j+g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            // 将d0桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(d_verify[i][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(d_verify[i][j+g], d_verify[i][j+g], mods->M);
                offset += coeff_bytes;
            }
                mpz_clears(mpz_pack, mpz_unpack, NULL);
        }

        // 将e传输到接收桶中
        for (size_t j = 0; j < BUCKET_POLY_LEN; j+= group_size) {
            unsigned char enc_buf[4096];
            unsigned char pack_buf[4096];
            unsigned char dec_buf[4096];
            int enc_len = 0;
            size_t pack_len = 0;

            // ---------- 打包 ----------
            memset(pack_buf, 0, sizeof(pack_buf));
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; ++g) {
                unsigned char temp_bytes[512];
                size_t written = 0;
                mpz_export(temp_bytes, &written, 1, 1, 0, 0, e_cloud[s][j+g]);
                memcpy(pack_buf + pack_len, temp_bytes, written);
                pack_len += written;
            }

            // ---------- 打包为 mpz_t ----------
            mpz_t mpz_pack, mpz_unpack;
            mpz_inits(mpz_pack, mpz_unpack, NULL);
            mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
            // 将e0桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, mpz_unpack);

            // ---------- 修正右对齐导出 ----------
            memset(dec_buf, 0, sizeof(dec_buf));
            size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
            if (real_len > pack_len) real_len = pack_len; // 防止越界
            mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

            // ---------- 拆包 ----------
            size_t offset = 0;
            for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                mpz_import(e_verify[i][j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                mpz_mod(e_verify[i][j+g], e_verify[i][j+g], mods->M);
                offset += coeff_bytes;
            }
                mpz_clears(mpz_pack, mpz_unpack, NULL);
            }

    }
        
    // ---------- Step 5: 验证方计算 PSI 结果 ----------

    // 多线程并行
    #pragma omp parallel for schedule(dynamic)
    for (size_t i = 0; i < k; ++i) {
        // 验证方侧
        Bucket *a0 = &verify->H_Beaver_a.buckets[i];
        Bucket *b0 = &verify->H_Beaver_b.buckets[i];
        Result_Bucket *c0 = &verify->H_Beaver_c.result_buckets[i];
        Result_Bucket *res_local = &verify->result_user.result_buckets[i];

        poly_modular_fft_compute(res_local->coeffs, d_verify[i], b0->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        
        poly_modular_fft_compute(res_local->coeffs, e_verify[i], a0->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(res_local->coeffs[j], res_local->coeffs[j], c0->coeffs[j]);
            mpz_mod(res_local->coeffs[j], res_local->coeffs[j], mods->M);
        }
    }

    // ---------- Step 6: 云端侧计算 PSI 结果（d,e 重新打乱对齐） ----------
    
    // 多线程并行
    #pragma omp parallel for schedule(dynamic)
    for (size_t s = 0; s < k; ++s) {
        Bucket *a1 = &psi_cloud->users[0].H_Beaver_a.buckets[s];
        Bucket *b1 = &psi_cloud->users[0].H_Beaver_b.buckets[s];
        Result_Bucket *c1 = &psi_cloud->users[0].H_Beaver_c.result_buckets[s];
        Result_Bucket *res_cloud = &psi_cloud->users[0].PSI_result.result_buckets[s];

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
            mpz_set_ui(res_cloud->coeffs[j], 0);

        poly_modular_fft_compute(res_cloud->coeffs, d_cloud[s], b1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        poly_modular_fft_compute(res_cloud->coeffs, e_cloud[s], a1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(res_cloud->coeffs[j], res_cloud->coeffs[j], c1->coeffs[j]);
            mpz_mod(res_cloud->coeffs[j], res_cloud->coeffs[j], mods->M);
        }
        mpz_set(res_cloud->tag, c1->tag);
    }
    
    // ---------- 清理内存 ----------
    free(inv_shuffle);
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_clear(d0[i][j]);
            mpz_clear(e0[i][j]);
            mpz_clear(d_verify[i][j]);
            mpz_clear(e_verify[i][j]);
            mpz_clear(recv_d0[i][j]);
            mpz_clear(recv_e0[i][j]);
        }
        free(d0[i]); free(e0[i]); free(d_verify[i]); free(e_verify[i]);
        free(recv_d0[i]); free(recv_e0[i]);
    }
    free(d0); free(e0); free(d_verify); free(e_verify);
    free(recv_d0); free(recv_e0);

    for (size_t s = 0; s < k; ++s) {
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_clear(d_cloud[s][j]);
            mpz_clear(e_cloud[s][j]);
        }
        free(d_cloud[s]); free(e_cloud[s]);
    }
    free(d_cloud);
    free(e_cloud);

    
    printf("[Beaver] Beaver 乘法阶段完成。\n");
    
}


// ===========================================================
//   验证方 → 分发 AES 密钥给所有用户 （已并行）
// ===========================================================
void verify_distribute_aes_key(Verify *verify, Client *clients[], int client_count){
    
    if (!verify || !clients) {
        fprintf(stderr, "[Verify] AES 密钥分发失败：参数错误。\n");
        return;
    }

    printf("[Verify] 开始生成并分发新的 AES 密钥（结果阶段通信使用）...\n");

    // ---------- Step 1. 验证方生成新的 AES 密钥 ----------
    aes_generate_mem(&verify->aes_verify);
    printf("[Verify] 已生成新的 AES 密钥，用于结果阶段通信。\n");

    // ---------- Step 2. 遍历每个用户 ----------
    // 多线程并行
    #pragma omp parallel for
    for (size_t i = 0; i < client_count; ++i) {
        Client *cli = clients[i];
        if (!cli) continue;

        // RSA 加密密钥并分发
        rsa_transfer_aes_key(cli->rsa_ctx, &cli->aes_verify, &verify->aes_verify);
    }

    printf("[Verify] 所有用户均已收到结果阶段 AES 密钥。\n");
}

// ===========================================================
//  发送 PSI 结果到验证方
// ===========================================================
void send_result_to_verify(Client *clients[], int client_count,  PSICloud *psi_cloud, Verify *verify, const ModSystem *mods)
{
    if (!clients || !psi_cloud || !verify || !mods) {
        fprintf(stderr, "[Client→Verify] 参数错误。\n");
        return;
    }

    // 计算单个数据的字节数
    size_t bit_size = mpz_sizeinbase(mods->M, 2);
    size_t coeff_bytes = (bit_size + 7) / 8;

    // 计算每个组里能包含多少个数据
    size_t group_size = MAX(1, 16 / coeff_bytes); 
    if (group_size < 1) group_size = 1;

    //中转中间态
    Result_BucketSet temp_result;
    // 得到桶数数据
    size_t k = clients[0]->k;
    // 初始化中转中间态
    result_bucket_init(&temp_result, k);
    

    for (size_t t = 0; t < client_count; t++){
        
        printf("[Client→Verify] 用户 %lu 开始发送 PSI 结果桶...\n", (unsigned long)clients[t]->user_id);
            
        // ---------- 用户将结果发送给验证方 ----------

        // 多线程并行
        #pragma omp parallel for
        for (size_t i = 0; i < k; i++){
            
            // 将用户计算结果传输到中间态中
            for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, clients[t]->PSI_result.result_buckets[i].coeffs[j+g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //Beaver云平台侧加密待传输的数据包
                aes_encrypt_mpz_buf(&clients[t]->aes_verify, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                // 验证方侧解密并存储数据包 
                aes_decrypt_mpz_buf(&verify->aes_verify, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(temp_result.result_buckets[i].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(temp_result.result_buckets[i].coeffs[j+g], temp_result.result_buckets[i].coeffs[j+g], mods->M);
                    offset += coeff_bytes;
                }
            }

            for (size_t j = 0; j < RESULT_POLY_LEN; j++){
                
                //验证方将结果加和到自己的结果中
                mpz_add(verify->result_user.result_buckets[i].coeffs[j], verify->result_user.result_buckets[i].coeffs[j], temp_result.result_buckets[i].coeffs[j]);

                //验证方进行mod M
                mpz_mod(verify->result_user.result_buckets[i].coeffs[j], verify->result_user.result_buckets[i].coeffs[j], mods->M);
            }
            
        } 
        printf("[Client→Verify] 用户 %lu 的结果桶已成功传输并合并（模 M）。\n", (unsigned long)clients[t]->user_id);
    }


    printf("[PSI→Verify] 云平台开始向验证方发送云平台计算 PSI 结果...\n");

    // 发送验证方云平台计算结果

    // ---------- 逆打乱桶顺序 ----------
        size_t *inv_shuffle = malloc(sizeof(size_t) * k);

        // 记录逆打乱表
        for(size_t i = 0; i < k; ++i){
            inv_shuffle[verify->shuffle_table[i]] = i;
        }

        // 多线程并行
        #pragma omp parallel for
        for (size_t i = 0; i < k; i++){
            size_t original_idx = inv_shuffle[i]; // 云端桶 s 对应的验证方原顺序位置

            Result_Bucket *res_cloud_user = &psi_cloud->users[0].PSI_result.result_buckets[i];
            Result_Bucket *res_verify     = &verify->result_cloud.result_buckets[original_idx];

            // 将云平台计算结果传输到中间态中
            for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, res_cloud_user->coeffs[j+g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //Beaver云平台侧加密待传输的数据包
                aes_encrypt_mpz_buf(&psi_cloud->aes_internal, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                // 验证方侧解密并存储数据包 
                aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(temp_result.result_buckets[original_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(temp_result.result_buckets[original_idx].coeffs[j+g], temp_result.result_buckets[original_idx].coeffs[j+g], mods->M);
                    offset += coeff_bytes;
                }
            }

            for (size_t j = 0; j < RESULT_POLY_LEN; j++){ 
                // 验证方取回并模运算
                mpz_add(res_verify->coeffs[j], res_verify->coeffs[j], temp_result.result_buckets[original_idx].coeffs[j]);
                mpz_mod(res_verify->coeffs[j], res_verify->coeffs[j], mods->M);

            }

        }

        free(inv_shuffle);


    // 遍历各个用户
    for (size_t t = 0; t < client_count; t++){
        
        // ---------- 逆打乱桶顺序 ----------
        size_t *inv_shuffle = malloc(sizeof(size_t) * k);
        
        for (size_t i = 0; i < k; ++i)
            inv_shuffle[clients[t]->shuffle_table[i]] = i;

        // 多线程并行
        #pragma omp parallel for
        for (size_t i = 0; i < k; i++){
            size_t original_idx = inv_shuffle[i]; // 云端桶 s 对应的用户原顺序位置

            Result_Bucket *res_cloud_user = &psi_cloud->users[clients[t]->user_id].PSI_result.result_buckets[i];
            Result_Bucket *res_verify     = &verify->result_cloud.result_buckets[original_idx];

            // 将云平台计算结果传输到中间态中
            for (size_t j = 0; j < RESULT_POLY_LEN; j += group_size){

                // 初始化加密相关中间态
                unsigned char enc_buf[4096];
                unsigned char pack_buf[4096];
                unsigned char dec_buf[4096];
                int enc_len = 0;
                size_t pack_len = 0;

                // ---------- 打包 ----------
                memset(pack_buf, 0, sizeof(pack_buf));
                for (size_t g = 0; g < group_size && (j + g) < RESULT_POLY_LEN; ++g) {
                    unsigned char temp_bytes[512];
                    size_t written = 0;
                    mpz_export(temp_bytes, &written, 1, 1, 0, 0, res_cloud_user->coeffs[j+g]);
                    memcpy(pack_buf + pack_len, temp_bytes, written);
                    pack_len += written;
                }

                // ---------- 打包为 mpz_t ----------
                mpz_t mpz_pack, mpz_unpack;
                mpz_inits(mpz_pack, mpz_unpack, NULL);
                mpz_import(mpz_pack, pack_len, 1, 1, 0, 0, pack_buf);
                
                //Beaver云平台侧加密待传输的数据包
                aes_encrypt_mpz_buf(&psi_cloud->aes_internal, mpz_pack, enc_buf, sizeof(enc_buf), &enc_len);
                // 验证方侧解密并存储数据包 
                aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, mpz_unpack);

                // ---------- 修正右对齐导出 ----------
                memset(dec_buf, 0, sizeof(dec_buf));
                size_t real_len = (mpz_sizeinbase(mpz_unpack, 2) + 7) / 8;
                if (real_len > pack_len) real_len = pack_len; // 防止越界
                mpz_export(dec_buf + (pack_len - real_len), NULL, 1, 1, 0, 0, mpz_unpack);

                // ---------- 拆包 ----------
                size_t offset = 0;
                for (size_t g = 0; g < group_size && (j + g) < BUCKET_POLY_LEN; g++) {
                    mpz_import(temp_result.result_buckets[original_idx].coeffs[j+g], coeff_bytes, 1, 1, 0, 0, dec_buf + offset);
                    mpz_mod(temp_result.result_buckets[original_idx].coeffs[j+g], temp_result.result_buckets[original_idx].coeffs[j+g], mods->M);
                    offset += coeff_bytes;
                }
            }

            for (size_t j = 0; j < RESULT_POLY_LEN; j++){ 
                // 验证方取回并模运算
                mpz_add(res_verify->coeffs[j], res_verify->coeffs[j], temp_result.result_buckets[original_idx].coeffs[j]);
                mpz_mod(res_verify->coeffs[j], res_verify->coeffs[j], mods->M);

            }
            
        }
        free(inv_shuffle);
    }
   
    printf("[PSI→Verify] 所有云端结果均已成功传输并合并至验证方。\n");
}


// ===========================================================
//   Verify → 合并结果并检查交集
// ===========================================================
void verify_merge_and_check_intersection(Verify *verify,const ModSystem *mods){
    if (!verify || !mods) {
        fprintf(stderr, "[Verify] 参数错误。\n");
        return;
    }

    printf("[Verify] 开始合并结果并检查交集...\n");

    size_t k = verify->k;
    size_t data_len = 1UL << verify->n;

    // ---------- Step 1. 合并 result_user 与 result_cloud ----------
    if (verify->result_merged.result_buckets == NULL)
        result_bucket_init(&verify->result_merged, k);

    for (size_t i = 0; i < k; ++i) {
        Result_Bucket *merged = &verify->result_merged.result_buckets[i];
        Result_Bucket *user   = &verify->result_user.result_buckets[i];
        Result_Bucket *cloud  = &verify->result_cloud.result_buckets[i];

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(merged->coeffs[j], user->coeffs[j], cloud->coeffs[j]);
            mpz_mod(merged->coeffs[j], merged->coeffs[j], mods->M);
        }

        mpz_set(merged->tag, user->tag);
    }

    printf("[Verify] 合并完成，开始检查交集...\n");

    // ---------- Step 2. 检查交集 ----------
    size_t intersection_count = 0;

    for (size_t i = 0; i < data_len; ++i) {
        mpz_t s_prime, eval;
        mpz_inits(s_prime, eval, NULL);

        // 计算哈希与桶索引
        uint64_t h = hash48_compute(verify->data[i]);
        size_t bucket_idx = h % k;

        // 构造带哈希的数据 s' = (s << 48) | h(s)
        hash48_append(s_prime, verify->data[i]);

        // 多项式 P(x) = 0 检查
        Result_Bucket *poly = &verify->result_merged.result_buckets[bucket_idx];
        mpz_set_ui(eval, 0);
        mpz_t power, term;
        mpz_inits(power, term, NULL);
        mpz_set_ui(power, 1);

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            // term = coeff[j] * power mod M
            mpz_mul(term, poly->coeffs[j], power);
            mpz_add(eval, eval, term);
            mpz_mod(eval, eval, mods->M);
            mpz_mul(power, power, s_prime);
            mpz_mod(power, power, mods->M);
        }

        // 若 P(s') ≡ 0 (mod M)，则交集成立
        if (mpz_sgn(eval) == 0) {
            gmp_printf("  → 交集元素: s = %Zd  (hash = %lu, 桶 = %zu)\n",
                       verify->data[i], h, bucket_idx);
            intersection_count++;
        }

        mpz_clears(s_prime, eval, power, term, NULL);
    }

    printf("[Verify] 交集检查完成，共发现 %zu 个交集元素。\n", intersection_count);
}