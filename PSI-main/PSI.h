#ifndef PSI_H
#define PSI_H

#include "crypt.h"
#include "client.h"
#include "Verify.h"
#include "PSI_Cloud.h"
#include "Beaver_Cloud.h"
#include "fft_poly.h"
#include "crt_gmp.h"
#include "modsystem.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


// =============================
//   PSI 协议阶段模块
// =============================

// -----------------------------
// 阶段 1：AES 密钥分发
// -----------------------------
// PSI 云平台使用各方 RSA 公钥加密自身 AES 密钥，
// 发送给 Client、Verify、BeaverCloud，
// 各方使用 RSA 私钥解密并存储到各自的 AES 区域中。
void psi_sync_all_clients(PSICloud *cloud, Client *clients[], size_t client_count, Verify *verify, BeaverCloud *beaver);
                            
// 用户上传桶
void Clients_send_encrypted_buckets(Client *clients[], int client_count, PSICloud *cloud, mpz_t M);

// 验证方上传桶
void psi_send_encrypted_buckets_verify(Verify *verify, PSICloud *cloud, mpz_t M);

// beaver 云平台分发多项式beaver三元组
void beaver_cloud_distribute_to_client(BeaverCloud *cloud, Client *clients[], size_t client_count, PSICloud *psi_cloud, Verify *verify, const mpz_t M);

// 计算多项式Beaver三元组结果
void beaver_compute_multiplication(Client *clients[], int client_count, PSICloud *psi_cloud, Verify *verify, const ModSystem *mods);

// 验证方 → 分发 AES 密钥给所有用户
void verify_distribute_aes_key(Verify *verify, Client *clients[], int client_count);

// 发送 PSI 结果到验证方
void send_result_to_verify(Client *clients[], int client_count,  PSICloud *psi_cloud, Verify *verify, const ModSystem *mods);

// Verify → 合并结果并检查交集
void verify_merge_and_check_intersection(Verify *verify,const ModSystem *mods);



#endif // PSI_H

