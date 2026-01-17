#include "PSI.h"
#include "client.h"
#include "PSI_Cloud.h"
#include "Verify.h"
#include "Beaver_Cloud.h"
#include <time.h>

// 定义数据比特位数
#define DATA_BIT 64

int main(){

    // 生成计时点（新增 client_build_buckets 专属计时变量）
    clock_t t_init_begin, t_init_end, 
            t_build_begin, t_build_end,  // 新增：单独记录桶构建耗时
            t_outsrc_begin, t_outsrc_end, 
            t_compute_begin, t_compute_end, 
            t_check_begin, t_check_end;

    // 用户数量
    int client_count = 1;

    // 数据集大小
    int DATASET_NUM;

    // 桶数量
    int BUCKET_NUM;

    // 不同数据集大小对应的桶数量
    int dataset_sizes[1] = {15};
    int bucket_counts[1] = {91};
    
    // 修复：外层循环变量 i，内层客户端循环改用 j，避免变量遮蔽
    for (size_t i = 0; i < 1; i++){
    
        DATASET_NUM = dataset_sizes[i];
        BUCKET_NUM = bucket_counts[i];
        
        // 生成PSI云平台 结构
        PSICloud psi_cloud;

        //生成验证方结构
        Verify verify;

        // 生成Beaver云平台结构
        BeaverCloud beaver_cloud;

        // 生成客户端数组
        Client **clients = malloc(sizeof(Client*) * client_count);

        
        // 生成模数
        ModSystem mods;

        //初始化模数
        modsystem_init_auto(&mods, 40, 123);

       
        // 初始化客户端（内层循环变量改为 j，避免与外层 i 冲突）
        for (size_t j = 0; j < client_count; ++j) {
            clients[j] = malloc(sizeof(Client));
            client_init(clients[j], DATASET_NUM, DATA_BIT, BUCKET_NUM, 123, j+1);
            
            // 1. 统计 client_generate_P_BUCKET 耗时（原有逻辑保留）
            t_init_begin = clock();
            client_generate_P_BUCKET(clients[j]);
            t_init_end = clock();
            printf("单个用户插入数据（client_generate_P_BUCKET）耗时：%.6f 秒\n", 
                   (double)(t_init_end - t_init_begin)/CLOCKS_PER_SEC / client_count);

            // 2. 新增：单独统计 client_build_buckets 耗时
            t_build_begin = clock();  // 记录桶构建开始时间
            client_build_buckets(clients[j], mods.M);
            t_build_end = clock();    // 记录桶构建结束时间
            // 计算并打印耗时（保留6位小数，更精准）
            double build_cost = (double)(t_build_end - t_build_begin) / CLOCKS_PER_SEC / client_count;
            printf("单个用户桶构建（client_build_buckets）耗时：%.6f 秒\n", build_cost);
        }

        // 初始化验证方
        verify_init(&verify, DATASET_NUM, DATA_BIT, BUCKET_NUM, 456);
        verify_build_buckets(&verify, mods.M);
        verify_insert_dataset(&verify, mods.M);

        // 初始化PSI云平台
        psi_cloud_init(&psi_cloud, client_count+1, BUCKET_NUM, DATA_BIT, 123);

        // 初始化Beaver云平台
        beaver_cloud_init(&beaver_cloud, DATA_BIT, 123, BUCKET_NUM);
        
        // 进行PSI
        // 第一步，PSI云平台将AES密钥发送给各方
        psi_sync_all_clients(&psi_cloud, clients, client_count, &verify, &beaver_cloud);

        // 第二步，Beaver云平台分发多项式Beaver三元组
        beaver_cloud_distribute_to_client(&beaver_cloud, clients, client_count, &psi_cloud, &verify, mods.M);

        t_outsrc_begin = clock();
        // 第三步，用户上传桶
        Clients_send_encrypted_buckets(clients, client_count, &psi_cloud, mods.M);
    
        // 第四步，验证方上传桶
        psi_send_encrypted_buckets_verify(&verify, &psi_cloud, mods.M);

        t_outsrc_end = clock();
        printf("托管阶段耗时：%.3f 秒\n", (double)(t_outsrc_end - t_outsrc_begin)/CLOCKS_PER_SEC);
        
        t_compute_begin = clock();
        // 第五步，计算多项式Beaver三元组结果
        beaver_compute_multiplication(clients, client_count, &psi_cloud, &verify, &mods);

        t_compute_end = clock();
        printf("PSI计算阶段总耗时：%.3f 秒\n", (double)(t_compute_end - t_compute_begin)/CLOCKS_PER_SEC);

        // 第六步，验证方分发AES密钥给用户
        verify_distribute_aes_key(&verify, clients, client_count);

        // 第七步，发送PSI结果到验证方
        send_result_to_verify(clients, client_count, &psi_cloud, &verify, &mods);

        t_check_begin = clock();
        // 最后一步，验证方合并结果并检查交集
        verify_merge_and_check_intersection(&verify, &mods);
        
        t_check_end = clock();
        printf("检查阶段耗时：%.3f 秒\n", (double)(t_check_end - t_check_begin)/CLOCKS_PER_SEC);

        // 释放内存
        // 释放客户端（内层循环变量改为 j）
        for (size_t j = 0; j < client_count; ++j) {
            client_free(clients[j]);
            free(clients[j]);
        }
        free(clients);  // 新增：释放客户端数组本身的内存（原有代码遗漏）

        // 释放 PSI云平台
        psi_cloud_free(&psi_cloud);

        // 释放 Beaver云平台
        beaver_cloud_free(&beaver_cloud);

        // 释放验证方
        verify_free(&verify);
    
    }

    return 0;

}