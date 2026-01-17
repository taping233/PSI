#ifndef MODSYSTEM_H
#define MODSYSTEM_H

#include <gmp.h>
#include <stddef.h>

typedef struct {
    mpz_t M;          // 大模数
    mpz_t *m_list;    // 小模数数组
    size_t m_count;   // 小模数数量
} ModSystem;

// 初始化小模数系统
// 参数：
//   sys        : 输出的结构体指针
//   small_bits : 每个小模数的位长（例如 20）
//   count      : 小模数数量上限（例如 16）
//   M          : 大模数
//   seed       : 随机种子
void modsystem_init_auto(ModSystem *sys, unsigned int M_bits, unsigned long seed);


// 释放内存
void modsystem_free(ModSystem *sys);

// 打印状态
void modsystem_print(const ModSystem *sys);

#endif

