#ifndef DATASET_H
#define DATASET_H

#include <gmp.h>
#include <stddef.h>

// 生成一个长度为 2^n 的数据集，每个数为 m-bit 随机整数
// 参数：
//   data  : 已分配好的 mpz_t 数组（长度 >= 2^n）
//   n     : 数据规模指数，数组长度 = 2^n
//   m     : 每个数的位宽（bit 数）
//   seed  : 随机数种子（如 0 表示使用 time(NULL)）
//
// 用法：
//   mpz_t *data = malloc(sizeof(mpz_t) * (1 << n));
//   dataset_generate(data, n, m, 1234UL);
void dataset_generate(mpz_t *data, unsigned int n, unsigned int m, unsigned long seed);

// 释放由 dataset_generate 初始化的数据集
void dataset_free(mpz_t *data, unsigned int n);

// 打印数据集的前 k 个元素（用于调试）
void dataset_print(mpz_t *data, unsigned int n, size_t k);

#endif // DATASET_H

