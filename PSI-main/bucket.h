#ifndef BUCKET_H
#define BUCKET_H

#include <gmp.h>
#include <stddef.h>

// 宏定义规范化：增加语义注释，避免魔法数
#define BUCKET_ROOTS        1023    // 每个桶的根数量（次数=1023）
#define BUCKET_POLY_LEN     1024    // 桶多项式系数长度（次数+1）
#define RESULT_POLY_LEN     2047    // 结果多项式系数长度
#define LINEAR_POLY_LEN     2       // 一次多项式(x - r)的系数长度
#define PRODUCT_POLY_LEN_2  3       // 两个一次多项式乘积的系数长度

// 桶结构：注释补充语义
typedef struct {
    mpz_t roots[BUCKET_ROOTS];      // 随机根数组（用于构造多项式∏(x - r_i)）
    mpz_t coeffs[BUCKET_POLY_LEN];  // 多项式系数（降幂，coeffs[0]最高次项）
    int element_num;                // 桶内元素数量
    mpz_t tag;                      // 桶唯一标识（云平台识别用）
} Bucket;

// 结果桶结构
typedef struct {
    mpz_t coeffs[RESULT_POLY_LEN];  // 结果多项式系数数组
    mpz_t tag;                      // 结果桶标识
} Result_Bucket;

// 桶集合结构
typedef struct {
    Bucket *buckets;                // 桶数组
    size_t count;                   // 桶数量
    unsigned int m_bit;             // 随机数的比特长度
} BucketSet;

// 结果桶集合结构
typedef struct {
    Result_Bucket *result_buckets;  // 结果桶数组
    size_t count;                   // 结果桶数量
} Result_BucketSet;

// 函数声明（保持接口不变，仅优化实现）
void bucket_init(BucketSet *set, unsigned int n, unsigned int m_bit);
void result_bucket_init(Result_BucketSet *result_set, unsigned int n);
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed);
void bucket_expand(BucketSet *set, const mpz_t M);
void bucket_expand_iterative(BucketSet *set, const mpz_t M);
void bucket_replace_root(mpz_t *poly, size_t degree, const mpz_t r_out, 
                         const mpz_t r_in, const mpz_t M);
void bucket_copy(Bucket *dest, const Bucket *src);
void result_bucket_copy(Result_Bucket *dest, const Result_Bucket *src);
void bucket_print(const BucketSet *set, size_t bucket_count, size_t roots_per_bucket);
void bucket_print_poly(const BucketSet *set, size_t bucket_count, size_t coeffs_to_show);
void bucket_free(BucketSet *set);
void result_bucket_free(Result_BucketSet *set);

#endif // BUCKET_H
