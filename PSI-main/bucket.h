#ifndef BUCKET_H
#define BUCKET_H

#include <gmp.h>
#include <stddef.h>

#define BUCKET_POLY_LEN 1024   // 多项式系数数量
#define RESULT_POLY_LEN 2047   // 结果多项式系数数量
#define BUCKET_ROOTS    1023   // 根数量

typedef struct {
    mpz_t roots[BUCKET_ROOTS];             // 127 个随机根
    mpz_t coeffs[BUCKET_POLY_LEN];         // 多项式系数数组
    int element_num;                       // 记录桶内数据个数
    mpz_t tag;                             // 桶随机标识（用于云平台识别）
} Bucket;

typedef struct{
  mpz_t coeffs[RESULT_POLY_LEN];          //结果多项式系数数组
  mpz_t tag;                              //桶随机标识（用于云平台识别）
} Result_Bucket;

typedef struct {
    Bucket *buckets;
    size_t count;
    unsigned int m_bit;
} BucketSet;

typedef struct{
  Result_Bucket *result_buckets;
  size_t count;
} Result_BucketSet;

//桶结构初始化
void bucket_init(BucketSet *set, unsigned int n, unsigned int m_bit);

//结果桶初始化
void result_bucket_init(Result_BucketSet *result_set, unsigned int n);

// 生成 n 个随机根桶，每个桶包含 127 个 m-bit 随机数
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed);

// 根据根展开多项式：P(x) = ∏ (x - r_i)
void bucket_expand(BucketSet *set, const mpz_t M);

// 在多项式中替换一个根：r_out → r_in（就地更新系数数组）
// poly: 降幂系数数组（长度 degree+1，poly[0] 为最高次项系数）
// degree: 多项式次数（例如 127）
// r_out, r_in: 被替换的旧根与新根（mpz_t）
void bucket_replace_root(mpz_t *poly, size_t degree, const mpz_t r_out, const mpz_t r_in, const mpz_t M);
                         
                         
// 拷贝桶结构
void bucket_copy(Bucket *dest, const Bucket *src);

// 拷贝结果桶结构
void result_bucket_copy(Result_Bucket *dest, const Result_Bucket *src);


// 打印前 few 个桶的前 few 个根/系数
void bucket_print(const BucketSet *set, size_t bucket_count, size_t roots_per_bucket);
void bucket_print_poly(const BucketSet *set, size_t bucket_count, size_t coeffs_to_show);

// 释放桶内存
void bucket_free(BucketSet *set);
void result_bucket_free(Result_BucketSet *set);

#endif // BUCKET_H
