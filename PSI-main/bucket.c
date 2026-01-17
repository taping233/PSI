#include "bucket.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <fftw3.h>
#include <gmp.h>

// -----------------------------
// 【模块化优化】抽离通用辅助函数（避免重复）
// -----------------------------

/**
 * 统一错误处理函数：打印错误信息并退出
 * @param msg 错误描述
 */
static void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

/**
 * 安全内存分配：封装malloc+NULL检查
 * @param size 分配大小
 * @param err_msg 错误提示
 * @return 分配成功的内存指针
 */
static void *safe_malloc(size_t size, const char *err_msg) {
    void *ptr = malloc(size);
    if (!ptr) handle_error(err_msg);
    return ptr;
}

/**
 * 初始化mpz_t数组并赋值
 * @param arr 数组指针
 * @param len 数组长度
 * @param val 初始值（无符号整数）
 */
static void mpz_array_init(mpz_t *arr, size_t len, unsigned long val) {
    for (size_t i = 0; i < len; i++) {
        mpz_init(arr[i]);
        mpz_set_ui(arr[i], val);
    }
}

/**
 * 清理mpz_t数组
 * @param arr 数组指针
 * @param len 数组长度
 */
static void mpz_array_clear(mpz_t *arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        mpz_clear(arr[i]);
    }
}

/**
 * 初始化单个Bucket（抽离重复初始化逻辑）
 * @param b Bucket指针
 * @param m_bit 随机数比特长度
 */
static void bucket_init_single(Bucket *b, unsigned int m_bit) {
    // 初始化根（默认0）
    mpz_array_init(b->roots, BUCKET_ROOTS, 0);
    // 初始化多项式系数（默认0）
    mpz_array_init(b->coeffs, BUCKET_POLY_LEN, 0);
    // 初始化tag（默认0）
    mpz_init(b->tag);
    mpz_set_ui(b->tag, 0);
    // 初始化元素数量
    b->element_num = 0;
}

// -----------------------------
// 原有辅助函数：保留+优化
// -----------------------------

/**
 * 计算大于等于n的最小2的幂次（FFTW高效长度）
 * @param n 输入长度
 * @return 最小2的幂次
 */
static size_t next_power_of_two(size_t n) {
    if (n == 0) return 1;
    size_t power = 1;
    while (power < n) power <<= 1;
    return power;
}

/**
 * 构造基本多项式 (x - r) → mpz_t数组（降幂）
 * @param poly 输出数组（长度LINEAR_POLY_LEN）
 * @param r 根
 * @param M 模数
 */
static void create_linear_poly(mpz_t *poly, const mpz_t r, const mpz_t M) {
    mpz_set_ui(poly[0], 1);          // x^1 系数：1
    mpz_neg(poly[1], r);             // 常数项：-r
    mpz_mod(poly[1], poly[1], M);    // 模M
    // 简化负数处理：mpz_mod已保证非负，无需额外判断
}

// -----------------------------
// 核心：FFTW多项式乘法（修复精度提示+逻辑精简）
// -----------------------------
static void poly_multiply_mod_fftw(const mpz_t *a, size_t deg_a,
                                   const mpz_t *b, size_t deg_b,
                                   mpz_t *result, const mpz_t M) {
    // 1. 计算FFT所需长度（避免循环卷积）
    size_t N = next_power_of_two(deg_a + deg_b + 1);
    
    // 2. 分配FFTW复数数组（使用safe_malloc）
    fftw_complex *in1 = safe_malloc(sizeof(fftw_complex) * N, "FFTW in1 malloc failed");
    fftw_complex *in2 = safe_malloc(sizeof(fftw_complex) * N, "FFTW in2 malloc failed");
    
    // 3. 初始化复数数组（mpz_t转double，标注精度风险）
    for (size_t i = 0; i < N; i++) {
        // 【精度提示】mpz_get_d对大整数（>2^53）会丢失精度，建议用mpfr库
        in1[i][0] = (i <= deg_a) ? mpz_get_d(a[i]) : 0.0;
        in1[i][1] = 0.0;
        in2[i][0] = (i <= deg_b) ? mpz_get_d(b[i]) : 0.0;
        in2[i][1] = 0.0;
    }
    
    // 4. 创建FFTW计划
    fftw_plan plan1 = fftw_plan_dft_1d(N, in1, in1, FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_plan plan2 = fftw_plan_dft_1d(N, in2, in2, FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_plan plan_inv = fftw_plan_dft_1d(N, in1, in1, FFTW_BACKWARD, FFTW_ESTIMATE);
    
    // 5. 执行正向FFT
    fftw_execute(plan1);
    fftw_execute(plan2);
    
    // 6. 频域相乘（复数乘法）
    for (size_t i = 0; i < N; i++) {
        double re1 = in1[i][0], im1 = in1[i][1];
        double re2 = in2[i][0], im2 = in2[i][1];
        in1[i][0] = re1 * re2 - im1 * im2;  // 实部
        in1[i][1] = re1 * im2 + im1 * re2;  // 虚部
    }
    
    // 7. 逆FFT + 缩放
    fftw_execute(plan_inv);
    for (size_t i = 0; i < N; i++) {
        in1[i][0] /= N;
        in1[i][1] /= N;  // 虚部理论上趋近于0，可忽略
    }
    
    // 8. 结果转mpz_t + 模M运算
    for (size_t i = 0; i < deg_a + deg_b + 1; i++) {
        mpz_set_d(result[i], round(in1[i][0]));  // 取整消除浮点误差
        mpz_mod(result[i], result[i], M);        // 模M（自动保证非负）
    }
    
    // 9. 清理FFTW资源
    fftw_destroy_plan(plan1);
    fftw_destroy_plan(plan2);
    fftw_destroy_plan(plan_inv);
    fftw_free(in1);
    fftw_free(in2);
}

// -----------------------------
// 递归分治多项式乘积（精简+安全分配）
// -----------------------------
static void recursive_poly_product_flint(mpz_t **roots, size_t start, size_t end,
                                         mpz_t *result, const mpz_t M) {
    if (start == end) {
        // 基本情况：单个根 → (x - r)
        create_linear_poly(result, *roots[start], M);
        return;
    }
    
    size_t mid = start + (end - start) / 2;
    size_t left_deg = mid - start + 1;   // 左子多项式次数
    size_t right_deg = end - mid;        // 右子多项式次数
    
    // 安全分配左右子多项式数组
    mpz_t *left_poly = safe_malloc(sizeof(mpz_t) * (left_deg + 1), "left_poly malloc failed");
    mpz_t *right_poly = safe_malloc(sizeof(mpz_t) * (right_deg + 1), "right_poly malloc failed");
    
    // 初始化子多项式数组
    mpz_array_init(left_poly, left_deg + 1, 0);
    mpz_array_init(right_poly, right_deg + 1, 0);
    
    // 递归计算左右子多项式
    recursive_poly_product_flint(roots, start, mid, left_poly, M);
    recursive_poly_product_flint(roots, mid + 1, end, right_poly, M);
    
    // FFTW多项式乘法
    poly_multiply_mod_fftw(left_poly, left_deg, right_poly, right_deg, result, M);
    
    // 清理临时数组
    mpz_array_clear(left_poly, left_deg + 1);
    mpz_array_clear(right_poly, right_deg + 1);
    free(left_poly);
    free(right_poly);
}

// -----------------------------
// 公开接口实现（优化+修复逻辑错误）
// -----------------------------

/**
 * 初始化空桶集合
 */
void bucket_init(BucketSet *set, unsigned int n, unsigned int m_bit) {
    if (!set || n == 0 || m_bit == 0) handle_error("bucket_init: invalid parameters");

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = safe_malloc(sizeof(Bucket) * n, "bucket_init: buckets malloc failed");

    for (size_t i = 0; i < n; ++i) {
        bucket_init_single(&set->buckets[i], m_bit);
    }
}

/**
 * 初始化结果桶集合
 */
void result_bucket_init(Result_BucketSet *result_set, unsigned int n) {
    if (!result_set || n == 0) handle_error("result_bucket_init: invalid parameters");
    
    result_set->count = n;
    result_set->result_buckets = safe_malloc(sizeof(Result_Bucket) * n, "result_bucket_init malloc failed");
    
    for (size_t i = 0; i < n; ++i) {
        Result_Bucket *b = &result_set->result_buckets[i];
        // 初始化系数（默认0）
        mpz_array_init(b->coeffs, RESULT_POLY_LEN, 0);
        // 初始化tag（默认0）
        mpz_init(b->tag);
        mpz_set_ui(b->tag, 0);
    }  
}

/**
 * 生成n个随机根桶（复用bucket_init_single，精简逻辑）
 */
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed) {
    if (!set || n == 0 || m_bit == 0) handle_error("bucket_generate: invalid parameters");

    if (seed == 0) seed = (unsigned long)time(NULL);
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = safe_malloc(sizeof(Bucket) * n, "bucket_generate: buckets malloc failed");

    for (size_t i = 0; i < n; ++i) {
        Bucket *b = &set->buckets[i];
        // 复用初始化逻辑
        bucket_init_single(b, m_bit);
        
        // 生成随机tag
        mpz_urandomb(b->tag, state, m_bit);
        // 生成随机根
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_urandomb(b->roots[j], state, m_bit);
        }
    }

    gmp_randclear(state);
}

/**
 * 桶多项式扩展（递归版）
 */
void bucket_expand(BucketSet *set, const mpz_t M) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        Bucket *b = &set->buckets[i];
        
        // 安全分配根指针数组
        mpz_t **roots_array = safe_malloc(sizeof(mpz_t*) * BUCKET_ROOTS, "roots_array malloc failed");
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            roots_array[j] = &b->roots[j];
        }
        
        // 递归计算乘积多项式
        if (BUCKET_ROOTS > 0) {
            recursive_poly_product_flint(roots_array, 0, BUCKET_ROOTS - 1, b->coeffs, M);
        } else {
            mpz_set_ui(b->coeffs[0], 1);
        }
        
        free(roots_array);
    }
}

/**
 * 迭代分治扩展（精简重复逻辑+安全分配）
 */
void bucket_expand_iterative(BucketSet *set, const mpz_t M) {
    if (!set || !set->buckets) return;
    
    for (size_t bucket_idx = 0; bucket_idx < set->count; ++bucket_idx) {
        Bucket *b = &set->buckets[bucket_idx];
        
        // 步骤1：为每个根创建基本多项式
        size_t base_count = BUCKET_ROOTS;
        mpz_t **base_polys = safe_malloc(sizeof(mpz_t*) * base_count, "base_polys malloc failed");
        for (size_t i = 0; i < base_count; i++) {
            base_polys[i] = safe_malloc(sizeof(mpz_t) * LINEAR_POLY_LEN, "base_poly[i] malloc failed");
            mpz_array_init(base_polys[i], LINEAR_POLY_LEN, 0);
            create_linear_poly(base_polys[i], b->roots[i], M);
        }
        
        // 步骤2：迭代合并多项式
        while (base_count > 1) {
            size_t new_count = (base_count + 1) / 2;
            mpz_t **new_polys = safe_malloc(sizeof(mpz_t*) * new_count, "new_polys malloc failed");
            
            for (size_t i = 0; i < new_count; i++) {
                size_t left_idx = 2 * i;
                size_t right_idx = 2 * i + 1;
                
                if (right_idx < base_count) {
                    // 左右多项式乘积：次数2，系数长度3
                    new_polys[i] = safe_malloc(sizeof(mpz_t) * PRODUCT_POLY_LEN_2, "new_poly[i] malloc failed");
                    mpz_array_init(new_polys[i], PRODUCT_POLY_LEN_2, 0);
                    // FFTW乘法合并
                    poly_multiply_mod_fftw(base_polys[left_idx], 1, 
                                         base_polys[right_idx], 1, 
                                         new_polys[i], M);
                    // 清理旧多项式
                    mpz_array_clear(base_polys[left_idx], LINEAR_POLY_LEN);
                    free(base_polys[left_idx]);
                    mpz_array_clear(base_polys[right_idx], LINEAR_POLY_LEN);
                    free(base_polys[right_idx]);
                } else {
                    // 奇数个：复制最后一个多项式
                    new_polys[i] = safe_malloc(sizeof(mpz_t) * LINEAR_POLY_LEN, "new_poly[i] malloc failed");
                    mpz_array_init(new_polys[i], LINEAR_POLY_LEN, 0);
                    mpz_set(new_polys[i][0], base_polys[left_idx][0]);
                    mpz_set(new_polys[i][1], base_polys[left_idx][1]);
                    // 清理旧多项式
                    mpz_array_clear(base_polys[left_idx], LINEAR_POLY_LEN);
                    free(base_polys[left_idx]);
                }
            }
            
            free(base_polys);
            base_polys = new_polys;
            base_count = new_count;
        }
        
        // 步骤3：复制最终结果到桶系数
        if (BUCKET_ROOTS > 0) {
            size_t res_deg = BUCKET_ROOTS; // 乘积多项式次数=根数量
            for (size_t j = 0; j <= res_deg && j < BUCKET_POLY_LEN; j++) {
                mpz_set(b->coeffs[j], base_polys[0][j]);
            }
            // 清理临时多项式
            mpz_array_clear(base_polys[0], res_deg + 1);
            free(base_polys[0]);
            free(base_polys);
        } else {
            mpz_set_ui(b->coeffs[0], 1);
        }
    }
}

/**
 * 桶内根替换操作（修复综合除法核心逻辑错误）
 */
void bucket_replace_root(mpz_t *poly, size_t poly_degree, const mpz_t r_out, 
                         const mpz_t r_in, const mpz_t M) {
    if (!poly || poly_degree == 0) return;

    // 步骤1：构造 (x - r_out) 多项式
    mpz_t linear[LINEAR_POLY_LEN];
    mpz_array_init(linear, LINEAR_POLY_LEN, 0);
    create_linear_poly(linear, r_out, M);
    
    // 步骤2：多项式除法 P(x) / (x - r_out) = Q(x)（修复综合除法逻辑）
    // 安全分配商多项式数组（次数=poly_degree-1，系数长度=poly_degree）
    mpz_t *q = safe_malloc(sizeof(mpz_t) * poly_degree, "q poly malloc failed");
    mpz_array_init(q, poly_degree, 0);
    
    // 【核心修复】综合除法：不修改q[i-1]，仅用其值计算q[i]
    mpz_set(q[0], poly[0]); // 最高次项系数直接复制
    for (size_t i = 1; i < poly_degree; i++) {
        mpz_t temp;
        mpz_init(temp);
        mpz_mul(temp, q[i-1], r_out);    // q[i-1] * r_out（不修改q[i-1]）
        mpz_add(q[i], poly[i], temp);    // q[i] = poly[i] + q[i-1]*r_out
        mpz_mod(q[i], q[i], M);          // 模M
        mpz_clear(temp);
    }
    
    // 步骤3：构造 (x - r_in) 并相乘 Q(x)*(x - r_in)
    create_linear_poly(linear, r_in, M);
    poly_multiply_mod_fftw(q, poly_degree-1, linear, 1, poly, M);
    
    // 清理临时变量
    mpz_array_clear(q, poly_degree);
    free(q);
    mpz_array_clear(linear, LINEAR_POLY_LEN);
}

/**
 * 桶拷贝（深拷贝）
 */
void bucket_copy(Bucket *dest, const Bucket *src) {
    if (!dest || !src) return;

    // 拷贝根
    for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
        mpz_init(dest->roots[j]);
        mpz_set(dest->roots[j], src->roots[j]);
    }

    // 拷贝多项式系数
    for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
        mpz_init(dest->coeffs[j]);
        mpz_set(dest->coeffs[j], src->coeffs[j]);
    }

    // 拷贝tag
    mpz_init(dest->tag);
    mpz_set(dest->tag, src->tag);
    // 拷贝元素数
    dest->element_num = src->element_num;
}

/**
 * 结果桶拷贝（深拷贝）
 */
void result_bucket_copy(Result_Bucket *dest, const Result_Bucket *src) {
    if (!dest || !src) return;

    // 拷贝系数
    for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
        mpz_init(dest->coeffs[j]);
        mpz_set(dest->coeffs[j], src->coeffs[j]);
    }

    // 拷贝tag
    mpz_init(dest->tag);
    mpz_set(dest->tag, src->tag);
}

/**
 * 打印桶根
 */
void bucket_print(const BucketSet *set, size_t bucket_count, size_t roots_per_bucket) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;
    if (roots_per_bucket > BUCKET_ROOTS) roots_per_bucket = BUCKET_ROOTS;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] roots:\n", i);
        for (size_t j = 0; j < roots_per_bucket; ++j)
            gmp_printf("  r[%03zu] = %Zd\n", j, set->buckets[i].roots[j]);
        printf("\n");
    }
}

/**
 * 打印桶多项式系数
 */
void bucket_print_poly(const BucketSet *set, size_t bucket_count, size_t coeffs_to_show) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;
    if (coeffs_to_show > BUCKET_POLY_LEN) coeffs_to_show = BUCKET_POLY_LEN;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] polynomial coefficients (deg: %d):\n", i, BUCKET_ROOTS);
        for (size_t j = 0; j < coeffs_to_show; ++j) {
            gmp_printf("  coeff[%03zu] = %Zd\n", j, set->buckets[i].coeffs[j]);
        }
        printf("\n");
    }
}

/**
 * 释放桶内存
 */
void bucket_free(BucketSet *set) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        // 释放根
        mpz_array_clear(set->buckets[i].roots, BUCKET_ROOTS);
        // 释放系数
        mpz_array_clear(set->buckets[i].coeffs, BUCKET_POLY_LEN);
        // 释放tag
        mpz_clear(set->buckets[i].tag);
    }

    free(set->buckets);
    set->buckets = NULL;
    set->count = 0;
}

/**
 * 释放结果桶内存
 */
void result_bucket_free(Result_BucketSet *set) {
    if (!set || !set->result_buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        // 释放系数
        mpz_array_clear(set->result_buckets[i].coeffs, RESULT_POLY_LEN);
        // 释放tag
        mpz_clear(set->result_buckets[i].tag);
    }

    free(set->result_buckets);
    set->result_buckets = NULL;
    set->count = 0;
}
