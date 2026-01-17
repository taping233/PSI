#include "bucket.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <fftw3.h>
#include <gmp.h>

// -----------------------------
// 辅助函数：计算大于等于n的最小2的幂次（FFTW高效长度）
// -----------------------------
static size_t next_power_of_two(size_t n) {
    if (n == 0) return 1;
    size_t power = 1;
    while (power < n) power <<= 1;
    return power;
}

// -----------------------------
// 核心：FFTW实现多项式乘法（mpz_t数组）+ 模M运算
// a/b: 降幂系数数组（a[0]最高次项），deg_a/deg_b: 多项式次数
// result: 输出结果数组（需预分配足够空间），M: 模数
// -----------------------------
static void poly_multiply_mod_fftw(const mpz_t *a, size_t deg_a,
                                   const mpz_t *b, size_t deg_b,
                                   mpz_t *result, const mpz_t M) {
    // 1. 计算FFT所需长度（避免循环卷积）
    size_t N = next_power_of_two(deg_a + deg_b + 1);
    
    // 2. 分配FFTW复数数组（实部存系数，虚部为0）
    fftw_complex *in1 = fftw_malloc(sizeof(fftw_complex) * N);
    fftw_complex *in2 = fftw_malloc(sizeof(fftw_complex) * N);
    if (!in1 || !in2) {
        fprintf(stderr, "poly_multiply_mod_fftw: FFTW malloc failed\n");
        exit(EXIT_FAILURE);
    }
    
    // 3. 初始化复数数组（mpz_t转double）
    for (size_t i = 0; i < N; i++) {
        in1[i][0] = (i <= deg_a) ? mpz_get_d(a[i]) : 0.0;
        in1[i][1] = 0.0;
        in2[i][0] = (i <= deg_b) ? mpz_get_d(b[i]) : 0.0;
        in2[i][1] = 0.0;
    }
    
    // 4. 创建FFTW计划（正向+逆向）
    fftw_plan plan1 = fftw_plan_dft_1d(N, in1, in1, FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_plan plan2 = fftw_plan_dft_1d(N, in2, in2, FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_plan plan_inv = fftw_plan_dft_1d(N, in1, in1, FFTW_BACKWARD, FFTW_ESTIMATE);
    
    // 5. 执行正向FFT
    fftw_execute(plan1);
    fftw_execute(plan2);
    
    // 6. 频域相乘（复数乘法：(a+bi)(c+di) = (ac-bd)+(ad+bc)i）
    for (size_t i = 0; i < N; i++) {
        double re1 = in1[i][0], im1 = in1[i][1];
        double re2 = in2[i][0], im2 = in2[i][1];
        in1[i][0] = re1 * re2 - im1 * im2;  // 实部
        in1[i][1] = re1 * im2 + im1 * re2;  // 虚部
    }
    
    // 7. 逆FFT + 缩放（FFTW逆变换结果需除以N）
    fftw_execute(plan_inv);
    for (size_t i = 0; i < N; i++) {
        in1[i][0] /= N;
        in1[i][1] /= N;  // 虚部理论上趋近于0，可忽略
    }
    
    // 8. 结果转mpz_t + 模M运算（四舍五入消除浮点误差）
    for (size_t i = 0; i < deg_a + deg_b + 1; i++) {
        mpz_set_d(result[i], round(in1[i][0]));  // 取整
        mpz_mod(result[i], result[i], M);        // 模M
        if (mpz_sgn(result[i]) < 0) {            // 确保非负
            mpz_add(result[i], result[i], M);
        }
    }
    
    // 9. 清理FFTW资源
    fftw_destroy_plan(plan1);
    fftw_destroy_plan(plan2);
    fftw_destroy_plan(plan_inv);
    fftw_free(in1);
    fftw_free(in2);
}

// -----------------------------
// 辅助：构造基本多项式 (x - r) → mpz_t数组（降幂）
// poly: 输出数组（长度2），r: 根，M: 模数
// -----------------------------
static void create_linear_poly(mpz_t *poly, const mpz_t r, const mpz_t M) {
    mpz_set_ui(poly[0], 1);          // x^1 系数：1
    mpz_neg(poly[1], r);             // 常数项：-r
    mpz_mod(poly[1], poly[1], M);    // 模M
    if (mpz_sgn(poly[1]) < 0) {
        mpz_add(poly[1], poly[1], M);
    }
}

// -----------------------------
// 递归分治计算多项式乘积（适配FFTW，接口兼容原FLINT版本）
// roots: 根数组，start/end: 分治区间，result: 输出多项式（mpz_t数组），M: 模数
// -----------------------------
static void recursive_poly_product_flint(mpz_t **roots, size_t start, size_t end,
                                         mpz_t *result, const mpz_t M) {
    if (start == end) {
        // 基本情况：单个根 → (x - r)，结果数组长度2
        create_linear_poly(result, *roots[start], M);
        return;
    }
    
    size_t mid = start + (end - start) / 2;
    size_t left_deg = mid - start + 1;   // 左子多项式次数
    size_t right_deg = end - (mid + 1) + 1; // 右子多项式次数
    
    // 分配左右子多项式数组（次数+1个系数）
    mpz_t *left_poly = malloc(sizeof(mpz_t) * (left_deg + 1));
    mpz_t *right_poly = malloc(sizeof(mpz_t) * (right_deg + 1));
    if (!left_poly || !right_poly) {
        fprintf(stderr, "recursive_poly_product_flint: malloc failed\n");
        exit(EXIT_FAILURE);
    }
    for (size_t i = 0; i <= left_deg; i++) mpz_init(left_poly[i]);
    for (size_t i = 0; i <= right_deg; i++) mpz_init(right_poly[i]);
    
    // 递归计算左右子多项式
    recursive_poly_product_flint(roots, start, mid, left_poly, M);
    recursive_poly_product_flint(roots, mid + 1, end, right_poly, M);
    
    // FFTW多项式乘法
    poly_multiply_mod_fftw(left_poly, left_deg, right_poly, right_deg, result, M);
    
    // 清理临时数组
    for (size_t i = 0; i <= left_deg; i++) mpz_clear(left_poly[i]);
    for (size_t i = 0; i <= right_deg; i++) mpz_clear(right_poly[i]);
    free(left_poly);
    free(right_poly);
}

// -----------------------------
// 初始化空桶集合（适配mpz_t，接口不变）
// -----------------------------
void bucket_init(BucketSet *set, unsigned int n, unsigned int m_bit) {
    if (!set || n == 0 || m_bit == 0) {
        fprintf(stderr, "bucket_init: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = malloc(sizeof(Bucket) * n);
    if (!set->buckets) {
        fprintf(stderr, "bucket_init: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < n; ++i) {
        Bucket *b = &set->buckets[i];

        // 初始化根、系数、tag（mpz_t）
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_init(b->roots[j]);
            mpz_set_ui(b->roots[j], 0);
        }
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(b->coeffs[j]);
            mpz_set_ui(b->coeffs[j], 0);
        }
        mpz_init(b->tag);
        mpz_set_ui(b->tag, 0);
        b->element_num = 0;
    }
}

// -----------------------------
// 初始化结果桶集合（适配mpz_t，接口不变）
// -----------------------------
void result_bucket_init(Result_BucketSet *result_set, unsigned int n) {
    if (!result_set || n == 0) {
        fprintf(stderr, "result_bucket_init: invalid parameters\n");
        exit(EXIT_FAILURE);
    }
    
    result_set->count = n;
    result_set->result_buckets = malloc(sizeof(Result_Bucket) * n);
    if (!result_set->result_buckets) {
        fprintf(stderr, "result_bucket_init: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    for (size_t i = 0; i < n; ++i) {
        Result_Bucket *b = &result_set->result_buckets[i];
        // 初始化结果多项式系数、tag
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_init(b->coeffs[j]);
            mpz_set_ui(b->coeffs[j], 0);
        }
        mpz_init(b->tag);
        mpz_set_ui(b->tag, 0);
    }  
}

// -----------------------------
// 生成n个随机根桶（GMP随机数，接口不变）
// -----------------------------
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed) {
    if (!set || n == 0 || m_bit == 0) {
        fprintf(stderr, "bucket_generate: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0) seed = (unsigned long)time(NULL);
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = malloc(sizeof(Bucket) * n);
    if (!set->buckets) {
        fprintf(stderr, "bucket_generate: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < n; ++i) {
        Bucket *b = &set->buckets[i];
        // 初始化tag
        mpz_init(b->tag);
        mpz_urandomb(b->tag, state, m_bit); // 随机tag
        
        // 初始化根（m_bit位随机数）
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_init(b->roots[j]);
            mpz_urandomb(b->roots[j], state, m_bit);
        }
        
        // 初始化系数数组
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(b->coeffs[j]);
            mpz_set_ui(b->coeffs[j], 0);
        }
        b->element_num = 0;
    }

    gmp_randclear(state);
}

// -----------------------------
// 桶多项式扩展（分治+FFTW，接口不变）
// -----------------------------
void bucket_expand(BucketSet *set, const mpz_t M) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        Bucket *b = &set->buckets[i];
        
        // 根指针数组（适配分治函数）
        mpz_t **roots_array = malloc(sizeof(mpz_t*) * BUCKET_ROOTS);
        if (!roots_array) {
            fprintf(stderr, "bucket_expand: memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            roots_array[j] = &b->roots[j];
        }
        
        // 递归计算乘积多项式 ∏(x - r_i)
        if (BUCKET_ROOTS > 0) {
            recursive_poly_product_flint(roots_array, 0, BUCKET_ROOTS - 1, 
                                         b->coeffs, M);
        } else {
            // 无根系数：多项式为1
            mpz_set_ui(b->coeffs[0], 1);
        }
        
        free(roots_array);
    }
}

// -----------------------------
// 迭代分治扩展（FFTW版本，接口不变）
// -----------------------------
void bucket_expand_iterative(BucketSet *set, const mpz_t M) {
    if (!set || !set->buckets) return;
    
    for (size_t bucket_idx = 0; bucket_idx < set->count; ++bucket_idx) {
        Bucket *b = &set->buckets[bucket_idx];
        
        // 步骤1：为每个根创建基本多项式 (x - r_i)（数组长度2）
        size_t base_count = BUCKET_ROOTS;
        mpz_t **base_polys = malloc(sizeof(mpz_t*) * base_count);
        if (!base_polys) {
            fprintf(stderr, "bucket_expand_iterative: malloc failed\n");
            exit(EXIT_FAILURE);
        }
        for (size_t i = 0; i < base_count; i++) {
            base_polys[i] = malloc(sizeof(mpz_t) * 2);
            mpz_init(base_polys[i][0]);
            mpz_init(base_polys[i][1]);
            create_linear_poly(base_polys[i], b->roots[i], M);
        }
        
        // 步骤2：迭代合并多项式
        while (base_count > 1) {
            size_t new_count = (base_count + 1) / 2;
            mpz_t **new_polys = malloc(sizeof(mpz_t*) * new_count);
            if (!new_polys) {
                fprintf(stderr, "bucket_expand_iterative: malloc failed\n");
                exit(EXIT_FAILURE);
            }
            
            for (size_t i = 0; i < new_count; i++) {
                size_t left_idx = 2 * i;
                size_t right_idx = 2 * i + 1;
                
                if (right_idx < base_count) {
                    // 左右多项式次数均为1，乘积次数为2（数组长度3）
                    new_polys[i] = malloc(sizeof(mpz_t) * 3);
                    for (size_t j = 0; j < 3; j++) mpz_init(new_polys[i][j]);
                    // FFTW乘法合并
                    poly_multiply_mod_fftw(base_polys[left_idx], 1, 
                                         base_polys[right_idx], 1, 
                                         new_polys[i], M);
                    // 清理旧多项式
                    mpz_clear(base_polys[left_idx][0]);
                    mpz_clear(base_polys[left_idx][1]);
                    free(base_polys[left_idx]);
                    mpz_clear(base_polys[right_idx][0]);
                    mpz_clear(base_polys[right_idx][1]);
                    free(base_polys[right_idx]);
                } else {
                    // 奇数个：直接复制最后一个多项式
                    new_polys[i] = malloc(sizeof(mpz_t) * 2);
                    mpz_init(new_polys[i][0]);
                    mpz_init(new_polys[i][1]);
                    mpz_set(new_polys[i][0], base_polys[left_idx][0]);
                    mpz_set(new_polys[i][1], base_polys[left_idx][1]);
                    // 清理旧多项式
                    mpz_clear(base_polys[left_idx][0]);
                    mpz_clear(base_polys[left_idx][1]);
                    free(base_polys[left_idx]);
                }
            }
            
            free(base_polys);
            base_polys = new_polys;
            base_count = new_count;
        }
        
        // 步骤3：将最终结果复制到桶的系数数组
        if (BUCKET_ROOTS > 0) {
            size_t res_deg = BUCKET_ROOTS; // 乘积多项式次数=根数量
            for (size_t j = 0; j <= res_deg && j < BUCKET_POLY_LEN; j++) {
                mpz_set(b->coeffs[j], base_polys[0][j]);
            }
            // 清理最后一个临时多项式
            for (size_t j = 0; j <= res_deg; j++) mpz_clear(base_polys[0][j]);
            free(base_polys[0]);
            free(base_polys);
        } else {
            mpz_set_ui(b->coeffs[0], 1);
        }
    }
}

// -----------------------------
// 桶内根替换操作（接口不变，适配mpz_t数组）
// -----------------------------
void bucket_replace_root(mpz_t *poly, size_t degree, const mpz_t r_out, 
                         const mpz_t r_in, const mpz_t M) {
    if (!poly || degree == 0) return;

    // 步骤1：构造 (x - r_out) 多项式
    mpz_t linear[2];
    mpz_init(linear[0]);
    mpz_init(linear[1]);
    create_linear_poly(linear, r_out, M);
    
    // 步骤2：多项式除法 P(x) / (x - r_out) = Q(x)（综合除法）
    mpz_t *q = malloc(sizeof(mpz_t) * degree);
    for (size_t i = 0; i < degree; i++) mpz_init(q[i]);
    mpz_set(q[0], poly[0]); // 最高次项系数直接复制
    for (size_t i = 1; i < degree; i++) {
        mpz_mul(q[i-1], q[i-1], r_out);
        mpz_add(q[i], poly[i], q[i-1]);
        mpz_mod(q[i], q[i], M);
    }
    
    // 步骤3：构造 (x - r_in) 并相乘 Q(x)*(x - r_in)
    create_linear_poly(linear, r_in, M);
    poly_multiply_mod_fftw(q, degree-1, linear, 1, poly, M);
    
    // 清理临时变量
    for (size_t i = 0; i < degree; i++) mpz_clear(q[i]);
    free(q);
    mpz_clear(linear[0]);
    mpz_clear(linear[1]);
}

// -----------------------------
// 桶拷贝（深拷贝，接口不变）
// -----------------------------
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

    // 拷贝tag和元素数
    mpz_init(dest->tag);
    mpz_set(dest->tag, src->tag);
    dest->element_num = src->element_num;
}

// -----------------------------
// 结果桶拷贝（深拷贝，接口不变）
// -----------------------------
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

// -----------------------------
// 打印桶根（接口不变）
// -----------------------------
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

// -----------------------------
// 打印桶多项式系数（接口不变）
// -----------------------------
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

// -----------------------------
// 释放桶内存（接口不变）
// -----------------------------
void bucket_free(BucketSet *set) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        // 释放根
        for (size_t j = 0; j < BUCKET_ROOTS; ++j)
            mpz_clear(set->buckets[i].roots[j]);
        // 释放系数
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j)
            mpz_clear(set->buckets[i].coeffs[j]);
        // 释放tag
        mpz_clear(set->buckets[i].tag);
    }

    free(set->buckets);
    set->buckets = NULL;
    set->count = 0;
}

// -----------------------------
// 释放结果桶内存（接口不变）
// -----------------------------
void result_bucket_free(Result_BucketSet *set) {
    if (!set || !set->result_buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        // 释放系数
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
            mpz_clear(set->result_buckets[i].coeffs[j]);
        // 释放tag
        mpz_clear(set->result_buckets[i].tag);
    }

    free(set->result_buckets);
    set->result_buckets = NULL;
    set->count = 0;
}
