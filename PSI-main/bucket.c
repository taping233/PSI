#include "bucket.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <flint/flint.h>
#include <flint/fmpz.h>
#include <flint/fmpz_poly.h>

// -----------------------------
// 辅助函数：FLINT 多项式乘法（替代朴素实现）
// -----------------------------
static void poly_multiply_mod_flint(const fmpz_poly_t a, const fmpz_poly_t b,
                                   fmpz_poly_t result, const fmpz_t M) {
    fmpz_poly_mul(result, a, b);  // FLINT 高效多项式乘法
    fmpz_poly_scalar_mod_fmpz(result, result, M);  // 模 M 运算
}

// -----------------------------
// 辅助函数：递归分治计算多项式乘积（FLINT 版本）
// -----------------------------
static void recursive_poly_product_flint(fmpz_t **roots, size_t start, size_t end,
                                         fmpz_poly_t result, const fmpz_t M) { 
    if (start == end) {
        // 基本情况：单个根，返回 (x - root)
        fmpz_poly_zero(result);
        fmpz_poly_set_coeff_ui(result, 1, 1);  // x^1 系数为 1
        fmpz_poly_set_coeff_fmpz(result, 0, roots[start][0]);
        fmpz_poly_neg(result, result);  // 常数项为 -root
        fmpz_poly_scalar_mod_fmpz(result, result, M);
        return;
    }
    
    size_t mid = start + (end - start) / 2;
    fmpz_poly_t left_poly, right_poly;
    fmpz_poly_init(left_poly);
    fmpz_poly_init(right_poly);
    
    // 递归计算左右子多项式
    recursive_poly_product_flint(roots, start, mid, left_poly, M);
    recursive_poly_product_flint(roots, mid + 1, end, right_poly, M);
    
    // 计算乘积（FLINT 优化）
    poly_multiply_mod_flint(left_poly, right_poly, result, M);
    
    // 清理临时多项式
    fmpz_poly_clear(left_poly);
    fmpz_poly_clear(right_poly);
}

// -----------------------------
// 初始化空桶集合（不生成随机根，FLINT 适配）
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

        // 初始化多项式根与系数（FLINT fmpz 类型）
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            fmpz_init(b->roots[j]);
            fmpz_set_ui(b->roots[j], 0);
        }
        fmpz_poly_init(b->poly);  // 替换原 coeffs 数组，使用 FLINT 多项式结构

        // 初始化随机标识和元素计数
        fmpz_init(b->tag);
        fmpz_set_ui(b->tag, 0);
        b->element_num = 0;
    }
}

// -----------------------------
// 初始化结果桶集合（不生成随机根，FLINT 适配）
// -----------------------------
void result_bucket_init(Result_BucketSet *result_set, unsigned int n){
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

        // 初始化结果多项式（FLINT fmpz_poly 类型）
        fmpz_poly_init(b->poly);
        fmpz_poly_zero(b->poly);

        // 初始化随机标识
        fmpz_init(b->tag);
        fmpz_set_ui(b->tag, 0);
    }  
}

// -----------------------------
// 初始化桶集合（生成随机根，FLINT 版本）
// -----------------------------
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed) {
    if (!set || n == 0 || m_bit == 0) {
        fprintf(stderr, "bucket_generate: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0)
        seed = (unsigned long)time(NULL);
    flint_rand_t state;
    flint_randinit(state);
    flint_randseed_ui(state, seed);

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = malloc(sizeof(Bucket) * n);
    if (!set->buckets) {
        fprintf(stderr, "bucket_generate: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    fmpz_t temp;
    fmpz_init(temp);

    for (size_t i = 0; i < n; ++i) {
        Bucket *b = &set->buckets[i];
        // 初始化桶随机标识
        fmpz_init(b->tag);
        // 初始化根与多项式
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            fmpz_init(b->roots[j]);
            fmpz_randbits(temp, state, m_bit);  // FLINT 随机数生成
            fmpz_set(b->roots[j], temp);
        }
        fmpz_poly_init(b->poly);
        fmpz_poly_zero(b->poly);
    }

    fmpz_clear(temp);
    flint_randclear(state);
}

// -----------------------------
// 桶多项式扩展（分治多样法，FLINT 优化）
// -----------------------------
void bucket_expand(BucketSet *set, const fmpz_t M) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        Bucket *b = &set->buckets[i];
        
        // 将根的指针放入数组，便于分治处理
        fmpz_t **roots_array = malloc(sizeof(fmpz_t*) * BUCKET_ROOTS);
        if (!roots_array) {
            fprintf(stderr, "bucket_expand: memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            roots_array[j] = &b->roots[j];
        }
        
        // FLINT 多项式存储结果
        fmpz_poly_t result_poly;
        fmpz_poly_init(result_poly);
        
        // 使用分治法计算多项式乘积 ∏(x - r_i)
        if (BUCKET_ROOTS > 0) {
            recursive_poly_product_flint(roots_array, 0, BUCKET_ROOTS - 1, 
                                         result_poly, M);
        } else {
            // 如果没有根，多项式为1
            fmpz_poly_set_ui(result_poly, 1);
        }
        
        // 将结果复制到桶的多项式
        fmpz_poly_set(b->poly, result_poly);
        
        // 清理临时空间
        fmpz_poly_clear(result_poly);
        free(roots_array);
    }
}

// -----------------------------
// 优化版本：迭代分治（FLINT 版本，减少递归开销）
// -----------------------------
void bucket_expand_iterative(BucketSet *set, const fmpz_t M) {
    if (!set || !set->buckets) return;
    
    for (size_t bucket_idx = 0; bucket_idx < set->count; ++bucket_idx) {
        Bucket *b = &set->buckets[bucket_idx];
        
        // 为每个根创建基本多项式 (x - r_i)
        fmpz_poly_t *base_polys = malloc(sizeof(fmpz_poly_t) * BUCKET_ROOTS);
        if (!base_polys) {
            fprintf(stderr, "bucket_expand_iterative: memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        
        for (size_t i = 0; i < BUCKET_ROOTS; ++i) {
            fmpz_poly_init(base_polys[i]);
            fmpz_poly_set_coeff_ui(base_polys[i], 1, 1);  // x^1 系数
            fmpz_poly_set_coeff_fmpz(base_polys[i], 0, b->roots[i]);
            fmpz_poly_neg(base_polys[i], base_polys[i]);  // 常数项 -r_i
            fmpz_poly_scalar_mod_fmpz(base_polys[i], base_polys[i], M);
        }
        
        // 迭代合并多项式
        size_t current_count = BUCKET_ROOTS;
        while (current_count > 1) {
            size_t new_count = (current_count + 1) / 2;
            fmpz_poly_t *new_polys = malloc(sizeof(fmpz_poly_t) * new_count);
            if (!new_polys) {
                fprintf(stderr, "bucket_expand_iterative: memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            
            for (size_t i = 0; i < new_count; ++i) {
                fmpz_poly_init(new_polys[i]);
                size_t left_idx = 2 * i;
                size_t right_idx = 2 * i + 1;
                
                if (right_idx < current_count) {
                    // FLINT 高效合并两个多项式
                    poly_multiply_mod_flint(base_polys[left_idx], base_polys[right_idx],
                                           new_polys[i], M);
                    // 清理旧多项式
                    fmpz_poly_clear(base_polys[left_idx]);
                    fmpz_poly_clear(base_polys[right_idx]);
                } else {
                    // 奇数情况，直接复制最后一个多项式
                    fmpz_poly_set(new_polys[i], base_polys[left_idx]);
                    fmpz_poly_clear(base_polys[left_idx]);
                }
            }
            
            free(base_polys);
            base_polys = new_polys;
            current_count = new_count;
        }
        
        // 将结果复制到桶的多项式
        if (BUCKET_ROOTS > 0) {
            fmpz_poly_set(b->poly, base_polys[0]);
            fmpz_poly_clear(base_polys[0]);
            free(base_polys);
        } else {
            // 没有根，多项式为1
            fmpz_poly_set_ui(b->poly, 1);
        }
    }
}

// -----------------------------
// 桶打印函数（FLINT 版本）
// -----------------------------
void bucket_print(const BucketSet *set, size_t bucket_count, size_t roots_per_bucket) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;
    if (roots_per_bucket > BUCKET_ROOTS) roots_per_bucket = BUCKET_ROOTS;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] roots:\n", i);
        for (size_t j = 0; j < roots_per_bucket; ++j)
            flint_printf("  r[%03zu] = %Zd\n", j, set->buckets[i].roots[j]);
        printf("\n");
    }
}

// -----------------------------
// 桶多项式打印函数（FLINT 版本）
// -----------------------------
void bucket_print_poly(const BucketSet *set, size_t bucket_count) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] polynomial:\n", i);
        flint_printf("  ");
        fmpz_poly_print_pretty(set->buckets[i].poly, "x");
        printf("\n\n");
    }
}

// -----------------------------
// 桶内存释放（FLINT 版本）
// -----------------------------
void bucket_free(BucketSet *set) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        for (size_t j = 0; j < BUCKET_ROOTS; ++j)
            fmpz_clear(set->buckets[i].roots[j]);
        fmpz_poly_clear(set->buckets[i].poly);  // 清理 FLINT 多项式
        fmpz_clear(set->buckets[i].tag); 
    }

    free(set->buckets);
    set->buckets = NULL;
    set->count = 0;
}

// -----------------------------
// 结果桶内存释放（FLINT 版本）
// -----------------------------
void result_bucket_free(Result_BucketSet *set) {
    if (!set || !set->result_buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        fmpz_poly_clear(set->result_buckets[i].poly);
        fmpz_clear(set->result_buckets[i].tag);
    }

    free(set->result_buckets);
    set->result_buckets = NULL;
    set->count = 0;
}

// -----------------------------
// 桶内根替换操作（FLINT 优化版本）
// -----------------------------
void bucket_replace_root(fmpz_poly_t poly, const fmpz_t r_out, const fmpz_t r_in,
                         const fmpz_t M) {
    if (!poly || fmpz_poly_is_zero(poly)) return;

    fmpz_poly_t q, linear, new_poly;
    fmpz_poly_init(q);
    fmpz_poly_init(linear);
    fmpz_poly_init(new_poly);

    // 1. 构造 (x - r_out) 并执行多项式除法：Q(x) = P(x) / (x - r_out)
    fmpz_poly_set_coeff_ui(linear, 1, 1);
    fmpz_poly_set_coeff_fmpz(linear, 0, r_out);
    fmpz_poly_neg(linear, linear);
    fmpz_poly_divrem(q, NULL, poly, linear);  // FLINT 多项式除法（无余数检查）
    fmpz_poly_scalar_mod_fmpz(q, q, M);

    // 2. 构造 (x - r_in) 并执行乘法：P'(x) = Q(x) * (x - r_in)
    fmpz_poly_zero(linear);
    fmpz_poly_set_coeff_ui(linear, 1, 1);
    fmpz_poly_set_coeff_fmpz(linear, 0, r_in);
    fmpz_poly_neg(linear, linear);
    poly_multiply_mod_flint(q, linear, new_poly, M);

    // 3. 更新原多项式
    fmpz_poly_set(poly, new_poly);

    // 清理临时变量
    fmpz_poly_clear(q);
    fmpz_poly_clear(linear);
    fmpz_poly_clear(new_poly);
}

// -----------------------------
// 桶拷贝函数：深拷贝（FLINT 版本）
// -----------------------------
void bucket_copy(Bucket *dest, const Bucket *src) {
    if (!dest || !src) return;

    // 拷贝 roots
    for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
        fmpz_init(dest->roots[j]);
        fmpz_set(dest->roots[j], src->roots[j]);
    }

    // 拷贝多项式
    fmpz_poly_init(dest->poly);
    fmpz_poly_set(dest->poly, src->poly);

    // 拷贝 tag
    fmpz_init(dest->tag);
    fmpz_set(dest->tag, src->tag);

    // 复制其他属性
    dest->element_num = src->element_num;
}

// -----------------------------
// 结果桶拷贝函数：深拷贝（FLINT 版本）
// -----------------------------
void result_bucket_copy(Result_Bucket *dest, const Result_Bucket *src) {
    if (!dest || !src) return;

    // 拷贝多项式
    fmpz_poly_init(dest->poly);
    fmpz_poly_set(dest->poly, src->poly);

    // 拷贝 tag
    fmpz_init(dest->tag);
    fmpz_set(dest->tag, src->tag);
}