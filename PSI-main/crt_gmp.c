#include "crt_gmp.h"
#include <stdlib.h>
#include <stdio.h>

// -----------------------------
// 【模块化优化】抽离通用辅助函数
// -----------------------------

/**
 * 统一错误处理函数：打印错误信息，清理临时mpz_t变量后退出
 * @param msg 错误描述
 * @param vars 需清理的mpz_t变量列表（以NULL结尾）
 */
static void crt_handle_error(const char *msg, mpz_t *vars) {
    fprintf(stderr, "CRT Error: %s\n", msg);
    // 清理所有传入的临时mpz_t变量
    if (vars) {
        for (int i = 0; vars[i] != NULL; i++) {
            mpz_clear(vars[i]);
        }
    }
    exit(EXIT_FAILURE);
}

/**
 * 检查模数是否合法（必须>0）
 * @param mod 模数
 * @param idx 模数索引（用于错误提示）
 * @return 合法返回1，非法返回0
 */
static int crt_check_modulus(const mpz_t mod, size_t idx) {
    if (mpz_sgn(mod) <= 0) {
        char mod_str[256];
        mpz_get_str(mod_str, 10, mod);
        fprintf(stderr, "CRT Error: 模数[%zu] = %s 非法（必须为正整数）\n", idx, mod_str);
        return 0;
    }
    return 1;
}

// -----------------------------
// 核心CRT合并实现（优化后）
// -----------------------------
void crt_combine(mpz_t result,
                 mpz_t M_out,
                 mpz_t *remainders,
                 mpz_t *moduli,
                 size_t n)
{
    // 1. 基础参数合法性检查（避免空指针/无效输入）
    if (!result) {
        crt_handle_error("result指针为空", NULL);
    }
    if (n == 0) {
        mpz_set_ui(result, 0);
        if (M_out) mpz_set_ui(M_out, 1);
        return;
    }
    if (!remainders || !moduli) {
        crt_handle_error("remainders或moduli数组为空", NULL);
    }

    // 2. 初始化临时变量（统一管理，便于错误清理）
    mpz_t product_M;  // 累计模数乘积 M = m0*m1*...*mi
    mpz_t temp;       // 临时计算变量
    mpz_t inv;        // 模逆元
    mpz_t delta;      // 差值 (r_i - result) mod m_i
    mpz_t term;       // 待累加项 M_prev * t
    mpz_inits(product_M, temp, inv, delta, term, NULL);

    // 用于错误清理的变量列表（以NULL结尾）
    mpz_t cleanup_vars[] = {product_M, temp, inv, delta, term, NULL};

    // 3. 检查第一个模数合法性
    if (!crt_check_modulus(moduli[0], 0)) {
        crt_handle_error("第一个模数非法", cleanup_vars);
    }

    // 4. 初始化：result = r0, product_M = m0
    mpz_mod(result, remainders[0], moduli[0]);  // 确保余数在合法范围
    mpz_set(product_M, moduli[0]);

    // 5. 逐步合并后续模数和余数
    for (size_t i = 1; i < n; ++i) {
        // 检查当前模数合法性
        if (!crt_check_modulus(moduli[i], i)) {
            crt_handle_error("模数非法", cleanup_vars);
        }

        // 步骤1：计算差值 delta = (r_i - result) mod m_i
        mpz_sub(delta, remainders[i], result);
        mpz_mod(delta, delta, moduli[i]);  // 确保delta非负

        // 步骤2：计算 product_M 在模 m_i 下的逆元
        if (mpz_invert(inv, product_M, moduli[i]) == 0) {
            char m_prev_str[256], m_i_str[256];
            mpz_get_str(m_prev_str, 10, product_M);
            mpz_get_str(m_i_str, 10, moduli[i]);
            fprintf(stderr, "CRT Error: 累计模数乘积 %s 与模数[%zu] %s 不互素！\n",
                    m_prev_str, i, m_i_str);
            crt_handle_error("模数不互素，无法计算逆元", cleanup_vars);
        }

        // 步骤3：计算 t = delta * inv mod m_i
        mpz_mul(temp, delta, inv);
        mpz_mod(temp, temp, moduli[i]);

        // 步骤4：累加项 term = product_M * t
        mpz_mul(term, product_M, temp);
        mpz_add(result, result, term);

        // 步骤5：更新累计模数乘积
        mpz_mul(product_M, product_M, moduli[i]);

        // 步骤6：确保结果在 [0, product_M) 范围内
        mpz_mod(result, result, product_M);
    }

    // 6. 输出累计模数乘积（若M_out非空）
    if (M_out) {
        mpz_set(M_out, product_M);
    }

    // 7. 清理所有临时变量
    mpz_clears(product_M, temp, inv, delta, term, NULL);
}
