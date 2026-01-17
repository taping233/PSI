#ifndef CRT_GMP_H
#define CRT_GMP_H

#include <gmp.h>
#include <stddef.h>

/**
 * 使用中国剩余定理（CRT）合并多个模余结果，还原整数
 * 经典 Garner 逐步合并法实现，要求模数两两互素
 * 
 * 输入：
 *   remainders[i] : 余数，满足 x ≡ remainders[i] (mod moduli[i])
 *   moduli[i]     : 模数（必须两两互素、且为正整数）
 *   n             : 余数/模数数组的长度
 * 输出：
 *   result        : 合并后的结果，满足 0 <= result < M（M为所有模数的乘积）
 *   M_out         : (可选，传NULL则不输出) 所有模数的乘积 M = Π moduli[i]
 * 
 * 要求：
 *   1. remainders 和 moduli 为非空的 mpz_t 数组（长度 n），且已初始化；
 *   2. 模数 moduli[i] 必须两两互素、且大于 0；
 *   3. 余数 remainders[i] 需满足 0 <= remainders[i] < moduli[i]（否则会自动取模）。
 */
void crt_combine(mpz_t result,
                 mpz_t M_out,
                 mpz_t *remainders,
                 mpz_t *moduli,
                 size_t n);

#endif // CRT_GMP_H
