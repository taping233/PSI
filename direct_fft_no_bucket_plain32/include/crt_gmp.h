#ifndef CRT_GMP_H
#define CRT_GMP_H

#include <gmp.h>
#include <stddef.h>

// 使用 n 个模数与对应余数，通过中国剩余定理还原模 M 的整数
// 输入：
//   remainders[i] : x ≡ r_i (mod m_i)
//   moduli[i]     : m_i (两两互素)
// 输出：
//   result        : 满足 x ≡ r_i (mod m_i)， 0 <= x < M
//   M_out         : (可选) 输出模数积 M = Π m_i
//
// 要求：remainders 和 moduli 都是 mpz_t 数组（长度 n），已经初始化。
void crt_combine(mpz_t result,
                 mpz_t M_out,
                 mpz_t *remainders,
                 mpz_t *moduli,
                 size_t n);

#endif // CRT_GMP_H

