#ifndef BEAVER_H
#define BEAVER_H

#include <gmp.h>
#include <stddef.h>

// 生成降幂序的 Beaver 三元组多项式 A(x), B(x), C(x)=A(x)*B(x)
void beaver_generate(mpz_t **A,
                     mpz_t **B,
                     mpz_t **C,
                     size_t n,
                     unsigned int m_bit,
                     unsigned long seed);

// 打印多项式系数（降幂序）
void beaver_print(const char *name, mpz_t *P, size_t k);

// 释放多项式内存
void beaver_free(mpz_t *A, mpz_t *B, mpz_t *C, size_t n);

#endif // BEAVER_H

