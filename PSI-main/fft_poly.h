#ifndef FFT_POLY_H
#define FFT_POLY_H

#include <stddef.h>
#include <complex.h>

typedef long double real_t;
typedef _Complex long double complex_t;

// 迭代 Cooley–Tukey FFT / IFFT
// invert = 0 做 FFT；invert = 1 做 IFFT（自动除以 n）
void fft(complex_t *a, size_t n, int invert);

// 经典（未缩放）FFT 多项式卷积，结果四舍五入到整数
void poly_multiply(const real_t *A, size_t n,
                   const real_t *B, size_t m,
                   real_t *result);

// “整数型”FFT：按基数 q 先缩放再恢复（a/q 与 b/q 做 FFT；逆变换后乘 q^2 再就近取整）
void poly_multiply_scaled(const real_t *A, size_t n,
                          const real_t *B, size_t m,
                          real_t q,
                          real_t *result);

#endif // FFT_POLY_H

