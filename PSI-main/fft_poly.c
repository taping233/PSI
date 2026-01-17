#include "fft_poly.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327950288L
#endif

static void bit_reverse_permute(complex_t *a, size_t n) {
    size_t j = 0;
    for (size_t i = 1; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            complex_t t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}

void fft(complex_t *a, size_t n, int invert) {
    bit_reverse_permute(a, n);

    for (size_t len = 2; len <= n; len <<= 1) {
        real_t ang = 2.0L * M_PI / (real_t)len * (invert ? -1.0L : 1.0L);
        complex_t wlen = cosl(ang) + sinl(ang) * I;
        for (size_t i = 0; i < n; i += len) {
            complex_t w = 1.0L + 0.0L*I;
            for (size_t j = 0; j < len/2; ++j) {
                complex_t u = a[i + j];
                complex_t v = a[i + j + len/2] * w;
                a[i + j] = u + v;
                a[i + j + len/2] = u - v;
                w *= wlen;
            }
        }
    }
    if (invert) {
        for (size_t i = 0; i < n; ++i) a[i] /= (real_t)n;
    }
}

static size_t next_pow2(size_t x) {
    size_t n = 1;
    while (n < x) n <<= 1;
    return n;
}

void poly_multiply(const real_t *A, size_t n,
                   const real_t *B, size_t m,
                   real_t *result) {
    size_t N = next_pow2(n + m - 1);
    complex_t *fa = calloc(N, sizeof(complex_t));
    complex_t *fb = calloc(N, sizeof(complex_t));
    if (!fa || !fb) { fprintf(stderr, "OOM\n"); exit(1); }

    for (size_t i = 0; i < n; ++i) fa[i] = A[i];
    for (size_t i = 0; i < m; ++i) fb[i] = B[i];

    fft(fa, N, 0);
    fft(fb, N, 0);
    for (size_t i = 0; i < N; ++i) fa[i] *= fb[i];
    fft(fa, N, 1);

    for (size_t i = 0; i < n + m - 1; ++i) result[i] = roundl(creall(fa[i]));

    free(fa); free(fb);
}

// “整数型”FFT：先缩放，再恢复
void poly_multiply_scaled(const real_t *A, size_t n,
                          const real_t *B, size_t m,
                          real_t q,
                          real_t *result) {
    size_t N = next_pow2(n + m - 1);
    complex_t *fa = calloc(N, sizeof(complex_t));
    complex_t *fb = calloc(N, sizeof(complex_t));
    if (!fa || !fb) { fprintf(stderr, "OOM\n"); exit(1); }

    // 1,2) 用 a/q, b/q 做 FFT
    for (size_t i = 0; i < n; ++i) fa[i] = A[i] / q;
    for (size_t i = 0; i < m; ++i) fb[i] = B[i] / q;

    fft(fa, N, 0);
    fft(fb, N, 0);

    // 3) 点乘
    for (size_t i = 0; i < N; ++i) fa[i] *= fb[i];

    // 4) IFFT
    fft(fa, N, 1);

    // 5) 乘回 q^2 再就近取整（相当于 ⌊ a′b′ · q^2 ⌉）
    real_t qsqr = q * q;
    for (size_t i = 0; i < n + m - 1; ++i)
        result[i] = roundl(creall(fa[i]) * qsqr);

    free(fa); free(fb);
}

