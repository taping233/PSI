// Tangent Graeffe root extraction glue, adapted from Michael Monagan's
// mainfft5.c implementation already used by the PSI benchmark.

#include <stdio.h>
#include <stdlib.h>

#define LONG long long int
#define ULONG unsigned long long int

extern ULONG seed;
extern ULONG mult;
LONG rand64s(LONG p);
LONG *array64s(LONG n);

#define UINT64 unsigned long long

typedef struct {
    UINT64 s;
    UINT64 v;
    UINT64 d0;
    UINT64 d1;
} recint;

recint recip1(UINT64 p);
UINT64 mulrec64(UINT64 a, UINT64 b, recint v);

#define add64s add64stg
#define sub64s sub64stg
#define mul64s mul64stg
#define neg64s neg64stg

LONG neg64s(LONG a, LONG p) { return (a == 0) ? 0 : p - a; }
LONG add64s(LONG a, LONG b, LONG p)
{
    LONG t = (a - p) + b;
    t += (t >> 63) & p;
    return t;
}
LONG sub64s(LONG a, LONG b, LONG p)
{
    LONG t = a - b;
    t += (t >> 63) & p;
    return t;
}
LONG mul64s(LONG a, LONG b, LONG p)
{
    LONG q, r;
    __asm__ __volatile__(
        "       mulq    %%rdx           \n\t"
        "       divq    %4              \n\t"
        : "=a"(q), "=d"(r)
        : "0"(a), "1"(b), "rm"(p));
    return r;
}

LONG modinv64s(LONG c, LONG p);
void polcopy64s(LONG *A, int d, LONG *B);
int poldiff64s(LONG *f, int d, LONG *fp, LONG p);
LONG FFTbluestein64s(LONG *a, LONG n, LONG s, LONG *v, LONG *T, LONG p);
void FFTtangGraeffe64s(LONG *f, LONG *g, LONG d, int k, LONG *T, LONG p);
int FFTpoldiv64s(LONG *a, LONG *b, LONG da, LONG db, long p);
void fastLambda(LONG *v, LONG n, LONG *f, LONG p);
void changebase3(LONG *f, LONG n, LONG alpha, LONG p);

static LONG getsonly(LONG n, LONG p)
{
    int k;
    LONG s, q;
    for (s = (p - 1) / 2; (s & 1) == 0; s = s / 2) {
    }
    q = (p - 1) / s;
    for (k = 0; q > 1; k++) {
        q = q >> 1;
    }
    while (s < 2 * n) {
        k--;
        s = 2 * s;
    }
    return s;
}

LONG roots64s_workspace_s(LONG n, LONG p)
{
    return getsonly(n, p);
}

LONG roots64s_workspace_t_len(LONG n, LONG p)
{
    LONG M, N, s;

    s = getsonly(n, p);
    for (N = 1; N <= 2 * n; N = 2 * N) {
    }
    N = 3 * N;
    for (M = 1; M <= 2 * s; M = 2 * M) {
    }
    M = 3 * M;
    return M > N ? M : N;
}

static int rootsrec(LONG *lambda, LONG n, LONG *R, LONG p,
                    LONG *f, LONG *g, LONG *P, LONG *Q, LONG *v,
                    LONG *x, LONG *y, LONG *W, LONG *T)
{
    LONG i, k, m, N;
    LONG alpha, omega, q, s;
    recint pp;

    m = 0;
    if (n > 0 && lambda[0] == 0) {
        R[0] = 0;
        lambda++;
        n--;
        R++;
        m++;
    }
    if (n == 0) {
        return (int)m;
    }
    if (n == 1) {
        R[0] = neg64s(lambda[0], p);
        return (int)(m + 1);
    }

    pp = recip1((UINT64)p);

    do {
        for (i = 0; i <= n; i++) {
            f[i] = lambda[i];
        }
        alpha = rand64s(p);
        changebase3(f, n, alpha, p);
    } while (f[0] == 0);

    for (s = (p - 1) / 2; (s & 1) == 0; s = s / 2) {
    }
    q = (p - 1) / s;
    for (k = 0; q > 1; k++) {
        q = q >> 1;
    }
    while (s < 2 * n) {
        k--;
        s = 2 * s;
    }

    for (i = 0; i <= n; i++) {
        P[i] = f[i];
    }
    poldiff64s(f, (int)n, Q, p);
    polcopy64s(P, (int)n, f);
    polcopy64s(Q, (int)(n - 1), g);

    FFTtangGraeffe64s(P, Q, n, (int)k, T, p);

    omega = FFTbluestein64s(P, n, s, v, T, p);
    FFTbluestein64s(Q, n - 1, s, x, T, p);
    poldiff64s(P, (int)n, Q, p);
    FFTbluestein64s(Q, n - 1, s, y, T, p);

    {
        LONG w, t, z, r;
        w = 1;
        N = 0;
        m = 0;
        for (i = 0; i < s; i++) {
            if (v[i] == 0) {
                N++;
            }
            if (v[i] == 0 && y[i] != 0) {
                t = modinv64s(y[i], p);
                t = (LONG)mulrec64((UINT64)t, (UINT64)x[i], pp);
                z = modinv64s(t, p);
                r = ((LONG)1) << k;
                r = (LONG)mulrec64((UINT64)r, (UINT64)w, pp);
                z = (LONG)mulrec64((UINT64)r, (UINT64)z, pp);
                z = add64s(z, alpha, p);
                R[m++] = z;
            }
            w = (LONG)mulrec64((UINT64)omega, (UINT64)w, pp);
        }
        if (N == 0) {
            return 0;
        }
    }

    fastLambda(R, m, g, p);
    for (i = 0; i <= n; i++) {
        f[i] = lambda[i];
    }
    k = FFTpoldiv64s(f, g, n, m, p);
    if (k != -1) {
        printf("roots: DIVIDE bad\n");
    }

    if (m < n) {
        m += rootsrec(f + m, n - m, R + m, p, lambda, g, P, Q, v, x, y, W, T);
    }
    return (int)m;
}

int roots64s_seeded(LONG *lambda, LONG n, LONG *R, LONG p,
                    ULONG initial_seed)
{
    seed = initial_seed;
    mult = 6364136223846793003LL;

    LONG m;
    LONG M, N, s;
    LONG *L, *f, *g, *P, *Q, *T, *v, *x, *y, *W;

    L = array64s(n + 1);
    polcopy64s(lambda, (int)n, L);
    f = array64s(n + 1);
    g = array64s(n + 1);
    P = array64s(n + 1);
    Q = array64s(n + 1);
    s = getsonly(n, p);

    for (N = 1; N <= 2 * n; N = 2 * N) {
    }
    N = 3 * N;
    for (M = 1; M <= 2 * s; M = 2 * M) {
    }
    M = 3 * M;
    if (M > N) {
        N = M;
    }

    T = array64s(N);
    v = array64s(s);
    x = array64s(s);
    y = array64s(s);
    W = array64s(s);

    m = rootsrec(L, n, R, p, f, g, P, Q, v, x, y, W, T);

    free(L);
    free(T);
    free(v);
    free(x);
    free(y);
    free(P);
    free(Q);
    free(W);
    free(f);
    free(g);
    return (int)m;
}

int roots64s(LONG *lambda, LONG n, LONG *R, LONG p)
{
    return roots64s_seeded(lambda, n, R, p, 1);
}

int roots64s_prealloc(LONG *lambda, LONG n, LONG *R, LONG p,
                      LONG *L, LONG *f, LONG *g, LONG *P, LONG *Q,
                      LONG *T, LONG *v, LONG *x, LONG *y, LONG *W)
{
    seed = 1;
    mult = 6364136223846793003LL;

    polcopy64s(lambda, (int)n, L);
    return rootsrec(L, n, R, p, f, g, P, Q, v, x, y, W, T);
}
