
// This file has my classical O(d^2) arithmetic library for Fp[x]
// It supports 63 bit primes i.e., p < 2^63
// It eliminates the O(d^2) divisions by p using accumulators
// It also uses Roman Pearce's mulrec64 routine for multiplication mod p from the file "int128g.c"
// Copyright Michael Monagan 2000--2019.

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifndef ROOT_DEBUG
#define ROOT_DEBUG 0
#endif

#define LONG long long int
#define ULONG unsigned long long int

/******************************************************************************************/
/*  Zp utilities                                                                          */
/******************************************************************************************/

#define UINT64 unsigned long long

//#include "int128g.c"
typedef struct {
        UINT64 s;       /* shift */
        UINT64 v;       /* reciprocal of d */
        UINT64 d0;      /* divisor shifted up */
        UINT64 d1;
} recint;

recint recip1(UINT64  p);
UINT64 mulrec64(UINT64  a, UINT64  b, recint  v);


ULONG seed;
ULONG mult;

LONG rand64s(LONG p) {
    LONG x,y;
    extern ULONG seed, mult;
    seed = mult*seed;
    x = seed >> 32;
    seed = mult*seed;
    y = seed >> 32;
    x = (x<<31) | y;
    x = x % p;
    return(x);
}


int  min32s(int a, int b) { if( a<b ) return a; else return b; }
int  max32s(int a, int b) { if( a>b ) return a; else return b; }
LONG add64s(LONG a, LONG b, LONG p) { LONG t; t = (a-p)+b; t += (t>>63) & p; return t; }
LONG sub64s(LONG a, LONG b, LONG p) { LONG t; t = a-b; t += (t>>63) & p; return t; }
LONG neg64s(LONG a, LONG p) { return (a==0) ? 0 : p-a; }
LONG mul64s(LONG a, LONG b, LONG p) {
        LONG q, r;
        __asm__ __volatile__(           \
        "       mulq    %%rdx           \n\t" \
        "       divq    %4              \n\t" \
        : "=a"(q), "=d"(r) : "0"(a), "1"(b), "rm"(p));
        return r;
}


        /* z += a1:a0 */
        #define zadd(z,a0,a1) __asm__(\
        "       addq    %4, %0  \n\t" \
        "       adcq    %5, %1  \n\t" \
                : "=&r"(z[0]), "=&r"(z[1]) : "0"(z[0]), "1"(z[1]), "r"(a0), "r"(a1))

        /* z -= a1:a0 */
        #define zsub(z,a0,a1) __asm__(\
        "       subq    %4, %0  \n\t" \
        "       sbbq    %5, %1  \n\t" \
                : "=&r"(z[0]), "=&r"(z[1]) : "0"(z[0]), "1"(z[1]), "r"(a0), "r"(a1))

        /* z = a*b */
        #define zmul(z,a,b) __asm__(\
        "       mulq    %%rdx   \n\t" \
                : "=a"(z[0]), "=d"(z[1]) : "a"(a), "d"(b))

        /* z += a*b */
        #define zfma(z,a,b) do {        \
        unsigned long u,v;              \
        __asm__(                        \
        "       mulq    %%rdx           \n\t" \
        "       addq    %%rax, %0       \n\t" \
        "       adcq    %%rdx, %1       \n\t" \
                : "=&r"(z[0]), "=&r"(z[1]), "=a"(u), "=d"(v) : "0"(z[0]), "1"(z[1]), "a"(a), "d"(b));\
        } while (0)

        /* z -= a*b */
        #define zfms(z,a,b) do {        \
        unsigned long u,v;              \
        __asm__(                        \
        "       mulq    %%rdx           \n\t" \
        "       subq    %%rax, %0       \n\t" \
        "       sbbq    %%rdx, %1       \n\t" \
                : "=&r"(z[0]), "=&r"(z[1]), "=a"(u), "=d"(v) : "0"(z[0]), "1"(z[1]), "a"(a), "d"(b));\
        } while (0)
        /* z[0] = z % p */
        /* z[1] = z / p */
        /* quotient can overflow */
        #define zdiv(z,p) __asm__(\
        "       divq    %4      \n\t" \
                : "=a"(z[1]), "=d"(z[0]) : "a"(z[0]), "d"(z[1]), "r"(p))

        /* z = z % p safe */
        #define zmod(z,p) __asm__(\
        "       divq    %4      \n\t" \
        "       xorq    %0, %0  \n\t" \
                : "=a"(z[1]), "=d"(z[0]) : "a"(z[0]), "d"(z[1] < p ? z[1] : z[1] % p), "r"(p))

        /* z = z << s */
        #define zshl(z,s) __asm__(\
        "       shldq   %%cl, %0, %1    \n\t" \
        "       shlq    %%cl, %0        \n\t" \
                : "=&r"(z[0]), "=&r"(z[1]) : "0"(z[0]), "1"(z[1]), "c"(s))


/* c^(-1) mod p assuming 0 < c < p < 2^63 */
LONG modinv64s( LONG c, LONG p )
{   LONG d,r,q,r1,c1,d1;
    d = p;
    c1 = 1;
    d1 = 0;
    while( d != 0 ) {
        q = c / d;
        r = c - q*d; r1 = c1 - q*d1;
        c = d; c1 = d1;
        d = r; d1 = r1;
    }
    if( c!=1 ) return( 0 );
    if( c1 < 0 ) c1 += p;
    return( c1 );
}


/* a^n mod p assuming 0 <= a < p < 2^63 */
LONG powmod64s( LONG a, LONG n, LONG p )
{   LONG r,s;
    a += (a>>63) & p; // protect from bad input
    if( n==0 ) return 1;
    if( n==1 ) return a;
    for( r=1, s=a; n>0; n /= 2 ) { if( n & 1 ) r = mul64s(r,s,p); s = mul64s(s,s,p); }
    return r;
}

/* a^n mod p assuming 0 <= a < p < 2^63 */
LONG powmodP64s( LONG a, LONG n, LONG p, recint P )
{   LONG r,s;
    a += (a>>63) & p; // protect from bad input
    if( n==0 ) return 1;
    if( n==1 ) return a;
    //for( r=1, s=a; n>0; n /= 2 ) { if( n & 1 ) r = mul64s(r,s,p); s = mul64s(s,s,p); }
    for( r=1, s=a; n>0; n /= 2 ) { if( n & 1 ) r = mulrec64(r,s,P); s = mulrec64(s,s,P); }
    return r;
}

/******************************************************************************************/
/* Polynomial routines                                                                    */
/******************************************************************************************/

void vecfill64s( LONG x, LONG *A, int n )
{   int i;
    for( i=0; i<n; i++ ) A[i] = x;
    return;
}

void polcopy64s( LONG *A, int d, LONG *B )
{   int i;
    for( i=0; i<=d; i++) B[i]=A[i];
    return;
}

/* print an array in form [a0,a1,...,an-1] */
void vecprint64s( LONG *A, int n )
{   int i;
    printf("[");
    for( i=0; i<n; i++ ) { printf("%lld",A[i]); if( i<n-1 ) printf(", "); }
    printf("];\n");
    return;
}

int vecequal64s( LONG *A, LONG *B, int n ) {
    int i,equal;
    for( equal=1,i=0; i<n; i++ ) equal = equal && (A[i]==B[i]);
    return equal;
}

/* print an array [a0,a1,...,ad] in form ad*x^d+...+a1*x+a0 */
void polprint64s( LONG *A, int d, LONG p ) {
    int i;
    if( d==-1 ) { printf("0;\n"); return; }
    for( i=d; i>0; i-- ) if( A[i]!=0 ) printf("%lld*x^%d+",A[i],i);
    printf("%lld;\n",A[0]);
    return;
}

int polequal64s( LONG *a, LONG *b, int d ) {
    int i,equal;
    for( equal=1,i=0; i<=d; i++ ) equal = equal && (a[i]==b[i]);
    return equal;
}

LONG poleval64s(LONG *a, int d, LONG x, LONG p) {
    int i; LONG r; recint P;
    P = recip1(p);
    if( d==-1 ) return 0;
    // a[0]+x(a[1]+x(a[2]+x(a[3])))
    for( r=a[d],i=d-1; i>=0; i-- ) r = add64s(a[i], mulrec64(x,r,P), p);
    return r;
}

void polmultieval64s(LONG *a, int d, LONG *x, LONG *y, int n, LONG p) {
    int j;
    for( j=0; j<n; j++ ) { y[j] = poleval64s(a,d,x[j],p); }
    return;
}

int poladd64s(LONG *a, LONG *b, LONG *c, int da, int db, LONG p) {
// c = a + b mod p
   int i,m;
   m = min32s(da,db);
   for( i=0; i<=m; i++ ) c[i] = add64s(a[i],b[i],p);
   if( da==db ) { while( da>=0 && c[da]==0 ) da--; return da; }
   if( da<db ) { for( i=da+1; i<=db; i++ ) c[i] = b[i]; return db; }
   for( i=db+1; i<=da; i++ ) c[i] = a[i]; return da;
}

int polsub64s(LONG *a, LONG *b, LONG *c, int da, int db, LONG p) {
// c = a-b mod p
   int i,m;
   m = min32s(da,db);
   for( i=0; i<=m; i++ ) c[i] = sub64s(a[i],b[i],p);
   if( da==db ) { while( da>=0 && c[da]==0 ) da--; return da; }
   if( da>db ) { for ( i=db+1; i<=da; i++ ) c[i] = a[i]; return da; }
   else { for( i=da+1; i<=db; i++ ) c[i] = neg64s(b[i],p); return db; }
}


int polsubmul( LONG *A, LONG *B, LONG a, LONG b, int dA, int dB, LONG p ) {
   // compute A = A - (ax+b) B efficiently

   LONG t; int i; ULONG z[2];

   if( dB==-1 ) return dA; // B = 0
   z[0] = z[1] = 0LL;

   // if deg(A) <= deg(B) then pad A with zeroes
   while( dA<=dB ) A[++dA] = 0;

   // constant term is special
   t = mul64s(b,B[0],p) ;
   A[0] = sub64s(A[0],t,p);

   for( i=1; i<=dB; i++ ) { zmul(z,a,B[i-1]); zfma(z,b,B[i]); zmod(z,p);
        t = A[i]-z[0]; A[i] = t + ((t>>63)&p); }

   // update leading term from B
   t = mul64s(a,B[dB],p);
   A[dB+1] = sub64s(A[dB+1],t,p);

   // compute and return degree
   while( dA>=0 && (A[dA]==0 || A[dA]==p) ) dA--;
   return dA;
}


/* compute gcd(A,B) and put gcd in A and return it's degree */
int polsubmulP( LONG *A, LONG *B, LONG a, LONG b, int dA, int dB, LONG p, recint P ) {

   // compute A = A - (ax+b) B efficiently

   LONG s,t; int i, d;

   if( dB==-1 ) return dA; // B = 0

   d = dA;

   // if deg(A) <= deg(B) then pad A with zeroes
   while( dA<=dB ) A[++dA] = 0;

   // constant term is special
   t = mulrec64(b,B[0],P);
   A[0] = sub64s(A[0],t,p);

   //for( i=1; i<=dB; i++ ) { t = mul64s(a,B[i-1],p); t = add64s(t,mul64s(b,B[i],p),p); A[i] = sub64s(A[i],t,p); }
   for( i=1; i<=dB; i++ ) { t = mulrec64(a,B[i-1],P); t = add64s(t,mulrec64(b,B[i],P),p); A[i] = sub64s(A[i],t,p); }

   // update leading term from B
   t = mulrec64(a,B[dB],P);
   A[dB+1] = sub64s(A[dB+1],t,p);

   // compute and return degree
   while( dA>=0 && (A[dA]==0 || A[dA]==p) ) dA--;

   if( dA==d ) printf("polsubmul failure: dAin=%d dAout=%d\n",d,dA);
   return dA;
}


int poldiff64s( LONG *f, int d, LONG *fp, LONG p ) {
    int i; recint P;
    P = recip1(p);
    for( i=1; i<=d; i++ ) fp[i-1] = mulrec64(f[i],(LONG) i,P);
    for( d--; d>=0 && fp[d]==0; d-- );
    return d;
}

/* compute C(x) = A(x)^2 mod p and return deg(C) */
/* we allow C to overwrite A i.e. polsqr64s(A,A,d,p) */
int polsqr64s( LONG * A, LONG * C, int d, LONG p )
{
    int i,k,m,dc; ULONG z[2];
    if( d<0 ) return d;
    for( k=2*d; k>=0; k-- ) {
       m = min32s(k,d);
       i = max32s(0,k-d);
       z[0] ^= z[0]; // = 0?
       z[1] ^= z[1]; // = 0?
       while( i<m-2 ) {
            zfma(z,A[i++],A[m--]);
            if( z[1]>=p ) z[1] -= p;
            zfma(z,A[i++],A[m--]);
       }
       if( i<m ) {
            zfma(z,A[i++],A[m--]);
            if( z[1]>=p ) z[1] -= p;
       }
       zadd(z,z[0],z[1]);
       if( z[1]>=p ) z[1] -= p;
       if( i==m ) zfma(z,A[i],A[i]);
       zmod(z,p);
       C[k] = z[0];
    }
    for( dc = 2*d; dc>=0 && C[dc]==0; dc-- );
    // Why is this loop here? Z_p has no zero-divisors.
    // Because p may not be prime!!
    return( dc );
}


/* compute C(x) = A(x) * B(x) mod p and return deg(C) */
/* we allow C to overwrite either A or B i.e. polmul64s(A,B,A,da,db,p) */
int polmul64s( LONG * A, LONG * B, LONG * C, int da, int db, LONG p)
{
    int i,k,m; ULONG z[2];
    if( da<0 || db<0 ) return da;
    int dc = da+db;
    for( k=dc; k>=0; k-- ) {
       i = max32s(0,k-db);
       m = min32s(k,da);
       z[0] ^= z[0]; // = 0?
       z[1] ^= z[1]; // = 0?
       while( i<m ) {
           zfma(z,A[i],B[k-i]); i++;
           if( z[1]>=p ) z[1] -= p;
           zfma(z,A[i],B[k-i]); i++;
       }
       if( i==m ) {
           zfma(z,A[i],B[k-i]);
           if( z[1]>=p ) z[1] -= p;
       }
       zmod(z,p);
       C[k] = z[0];
    }
    for( ; dc>=0 && C[dc]==0; dc-- );
    return( dc );
}


/* divide A by B and put the remainder and quotient in A */
/* return the degree of the remainder                    */
int poldiv64s( LONG * A, LONG * B, int da, int db, LONG p )
{
    int dq,dr,k,j,m; LONG t,inv; ULONG z[2];
    if( db<0 ) { printf("division by zero\n"); exit(1); }
    if( da<db ) return da; else { dq = da-db; dr = db-1; }
    inv = modinv64s(B[db],p);
    for( k=da; k>=0; k-- ) {
        z[0] = 0ll; z[1] = 0ll;
        m = min32s(dr,k);
        j = max32s(0,k-dq);
        //for( j=max32s(0,k-dq); j<=m; j++ ) { t -= ((LONG) B[j])*A[k-j+db]; t += (t>>63) & M; }
        while( j<m ) {
            zfma(z,B[j],A[k-j+db]); j++;
            if( z[1]>=p ) z[1] -= p;
            zfma(z,B[j],A[k-j+db]); j++;
        }
        if( j==m ) zfma(z,B[j],A[k-j+db]);
        if( z[1]>=p ) z[1] -= p;
        zmod(z,p);
        t = A[k] - z[0];
        t += (t>>63) & p;
        if( k>=db && inv!=1 ) t = mul64s(t,inv,p);
        A[k] = t;
    }
    while( dr>=0 && A[dr]==0 ) dr--;
    return( dr );
}


void polscamul64s( LONG x, LONG *A, int d, LONG p ) {
    int i;
    if( x==1 ) return;
    if( x==-1 ) for( i=0; i<=d; i++ ) A[i] = neg64s(A[i],p);
    else for( i=0; i<=d; i++ ) A[i] = mul64s(x,A[i],p);
    return;
}


/* make polynomial in A monic */
void monic64s( LONG *A, int d, LONG p ) {
    int i; LONG inv;
    if( d<0 || A[d]==1 ) return;
    inv = modinv64s(A[d],p);
    for( i=0; i<d; i++ ) A[i] = mul64s(inv, A[i], p);
    A[d] = 1;
    return;
}


/* compute gcd(A,B) and put gcd in A and return it's degree */
/* Both A and B are destroyed */
int polgcd64s( LONG * A, LONG * B, int da, int db, LONG p ) {
    int dr; LONG *C, *D, *R, u, a, b;
    recint P;
    if( db<0 ) { printf("division by zero\n"); exit(1); }
    P = recip1(p);
    C = A; D = B;
    if( da<db ) { R = C; C = D; D = R; dr = da; da = db; db = dr; }
    while( 1 ) {
        if( db>0 && da-db==1 ) { // normal case
            u = modinv64s(D[db],p);
            a = mulrec64(C[da],u,P);
        //    a = mul64s(C[da],u,p);
            b = mulrec64(a,D[db-1],P);
        //    b = mul64s(a,D[db-1],p);
            b = mulrec64(u,sub64s(C[da-1],b,p),P);  // quotient = a x + b
        //    b = mul64s(u,sub64s(C[da-1],b,p),p);  // quotient = a x + b
            dr = polsubmulP(C,D,a,b,da,db,p,P);  // C = C - (a x + b) D
        //    dr = polsubmul(C,D,a,b,da,db,p);  // C = C - (a x + b) D
            if( dr>=db ) printf("failure\n");
        }
        else dr = poldiv64s(C,D,da,db,p);
        if( dr<0 ) { /* D|C so gcd(A,B)=D */
            if( D!=A ) polcopy64s(D,db,A);
            monic64s( A, db, p );
            return db;
        }
        R = C; C = D; D = R; da = db; db = dr;
        //printf("da=%d db=%d\n",da,db);
    }
}


void polgcdext64s( LONG *A, LONG *B, int da, int db,
                  LONG *G, LONG *S, LONG *T, int *dG, int *dS, int *dT,
                  LONG *W, LONG p )
{
    // Solve S A + T B = G = monic gcd(A,B) for G,S,T in Zp[x]
    // The arrays A and B are used for the remainder sequence so they are destroyed
    // G,S,T must all be of size max(da+1,db+1)
    // W is working storage of size 2max(da+1,db+1)
    // if S==0 or T==0 then S (and/or T) are not computed

    int m,dr,ds,dt,dq,ds1,ds2,dt1,dt2; LONG a,b,u;
    LONG *q,*r,*r1,*r2,*s,*s1,*s2,*t,*t1,*t2;

    recint P; P = recip1(p);

    if( da<0 || db<0 ) { printf("inputs must be non-zero\n"); exit(1); }
    m = max32s(da+1,db+1);
    r1 = A; r2 = B;
    if(S) { s1 = S; s2 = W;   s1[0]=1; ds1=0; ds2=-1; }
    if(T) { t1 = T; t2 = W+m; t2[0]=1; dt2=0; dt1=-1; }
    while( 1 ) {
        if( db>0 && da-db==1 ) { // normal case
            u = modinv64s(r2[db],p);
            a = mul64s(r1[da],u,p);
            b = mul64s(a,r2[db-1],p);
            b = mul64s(u,sub64s(r1[da-1],b,p),p);             // quotient = a x + b
            dr = polsubmul(r1,r2,a,b,da,db,p);                // r1 = r1 - (a x + b) r2
            if(S) ds = polsubmul(s1,s2,a,b,ds1,ds2,p);        // s1 = s1 - (a x + b) s2
            if(T) dt = polsubmul(t1,t2,a,b,dt1,dt2,p);        // t1 = t1 - (a x + b) t2
            //dr = polsubmulP(r1,r2,a,b,da,db,p,P);              // r1 = r1 - (a x + b) r2
            //if(S) ds = polsubmulP(s1,s2,a,b,ds1,ds2,p,P);      // s1 = s1 - (a x + b) s2
            //if(T) dt = polsubmulP(t1,t2,a,b,dt1,dt2,p,P);      // t1 = t1 - (a x + b) t2
        }
        else {
            dr = poldiv64s(r1,r2,da,db,p);                 // r1 = [remainder,quotient]
            q  = r1+db; dq = da-db;
            if(S) ds = polmul64s(q,s2,G,dq,ds2,p);
            if(S) ds = polsub64s(s1,G,s1,ds1,ds,p);        // s1 = s1 - q s2
            if(T) dt = polmul64s(q,t2,G,dq,dt2,p);
            if(T) dt = polsub64s(t1,G,t1,dt1,dt,p);        // t1 = t1 - q t2
        }
        if( dr<0 ) { /* D|C so gcd(A,B)=D */
            polcopy64s(r2,db,G);
            if(S) if( s2!=S ) polcopy64s(s2,ds2,S);
            if(T) if( t2!=T ) polcopy64s(t2,dt2,T);
            if( G[db]!=1 ) {
                u = modinv64s(G[db],p);
                polscamul64s(u,G,db,p);
                if(S) polscamul64s(u,S,ds2,p);
                if(T) polscamul64s(u,T,dt2,p);
            }
            dG[0] = db;
            if(S) dS[0] = ds2;
            if(T) dT[0] = dt2;
            return;
        }
        r = r1; r1 = r2; r2 = r;  da = db;   db = dr;
        if(S) { s = s1; s1 = s2; s2 = s; ds1 = ds2; ds2 = ds; }
        if(T) { t = t1; t1 = t2; t2 = t; dt1 = dt2; dt2 = dt; }
    }
}


/* C(x) := A(x)^n mod B(x) mod p;  0<=deg(A)<deg(B) and R must be of size 2*db-1 */
/* If A(x) is not reduced mod B(x) then we first compute C(x) := A(x) mod B(x)   */
int polpowmod64s( LONG * A, LONG n, LONG * B, int da, int db, LONG *C, LONG *R, LONG p )
{
    int dc,k,b[63];

    if( n==0 ) { C[0] = 1; return 0; }
    if( da>=db ) da = poldiv64s(A,B,da,db,p);                   // reduce A mod B first
    for( k=0; n>0; k++ ) { b[k]=n&1; n=n/2; }
    polcopy64s(A,da,C);
    dc = da;
    k--;
    while( k>0 ) { k--;
       // Main step: compute C := C^2 mod B in Zp[x]
       //dc = polmul64s(C,C,R,dc,dc,p);                           //printf("deg(R) = %d; R = ",dc); polprint64s(R,dc);
       dc = polsqr64s(C,R,dc,p);                                //printf("deg(R) = %d; R = ",dc); polprint64s(R,dc);
       dc = poldiv64s(R,B,dc,db,p);
       polcopy64s(R,dc,C);                                      //printf("deg(C) = %d; C = ",dc); polprint64s(C,dc);
       if( b[k]==1 ) {                                          //printf(" b[%d]=%d \n", k, b[k] );
           dc = polmul64s(A,C,R,da,dc,p);                       //printf("deg(R) = %d; R = ",dc); polprint64s(R,dc);
           dc = poldiv64s(R,B,dc,db,p);
           polcopy64s(R,dc,C);                                  //printf("deg(C) = %d; C = ",dc); polprint64s(C,dc);
       }
    }
    return dc;
}


// Input f in Zp[x] of degree d > 0, a known product of d linear factors.
// Output roots of f in R.
// The input array f is destroyed.
// W is a scratch array of size at least 3*d
void polsplit64s( LONG *f, int d, LONG *R, LONG *W, LONG p )
{
   int da,dg; LONG alpha, A[2];
   if( d==1 ) { alpha = p-f[0]; R[0] = alpha; return; }
   alpha = rand64s(p); A[1] = 1; A[0] = alpha;
   da = polpowmod64s( A, (p-1)/2, f, 1, d, W, W+d, p );
   if( da==0 ) return polsplit64s(f,d,R,W,p);      // alpha is unlucky, try again
   W[0] = add64s(W[0],1,p);                        // W = (x+alpha)^((p-1)/2) + 1 mod f
   polcopy64s( f, d, W+d );
   dg = polgcd64s( W, W+d, da, d, p );             // g = gcd( W, f ) in W
   if( dg==0 ) return polsplit64s(f,d,R,W,p);      // g = 1 ==> alpha is unlucky, try again
   poldiv64s(f,W,d,dg,p);                          // compute quotient q = f/g destroying f
   polcopy64s(W,dg-1,f);                           // f = [ g mod x^dg followed by q ]
   polsplit64s(f+dg,d-dg,R,W,p);
   f[dg] = 1;
   polsplit64s(f,dg,R+d-dg,W,p);
   return;
}


int polroots64s( LONG * f, int d, LONG * R, LONG *W, LONG p )
{
   int i, da, dg; LONG A[2]; extern ULONG seed,mult;
   clock_t st,et;
    
  if (ROOT_DEBUG) printf("roots: deg(f)=%d\n",d);
    // printf("f := "); polprint64s(f,d);
   for( i=0; i<d && f[i]==0; i++ );
   if( i>0 ) { R[0]=0; return( 1 + polroots64s(f+i,d-i,R+1,W,p) ); }
   if( f[d]!=1 ) monic64s(f,d,p);
   A[1] = 1;
   A[0] = 0;
   st = clock();
   da = polpowmod64s( A, p-1, f, 1, d, W, W+d, p );    // W = x^(p-1) mod f
   et = clock();
  if (ROOT_DEBUG) printf("Roots: powmod: x^(p-1) mod f = x^%d + ... time = %10d ms\n", da, (et-st)/1000 );
   //printf("da = %d, a := ",da); polprint64s(W,da);
   if( da==0 && W[0]==1 ) dg = d; // f is all linear factors
   else { W[0] = sub64s(W[0],1,p); dg = polgcd64s( f, W, d, da, p ); }   // f = gcd(f,W-1)
   //printf("g := "); polprint64s(f,dg);
  if (ROOT_DEBUG) printf("Roots: def(f)=%d  #roots=%d\n",d,dg);
   if( dg==0 ) return 0;
   seed = 1;
   mult = 6364136223846793003ll;
   st = clock();
   polsplit64s( f, dg, R, W, p );
   et = clock();
 if (ROOT_DEBUG) printf("Roots: split time=%10d ms\n", (et-st)/1000 );
   return dg; // number of roots in R
}


int BerlekampMassey64s( LONG *a, int N, LONG *L, LONG *W, LONG p )
{
    // Input sequence a = [a1,a2,a3,...,aN]
    // Output polynomial Lambda(x) is written to L
    // Uses the half extended Euclidean algorithm
    int i,m,n,dr,dq,dr0,dr1,dv0,dv1,dt;
    LONG *r,*q,*r0,*r1,*v0,*v1,*t,u,A,b;
    //recint P;
    while( N>0 && a[N-1]==0 ) N--; // ignore leading zeroes
    n = N/2;
    N = 2*n;
    if( N==0 ) return -1;
    m = N-1;
    // W is space for r0 = x^N and r1 of degree m and v0 and v1 of degree at most n
    r0 = W; r1 = r0+N+1; v0 = r1+N; v1 = v0+n+1;
    vecfill64s(0,r0,N); r0[N] = 1; dr0 = N;             // r0 = x^(2*n)
    for(i=0; i<N; i++) r1[i] = a[m-i];
    for(dr1=m; dr1>=0 && r1[dr1]==0; dr1--);            // r1 = sum(a[m-i]*x^i,i=0..m)
    if( dr1==-1 ) return -1;
    dv0 = -1;                                           // v0 = 0
    v1[0] = 1; dv1 = 0;                                 // v1 = 1
    //P = recip1(p);
    while( n <= dr1 ) {
        if( dr1>0 && dr0-dr1==1 ) { // normal case
            u = modinv64s(r1[dr1],p);
            A = mul64s(r0[dr0],u,p);
            b = mul64s(A,r1[dr1-1],p);
            b = mul64s(u,sub64s(r0[dr0-1],b,p),p);             // quotient q = A x + b
            //dr = polsubmulP(r0,r1,A,b,dr0,dr1,p,P);            // r0 = r0 - (A x + b) r1
            dr = polsubmul(r0,r1,A,b,dr0,dr1,p);            // r0 = r0 - (A x + b) r1
            // dt = polsubmulP(v0,v1,A,b,dv0,dv1,p,P);            // v0 = v0 - (A x + b) v1
            dt = polsubmul(v0,v1,A,b,dv0,dv1,p);            // v0 = v0 - (A x + b) v1
        } else {
           dr = poldiv64s(r0,r1,dr0,dr1,p);
           q = r0+dr1; dq = dr0-dr1;                           // q = quo(r0,r1)
           dt = polmul64s(q,v1,L,dq,dv1,p);
           dt = polsub64s(v0,L,v0,dv0,dt,p);
        }
        r = r0; r0 = r1; r1 = r; dr0 = dr1; dr1 = dr;         // r0,r1 = r1,rem(r0,r1)
        t = v0; v0 = v1; v1 = t; dv0 = dv1; dv1 = dt;         // v0,v1 = v1,v0 - q*v1
        //printf("r0 = "); polprint64s(r0,dr0);
        //printf("r1 = "); polprint64s(r1,dr1);
        //printf("v0 = "); polprint64s(v0,dv0);
        //printf("v1 = "); polprint64s(v1,dv1);
    }
    if( dv1>=0 ) {
        polcopy64s(v1,dv1,L);
        monic64s(L,dv1,p);
    }
    return dv1;
}


void polLambda64s( LONG *R, int n, LONG *L, LONG *W, LONG p ) {
// L must be length n+1, W length 2n
    int m;
    //if( n==0 ) { printf("n=0\n"); }
    if( n==1 ) { L[0] = neg64s(R[0],p); L[1] = 1; return; }
    m = n/2;
    polLambda64s( R, m, W, L, p );
    polLambda64s( R+m, n-m, W+m+1, L, p );
    //for( i=0; i<n; i++ ) {
    //    A[0] = neg64s(m[i],p);
    //    polmul64s( A, L, L, 1, i, p);
    //}
    polmul64s( W, W+m+1, L, m, n-m, p );
    return;
}
