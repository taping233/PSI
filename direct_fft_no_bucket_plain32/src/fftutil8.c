// This file contains FFT code and FFT based polynomial routines
// Copyright Michael Monagan, March 2020

#include <stdio.h>
#include <stdlib.h>
#include "int128g.c"


// Switch from int i,j,n; to LONG i,j,n; to allow FFTs of size 2^31 and 2^32

#define LONG long long int

/********************************************************************************/
/*  Zp utilities                                                                */
/********************************************************************************/

#define ADD64s fftadd64s
#define ADD32s fftadd32s
#define SUB64s fftsub64s
#define NEG64s fftneg64s
#define MUL64s fftmul64s
#define MOD64s fftmod64s
#define MIN64s fftmin64s
#define INV64s modinv64s

LONG ADD64s(LONG a, LONG b, LONG p) { LONG t; t = (a-p)+b; t += (t>>63) & p; return t; }
LONG ADD32s(int a, int b, int p) { int t; t = (a-p)+b; t += (t>>31) & p; return t; }
LONG SUB64s(LONG a, LONG b, LONG p) { LONG t; t = a-b; t += (t>>63) & p; return t; }
LONG NEG64s(LONG a, LONG p) { LONG t; t = -a; t += (t>>63) & p; return t; }
LONG MUL64s(LONG a, LONG b, LONG p)
{
         LONG q, r;
         __asm__ __volatile__(           \
         "       mulq    %%rdx           \n\t" \
         "       divq    %4              \n\t" \
         : "=a"(q), "=d"(r) : "0"(a), "1"(b), "rm"(p));
         return r;
}

#define UINT64 unsigned long long

//typedef struct {
//  UINT64 s;	/* shift */
//  UINT64 v;	/* reciprocal of d */
//  UINT64 d0;	/* divisor shifted up */
//  UINT64 d1;
//} recint;
//recint recip1(UINT64  p);
//UINT64 mulrec64(UINT64  a, UINT64  b, recint  v);


LONG MOD64s(LONG a,LONG p) { return(a % p); }
LONG MIN64s(LONG a, LONG b) { if(a<b) return a; else return b; }
LONG modinv64s( LONG c, LONG p );
LONG powmod64s( LONG a, LONG n, LONG p );


/********************************************************************************/
/*  Array utilities                                                             */
/********************************************************************************/

void vecprint64s( LONG *A, int n );
void VECCOPY64s( LONG *A, LONG *B, LONG n ) { LONG i; for( i=0; i<n; i++ ) B[i] = A[i]; }
void VECFILL64s( LONG *A, LONG n, LONG x ) { LONG i; for( i=0; i<n; i++ ) A[i] = x; }
void VECSCAMUL64s( LONG *A, LONG n, LONG x, recint P ) { LONG i; for( i=0; i<n; i++ ) A[i] = mulrec64(A[i],x,P); }
void VECZIPMUL64s( LONG *A, LONG *B, LONG n, recint P ) { LONG i; for( i=0; i<n; i++ ) A[i] = mulrec64(A[i],B[i],P); }
void VECZIP2MUL64s( LONG *A, LONG *B, LONG n, LONG *C, recint P ) { LONG i; for( i=0; i<n; i++ ) C[i] = mulrec64(A[i],B[i],P); }
void VECPOWMUL64s( LONG *A, LONG n, LONG omega, recint P ) { LONG i; A[0] = 1; for( i=1; i<n; i++ ) A[i] = mulrec64(A[i-1],omega,P); }

LONG * array64s( LONG n ) { 
    LONG *A;
if(n<0) { printf("array64s: n=%lld must be >= 0\n"); exit(1); }
    n = n * sizeof( LONG );
    A = (LONG *) malloc( n ); 
    if( A==0 ) { printf("array64s: malloc failed\n"); exit(1); }
    return A;
}


/********************************************************************************/
/*  Polynomial routines                                                         */
/********************************************************************************/

int poladd64s(LONG *a, LONG *b, LONG *c, int da, int db, LONG p);
int polsqr64s( LONG * A, LONG * C, int d, LONG p );
int polmul64s( LONG * A, LONG * B, LONG * C, int da, int db, LONG p );
int poldiv64s( LONG * A, LONG * B, int da, int db, LONG p );
void polprint64s( LONG *A, int d );
void polcopy64s( LONG *A, int d, LONG *B );
LONG poleval64s(LONG *a, int d, LONG x, LONG p);


/********************************************************************************/
/*  FFT utilities and routines                                                  */
/********************************************************************************/

int vecequal64s( LONG *A, LONG *B, int n );

LONG getprimelem64s( LONG p ); // in primitive.c
LONG getomega64s( LONG p, LONG n ) { // p is assumed prime > 2
   LONG a,m,omega;
   m = (p-1)/n;
   if( (p-1)-n*m ) return 0; // there is no such omega
   a = getprimelem64s( p );  // printf("primelem = %lld\n",a);
   omega = powmod64s( a, m, p );
   return omega;
}

void FFTwork1( LONG n2, LONG *a, LONG *b, LONG *W, LONG p, recint P ) {
   LONG i,t;
   for( i=0; i<n2; i++ ) {
      t = SUB64s(a[i],b[i],p);
      t = mulrec64(t,W[i],P);
      a[i] = ADD64s(a[i],b[i],p);
      b[i] = t;
   }
   return;
}

void FFT64s1( LONG n, LONG *a, LONG *W, LONG p, recint P )
{  LONG i,j,n2;
   LONG s,t,*b;
   if( n==1 ) return;
   if( n==2 ) { s = ADD64s(a[0],a[1],p); t = SUB64s(a[0],a[1],p); a[0] = s; a[1] = t; return; }
   if( n==4 ) {
      LONG t1,t2,t3,t4;
      t1 = ADD64s(a[0],a[2],p);
      t2 = SUB64s(a[0],a[2],p);
      t3 = ADD64s(a[1],a[3],p);
      t4 = SUB64s(a[1],a[3],p);
      t4 = mulrec64(t4,W[1],P);
      a[0] = ADD64s(t1,t3,p); // (a0+a2)+(a1+a3)
      a[1] = SUB64s(t1,t3,p); // (a0+a2)-(a1+a3)
      a[2] = ADD64s(t2,t4,p); // (a0-a2)+w(a1-a3)
      a[3] = SUB64s(t2,t4,p); // (a0-a2)-w(a1-a3)
      return;
   }
   n2 = n/2;
   b = a+n2;
   for( i=0; i<n2; i++ ) {
      t = SUB64s(a[i],b[i],p);
      t = mulrec64(t,W[i],P);
      a[i] = ADD64s(a[i],b[i],p);
      b[i] = t;
   }
   FFT64s1(n2,a,W+n2,p,P);
   FFT64s1(n2,b,W+n2,p,P);
   return;
}

void FFTwork2( LONG n2, LONG *a, LONG *b, LONG *W, LONG p, recint P ) {
   LONG i,s,t;
   for( i=0; i<n2; i++ ) {
      s = a[i];
      t = mulrec64(b[i],W[i],P);
      a[i] = ADD64s(s,t,p);
      b[i] = SUB64s(s,t,p);
   }
   return;
}

void FFT64s2( LONG n, LONG *a, LONG *W, LONG p, recint P )
{ LONG i,j,n2;
  LONG s,t,*b;
  if( n==1 ) return;
  if( n==2 ) { s = ADD64s(a[0],a[1],p); t = SUB64s(a[0],a[1],p); a[0] = s; a[1] = t; return; }
  if( n==4 ) {
      LONG t0,t1,t2,t3;
      t0 = ADD64s(a[0],a[1],p);
      t1 = SUB64s(a[0],a[1],p);
      t2 = ADD64s(a[2],a[3],p);
      t3 = SUB64s(a[2],a[3],p);
      t3 = mulrec64(t3,W[1],P);
      a[0] = ADD64s(t0,t2,p);
      a[1] = ADD64s(t1,t3,p);
      a[2] = SUB64s(t0,t2,p);
      a[3] = SUB64s(t1,t3,p);
      return;
  }
  n2 = n/2;
  b = a+n2;
  FFT64s2(n2,a,W+n2,p,P);
  FFT64s2(n2,b,W+n2,p,P);
  for( i=0; i<n2; i++ ) {
      s = a[i];
      t = mulrec64(b[i],W[i],P);
      a[i] = ADD64s(s,t,p);
      b[i] = SUB64s(s,t,p);
  }
  return;
}

void FFT64s2even( LONG n, LONG *a, LONG *W, LONG p, recint P )
{ LONG i,j,n2;
  LONG s,t,*b;
  if( n==1 ) return;
  if( n==2 ) { s = ADD64s(a[0],a[1],p); t = SUB64s(a[0],a[1],p); a[0] = s; a[1] = t; return; }
  if( n==4 ) {
      LONG t0,t1,t2,t3;
      t0 = ADD64s(a[0],a[1],p);
      //t1 = SUB64s(a[0],a[1],p); // = 0
      t2 = ADD64s(a[2],a[3],p);
      //t3 = SUB64s(a[2],a[3],p); // = 0
      //t3 = mulrec64(t3,W[1],P);
      a[0] = ADD64s(t0,t2,p);
      //a[1] = ADD64s(t1,t3,p); // 0
      a[2] = SUB64s(t0,t2,p);
      //a[3] = SUB64s(t1,t3,p); // 0
      return;
  }
  n2 = n/2;
  b = a+n2;
  FFT64s2even(n2,a,W+n2,p,P);
  FFT64s2even(n2,b,W+n2,p,P);
  for( i=0; i<n2; i+=2 ) { // a[odd] = b[odd] = 0
      s = a[i];
      t = mulrec64(b[i],W[i],P);
      a[i] = ADD64s(s,t,p);
      b[i] = SUB64s(s,t,p);
  }
  return;
}


void FFT64s2even2( LONG n, LONG *a, LONG *W, LONG p, recint P )
{ LONG i,j,n2;
  LONG s,t,*b;
  if( n==1 ) return;
  if( n==2 ) { s = ADD64s(a[0],a[1],p); t = SUB64s(a[0],a[1],p); a[0] = s; a[1] = t; return; }
/*
  if( n==4 ) {
      LONG t0,t1,t2,t3;
      t0 = ADD64s(a[0],a[1],p);
      //t1 = SUB64s(a[0],a[1],p); // = 0
      t2 = ADD64s(a[2],a[3],p);
      //t3 = SUB64s(a[2],a[3],p); // = 0
      //t3 = mulrec64(t3,W[1],P);
      a[0] = ADD64s(t0,t2,p);
      //a[1] = ADD64s(t1,t3,p); // 0
      a[2] = SUB64s(t0,t2,p);
      //a[3] = SUB64s(t1,t3,p); // 0
      return;
  }
*/
  n2 = n/2;
  b = a+n2;
  FFT64s2even2(n2,a,W+n2,p,P);
  FFT64s2even2(n2,b,W+n2,p,P);
  for( i=0; i<n2; i++ ) { // a[odd] = b[odd] = 0
      s = a[i];
      t = mulrec64(b[i],W[i],P);
      a[i] = ADD64s(s,t,p);
      b[i] = SUB64s(s,t,p);
  }
  return;
}


void FFT64s2T( LONG n, LONG *a, LONG *W, LONG *T, LONG p, recint P )
{ LONG i,n2;
  LONG s,t,*b;
  if( n==1 ) return;
  if( n==2 ) { s = ADD64s(a[0],a[1],p); t = SUB64s(a[0],a[1],p); a[0] = s; a[1] = t; return; }
  if( n==4 ) {
      LONG t1,t2,t3,t4;
      t1 = ADD64s(a[0],a[2],p);
      t2 = SUB64s(a[0],a[2],p);
      t3 = ADD64s(a[1],a[3],p);
      t4 = mulrec64(SUB64s(a[1],a[3],p),W[1],P);
      //t4 = MUL64s(SUB64s(a[1],a[3],p),W[1],p);
      a[0] = ADD64s(t1,t3,p); // (a0+a2)+(a1+a3)
      a[1] = ADD64s(t2,t4,p); // (a0-a2)+w(a1-a3)
      a[2] = SUB64s(t1,t3,p); // (a0+a2)-(a1+a3)
      a[3] = SUB64s(t2,t4,p); // (a0-a2)-w(a1-a3)
      return;
  }
  n2 = n/2;
  b = a+n2;
  for( i=0; i<n2; i++ ) { T[i] = a[2*i]; T[i+n2] = a[2*i+1]; }
  FFT64s2T(n2,T   ,W+n2,a,p,P);
  FFT64s2T(n2,T+n2,W+n2,b,p,P);
  for( i=0; i<n2; i++ ) {
      t = mulrec64(T[n2+i],W[i],P);
      //t = MUL64s(T[n2+i],W[i],p);
      b[i] = SUB64s(T[i],t,p);
      a[i] = ADD64s(T[i],t,p);
  }
  return;
}


void FFTPermute64s( LONG n, LONG *A, LONG *T )
{   LONG i,n2;
    if( n<=2 ) return;
    n2 = n/2;
    for( i=0; i<n2; i++ ) { T[i] = A[2*i]; T[n2+i] = A[2*i+1]; }
    for( i=0; i<n; i++ ) A[i] = T[i];
    FFTPermute64s( n2, A, T );
    FFTPermute64s( n2, A+n2, T+n2 );
    return;
}


void polmod64s( LONG d, LONG n, LONG *A, LONG *B, LONG p )
{       LONG i;
        for( i=0; i<=d; i++ ) A[i] = MOD64s(B[i],p);
        for(    ; i<n;  i++ ) A[i] = 0;
        return;
}

void polpad64s( LONG d, LONG n, LONG *A, LONG *B )
{       LONG i;
        for( i=0; i<=d; i++ ) A[i] = B[i];
        for(    ; i<n;  i++ ) A[i] = 0;
        return;
}


void MakeW64( LONG n, LONG w, LONG *W, LONG p )
{  LONG i,j,m,n2;
   LONG *H,*I;
   recint P;
   P = recip1(p);
   W[0] = 1; n2 = n/2;
   //for( i=1; i<n2; i++ ) W[i] = MUL64s(w,W[i-1],p);
   for( i=1; i<n2; i++ ) W[i] = mulrec64(w,W[i-1],P);
   for( H=W,I=W+n2, m=n2/2; m>0; m=m/2 ) { for( j=0; j<m; j++ ) I[j] = H[2*j]; H=I; I=I+m; }
   return;
}

void MakeWinv64( LONG n, LONG *W, LONG p )
{  LONG i,j,n4,n2,m;
   LONG t,*H,*I;
   if( n==2 ) return;
   n2 = n/2; n4 = n/4;
   for( i=1; i<n4; i++ ) { t = W[i]; W[i] = p-W[n2-i]; W[n2-i] = p-t; }
   W[n4] = p-W[n4];
   for( H=W,I=W+n2, m=n4; m>0; m=m/2 ) { for( j=0; j<m; j++ ) I[j] = H[2*j]; H=I; I=I+m; }
   return;
}


/********************************************************************************/
/*  Fast polynomial multiplication and division                                 */
/********************************************************************************/

int FFTmul64s( LONG * a, LONG * b, LONG * c, int da, int db, LONG *T, LONG p )
{  // T has to be length at least 3n where n=2^k > da+db
   LONG i,n,dc;  LONG *A, *B, *W;  recint P;

   if( da==-1 || db==-1 ) return -1;
   P = recip1(p);
   dc = da+db;
   for( n=1; n<dc; n*=2 );    // printf("da=%d db=%d n=%d\n",da,db,n);
   if( n==dc ) { // avoid an FFT with size 2 dc
       FFTmul64s( a, b+1, c+1, da, db-1, T, p );
       c[0] = mulrec64(a[0],b[0],P);
       for( i=1; i<=da; i++ ) c[i] = ADD64s(c[i],mulrec64(b[0],a[i],P),p);
       for( dc=da+db; dc>=0 && c[dc]==0; dc-- );
       return dc;
   }
   LONG w = getomega64s(p,n);                   //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist: dc=%d  n=%d\n",dc,n); exit(1); }
   A = T; B = T+n; W = B+n;
   MakeW64(n,w,W,p);                            //printf("W := "); vecprint32s(W,n);
   polpad64s(da,n,A,a);                         //printf("A := "); vecprint32s(A,n);
   FFT64s1(n,A,W,p,P);                          //printf("F := "); vecprint32s(A,n);
   if( a==b ) B = A; // c = a^2
   else {
       polpad64s(db,n,B,b);                     //printf("B := "); vecprint32s(B,n);
       FFT64s1(n,B,W,p,P);                      //printf("F := "); vecprint32s(B,n);
   }
   for( i=0; i<n; i++ ) A[i] = mulrec64(A[i],B[i],P);  //printf("AB := "); vecprint32s(A,n);
   MakeWinv64(n,W,p);                           //printf("W := "); vecprint32s(W,n);
   FFT64s2(n,A,W,p,P);                          //printf("C := "); vecprint32s(A,n);
   LONG t = INV64s(n,p);
   for( i=0; i<=dc; i++ ) c[i] = mulrec64(t,A[i],P);
   while( dc>=0 && c[dc]==0 ) dc--;
   return dc;
}


int FFTpolmul64s( LONG *a, LONG *b, LONG *c, LONG da, LONG db, LONG p ) 
{
    LONG dc; 
    LONG n;
    if( da<0 || db<0 ) return -1;
    if( da<20 || db<20 || (LONG) da*db < 4096 ) return polmul64s(a,b,c,da,db,p);
    dc = da+db;
    for( n=1; n<=dc; n*=2 ); // FFT must hold a x b which has degree dc so n must be > dc.
    LONG *T = array64s(3*n);
    dc = FFTmul64s( a, b, c, da, db, T, p );
    free(T);
    return dc;
}


/*********************   Joris' root finding algorithm    *********************/


void FFTgraeffe64s( LONG * f, LONG * g, LONG d, LONG *T, LONG p )
{
   // Compute f(x) f(-x) = then replace x^2 with x and for add degree d, (-x)
   LONG i,n,n2;
   LONG w, *A, *B, *W; 
   recint P;
   // T has to be length at least 3n where n=2^k > da+db
   printf("Graeffe: d=%d\n",d);
   P = recip1(p);
   for( n=1; n<=2*d; n*=2 );                        //printf("n := %d;\n",n);
   w = getomega64s(p,n);                            //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist: d=%d  n=%d\n",d,n); exit(1); }
   A = T; B = T+n; W = T+2*n;
   MakeW64(n,w,W,p);                                //printf("W := "); vecprint64s(W,n);
   polpad64s(d,n,A,f);                              //printf("A := "); vecprint64s(A,n);
   FFT64s2T(n,A,W,B,p,P);                           //printf("F := "); vecprint64s(A,n);
   n2 = n/2;
   for( i=0; i<n2; i++ ) B[i] = A[n2+i];
   for( i=0; i<n2; i++ ) B[n2+i] = A[i];
   for( i=0; i<n; i++ ) A[i] = mulrec64(A[i],B[i],P);
   MakeWinv64(n,W,p);                               //printf("W := "); vecprint64s(W,n);
   FFT64s2T(n,A,W,B,p,P);                           //printf("I = "); vecprint64s(A,n);          
   LONG t = INV64s(n,p);
   for( i=0; i<=d; i++ ) A[2*i] = mulrec64(t,A[2*i],P);  //printf("A := "); vecprint64s(A,n);
   if( d%2 == 1 ) for( i=0; i<=d; i++ ) g[i] = NEG64s(A[2*i],p);
   else for( i=0; i<=d; i++ ) g[i] = A[2*i];        //printf("g := "); polprint64s(g,d); printf(";");
   printf("EXIT Graeffe\n");
   return;
}


void tangGraeffe64s( LONG *f, LONG *g, LONG d, LONG p )
{
   LONG i; LONG *mf,*mg,*H1,*H2;
   mf = array64s(d+1);
   mg = array64s(d);
   for( i=0; i<=d; i++ ) if( i&1 ) mf[i] = NEG64s(f[i],p); else mf[i] = f[i];
   for( i=0; i<d; i++ ) if( i&1 ) mg[i] = NEG64s(g[i],p); else mg[i] = g[i];
   H1 = array64s(2*d+1);
   H2 = array64s(2*d);
   polmul64s(f,mg,H1,d,d-1,p);
   polmul64s(mf,g,H2,d,d-1,p);
   poladd64s(H1,H2,H1,2*d-1,2*d-1,p);
   for( i=0; i<d; i++ ) g[i] = H1[2*i];
   polmul64s(f,mf,H1,d,d,p);
   for( i=0; i<=d; i++ ) f[i] = H1[2*i];
   if( d&1 ) {
       for( i=0; i<=d; i++ ) f[i] = NEG64s(f[i],p);
       for( i=0; i<d; i++ ) g[i] = NEG64s(g[i],p);
   }
   free(mf); free(mg);
   free(H1); free(H2);
   return;
}
   

void compress64s( LONG *a, LONG n, LONG p ) {
   LONG i;
   for( i=0; i<n/2; i++ ) a[i] = ADD64s(a[2*i],a[2*i],p);
   return;
}


void FFTtangGraeffeWork( LONG n2, LONG *A, LONG *C, LONG p, recint P ) {
   LONG i;
   for( i=0; i<n2; i++ ) // C = BC + AD = FFT( f(-x) g(x) + f(x) g(-x) )
        //C[i] = ADD64s( mulrec64(C[2*i],B[2*i],P), mulrec64(D[2*i],A[2*i],P), p );
        C[i] = ADD64s( mulrec64(C[2*i],A[2*i+1],P), mulrec64(C[2*i+1],A[2*i],P), p );
   for( i=0; i<n2; i++ ) // A = A B = FFT( f(x) f(-x) )
        //A[i] = mulrec64(A[2*i],B[2*i],P); 
        A[i] = mulrec64(A[2*i],A[2*i+1],P); 
   return;
}

void FFTtangGraeffe64s( LONG *f, LONG *g, LONG d, int k, LONG *T, LONG p )
{
   // This version composes the Tangent Graeffe transform k times
   //
   // Given h(x) = f(x) + e g(x) where deg(f)=d and deg(g)=d-1
   // Compute r(x,e) where r(x^2,e) = h(x) h(-x) mod e^2
   // Via P(x^2) = f(x) f(-x) and Q(x^2) = g(x) f(-x) + f(x) g(-x)
   // I decided to overwrite f with P(x) and g with Q(x) so that the output is f(x) + g(x) e
   // The working storage vector T needs to be of size 3n where n=2^k>2d
   // There is an optimization available for the inverse transform of vectors
   // e.g. (n=8) [a0, a0, a1, a1, a2, a2, a3, a3] 
   LONG i,j;
   LONG n,n2;
   LONG w, t, *A, *B, *C, *D, *W; 
   recint P;
   P = recip1(p);
   if( d<1 ) { printf("degree d must be at least 1\n"); exit(1); }
   for( n=1; n<=2*d; n*=2 );                        //printf("n := %d;\n",n);
   w = getomega64s(p,n);                            //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist: d=%d  n=%d\n",d,n); exit(1); }
   n2 = n/2;
   A = T; C = T+n; W = C+n; // B = W+n; D = B+n;
   MakeW64(n,w,W,p);                                //printf("W := "); vecprint64s(W,n);
   polpad64s(d,n,A,f);                              //printf("A := "); vecprint64s(A,n);
   polpad64s(d-1,n,C,g);                            //printf("C := "); vecprint64s(C,n-1);
   FFT64s1(n,A,W,p,P);  // A = FFT1(f(x))          //printf("A := "); vecprint64s(A,n);
   FFT64s1(n,C,W,p,P);  // C = FFT1(g(x))          //printf("C := "); vecprint64s(A,n);
for( j=0; j<k; j++ ) {
   //if( n>1000000 ) printf(" TG: j=%d\n", j );
   if( j>0 ) { // double the order
       MakeWinv64(n,W,p); // reset it
       VECZIPMUL64s(A+n2,W,n2,P); //for( i=0; i<n2; i++ ) A[n2+i] = mulrec64(A[n2+i],W[i],P);
       VECZIPMUL64s(C+n2,W,n2,P); //for( i=0; i<n2; i++ ) C[n2+i] = mulrec64(C[n2+i],W[i],P);
       FFT64s1(n2,A+n2,W+n2,p,P);
       FFT64s1(n2,C+n2,W+n2,p,P);
   }
   // The FFT permutation for [0 1 2 3 4 5 6 7] is [0 4 2 6 1 5 3 7]
   // The FFT permutation for f(-x) is [4 0 6 2 5 1 7 3] so just interchange
   // for( i=0; i<n; i+=2 ) { B[i] = A[i+1]; B[i+1] = A[i]; } // B = FFT1(f(-x))
   // for( i=0; i<n; i+=2 ) { D[i] = C[i+1]; D[i+1] = C[i]; } // D = FFT1(g(-x))
   // But we don't need to explicitly do that because we know where the negatives are
   for( i=0; i<n2; i++ ) // C = BC + AD = FFT( f(-x) g(x) + f(x) g(-x) )
        //C[i] = ADD64s( mulrec64(C[2*i],B[2*i],P), mulrec64(D[2*i],A[2*i],P), p );
        C[i] = ADD64s( mulrec64(C[2*i],A[2*i+1],P), mulrec64(C[2*i+1],A[2*i],P), p );
   for( i=0; i<n2; i++ ) // A = A B = FFT( f(x) f(-x) )
        //A[i] = mulrec64(A[2*i],B[2*i],P); 
        A[i] = mulrec64(A[2*i],A[2*i+1],P); 
   // A = [a0,--,a1,--,a2,--,a3,--] and C = [c0,--,c1,--,c2,--,c3,--]
   VECCOPY64s(A,A+n2,n2);  // A = [a0,a1,a2,a3,a0,a1,a2,a3]
   VECCOPY64s(C,C+n2,n2);  // C = [c0,c1,c2,c3,c0,c1,c2,c3]
   // Inverse FFT on the copies
   MakeWinv64(n,W,p);
   FFT64s2(n2,A+n2,W+n2,p,P);
   FFT64s2(n2,C+n2,W+n2,p,P);
   t = INV64s(n2,p);
   if( d&1 ) t = NEG64s(t,p); // to make lc(f) = +1 and lc(g) = +1
   VECSCAMUL64s(A+n2,n2,t,P);
   VECSCAMUL64s(C+n2,n2,t,P);
}
   VECCOPY64s(A+n2,f,d+1);
   VECCOPY64s(C+n2,g,d);
   return;
}


LONG bluestein64s( LONG *a, LONG d, LONG s, LONG *v, LONG p )
{
   LONG w,omega;
   LONG i;
   recint P;
   P = recip1(p);
   omega = getomega64s(p,s);
   if( omega==0 ) { printf("p has no s'th root of unity\n"); return omega; }
   w = 1;
   for( i=0; i<s; i++ ) { 
       v[i] = poleval64s(a,d,w,p);
       w = MUL64s(omega,w,p);
   }
   return omega;
}


LONG FFTbluestein64s( LONG *a, LONG d, LONG s, LONG *v, LONG *T, LONG p )
{
   // a(x) is a polynomial of degree d
   // compute v = [ a(w^i) mod p, 0 <= i < s ] for w^s=1 via Bluestein
   // BUG:  the computation (i*i)%(2s) can overflow in an int type
   // MBM:  the (i*i)%(2s) can be replaced using i*i = (i-1)*(i-1)+2i-1

   LONG i,j,k,N;
   LONG w,omega,winv,t,*A,*B,*W; 
   recint P;
   P = recip1(p);
   //printf("Bluestein: d=%d  s=%d\n",d,s);
   if( (p-1)%s != 0 ) { printf("s must divide p-1\n"); exit(1); }
   w = getomega64s(p,2*s);                          //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist: s=%d\n",s); exit(1); }
   omega = mulrec64(w,w,P);
   for( N=2; N<2*s; N=2*N );                        // printf("Bluestein: N = %d\n",N);
   if( (p-1)%N != 0 ) { printf("N must divide p-1\n"); exit(1); }
   // T = array64s(3*N);  T must be at least this big
   W = T; A = T+N; B = A+N;
   W[0] = 1; W[s] = p-1;
   for( i=1; i<s; i++ ) { W[i] = mulrec64(w,W[i-1],P); W[s+i] = NEG64s(W[i],p); }
   v[0] = 1;
   //for( i=1; i<s; i++ ) v[i] = W[((LONG) i*i)%(2*s)];      //printf("v := "); vecprint64s(v,s);
   for( k=0,i=1,j=1; i<s; i++,j+=2 ) { k = ADD32s(j,k,2*s); v[i] = W[k]; }
   for( i=0; i<=d; i++ ) A[i] = mulrec64(a[i],v[i],P);
   for( i=d+1; i<N; i++ ) A[i] = 0;                 //printf("A := "); vecprint64s(A,N);
   // compute W = [1,w^(-1),w^(-2),...,w^(1-2s)] from W = [1,w,w^2,...,w^(2s-1)]
   for( i=1,j=2*s-1; i<s; i++,j-- ) { t = W[i]; W[i] = W[j]; W[j] = t; }
   B[0] = 1;
   //for( i=1; i<s; i++ ) B[i] = W[((LONG) i*i)%(2*s)];
   for( k=0,i=1,j=1; i<s; i++,j+=2 ) { k = ADD32s(j,k,2*s); B[i] = W[k]; }
   for( i=s; i<N; i++ ) B[i] = 0;
   for( i=1; i<s; i++ ) B[N-i] = B[i];              //printf("B := "); vecprint64s(B,N);
   // We will multiply A B mod x^N - 1 using an FFT of order N
   w = getomega64s(p,N);                            //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist: N=%d\n",N); exit(1); }
   MakeW64(N,w,W,p);
   FFT64s1(N,A,W,p,P);                              //printf("FA := "); vecprint64s(A,N);
   FFT64s1(N,B,W,p,P);                              //printf("FB := "); vecprint64s(B,N);
   for( i=0; i<N; i++ ) A[i] = mulrec64(A[i],B[i],P);
   MakeWinv64(N,W,p);
   FFT64s2(N,A,W,p,P);
   t = INV64s(N,p);
   for( i=0; i<s; i++ ) { w = mulrec64(t,A[i],P); v[i] = mulrec64(v[i],w,P); }
   return omega; // omega^s = 1
}


/*****************************    Fast division    ******************************/


void polinv64s( LONG *f, int n, LONG *y, LONG *T, LONG p )
{   
    int m,i;
    // compute y = f^(-1) mod p as a power series to O(x^n)
    // y needs to be of size n
    // T needs to be of size ceil(3/2n)
    if( f[0]==0 ) { printf("no inverse\n"); return; }
    if( n==1 ) { y[0] = INV64s(f[0],p); return; }
    m = (n+1)/2;
    polinv64s( f, m, y, T, p );
    polmul64s( y, f, T, m-1, n-1, p );
    for( i=0; i<m; i++ ) T[i] = NEG64s(T[i+m],p);
    polmul64s( y, T, T, m-1, m-1, p );
    for( i=0; i<m && i+m<n; i++ ) y[i+m] = T[i];
    return;
}

#define INVCUTOFF 128
void FFTpolinvmod64s( LONG *f, LONG d, LONG n, LONG *y, LONG *W, LONG *Winv, LONG *T, LONG p )
{
    LONG i,m,n2;
    recint P;
    LONG *Y,*F,*M,ni;
    if( n<INVCUTOFF ) { polinv64s( f, MIN64s(n,d), y, T, p ); return; }
    Y = T;
    F = T+n;
    n2 = n/2;
    P = recip1(p);
    FFTpolinvmod64s( f, d, n2, y, W+n2, Winv+n2, T, p );
    VECCOPY64s(y,Y,n2); VECFILL64s(Y+n2,n2,0);
    FFT64s1(n,Y,W,p,P);
    m = MIN64s(d,n); VECCOPY64s(f,F,m); VECFILL64s(F+m,n-m,0);
    FFT64s1(n,F,W,p,P);
    VECZIPMUL64s(F,Y,n,P); //for( i=0; i<n; i++ ) F[i] = MUL(F[i],Y[i],p);
    FFT64s2(n,F,Winv,p,P);
    ni = modinv64s(n,p);
    VECSCAMUL64s(F,n,ni,P);
    // M = "middle product" is in second half of F
    M = F+n2; VECCOPY64s(M,F,n2); VECFILL64s(M,n2,0);
    FFT64s1(n,F,W,p,P);
    VECZIPMUL64s(F,Y,n,P); // for( i=0; i<n; i++ ) F[i] = MUL(F[i],Y[i],p);
    FFT64s2(n,F,Winv,p,P);
    VECSCAMUL64s(F,n,ni,P);
    for( i=0; i<n2; i++ ) y[n2+i] = NEG64s(F[i],p);      // yk = yk + x^n2 F
    return;
}

void FFTinv64s( LONG * f, LONG m, LONG * y, LONG *T, LONG p )
{  // y must be of length m
   // T must be of length 5n where n=2^k and n >= m
   LONG i,n;
   LONG w,winv,*W,*Winv,*Y;
   if( m==1 ) { y[0] = INV64s(f[0],p); return; }
   for( n=1; n<m; n*=2 );                       //printf("n := %d;\n",n);
   w = getomega64s(p,n);                        //printf("w := %lld;\n",w);
   if( w==0 ) { printf("omega does not exist  n=%d\n",n); exit(1); }
   W = T;
   MakeW64(n,w,W,p);
   winv = modinv64s(w,p);
   Winv = T + n; 
   MakeW64(n,winv,Winv,p);
   Y = T + 2*n;
   FFTpolinvmod64s( f, m, n, Y, W, Winv, T+3*n, p );
   for( i=0; i<m; i++ ) y[i] = Y[i];
   return;
}

int FFTpoldivinp64s( LONG *a, LONG *b, LONG da, LONG db, LONG *Q, LONG *T, LONG p ) {
// Inplace a div b using the FFT
// Q must be an array of size 4(dq+1) and T of size 4n where n=2^k>da 
    LONG i,dr,dq,n;
    LONG *ra, *rb, *rq, *y, *q, *r;
    if( db<0 ) { printf("division by zero\n"); exit(1); }
    if( da<db ) return da;
    dq = da-db;
    if( db<16 || dq<16 || (LONG) db*dq < 40000 ) return poldiv64s(a,b,da,db,p);
    q = a + db; // this is where q will go
    for( n=1; n<=da; n*=2 ); // FFT must hold q x b which has degree da so n must be > da.
    //Q = array64s(4*dq+4);
    //T = array64s(4*n);
    ra = Q; y = Q + dq + 1; rb = Q + 2*dq + 2;
    for( i=0; i<=dq; i++ ) ra[i] = a[da-i]; // ra = recip(a)
//printf("p:="); printf("%lld;\n",p);
//printf("ra:="); polprint64s(ra,dq);
    for( i=0; i<=MIN64s(db,dq); i++ ) rb[i] = b[db-i]; // rb = recip(b)
//printf("rb:="); polprint64s(rb,dq);
    while( i<=dq ) rb[i++] = 0;
    FFTinv64s( rb, dq+1, y, T, p ); // compute 1/rb to O(x^(dq+1))
//printf("inv:="); polprint64s(y,dq);
    rq = Q + 2*dq + 2;
    FFTmul64s( ra, y, rq, dq, dq, T, p ); // T must be size 3n
//printf("rq:="); polprint64s(rq,2*dq);
    for( i=0; i<=dq; i++ ) q[i] = rq[dq-i];
    r = T;
    FFTmul64s( b, q, r, db, dq, T+n, p ); // T must be size 4n
    for( i=0; i<db; i++ ) a[i] = SUB64s(a[i],r[i],p); // copy the remainder into a
    for( dr=db-1; dr>=0 && a[dr]==0; dr-- ); // compute deg(r)
    return dr;
}
    

int FFTpoldiv64s( LONG *a, LONG *b, LONG da, LONG db, LONG p ) {
    LONG i,dr,dq,n;
    LONG *Q, *T;
    if( db<0 ) { printf("division by zero\n"); exit(1); }
    if( da<db ) return da;  
    dq = da-db; 
    if( db<16 || dq<16 || (LONG) db*dq < 40000 ) return poldiv64s(a,b,da,db,p);
    for( n=1; n<=da; n*=2 ); // FFT must hold q x b which has degree da so n must be > da.
//printf("FFTpoldiv64s: da=%d  n=%d  p=%lld\n",da,n,p);
    Q = array64s(4*dq+4);
    T = array64s(4*n);
    dr = FFTpoldivinp64s( a, b, da, db, Q, T, p );
//printf("FFTpoldiv64s: dr=%d\n",dr);
    free(Q);
    free(T);
    return dr;
}


/*****************************  TREE MUL ALGORITHM  ********************************/


LONG treemulspace( LONG n, LONG m ) { LONG q;
    if( n<m ) return(n+1);
    q = (n>>1) + (n&1);
    return 2*treemulspace(q,m);
}


#define CUTOFF 16
void fastLambdarec( LONG *alpha, LONG n, LONG *f, LONG *T, LONG s, LONG *W, LONG p ) {
    LONG i,m;
    if( n==0 ) { f[0] = 1; return; }
    f[0] = NEG64s(alpha[0],p);
    f[1] = 1; 
    if( n==1 ) return;
    if( n<CUTOFF ) {
        T[1] = 1;
        for( i=1; i<n; i++ ) { T[0] = NEG64s(alpha[i],p); polmul64s(T,f,f,1,i,p); }
        return;
    }
    m = n/2;
    fastLambdarec( alpha, m, T, f, s/2, W, p );
    fastLambdarec( alpha+m, n-m, T+s/2, f, s/2, W, p );
    // FFTpolmul64s( T, T+s/2, f, m, n-m, p );
    if( n<200 ) polmul64s( T, T+s/2, f, m, n-m, p );
    else FFTmul64s( T, T+s/2, f, m, n-m, W, p );
    return;
}

void fastLambda( LONG * v, LONG n, LONG *f, LONG p ) {
// v = [a1,a2,a3,...,an] compute lambda(x) = (x-a1)(x-a2)...(x-an)
    LONG i, s, N, d;
    LONG a[2], * c, *T, *W;
    if( n<CUTOFF ) {
        c = f;
        a[1] = 1;
        c[0] = 1;
        for( i=0; i<n; i++ ) {
            a[0] = NEG64s(v[i],p); // a = x-v[i]
            polmul64s(a,c,c,1,i,p);
        }
        return;
    } else {
        s = treemulspace( n, CUTOFF ); //printf("s = %d\n",s);
        //s = 2*s;
        T = array64s(s);
        for( N=1; N<=n; N*=2 ); // FFT must hold lambda(x) of degree n so N > n.
        //printf("N = %d\n",N);
        W = array64s(3*N);
        fastLambdarec( v, n, f, T, s, W, p );
        free(W);
        free(T);
        return;
    }
}


/*****************************  Fast change of basis  ******************************/


void makedivisors( LONG alpha, LONG n, LONG *T, LONG p ) {
// construct T = [ (x-alpha)^n  (x-alpha)^(n/2) ... (x-alpha)^2  (x-alpha) ]
   LONG m;
   LONG *g, h[2];
   if( n<1 ) return;
   if( n==1 ) { T[0] = NEG64s(alpha,p); T[1] = 1; return; }
   m = n/2;
   g = T+n+1;
   makedivisors( alpha, m, g, p );
   FFTpolmul64s( g, g, T, m, m, p );
   return;
}


void makepowers( LONG alpha, LONG n, LONG *T, LONG p ) {
// construct T = [ (x+alpha)^n  (x+alpha)^(n/2) ... (x+alpha)^2  (x+alpha) ]
   LONG m;
   LONG *g, h[2];
   if( n<1 ) return;
   if( n==1 ) { T[0] = alpha; T[1] = 1; return; }
   m = n/2;
   g = T+n+1;
   makepowers( alpha, m, g, p );
   FFTpolmul64s( g, g, T, m, m, p );
   return;
}


void recbase( LONG *f, LONG n, LONG alpha, LONG *T, LONG m, LONG p ) {
   // f(x) has degree n
   // T = [ (x-alpha)^m  (x-alpha)^(m/2) ... (x-alpha)^2  (x-alpha) ]
   // m is a power of 2
   // Let (q,r) = f div (x-alpha)^m.
   // Output r(x+alpha) + x^m + q(x+alpha)
   LONG i,dr;
   if( n<=0 ) return;
   if( n==1 ) { f[0] = ADD64s( f[0], MUL64s(f[1],alpha,p), p ); return; }
   if( n<m ) return recbase( f, n, alpha, T+(m+1), m/2, p );
   //dr = poldiv64s( f, T, n, m, p );
   dr = FFTpoldiv64s( f, T, n, m, p ); // T[1] = (x-alpha)^m
   // the remainder is in f[0..dr] and the quotient is in f[m..n]
   recbase( f, dr, alpha, T+(m+1), m/2, p );
   for( i=dr+1; i<m/2; i++ ) f[i] = 0;
   recbase( f+m, n-m, alpha, T+(m+1), m/2, p );
   //printf("n=%d  m=%d  dr=%d  dq=%d\n",n,m,dr,n-m);
   return;
}
   

void recbase2( LONG *f, LONG n, LONG alpha, LONG *T, LONG m, LONG *W, LONG *S, LONG p ) {
   // f(x) has degree n
   // T = [ (x+alpha)^m  (x+alpha)^(m/2) ... (x+alpha)^2  (x+alpha) ]
   // m is a power of 2
   // Convert f(x+alpha) via f1(x+alpha) + f2(x+alpha) (x+alpha)^m using multiplication
   // W is space for a product of size n+1
   LONG i,d,dr,N;
   if( n<=0 ) return;
   if( n==1 ) { f[0] = ADD64s( f[0], MUL64s(f[1],alpha,p), p ); return; }
   if( n<m ) return recbase2( f, n, alpha, T+(m+1), m/2, W, S, p );
   for( dr=m-1; dr>=0 && f[dr]==0; dr-- );
   recbase2( f, dr, alpha, T+(m+1), m/2, W, S, p );
   recbase2( f+m, n-m, alpha, T+(m+1), m/2, W, S, p );
   if( n<20 || m<20 || (LONG) m*n < 4096 ) d = polmul64s( f+m, T, W, n-m, m, p );
   else d = FFTmul64s( f+m, T, W, n-m, m, S, p );
   //d = FFTpolmul64s( f+m, T, W, n-m, m, p);
   if( d!=n ) printf("recbase2 degree bug\n");
   poladd64s( W, f, f, n, dr, p );
   return;
}


int divisorsspace( LONG n ) { 
   // space required for polynomials in (x-alpha)^n list for n in [1,2,4,8,...,n=2^k]
   if( n<1 ) return 0;
   if( n==1 ) return 2;
   return( n+1 + divisorsspace(n/2) );
}


void changebase( LONG *f, LONG n, LONG alpha, LONG p ) {
// write f(x+alpha) = sum( a_i (x-alpha)^i ) and output [a0,a1,...,an] in f
    LONG m,s; LONG *T;
    if( n==0 ) { return; }
    if( n==1 ) { f[0] = MUL64s(f[1],alpha,p); return; }
    for( m=1; 2*m<n; m=2*m );
    s = divisorsspace( m );
    T = array64s(s);
    makedivisors( alpha, m, T, p );
    recbase( f, n, alpha, T, m, p );
    free(T);
    return;
}


void changebase2( LONG *f, LONG n, LONG alpha, LONG p ) {
// write f(x+alpha) = f1(x+alpha) + f2(x+alpha)*(x+alpha)^d/2
    LONG m,s; LONG *S,*T,*W;
    if( n==0 ) { return; }
    if( n==1 ) { f[0] = MUL64s(f[1],alpha,p); return; }
    for( m=1; 2*m<=n; m=2*m );
    s = divisorsspace( m );
    T = array64s(s);
    makepowers( alpha, m, T, p );
    S = array64s( (LONG) 6*m );
    W = array64s(n+1);
    recbase2( f, n, alpha, T, m, W, S, p );
    free(W);
    free(S);
    free(T);
    return;
}

void polrev64s( LONG *f, LONG d ) {
    LONG i; LONG t;
    for( i=0; i<=d/2; i++ ) { t = f[i]; f[i] = f[d-i]; f[d-i] = t; }
    return;
}

void changebase3( LONG *f, LONG n, LONG alpha, LONG p ) {
//  Input f a polynomial of degree n in Zp[x]
//  Output f(x+alpha) mod p in the array f
//  This version computes f(x+alpha) in O( M(n) ) instead of O( M(n) log n )
//  Since the method computes 1/i! mod p we cannot use it for p<=n.
//  Computing inverses is expensive so some thought is needed for that.
//  Joris suggested precomputing (1/i!)^(-1) and going backwards.
//  Since the we have to compute i! first anyway this is free.
    LONG i,fac,inv,*g,*h;
    recint P;
    if( p<=n || n<3000 ) return changebase2(f,n,alpha,p);
    P = recip1(p);
    fac = 1;
    for( i=1; i<=n; i++ ) {
        // compute f[i] = f[i]*i! mod p
        fac = mulrec64(i,fac,P);
        f[i] = mulrec64(fac,f[i],P);
    }
    inv = modinv64s(fac,p); // = 1/n! mod p
    polrev64s(f,n);
    g = array64s(n+1);
    g[0] = 1;
    for( i=1; i<=n; i++ ) {
        // compute g[i] = alpha^i mod p
        g[i] = mulrec64(alpha,g[i-1],P);
    }
    fac = inv;
    for( i=n; i>0; i-- ) {
        // compute g[i] = alpha^i/i! mod p
        g[i] = mulrec64(fac,g[i],P);
        fac = mulrec64((LONG) i,fac,P); 
    }
    h = array64s(2*n+1);
    FFTpolmul64s(f,g,h,n,n,p);
    polrev64s(h,n);
    f[0] = h[0];
    fac = inv;
    for( i=n; i>0; i-- ) {
        // compute f[i] = h[i]/i! mod p
        f[i] = mulrec64(fac,h[i],P);
        fac = mulrec64(fac,(LONG) i,P);
    }
    free(g);
    free(h);
    return;
}

