// This code computes primitive elements -- precomputed for some primes
// Copyright, Michael Monagan, March 2020.

#include<stdio.h>
#define LONG long long int

int ifactor64s( LONG n, LONG *P ) {
// return k factors in P[0], P[1], ..., P[k-1]
    int k; LONG p,q,r; 
    p = 2;
    k = 0;
    while( n>1 ) {
        q = n/p; r = n-p*q;
        if( r==0 ) P[k++] = p;
        while( r==0 ) { n = q; q = n/p; r = n-q*p; }
        if( p==2 ) p = 3; else p += 2;
        if( n>1 && p*p>n ) { P[k++] = n; n = 1; }
    }
    return k;
}

LONG powmod64s( LONG a, LONG n, LONG p );

int isprimitive64s( LONG a, LONG *P, int n, LONG p ) {
    int k;
    for( k=0; k<n; k++ ) if( powmod64s(a,(p-1)/P[k],p) == 1 ) return 0;
    return 1;
}

LONG getprimelem64s( LONG p ) {
    int k; LONG a,P[30];
    if( p==180143985094819841LL ) return 6;
    if( p==1231453023109121LL ) return 3;
    if( p==6269010681299730433LL ) return 5;
    if( p==4719772409484279809LL ) return 6;
    if( p==469762049 ) return 3;
    if( p==3221225473LL ) return 5;
    k = ifactor64s(p-1,P);
    for( a=2; !isprimitive64s(a,P,k,p); a++ );
    return a;
}
    
/*
int main() {
    int i,k;
    LONG p,P[10],a;
    p = 1; 
    p = 3*29*(p << 56) + 1;
    k = ifactor64s(p-1,P);
    for( i=0; i<k; i++ ) printf("P[%d]==%lld\n",i,P[i]);
    a = getprimelem64s(p);
    printf("a = %lld\n",a);
    p = 1; 
    p = 5*(p << 55) + 1;
    k = ifactor64s(p-1,P);
    for( i=0; i<k; i++ ) printf("P[%d]==%lld\n",i,P[i]);
    a = getprimelem64s(p);
    printf("a = %lld\n",a);
    return 1;
}
*/
