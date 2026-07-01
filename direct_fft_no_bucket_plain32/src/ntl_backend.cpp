#include <NTL/lzz_p.h>
#include <NTL/lzz_pX.h>

#include <cstdint>
#include <cstdlib>

extern "C" int ntl_poly_gcd_u64(const uint64_t *lhs, size_t lhs_len,
                                const uint64_t *rhs, size_t rhs_len,
                                uint64_t prime, uint64_t *out,
                                size_t *out_len)
{
    if (!lhs || !rhs || !out || !out_len || lhs_len == 0 || rhs_len == 0) {
        return 0;
    }

    NTL::zz_p::init((long)prime);

    NTL::zz_pX a;
    NTL::zz_pX b;
    for (size_t i = 0; i < lhs_len; ++i) {
        if (lhs[i] != 0) {
            NTL::SetCoeff(a, (long)i, NTL::to_zz_p((long)lhs[i]));
        }
    }
    for (size_t i = 0; i < rhs_len; ++i) {
        if (rhs[i] != 0) {
            NTL::SetCoeff(b, (long)i, NTL::to_zz_p((long)rhs[i]));
        }
    }

    NTL::zz_pX g = NTL::GCD(a, b);
    NTL::MakeMonic(g);
    long degree = NTL::deg(g);
    if (degree < 0) {
        out[0] = 0;
        *out_len = 1;
        return 1;
    }

    for (long i = 0; i <= degree; ++i) {
        out[i] = (uint64_t)NTL::rep(NTL::coeff(g, i));
    }
    *out_len = (size_t)degree + 1;
    return 1;
}
