#include <NTL/lzz_p.h>
#include <NTL/lzz_pX.h>

#include <flint/flint.h>
#include <flint/nmod_poly.h>
#include <flint/nmod_poly_factor.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static const uint64_t FIELD_PRIME = 180143985094819841ULL;

static void die(const std::string &message)
{
    std::cerr << message << "\n";
    std::exit(2);
}

static uint64_t read_u64(std::istream &in, const char *name)
{
    uint64_t value = 0;
    if (!(in >> value)) {
        die(std::string("missing ") + name);
    }
    return value;
}

static void init_field()
{
    NTL::zz_p::init((long)FIELD_PRIME);
}

static uint64_t coeff_u64(const NTL::zz_pX &poly, long i)
{
    return (uint64_t)NTL::rep(NTL::coeff(poly, i));
}

static std::vector<uint64_t> to_vec(const NTL::zz_pX &poly, size_t min_len = 1)
{
    long d = NTL::deg(poly);
    size_t len = d < 0 ? 1 : (size_t)d + 1;
    if (len < min_len) len = min_len;
    std::vector<uint64_t> out(len, 0);
    for (long i = 0; d >= 0 && i <= d; ++i) {
        out[(size_t)i] = coeff_u64(poly, i);
    }
    while (out.size() > min_len && out.back() == 0) out.pop_back();
    return out;
}

static NTL::zz_pX from_vec(const std::vector<uint64_t> &coeffs)
{
    NTL::zz_pX poly;
    for (size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] != 0) {
            NTL::SetCoeff(poly, (long)i, NTL::to_zz_p((long)(coeffs[i] % FIELD_PRIME)));
        }
    }
    return poly;
}

static void print_vec(std::ostream &out, const std::vector<uint64_t> &values)
{
    out << '[';
    for (size_t i = 0; i < values.size(); ++i) {
        if (i) out << ',';
        out << values[i];
    }
    out << ']';
}

static uint64_t random_field(std::mt19937_64 &rng)
{
    return rng() % FIELD_PRIME;
}

static void command_share()
{
    init_field();
    uint64_t rounds = read_u64(std::cin, "rounds");
    uint64_t degree_bound = read_u64(std::cin, "degree_bound");
    uint64_t value_count = read_u64(std::cin, "value_count");
    std::set<uint64_t> unique;
    for (uint64_t i = 0; i < value_count; ++i) {
        uint64_t value = read_u64(std::cin, "value");
        if (value > UINT32_MAX) die("dataset element exceeds 32-bit range");
        unique.insert(value);
    }
    if (unique.size() > degree_bound) die("dataset exceeds degree bound");

    NTL::zz_pX set_poly;
    NTL::SetCoeff(set_poly, 0, 1);
    for (uint64_t value : unique) {
        NTL::zz_pX factor;
        NTL::SetCoeff(factor, 0, NTL::to_zz_p((long)((FIELD_PRIME - value) % FIELD_PRIME)));
        NTL::SetCoeff(factor, 1, 1);
        set_poly *= factor;
    }

    std::random_device rd;
    std::mt19937_64 rng(((uint64_t)rd() << 32) ^ rd());
    size_t public_len = (size_t)2 * (size_t)degree_bound + 1;

    std::cout << "{\"field_prime\":" << FIELD_PRIME << ",\"cloud\":[";
    std::vector<std::vector<uint64_t>> query_shares;
    for (uint64_t round = 1; round <= rounds; ++round) {
        NTL::zz_pX omega;
        for (uint64_t i = 0; i <= degree_bound; ++i) {
            uint64_t c = random_field(rng);
            if (i == degree_bound && c == 0) c = 1;
            if (c != 0) NTL::SetCoeff(omega, (long)i, NTL::to_zz_p((long)c));
        }
        NTL::zz_pX q = set_poly * omega;
        std::vector<uint64_t> qv = to_vec(q, public_len);
        qv.resize(public_len, 0);
        std::vector<uint64_t> cloud(public_len, 0), query(public_len, 0);
        for (size_t i = 0; i < public_len; ++i) {
            cloud[i] = random_field(rng);
            query[i] = (qv[i] + FIELD_PRIME - cloud[i]) % FIELD_PRIME;
        }
        query_shares.push_back(query);
        if (round > 1) std::cout << ',';
        std::cout << "{\"round\":" << round << ",\"share\":";
        print_vec(std::cout, cloud);
        std::cout << '}';
    }
    std::cout << "],\"query\":[";
    for (uint64_t round = 1; round <= rounds; ++round) {
        if (round > 1) std::cout << ',';
        std::cout << "{\"round\":" << round << ",\"share\":";
        print_vec(std::cout, query_shares[(size_t)round - 1]);
        std::cout << '}';
    }
    std::cout << "]}\n";
}

static std::vector<uint64_t> flint_linear_roots(const std::vector<uint64_t> &poly)
{
    nmod_poly_t f;
    nmod_poly_factor_t fac;
    nmod_poly_init2(f, (mp_limb_t)FIELD_PRIME, (slong)poly.size());
    nmod_poly_factor_init(fac);
    for (size_t i = 0; i < poly.size(); ++i) {
        nmod_poly_set_coeff_ui(f, (slong)i, (mp_limb_t)(poly[i] % FIELD_PRIME));
    }
    nmod_poly_factor(fac, f);
    std::vector<uint64_t> roots;
    for (slong i = 0; i < fac->num; ++i) {
        nmod_poly_struct *factor = fac->p + i;
        if (nmod_poly_degree(factor) != 1) continue;
        uint64_t constant = (uint64_t)nmod_poly_get_coeff_ui(factor, 0);
        uint64_t leading = (uint64_t)nmod_poly_get_coeff_ui(factor, 1);
        NTL::zz_p root = -NTL::to_zz_p((long)constant) / NTL::to_zz_p((long)leading);
        uint64_t root_u = (uint64_t)NTL::rep(root);
        for (slong e = 0; e < fac->exp[i]; ++e) roots.push_back(root_u);
    }
    nmod_poly_factor_clear(fac);
    nmod_poly_clear(f);
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    return roots;
}

static void command_roots()
{
    init_field();
    uint64_t n1 = read_u64(std::cin, "len1");
    std::vector<uint64_t> lhs((size_t)n1);
    for (uint64_t i = 0; i < n1; ++i) lhs[(size_t)i] = read_u64(std::cin, "lhs coeff") % FIELD_PRIME;
    uint64_t n2 = read_u64(std::cin, "len2");
    std::vector<uint64_t> rhs((size_t)n2);
    for (uint64_t i = 0; i < n2; ++i) rhs[(size_t)i] = read_u64(std::cin, "rhs coeff") % FIELD_PRIME;

    NTL::zz_pX a = from_vec(lhs);
    NTL::zz_pX b = from_vec(rhs);
    NTL::zz_pX g = NTL::GCD(a, b);
    if (NTL::deg(g) >= 0) NTL::MakeMonic(g);
    std::vector<uint64_t> gv = to_vec(g, 1);
    std::vector<uint64_t> roots = flint_linear_roots(gv);
    std::cout << "{\"field_prime\":" << FIELD_PRIME << ",\"degree_gcd\":"
              << (gv.size() ? gv.size() - 1 : 0) << ",\"gcd\":";
    print_vec(std::cout, gv);
    std::cout << ",\"roots\":";
    print_vec(std::cout, roots);
    std::cout << "}\n";
}


static void command_eval()
{
    init_field();
    uint64_t n = read_u64(std::cin, "poly len");
    std::vector<uint64_t> coeffs((size_t)n);
    for (uint64_t i = 0; i < n; ++i) coeffs[(size_t)i] = read_u64(std::cin, "poly coeff") % FIELD_PRIME;
    uint64_t value_count = read_u64(std::cin, "value count");
    std::vector<mp_limb_t> xs((size_t)value_count), ys((size_t)value_count);
    std::vector<uint64_t> original((size_t)value_count);
    for (uint64_t i = 0; i < value_count; ++i) {
        uint64_t value = read_u64(std::cin, "query value");
        if (value > UINT32_MAX) die("query element exceeds 32-bit range");
        original[(size_t)i] = value;
        xs[(size_t)i] = (mp_limb_t)(value % FIELD_PRIME);
    }

    nmod_poly_t f;
    nmod_poly_init2(f, (mp_limb_t)FIELD_PRIME, (slong)coeffs.size());
    for (size_t i = 0; i < coeffs.size(); ++i) {
        nmod_poly_set_coeff_ui(f, (slong)i, (mp_limb_t)coeffs[i]);
    }
    if (value_count) {
        nmod_poly_evaluate_nmod_vec_fast(ys.data(), f, xs.data(), (slong)value_count);
    }
    nmod_poly_clear(f);

    std::vector<uint64_t> matches;
    for (size_t i = 0; i < original.size(); ++i) {
        if (ys[i] == 0) matches.push_back(original[i]);
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    std::cout << "{\"field_prime\":" << FIELD_PRIME << ",\"tested\":"
              << value_count << ",\"matches\":";
    print_vec(std::cout, matches);
    std::cout << ",\"match_count\":" << matches.size() << "}\n";
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        die("usage: dpsi_poly_backend share|roots|eval < input");
    }
    std::string command = argv[1];
    if (command == "share") {
        command_share();
        return 0;
    }
    if (command == "roots") {
        command_roots();
        return 0;
    }
    if (command == "eval") {
        command_eval();
        return 0;
    }
    die("unknown command: " + command);
    return 2;
}
