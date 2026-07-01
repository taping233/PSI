#ifndef MODSYSTEM_H
#define MODSYSTEM_H

#include <gmp.h>
#include <stddef.h>

typedef struct {
    mpz_t M;
    mpz_t *m_list;
    size_t m_count;
} ModSystem;

void modsystem_init_auto(ModSystem *sys, unsigned int M_bits,
                         unsigned long seed);
void modsystem_init_auto_with_order(ModSystem *sys, unsigned int M_bits,
                                    unsigned long fft_order,
                                    unsigned long seed);
void modsystem_init(ModSystem *mods, mpz_t p, unsigned int seed);
void modsystem_init_with_order(ModSystem *mods, mpz_t p,
                               unsigned long fft_order,
                               unsigned int seed);
void modsystem_free(ModSystem *sys);
void modsystem_print(const ModSystem *sys);

#endif
