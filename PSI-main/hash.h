#ifndef HASH_H
#define HASH_H

#include <gmp.h>
#include <stdint.h>

// 计算 48-bit 哈希值（返回 uint64_t 低 48 位）
uint64_t hash48_compute(const mpz_t x);

// 计算哈希并附加到低位： s' = (s << 48) | h(s)
void hash48_append(mpz_t result, const mpz_t x);

// 校验：提取低48位哈希并验证是否匹配
// 返回 1 表示验证成功，0 表示失败
int hash48_verify(const mpz_t x_with_hash);

// 去除低48位哈希部分，得到原始数据
void hash48_strip(mpz_t out, const mpz_t x_with_hash);

#endif // HASH_H

