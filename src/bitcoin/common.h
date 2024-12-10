// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "config.h"

#ifdef __cplusplus
#include <cstdint>
#include <cstring>
#include <type_traits>
static_assert(std::is_same_v<uint8_t, unsigned char>, "Assumption is that uint8_t and unsigned char are the same type");
#define STD_NS std::
#else
#include <stdint.h>
#include <string.h>
#define STD_NS
#endif

#include "compat_endian.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16_t ReadLE16(const uint8_t *ptr) {
    uint16_t x;
    STD_NS memcpy(&x, ptr, 2);
    return le16toh(x);
}

static inline uint32_t ReadLE32(const uint8_t *ptr) {
    uint32_t x;
    STD_NS memcpy(&x, ptr, 4);
    return le32toh(x);
}

static inline uint64_t ReadLE64(const uint8_t *ptr) {
    uint64_t x;
    STD_NS memcpy(&x, ptr, 8);
    return le64toh(x);
}

static inline void WriteLE16(uint8_t *ptr, uint16_t x) {
    uint16_t v = htole16(x);
    STD_NS memcpy(ptr, &v, 2);
}

static inline void WriteLE32(uint8_t *ptr, uint32_t x) {
    uint32_t v = htole32(x);
    STD_NS memcpy(ptr, &v, 4);
}

static inline void WriteLE64(uint8_t *ptr, uint64_t x) {
    uint64_t v = htole64(x);
    STD_NS memcpy(ptr, &v, 8);
}

uint16_t static inline ReadBE16(const uint8_t *ptr) {
    uint16_t x;
    STD_NS memcpy(&x, ptr, 2);
    return be16toh(x);
}

static inline uint32_t ReadBE32(const uint8_t *ptr) {
    uint32_t x;
    STD_NS memcpy(&x, ptr, 4);
    return be32toh(x);
}

static inline uint64_t ReadBE64(const uint8_t *ptr) {
    uint64_t x;
    STD_NS memcpy(&x, ptr, 8);
    return be64toh(x);
}

static inline void WriteBE32(uint8_t *ptr, uint32_t x) {
    uint32_t v = htobe32(x);
    STD_NS memcpy(ptr, &v, 4);
}

static inline void WriteBE64(uint8_t *ptr, uint64_t x) {
    uint64_t v = htobe64(x);
    STD_NS memcpy(ptr, &v, 8);
}

/**
 * Return the smallest number n such that (x >> n) == 0 (or 64 if the highest
 * bit in x is set.
 */
static inline uint64_t CountBits(uint64_t x) {
#ifdef HAVE_DECL___BUILTIN_CLZL
    if (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long) - __builtin_clzl(x) : 0;
    }
#endif
#ifdef HAVE_DECL___BUILTIN_CLZLL
    if (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long long) - __builtin_clzll(x) : 0;
    }
#endif
    int ret = 0;
    while (x) {
        x >>= 1;
        ++ret;
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
#undef STD_NS
