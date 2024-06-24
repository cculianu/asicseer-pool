// Copyright (c) 2017-2019 The Bitcoin Core developers
// Copyright (c) 2020-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#if defined(__cplusplus) && (defined(__x86_64__) || defined(__amd64__) || defined(__i386__))
#define HAVE_GETCPUID

#include <cstdint>

#include <cpuid.h>

// We can't use cpuid.h's __get_cpuid as it does not support subleafs.
static inline void GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
#ifdef __GNUC__
    __cpuid_count(leaf, subleaf, a, b, c, d);
#else
    __asm__("cpuid"
            : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
            : "0"(leaf), "2"(subleaf));
#endif
}

#endif // defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
