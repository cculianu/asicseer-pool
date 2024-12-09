// Limited port of Bitcoin Core src/random.cpp
//
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "config.h"
#include "sha512.h"
#include "../util_cxx.h"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <optional>
#include <string_view>
#include <utility>

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#endif
#ifdef HAVE_ARC4RANDOM
#include <stdlib.h>
#endif

// TODO: Import the threadsafety stuff from Bitcoin
#define GUARDED_BY(x)
#define EXCLUSIVE_LOCKS_REQUIRED(x)
#define PASTE(x, y) x ## y
#define PASTE2(x, y) PASTE(x, y)
#define UNIQUE_NAME(name) PASTE2(name, __COUNTER__)
#define LOCK(x) std::unique_lock UNIQUE_NAME(lock___)(x)

namespace {

inline constexpr size_t HALF_SHA512_SIZE = CSHA512::OUTPUT_SIZE / 2;
static_assert(HALF_SHA512_SIZE * 2 == CSHA512::OUTPUT_SIZE);

/* Number of random bytes returned by GetOSRand.
 * When changing this constant make sure to change all call sites, and make
 * sure that the underlying OS APIs for all platforms support the number.
 * (many cap out at 256 bytes).
 */
inline constexpr size_t NUM_OS_RANDOM_BYTES = HALF_SHA512_SIZE;

using Mutex = std::mutex;

class RNGState {
    Mutex m_mutex;
    /* The RNG state consists of 256 bits of entropy, taken from the output of
     * one operation's SHA512 output, and fed as input to the next one.
     * Carrying 256 bits of entropy should be sufficient to guarantee
     * unpredictability as long as any entropy source was ever unpredictable
     * to an attacker. To protect against situations where an attacker might
     * observe the RNG's state, fresh entropy is always mixed when
     * GetStrongRandBytes is called.
     */
    unsigned char m_state[HALF_SHA512_SIZE] GUARDED_BY(m_mutex) = {0};
    uint64_t m_counter GUARDED_BY(m_mutex) = 0;

public:
    RNGState() noexcept = default;
    ~RNGState() = default;

    /** Extract up to 32 bytes of entropy from the RNG state, mixing in new entropy from hasher.
     *
     * On first invocation this function returns false.
     */
    bool MixExtract(std::span<unsigned char> out, CSHA512&& hasher) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
        assert(out.size() <= HALF_SHA512_SIZE);
        unsigned char buf[CSHA512::OUTPUT_SIZE];
        bool ret;
        {
            LOCK(m_mutex);
            // Write the current state of the RNG into the hasher
            hasher.Write(m_state, sizeof(m_state));
            // Write a new counter number into the state
            hasher.Write((const unsigned char*)&m_counter, sizeof(m_counter));
            ret = m_counter++;
            // Finalize the hasher
            hasher.Finalize(buf);
            // Store the last 32 bytes of the hash output as new RNG state.
            std::memcpy(m_state, buf + HALF_SHA512_SIZE, HALF_SHA512_SIZE);
        }
        // If desired, copy (up to) the first 32 bytes of the hash output as output.
        if (!out.empty()) {
            std::memcpy(out.data(), buf, out.size());
        }
        // Best effort cleanup of internal state
        hasher.Reset();
        return ret;
    }
};

RNGState& GetRNGState() noexcept
{
    static std::once_flag flag;
    static std::optional<RNGState> g_opt_rng;
    std::call_once(flag, []{ g_opt_rng.emplace(); });
    return g_opt_rng.value();
}

void SeedTimestamp(CSHA512& hasher) noexcept
{
    auto GetPerformanceCounter = []() -> uint64_t {
        // Read the hardware time stamp counter when available.
        // See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
        return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
        uint64_t r = 0;
        __asm__ volatile ("rdtsc" : "=A"(r)); // Constrain the r variable to the eax:edx pair.
        return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
        uint64_t r1 = 0, r2 = 0;
        __asm__ volatile ("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
        return (r2 << 32) | r1;
#else
        // Fall back to using standard library clock (usually microsecond or nanosecond precision)
        return static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
#endif
    };
    const uint64_t perfcounter = GetPerformanceCounter();
    hasher.Write(std::span{reinterpret_cast<const unsigned char *>(&perfcounter), sizeof(perfcounter)});
}

void SeedFast(CSHA512& hasher) noexcept
{
    unsigned char dummy[4];

    // Stack pointer to indirectly commit to thread/callstack
    unsigned char *ptr = dummy;
    hasher.Write(std::span{reinterpret_cast<unsigned char *>(&ptr), sizeof(ptr)});

    // High-precision timestamp
    SeedTimestamp(hasher);
}

[[noreturn]] void RandFailure(std::string_view source)
{
    std::cerr << "Failed to read randomness from " << source << "\n" << std::flush;
    std::abort();
}

/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
[[maybe_unused]] void GetDevURandom(std::span<unsigned char> ent32)
{
    if (ent32.empty()) return;
    FILE *f = std::fopen("/dev/urandom", "rb");
    if (!f) {
        RandFailure("/dev/urandom");
    }
    Defer d([&f]{
        if (f) {
            std::fclose(f);
            f = nullptr;
        }
    });
    size_t have = 0;
    do {
        size_t n = std::fread(ent32.data() + have, 1, ent32.size() - have, f);
        if (n == 0 || n + have > ent32.size()) {
            RandFailure("/dev/urandom");
        }
        have += n;
    } while (have < ent32.size());
}

/** Get 32 bytes of system entropy. */
void GetOSRand(std::span<unsigned char> ent32)
{
    if (ent32.empty()) return;
#if defined(WIN32)
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) {
        RandFailure("Windows Crypto API");
    }
    ret = CryptGenRandom(hProvider, ent32.size(), ent32.data());
    if (!ret) {
        RandFailure("Windows Crypto API");
    }
    CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_ARC4RANDOM)
    /* OpenBSD. From the arc4random(3) man page:
       "Use of these functions is encouraged for almost all random number
        consumption because the other interfaces are deficient in either
        quality, portability, standardization, or availability."
       The function call is always successful.
     */
    arc4random_buf(ent32.data(), ent32.size());
#else
    /* Fall back to /dev/urandom if there is no specific method implemented to
     * get system entropy for this OS.
     */
    GetDevURandom(ent32);
#endif
}


void SeedStartup(CSHA512& hasher, RNGState& rng) noexcept
{
    unsigned char buffer[NUM_OS_RANDOM_BYTES];
    // OS randomness
    GetOSRand(buffer);
    hasher.Write(buffer, sizeof(buffer));
}

void ProcRand(std::span<unsigned char> out) noexcept
{
    // Make sure the RNG is initialized first (as all Seed* function possibly need hwrand to be available).
    RNGState& rng = GetRNGState();

    assert(out.size() <= HALF_SHA512_SIZE);

    CSHA512 hasher;
    SeedFast(hasher);

    // Combine with and update state
    if (!rng.MixExtract(out, std::move(hasher))) {
        // On the first invocation, also seed with SeedStartup().
        CSHA512 startup_hasher;
        SeedStartup(startup_hasher, rng);
        rng.MixExtract(out, std::move(startup_hasher));
    }
}
} // namespace

void GetRandBytes(std::span<unsigned char> bytes) noexcept
{
    do {
        // Do up to 32-bytes at a time since that's ProcRand()'s limit.
        auto sp = bytes.subspan(0, std::min(bytes.size(), HALF_SHA512_SIZE));
        ProcRand(sp);
        bytes = bytes.subspan(sp.size());
    } while (!bytes.empty());
}
