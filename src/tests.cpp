/*
 * Copyright (c) 2024 Calin Culianu <calin.culianu@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "bitcoin/sha256.h"
#include "bitcoin/sha512.h"
#include "cashaddr.h"
#include "libasicseerpool.h"
#include "sha2.h"
#include "util_cxx.h"

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

template <ByteLike ByteT>
void GetRandBytes(ByteT *dest, std::size_t count) {  get_random_bytes(dest, count); }

template <ByteLike ByteT = std::byte>
std::vector<ByteT> MakeRandBytes(size_t count) {
    std::vector<ByteT> ret(count);
    GetRandBytes(ret.data(), count);
    return ret;
}

/** Generate a random 64-bit integer. */
template <std::integral U>
inline U randInt() noexcept {
    U num;
    GetRandBytes(reinterpret_cast<std::byte *>(&num), sizeof(num));
    return num;
}

inline uint64_t rand64() { return randInt<uint64_t>(); }
inline uint32_t rand32() { return randInt<uint32_t>(); }

inline uint64_t InsecureRandRange(uint64_t range) { return rand64() % range; }
inline uint64_t InsecureRandBits(int bits) {
    if (bits == 0)
        return 0;
    else if (bits <= 32)
        return rand32() >> (32 - bits);
    else
        return rand64() >> (64 - bits);
}
[[maybe_unused]] inline std::uint32_t InsecureRand32() { return rand32(); }
[[maybe_unused]] inline bool InsecureRandBool() { return InsecureRandBits(1); }

class Log {
protected:
    std::string buf;
    bool suppress = false;
public:
    Log() = default;
    virtual ~Log();

    template <typename T>
    Log & operator<<(T && t) {
        buf += std::format("{}", t);
        return *this;
    }
};

Log::~Log() { if (!suppress) std::cout << buf << "\n" << std::flush; }

struct Warning : Log { Warning() { buf = "WARNING: "; } };
struct Error : Log { Error() { buf = "ERROR: "; } };
struct Trace : Log {
    static inline bool enabled = false;
    Trace() { suppress = !enabled; buf = "TRACE: "; }
};

class Tic {
    using Clock = std::conditional_t<std::chrono::high_resolution_clock::is_steady, std::chrono::high_resolution_clock,
                                     std::chrono::steady_clock>;
    std::chrono::time_point<Clock, std::chrono::nanoseconds> tstart = Clock::now();
public:
    int64_t nsec() const { return (Clock::now() - tstart).count(); }
    double msec() const { return (Clock::now() - tstart).count() / 1e6; }
    double sec() const { return (Clock::now() - tstart).count() / 1e9; }
    std::string msecStr() const { return std::format("{:1.3f}", msec()); }
    std::string secStr() const { return std::format("{:1.3f}", sec()); }
};

using VoidFunc = std::function<void()>;

std::vector<uint8_t> ParseHex(const std::string &hex) {
    std::vector<uint8_t> ret(hex.size() / 2);
    const bool ok = hex2bin(ret.data(), hex.c_str(), ret.size());
    if (!ok) throw std::runtime_error(std::format("ParseHex failed for hex string: {}", hex));
    return ret;
}

/// BCHN Unit Test work-alike support ...
struct Context {
    const std::string name;
    unsigned  nChecks = 0, nChecksFailed = 0, nChecksOk = 0;
    std::list<std::pair<std::string, VoidFunc>> tests;
    inline static std::list<Context *> stack;
    static void throwIfStackEmpty() {
        if (stack.empty() || stack.back() == nullptr)
            throw std::runtime_error("Context stack is empty!");
    }

    static Context & cur() { throwIfStackEmpty(); return *stack.back(); }

    explicit Context(const std::string &name) : name(name) { stack.push_back(this); }
    ~Context() { throwIfStackEmpty(); stack.pop_front(); }

    void checkExpr(const char * const estr, const bool expr, unsigned line, const char * const file, const std::string &msg = {}) {
        ++nChecks;
        auto msgStr = [&msg]() -> std::string {
            return (msg.empty() ? std::string("") : std::string(", msg: \"") + msg + "\"");
        };
        if (!expr) {
            ++nChecksFailed;
            Warning() << "Check failed (" << file << ":" << line << "): " << estr << msgStr();
        } else {
            ++nChecksOk;
            if (Trace::enabled)
                Trace() << "Check success (" << file << ":" << line << "): " << estr << msgStr();
        }
    }

    void runAll() {
        unsigned nTests = 0;
        std::tie(nChecks, nChecksOk, nChecksFailed) = std::tuple(0u, 0u, 0u); // stats
        Tic t0;
        for (const auto & [tname, func] : tests) {
            Tic t1;
            ++nTests;
            Log() << "Running " << name << " test: " << tname << " ...";
            const auto [b4checks, b4ok, b4failed] = std::tuple(nChecks, nChecksOk, nChecksFailed);
            func();
            const auto [checks, ok, failed] = std::tuple(nChecks, nChecksOk, nChecksFailed);
            if (failed > b4failed)
                throw std::runtime_error(std::format("{} check(s) failed for test: {}", failed - b4failed,  tname));
            Log() << (ok - b4ok) << "/" << (checks - b4checks) << " checks ok for " << tname << " in "
                  << t1.msecStr() << " msec";
        }
        Log() << name << ": ran " << nTests << " tests total."
              << " Checks: " << nChecksOk << " passed, " << nChecksFailed << " failed."
              << " Elapsed: " << t0.msecStr() << " msec.";
    }
};

std::map<std::string, VoidFunc> allSuites;

auto registerTest(std::string_view name, VoidFunc && f) {
    return allSuites.try_emplace(std::string{name}, std::move(f)).first;
}


// Some macros used below so we can just copy-paste unit tests from BCHN without changing them
#define TEST_RUN_CONTEXT() Context::cur().runAll()
#if defined(__LINE__) && defined(__FILE__)
#    define TEST_SETUP_CONTEXT(name) Context PASTE2(testContext, __LINE__)(name)
#    define TEST_CHECK(expr) Context::cur().checkExpr(#expr, (expr), __LINE__, __FILE__)
#    define TEST_CHECK_MESSAGE(expr, msg) Context::cur().checkExpr(#expr, (expr), __LINE__, __FILE__, msg)
#else
#    define TEST_SETUP_CONTEXT(name) Context testContext(name)
#    define TEST_CHECK(expr) Context::cur().checkExpr(#expr, (expr), 0, "???")
#    define TEST_CHECK_MESSAGE(expr, msg) Context::cur().checkExpr(#expr, (expr), 0, "???", msg)
#endif
#define TEST_CHECK_EQUAL(a, b) TEST_CHECK((a) == (b))
#define TEST_CHECK_EXCEPTION(expr, exc, pred) \
do { \
        bool is_ok_ = false; \
    try { \
            expr; \
    } catch (const exc &e) { \
            is_ok_ = pred(e); \
    } \
        TEST_CHECK_MESSAGE(is_ok_, "Expression: \"" #expr "\" should throw \"" #exc "\" and satisfy pred"); \
} while (0)
#define TEST_CHECK_THROW(expr, exc) TEST_CHECK_EXCEPTION(expr, exc, [](auto &&){ return true; })
#define TEST_CHECK_NO_THROW(expr) \
    do { \
        bool is_ok_ = true; \
    try { \
            expr; \
    } catch (...) { \
            is_ok_ = false; \
    } \
        TEST_CHECK_MESSAGE(is_ok_, "Expression: \"" #expr "\" should not throw"); \
} while (0)
#define TEST_CASE(name) \
    Context::cur().tests.emplace_back( #name, VoidFunc{} ); \
    Context::cur().tests.back().second = [&]

#define TEST_SUITE(name) \
    namespace { \
        void name ## _test_func(); \
        const auto UNIQUE_NAME(name_handle) = ::registerTest( #name , name ## _test_func ); \
        void name ## _test_func() { \
            TEST_SETUP_CONTEXT( #name );
#define TEST_SUITE_END() \
            TEST_RUN_CONTEXT(); \
        } /* end name_test_func */ \
    } // end namespace

TEST_SUITE(misc)

// Tests hex2bin and bin2hex round-trip (also tests: get_random_bytes indirectly)
TEST_CASE(bin2hex) {
    using CallStdFree = decltype([](char *p) { std::free(p); });
    std::unique_ptr<char, CallStdFree> allocd;

    // basic check
    {
        const std::array<uint8_t, 12> bin = {0xef, 0xff, 0x01, 0x02, 0x0, 0x03, 0x04, 0xaa, 0x7f, 0x0, 0xfe, 00};
        allocd.reset(bin2hex(bin.data(), bin.size()));
        TEST_CHECK_EQUAL(std::string_view{allocd.get()}, "efff0102000304aa7f00fe00");
        TEST_CHECK_EQUAL(ParseHex(allocd.get()), std::vector(bin.begin(), bin.end()));
    }

    // random bin -> hex -> bin -> hex round-trips
    std::map<std::string, std::vector<std::byte>> blobs;

    for (size_t i = 0; i < 1000; ++i) {
        const size_t randLen = InsecureRandBits(10);
        auto bin = MakeRandBytes(randLen);
        TEST_CHECK_EQUAL(bin.size(), randLen);
        allocd.reset(bin2hex(bin.data(), randLen));
        std::string hex = allocd.get();
        TEST_CHECK_EQUAL(hex.length(), randLen * 2);

        if (!hex.empty())
            TEST_CHECK(validhex(hex.c_str()));

        Trace() << "Hex str " << i << " " << hex.substr(0, 12) << "... (binary len: " << randLen << ")";

        std::vector<std::byte> bin2(bin.size());
        hex2bin(bin2.data(), hex.data(), bin2.size());
        TEST_CHECK_EQUAL(bin, bin2);
        allocd.reset(bin2hex(bin.data(), randLen));
        std::string hex2 = allocd.get();
        TEST_CHECK_EQUAL(hex, hex2);

        // Below checks that random generator is always generating unique binary data (for sufficiently long data)
        auto [it, inserted] = blobs.try_emplace(std::move(hex), std::move(bin));
        if (randLen > 2) TEST_CHECK(inserted);
    }
};

TEST_CASE(base58) {
    std::vector<uint8_t> result(256);
    constexpr auto anAddress = "1C3SoftYBC2bbDzCadZxDrfbnobEXLBLQZ";
    TEST_CHECK(b58tobin_safe(result.data(), anAddress));
    result.resize(21);
    TEST_CHECK_EQUAL(result, ParseHex("00791fc195e712c142df4c4e14fd4ec5b302733832"));
};

TEST_CASE(cashaddr_selftest) {
    TEST_CHECK(cashaddr_selftest());
};

TEST_CASE(ser_deser_cbheight) {
    constexpr int from = -1'000'000, to = 10'000'000;
    Log() << "Testing ser/deser of cb_height from " << from << " to " << to << " ...";
    char buf[64];
    for (int i = from; i < to; ++i) {
        ser_cbheight(buf, i);
        const int val = deser_cbheight(buf);
        if (val != i) {
            std::ostringstream os;
            os << "Failed for " << i << " != " << val;
            throw std::runtime_error(os.str());
        } else
            TEST_CHECK_EQUAL(val, i);
    }
};

TEST_CASE(int64_to_vch_and_back) {
    constexpr int from = -1'000'000, to = 10'000'000;
    Log() << "Testing int64_to_vch and back from " << from << " to " << to << " ...";
    for (int i = from; i < to; ++i) {
        const auto vch = int64_to_vch(i);
        TEST_CHECK((!vch.empty() && i != 0) || (vch.empty() && i == 0));
        const bool neg = i < 0;
        std::optional<std::vector<uchar>> optVec;
        std::span<const uchar> sp;
        if (neg) {
            if (vch.empty()) throw std::runtime_error("Expected non-empty vector!");
            optVec.emplace(vch);
            TEST_CHECK(optVec->back() & 0x80u);
            optVec->back() &= 0x7fu;
            sp = *optVec;
        } else
            sp = vch;
        // ensure abs val is just little endian
        uint64_t val{};
        std::memcpy(&val, sp.data(), std::min(sp.size(), sizeof(val)));
        if constexpr (std::endian::native == std::endian::big) {
            // reverse it if big endian host
            std::reverse(reinterpret_cast<std::byte *>(&val), reinterpret_cast<std::byte *>(&val) + sizeof(val));
        }
        // abs value should match expected
        TEST_CHECK_EQUAL(val, static_cast<uint64_t>(std::abs(static_cast<long>(i))));
        if (neg) {
            // undo absval-ification
            optVec.value().back() |= 0x80u;
        }
        if (optVec)
            // if we had optVec, at this point it should equal vch
            TEST_CHECK_EQUAL(*optVec, vch);

        // lastly, round-trip should produce same result
        TEST_CHECK_EQUAL(vch_to_int64(std::move(vch)), i);
    }
};

TEST_SUITE_END() // misc

// the below is mostly taken from BCHN sources: src/test/crypto_tests.cpp
TEST_SUITE(crypto)

TEST_CASE(sha256_selftest) {
    TEST_CHECK(sha256_selftest());
};

static auto TestVector = [] (const auto &h, const auto &in, const auto &out) {
    using Out = std::remove_cvref_t<decltype(out)>;
    using Hasher = std::remove_cvref_t<decltype(h)>;
    Out hash;
    TEST_CHECK(out.size() == h.OUTPUT_SIZE);
    hash.resize(out.size());
    {
        // Test that writing the whole input string at once works.
        Hasher(h).Write((uint8_t *)&in[0], in.size()).Finalize(&hash[0]);
        TEST_CHECK(hash == out);
    }
    for (int i = 0; i < 32; ++i) {
        // Test that writing the string broken up in random pieces works.
        Hasher hasher(h);
        size_t pos = 0;
        while (pos < in.size()) {
            size_t len = InsecureRandRange((in.size() - pos + 1) / 2 + 1);
            hasher.Write((uint8_t *)&in[pos], len);
            pos += len;
            if (pos > 0 && pos + 2 * out.size() > in.size() &&
                pos < in.size()) {
                // Test that writing the rest at once to a copy of a hasher
                // works.
                Hasher(hasher)
                    .Write((uint8_t *)&in[pos], in.size() - pos)
                    .Finalize(&hash[0]);
                TEST_CHECK(hash == out);
            }
        }
        hasher.Finalize(&hash[0]);
        TEST_CHECK(hash == out);
    }
};

auto TestSHA256 = [](std::string_view in, const std::string &hexout) {
    TestVector(CSHA256(), in, ParseHex(hexout));
};

auto TestSHA512 = [](std::string_view in, const std::string &hexout) {
    TestVector(CSHA512(), in, ParseHex(hexout));
};

const std::string longTestString = [] {
    std::string ret;
    ret.reserve(200'000 * 5);
    for (int i = 0; i < 200'000; i++) {
        ret += uint8_t(i);
        ret += uint8_t(i >> 4);
        ret += uint8_t(i >> 8);
        ret += uint8_t(i >> 12);
        ret += uint8_t(i >> 16);
    }
    return ret;
}();

TEST_CASE(sha256_testvectors) {
    TestSHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    TestSHA256("message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
    TestSHA256("secure hash algorithm", "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
    TestSHA256("SHA256 is considered to be safe", "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
    TestSHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    TestSHA256("For this sample, this 63-byte string will be used as input data", "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
    TestSHA256("This is exactly 64 bytes long, not counting the terminating byte", "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
    TestSHA256("As Bitcoin relies on 80 byte header hashes, we want to have an "
               "example for that.", "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
    TestSHA256(std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    TestSHA256(longTestString, "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26");
};

TEST_CASE(sha512_testvectors) {TestSHA512("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    TestSHA512("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    TestSHA512("message digest", "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
    TestSHA512("secure hash algorithm", "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3d5db502e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e");
    TestSHA512("SHA512 is considered to be safe", "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a99646b4a3901caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2");
    TestSHA512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    TestSHA512("For this sample, this 63-byte string will be used as input data", "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766");
    TestSHA512("This is exactly 64 bytes long, not counting the terminating byte", "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a387d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030");
    TestSHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    TestSHA512(std::string(1000000, 'a'), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    TestSHA512(longTestString, "40cac46c147e6131c5193dd5f34e9d8bb4951395f27b08c558c65ff4ba2de59437de8c3ef5459d76a52cedc02dc499a3c9ed9dedbfb3281afd9653b8a112fafc");
};

TEST_CASE(sha256d64) {
    for (int i = 0; i <= 32; ++i) {
        uint8_t in[64 * 32];
        uint8_t out1[32 * 32], out2[32 * 32];
        for (int j = 0; j < 64 * i; ++j) {
            in[j] = InsecureRandBits(8);
        }
        for (int j = 0; j < i; ++j) {
            gen_hash(in + 64 * j, out1 + 32 * j, 64);
        }
        sha256_d64(out2, in, i);
        TEST_CHECK(std::memcmp(out1, out2, 32 * i) == 0);
    }
};

TEST_SUITE_END() // crypto

} // namespace

int main() {
    const std::string hline(size_t{80u}, '-');
    size_t ctr = 0;
    Tic tstart;
    std::cout << "Running " << allSuites.size() << " test suites ...\n";
    for (const auto & [name, func] : allSuites) {
        if (!ctr++) std::cout << hline << "\n";
        std::cout << "Running test suite: " << name << " ...\n";
        Tic t0;
        try {
            func();
        } catch (const std::exception &e) {
            Error() << e.what();
            return EXIT_FAILURE;
        }
        std::cout << "Test suite \"" << name << "\" completed in " << t0.msecStr() << " msec\n" << hline <<  "\n";
    }
    std::cout << "Ran " << ctr << " test suites in " << tstart.secStr() << " sec\n";
    return EXIT_SUCCESS;
}
