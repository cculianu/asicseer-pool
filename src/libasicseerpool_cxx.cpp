#include "libasicseerpool.h"
#include "sha2.h"

#include "bitcoin/random.h"
#include "bitcoin/sha256.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <semaphore>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {
enum opcodetype {
    // push value
    OP_0 = 0x00,
    OP_1 = 0x51,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
};

// standard way to push a vector in bitcoin
void pushVec(std::vector<uchar> &v, const std::vector<uchar> &b) {
     if (b.size() < OP_PUSHDATA1) {
         v.insert(v.end(), uint8_t(b.size()));
     } else if (b.size() <= 0xff) {
         v.insert(v.end(), OP_PUSHDATA1);
         v.insert(v.end(), uint8_t(b.size()));
     } else if (b.size() <= 0xffff) {
         v.insert(v.end(), OP_PUSHDATA2);
         uint8_t data[2];
         WriteLE16(data, b.size());
         v.insert(v.end(), data, data + sizeof(data));
     } else {
         v.insert(v.end(), OP_PUSHDATA4);
         uint8_t data[4];
         WriteLE32(data, b.size());
         v.insert(v.end(), data, data + sizeof(data));
     }
     v.insert(v.end(), b.begin(), b.end());
}

std::vector<uchar> BCHN_ser_cbheight(int64_t n) {
    std::vector<uchar> v;
    v.reserve(16);
    if (n == -1 || (n >= 1 && n <= 16)) {
        v.push_back(n + (OP_1 - 1));
    } else if (n == 0) {
        v.push_back(OP_0);
    } else {
        const auto bytes = int64_to_vch(n); // serialize compact
        pushVec(v, bytes);
    }
    return v;
}

std::size_t readScriptSizeAndAdvance(const uchar * & p) {
    const uchar c = *p;
    if (c < OP_PUSHDATA1) {
        ++p; // consume size byte
        return c;
    } else if (c == OP_PUSHDATA1) {
        // 1 byte pushdata, 1 byte size, >= 76
        ++p; // consume pushdata
        const uint8_t size = *p;
        ++p; // consume 1 byte data
        return size;
    } else if (c == OP_PUSHDATA2) {
        // 1 byte pushdata, 2 byte size <= 0xffff
        ++p; // consume pushdata
        const uint16_t size = ReadLE16(p);
        p += 2;
        return size;
    } else if (c == OP_PUSHDATA4) {
        ++p; // consume pushdata
        const uint32_t size = ReadLE32(p);
        p += 4;
        return size;
    }
    throw std::runtime_error("readScriptSize: data does not contain a valid encoded script size!");
}
} // namespace

// minimal encoding for bitcoin script: encodes an int64, taken from BCHN sources
std::vector<uchar> int64_to_vch(const int64_t value) {
    std::vector<uchar> result;
    if (value == 0) {
        return result;
    }

    const bool neg = value < 0;
    uint64_t absvalue = neg ? -value : value;

    while (absvalue) {
        result.push_back(absvalue & 0xff);
        absvalue >>= 8u;
    }

    // - If the most significant byte is >= 0x80 and the value is positive,
    //   push a new zero-byte to make the significant byte < 0x80 again.
    // - If the most significant byte is >= 0x80 and the value is negative,
    //   push a new 0x80 byte that will be popped off when converting to an
    //   integral.
    // - If the most significant byte is < 0x80 and the value is negative,
    //   add 0x80 to it, since it will be subtracted and interpreted as a
    //   negative when converting to an integral.
    if (result.back() & 0x80u) {
        result.push_back(neg ? 0x80u : 0u);
    } else if (neg) {
        result.back() |= 0x80u;
    }

    return result;
}

// taken from BCHN sources to read an int64 from a script
int64_t vch_to_int64(std::vector<uchar> vchIn) {
    if (vchIn.empty()) {
        return 0;
    }
    std::span<uchar> span = vchIn;
    // uh-oh, this is too large. this really should be unsupported, but force 64-bit, keeping the last byte (for sign)
    if (span.size() > 8u) [[unlikely]]
        span = span.last(8u);

    // If most significant bit is set, vchIn is negative
    const bool neg = span.back() & 0x80u;
    // Remove sign bit (modifies vchIn, in-place)
    span.back() &= 0x7fu;

    uint64_t absVal = 0u;
    for (size_t i = 0, sz = span.size(); i != sz; ++i) {
        absVal |= uint64_t(span[i]) << 8u * i;
    }

    // cast abs value to signed
    int64_t result = static_cast<int64_t>(absVal);
    if (neg)
        // was negative, negate
        result = -result;
    return result;
}

/*  For encoding nHeight into coinbase, return how many bytes were used */
// extern "C"
int ser_cbheight(void *outp, int32_t val)
{
    const auto data = BCHN_ser_cbheight(val);
    std::memcpy(outp, &data[0], data.size());
    return int(data.size());
}

// returns the height
// extern "C"
int deser_cbheight(const void *inp)
{
    const uchar *p = static_cast<const uchar *>(inp);
    uchar c = p[0];
    if (!c) {
        return 0;
    } else if (c == 0x4f || (c >= 0x51 && c <= 0x60)) {
        // OP_1 == 81 or 0x51
        // c = n + (OP_1 - 1)  for n == -1, 1 <= n <= 16
        // n = c - (OP_1 - 1)
        return int(c - (OP_1 - 1));
    }
    // else ...
    const auto size = readScriptSizeAndAdvance(p); // moves p forward
    std::vector<uchar> vec;
    vec.insert(vec.end(), p, p + size); // copy data out of p
    return vch_to_int64(std::move(vec));
}

// extern "C"
void sha256(const uchar *message, size_t len, uchar digest[SHA256_DIGEST_SIZE])
{
    static_assert(SHA256_DIGEST_SIZE == CSHA256::OUTPUT_SIZE);
    CSHA256 ctx;
    ctx.Write(std::span{message, len});
    ctx.Finalize(std::span{&*digest, SHA256_DIGEST_SIZE});
}

// extern "C"
void sha256_d64(uchar *output, const uchar *input, size_t blocks)
{
    SHA256D64(output, input, blocks);
}


// extern "C"
bool sha256_selftest(void)
{
    try {
        const auto impl = SHA256AutoDetect();
        LOGINFO("Using SHA256: %s", impl.c_str());
        // Test sha256() API above is ok
        using namespace std::string_view_literals;
        constexpr auto expected = "\x58\xb4\x33\xfa\x7e\x8b\x0f\x94\xb2\xff\x02\x17\x8e\x77\x68\xf5\xa3\x29\xef\x34\x6d"
                                  "\x90\x8c\x7b\x91\x78\x24\xe5\xa4\xca\x95\x75"sv;
        static_assert(expected.size() == SHA256_DIGEST_SIZE);
        constexpr auto message = "The quick brown fox jumped over the lazy dogs"sv;
        unsigned char buf[SHA256_DIGEST_SIZE];
        sha256(reinterpret_cast<const unsigned char *>(message.data()), message.size(), buf);
        if (0 != std::memcmp(expected.data(), buf, expected.size()))
            throw std::runtime_error("Hashing produced unexpected results when runtime-tested -- this sould never happen!");
    } catch (const std::exception &e) {
        LOGEMERG("SHA256 self-test failed: %s", e.what());
        std::exit(1);
        return false; // not reached
    }
    return true;
}

struct OpaqueSem {
    using SemType = std::counting_semaphore<>;
#ifdef _POSIX_SEM_VALUE_MAX
    static_assert(SemType::max() >= _POSIX_SEM_VALUE_MAX);
#else
    static_assert(SemType::max() >= 1024);
#endif
    SemType sem;

    OpaqueSem(unsigned int value = 0) : sem(value) {}
};

// extern "C"
void cksem_init_(cksem_t *sem, const char *file, const char *func, const int line)
{
    static_assert(OpaqueSem::SemType::max() > 0);
    try {
        auto uptr = std::make_unique<OpaqueSem>(0);
        *sem = uptr.release();
    } catch (const std::exception &e) {
        quitfrom(1, file, func, line, "Failed to construct OpaqueSem (%s)", e.what());
    }
}

// extern "C"
void cksem_destroy_(cksem_t *sem, const char *file, const char *func, const int line)
{
    if (const void *a[2] = {}; !(a[0] = sem) || !(a[1] = *sem)) {
        quitfrom(1, file, func, line, "Failed to destroy OpaqueSem sem=0x%p *sem=0x%p", a[0], a[1]);
        return; // not reached
    }
    // will auto-delete on scope end. we do this to avoid the `delete` keyword and for symmetry with above
    std::unique_ptr<OpaqueSem> uptr(*sem);
    *sem = nullptr;
}

// extern "C"
void cksem_post_(cksem_t *sem, const char *file, const char *func, const int line)
{
    const void *a[2] = {};
    try {
        if (!(a[0] = sem)) throw std::invalid_argument("nullptr `sem` argument");
        if (!(a[1] = *sem)) throw std::invalid_argument("nullptr `*sem` argument");
        (*sem)->sem.release(1);
    } catch (const std::exception &e) {
        quitfrom(1, file, func, line, "Failed to `post()` to OpaqueSem sem=0x%p *sem=0x%p (%s)", a[0], a[1], e.what());
    }
}

// extern "C"
void cksem_wait_(cksem_t *sem, const char *file, const char *func, const int line)
{
    const void *a[2] = {};
    try {
        if (!(a[0] = sem)) throw std::invalid_argument("nullptr `sem` argument");
        if (!(a[1] = *sem)) throw std::invalid_argument("nullptr `*sem` argument");
        (*sem)->sem.acquire();
    } catch (const std::exception &e) {
        quitfrom(1, file, func, line, "Failed to `acquire()` from OpaqueSem sem=0x%p *sem=0x%p (%s)", a[0], a[1], e.what());
    }
}

// extern "C"
int cksem_trywait_(cksem_t *sem, const char *file, const char *func, const int line)
{
    const void *a[2] = {};
    try {
        if (!(a[0] = sem)) throw std::invalid_argument("nullptr `sem` argument");
        if (!(a[1] = *sem)) throw std::invalid_argument("nullptr `*sem` argument");
        if ((*sem)->sem.try_acquire())
            return 0; // success
    } catch (const std::exception &e) {
        quitfrom(1, file, func, line, "Failed to `try_acquire()` from OpaqueSem sem=0x%p *sem=0x%p (%s)", a[0], a[1], e.what());
    }
    return -1; // failure
}

// extern "C"
void get_random_bytes(void * const vbuf, const size_t nbytes)
{
    unsigned char * const buf = static_cast<unsigned char *>(vbuf);
    GetRandBytes(std::span{buf, nbytes});
}
