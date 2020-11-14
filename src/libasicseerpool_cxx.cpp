#include "libasicseerpool.h"

#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

namespace {
using uchar = uint8_t;

inline void WriteLE16(uint8_t *ptr, uint16_t x) {
    uint16_t v = htole16(x);
    std::memcpy(ptr, (char *)&v, 2);
}

inline void WriteLE32(uint8_t *ptr, uint32_t x) {
    uint32_t v = htole32(x);
    std::memcpy(ptr, (char *)&v, 4);
}

inline uint16_t ReadLE16(const uint8_t *ptr) {
    uint16_t x;
    std::memcpy((char *)&x, ptr, 2);
    return le16toh(x);
}

inline uint32_t ReadLE32(const uint8_t *ptr) {
    uint32_t x;
    std::memcpy((char *)&x, ptr, 4);
    return le32toh(x);
}

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
         uint8_t _data[2];
         WriteLE16(_data, b.size());
         v.insert(v.end(), _data, _data + sizeof(_data));
     } else {
         v.insert(v.end(), OP_PUSHDATA4);
         uint8_t _data[4];
         WriteLE32(_data, b.size());
         v.insert(v.end(), _data, _data + sizeof(_data));
     }
     v.insert(v.end(), b.begin(), b.end());
}

// minimal encoding for bitcoin script: encodes an int64, taken from BCHN sources
std::vector<uint8_t> int64_to_vch(const int64_t &value) {
    if (value == 0) {
        return {};
    }

    std::vector<uint8_t> result;
    const bool neg = value < 0;
    uint64_t absvalue = neg ? -value : value;

    while (absvalue) {
        result.push_back(absvalue & 0xff);
        absvalue >>= 8;
    }

    // - If the most significant byte is >= 0x80 and the value is positive,
    // push a new zero-byte to make the significant byte < 0x80 again.
    // - If the most significant byte is >= 0x80 and the value is negative,
    // push a new 0x80 byte that will be popped off when converting to an
    // integral.
    // - If the most significant byte is < 0x80 and the value is negative,
    // add 0x80 to it, since it will be subtracted and interpreted as a
    // negative when converting to an integral.
    if (result.back() & 0x80) {
        result.push_back(neg ? 0x80 : 0);
    } else if (neg) {
        result.back() |= 0x80;
    }

    return result;
};

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

// taken from BCHN sources to read an int64 from a script
int64_t vch_to_int64(const std::vector<uchar> &vch) {
    if (vch.empty()) {
        return 0;
    }

    int64_t result = 0;
    for (size_t i = 0; i != vch.size(); ++i) {
        result |= int64_t(vch[i]) << 8 * i;
    }

    // If the input vector's most significant byte is 0x80, remove it from
    // the result's msb and return a negative.
    if (vch.back() & 0x80) {
        return -int64_t(result & ~(0x80ULL << (8 * (vch.size() - 1))));
    }

    return result;
}
} // namespace

/*  For encoding nHeight into coinbase, return how many bytes were used */
extern "C"
int ser_cbheight(void *outp, int32_t val)
{
    const auto data = BCHN_ser_cbheight(val);
    std::memcpy(outp, &data[0], data.size());
    return int(data.size());
}

// returns the height
extern "C"
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
    return vch_to_int64(vec);
}

extern "C" void test_ser_deser_cbheight(void)
{
    constexpr int from = -1'000'000, to = 10'000'000;
    std::cout << "Testing ser/deser of cb_height from " << from << " to " << to << " ..." << std::endl;
    char buf[64];
    for (int i = from; i < to; ++i) {
        ser_cbheight(buf, i);
        const int val = deser_cbheight(buf);
        if (val != i) {
            std::ostringstream os;
            os << "Failed for " << i << " != " << val;
            throw std::runtime_error(os.str());
        }
    }
    std::cout << "Success!" << std::endl;
}
