/* Cash Address decode for asicseer-pool.
 * Copyright (c) 2024 Calin Culianu <calin.culianu@gmail.com>
 * Original C++ sources: Bitcoin Cash Node https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node
 * LICENSE: MIT
 */
#include "cashaddr.h"
#include "libasicseerpool.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

/**
 * Convert from one power-of-2 number base to another.
 *
 * If padding is enabled, this always return true. If not, then it returns true
 * of all the bits of the input are encoded in the output.
 */
template <size_t frombits, size_t tobits, bool pad, typename O, typename I>
bool ConvertBits(const O &outfn, I it, I end) {
    constexpr size_t size_t_bits = sizeof(size_t) * 8; // the size of size_t, in bits
    static_assert(frombits > 0 && tobits > 0 && frombits <= size_t_bits && tobits <= size_t_bits
                      && frombits + tobits <= size_t_bits, "ConvertBits template argument(s) out of range");
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (size_t{1} << tobits) - 1u;
    constexpr size_t max_acc = (size_t{1} << (frombits + tobits - 1u)) - 1u;
    while (it != end) {
        acc = ((acc << frombits) | static_cast<size_t>(*it)) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            outfn((acc >> bits) & maxv);
        }
        ++it;
    }

    if (pad) {
        if (bits) {
            outfn((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }

    return true;
}

/**
 * This function will compute what 8 5-bit values to XOR into the last 8 input
 * values, in order to make the checksum 0. These 8 values are packed together
 * in a single 40-bit integer. The higher bits correspond to earlier values.
 */
uint64_t PolyMod(const std::span<const uint8_t> sp) {
    /**
     * The input is interpreted as a list of coefficients of a polynomial over F
     * = GF(32), with an implicit 1 in front. If the input is [v0,v1,v2,v3,v4],
     * that polynomial is v(x) = 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4.
     * The implicit 1 guarantees that [v0,v1,v2,...] has a distinct checksum
     * from [0,v0,v1,v2,...].
     *
     * The output is a 40-bit integer whose 5-bit groups are the coefficients of
     * the remainder of v(x) mod g(x), where g(x) is the cashaddr generator, x^8
     * + {19}*x^7 + {3}*x^6 + {25}*x^5 + {11}*x^4 + {25}*x^3 + {3}*x^2 + {19}*x
     * + {1}. g(x) is chosen in such a way that the resulting code is a BCH
     * code, guaranteeing detection of up to 4 errors within a window of 1025
     * characters. Among the various possible BCH codes, one was selected to in
     * fact guarantee detection of up to 5 errors within a window of 160
     * characters and 6 erros within a window of 126 characters. In addition,
     * the code guarantee the detection of a burst of up to 8 errors.
     *
     * Note that the coefficients are elements of GF(32), here represented as
     * decimal numbers between {}. In this finite field, addition is just XOR of
     * the corresponding numbers. For example, {27} + {13} = {27 ^ 13} = {22}.
     * Multiplication is more complicated, and requires treating the bits of
     * values themselves as coefficients of a polynomial over a smaller field,
     * GF(2), and multiplying those polynomials mod a^5 + a^3 + 1. For example,
     * {5} * {26} = (a^2 + 1) * (a^4 + a^3 + a) = (a^4 + a^3 + a) * a^2 + (a^4 +
     * a^3 + a) = a^6 + a^5 + a^4 + a = a^3 + 1 (mod a^5 + a^3 + 1) = {9}.
     *
     * During the course of the loop below, `c` contains the bitpacked
     * coefficients of the polynomial constructed from just the values of v that
     * were processed so far, mod g(x). In the above example, `c` initially
     * corresponds to 1 mod (x), and after processing 2 inputs of v, it
     * corresponds to x^2 + v0*x + v1 mod g(x). As 1 mod g(x) = 1, that is the
     * starting value for `c`.
     */
    uint64_t c = 1;
    for (const uint8_t d : sp) {
        /**
         * We want to update `c` to correspond to a polynomial with one extra
         * term. If the initial value of `c` consists of the coefficients of
         * c(x) = f(x) mod g(x), we modify it to correspond to
         * c'(x) = (f(x) * x + d) mod g(x), where d is the next input to
         * process.
         *
         * Simplifying:
         * c'(x) = (f(x) * x + d) mod g(x)
         *         ((f(x) mod g(x)) * x + d) mod g(x)
         *         (c(x) * x + d) mod g(x)
         * If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to
         * compute
         * c'(x) = (c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5) * x + d
         *                                                             mod g(x)
         *       = c0*x^6 + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d
         *                                                             mod g(x)
         *       = c0*(x^6 mod g(x)) + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 +
         *                                                             c5*x + d
         * If we call (x^6 mod g(x)) = k(x), this can be written as
         * c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d) + c0*k(x)
         */

         // First, determine the value of c0:
        uint8_t c0 = c >> 35;

        // Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + d:
        c = ((c & 0x07ffffffff) << 5) ^ d;

        // Finally, for each set bit n in c0, conditionally add {2^n}k(x):
        if (c0 & 0x01) {
            // k(x) = {19}*x^7 + {3}*x^6 + {25}*x^5 + {11}*x^4 + {25}*x^3 +
            //        {3}*x^2 + {19}*x + {1}
            c ^= 0x98f2bc8e61;
        }

        if (c0 & 0x02) {
            // {2}k(x) = {15}*x^7 + {6}*x^6 + {27}*x^5 + {22}*x^4 + {27}*x^3 +
            //           {6}*x^2 + {15}*x + {2}
            c ^= 0x79b76d99e2;
        }

        if (c0 & 0x04) {
            // {4}k(x) = {30}*x^7 + {12}*x^6 + {31}*x^5 + {5}*x^4 + {31}*x^3 +
            //           {12}*x^2 + {30}*x + {4}
            c ^= 0xf33e5fb3c4;
        }

        if (c0 & 0x08) {
            // {8}k(x) = {21}*x^7 + {24}*x^6 + {23}*x^5 + {10}*x^4 + {23}*x^3 +
            //           {24}*x^2 + {21}*x + {8}
            c ^= 0xae2eabe2a8;
        }

        if (c0 & 0x10) {
            // {16}k(x) = {3}*x^7 + {25}*x^6 + {7}*x^5 + {20}*x^4 + {7}*x^3 +
            //            {25}*x^2 + {3}*x + {16}
            c ^= 0x1e4f43e470;
        }
    }

    /**
     * PolyMod computes what value to xor into the final values to make the
     * checksum 0. However, if we required that the checksum was 0, it would be
     * the case that appending a 0 to a valid list of values would result in a
     * new valid list. For that reason, cashaddr requires the resulting checksum
     * to be 1 instead.
     */
    return c ^ 1;
}


/**
 * The cashaddr character set for decoding.
 */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1,
};

/**
 * Convert to lower case.
 *
 * Assume the input is a character.
 */
inline uint8_t LowerCase(uint8_t c) {
    // ASCII black magic.
    return c | 0x20;
}

/**
 * Verify a checksum.
 */
static bool VerifyChecksum(const std::string_view prefix, const std::span<const uint8_t> payload) {
    /**
     * Expand the address prefix for the checksum computation.
     */
    auto ExpandPrefix = [](const std::string_view prefix) {
        std::vector<uint8_t> ret;
        ret.reserve(prefix.size() + 1u);
        for (const char ch : prefix) {
            ret.push_back(ch & 0x1Fu);
        }
        ret.push_back(0u);
        return ret;
    };
    auto Cat = [](std::vector<uint8_t> &&v, const std::span<const uint8_t> arg) {
        v.insert(v.end(), arg.begin(), arg.end());
        return v;
    };
    return PolyMod(Cat(ExpandPrefix(prefix), payload)) == 0;
}

/**
 * Decode a cashaddr string.
 */
std::pair<std::string, std::vector<uint8_t>> CashAddr_Decode(const std::string_view str, const std::string_view default_prefix) {
    using Data = std::vector<uint8_t>;
    // Go over the string and do some sanity checks.
    bool lower = false, upper = false, hasNumber = false;
    size_t prefixSize = 0;
    for (size_t i = 0; i < str.size(); ++i) {
        uint8_t c = str[i];
        if (c >= 'a' && c <= 'z') {
            lower = true;
            continue;
        }

        if (c >= 'A' && c <= 'Z') {
            upper = true;
            continue;
        }

        if (c >= '0' && c <= '9') {
            // We cannot have numbers in the prefix.
            hasNumber = true;
            continue;
        }

        if (c == ':') {
            // The separator cannot be the first character, cannot have number
            // and there must not be 2 separators.
            if (hasNumber || i == 0 || prefixSize != 0) {
                return {};
            }

            prefixSize = i;
            continue;
        }

        // We have an unexpected character.
        return {};
    }

    // We can't have both upper case and lowercase.
    if (upper && lower) {
        return {};
    }

    // Get the prefix.
    std::string prefix;
    if (prefixSize == 0) {
        prefix = default_prefix;
    } else {
        prefix.reserve(prefixSize);
        for (size_t i = 0; i < prefixSize; ++i) {
            prefix += LowerCase(str[i]);
        }

        // Now add the ':' in the size.
        prefixSize++;
    }

    // Decode values.
    const size_t valuesSize = str.size() - prefixSize;
    Data values(valuesSize);
    for (size_t i = 0; i < valuesSize; ++i) {
        uint8_t c = str[i + prefixSize];
        // We have an invalid char in there.
        if (c > 127 || CHARSET_REV[c] == -1) {
            return {};
        }

        values[i] = CHARSET_REV[c];
    }

    // Verify the checksum.
    if (!VerifyChecksum(prefix, values)) {
        return {};
    }

    return {std::move(prefix), Data(values.begin(), values.end() - 8)};
}

enum CashAddrType : uint8_t {
    PUBKEY_TYPE = 0,
    SCRIPT_TYPE = 1,
    TOKEN_PUBKEY_TYPE = 2, //< Token-Aware P2PKH
    TOKEN_SCRIPT_TYPE = 3, //< Token-Aware P2SH
};

struct CashAddrContent {
    CashAddrType type{};
    std::vector<uint8_t> hash;

    bool IsNull() const { return hash.empty(); }
    bool IsTokenAwareType() const { return type == TOKEN_PUBKEY_TYPE || type == TOKEN_SCRIPT_TYPE; }
};

CashAddrContent DecodeCashAddrContent(const std::string_view addr, const std::string_view expectedPrefix) {
    const auto & [prefix, payload] = CashAddr_Decode(addr, expectedPrefix);

    if (prefix != expectedPrefix) {
        return {};
    }

    if (payload.empty()) {
        return {};
    }

    std::vector<uint8_t> data;
    data.reserve(payload.size() * 5 / 8);
    if (!ConvertBits<5, 8, false>([&](const uint8_t c) { data.push_back(c); },
                                  payload.begin(), payload.end())) {
        return {};
    }

    // Decode type and size from the version.
    uint8_t version = data[0];
    if (version & 0x80) {
        // First bit is reserved.
        return {};
    }

    auto type = CashAddrType((version >> 3) & 0x1f);
    uint32_t hash_size = 20 + 4 * (version & 0x03);
    if (version & 0x04) {
        hash_size *= 2;
    }

    // Check that we decoded the exact number of bytes we expected.
    if (data.size() != hash_size + 1) {
        return {};
    }

    // Pop the version.
    data.erase(data.begin());
    return {type, std::move(data)};
}

} // namespace

/* Returns a 20-byte buffer containing the hash160 of the pk or script decoded
 * from a cashaddr string, or NULL on bad address string. The passed-in string
 * may be preceded by a prefix such as "bitcoincash:" or "bchtest:". If no prefix
 * is specified, "bitcoincash:" is assumed. Use the correct prefix to ensure
 * proper checksum validation.
 *
 * The returned buffer must be freed by the caller.
 */
/* extern "C" */
uint8_t *cashaddr_decode_hash160(const char *addr, const char *default_prefix)
{
    const std::string_view sv_addr = addr;
    std::string_view sv_def_pfx;
    if (!default_prefix || !*default_prefix) {
        if (auto pos = sv_addr.find(':'); pos != sv_addr.npos) {
            sv_def_pfx = sv_addr.substr(0, pos);
        } else {
            sv_def_pfx = CASHADDR_PREFIX_MAIN;
        }
    } else {
        sv_def_pfx = default_prefix;
    }
    const auto content = DecodeCashAddrContent(sv_addr, sv_def_pfx);
    if (unlikely(content.IsNull())) {
        return nullptr;
    }
    if (unlikely(content.hash.size() != 20)) {
        // TODO: fix this to support >20 byte hashes (e.g. p2sh32). For now we just do this (error out).
        return nullptr;
    }
    uint8_t *ret = static_cast<uint8_t *>(ckalloc(content.hash.size()));
    std::memcpy(ret, content.hash.data(), content.hash.size());
    return ret;
}

/* extern "C" */
int cashaddr_selftest(void)
{
    int ret = 1;
    const char *addr, *pfx, *expect;
    auto Deleter = [](uint8_t *p) { std::free(p); };
    std::unique_ptr<uint8_t[], decltype(Deleter)> buf;

    auto ToHex = [](const std::span<const uint8_t> bytes) -> std::string {
        std::string str(bytes.size() * 2 + 1, '\0'); // bin2hex writes the NUL byte so we must allocate 1 extra then pop
        bin2hex__(str.data(), bytes.data(), bytes.size());
        str.pop_back();
        return str;
    };

    addr = "bitcoincash:qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc";
    pfx = "bitcoincash";
    expect = "6fd35615996fa7c8d2526c3942347296c436ae13";
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    if (!buf || ToHex({buf.get(), 20}) != expect) {
        LOGERR("cashaddr self-test: %s, prefix: %s -- ERROR!", addr, pfx);
        ret = 0;
    }

    addr = "qphax4s4n9h60jxj2fkrjs35w2tvgd4wzvf52cgtzc";
    pfx = nullptr;
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    expect = "6fd35615996fa7c8d2526c3942347296c436ae13";
    if (!buf || ToHex({buf.get(), 20}) != expect) {
        LOGERR("cashaddr self-test: %s with missing prefix -- ERROR!", addr);
        ret = 0;
    }

    addr = "qqhv9xuu5edq22k528yegwdmej7u0wxgmqncqjve64";
    pfx = "bitcoincash";
    expect = "2ec29b9ca65a052ad451c99439bbccbdc7b8c8d8";
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    if (!buf || ToHex({buf.get(), 20}) != expect) {
        LOGERR("cashaddr self-test: %s, prefix: %s -- ERROR!", addr, pfx);
        ret = 0;
    }

    addr = "qza3z5equsq6eqaw6lfqzzc0vpzs8fa5dcg08tpknk";
    pfx = "bchtest";
    expect = "bb115320e401ac83aed7d2010b0f604503a7b46e";
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    if (!buf || ToHex({buf.get(), 20}) != expect) {
        LOGERR("cashaddr self-test: %s, prefix: %s -- ERROR!", addr, pfx);
        ret = 0;
    }

    addr = "qza3z5equsq6eqaw6lfqzzc0vpzs8fa5dcg08tpknk";
    pfx = nullptr;
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    if (buf) {
        LOGERR("cashaddr self-test: %s with bad prefix -- ERROR!", addr);
        ret = 0;
    }

    addr = "bchtest:qza3z5equsq6eqaw6lfqzzc0vpzs8fa5dcg08tpknk";
    pfx = nullptr;
    buf.reset( cashaddr_decode_hash160(addr, pfx) );
    expect = "bb115320e401ac83aed7d2010b0f604503a7b46e";
    if (!buf || ToHex({buf.get(), 20}) != expect) {
        LOGERR("cashaddr self-test: %s with missing prefix -- ERROR!", addr);
        ret = 0;
    }

    if (!ret)
        LOGERR("cashaddr self-test: FAILED");
    else
        LOGDEBUG("cashaddr self-test: OK");

    return ret;
}
