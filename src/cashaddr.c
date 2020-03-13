/* Cash Address decode for asicseer-pool.
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Code adapted to C from C++ by Calin Culianu
 * Original C++ sources: Bitcoin Cash Node https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node
 * LICENSE: MIT
 */
#include "cashaddr.h"
#include "libasicseerpool.h"

#include <stdlib.h>
#include <string.h>

// FWD decls
static int cashaddr_decode(const char *str, uint8_t **buf, size_t *buflen, const char *default_prefix);
static bool ConvertBits(uint8_t **out, size_t *outlen, size_t frombits, size_t tobits,
                        const uint8_t *in, size_t inlen);

/* Returns a 20-byte buffer containing the hash160 of the pk or script decoded
 * from a cashaddr string, or NULL on bad address string. The passed-in string
 * may be preceded by a prefix such as "bitcoincash:" or "bchtest:". If no prefix
 * is specified, "bitcoincash:" is assumed. Use the correct prefix to ensure
 * proper checksum validation.
 *
 * The returned buffer must be freed by the caller.
 */
uint8_t *cashaddr_decode_hash160(const char *addr, const char *default_prefix)
{
    uint8_t *buf = NULL;
    size_t buflen = 0;
    int res = cashaddr_decode(addr, &buf, &buflen, default_prefix);
    if (unlikely(res < 0))
        return NULL;
    uint8_t *bits = NULL;
    size_t bitslen = 0;
    ConvertBits(&bits, &bitslen, 5, 8, buf, buflen);
    uint8_t *retval = NULL;
    if (likely(bits && bitslen >= 21)) {
        retval = (uint8_t *)ckzalloc(20);
        memcpy(retval, bits + 1, 20);
    }
    free(bits);
    free(buf);
    return retval;
}

/**
 * This function will compute what 8 5-bit values to XOR into the last 8 input
 * values, in order to make the checksum 0. These 8 values are packed together
 * in a single 40-bit integer. The higher bits correspond to earlier values.
 */
static uint64_t PolyMod(const uint8_t *v, size_t vlen) {
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
    for (size_t i = 0; i < vlen; ++i) {
        uint8_t d = v[i];
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
 * Expand the address prefix for the checksum computation.  Allocates the returned buffer to be 1 + strlen(prefix).
 */
static uint8_t *ExpandPrefix(const char *prefix) {
    const size_t plen = strlen(prefix);
    uint8_t *ret = ckzalloc(plen + 1);
    for (size_t i = 0; i < plen; ++i) {
        ret[i] = prefix[i] & 0x1f;
    }
    ret[plen] = 0;
    return ret;
}

/**
 * Verify a checksum.
 */
static bool cashaddr_verify_checksum(const char *prefix, const uint8_t *payload, size_t plen)
{
    size_t pflen = strlen(prefix) + 1;
    uint8_t *buf = ExpandPrefix(prefix);
    buf = realloc(buf, pflen + plen);
    memcpy(buf + pflen, payload, plen);
    const uint64_t val = PolyMod(buf, pflen + plen);
    free(buf);
    return val == 0;
}

/**
 * The cashaddr character set for decoding.
 */
static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

/**
 * Convert to lower case.
 *
 * Assume the input is a character.
 */
static inline uint8_t to_lower_case(uint8_t c) {
    // ASCII black magic.
    return c | 0x20;
}

/**
 * Decode a cashaddr string.  *buf will be allocated and *buflen set to its decoded
 * length on success. Returns the length of the prefix (or 0 if no prefix) on success,
 * or -1 on failure.
 *
 * Note the *buf will need to be freed on successful return.
 */
static int cashaddr_decode(const char *str, uint8_t **buf, size_t *buflen, const char *default_prefix) {
    // Go over the string and do some sanity checks.
    bool lower = false, upper = false, hasNumber = false;
    size_t slen = strlen(str ? str : "");
    size_t prefixSize = 0;
    if (unlikely(!slen || !buf || !buflen))
        return -1;
    *buf = NULL;
    *buflen = 0;
    for (size_t i = 0; i < slen; ++i) {
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
                return -1;
            }

            prefixSize = i + 1;
            continue;
        }

        // We have an unexpected character.
        return -1;
    }

    // We can't have both upper case and lowercase.
    if (upper && lower) {
        return -1;
    }

    char *prefix = NULL;
    if (prefixSize) {
        // copy out the prefix sans ':'
        prefix = ckzalloc(prefixSize);
        for (int i = 0; i < (int)prefixSize-1; ++i)
            prefix[i] = to_lower_case(str[i]);
        prefix[prefixSize-1] = 0; // NUL
        // Fast-forward past the prefix now
        str += prefixSize;
        slen -= prefixSize;
    } else {
        // default prefix, without the :
        prefix = strdup(default_prefix && *default_prefix
                        ? default_prefix
                        : CASHADDR_PREFIX_MAIN);
    }

    // Decode values.
    *buflen = slen;
    *buf = ckzalloc(*buflen);
    for (size_t i = 0; i < *buflen; ++i) {
        uint8_t c = str[i];
        // We have an invalid char in there.
        if (unlikely(c > 127 || CHARSET_REV[c] == -1)) {
            goto err_out;
        }

        (*buf)[i] = CHARSET_REV[c];
    }

    // Verify the checksum.
    if (!cashaddr_verify_checksum(prefix, *buf, *buflen)) {
        goto err_out;
    }

    *buflen -= 8; // this was in original cashaddr.cpp; remove the checksum from the end
    free(prefix);
    return (int)prefixSize;
err_out:
    free(prefix);
    free(*buf);
    *buf = NULL;
    *buflen = 0;
    return -1;
}

static inline bool push_back(uint8_t **buf, size_t *len, uint8_t val)
{
    // the below is equivalent to a C++ push_back to a vector, more or less, due to how malloc works.
    uint8_t *newbuf = realloc(*buf, ++(*len)); // allocate 1 more byte; realloc of NULL pointer is just a malloc
    if (unlikely(!newbuf)) {
        // Paranoia -- should never happen. But if it does, make sure to print to log.
        LOGCRIT("Failed to reallocate a buffer in push_back in %s", __FILE__);
        free(*buf); // free old buffer, if any
        *buf = NULL;
        *len = 0;
        return false; // indicate failure
    }
    *buf = newbuf;
    newbuf[(*len) - 1] = val;
    return true;
}

static bool ConvertBits(uint8_t **out, size_t *outlen, size_t frombits, size_t tobits, const uint8_t *in, size_t inlen) {
    size_t acc = 0;
    size_t bits = 0;
    const size_t maxv = (1 << tobits) - 1;
    const size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    const uint8_t *it = in, *end = in + inlen;
    *out = NULL;
    *outlen = 0;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            const uint8_t val = (acc >> bits) & maxv;
            if (unlikely(!push_back(out, outlen, val))) {
                // memory allocation failure -- very unlikely.
                return false;
            }
        }
        ++it;
    }

    // We have remaining bits to encode but do not pad.
    if (bits)
        return false;
    return true;
}
