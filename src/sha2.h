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
#pragma once

#ifdef  __cplusplus
#include <cstddef>
extern "C" {
#else
#include <stddef.h>
#endif

#define SHA256_DIGEST_SIZE ((size_t)32u)

typedef unsigned char uchar;

void sha256(const uchar *message, size_t len, uchar digest[SHA256_DIGEST_SIZE]);
bool sha256_selftest(void); /* will perform the self-test and if there is a problem will exit the app with an error */

/**
 * Compute multiple double-SHA256's of 64-byte blobs.
 * output:  pointer to a blocks*32 byte output buffer
 * input:   pointer to a blocks*64 byte input buffer
 * blocks:  the number of hashes to compute.
 */
void sha256_d64(uchar *output, const uchar *input, size_t blocks);

#ifdef  __cplusplus
}
#endif
