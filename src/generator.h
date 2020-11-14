/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICshack LLC https://asicshack.com
 * Copyright 2014-2018 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef GENERATOR_H
#define GENERATOR_H

#include "config.h"
#include "asicseer-pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define GETBEST_FAILED -1
#define GETBEST_NOTIFY 0
#define GETBEST_SUCCESS 1

#define GENERATOR_MAX_CSCRIPT_LEN 48

void generator_add_send(pool_t *ckp, json_t *val);
struct genwork *generator_getbase(pool_t *ckp);
int generator_getbest(pool_t *ckp, char *hash, bool force);
/// Returns the length of the CScript if `addr` is a valid address, and writes
/// the CScript (scriptPubkey) bytes into the buffer `cscript_out` (which must
/// have space for GENERATOR_MAX_CSCRIPT_LEN bytes).
/// Returns 0 on failure.  (This always queries bitcoind.)
int generator_checkaddr(pool_t *ckp, const char *addr, void *cscript_out);
char *generator_get_txn(pool_t *ckp, const char *hash);
bool generator_submitblock(pool_t *ckp, const char *buf, const size_t len);
void generator_preciousblock(pool_t *ckp, const char *hash);
bool generator_get_blockhash(pool_t *ckp, int height, char *hash);
void *generator(void *arg);
/* A wrapper around bitcoin.c get_chain:
 * Request getblockchaininfo from bitcoind for "chain", writing the value into "chain"
 * which should be at least 16 bytes long. */
bool generator_get_chain(pool_t *ckp, char *chain);

#ifdef  __cplusplus
}
#endif

#endif /* GENERATOR_H */
