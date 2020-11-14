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

#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include "connector.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct genwork gbtbase_t;

/**
 * Returns true if bitcoind reports address `address` as valid.
 * If pointer `is_p2sh` is not NULL, writes *is_p2sh = true/false depending on whether the
 * address is a P2SH address.
 * If pointer `cscript_out` is not NULL, writes up to *cscript_len bytes of the scriptPubkey,
 * modifying *cscript_len to contain the number of bytes written. If `cscript_out` is not
 * NULL and the scriptPubkey does not fit into cscript_out, false will be returned.
 * Returns true on success (and if the address is valid). */
bool validate_address(connsock_t *cs, const char *address, bool *is_p2sh, void *cscript_out, int *cscript_len);
bool gen_gbtbase(connsock_t *cs, gbtbase_t *gbt);
void clear_gbtbase(gbtbase_t *gbt);
int get_blockcount(connsock_t *cs);
bool get_blockhash(connsock_t *cs, int height, char *hash);
bool get_bestblockhash(connsock_t *cs, char *hash);
bool submit_block(connsock_t *cs, const char *params, size_t param_len);
void precious_block(connsock_t *cs, const char *params);
void submit_txn(connsock_t *cs, const char *params);
char *get_txn(connsock_t *cs, const char *hash);
/* Request getblockchaininfo from bitcoind for "chain", writing the value into "chain"
 * which should be at least 16 bytes long. */
bool get_chain(connsock_t *cs, char *chain);

/* Request getzmqnotifications and test that the response roughly matches
 * the expected url. e.g. tcp://1.2.3.4:6789 would match any IP with proto "tcp" and port "6789".
 * If it finds any "address" entries for "pubhashblock", *found will be set, pointing to a malloc'd string
 * (this pointer is set on true or false return). */
bool check_getzmqnotifications_roughly_matches(connsock_t *cs, const char *expected, char **found);

#define DUST_LIMIT_SATS 546

#ifdef  __cplusplus
}
#endif

#endif /* BITCOIN_H */
