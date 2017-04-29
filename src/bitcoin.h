/*
 * Copyright 2014-2017 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef BITCOIN_H
#define BITCOIN_H

struct gbtbase {
	char target[68];
	double diff;
	uint32_t version;
	uint32_t curtime;
	char prevhash[68];
	char ntime[12];
	char bbversion[12];
	char nbit[12];
	uint64_t coinbasevalue;
	int height;
	char *flags;
	int txns;
	char *txn_data;
	char *txn_hashes;
	int merkles;
	char merklehash[16][68];
	json_t *json;
};

typedef struct gbtbase gbtbase_t;

bool validate_address(connsock_t *cs, const char *address);
bool gen_gbtbase(connsock_t *cs, gbtbase_t *gbt);
void clear_gbtbase(gbtbase_t *gbt);
int get_blockcount(connsock_t *cs);
bool get_blockhash(connsock_t *cs, int height, char *hash);
bool get_bestblockhash(connsock_t *cs, char *hash);
bool submit_block(connsock_t *cs, const char *params);
void precious_block(connsock_t *cs, const char *params);
void submit_txn(connsock_t *cs, const char *params);
char *get_txn(connsock_t *cs, const char *hash);

#endif /* BITCOIN_H */
