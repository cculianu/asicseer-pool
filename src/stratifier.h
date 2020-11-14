/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICshack LLC https://asicshack.com
 * Copyright 2014-2017 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef STRATIFIER_H
#define STRATIFIER_H

#include "asicseer-pool.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Max depth of the merkle tree. Increase this if blocks ever have more than 4 billion tx's. */
#define GENWORK_MAX_MERKLE_DEPTH 32

/* The max length of user bchsig portion.  This may get truncated down below this value if the scriptsig
   gets too long. */
#define MAX_USER_COINBASE_LEN 96

#define MAX_USERNAME 127 /* The max length of a username. Used in internal struct user_instance_t */

/* Generic structure for both workbase in stratifier and gbtbase in generator */
struct genwork {
    /* Hash table data */
    UT_hash_handle hh;

    /* The next two fields need to be consecutive as both of them are
     * used as the key for their hashtable entry in remote_workbases */
    int64_t id;
    /* The client id this workinfo came from if remote */
    int64_t client_id;

    char idstring[20];

    /* How many readers we currently have of this workbase, set
     * under write workbase_lock */
    int readcount;

    /* The id a remote workinfo is mapped to locally */
    int64_t mapped_id;

    ts_t gentime;
    tv_t retired;

    /* GBT/shared variables */
    char target[68];
    double diff;
    double network_diff;
    uint32_t version;
    uint32_t curtime;
    char prevhash[68];
    char ntime[12];
    uint32_t ntime32;
    char bbversion[12];
    char nbit[12];
    uint64_t coinbasevalue;
    int height;
    char *flags;
    int txns;
    char *txn_data;
    size_t txn_data_len;
    char *txn_hashes;
    int merkles;
    char merklehash[GENWORK_MAX_MERKLE_DEPTH][68];
    char merklebin[GENWORK_MAX_MERKLE_DEPTH][32];
    json_t *merkle_array;

    /* Template variables, lengths are binary lengths! */
    char *coinb1; // coinbase1
    uchar *coinb1bin;
    int coinb1len; // length of above

    char enonce1const[32]; // extranonce1 section that is constant
    uchar enonce1constbin[16];
    int enonce1constlen; // length of above - usually zero unless proxying
    int enonce1varlen; // length of unique extranonce1 string for each worker - usually 4

    int enonce2varlen; // length of space left for extranonce2 - usually 8 unless proxying

    char *coinb2; // coinbase2
    uchar *coinb2bin;
    int coinb2len; // length of above

    /* Cached header binary */
    char headerbin[112];

    char *logdir;

    pool_t *ckp;
    bool proxy; /* This workbase is proxied work */

    bool incomplete; /* This is a remote workinfo without all the txn data */

    json_t *payout; /* Current generation payout summary data */

    json_t *json; /* getblocktemplate json */
};

void parse_remote_txns(pool_t *ckp, const json_t *val);
#define parse_upstream_txns(ckp, val) parse_remote_txns(ckp, val)
void parse_upstream_auth(pool_t *ckp, json_t *val);
void parse_upstream_workinfo(pool_t *ckp, json_t *val);
void parse_upstream_block(pool_t *ckp, json_t *val);
void parse_upstream_reqtxns(pool_t *ckp, json_t *val);
char *stratifier_stats(pool_t *ckp, void *data);
void _stratifier_add_recv(pool_t *ckp, json_t *val, const char *file, const char *func, const int line);
#define stratifier_add_recv(ckp, val) _stratifier_add_recv(ckp, val, __FILE__, __func__, __LINE__)

// Limits the length of string str to MAX_USER_COINBASE_LEN (by inserting a NUL byte if the string is too long).
// Postcondition: str is truncated to max MAX_USER_COINBASE_LEN bytes, and `str_len_out` is set to the length of `str`.
void normalize_bchsig(char *str, int *str_len_out);

void *stratifier(void *arg);

#ifdef  __cplusplus
}
#endif

#endif /* STRATIFIER_H */
