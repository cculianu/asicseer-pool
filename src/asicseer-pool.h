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

#ifndef ASICSEER_POOL_H
#define ASICSEER_POOL_H

#include "config.h"

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdatomic.h>

#include "donation.h"
#include "libasicseerpool.h"
#include "uthash.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define RPC_TIMEOUT 60

struct pool_instance;
typedef struct pool_instance pool_t;

struct ckmsg {
    struct ckmsg *next;
    struct ckmsg *prev;
    void *data;
};

typedef struct ckmsg ckmsg_t;

typedef struct unix_msg unix_msg_t;

struct unix_msg {
    unix_msg_t *next;
    unix_msg_t *prev;
    int sockd;
    char *buf;
};

struct ckmsgq {
    pool_t *ckp;
    char name[16];
    pthread_t pth;
    mutex_t *lock;
    pthread_cond_t *cond;
    ckmsg_t *msgs;
    void (*func)(pool_t *, void *);
    int64_t messages;
    volatile bool active;
};

typedef struct ckmsgq ckmsgq_t;

typedef struct proc_instance proc_instance_t;

struct proc_instance {
    pool_t *ckp;
    unixsock_t us;
    char *processname;
    char *sockname;
    int pid;
    int oldpid;
    pthread_t pth_process;

    /* Linked list of received messages, locking and conditional */
    unix_msg_t *unix_msgs;
    mutex_t rmsg_lock;
    pthread_cond_t rmsg_cond;
};

struct connsock {
    int fd;
    char *url;
    char *port;
    char *auth;

    char *buf;
    int bufofs;
    int buflen;
    int bufsize;
    int rcvbufsiz;
    int sendbufsiz;

    pool_t *ckp;
    /* Semaphore used to serialise request/responses */
    cksem_t sem;

    atomic_bool alive;
};

typedef struct connsock connsock_t;

typedef struct char_entry char_entry_t;

struct char_entry {
    char_entry_t *next;
    char_entry_t *prev;
    char *buf;
    double comparator;
};

typedef struct log_entry log_entry_t;

struct log_entry {
    log_entry_t *next;
    log_entry_t *prev;
    char *fname;
    char *buf;
    double comparator;
};

struct server_instance {
    /* Hash table data */
    UT_hash_handle hh;
    int id;

    const char *url;
    const char *auth;
    const char *pass;
    const char *zmqendpoint; // May be NULL. If not NULL, points to the corresponding string in the pool_instance_t btcdzmqblock, signifying this btcd uses zmq.
    atomic_bool notify; // this is true if either "notify": true in JSON or if this btcd has a zmq endpoint
    atomic_bool alive;
    connsock_t cs;
};

typedef struct server_instance server_instance_t;

// Overrides for client mindiff and startdiff, applied based on useragent string from mining.subscribe.
typedef struct mindiff_override {
    /* If a client's useragent starts with this string (case insensitive),  then we apply the override. */
    const char *useragent; // NB: in this program this is a malloc'd string owned by this object
    size_t ualen; // strlen(useragent), cached so we don't have to recompute it each time
    /* This override is applied if it's >= global mindiff, it affects client starting difficulty and minimum difficulty. */
    int64_t mindiff;
} mindiff_override_t;

// Comes from config as "fee_discounts", which is a dict.
// e.g.: "fee_discounts" : { "username" : 0.25, "anotherusername" : 0.0 }
typedef struct user_fee_discount {
    UT_hash_handle hh;
    // The username specified in config
    const char *username;
    // A value between [0.0, 1.0] where 0.0 = no discount, 1.0 = full discount
    double discount;
} user_fee_discount_t;

struct pool_instance {
    /* Start time */
    time_t starttime;
    /* Start pid */
    pid_t startpid;
    /* The initial command line arguments */
    char **initial_args;
    /* Number of arguments */
    int args;
    /* Filename of config file */
    char *config;
    /* Kill old instance with same name */
    bool killold;
    /* Whether to log shares or not */
    bool logshares;
    /* Logging level */
    int loglevel;
    /* Main process name */
    char *name;
    /* Directory where sockets are created */
    char *socket_dir;
    /* Group ID for unix sockets */
    char *grpnam;
    gid_t gr_gid;
    /* Directory where logs are written */
    char *logdir;
    /* Logfile */
    char *logfilename;
    FILE *logfp;
    int logfd;
    time_t lastopen_t;
    /* Connector fds if we inherit them from a running process */
    int *oldconnfd;
    /* Should we inherit a running instance's socket and shut it down */
    bool handover;
    /* How many clients maximum to accept before rejecting further */
    int maxclients;

    /* API message queue */
    ckmsgq_t *ckpapi;

    /* Logger message queue */
    ckmsgq_t *logger;
    ckmsgq_t *console_logger;

    /* Process instance data of parent/child processes */
    proc_instance_t main;

    proc_instance_t generator;
    proc_instance_t stratifier;
    proc_instance_t connector;

    volatile bool generator_ready; // TODO: use a real atomic value here
    volatile bool stratifier_ready; // TODO: use a real atomic value here
    volatile bool connector_ready; // TODO: use a real atomic value here

    /* Threads of main process */
    pthread_t pth_listener;
    pthread_t pth_watchdog;

    /* Are we running in trusted remote node mode */
    bool remote;
    /* Does our upstream pool in remote mode have ckdb */
    bool upstream_ckdb;

    /* Are we running in node proxy mode */
    bool node;

    /* Are we running in passthrough mode */
    bool passthrough;

    /* Are we a redirecting passthrough */
    bool redirector;

    /* Are we running as a proxy */
    bool proxy;

    /* Are we running in SOLO mode */
    bool solo;

    /* Are we running in userproxy mode */
    bool userproxy;

    /* Should we daemonise the asicseer-pool process */
    bool daemon;

    /* Should we disable the throbber */
    bool quiet;

    /* Have we given warnings about the inability to raise buf sizes */
    bool wmem_warn;
    bool rmem_warn;

    /* Print logs in localtime rather than UTC */
    bool localtime_logging;

    /* Bitcoind data */
    int btcds;
    char **btcdurl;
    char **btcdauth;
    char **btcdpass;
    bool *btcdnotify;
    char **btcdzmqblock; // per-btcd zmqpubhashblock endpoint (each entry in array may be NULL)
    int n_zmq_btcds; // the count of the above btcds that have a non-NULL btcdzmqblock pointer
    int n_notify_btcds; // the count of the above btcds that have notify set. This is always >= n_zmq_btcds.
    int blockpoll; // How frequently in ms to poll bitcoind for block updates
    int nonce1length; // Extranonce1 length
    int nonce2length; // Extranonce2 length

    /* Difficulty settings */
    int64_t mindiff; // Default 1
    int64_t startdiff; // Default 42
    int64_t maxdiff; // No default

    const mindiff_override_t *mindiff_overrides; // Taken from top-level "mindiff_overrides" : { ... } in config.
    size_t n_mindiff_overrides; // The number of mindiff_override in the above array. Will be 0 if array is NULL.

    user_fee_discount_t *user_fee_discounts; // Hash table, comes from config "fee_discounts". NULL if table is empty.

    /* Which chain are we on: "main", "test", or "regtest". Defaults to "main" but may be read
       from bitcoind and updated if !proxy instance.
       If you change these buffer sizes, update bitcoin.c get_chain(). */
    char chain[16];
    char cashaddr_prefix[16]; // defaults to "bitcoincash" but may be "bchtest" or "bchreg" after chain is correctly updated from bitcoind
    bool not_mainnet; // if true, we are not on main net but rather on test net or regtest net

    /* Coinbase data */
    char *bchaddress; // Address to mine to. In SPLNS mode this is used as a fallback address on worker address failure, etc, as well as the pool fee address.
    char *single_payout_override; // Override all payouts to a single address.  This is for private pools that use T17s which crash when there are too may outputs in coinbase.
    // optional coinbase scriptsig text. If more than 1 is specified, one is randomly picked each time.
    struct {
        char *sig; // Optional signature to add to coinbase
        int siglen; // 0 or the length of bchsig (always >= 0)
    } *bchsigs;
    int n_bchsigs; // the number of bchsigs. May be 0 if bchsigs is NULL.

    struct {
        char *address;
        bool valid;
    } dev_donations[DONATION_NUM_ADDRESSES];  // [0] = calin, [1] = bchn -- see donation.h

    double pool_fee; // comes from "pool_fee" in config, as a percentage. Defaults to 1.0 if unspecified. SPLNS mode only.

    bool disable_dev_donation; // comes from "disable_dev_donation" top level key. Defaults to false if unspecified.

    time_t blocking_timeout; // defaults to 60 seconds, can be set as a top-level option "blocking_timeout" : NN

    /* Stratum options */
    server_instance_t **servers;
    char **serverurl; // Array of URLs to bind our server/proxy to
    int serverurls; // Number of server bindings
    bool *nodeserver; // If this server URL serves node information
    int nodeservers; // If this server has remote node servers
    bool *trusted; // If this server URL accepts trusted remote nodes
    char *upstream; // Upstream pool in trusted remote mode

    int update_interval; // Seconds between stratum updates

    uint32_t version_mask; // Bits which set to true means allow miner to modify those bits

    /* Proxy options */
    int proxies;
    char **proxyurl;
    char **proxyauth;
    char **proxypass;

    /* Passthrough redirect options */
    int redirecturls;
    char **redirecturl;
    char **redirectport;

    /* Private data for each process */
    void *gdata;
    void *sdata;
    void *cdata;
};

enum stratum_msgtype {
    SM_RECONNECT = 0,
    SM_DIFF,
    SM_MSG,
    SM_UPDATE,
    SM_ERROR,
    SM_SUBSCRIBE,
    SM_SUBSCRIBERESULT,
    SM_SHARE,
    SM_SHARERESULT,
    SM_AUTH,
    SM_AUTHRESULT,
    SM_TXNS,
    SM_TXNSRESULT,
    SM_PING,
    SM_WORKINFO,
    SM_SUGGESTDIFF,
    SM_BLOCK,
    SM_PONG,
    SM_TRANSACTIONS,
    SM_SHAREERR,
    SM_WORKERSTATS,
    SM_REQTXNS,
    SM_CONFIGURE,
    SM_NONE
};

static const char maybe_unused__ *stratum_msgs[] = {
    "reconnect",
    "diff",
    "message",
    "update",
    "error",
    "subscribe",
    "subscribe.result",
    "share",
    "share.result",
    "auth",
    "auth.result",
    "txns",
    "txns.result",
    "ping",
    "workinfo",
    "suggestdiff",
    "block",
    "pong",
    "transactions",
    "shareerr",
    "workerstats",
    "reqtxns",
    "mining.configure",
    ""
};

#define SAFE_HASH_OVERHEAD(HASHLIST) (HASHLIST ? HASH_OVERHEAD(hh, HASHLIST) : 0)

void get_timestamp(char *stamp, size_t stamp_len, bool is_localtime /* if false, use gmtime */);

ckmsgq_t *create_ckmsgq(pool_t *ckp, const char *name, const void *func);
ckmsgq_t *create_ckmsgqs(pool_t *ckp, const char *name, const void *func, const int count);
bool ckmsgq_add_(ckmsgq_t *ckmsgq, void *data, const char *file, const char *func, const int line);
#define ckmsgq_add(ckmsgq, data) ckmsgq_add_(ckmsgq, data, __FILE__, __func__, __LINE__)
bool ckmsgq_empty(ckmsgq_t *ckmsgq);
unix_msg_t *get_unix_msg(proc_instance_t *pi);

extern pool_t *global_ckp;

bool ping_main(pool_t *ckp);
void empty_buffer(connsock_t *cs);
int set_sendbufsize(pool_t *ckp, const int fd, const int len);
int set_recvbufsize(pool_t *ckp, const int fd, const int len);
int read_socket_line(connsock_t *cs, float *timeout);
/* Like read_socket_line except it doesn't read lines. Designed to be used with
 * http response content. Read from a socket into cs->buf up to contentlen bytes.
 */
int read_socket_contentlen(connsock_t *cs, int contentlen, float *timeout);
void queue_proc_(proc_instance_t *pi, const char *msg, const char *file, const char *func, const int line);
#define send_proc(pi, msg) queue_proc_(&(pi), msg, __FILE__, __func__, __LINE__)
char *send_recv_proc_(const proc_instance_t *pi, const char *msg, int writetimeout, int readtimedout,
                      const char *file, const char *func, const int line);
#define send_recv_proc(pi, msg) send_recv_proc_(&(pi), msg, UNIX_WRITE_TIMEOUT, UNIX_READ_TIMEOUT, __FILE__, __func__, __LINE__)

struct rpc_req_part {
    const char *string;
    const size_t length;
};
json_t *json_rpc_call_parts(connsock_t *cs, const struct rpc_req_part *rpc_req);
json_t *json_rpc_call(connsock_t *cs, const char *rpc_req);
json_t *json_rpc_response(connsock_t *cs, const char *rpc_req);
void json_rpc_msg(connsock_t *cs, const char *rpc_req);
bool send_json_msg(connsock_t *cs, const json_t *json_msg);
json_t *json_msg_result(const char *msg, json_t **res_val, json_t **err_val);

bool json_get_string(char **store, const json_t *val, const char *res);
bool json_get_int64(int64_t *store, const json_t *val, const char *res);
bool json_get_int(int *store, const json_t *val, const char *res);
bool json_get_double(double *store, const json_t *val, const char *res);
bool json_get_uint32(uint32_t *store, const json_t *val, const char *res);
bool json_get_bool(bool *store, const json_t *val, const char *res);
bool json_getdel_int(int *store, json_t *val, const char *res);
bool json_getdel_int64(int64_t *store, json_t *val, const char *res);


/* API Placeholders for future API implementation */
typedef struct apimsg apimsg_t;

struct apimsg {
    char *buf;
    int sockd;
};

static inline void asicseer_pool_api(pool_t maybe_unused__ *ckp, apimsg_t maybe_unused__ *apimsg) {}
static inline json_t *json_encode_errormsg(json_error_t maybe_unused__ *err_val) { return NULL; }
static inline json_t *json_errormsg(const char maybe_unused__ *fmt, ...) { return NULL; }
static inline void send_api_response(json_t maybe_unused__ *val, const int maybe_unused__ sockd) {}

/* Subclients have client_ids in the high bits. Returns the value of the parent
 * client if one exists. */
static inline int64_t subclient(const int64_t client_id)
{
    return (client_id >> 32);
}

// Returns a value from 0.0 (no discount) to 1.0 (full discount) for a particular
// username.  This is set in the config file as a dict named "fee_discounts".
extern double username_get_fee_discount(pool_t *ckp, const char *username);

#ifdef __cplusplus
}
#endif

#endif /* ASICSEER_POOL_H */
