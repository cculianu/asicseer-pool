/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 2014-2018 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CKPOOL_H
#define CKPOOL_H

#include "config.h"

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>

#include "donation.h"
#include "libckpool.h"
#include "uthash.h"

#define RPC_TIMEOUT 60

struct ckpool_instance;
typedef struct ckpool_instance ckpool_t;

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
	ckpool_t *ckp;
	char name[16];
	pthread_t pth;
	mutex_t *lock;
	pthread_cond_t *cond;
	ckmsg_t *msgs;
	void (*func)(ckpool_t *, void *);
	int64_t messages;
	bool active;
};

typedef struct ckmsgq ckmsgq_t;

typedef struct proc_instance proc_instance_t;

struct proc_instance {
	ckpool_t *ckp;
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

	ckpool_t *ckp;
	/* Semaphore used to serialise request/responses */
	sem_t sem;

	bool alive;
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

	char *url;
	char *auth;
	char *pass;
	bool notify;
	bool alive;
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

struct ckpool_instance {
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
	/* Directory where ckdb sockets are */
	char *ckdb_sockdir;
	/* Name of the ckdb process */
	char *ckdb_name;
	char *ckdb_sockname;
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

	/* Are we running without ckdb */
	bool standalone;

	/* Are we running in userproxy mode */
	bool userproxy;

	/* Should we daemonise the ckpool process */
	bool daemon;

	/* Should we disable the throbber */
	bool quiet;

	/* Have we given warnings about the inability to raise buf sizes */
	bool wmem_warn;
	bool rmem_warn;

	/* Bitcoind data */
	int btcds;
	char **btcdurl;
	char **btcdauth;
	char **btcdpass;
	bool *btcdnotify;
	int blockpoll; // How frequently in ms to poll bitcoind for block updates
	int nonce1length; // Extranonce1 length
	int nonce2length; // Extranonce2 length

	/* Difficulty settings */
	int64_t mindiff; // Default 1
	int64_t startdiff; // Default 42
	int64_t maxdiff; // No default

	const mindiff_override_t *mindiff_overrides; // Taken from top-level "mindiff_overrides" : { ... } in config.
	size_t n_mindiff_overrides; // The number of mindiff_override in the above array. Will be 0 if array is NULL.

	/* Which chain are we on: "main", "test", or "regtest". Defaults to "main" but may be read
	   from bitcoind and updated if !proxy instance.
	   If you change these buffer sizes, update bitcoin.c get_chain(). */
	char chain[16];
	char cashaddr_prefix[16]; // defaults to "bitcoincash" but may be "bchtest" or "bchreg" after chain is correctly updated from bitcoind
	bool not_mainnet; // if true, we are not on main net but rather on test net or regtest net

	/* Coinbase data */
	char *bchaddress; // Address to mine to. In SPLNS mode this is used as a fallback address ok worker address failure, etc.
	bool script; // Address is a script address
	char *bchsig; // Optional signature to add to coinbase
	struct {
		char *address;
		bool isscript;
		bool valid;
	} dev_donations[DONATION_NUM_ADDRESSES];  // [0] = calin, [1] = bchn -- see donation.h

	double pool_fee; // comes from "pool_fee" in config, as a percentage. Defaults to 1.0 if unspecified. SPLNS mode only.

	/* Stratum options */
	server_instance_t **servers;
	char **serverurl; // Array of URLs to bind our server/proxy to
	int serverurls; // Number of server bindings
	bool *nodeserver; // If this server URL serves node information
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

static const char __maybe_unused *stratum_msgs[] = {
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

#ifdef USE_CKDB
#define CKP_STANDALONE(CKP) ((CKP)->standalone == true)
#else
#define CKP_STANDALONE(CKP) ((CKP) == (CKP)) /* Always true, silences unused warn */
#endif

#define SAFE_HASH_OVERHEAD(HASHLIST) (HASHLIST ? HASH_OVERHEAD(hh, HASHLIST) : 0)

void get_timestamp(char *stamp);

ckmsgq_t *create_ckmsgq(ckpool_t *ckp, const char *name, const void *func);
ckmsgq_t *create_ckmsgqs(ckpool_t *ckp, const char *name, const void *func, const int count);
bool _ckmsgq_add(ckmsgq_t *ckmsgq, void *data, const char *file, const char *func, const int line);
#define ckmsgq_add(ckmsgq, data) _ckmsgq_add(ckmsgq, data, __FILE__, __func__, __LINE__)
bool ckmsgq_empty(ckmsgq_t *ckmsgq);
unix_msg_t *get_unix_msg(proc_instance_t *pi);

ckpool_t *global_ckp;

bool ping_main(ckpool_t *ckp);
void empty_buffer(connsock_t *cs);
int set_sendbufsize(ckpool_t *ckp, const int fd, const int len);
int set_recvbufsize(ckpool_t *ckp, const int fd, const int len);
int read_socket_line(connsock_t *cs, float *timeout);
void _queue_proc(proc_instance_t *pi, const char *msg, const char *file, const char *func, const int line);
#define send_proc(pi, msg) _queue_proc(&(pi), msg, __FILE__, __func__, __LINE__)
char *_send_recv_proc(const proc_instance_t *pi, const char *msg, int writetimeout, int readtimedout,
		      const char *file, const char *func, const int line);
#define send_recv_proc(pi, msg) _send_recv_proc(&(pi), msg, UNIX_WRITE_TIMEOUT, UNIX_READ_TIMEOUT, __FILE__, __func__, __LINE__)
char *_send_recv_ckdb(const ckpool_t *ckp, const char *msg, const char *file, const char *func, const int line);
#define send_recv_ckdb(ckp, msg) _send_recv_ckdb(ckp, msg, __FILE__, __func__, __LINE__)
char *_ckdb_msg_call(const ckpool_t *ckp, const char *msg,  const char *file, const char *func,
		     const int line);
#define ckdb_msg_call(ckp, msg) _ckdb_msg_call(ckp, msg, __FILE__, __func__, __LINE__)

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

static inline void ckpool_api(ckpool_t __maybe_unused *ckp, apimsg_t __maybe_unused *apimsg) {};
static inline json_t *json_encode_errormsg(json_error_t __maybe_unused *err_val) { return NULL; };
static inline json_t *json_errormsg(const char __maybe_unused *fmt, ...) { return NULL; };
static inline void send_api_response(json_t __maybe_unused *val, const int __maybe_unused sockd) {};

/* Subclients have client_ids in the high bits. Returns the value of the parent
 * client if one exists. */
static inline int64_t subclient(const int64_t client_id)
{
	return (client_id >> 32);
}

#endif /* CKPOOL_H */
