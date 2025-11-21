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

/* This file should contain all exported functions of libasicseerpool */

#ifndef LIB_ASICSEER_POOL_H
#define LIB_ASICSEER_POOL_H

// The below are used to name processes and for socket names in the sockets dir
#define PROG_PREFIX "asicseer-"
#define POOL_PROGNAME PROG_PREFIX"pool"
#define PROXY_PROGNAME PROG_PREFIX"proxy"
#define NODE_PROGNAME PROG_PREFIX"node"
#define REDIRECTOR_PROGNAME PROG_PREFIX"redirector"
#define PASSTHROUGH_PROGNAME PROG_PREFIX"passthrough"

#include <errno.h>
#include <jansson.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#if HAVE_BYTESWAP_H
# include <byteswap.h>
#endif

#if HAVE_ENDIAN_H
# include <endian.h>
#elif HAVE_SYS_ENDIAN_H
# include <sys/endian.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>

#include "bitcoin/common.h"
#include "utlist.h"

#ifdef  __cplusplus

#include <vector>

// Below is used by tests.cpp to test internals
int64_t vch_to_int64(std::vector<unsigned char> vchIn);
std::vector<unsigned char> int64_to_vch(int64_t value);

extern "C" {
#endif

#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#define maybe_unused__ __attribute__((unused))

#ifndef MAX
#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a > _b ? _a : _b; })
#endif
#ifndef MIN
#define MIN(a,b) \
    ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
       _a < _b ? _a : _b; })
#endif

#define PASTE(x, y) x ## y
#define PASTE2(x, y) PASTE(x, y)
#define UNIQUE_NAME(name) PASTE2(PASTE(name, _), __COUNTER__)


typedef unsigned char uchar;

typedef struct timeval tv_t;
typedef struct timespec ts_t;

static inline uint32_t read_i32(const void *p) { uint32_t ret; memcpy(&ret, p, sizeof(ret)); return ret; }
static inline uint64_t read_i64(const void *p) { uint64_t ret; memcpy(&ret, p, sizeof(ret)); return ret; }
static inline void write_i32(void *dest, uint32_t val) { memcpy(dest, &val, sizeof(val)); }
static inline void write_i64(void *dest, uint64_t val) { memcpy(dest, &val, sizeof(val)); }

maybe_unused__
static inline void swap_256(void *dest_p, const void *src_p)
{
    uchar *dest = (uchar *)dest_p;
    const uchar *src = (const uchar *)src_p;

    /* if dest and src were aligned uint32_t *, it would look like this:
    dest[0] = src[7];
    dest[1] = src[6];
    dest[2] = src[5];
    dest[3] = src[4];
    dest[4] = src[3];
    dest[5] = src[2];
    dest[6] = src[1];
    dest[7] = src[0];
    */
#define CPY32__(d, s) memcpy(d, s, 4)
    CPY32__(dest + 0*4, src + 7*4);
    CPY32__(dest + 1*4, src + 6*4);
    CPY32__(dest + 2*4, src + 5*4);
    CPY32__(dest + 3*4, src + 4*4);
    CPY32__(dest + 4*4, src + 3*4);
    CPY32__(dest + 5*4, src + 2*4);
    CPY32__(dest + 6*4, src + 1*4);
    CPY32__(dest + 7*4, src + 0*4);
#undef CPY32__
}

maybe_unused__
static inline void bswap_256(void *dest_p, const void *src_p)
{
    uchar *dest = (uchar *)dest_p;
    const uchar *src = (const uchar *)src_p;

    /* if dest and src were aligned uint32_t *, it would look like this:
    dest[0] = bswap_32(src[7]);
    dest[1] = bswap_32(src[6]);
    dest[2] = bswap_32(src[5]);
    dest[3] = bswap_32(src[4]);
    dest[4] = bswap_32(src[3]);
    dest[5] = bswap_32(src[2]);
    dest[6] = bswap_32(src[1]);
    dest[7] = bswap_32(src[0]);
    */

    write_i32(dest + 0*4, bswap_32(read_i32(src + 7*4)));
    write_i32(dest + 1*4, bswap_32(read_i32(src + 6*4)));
    write_i32(dest + 2*4, bswap_32(read_i32(src + 5*4)));
    write_i32(dest + 3*4, bswap_32(read_i32(src + 4*4)));
    write_i32(dest + 4*4, bswap_32(read_i32(src + 3*4)));
    write_i32(dest + 5*4, bswap_32(read_i32(src + 2*4)));
    write_i32(dest + 6*4, bswap_32(read_i32(src + 1*4)));
    write_i32(dest + 7*4, bswap_32(read_i32(src + 0*4)));
}

static inline void flip_N(void *dest_p, const void *src_p, const int N)
{
    uchar *dest = (uchar *)dest_p;
    const uchar *src = (const uchar *)src_p;
    int offset;

    for (offset = 0; offset < N; offset += 4)
        write_i32(dest + offset, bswap_32(read_i32(src + offset))); // dest_int[i] = bswap_32(src_int[i]);
}

maybe_unused__ static inline void flip_32(void *dest_p, const void *src_p) { flip_N(dest_p, src_p, 32); }
maybe_unused__ static inline void flip_80(void *dest_p, const void *src_p) { flip_N(dest_p, src_p, 80); }

#define cond_wait(_cond, _lock) cond_wait_(_cond, _lock, __FILE__, __func__, __LINE__)
#define cond_timedwait(_cond, _lock, _abstime) cond_timedwait_(_cond, _lock, _abstime, __FILE__, __func__, __LINE__)
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
#define mutex_timedlock(_lock, _timeout) mutex_timedlock_(_lock, _timeout, __FILE__, __func__, __LINE__)
#endif
#define mutex_lock(_lock) mutex_lock_(_lock, __FILE__, __func__, __LINE__)
#define mutex_unlock(_lock) mutex_unlock_(_lock, __FILE__, __func__, __LINE__)
#define mutex_trylock(_lock) mutex_trylock_(_lock, __FILE__, __func__, __LINE__)
#define wr_lock(_lock) wr_lock_(_lock, __FILE__, __func__, __LINE__)
#define wr_trylock(_lock) wr_trylock_(_lock, __FILE__, __func__, __LINE__)
#define rd_lock(_lock) rd_lock_(_lock, __FILE__, __func__, __LINE__)
#define rw_unlock(_lock) rw_unlock_(_lock, __FILE__, __func__, __LINE__)
#define rd_unlock(_lock) rd_unlock_(_lock, __FILE__, __func__, __LINE__)
#define wr_unlock(_lock) wr_unlock_(_lock, __FILE__, __func__, __LINE__)
#define mutex_init(_lock) mutex_init_(_lock, __FILE__, __func__, __LINE__)
#define rwlock_init(_lock) rwlock_init_(_lock, __FILE__, __func__, __LINE__)
#define cond_init(_cond) cond_init_(_cond, __FILE__, __func__, __LINE__)

#define cklock_init(_lock) cklock_init_(_lock, __FILE__, __func__, __LINE__)
#define ck_rlock(_lock) ck_rlock_(_lock, __FILE__, __func__, __LINE__)
#define ck_wlock(_lock) ck_wlock_(_lock, __FILE__, __func__, __LINE__)
#define ck_dwlock(_lock) ck_dwlock_(_lock, __FILE__, __func__, __LINE__)
#define ck_runlock(_lock) ck_runlock_(_lock, __FILE__, __func__, __LINE__)
#define ck_wunlock(_lock) ck_wunlock_(_lock, __FILE__, __func__, __LINE__)

#define ckalloc(len) ckzrealloc_(NULL, len, false, __FILE__, __func__, __LINE__)
#define ckzalloc(len) ckzrealloc_(NULL, len, true, __FILE__, __func__, __LINE__)
#define ckrealloc(buf, len) ckzrealloc_(buf, len, false, __FILE__, __func__, __LINE__)
#define ckzrealloc(buf, len) ckzrealloc_(buf, len, true, __FILE__, __func__, __LINE__)
char *ckstrdup(const char *s);
char *ckstrndup(const char *s, int len);

#define dealloc(ptr) do { \
    free(ptr); \
    ptr = NULL; \
} while (0)

#define VASPRINTF(strp, fmt, ...) do { \
    if (unlikely(vasprintf(strp, fmt, ##__VA_ARGS__) < 0)) \
        quitfrom(1, __FILE__, __func__, __LINE__, "Failed to asprintf"); \
} while (0)

#define ASPRINTF(strp, fmt, ...) do { \
    if (unlikely(asprintf(strp, fmt, ##__VA_ARGS__) < 0)) \
        quitfrom(1, __FILE__, __func__, __LINE__, "Failed to asprintf"); \
} while (0)

/// This pointer starts out NULL. Set it to point to your global_ckp->loglevel
/// int order to use global loglevel suppression at the macro level,
/// in order to avoid evaluating macro arguments if the global loglevel is below
/// the message level.
extern const int *global_loglevel_ptr;
#define SHOULD_EVALUATE_LOGMSG(lvl) (!global_loglevel_ptr || lvl <= *global_loglevel_ptr)

void logmsg(int loglevel, const char *fmt, ...);

#define DEFLOGBUFSIZ 1000

#define LOGMSGBUF(__lvl, __buf) do { \
        if (SHOULD_EVALUATE_LOGMSG(__lvl)) \
            logmsg(__lvl, "%s", __buf); \
    } while(0)
#define LOGMSGSIZ(__siz, __lvl, __fmt, ...) do { \
        if (SHOULD_EVALUATE_LOGMSG(__lvl)) { \
            char tmp42[__siz]; \
            snprintf(tmp42, sizeof(tmp42), __fmt, ##__VA_ARGS__); \
            logmsg(__lvl, "%s", tmp42); \
        } \
    } while(0)

#define LOGMSG(_lvl, _fmt, ...) \
    LOGMSGSIZ(DEFLOGBUFSIZ, _lvl, _fmt, ##__VA_ARGS__)

#define LOGEMERG(fmt, ...) LOGMSG(LOG_EMERG, fmt, ##__VA_ARGS__)
#define LOGALERT(fmt, ...) LOGMSG(LOG_ALERT, fmt, ##__VA_ARGS__)
#define LOGCRIT(fmt, ...) LOGMSG(LOG_CRIT, fmt, ##__VA_ARGS__)
#define LOGERR(fmt, ...) LOGMSG(LOG_ERR, fmt, ##__VA_ARGS__)
#define LOGWARNING(fmt, ...) LOGMSG(LOG_WARNING, fmt, ##__VA_ARGS__)
#define LOGNOTICE(fmt, ...) LOGMSG(LOG_NOTICE, fmt, ##__VA_ARGS__)
#define LOGINFO(fmt, ...) LOGMSG(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOGDEBUG(fmt, ...) LOGMSG(LOG_DEBUG, fmt, ##__VA_ARGS__)

#define IN_FMT_FFL " in %s %s():%d"
#define quitfrom(status, _file, _func, _line, fmt, ...) do { \
    if (fmt) { \
        fprintf(stderr, fmt IN_FMT_FFL, ##__VA_ARGS__, _file, _func, _line); \
        fprintf(stderr, "\n"); \
        fflush(stderr); \
    } \
    exit(status); \
} while (0)

#define quit(status, fmt, ...) do { \
    if (fmt) { \
        fprintf(stderr, fmt, ##__VA_ARGS__); \
        fprintf(stderr, "\n"); \
        fflush(stderr); \
    } \
    exit(status); \
} while (0)

#define PAGESIZE (4096)

/* Default timeouts for unix socket reads and writes in seconds. Set write
 * timeout to double the read timeout in case of one read blocking the next
 * writer. */
#define UNIX_READ_TIMEOUT 5
#define UNIX_WRITE_TIMEOUT 10

#define MIN1	60
#define MIN5	300
#define MIN15	900
#define HOUR	3600
#define HOUR6	21600
#define DAY	86400
#define WEEK	604800

/* Share error values */

enum share_err {
    SE_INVALID_NONCE2 = -9,
    SE_WORKER_MISMATCH,
    SE_NO_NONCE,
    SE_NO_NTIME,
    SE_NO_NONCE2,
    SE_NO_JOBID,
    SE_NO_USERNAME,
    SE_INVALID_SIZE,
    SE_NOT_ARRAY,
    SE_NONE, // 0
    SE_INVALID_JOBID,
    SE_STALE,
    SE_NTIME_INVALID,
    SE_DUPE,
    SE_HIGH_DIFF,
    SE_INVALID_VERSION_MASK
};

static const char maybe_unused__ *share_errs[] = {
    "Invalid nonce2 length",
    "Worker mismatch",
    "No nonce",
    "No ntime",
    "No nonce2",
    "No job_id",
    "No username",
    "Invalid array size",
    "Params not array",
    "Valid",
    "Invalid JobID",
    "Stale",
    "Ntime out of range",
    "Duplicate",
    "Above target",
    "Invalid version mask"
};

#define SHARE_ERR(x) share_errs[((x) + 9)]

typedef struct ckmutex mutex_t;

struct ckmutex {
    pthread_mutex_t mutex;
    const char *file;
    const char *func;
    int line;
};

typedef struct ckrwlock rwlock_t;

struct ckrwlock {
    pthread_rwlock_t rwlock;
    const char *file;
    const char *func;
    int line;
};

/* ck locks, a write biased variant of rwlocks */
struct cklock {
    mutex_t mutex;
    rwlock_t rwlock;
    const char *file;
    const char *func;
    int line;
};

typedef struct cklock cklock_t;

struct unixsock {
    int sockd;
    char *path;
};

typedef struct unixsock unixsock_t;

void json_check_(json_t *val, json_error_t *err, const char *file, const char *func, const int line);
#define json_check(VAL, ERR) json_check_(VAL, ERR,  __FILE__, __func__, __LINE__)

/* Check and pack json */
#define JSON_CPACK(VAL, ...) do { \
    json_error_t ERR; \
    VAL = json_pack_ex(&ERR, 0, ##__VA_ARGS__); \
    json_check(VAL, &ERR); \
} while (0)

/* No error checking with these, make sure we know they're valid already! */
maybe_unused__
static inline void json_strcpy(char *buf, json_t *val, const char *key)
{
    strcpy(buf, json_string_value(json_object_get(val, key)) ? : "");
}

maybe_unused__
static inline void json_dblcpy(double *dbl, json_t *val, const char *key)
{
    *dbl = json_real_value(json_object_get(val, key));
}

maybe_unused__
static inline void json_uintcpy(uint32_t *u32, json_t *val, const char *key)
{
    *u32 = (uint32_t)json_integer_value(json_object_get(val, key));
}

maybe_unused__
static inline void json_uint64cpy(uint64_t *u64, json_t *val, const char *key)
{
    *u64 = (uint64_t)json_integer_value(json_object_get(val, key));
}

maybe_unused__
static inline void json_int64cpy(int64_t *i64, json_t *val, const char *key)
{
    *i64 = (int64_t)json_integer_value(json_object_get(val, key));
}

maybe_unused__
static inline void json_intcpy(int *i, json_t *val, const char *key)
{
    *i = json_integer_value(json_object_get(val, key));
}

maybe_unused__
static inline void json_strdup(char **buf, json_t *val, const char *key)
{
    *buf = strdup(json_string_value(json_object_get(val, key)) ? : "");
}

/* Helpers for setting a field will check for valid entry and print an error
 * if it is unsuccessfully set. */
maybe_unused__
static inline void json_set_string_(json_t *val, const char *key, const char *str,
                    const char *file, const char *func, const int line)
{
    if (unlikely(json_object_set_new(val, key, json_string(str))))
        LOGERR("Failed to set json string from %s %s:%d", file, func, line);
}
#define json_set_string(val, key, str) json_set_string_(val, key, str, __FILE__, __func__, __LINE__)

/* Int is long long so will work for u32 and int64 */
maybe_unused__
static inline void json_set_int_(json_t *val, const char *key, int64_t integer,
                 const char *file, const char *func, const int line)
{
    if (unlikely(json_object_set_new_nocheck(val, key, json_integer(integer))))
        LOGERR("Failed to set json int from %s %s:%d", file, func, line);
}
#define json_set_int(val, key, integer) json_set_int_(val, key, integer, __FILE__, __func__, __LINE__)
#define json_set_uint32(val, key, u32) json_set_int_(val, key, u32, __FILE__, __func__, __LINE__)
#define json_set_int64(val, key, i64) json_set_int_(val, key, i64, __FILE__, __func__, __LINE__)

maybe_unused__
static inline void json_set_double_(json_t *val, const char *key, double real,
                    const char *file, const char *func, const int line)
{
    if (unlikely(json_object_set_new_nocheck(val, key, json_real(real))))
        LOGERR("Failed to set json double from %s %s:%d", file, func, line);
}
#define json_set_double(val, key, real) json_set_double_(val, key, real, __FILE__, __func__, __LINE__)

maybe_unused__
static inline void json_set_bool_(json_t *val, const char *key, bool boolean,
                  const char *file, const char *func, const int line)
{
    if (unlikely(json_object_set_new_nocheck(val, key, json_boolean(boolean))))
        LOGERR("Failed to set json bool from %s %s:%d", file, func, line);
}
#define json_set_bool(val, key, boolean) json_set_bool_(val, key, boolean, __FILE__, __func__, __LINE__)

/* Steals an object and NULLs original reference */
maybe_unused__
static inline void json_steal_object_(json_t *val, const char *key, json_t **object,
                  const char *file, const char *func, const int line)
{
    if (unlikely(json_object_set_new_nocheck(val, key, *object)))
        LOGERR("Failed to set json object from %s %s:%d", file, func, line);
    *object = NULL;
}
#define json_steal_object(val, key, object) json_steal_object_(val, key, &(object), __FILE__, __func__, __LINE__)

const char *package_version(void); // returns the libasicseerpool compiled-in PACKAGE_VERSION string
void rename_proc(const char *name);
void create_pthread(pthread_t *thread, void *(*start_routine)(void *), void *arg);
void join_pthread(pthread_t thread);

int cond_wait_(pthread_cond_t *cond, mutex_t *lock, const char *file, const char *func, const int line);
int cond_timedwait_(pthread_cond_t *cond, mutex_t *lock, const struct timespec *abstime, const char *file, const char *func, const int line);
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
int mutex_timedlock_(mutex_t *lock, int timeout, const char *file, const char *func, const int line);
#endif
void mutex_lock_(mutex_t *lock, const char *file, const char *func, const int line);
void mutex_unlock_(mutex_t *lock, const char *file, const char *func, const int line);
int mutex_trylock_(mutex_t *lock, maybe_unused__ const char *file, maybe_unused__ const char *func, maybe_unused__ const int line);
void mutex_destroy(mutex_t *lock);

void wr_lock_(rwlock_t *lock, const char *file, const char *func, const int line);
int wr_trylock_(rwlock_t *lock, maybe_unused__ const char *file, maybe_unused__ const char *func, maybe_unused__ const int line);
void rd_lock_(rwlock_t *lock, const char *file, const char *func, const int line);
void rw_unlock_(rwlock_t *lock, const char *file, const char *func, const int line);
void rd_unlock_(rwlock_t *lock, const char *file, const char *func, const int line);
void wr_unlock_(rwlock_t *lock, const char *file, const char *func, const int line);
void mutex_init_(mutex_t *lock, const char *file, const char *func, const int line);
void rwlock_init_(rwlock_t *lock, const char *file, const char *func, const int line);
void cond_init_(pthread_cond_t *cond, const char *file, const char *func, const int line);

void cklock_init_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_rlock_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_wlock_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_dwlock_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_dwilock_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_runlock_(cklock_t *lock, const char *file, const char *func, const int line);
void ck_wunlock_(cklock_t *lock, const char *file, const char *func, const int line);
void cklock_destroy(cklock_t *lock);

struct OpaqueSem; // opaque semaphore type, implemented on the C++ side
typedef struct OpaqueSem *cksem_t;

/* The below are implemented in the C++ part of this lib */
void cksem_init_(cksem_t *sem, const char *file, const char *func, const int line);
void cksem_post_(cksem_t *sem, const char *file, const char *func, const int line);
void cksem_wait_(cksem_t *sem, const char *file, const char *func, const int line);
int cksem_trywait_(cksem_t *sem, const char *file, const char *func, const int line);
void cksem_destroy_(cksem_t *sem, const char *file, const char *func, const int line);

#define cksem_init(SEM) cksem_init_(SEM, __FILE__, __func__, __LINE__)
#define cksem_post(SEM) cksem_post_(SEM, __FILE__, __func__, __LINE__)
#define cksem_wait(SEM) cksem_wait_(SEM, __FILE__, __func__, __LINE__)
#define cksem_trywait(SEM) cksem_trywait_(SEM, __FILE__, __func__, __LINE__)
#define cksem_destroy(SEM) cksem_destroy_(SEM, __FILE__, __func__, __LINE__)

maybe_unused__
static inline bool sock_connecting(void)
{
    return errno == EINPROGRESS;
}

maybe_unused__
static inline bool sock_blocks(void)
{
    return (errno == EAGAIN || errno == EWOULDBLOCK);
}

maybe_unused__
static inline bool sock_timeout(void)
{
    return (errno == ETIMEDOUT);
}
bool extract_sockaddr(const char *url, char **sockaddr_url, char **sockaddr_port);
bool url_from_sockaddr(const struct sockaddr *addr, char *url, char *port);
bool addrinfo_from_url(const char *url, const char *port, struct addrinfo *addrinfo);
bool url_from_serverurl(char *serverurl, char *newurl, char *newport);
bool url_from_socket(const int sockd, char *url, char *port);

/// Given a zmq endpoint e.g. tcp://someip:1234, extracts the protocol portion
/// "tcp" and port portion "1234", into malloc'd strings.
/// If middle pointer is not NULL, will also malloc a string for the middle portion
/// before the port.
/// Returns false on parse error (in which case nothing is allocated).
bool extract_zmq_proto_port(const char *zmqurl, char **proto, char **port, char **middle);

void keep_sockalive(int fd);
void nolinger_socket(int fd);
void noblock_socket(int fd);
void block_socket(int fd);
void close_helper(int *fd, const char *file, const char *func, const int line);
#define Close_(FD) close_helper(FD, __FILE__, __func__, __LINE__)
#define Close(FD) close_helper(&FD, __FILE__, __func__, __LINE__)
int bind_socket(char *url, char *port);
int connect_socket(char *url, char *port);
int round_trip(char *url);
int write_socket(int fd, const void *buf, size_t nbyte);
void empty_socket(int fd);
void close_unix_socket_(int *sockd, const char *server_path);
#define close_unix_socket(sockd, server_path) close_unix_socket_(&sockd, server_path)
int open_unix_server_(const char *server_path, const char *file, const char *func, const int line);
#define open_unix_server(server_path) open_unix_server_(server_path, __FILE__, __func__, __LINE__)
int open_unix_client_(const char *server_path, const char *file, const char *func, const int line);
#define open_unix_client(server_path) open_unix_client_(server_path, __FILE__, __func__, __LINE__)
int wait_close(int sockd, int timeout);
int wait_read_select(int sockd, float timeout);
int read_length(int sockd, void *buf, int len);
char *recv_unix_msg_(int sockd, int timeout1, int timeout2, const char *file, const char *func, const int line);
#define RECV_UNIX_TIMEOUT1 30
#define RECV_UNIX_TIMEOUT2 5
#define recv_unix_msg(sockd) recv_unix_msg_(sockd, UNIX_READ_TIMEOUT, UNIX_READ_TIMEOUT, __FILE__, __func__, __LINE__)
#define recv_unix_msg_tmo(sockd, tmo) recv_unix_msg_(sockd, tmo, UNIX_READ_TIMEOUT, __FILE__, __func__, __LINE__)
#define recv_unix_msg_tmo2(sockd, tmo1, tmo2) recv_unix_msg_(sockd, tmo1, tmo2, __FILE__, __func__, __LINE__)
int wait_write_select(int sockd, float timeout);
#define write_length(sockd, buf, len) write_length_(sockd, buf, len, __FILE__, __func__, __LINE__)
int write_length_(int sockd, const void *buf, int len, const char *file, const char *func, const int line);
bool send_unix_msg_(int sockd, const char *buf, int timeout, const char *file, const char *func, const int line);
#define send_unix_msg(sockd, buf) send_unix_msg_(sockd, buf, UNIX_WRITE_TIMEOUT, __FILE__, __func__, __LINE__)
bool send_unix_data_(int sockd, const struct msghdr *msg, const char *file, const char *func, const int line);
#define send_unix_data(sockd, msg) send_unix_data_(sockd, msg, __FILE__, __func__, __LINE__)
bool recv_unix_data_(int sockd, struct msghdr *msg, const char *file, const char *func, const int line);
#define recv_unix_data(sockd, msg) recv_unix_data_(sockd, msg, __FILE__, __func__, __LINE__)
bool send_fd_(int fd, int sockd, const char *file, const char *func, const int line);
#define send_fd(fd, sockd) send_fd_(fd, sockd, __FILE__, __func__, __LINE__)
int get_fd_(int sockd, const char *file, const char *func, const int line);
#define get_fd(sockd) get_fd_(sockd, __FILE__, __func__, __LINE__)

const char *json_array_string__(json_t *val, unsigned int entry);
char *json_array_string(json_t *val, unsigned int entry);
json_t *json_object_dup(json_t *val, const char *entry);

char *rotating_filename(const char *path, time_t when);
bool rotating_log(const char *path, const char *msg);

void align_len(size_t *len);
void realloc_strcat(char **ptr, const char *s);
void trail_slash(char **buf);
void *json_ckalloc(size_t size);
void *ckzrealloc_(void *old, size_t len, bool zeromem, const char *file, const char *func, const int line);
size_t round_up_page(size_t len);

size_t bin2hex__(char *dest, const void *bin, size_t len);
char *bin2hex(const void *bin, size_t len);
bool validhex__(const char *buf, const char *file, const char *func, const int line);
#define validhex(buf) validhex__(buf, __FILE__, __func__, __LINE__)
bool hex2bin__(void *dest, const char *hexstr, size_t len, const char *file, const char *func, const int line);
#define hex2bin(p, hexstr, len) hex2bin__(p, hexstr, len, __FILE__, __func__, __LINE__)
char *http_base64(const char *src);
/* Does no checksum checks but returns false if the characters in b58 source are invalid, or if b58 is > 35 characters, true otherwise. */
bool b58tobin_safe(uchar *b58bin, const char *b58);
int safecmp(const char *a, const char *b);
int safecasecmp(const char *a, const char *b, int len); // pass len < 0 to compare all
bool cmdmatch(const char *buf, const char *cmd);

/// Writes length_byte(s) + `size_to_write` to the buffer at dest.  Returns the number of bytes written,
/// including the size byte(s). `dest` should have space for at least 9 bytes.
/// Return value will always be <= 9.
int write_compact_size(void *dest, size_t size_to_write);

// returns 0 on address parse failure, otherwise returns length of generated CScript
int address_to_script(uchar *script, const char *addr, bool is_p2sh, const char *default_cashaddr_prefix);

int ser_cbheight(void *s, int32_t val);
int deser_cbheight(const void *s);
bool fulltest(const uchar *hash, const uchar *target);

void copy_tv(tv_t *dest, const tv_t *src);
void ts_to_tv(tv_t *val, const ts_t *spec);
void tv_to_ts(ts_t *spec, const tv_t *val);
void us_to_tv(tv_t *val, int64_t us);
void us_to_ts(ts_t *spec, int64_t us);
void ms_to_ts(ts_t *spec, int64_t ms);
void ms_to_tv(tv_t *val, int64_t ms);
void tv_time(tv_t *tv);
void ts_realtime(ts_t *ts);
void ts_monotonic(ts_t *ts);
/* This is monotomic time in microseconds, using CLOCK_MONOTONIC. Suitable for profiling
   or obtaining a unique timestamp throughout the run of the program.  */
int64_t time_micros(void);

void cksleep_prepare_r(ts_t *ts);
void nanosleep_abstime(const ts_t *ts_end);
void timeraddspec(ts_t *a, const ts_t *b);
void cksleep_ms_r(ts_t *ts_start, int ms);
void cksleep_us_r(ts_t *ts_start, int64_t us);
void cksleep_ms(int ms);
void cksleep_us(int64_t us);

double us_tvdiff(tv_t *end, tv_t *start);
int ms_tvdiff(tv_t *end, tv_t *start);
double tvdiff(tv_t *end, tv_t *start);

void decay_time(double *f, double fadd, double fsecs, double interval);
double sane_tdiff(tv_t *end, tv_t *start);
void suffix_string(double val, char *buf, size_t bufsiz, int sigdigits);

double le256todouble(const uchar *target);
double diff_from_target(const uchar *target);
double diff_from_nbits(const uchar *nbits);
void target_from_diff(uchar *target, double diff);

void gen_hash(const uchar *data, uchar *hash, int len);

/// returns a number in the range [0, range)
int random_threadsafe(int range);

/* epoll()/kevent() abstraction layer */
struct AbstractEvent {
    int fd;
    uint64_t userdata;
    bool in, out, hup, rdhup, err;
    int64_t data;
};
typedef struct AbstractEvent aevt_t;

int epfd_create_(const char *file, const char *func, int line); //< crate a new epfd .. close it using close()
int epfd_add_or_mod_(int epfd, int fd, uint64_t userdata, bool isAdd, bool forRead, bool oneShot, bool edgeTriggered, const char *file, const char *func, int line);
int epfd_rm_(int epfd, int fd, const char *file, const char *func, int line);
int epfd_wait_(int epfd, aevt_t *event, int timeout_msec, const char *file, const char *func, int line);
#define epfd_create() epfd_create_(__FILE__, __func__, __LINE__)
#define epfd_add(epfd, fd, ud, ro, os, et) epfd_add_or_mod_(epfd, fd, ud,  true, ro, os, et, __FILE__, __func__, __LINE__)
#define epfd_mod(epfd, fd, ud, ro, os, et) epfd_add_or_mod_(epfd, fd, ud, false, ro, os, et, __FILE__, __func__, __LINE__)
#define epfd_rm(epfd, fd) epfd_rm_(epfd, fd, __FILE__, __func__, __LINE__)
#define epfd_wait(epfd, event, timeout_msec) epfd_wait_(epfd, event, timeout_msec, __FILE__, __func__, __LINE__)

/// Reads nbytes random bytes from a fast, insecure but high quality randomness source. This call is thread safe.
void get_random_bytes(void *buf, size_t nbytes);

struct MaxOpenFilesResult {
    bool ok;
    long old_limit, new_limit;
    char err_msg[64];
};
typedef struct MaxOpenFilesResult mofr_t;

/// Will attempt to raise the POSIX RLIMIT_NOFILE limit from the soft limit to the hard limit.
mofr_t raise_max_open_files_to_hard_limit(void);

#ifdef  __cplusplus
}
#endif

#endif /* LIB_ASICSEER_POOL_H */
