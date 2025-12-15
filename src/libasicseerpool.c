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

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_LINUX_UN_H
#include <linux/un.h>
#else
#include <sys/un.h>
#endif
#include <sys/file.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <poll.h>
#include <arpa/inet.h>

#include "libasicseerpool.h"
#include "donation.h"
#include "sha2.h"
#include "utlist.h"
#include "cashaddr.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

const int *global_loglevel_ptr = NULL; /// used by macros if set

/* We use a weak function as a simple printf within the library that can be
 * overridden by however the outside executable wishes to do its logging. */
void __attribute__((weak)) logmsg(int maybe_unused__ loglevel, const char *fmt, ...)
{
    va_list ap;
    char *buf;

    va_start(ap, fmt);
    VASPRINTF(&buf, fmt, ap);
    va_end(ap);

    printf("%s\n", buf);
    free(buf);
}

const char *package_version(void)
{
    return PACKAGE_VERSION;
}

void create_pthread(pthread_t *thread, void *(*start_routine)(void *), void *arg)
{
    int ret = pthread_create(thread, NULL, start_routine,  arg);

    if (unlikely(ret))
        quit(1, "Failed to pthread_create");
}

void join_pthread(pthread_t thread)
{
    if (!pthread_kill(thread, 0))
        pthread_join(thread, NULL);
}

int cond_wait_(pthread_cond_t *cond, mutex_t *lock, const char *file, const char *func, const int line)
{
    int ret;

    ret = pthread_cond_wait(cond, &lock->mutex);
    lock->file = file;
    lock->func = func;
    lock->line = line;
    return ret;
}

int cond_timedwait_(pthread_cond_t *cond, mutex_t *lock, const struct timespec *abstime, const char *file, const char *func, const int line)
{
    int ret;

    ret = pthread_cond_timedwait(cond, &lock->mutex, abstime);
    lock->file = file;
    lock->func = func;
    lock->line = line;
    return ret;
}

#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
int mutex_timedlock_(mutex_t *lock, int timeout, const char *file, const char *func, const int line)
{
    tv_t now;
    ts_t abs;
    int ret;

    tv_time(&now);
    tv_to_ts(&abs, &now);
    abs.tv_sec += timeout;

    ret = pthread_mutex_timedlock(&lock->mutex, &abs);
    if (!ret) {
        lock->file = file;
        lock->func = func;
        lock->line = line;
    }

    return ret;
}
#endif

/* On platforms that have pthread_mutex_timedlock:
 *   Make every locking attempt warn if we're unable to get the lock for more
 *   than 10 seconds and fail if we can't get it for longer than a minute.
 * On other platforms: Just lock the mutex and quit app if error.
 */
void mutex_lock_(mutex_t *lock, const char *file, const char *func, const int line)
{
    int ret, retries = 0;

retry:
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
    ret = mutex_timedlock_(lock, 10, file, func, line);
#else
    ret = pthread_mutex_lock(&lock->mutex);
#endif
    if (unlikely(ret)) {
        if (likely(ret == ETIMEDOUT)) {
            LOGERR("WARNING: Prolonged mutex lock contention from %s %s:%d, held by %s %s:%d",
                   file, func, line, lock->file, lock->func, lock->line);
            if (++retries < 6)
                goto retry;
            quitfrom(1, file, func, line, "FAILED TO GRAB MUTEX!");
        }
        quitfrom(1, file, func, line, "MUTEX ERROR %d ON LOCK 0x%p: (%s)", ret, (void *)&lock->mutex, strerror(ret));
    }
}

/* Does not unset lock->file/func/line since they're only relevant when the lock is held */
void mutex_unlock_(mutex_t *lock, const char *file, const char *func, const int line)
{
    if (unlikely(pthread_mutex_unlock(&lock->mutex)))
        quitfrom(1, file, func, line, "WTF MUTEX ERROR ON UNLOCK!");
}

int mutex_trylock_(mutex_t *lock, maybe_unused__ const char *file, maybe_unused__ const char *func, maybe_unused__ const int line)
{
    int ret;

    ret = pthread_mutex_trylock(&lock->mutex);
    if (!ret) {
        lock->file = file;
        lock->func = func;
        lock->line = line;
    }
    return ret;
}

void mutex_destroy(mutex_t *lock)
{
    pthread_mutex_destroy(&lock->mutex);
}


#if HAVE_PTHREAD_RWLOCK_TIMEDWRLOCK
static int wr_timedlock(pthread_rwlock_t *lock, int timeout)
{
    tv_t now;
    ts_t abs;
    int ret;

    tv_time(&now);
    tv_to_ts(&abs, &now);
    abs.tv_sec += timeout;

    ret = pthread_rwlock_timedwrlock(lock, &abs);

    return ret;
}
#endif

void wr_lock_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    int ret, retries = 0;

retry:
#if HAVE_PTHREAD_RWLOCK_TIMEDWRLOCK
    ret = wr_timedlock(&lock->rwlock, 10);
#else
    ret = pthread_rwlock_wrlock(&lock->rwlock);
#endif
    if (unlikely(ret)) {
        if (likely(ret == ETIMEDOUT)) {
            LOGERR("WARNING: Prolonged write lock contention from %s %s:%d, held by %s %s:%d",
                   file, func, line, lock->file, lock->func, lock->line);
            if (++retries < 6)
                goto retry;
            quitfrom(1, file, func, line, "FAILED TO GRAB WRITE LOCK!");
        }
        quitfrom(1, file, func, line, "WTF ERROR ON WRITE LOCK!");
    }
    lock->file = file;
    lock->func = func;
    lock->line = line;
}

int wr_trylock_(rwlock_t *lock, maybe_unused__ const char *file, maybe_unused__ const char *func, maybe_unused__ const int line)
{
    int ret = pthread_rwlock_trywrlock(&lock->rwlock);

    if (!ret) {
        lock->file = file;
        lock->func = func;
        lock->line = line;
    }
    return ret;
}

#if HAVE_PTHREAD_RWLOCK_TIMEDRDLOCK
static int rd_timedlock(pthread_rwlock_t *lock, int timeout)
{
    tv_t now;
    ts_t abs;
    int ret;

    tv_time(&now);
    tv_to_ts(&abs, &now);
    abs.tv_sec += timeout;

    ret = pthread_rwlock_timedrdlock(lock, &abs);

    return ret;
}
#endif

void rd_lock_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    int ret, retries = 0;

retry:
#if HAVE_PTHREAD_RWLOCK_TIMEDRDLOCK
    ret = rd_timedlock(&lock->rwlock, 10);
#else
    ret = pthread_rwlock_rdlock(&lock->rwlock);
#endif
    if (unlikely(ret)) {
        if (likely(ret == ETIMEDOUT)) {
            LOGERR("WARNING: Prolonged read lock contention from %s %s:%d, held by %s %s:%d",
                   file, func, line, lock->file, lock->func, lock->line);
            if (++retries < 6)
                goto retry;
            quitfrom(1, file, func, line, "FAILED TO GRAB READ LOCK!");
        }
        quitfrom(1, file, func, line, "WTF ERROR ON READ LOCK!");
    }
    lock->file = file;
    lock->func = func;
    lock->line = line;
}

void rw_unlock_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    if (unlikely(pthread_rwlock_unlock(&lock->rwlock)))
        quitfrom(1, file, func, line, "WTF RWLOCK ERROR ON UNLOCK!");
}

void rd_unlock_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    rw_unlock_(lock, file, func, line);
}

void wr_unlock_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    rw_unlock_(lock, file, func, line);
}

void mutex_init_(mutex_t *lock, const char *file, const char *func, const int line)
{
    if (unlikely(pthread_mutex_init(&lock->mutex, NULL)))
        quitfrom(1, file, func, line, "Failed to pthread_mutex_init");
}

void rwlock_init_(rwlock_t *lock, const char *file, const char *func, const int line)
{
    if (unlikely(pthread_rwlock_init(&lock->rwlock, NULL)))
        quitfrom(1, file, func, line, "Failed to pthread_rwlock_init");
}


void cond_init_(pthread_cond_t *cond, const char *file, const char *func, const int line)
{
    if (unlikely(pthread_cond_init(cond, NULL)))
        quitfrom(1, file, func, line, "Failed to pthread_cond_init!");
}

void cklock_init_(cklock_t *lock, const char *file, const char *func, const int line)
{
    mutex_init_(&lock->mutex, file, func, line);
    rwlock_init_(&lock->rwlock, file, func, line);
}


/* Read lock variant of cklock. Cannot be promoted. */
void ck_rlock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    mutex_lock_(&lock->mutex, file, func, line);
    rd_lock_(&lock->rwlock, file, func, line);
    mutex_unlock_(&lock->mutex, file, func, line);
}

/* Write lock variant of cklock */
void ck_wlock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    mutex_lock_(&lock->mutex, file, func, line);
    wr_lock_(&lock->rwlock, file, func, line);
}

/* Downgrade write variant to a read lock */
void ck_dwlock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    wr_unlock_(&lock->rwlock, file, func, line);
    rd_lock_(&lock->rwlock, file, func, line);
    mutex_unlock_(&lock->mutex, file, func, line);
}

/* Demote a write variant to an intermediate variant */
void ck_dwilock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    wr_unlock_(&lock->rwlock, file, func, line);
}

void ck_runlock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    rd_unlock_(&lock->rwlock, file, func, line);
}

void ck_wunlock_(cklock_t *lock, const char *file, const char *func, const int line)
{
    wr_unlock_(&lock->rwlock, file, func, line);
    mutex_unlock_(&lock->mutex, file, func, line);
}

void cklock_destroy(cklock_t *lock)
{
    pthread_rwlock_destroy(&lock->rwlock.rwlock);
    pthread_mutex_destroy(&lock->mutex.mutex);
}

bool extract_zmq_proto_port(const char *z, char **proto, char **port, char **middle)
{
    const char *slashes = strstr(z, "//");
    if (!slashes)
        return false;
    const char *middle_start = slashes + 2;
    const char *prt = strrchr(middle_start, ':');
    if (!prt || prt - slashes <= 2 || !*++prt)
        prt = ""; // return empty port if not ':'
    int protolen = slashes - z;
    if (protolen > 0 && z[protolen-1] == ':')
        --protolen;
    *proto = ckstrndup(z, protolen);
    if (strcasecmp(*proto, "ipc") == 0)
        prt = ""; // IPC never has a port.
    *port = ckstrdup(prt);
    if (middle) {
        int middle_len = strlen(middle_start) - strlen(prt);
        while (middle_len && middle_start[middle_len-1] == ':')
            --middle_len; // trim trailing ':' character
        *middle = ckstrndup(middle_start, middle_len);
    }
    //LOGDEBUG("PARSED PROTO \"%s\" PORT \"%s\" MIDDLE \"%s\" from \"%s\"", *proto, *port, middle ? *middle : "", z);
    return true;
}

/* Extract just the url and port information from a url string, allocating
 * heap memory for sockaddr_url and sockaddr_port. */
bool extract_sockaddr(const char *url, char **sockaddr_url, char **sockaddr_port)
{
    const char *url_begin, *url_end, *ipv6_begin, *ipv6_end, *port_start = NULL;
    char *url_address, *port, *tmp;
    int url_len, port_len = 0;
    size_t hlen;

    if (!url) {
        LOGWARNING("Null length url string passed to extract_sockaddr");
        return false;
    }
    url_begin = strstr(url, "//");
    if (!url_begin)
        url_begin = url;
    else
        url_begin += 2;

    /* Look for numeric ipv6 entries */
    ipv6_begin = strstr(url_begin, "[");
    ipv6_end = strstr(url_begin, "]");
    if (ipv6_begin && ipv6_end && ipv6_end > ipv6_begin)
        url_end = strstr(ipv6_end, ":");
    else
        url_end = strstr(url_begin, ":");
    if (url_end) {
        url_len = url_end - url_begin;
        port_len = strlen(url_begin) - url_len - 1;
        if (port_len < 1)
            return false;
        port_start = url_end + 1;
    } else
        url_len = strlen(url_begin);

    /* Get rid of the [] */
    if (ipv6_begin && ipv6_end && ipv6_end > ipv6_begin){
        url_len -= 2;
        url_begin++;
    }

    if (url_len < 1) {
        LOGWARNING("Null length URL passed to extract_sockaddr");
        return false;
    }

    hlen = url_len + 1;
    url_address = ckalloc(hlen);
    sprintf(url_address, "%.*s", url_len, url_begin);

    port = ckalloc(8);
    if (port_len) {
        char *slash;

        snprintf(port, 6, "%.*s", port_len, port_start);
        slash = strchr(port, '/');
        if (slash)
            *slash = '\0';
    } else
        strcpy(port, "80");

    /*
     * This function may be called with sockaddr_* already set as it may
     * be getting updated so we need to free the old entries safely.
     * Use a temporary variable so they never dereference */
    if (*sockaddr_port && !safecmp(*sockaddr_port, port))
        free(port);
    else {
        tmp = *sockaddr_port;
        *sockaddr_port = port;
        free(tmp);
    }
    if (*sockaddr_url && !safecmp(*sockaddr_url, url_address))
        free(url_address);
    else {
        tmp = *sockaddr_url;
        *sockaddr_url = url_address;
        free(tmp);
    }

    return true;
}

/* Convert a sockaddr structure into a url and port. URL should be a string of
 * INET6_ADDRSTRLEN size, port at least a string of 6 bytes */
bool url_from_sockaddr(const struct sockaddr *addr, char *url, char *port)
{
    int port_no = 0;

    switch(addr->sa_family) {
        const struct sockaddr_in *inet4_in;
        const struct sockaddr_in6 *inet6_in;

        case AF_INET:
            inet4_in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &inet4_in->sin_addr, url, INET6_ADDRSTRLEN);
            port_no = htons(inet4_in->sin_port);
            break;
        case AF_INET6:
            inet6_in = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &inet6_in->sin6_addr, url, INET6_ADDRSTRLEN);
            port_no = htons(inet6_in->sin6_port);
            break;
        default:
            return false;
    }
    sprintf(port, "%d", port_no);
    return true;
}

/* Helper for getaddrinfo with the same API that retries while getting
 * EAI_AGAIN error */
static int addrgetinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res)
{
    int ret;

    do {
        ret = getaddrinfo(node, service, hints, res);
    } while (ret == EAI_AGAIN);

    return ret;
}


bool addrinfo_from_url(const char *url, const char *port, struct addrinfo *addrinfo)
{
    struct addrinfo *servinfo, hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    servinfo = addrinfo;
    if (addrgetinfo(url, port, &hints, &servinfo) != 0)
        return false;
    if (!servinfo)
        return false;
    memcpy(addrinfo, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    return true;
}

/* Extract a resolved url and port from a serverurl string. newurl must be
 * a string of at least INET6_ADDRSTRLEN and newport at least 6 bytes. */
bool url_from_serverurl(char *serverurl, char *newurl, char *newport)
{
    char *url = NULL, *port = NULL;
    struct addrinfo addrinfo;
    bool ret = false;

    if (!extract_sockaddr(serverurl, &url, &port)) {
        LOGWARNING("Failed to extract server address from %s", serverurl);
        goto out;
    }
    if (!addrinfo_from_url(url, port, &addrinfo)) {
        LOGWARNING("Failed to extract addrinfo from url %s:%s", url, port);
        goto out;
    }
    if (!url_from_sockaddr((const struct sockaddr *)&addrinfo, newurl, newport)) {
        LOGWARNING("Failed to extract url from sockaddr for original url: %s:%s",
               url, port);
        goto out;
    }
    ret = true;
out:
    dealloc(url);
    dealloc(port);
    return ret;
}

/* Convert a socket into a url and port. URL should be a string of
 * INET6_ADDRSTRLEN size, port at least a string of 6 bytes */
bool url_from_socket(const int sockd, char *url, char *port)
{
    struct sockaddr_storage storage;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    struct sockaddr *addr = (struct sockaddr *)&storage;

    if (sockd < 1)
        return false;
    if (getsockname(sockd, addr, &addrlen))
        return false;
    if (!url_from_sockaddr(addr, url, port))
        return false;
    return true;
}


void keep_sockalive(int fd)
{
    const int tcp_one = 1;
    const int tcp_keepidle maybe_unused__ = 45;
    const int tcp_keepintvl = 30;
#ifndef SOL_TCP
    const int SOL_TCP = 6; /* IANA protocol number */
#endif
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const void *)&tcp_one, sizeof(tcp_one));
    setsockopt(fd, SOL_TCP, TCP_NODELAY, (const void *)&tcp_one, sizeof(tcp_one));
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &tcp_one, sizeof(tcp_one));
#ifdef TCP_KEEPIDLE
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle));
#endif
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl));
}

void nolinger_socket(int fd)
{
    const struct linger so_linger = { 1, 0 };

    setsockopt(fd, SOL_SOCKET, SO_LINGER, &so_linger, sizeof(so_linger));
}

void noblock_socket(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    fcntl(fd, F_SETFL, O_NONBLOCK | flags);
}

void block_socket(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

void close_helper(int *fd, const char *file, const char *func, const int line)
{
    int sockd;

    if (*fd < 0)
        return;
    sockd = *fd;
    LOGDEBUG("Closing file handle %d", sockd);
    *fd = -1;
    if (unlikely(close(sockd))) {
        LOGWARNING("Close of fd %d failed with errno %d:%s from %s %s:%d",
                   sockd, errno, strerror(errno), file, func, line);
    }
}

int bind_socket(char *url, char *port)
{
    struct addrinfo servinfobase, *servinfo, hints, *p;
    int ret, sockd = -1;
    const int on = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    servinfo = &servinfobase;

    if (addrgetinfo(url, port, &hints, &servinfo) != 0) {
        LOGWARNING("Failed to resolve (?wrong URL) %s:%s", url, port);
        return sockd;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockd > 0)
            break;
    }
    if (sockd < 1 || p == NULL) {
        LOGWARNING("Failed to open socket for %s:%s", url, port);
        goto out;
    }
    setsockopt(sockd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    ret = bind(sockd, p->ai_addr, p->ai_addrlen);
    if (ret < 0) {
        LOGWARNING("Failed to bind socket for %s:%s", url, port);
        Close(sockd);
        goto out;
    }

out:
    freeaddrinfo(servinfo);
    return sockd;
}

int connect_socket(char *url, char *port)
{
    struct addrinfo servinfobase, *servinfo, hints, *p;
    int sockd = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    memset(&servinfobase, 0, sizeof(struct addrinfo));
    servinfo = &servinfobase;

    if (addrgetinfo(url, port, &hints, &servinfo) != 0) {
        LOGWARNING("Failed to resolve (?wrong URL) %s:%s", url, port);
        goto out;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockd == -1) {
            LOGDEBUG("Failed socket");
            continue;
        }

        /* Iterate non blocking over entries returned by getaddrinfo
         * to cope with round robin DNS entries, finding the first one
         * we can connect to quickly. */
        noblock_socket(sockd);
        if (connect(sockd, p->ai_addr, p->ai_addrlen) == -1) {
            int selret;

            if (!sock_connecting()) {
                Close(sockd);
                LOGDEBUG("Failed sock connect");
                continue;
            }
            selret = wait_write_select(sockd, 5);
            if  (selret > 0) {
                socklen_t len;
                int err, n;

                len = sizeof(err);
                n = getsockopt(sockd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
                if (!n && !err) {
                    LOGDEBUG("Succeeded delayed connect");
                    block_socket(sockd);
                    break;
                }
            }
            Close(sockd);
            LOGDEBUG("Select timeout/failed connect");
            continue;
        }
        LOGDEBUG("Succeeded immediate connect");
        if (sockd >= 0)
            block_socket(sockd);

        break;
    }
    if (p == NULL) {
        LOGNOTICE("Failed to connect to %s:%s", url, port);
        sockd = -1;
    }
    freeaddrinfo(servinfo);
out:
    return sockd;
}

/* Measure the minimum round trip time it should take to get to a url by attempting
 * to connect to what should be a closed socket on port 1042. This is a blocking
 * function so can take many seconds. Returns 0 on failure */
int round_trip(char *url)
{
    struct addrinfo servinfobase, *p, hints;
    int sockd = -1, ret = 0, i, diff;
    tv_t start_tv, end_tv;
    char port[] = "1042";

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    memset(&servinfobase, 0, sizeof(struct addrinfo));
    p = &servinfobase;

    if (addrgetinfo(url, port, &hints, &p) != 0) {
        LOGWARNING("Failed to resolve (?wrong URL) %s:%s", url, port);
        return ret;
    }
    /* This function should be called only on already-resolved IP addresses so
     * we only need to use the first result from servinfobase */
    sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockd == -1) {
        LOGERR("Failed socket");
        goto out;
    }
    /* Attempt to connect 5 times to what should be a closed port and measure
     * the time it takes to get a refused message */
    for (i = 0; i < 5; i++) {
        tv_time(&start_tv);
        if (!connect(sockd, p->ai_addr, p->ai_addrlen) || errno != ECONNREFUSED) {
            LOGINFO("Unable to get round trip due to %s:%s connect not being refused",
                url, port);
            goto out;
        }
        tv_time(&end_tv);
        diff = ms_tvdiff(&end_tv, &start_tv);
        if (!ret || diff < ret)
            ret = diff;
    }
    if (ret > 500) {
        LOGINFO("Round trip to %s:%s greater than 500ms at %d, clamping to 500", url, port, diff);
        ret = 500;
    }
    LOGINFO("Minimum round trip to %s:%s calculated as %dms", url, port, ret);
out:
    Close(sockd);
    freeaddrinfo(p);
    return ret;
}

int write_socket(int fd, const void *buf, size_t nbyte)
{
    int ret;

    ret = wait_write_select(fd, 5);
    if (ret < 1) {
        if (!ret)
            LOGNOTICE("Select timed out in write_socket");
        else
            LOGNOTICE("Select failed in write_socket");
        goto out;
    }
    ret = write_length(fd, buf, nbyte);
    if (ret < 0)
        LOGNOTICE("Failed to write in write_socket");
out:
    return ret;
}

void empty_socket(int fd)
{
    char buf[512];
    int ret;

    if (fd < 1)
        return;

    do {
        ret = recv(fd, buf, 511, MSG_DONTWAIT);
        if (ret > 0) {
            buf[ret] = 0;
            LOGDEBUG("Discarding: %s", buf);
        }
    } while (ret > 0);
}

void close_unix_socket_(int *sockd, const char *server_path)
{
    LOGDEBUG("Closing unix socket %d %s", *sockd, server_path);
    Close_(sockd);
}

int open_unix_server_(const char *server_path, const char *file, const char *func, const int line)
{
    mode_t mode = S_IRWXU | S_IRWXG; // Owner+Group RWX
    struct sockaddr_un serveraddr;
    int sockd = -1, len, ret;
    struct stat buf;

    if (likely(server_path)) {
        len = strlen(server_path);
        if (unlikely(len < 1 || len >= UNIX_PATH_MAX)) {
            LOGERR("Invalid server path length %d in open_unix_server", len);
            goto out;
        }
    } else {
        LOGERR("Null passed as server_path to open_unix_server");
        goto out;
    }

    if (!stat(server_path, &buf)) {
        if ((buf.st_mode & S_IFMT) == S_IFSOCK) {
            ret = unlink(server_path);
            if (ret) {
                LOGERR("Unlink of %s failed in open_unix_server", server_path);
                goto out;
            }
            LOGDEBUG("Unlinked %s to recreate socket", server_path);
        } else {
            LOGWARNING("%s already exists and is not a socket, not removing",
                   server_path);
            goto out;
        }
    }

    sockd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unlikely(sockd < 0)) {
        LOGERR("Failed to open socket in open_unix_server");
        goto out;
    }
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, server_path);

    ret = bind(sockd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (unlikely(ret < 0)) {
        LOGERR("Failed to bind to socket in open_unix_server");
        close_unix_socket(sockd, server_path);
        sockd = -1;
        goto out;
    }

    ret = chmod(server_path, mode);
    if (unlikely(ret < 0))
        LOGERR("Failed to set mode in open_unix_server - continuing");

    ret = listen(sockd, SOMAXCONN);
    if (unlikely(ret < 0)) {
        LOGERR("Failed to listen to socket in open_unix_server");
        close_unix_socket(sockd, server_path);
        sockd = -1;
        goto out;
    }

    LOGDEBUG("Opened server path %s successfully on socket %d", server_path, sockd);
out:
    if (unlikely(sockd == -1))
        LOGERR("Failure in open_unix_server from %s %s:%d", file, func, line);
    return sockd;
}

int open_unix_client_(const char *server_path, const char *file, const char *func, const int line)
{
    struct sockaddr_un serveraddr;
    int sockd = -1, len, ret;

    if (likely(server_path)) {
        len = strlen(server_path);
        if (unlikely(len < 1 || len >= UNIX_PATH_MAX)) {
            LOGERR("Invalid server path length %d in open_unix_client", len);
            goto out;
        }
    } else {
        LOGERR("Null passed as server_path to open_unix_client");
        goto out;
    }

    sockd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unlikely(sockd < 0)) {
        LOGERR("Failed to open socket in open_unix_client");
        goto out;
    }
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strcpy(serveraddr.sun_path, server_path);

    ret = connect(sockd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (unlikely(ret < 0)) {
        LOGERR("Failed to bind to socket in open_unix_client");
        Close(sockd);
        goto out;
    }

    LOGDEBUG("Opened client path %s successfully on socket %d", server_path, sockd);
out:
    if (unlikely(sockd == -1))
        LOGERR("Failure in open_unix_client from %s %s:%d", file, func, line);
    return sockd;
}

int read_length(int sockd, void *vbuf, int len)
{
    char *buf = (char *)vbuf;
    int ret, ofs = 0;

    if (unlikely(len < 1)) {
        LOGWARNING("Invalid read length of %d requested in read_length", len);
        return -1;
    }
    if (unlikely(sockd < 0))
        return -1;
    while (len) {
        ret = recv(sockd, buf + ofs, len, MSG_WAITALL);
        if (unlikely(ret < 1))
            return -1;
        ofs += ret;
        len -= ret;
    }
    return ofs;
}

/* Use a standard message across the unix sockets:
 * 4 byte length of message as little endian encoded uint32_t followed by the
 * string. Return NULL in case of failure. */
char *recv_unix_msg_(int sockd, int timeout1, int timeout2, const char *file, const char *func, const int line)
{
    char *buf = NULL;
    uint32_t msglen;
    int ret, ern;

    ret = wait_read_select(sockd, timeout1);
    if (unlikely(ret < 1)) {
        ern = errno;
        LOGERR("Select1 failed in recv_unix_msg (%d)", ern);
        goto out;
    }
    /* Get message length */
    ret = read_length(sockd, &msglen, 4);
    if (unlikely(ret < 4)) {
        ern = errno;
        LOGERR("Failed to read 4 byte length in recv_unix_msg (%d?)", ern);
        goto out;
    }
    msglen = le32toh(msglen);
    if (unlikely(msglen < 1 || msglen > 0x80000000)) {
        LOGWARNING("Invalid message length %u sent to recv_unix_msg", msglen);
        goto out;
    }
    ret = wait_read_select(sockd, timeout2);
    if (unlikely(ret < 1)) {
        ern = errno;
        LOGERR("Select2 failed in recv_unix_msg (%d)", ern);
        goto out;
    }
    buf = ckzalloc(msglen + 1);
    ret = read_length(sockd, buf, msglen);
    if (unlikely(ret < (int)msglen)) {
        ern = errno;
        LOGERR("Failed to read %u bytes in recv_unix_msg (%d?)", msglen, ern);
        dealloc(buf);
    }
out:
    shutdown(sockd, SHUT_RD);
    if (unlikely(!buf))
        LOGERR("Failure in recv_unix_msg from %s %s:%d", file, func, line);
    return buf;
}

int write_length_(int sockd, const void *vbuf, int len, const char *file, const char *func, const int line)
{
    const char * const buf = (const char *)vbuf;
    int ret, ofs = 0, ern;

    if (unlikely(len < 1)) {
        LOGWARNING("Invalid write length of %d requested in write_length from %s %s:%d",
                   len, file, func, line);
        return -1;
    }
    if (unlikely(sockd < 0)) {
        LOGWARNING("Attempt to write to invalidated sock in write_length from %s %s:%d",
                   file, func, line);
        return -1;
    }
    while (len) {
        ret = write(sockd, buf + ofs, len);
        if (unlikely(ret < 0)) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            ern = errno;
            LOGERR("Failed to write %d bytes in write_length (%d) from %s %s:%d",
                   len, ern, file, func, line);
            return -1;
        }
        ofs += ret;
        len -= ret;
    }
    return ofs;
}

bool send_unix_msg_(int sockd, const char *buf, int timeout, const char *file, const char *func, const int line)
{
    uint32_t msglen, len;
    bool retval = false;
    int ret, ern;

    if (unlikely(sockd < 0)) {
        LOGWARNING("Attempting to send unix message to invalidated sockd %d", sockd);
        goto out;
    }
    if (unlikely(!buf)) {
        LOGWARNING("Null message sent to send_unix_msg");
        goto out;
    }
    len = strlen(buf);
    if (unlikely(!len)) {
        LOGWARNING("Zero length message sent to send_unix_msg");
        goto out;
    }
    msglen = htole32(len);
    ret = wait_write_select(sockd, timeout);
    if (unlikely(ret < 1)) {
        ern = errno;
        LOGERR("Select1 failed in send_unix_msg (%d)", ern);
        goto out;
    }
    ret = write_length_(sockd, &msglen, 4, file, func, line);
    if (unlikely(ret < 4)) {
        LOGERR("Failed to write 4 byte length in send_unix_msg");
        goto out;
    }
    ret = wait_write_select(sockd, timeout);
    if (unlikely(ret < 1)) {
        ern = errno;
        LOGERR("Select2 failed in send_unix_msg (%d)", ern);
        goto out;
    }
    ret = write_length_(sockd, buf, len, file, func, line);
    if (unlikely(ret < 0)) {
        LOGERR("Failed to write %d bytes in send_unix_msg", len);
        goto out;
    }
    retval = true;
out:
    shutdown(sockd, SHUT_WR);
    if (unlikely(!retval))
        LOGERR("Failure in send_unix_msg from %s %s:%d", file, func, line);
    return retval;
}

bool send_unix_data_(int sockd, const struct msghdr *msg, const char *file, const char *func, const int line)
{
    bool retval = false;
    int ret;

    if (unlikely(!msg)) {
        LOGWARNING("Null message sent to send_unix_data");
        goto out;
    }
    ret = wait_write_select(sockd, UNIX_WRITE_TIMEOUT);
    if (unlikely(ret < 1)) {
        LOGERR("Select1 failed in send_unix_data");
        goto out;
    }
    ret = sendmsg(sockd, msg, 0);
    if (unlikely(ret < 1)) {
        LOGERR("Failed to send in send_unix_data");
        goto out;
    }
    retval = true;
out:
    shutdown(sockd, SHUT_WR);
    if (unlikely(!retval))
        LOGERR("Failure in send_unix_data from %s %s:%d", file, func, line);
    return retval;
}

bool recv_unix_data_(int sockd, struct msghdr *msg, const char *file, const char *func, const int line)
{
    bool retval = false;
    int ret;

    ret = wait_read_select(sockd, UNIX_READ_TIMEOUT);
    if (unlikely(ret < 1)) {
        LOGERR("Select1 failed in recv_unix_data");
        goto out;
    }
    ret = recvmsg(sockd, msg, MSG_WAITALL);
    if (unlikely(ret < 0)) {
        LOGERR("Failed to recv in recv_unix_data");
        goto out;
    }
    retval = true;
out:
    shutdown(sockd, SHUT_RD);
    if (unlikely(!retval))
        LOGERR("Failure in recv_unix_data from %s %s:%d", file, func, line);
    return retval;
}

#define CONTROLLLEN CMSG_LEN(sizeof(int))
#define MAXLINE 4096

/* Send a msghdr containing fd via the unix socket sockd */
bool send_fd_(int fd, int sockd, const char *file, const char *func, const int line)
{
    struct cmsghdr *cmptr = ckzalloc(CONTROLLLEN);
    struct iovec iov[1];
    struct msghdr msg;
    char buf[2];
    bool ret;
    int *cm;

    memset(&msg, 0, sizeof(struct msghdr));
    iov[0].iov_base = buf;
    iov[0].iov_len = 2;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_controllen = CONTROLLLEN;
    msg.msg_control = cmptr;
    cmptr->cmsg_level = SOL_SOCKET;
    cmptr->cmsg_type = SCM_RIGHTS;
    cmptr->cmsg_len = CONTROLLLEN;
    cm = (int *)CMSG_DATA(cmptr);
    *cm = fd;
    buf[1] = 0;
    buf[0] = 0;
    ret = send_unix_data(sockd, &msg);
    free(cmptr);
    if (!ret)
        LOGERR("Failed to send_unix_data in send_fd from %s %s:%d", file, func, line);
    return ret;
}

/* Receive an fd by reading a msghdr from the unix socket sockd */
int get_fd_(int sockd, const char *file, const char *func, const int line)
{
    int newfd = -1;
    char buf[MAXLINE];
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmptr = ckzalloc(CONTROLLLEN);
    int *cm;

    memset(&msg, 0, sizeof(struct msghdr));
    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);
    msg.msg_iov = iov;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = cmptr;
    msg.msg_controllen = CONTROLLLEN;
    if (!recv_unix_data(sockd, &msg)) {
        LOGERR("Failed to recv_unix_data in get_fd from %s %s:%d", file, func, line);
        goto out;
    }
out:
    cm = (int *)CMSG_DATA(cmptr);
    newfd = *cm;
    free(cmptr);
    return newfd;
}


void json_check_(json_t *val, json_error_t *err, const char *file, const char *func, const int line)
{
    if (likely(val))
        return;

    LOGERR("Invalid json line:%d col:%d pos:%d text: %s from %s %s:%d",
           err->line, err->column, err->position, err->text,
           file, func, line);
}

/* Extracts a string value from a json array with error checking. To be used
 * when the value of the string returned is only examined and not to be stored.
 * See json_array_string below */
const char *json_array_string__(json_t *val, unsigned int entry)
{
    json_t *arr_entry;

    if (json_is_null(val))
        return NULL;
    if (!json_is_array(val))
        return NULL;
    if (entry > json_array_size(val))
        return NULL;
    arr_entry = json_array_get(val, entry);
    if (!json_is_string(arr_entry))
        return NULL;

    return json_string_value(arr_entry);
}

/* Creates a freshly malloced dup of json_array_string__ */
char *json_array_string(json_t *val, unsigned int entry)
{
    const char *buf = json_array_string__(val, entry);

    if (buf)
        return strdup(buf);
    return NULL;
}

json_t *json_object_dup(json_t *val, const char *entry)
{
    return json_copy(json_object_get(val, entry));
}

char *rotating_filename(const char *path, time_t when)
{
    char *filename;
    struct tm tm;

    gmtime_r(&when, &tm);
    ASPRINTF(&filename, "%s%04d%02d%02d%02d.log", path, tm.tm_year + 1900, tm.tm_mon + 1,
         tm.tm_mday, tm.tm_hour);
    return filename;
}

/* Creates a logfile entry which changes filename hourly with exclusive access */
bool rotating_log(const char *path, const char *msg)
{
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    char *filename;
    FILE *fp;
    int fd;
    bool ok = false;

    filename = rotating_filename(path, time(NULL));
    fd = open(filename, O_CREAT | O_RDWR | O_CLOEXEC , mode);
    if (unlikely(fd == -1)) {
        LOGERR("Failed to open %s in rotating_log!", filename);
        goto stageleft;
    }
    fp = fdopen(fd, "ae");
    if (unlikely(!fp)) {
        Close(fd);
        LOGERR("Failed to fdopen %s in rotating_log!", filename);
        goto stageleft;
    }
    if (unlikely(flock(fd, LOCK_EX))) {
        fclose(fp);
        LOGERR("Failed to flock %s in rotating_log!", filename);
        goto stageleft;
    }
    fprintf(fp, "%s\n", msg);
    fclose(fp);
    ok = true;

stageleft:
    free(filename);

    return ok;
}

/* Align a size_t to 4 byte boundaries for fussy arches */
void align_len(size_t *len)
{
    const size_t rem = *len % 4u;
    if (rem) *len += 4u - rem;
}

/* Malloc failure should be fatal but keep backing off and retrying as the OS
 * will kill us eventually if it can't recover. */
void realloc_strcat(char **ptr, const char *s)
{
    size_t old, new, len;
    char *ofs;

    if (unlikely(!*s)) {
        LOGWARNING("Passed empty pointer to realloc_strcat");
        return;
    }
    new = strlen(s);
    if (unlikely(!new)) {
        LOGWARNING("Passed empty string to realloc_strcat");
        return;
    }
    if (!*ptr)
        old = 0;
    else
        old = strlen(*ptr);
    len = old + new + 1;
    *ptr = (char *)ckrealloc(*ptr, len); // always either succeeds or keeps retrying
    ofs = *ptr + old;
    sprintf(ofs, "%s", s);
}

void trail_slash(char **buf)
{
    int ofs;

    ofs = strlen(*buf) - 1;
    if (memcmp(*buf + ofs, "/", 1))
        realloc_strcat(buf, "/");
}

void *json_ckalloc(size_t size)
{
    return ckalloc(size);
}

char *ckstrdup(const char *s)
{
    const int len = strlen(s);
    return ckstrndup(s, len);
}

char *ckstrndup(const char *s, int len)
{
    if (len < 0)
        return NULL;
    char *ret = ckzalloc(len + 1);
    strncpy(ret, s, len);
    ret[len] = 0;
    return ret;
}

void *ckzrealloc_(void *oldbuf, size_t len, bool zeromem, const char *file, const char *func, const int line)
{
    int backoff = 1;
    void *ptr;

    align_len(&len);
    while (1) {
        // NB: old may be NULL, in which case this behaves like malloc()
        ptr = realloc(oldbuf, len);
        if (likely(ptr)) {
            if (zeromem)
                memset(ptr, 0, len);
            return ptr;
        }
        if (backoff == 1) {
            fprintf(stderr, "Failed to alloc %lu bytes, retrying.... (from: %s %s:%d)\n",
                    (unsigned long)len, file, func, line);
        }
        cksleep_ms(backoff);
        backoff <<= 1;
        if (unlikely(backoff <= 0))
            // overflow past end, start over -- this is here for correctness but should never
            // happen in practice as it indicates we have been sleeping for 2 million seconds
            backoff = 1;
    }
}

/* Round up to the nearest page size for efficient malloc */
size_t round_up_page(size_t len)
{
    int rem = len % PAGESIZE;

    if (rem)
        len += PAGESIZE - rem;
    return len;
}

static const char bin2hex_tbl[513] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/* Adequate size s==len*2 + 1 must be alloced to use this variant */
size_t bin2hex__(char *dest, const void *src, const size_t len)
{
    const uchar *p = src;
    const uchar *const end = p + len;
    uint16_t hex_idx;

    while (p < end) {
        hex_idx = ((uint16_t)*p++) * 2u;
        *dest++ = bin2hex_tbl[hex_idx++];
        *dest++ = bin2hex_tbl[hex_idx++];
    }
    *dest++ = '\0';
    return len * 2u;
}

/* Returns a malloced array string of a binary value of arbitrary length. The
 * array is rounded up to a 4 byte size to appease architectures that need
 * aligned array  sizes */
char *bin2hex(const void *bin, const size_t len)
{
    size_t slen;
    char *s;

    slen = len * 2u + 1u;
    s = ckalloc(slen);
    bin2hex__(s, bin, len);

    return s;
}

static const int8_t hex2bin_tbl[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

bool validhex__(const char *buf, const char *file, const char *func, const int line)
{
    size_t i, slen;
    bool ret = false;

    slen = strlen(buf);
    if (!slen || slen % 2u) {
        LOGDEBUG("Invalid hex due to length %lu from %s %s:%d", (unsigned long)slen, file, func, line);
        goto out;
    }
    for (i = 0u; i < slen; ++i) {
        const uchar idx = (uchar)buf[i];

        if (hex2bin_tbl[idx] < 0) {
            LOGDEBUG("Invalid hex due to value %u at offset %lu from %s %s:%d", (unsigned)idx, (unsigned long)i, file, func, line);
            goto out;
        }
    }
    ret = true;
out:
    return ret;
}

/* Does the reverse of bin2hex but does not allocate any ram */
bool hex2bin__(void *dest, const char *hexstr, size_t len, const char *file, const char *func, const int line)
{
    const uchar *ustr = (const uchar *)hexstr;
    int8_t nibble1, nibble2;
    bool ret = false;
    uchar *p = dest;

    while (*ustr && len) {
        if (unlikely(!ustr[1])) {
            LOGWARNING("Early end of string in hex2bin from %s %s:%d", file, func, line);
            return ret;
        }

        nibble1 = hex2bin_tbl[*ustr++];
        nibble2 = hex2bin_tbl[*ustr++];

        if (unlikely((nibble1 < 0) || (nibble2 < 0))) {
            LOGWARNING("Invalid binary encoding in hex2bin from %s %s:%d", file, func, line);
            return ret;
        }

        *p++ = (((uchar)nibble1) << 4) | ((uchar)nibble2);
        --len;
    }

    if (likely(len == 0 && *ustr == 0))
        ret = true;
    if (!ret)
        LOGWARNING("Failed hex2bin decode from %s %s:%d", file, func, line);
    return ret;
}

static const int b58tobin_tbl[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57
};

/* b58bin should always be at least 25 bytes long and already checked to be
 * valid.  Does no checksum checks but returns false if the characters in b58 source are invalid,
 * or if b58 is > 35 characters, true otherwise. */
bool b58tobin_safe(uchar *b58bin, const char *b58)
{
    uint32_t c, bin32[7];
    int len, i, j;
    uint64_t t;
    static const int tbl_len = sizeof(b58tobin_tbl) / sizeof(*b58tobin_tbl);

    memset(bin32, 0, 7 * sizeof(uint32_t));
    len = strlen((const char *)b58);
    if (len > CASHADDR_HEURISTIC_LEN)
        return false;
    for (i = 0; i < len; i++) {
        int32_t c_tmp = b58[i];
        if (c_tmp < 0 || c_tmp >= tbl_len)
            return false;
        c_tmp = b58tobin_tbl[c_tmp];
        if (c_tmp < 0)
            return false;
        c = (uint32_t)c_tmp;
        for (j = 6; j >= 0; j--) {
            t = ((uint64_t)bin32[j]) * 58 + c;
            c = (t & 0x3f00000000ull) >> 32;
            bin32[j] = t & 0xffffffffull;
        }
    }
    *(b58bin++) = bin32[0] & 0xff;
    for (i = 1; i < 7; i++) {
        write_i32(b58bin, htobe32(bin32[i]));
        b58bin += sizeof(uint32_t);
    }
    return true;
}

/* Does a safe string comparison tolerating zero length and NULL strings */
int safecmp(const char *a, const char *b)
{
    int lena, lenb;

    if (unlikely(!a || !b)) {
        if (a != b)
            return -1;
        return 0;
    }
    lena = strlen(a);
    lenb = strlen(b);
    if (unlikely(!lena || !lenb)) {
        if (lena != lenb)
            return -1;
        return 0;
    }
    return (strcmp(a, b));
}

/* Does a safe strcasecmp or strncasecmp comparison tolerating zero length and NULL strings.
   Pass len < 0 to compare all, or len >= 0 to compare first len bytes. */
int safecasecmp(const char *a, const char *b, int len)
{
    int lena, lenb;

    if (unlikely(!a || !b)) {
        if (a != b)
            return -1;
        return 0;
    }
    lena = strlen(a);
    lenb = strlen(b);
    if (unlikely(!lena || !lenb)) {
        if (lena != lenb)
            return -1;
        return 0;
    }
    if (len < 0) {
        return strcasecmp(a, b);
    } else {
        return strncasecmp(a, b, len);
    }
}

/* Returns whether there is a case insensitive match of buf to cmd, safely
 * handling NULL or zero length strings. */
bool cmdmatch(const char *buf, const char *cmd)
{
    int cmdlen, buflen;

    if (!buf)
        return false;
    buflen = strlen(buf);
    if (!buflen)
        return false;
    cmdlen = strlen(cmd);
    if (buflen < cmdlen)
        return false;
    return !strncasecmp(buf, cmd, cmdlen);
}


static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Return a malloced string of *src encoded into mime base 64 */
char *http_base64(const char *src_c)
{
    char *str, *dst;
    const uchar *src = (const uchar *)src_c;
    size_t l, hlen;
    uint32_t t;

    l = strlen(src_c);
    hlen = ((l + 2u) / 3u) * 4u + 1u;
    dst = str = ckalloc(hlen);

    while (l >= 3) {
        t = (src[0] << 16u) | (src[1] << 8u) | src[2];
        dst[0] = base64[(t >> 18u) & 0x3fu];
        dst[1] = base64[(t >> 12u) & 0x3fu];
        dst[2] = base64[(t >>  6u) & 0x3fu];
        dst[3] = base64[(t >>  0u) & 0x3fu];
        src += 3u; l -= 3u;
        dst += 4u;
    }

    switch (l) {
        case 2u:
            t = (src[0] << 16u) | (src[1] << 8u);
            dst[0] = base64[(t >> 18u) & 0x3fu];
            dst[1] = base64[(t >> 12u) & 0x3fu];
            dst[2] = base64[(t >>  6u) & 0x3fu];
            dst[3] = '=';
            dst += 4;
            break;
        case 1u:
            t = src[0] << 16;
            dst[0] = base64[(t >> 18u) & 0x3fu];
            dst[1] = base64[(t >> 12u) & 0x3fu];
            dst[2] = dst[3] = '=';
            dst += 4;
            break;
        case 0u:
            break;
    }
    *dst = 0;
    return str;
}

static const char *remove_any_cashaddr_prefix(const char *addr)
{
    const char *ret = addr;
    static const char *prefixes[] = {"bitcoincash:", "bchtest:", "bchreg:"};
    static const int N = sizeof(prefixes)/sizeof(*prefixes);
    int i;

    for (i = 0; i < N; ++i) {
        const char *prefix = prefixes[i];
        const int plen = strlen(prefix);
        if (safecasecmp(prefix, addr, plen) == 0) {
            ret = &addr[plen];
            break;
        }
    }
    return ret;
}

static int p2pkh_address_to_script(uchar *pkh, const char *addr, const char *cashaddr_prefix)
{
    uchar b58bin[25] = {0};
    bool decoded_cashaddr = false;

    if (strlen(addr) > CASHADDR_HEURISTIC_LEN) {
        // address is long -- try parsing it as a cashaddr
        uint8_t *h160 = cashaddr_decode_hash160(addr, cashaddr_prefix);
        if (h160) {
            memcpy(&b58bin[1], h160, 20); // hack -- we only care about the hash 160 anyway
            free(h160);
            decoded_cashaddr = true;
        }
    }

    if (!decoded_cashaddr) {
        addr = remove_any_cashaddr_prefix(addr);

        if (!b58tobin_safe(b58bin, addr)) {
            LOGWARNING("Could not decode address '%s'!", addr);
            return 0;
        }
    }
    pkh[0] = 0x76;
    pkh[1] = 0xa9;
    pkh[2] = 0x14;
    memcpy(&pkh[3], &b58bin[1], 20); // this hash160 may have come either from cashaddr or base58 decoding above
    pkh[23] = 0x88;
    pkh[24] = 0xac;
    return 25;
}

static int p2sh_address_to_script(uchar *psh, const char *addr, const char *cashaddr_prefix)
{
    uchar b58bin[25] = {0};
    bool decoded_cashaddr = false;

    if (strlen(addr) > CASHADDR_HEURISTIC_LEN) {
        // address is long -- try parsing it as a cashaddr
        uint8_t *h160 = cashaddr_decode_hash160(addr, cashaddr_prefix);
        if (h160) {
            memcpy(&b58bin[1], h160, 20); // hack -- we only care about the hash 160 anyway
            free(h160);
            decoded_cashaddr = true;
        }
    }

    if (!decoded_cashaddr) {
        addr = remove_any_cashaddr_prefix(addr);

        if (!b58tobin_safe(b58bin, addr)) {
            LOGWARNING("Could not decode address '%s'!", addr);
            return 0;
        }
    }
    psh[0] = 0xa9;
    psh[1] = 0x14;
    memcpy(&psh[2], &b58bin[1], 20); // this hash160 may have come either from cashaddr or base58 decoding above
    psh[22] = 0x87;
    return 23;
}

/* Convert an address to a transaction and return the length of the transaction */
int address_to_script(uchar *p2h, const char *addr, bool is_p2sh, const char *cashaddr_prefix)
{
    if (is_p2sh)
        return p2sh_address_to_script(p2h, addr, cashaddr_prefix);
    return p2pkh_address_to_script(p2h, addr, cashaddr_prefix);
}

int write_compact_size(void *dest, size_t nSize)
{
    uint8_t *buf = (uint8_t *)dest;
    if (nSize < 253) {
        *buf = (uint8_t)nSize;
        return 1;
    }
    if (nSize <= UINT16_MAX) {
        *buf++ = 0xfd;
        // avoid unaligned access
        const uint16_t datum = htole16((uint16_t)nSize);
        memcpy(buf, &datum, 2);
        return 3;
    }
    if (nSize <= UINT32_MAX) {
        *buf++ = 0xfe;
        // avoid unaligned access
        const uint32_t datum = htole32((uint32_t)nSize);
        memcpy(buf, &datum, 4);
        return 5;
    }
    // 64-bit (8 byte) .. unlikely.
    *buf++ = 0xff;
    // avoid unaligned access
    const uint64_t datum = htole64((uint64_t)nSize);
    memcpy(buf, &datum, 8);
    return 9;
}

/* For testing a le encoded 256 byte hash against a target */
bool fulltest(const uchar *hash, const uchar *target)
{
    bool ret = true;
    int i;

    for (i = 28; i >= 0; i -= 4) {
        const uint32_t h32tmp = le32toh(read_i32(hash + i*4));
        const uint32_t t32tmp = le32toh(read_i32(target + i*4));

        if (h32tmp > t32tmp) {
            ret = false;
            break;
        }
        if (h32tmp < t32tmp) {
            ret = true;
            break;
        }
    }
    return ret;
}

void copy_tv(tv_t *dest, const tv_t *src)
{
    memcpy(dest, src, sizeof(tv_t));
}

void ts_to_tv(tv_t *val, const ts_t *spec)
{
    val->tv_sec = spec->tv_sec;
    val->tv_usec = spec->tv_nsec / 1000;
}

void tv_to_ts(ts_t *spec, const tv_t *val)
{
    spec->tv_sec = val->tv_sec;
    spec->tv_nsec = val->tv_usec * 1000;
}

void us_to_tv(tv_t *val, int64_t us)
{
    lldiv_t tvdiv = lldiv(us, 1000000);

    val->tv_sec = tvdiv.quot;
    val->tv_usec = tvdiv.rem;
}

void us_to_ts(ts_t *spec, int64_t us)
{
    lldiv_t tvdiv = lldiv(us, 1000000);

    spec->tv_sec = tvdiv.quot;
    spec->tv_nsec = tvdiv.rem * 1000;
}

void ms_to_ts(ts_t *spec, int64_t ms)
{
    lldiv_t tvdiv = lldiv(ms, 1000);

    spec->tv_sec = tvdiv.quot;
    spec->tv_nsec = tvdiv.rem * 1000000;
}

void ms_to_tv(tv_t *val, int64_t ms)
{
    lldiv_t tvdiv = lldiv(ms, 1000);

    val->tv_sec = tvdiv.quot;
    val->tv_usec = tvdiv.rem * 1000;
}

void tv_time(tv_t *tv)
{
    gettimeofday(tv, NULL);
}

void ts_realtime(ts_t *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

void ts_monotonic(ts_t *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

int64_t time_micros(void)
{
    int64_t ret;
    ts_t ts;
    ts_monotonic(&ts);
    // we do the below to prevent overflow on 32-bit
    ret = ts.tv_sec;
    ret *= (int64_t)1000000L; // seconds -> scaled to millions of microseconds
    ret += (int64_t)(ts.tv_nsec / 1000L);  // nanoseconds -> to microseconds
    return ret;
}

void cksleep_prepare_r(ts_t *ts)
{
    clock_gettime(CLOCK_MONOTONIC, ts);
}

void timeraddspec(ts_t *a, const ts_t *b)
{
    a->tv_sec += b->tv_sec;
    a->tv_nsec += b->tv_nsec;
    if (a->tv_nsec >= 1000000000) {
        a->tv_nsec -= 1000000000;
        a->tv_sec++;
    }
}

/* Reentrant version of cksleep functions allow start time to be set separately
 * from the beginning of the actual sleep, allowing scheduling delays to be
 * counted in the sleep. */
void cksleep_ms_r(const ts_t *ts_start, int ms)
{
    ts_t ts_end;

    ms_to_ts(&ts_end, ms);
    timeraddspec(&ts_end, ts_start);
    nanosleep_abstime(&ts_end);
}

void cksleep_us_r(const ts_t *ts_start, int64_t us)
{
    ts_t ts_end;

    us_to_ts(&ts_end, us);
    timeraddspec(&ts_end, ts_start);
    nanosleep_abstime(&ts_end);
}

void cksleep_ms(int ms)
{
    ts_t ts_start;

    cksleep_prepare_r(&ts_start);
    cksleep_ms_r(&ts_start, ms);
}

void cksleep_us(int64_t us)
{
    ts_t ts_start;

    cksleep_prepare_r(&ts_start);
    cksleep_us_r(&ts_start, us);
}

/* Returns the microseconds difference between end and start times as a double */
double us_tvdiff(const tv_t *end, const tv_t *start)
{
    /* Sanity check. We should only be using this for small differences so
     * limit the max to 60 seconds. */
    if (unlikely(end->tv_sec - start->tv_sec > 60))
        return 60000000;
    return (end->tv_sec - start->tv_sec) * 1000000 + (end->tv_usec - start->tv_usec);
}

/* Returns the milliseconds difference between end and start times */
int ms_tvdiff(const tv_t *end, const tv_t *start)
{
    /* Like us_tdiff, limit to 1 hour. */
    if (unlikely(end->tv_sec - start->tv_sec > 3600))
        return 3600000;
    return (end->tv_sec - start->tv_sec) * 1000 + (end->tv_usec - start->tv_usec) / 1000;
}

/* Returns the seconds difference between end and start times as a double */
double tvdiff(const tv_t *end, const tv_t *start)
{
    return end->tv_sec - start->tv_sec + (end->tv_usec - start->tv_usec) / 1000000.0;
}

/* Create an exponentially decaying average over interval */
void decay_time(double *f, double fadd, double fsecs, double interval)
{
    double ftotal, fprop, dexp;

    if (fsecs <= 0)
        return;
    dexp = fsecs / interval;
    /* Put Sanity bound on how large the denominator can get */
    if (unlikely(dexp > 36))
        dexp = 36;
    fprop = 1.0 - 1 / exp(dexp);
    ftotal = 1.0 + fprop;
    *f += (fadd / fsecs * fprop);
    *f /= ftotal;
    /* Sanity check to prevent meaningless super small numbers that
     * eventually underflow libjansson's real number interpretation. */
    if (unlikely(*f < 2E-16))
        *f = 0;
}

/* Sanity check to prevent clock adjustments backwards from screwing up stats */
double sane_tdiff(const tv_t *end, const tv_t *start)
{
    double tdiff = tvdiff(end, start);

    if (unlikely(tdiff < 0.001))
        tdiff = 0.001;
    return tdiff;
}

/* Convert a double value into a truncated string for displaying with its
 * associated suitable for Mega, Giga etc. Buf array needs to be long enough */
void suffix_string(double val, char *buf, size_t bufsiz, int sigdigits)
{
    const double kilo = 1000;
    const double mega = 1000000;
    const double giga = 1000000000;
    const double tera = 1000000000000;
    const double peta = 1000000000000000;
    const double exa  = 1000000000000000000;
    char suffix[2] = "";
    bool decimal = true;
    double dval;

    if (val >= exa) {
        val /= peta;
        dval = val / kilo;
        strcpy(suffix, "E");
    } else if (val >= peta) {
        val /= tera;
        dval = val / kilo;
        strcpy(suffix, "P");
    } else if (val >= tera) {
        val /= giga;
        dval = val / kilo;
        strcpy(suffix, "T");
    } else if (val >= giga) {
        val /= mega;
        dval = val / kilo;
        strcpy(suffix, "G");
    } else if (val >= mega) {
        val /= kilo;
        dval = val / kilo;
        strcpy(suffix, "M");
    } else if (val >= kilo) {
        dval = val / kilo;
        strcpy(suffix, "K");
    } else {
        dval = val;
        decimal = false;
    }

    if (!sigdigits) {
        if (decimal)
            snprintf(buf, bufsiz, "%.3g%s", dval, suffix);
        else
            snprintf(buf, bufsiz, "%d%s", (unsigned int)dval, suffix);
    } else {
        /* Always show sigdigits + 1, padded on right with zeroes
         * followed by suffix */
        int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

        snprintf(buf, bufsiz, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
    }
}

/* truediffone == 0x00000000FFFF0000000000000000000000000000000000000000000000000000
 * Generate a 256 bit binary LE target by cutting up diff into 64 bit sized
 * portions or vice versa. */
static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
static const double bits192 = 6277101735386680763835789423207666416102355444464034512896.0;
static const double bits128 = 340282366920938463463374607431768211456.0;
static const double bits64 = 18446744073709551616.0;

/* Converts a little endian 256 bit value to a double */
double le256todouble(const uchar * const target)
{
    double dcut64;

    dcut64  = le64toh(read_i64(target + 24)) * bits192;
    dcut64 += le64toh(read_i64(target + 16)) * bits128;
    dcut64 += le64toh(read_i64(target +  8)) * bits64;
    dcut64 += le64toh(read_i64(target +  0));

    return dcut64;
}

/* Return a difficulty from a binary target */
double diff_from_target(const uchar *target)
{
    double d64, dcut64;

    d64 = truediffone;
    dcut64 = le256todouble(target);
    if (unlikely(dcut64 <= 0.0))
        dcut64 = 1.;
    return d64 / dcut64;
}

/* Return the network difficulty from the block header which is in packed form,
 * as a double. */
double diff_from_nbits(const uchar *nbits)
{
    double numerator;
    uint32_t diff32;
    uint8_t pow;
    int powdiff;

    pow = nbits[0];
    powdiff = (8 * (0x1d - 3)) - (8 * (pow - 3));
    if (unlikely(powdiff < 0)) // testnet only
        powdiff = 0;
    memcpy(&diff32, nbits, sizeof(diff32));
    diff32 = be32toh(diff32) & 0x00FFFFFFu;
    numerator = 0xFFFFULL << powdiff;
    if (unlikely(diff32 == 0))
        // this should never happen, but prevent floating point exceptions
        diff32 = 1;

    return numerator / (double)diff32;
}

void target_from_diff(uchar *const target, double const diff)
{
    uint64_t h64;
    double d64, dcut64;

    if (unlikely(diff == 0.0)) {
        /* This shouldn't happen but best we check to prevent a crash */
        memset(target, 0xff, 32);
        return;
    }

    d64 = truediffone;
    d64 /= diff;

    dcut64 = d64 / bits192;
    h64 = dcut64;
    write_i64(target + 24, htole64(h64));
    dcut64 = h64;
    dcut64 *= bits192;
    d64 -= dcut64;

    dcut64 = d64 / bits128;
    h64 = dcut64;
    write_i64(target + 16, htole64(h64));
    dcut64 = h64;
    dcut64 *= bits128;
    d64 -= dcut64;

    dcut64 = d64 / bits64;
    h64 = dcut64;
    write_i64(target +  8, htole64(h64));
    dcut64 = h64;
    dcut64 *= bits64;
    d64 -= dcut64;

    h64 = d64;
    write_i64(target +  0, htole64(h64));
}

void gen_hash(const uchar *data, uchar *hash, int len)
{
    assert(len >= 0); // debug builds
    if (unlikely(len < 0)) len = 0; // non-debug builds

    sha256(data, len, hash);
    sha256(hash, 32, hash);
}
