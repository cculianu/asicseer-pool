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

#include "config.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <fenv.h>
#include <getopt.h>
#include <grp.h>
#include <jansson.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asicseer-pool.h"
#include "cashaddr.h"
#include "connector.h"
#include "donation.h"
#include "generator.h"
#include "libasicseerpool.h"
#include "sha2.h"
#include "stratifier.h"

pool_t *global_ckp;

static bool open_logfile(pool_t *ckp)
{
    if (ckp->logfd > 0) {
        flock(ckp->logfd, LOCK_EX);
        fflush(ckp->logfp);
        Close(ckp->logfd);
    }
    ckp->logfp = fopen(ckp->logfilename, "ae");
    if (unlikely(!ckp->logfp)) {
        LOGEMERG("Failed to open log file %s", ckp->logfilename);
        return false;
    }
    /* Make logging line buffered */
    setvbuf(ckp->logfp, NULL, _IOLBF, 0);
    ckp->logfd = fileno(ckp->logfp);
    ckp->lastopen_t = time(NULL);
    return true;
}

/* Use ckmsgqs for logging to console and files to prevent logmsg from blocking
 * on any delays. */
static void console_log(pool_t maybe_unused__ *ckp, char *msg)
{
    /* Add clear line only if stderr is going to console */
    if (isatty(fileno(stderr)))
        fprintf(stderr, "\33[2K\r");
    fprintf(stderr, "%s", msg);
    fflush(stderr);

    free(msg);
}

static void proclog(pool_t *ckp, char *msg)
{
    time_t log_t = time(NULL);

    /* Reopen log file every minute, allowing us to move/rename it and
     * create a new logfile */
    if (log_t > ckp->lastopen_t + 60) {
        LOGDEBUG("Reopening logfile");
        open_logfile(ckp);
    }

    flock(ckp->logfd, LOCK_EX);
    fprintf(ckp->logfp, "%s", msg);
    flock(ckp->logfd, LOCK_UN);

    free(msg);
}

void get_timestamp(char *stamp, size_t stamp_len, bool is_localtime)
{
    struct tm tm;
    tv_t now_tv;
    long ms;

    tv_time(&now_tv);
    ms = (long)(now_tv.tv_usec / 1000L);
    if (is_localtime)
        localtime_r(&now_tv.tv_sec, &tm);
    else
        gmtime_r(&now_tv.tv_sec, &tm);
    snprintf(stamp, stamp_len, "[%d-%02d-%02d %02d:%02d:%02d.%03ld]",
             tm.tm_year + 1900,
             tm.tm_mon + 1,
             tm.tm_mday,
             tm.tm_hour,
             tm.tm_min,
             tm.tm_sec, ms);
}

/* Log everything to the logfile, but display warnings on the console as well */
void logmsg(int loglevel, const char *fmt, ...)
{
    const int logfd = global_ckp->logfd;
    const bool is_localtime = global_ckp->localtime_logging;
    char *log, *buf = NULL;
    char stamp[128];
    va_list ap;

    if (global_ckp->loglevel < loglevel || !fmt)
        return;

    va_start(ap, fmt);
    VASPRINTF(&buf, fmt, ap);
    va_end(ap);

    if (unlikely(!buf)) {
        fprintf(stderr, "Null buffer sent to logmsg\n");
        return;
    }
    if (unlikely(!strlen(buf))) {
        fprintf(stderr, "Zero length string sent to logmsg\n");
        goto out;
    }
    get_timestamp(stamp, sizeof(stamp), is_localtime);
    if (loglevel <= LOG_ERR && errno != 0)
        ASPRINTF(&log, "%s %s with errno %d: %s\n", stamp, buf, errno, strerror(errno));
    else
        ASPRINTF(&log, "%s %s\n", stamp, buf);

    if (unlikely(!global_ckp->console_logger)) {
        // logger not up yet -- output to stderr immediately and return.
        fprintf(stderr, "%s", log);
        goto out_free;
    }
    if (loglevel <= LOG_WARNING)
        ckmsgq_add(global_ckp->console_logger, strdup(log));
    if (logfd > 0)
        ckmsgq_add(global_ckp->logger, strdup(log));
out_free:
    free(log);
out:
    free(buf);
}

/* Generic function for creating a message queue receiving and parsing thread */
static void *ckmsg_queue(void *arg)
{
    ckmsgq_t *ckmsgq = (ckmsgq_t *)arg;
    pool_t *ckp = ckmsgq->ckp;

    pthread_detach(pthread_self());
    rename_proc(ckmsgq->name);
    ckmsgq->active = true;

    while (42) {
        ckmsg_t *msg;
        tv_t now;
        ts_t abs;

        mutex_lock(ckmsgq->lock);
        tv_time(&now);
        tv_to_ts(&abs, &now);
        abs.tv_sec++;
        if (!ckmsgq->msgs)
            cond_timedwait(ckmsgq->cond, ckmsgq->lock, &abs);
        msg = ckmsgq->msgs;
        if (msg)
            DL_DELETE(ckmsgq->msgs, msg);
        mutex_unlock(ckmsgq->lock);

        if (!msg)
            continue;
        ckmsgq->func(ckp, msg->data);
        free(msg);
    }
    return NULL;
}

ckmsgq_t *create_ckmsgq(pool_t *ckp, const char *name, const void *func)
{
    ckmsgq_t *ckmsgq = ckzalloc(sizeof(ckmsgq_t));

    strncpy(ckmsgq->name, name, 15);
    ckmsgq->func = func;
    ckmsgq->ckp = ckp;
    ckmsgq->lock = ckalloc(sizeof(mutex_t));
    ckmsgq->cond = ckalloc(sizeof(pthread_cond_t));
    mutex_init(ckmsgq->lock);
    cond_init(ckmsgq->cond);
    create_pthread(&ckmsgq->pth, ckmsg_queue, ckmsgq);

    return ckmsgq;
}

ckmsgq_t *create_ckmsgqs(pool_t *ckp, const char *name, const void *func, const int count)
{
    ckmsgq_t *ckmsgq = ckzalloc(sizeof(ckmsgq_t) * count);
    mutex_t *lock;
    pthread_cond_t *cond;
    int i;

    lock = ckalloc(sizeof(mutex_t));
    cond = ckalloc(sizeof(pthread_cond_t));
    mutex_init(lock);
    cond_init(cond);

    for (i = 0; i < count; i++) {
        snprintf(ckmsgq[i].name, 15, "%.6s%x", name, i);
        ckmsgq[i].func = func;
        ckmsgq[i].ckp = ckp;
        ckmsgq[i].lock = lock;
        ckmsgq[i].cond = cond;
        create_pthread(&ckmsgq[i].pth, ckmsg_queue, &ckmsgq[i]);
    }

    return ckmsgq;
}

/* Generic function for adding messages to a ckmsgq linked list and signal the
 * ckmsgq parsing thread(s) to wake up and process it. */
bool ckmsgq_add_(ckmsgq_t *ckmsgq, void *data, const char *file, const char *func, const int line)
{
    ckmsg_t *msg;

    if (unlikely(!ckmsgq)) {
        LOGWARNING("Sending messages to no queue from %s %s:%d", file, func, line);
        /* Discard data if we're unlucky enough to be sending it to
         * msg queues not set up during start up */
        free(data);
        return false;
    }
    while (unlikely(!ckmsgq->active))
        cksleep_ms(10);

    msg = ckalloc(sizeof(ckmsg_t));
    msg->data = data;

    mutex_lock(ckmsgq->lock);
    ckmsgq->messages++;
    DL_APPEND(ckmsgq->msgs, msg);
    pthread_cond_broadcast(ckmsgq->cond);
    mutex_unlock(ckmsgq->lock);

    return true;
}

/* Return whether there are any messages queued in the ckmsgq linked list. */
bool ckmsgq_empty(ckmsgq_t *ckmsgq)
{
    bool ret = true;

    if (unlikely(!ckmsgq || !ckmsgq->active))
        goto out;

    mutex_lock(ckmsgq->lock);
    if (ckmsgq->msgs)
        ret = (ckmsgq->msgs->next == ckmsgq->msgs->prev);
    mutex_unlock(ckmsgq->lock);
out:
    return ret;
}

/* Create a standalone thread that queues received unix messages for a proc
 * instance and adds them to linked list of received messages with their
 * associated receive socket, then signal the associated rmsg_cond for the
 * process to know we have more queued messages. The unix_msg_t ram must be
 * freed by the code that removes the entry from the list. */
static void *unix_receiver(void *arg)
{
    proc_instance_t *pi = (proc_instance_t *)arg;
    int rsockd = pi->us.sockd, sockd;
    char qname[16];

    sprintf(qname, "%cunixrq", pi->processname[0]);
    rename_proc(qname);
    pthread_detach(pthread_self());

    while (42) {
        unix_msg_t *umsg;
        char *buf;

        sockd = accept(rsockd, NULL, NULL);
        if (unlikely(sockd < 0)) {
            LOGEMERG("Failed to accept on %s socket, exiting", qname);
            break;
        }
        buf = recv_unix_msg(sockd);
        if (unlikely(!buf)) {
            Close(sockd);
            LOGWARNING("Failed to get message on %s socket", qname);
            continue;
        }
        umsg = ckalloc(sizeof(unix_msg_t));
        umsg->sockd = sockd;
        umsg->buf = buf;

        mutex_lock(&pi->rmsg_lock);
        DL_APPEND(pi->unix_msgs, umsg);
        pthread_cond_signal(&pi->rmsg_cond);
        mutex_unlock(&pi->rmsg_lock);
    }

    return NULL;
}

/* Get the next message in the receive queue, or wait up to 5 seconds for
 * the next message, returning NULL if no message is received in that time. */
unix_msg_t *get_unix_msg(proc_instance_t *pi)
{
    unix_msg_t *umsg;

    mutex_lock(&pi->rmsg_lock);
    if (!pi->unix_msgs) {
        tv_t now;
        ts_t abs;

        tv_time(&now);
        tv_to_ts(&abs, &now);
        abs.tv_sec += 5;
        cond_timedwait(&pi->rmsg_cond, &pi->rmsg_lock, &abs);
    }
    umsg = pi->unix_msgs;
    if (umsg)
        DL_DELETE(pi->unix_msgs, umsg);
    mutex_unlock(&pi->rmsg_lock);

    return umsg;
}

static void create_unix_receiver(proc_instance_t *pi)
{
    pthread_t pth;

    mutex_init(&pi->rmsg_lock);
    cond_init(&pi->rmsg_cond);

    create_pthread(&pth, unix_receiver, pi);
}

/* Put a sanity check on kill calls to make sure we are not sending them to
 * pid 0. */
static int kill_pid(const int pid, const int sig)
{
    if (pid < 1)
        return -1;
    return kill(pid, sig);
}

static int pid_wait(const pid_t pid, const int ms)
{
    tv_t start, now;
    int ret;

    tv_time(&start);
    do {
        ret = kill_pid(pid, 0);
        if (ret)
            break;
        tv_time(&now);
    } while (ms_tvdiff(&now, &start) < ms);
    return ret;
}

static void api_message(pool_t *ckp, char **buf, int *sockd)
{
    apimsg_t *apimsg = ckalloc(sizeof(apimsg_t));

    apimsg->buf = *buf;
    *buf = NULL;
    apimsg->sockd = *sockd;
    *sockd = -1;
    ckmsgq_add(ckp->ckpapi, apimsg);
}

/* Listen for incoming global requests. Always returns a response if possible */
static void *listener(void *arg)
{
    proc_instance_t *pi = (proc_instance_t *)arg;
    unixsock_t *us = &pi->us;
    pool_t *ckp = pi->ckp;
    char *buf = NULL, *msg;
    int sockd;

    rename_proc(pi->sockname);
retry:
    dealloc(buf);
    sockd = accept(us->sockd, NULL, NULL);
    if (sockd < 0) {
        LOGERR("Failed to accept on socket in listener");
        goto out;
    }

    buf = recv_unix_msg(sockd);
    if (!buf) {
        LOGWARNING("Failed to get message in listener");
        send_unix_msg(sockd, "failed");
    } else if (buf[0] == '{') {
        /* Any JSON messages received are for the RPC API to handle */
        api_message(ckp, &buf, &sockd);
    } else if (cmdmatch(buf, "shutdown")) {
        LOGWARNING("Listener received shutdown message, terminating " POOL_PROGNAME);
        send_unix_msg(sockd, "exiting");
        goto out;
    } else if (cmdmatch(buf, "ping")) {
        LOGDEBUG("Listener received ping request");
        send_unix_msg(sockd, "pong");
    } else if (cmdmatch(buf, "loglevel")) {
        int loglevel;

        if (sscanf(buf, "loglevel=%d", &loglevel) != 1) {
            LOGWARNING("Failed to parse loglevel message %s", buf);
            send_unix_msg(sockd, "Failed");
        } else if (loglevel < LOG_EMERG || loglevel > LOG_DEBUG) {
            LOGWARNING("Invalid loglevel %d sent", loglevel);
            send_unix_msg(sockd, "Invalid");
        } else {
            ckp->loglevel = loglevel;
            send_unix_msg(sockd, "success");
        }
    } else if (cmdmatch(buf, "getxfd")) {
        int fdno = -1;

        sscanf(buf, "getxfd%d", &fdno);
        connector_send_fd(ckp, fdno, sockd);
    } else if (cmdmatch(buf, "accept")) {
        LOGWARNING("Listener received accept message, accepting clients");
        send_proc(ckp->connector, "accept");
        send_unix_msg(sockd, "accepting");
    } else if (cmdmatch(buf, "reject")) {
        LOGWARNING("Listener received reject message, rejecting clients");
        send_proc(ckp->connector, "reject");
        send_unix_msg(sockd, "rejecting");
    } else if (cmdmatch(buf, "reconnect")) {
        LOGWARNING("Listener received request to send reconnect to clients");
        send_proc(ckp->stratifier, buf);
        send_unix_msg(sockd, "reconnecting");
    } else if (cmdmatch(buf, "restart")) {
        LOGWARNING("Listener received restart message, attempting handover");
        send_unix_msg(sockd, "restarting");
        if (!fork()) {
            if (!ckp->handover) {
                ckp->initial_args[ckp->args++] = strdup("-H");
                ckp->initial_args[ckp->args] = NULL;
            }
            execv(ckp->initial_args[0], (char *const *)ckp->initial_args);
        }
    } else if (cmdmatch(buf, "stratifierstats")) {
        LOGDEBUG("Listener received stratifierstats request");
        msg = stratifier_stats(ckp, ckp->sdata);
        send_unix_msg(sockd, msg);
        dealloc(msg);
    } else if (cmdmatch(buf, "connectorstats")) {
        LOGDEBUG("Listener received connectorstats request");
        msg = connector_stats(ckp->cdata, 0);
        send_unix_msg(sockd, msg);
        dealloc(msg);
    } else if (cmdmatch(buf, "ckdbflush")) {
        LOGWARNING("Received ckdb flush message");
        send_proc(ckp->stratifier, buf);
        send_unix_msg(sockd, "flushing");
    } else {
        LOGINFO("Listener received unhandled message: %s", buf);
        send_unix_msg(sockd, "unknown");
    }
    Close(sockd);
    goto retry;
out:
    dealloc(buf);
    close_unix_socket(us->sockd, us->path);
    return NULL;
}

void empty_buffer(connsock_t *cs)
{
    if (cs->buf)
        cs->buf[0] = '\0';
    cs->buflen = cs->bufofs = 0;
}

int set_sendbufsize(pool_t *ckp, const int fd, const int len)
{
    socklen_t optlen;
    int opt;

    optlen = sizeof(opt);
    opt = len * 4 / 3;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, optlen);
    getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, &optlen);
    opt /= 2;
    if (opt < len) {
        LOGDEBUG("Failed to set desired sendbufsize of %d unprivileged, only got %d",
             len, opt);
        optlen = sizeof(opt);
        opt = len * 4 / 3;
#ifdef SO_SNDBUFFORCE
        setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &opt, optlen);
#endif
        getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, &optlen);
        opt /= 2;
    }
    if (opt < len) {
        LOGWARNING("Failed to increase sendbufsize to %d, increase wmem_max or start %s privileged",
               len, ckp->name);
        ckp->wmem_warn = true;
    } else
        LOGDEBUG("Increased sendbufsize to %d of desired %d", opt, len);
    return opt;
}

int set_recvbufsize(pool_t *ckp, const int fd, const int len)
{
    socklen_t optlen;
    int opt;

    optlen = sizeof(opt);
    opt = len * 4 / 3;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, optlen);
    getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &optlen);
    opt /= 2;
    if (opt < len) {
        LOGDEBUG("Failed to set desired rcvbufsiz of %d unprivileged, only got %d",
             len, opt);
        optlen = sizeof(opt);
        opt = len * 4 / 3;
#ifdef SO_RCVBUFFORCE
        setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, optlen);
#endif
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, &optlen);
        opt /= 2;
    }
    if (opt < len) {
        LOGWARNING("Failed to increase rcvbufsiz to %d, increase rmem_max or start %s privileged",
               len, ckp->name);
        ckp->rmem_warn = true;
    } else
        LOGDEBUG("Increased rcvbufsiz to %d of desired %d", opt, len);
    return opt;
}

/* If there is any cs->buflen it implies a full line was received on the last
 * pass through read_socket_line and subsequently processed, leaving
 * unprocessed data beyond cs->bufofs. Otherwise a zero buflen means there is
 * only unprocessed data of bufofs length. */
static void clear_bufline(connsock_t *cs)
{
    if (unlikely(!cs->buf)) {
        socklen_t optlen = sizeof(cs->rcvbufsiz);

        cs->buf = ckzalloc(PAGESIZE);
        cs->bufsize = PAGESIZE;
        getsockopt(cs->fd, SOL_SOCKET, SO_RCVBUF, &cs->rcvbufsiz, &optlen);
        cs->rcvbufsiz /= 2;
        LOGDEBUG("connsock rcvbufsiz detected as %d", cs->rcvbufsiz);
    } else if (cs->buflen) {
        memmove(cs->buf, cs->buf + cs->bufofs, cs->buflen);
        memset(cs->buf + cs->buflen, 0, cs->bufofs);
        cs->bufofs = cs->buflen;
        cs->buflen = 0;
        cs->buf[cs->bufofs] = '\0';
    }
}

static void ensure_buf_size(connsock_t *cs, const size_t reqalloc, const size_t maxinc_mb)
{
    int backoff = 1;
    size_t newalloc;
    void *newmem;
    const size_t max_realloc_increase = maxinc_mb * 1024 * 1024;
    static const size_t initial_alloc = 16 * 1024;

    while (reqalloc > cs->bufsize) {
        if (cs->bufsize > 0) {
            newalloc = cs->bufsize * 2;
        } else {
            newalloc = initial_alloc;
        }

        if (max_realloc_increase > 0) {
            /* limit the maximum buffer increase */
            if (newalloc - cs->bufsize > max_realloc_increase)
                newalloc = cs->bufsize + max_realloc_increase;
        }

        /* ensure we have a big enough allocation */
        if (reqalloc > newalloc)
            newalloc = reqalloc;

        newalloc = round_up_page(newalloc);

        newmem = realloc(cs->buf, newalloc);
        if (unlikely(!newmem)) {
            if (backoff == 1)
                fprintf(stderr, "Failed to realloc %d in read_socket_line, retrying\n", (int)newalloc);
            cksleep_ms(backoff);
            backoff <<= 1;
            continue;
        }

        cs->buf = newmem;
        cs->bufsize = newalloc;
        break;
    }
}

static void add_buflen(pool_t *ckp, connsock_t *cs, const char *readbuf, const int len)
{
    int buflen = cs->bufofs + len + 1;

    ensure_buf_size(cs, buflen, 8);

    /* Increase receive buffer if possible to larger than the largest
     * message we're likely to buffer */
    if (unlikely(!ckp->rmem_warn && buflen > cs->rcvbufsiz))
        cs->rcvbufsiz = set_recvbufsize(ckp, cs->fd, buflen);

    memcpy(cs->buf + cs->bufofs, readbuf, len);
    cs->bufofs += len;
    cs->buf[cs->bufofs] = '\0';
}

/* Receive as much data is currently available without blocking into a connsock
 * buffer. Returns total length of data read. */
static int recv_available(pool_t *ckp, connsock_t *cs, size_t pagesize)
{
    if (!pagesize)
        return 0;
    char readbuf[pagesize];
    int len = 0, ret;

    do {
        ret = recv(cs->fd, readbuf, pagesize, MSG_DONTWAIT);
        if (ret > 0) {
            add_buflen(ckp, cs, readbuf, ret);
            len += ret;
        }
    } while (ret > 0);

    return len;
}


/* Like read_socket_line except it doesn't read lines. Designed to be used with
 * http response content. Read from a socket into cs->buf up to contentlen bytes.
 */
int read_socket_contentlen(connsock_t *cs, int contentlen, float *timeout)
{
    tv_t start, now;
    pool_t *ckp;
    int ret = -1;
    bool quiet;
    float diff;
    int nread = 0;

    if (unlikely(!cs)) {
        LOGNOTICE("Invalidated connsock sent to %s", __func__);
        return ret;
    }

    ckp = cs->ckp;
    quiet = ckp->proxy | ckp->remote;

    clear_bufline(cs);
    ensure_buf_size(cs, contentlen, 0);
    nread = cs->bufofs;
    tv_time(&start);

    while (nread < contentlen) {
        if (unlikely(cs->fd < 0)) {
            ret = -1;
            goto out;
        }

        if (*timeout < 0) {
            if (quiet)
                LOGINFO("Timed out in %s", __func__);
            else
                LOGERR("Timed out in %s", __func__);
            ret = 0;
            goto out;
        }
        ret = wait_read_select(cs->fd, *timeout);
        if (ret < 1) {
            if (quiet)
                LOGINFO("Select %s in %s", !ret ? "timed out" : "failed", __func__);
            else
                LOGERR("Select %s in %s", !ret ? "timed out" : "failed", __func__);
            goto out;
        }
        ret = recv_available(ckp, cs, MIN(contentlen - nread, PAGESIZE * 4));
        if (ret < 1) {
            /* If we have done wait_read_select there should be
             * something to read and if we get nothing it means the
             * socket is closed. */
            if (quiet)
                LOGINFO("Failed to recv in %s", __func__);
            else
                LOGERR("Failed to recv in %s", __func__);
            ret = -1;
            goto out;
        } else {
            //LOGDEBUG("read: %d (%d)", ret, cs->fd);
            nread += ret;
        }
        tv_time(&now);
        diff = tvdiff(&now, &start);
        copy_tv(&start, &now);
        *timeout -= diff;
    }
    if (nread && contentlen > 0) {
        cs->buflen = cs->bufofs - contentlen - 1;
        if (cs->buflen > 0)
            cs->bufofs = nread + 1;
        else {
            cs->buflen = 0;
            cs->bufofs = 0;
        }
        cs->buf[contentlen] = '\0'; // is this redundant?
        ret = contentlen;
        //LOGDEBUG("%s: contentlen: %d nread: %d buflen: %d bufofs: %d bufsize: %d content: \"%s\"", __func__,
        //         contentlen, nread, cs->buflen, cs->bufofs, cs->bufsize, cs->buf);
    }
out:
    if (ret < 0) {
        empty_buffer(cs);
        dealloc(cs->buf);
    }
    return ret;
}

/* Read from a socket into cs->buf till we get an '\n', converting it to '\0'
 * and storing how much extra data we've received, to be moved to the beginning
 * of the buffer for use on the next receive. Returns length of the line if a
 * whole line is received, zero if none/some data is received without an EOL
 * and -1 on error. */
int read_socket_line(connsock_t *cs, float *timeout)
{
    char *eom = NULL;
    tv_t start, now;
    pool_t *ckp;
    int ret = -1;
    bool quiet;
    float diff;

    if (unlikely(!cs)) {
        LOGNOTICE("Invalidated connsock sent to read_socket_line");
        return ret;
    }

    ckp = cs->ckp;
    quiet = ckp->proxy | ckp->remote;

    clear_bufline(cs);
    recv_available(ckp, cs, PAGESIZE-4); // Intentionally ignore return value
    eom = memchr(cs->buf, '\n', cs->bufofs);

    tv_time(&start);

    while (!eom) {
        if (unlikely(cs->fd < 0)) {
            ret = -1;
            goto out;
        }

        if (*timeout < 0) {
            if (quiet)
                LOGINFO("Timed out in read_socket_line");
            else
                LOGERR("Timed out in read_socket_line");
            ret = 0;
            goto out;
        }
        ret = wait_read_select(cs->fd, *timeout);
        if (ret < 1) {
            if (quiet)
                LOGINFO("Select %s in read_socket_line", !ret ? "timed out" : "failed");
            else
                LOGERR("Select %s in read_socket_line", !ret ? "timed out" : "failed");
            goto out;
        }
        ret = recv_available(ckp, cs, PAGESIZE-4);
        if (ret < 1) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            /* If we have done wait_read_select there should be
             * something to read and if we get nothing it means the
             * socket is closed. */
            if (quiet)
                LOGINFO("Failed to recv in read_socket_line");
            else
                LOGERR("Failed to recv in read_socket_line");
            ret = -1;
            goto out;
        }
        // LOGDEBUG("read: %d (%d)", ret, cs->fd);
        eom = memchr(cs->buf, '\n', cs->bufofs);
        tv_time(&now);
        diff = tvdiff(&now, &start);
        copy_tv(&start, &now);
        *timeout -= diff;
    }
    ret = eom - cs->buf;

    cs->buflen = cs->buf + cs->bufofs - eom - 1;
    if (cs->buflen)
        cs->bufofs = eom - cs->buf + 1;
    else
        cs->bufofs = 0;
    *eom = '\0';
out:
    if (ret < 0) {
        empty_buffer(cs);
        dealloc(cs->buf);
    }
    //LOGDEBUG("%s: fd: %d, ret: %d buflen: %d bufofs: %d bufsize: %d buf: \"%s\"", __func__,
    //         cs->fd, ret, cs->buflen, cs->bufofs, cs->bufsize, cs->buf);
    return ret;
}

/* We used to send messages between each proc_instance via unix sockets when
 * asicseer-pool was a multi-process model but that is no longer required so we can
 * place the messages directly on the other proc_instance's queue until we
 * deprecate this mechanism. */
void queue_proc_(proc_instance_t *pi, const char *msg, const char *file, const char *func, const int line)
{
    unix_msg_t *umsg;

    if (unlikely(!msg || !strlen(msg))) {
        LOGWARNING("Null msg passed to queue_proc from %s %s:%d", file, func, line);
        return;
    }
    umsg = ckalloc(sizeof(unix_msg_t));
    umsg->sockd = -1;
    umsg->buf = strdup(msg);

    mutex_lock(&pi->rmsg_lock);
    DL_APPEND(pi->unix_msgs, umsg);
    pthread_cond_signal(&pi->rmsg_cond);
    mutex_unlock(&pi->rmsg_lock);
}

/* Send a single message to a process instance and retrieve the response, then
 * close the socket. */
char *send_recv_proc_(const proc_instance_t *pi, const char *msg, int writetimeout, int readtimedout,
                      const char *file, const char *func, const int line)
{
    char *path = pi->us.path, *buf = NULL;
    int sockd;

    if (unlikely(!path || !strlen(path))) {
        LOGERR("Attempted to send message %s to null path in send_proc", msg ? msg : "");
        goto out;
    }
    if (unlikely(!msg || !strlen(msg))) {
        LOGERR("Attempted to send null message to socket %s in send_proc", path);
        goto out;
    }
    sockd = open_unix_client(path);
    if (unlikely(sockd < 0)) {
        LOGWARNING("Failed to open socket %s in send_recv_proc", path);
        goto out;
    }
    if (unlikely(!send_unix_msg_(sockd, msg, writetimeout, file, func, line)))
        LOGWARNING("Failed to send %s to socket %s", msg, path);
    else
        buf = recv_unix_msg_(sockd, readtimedout, readtimedout, file, func, line);
    Close(sockd);
out:
    if (unlikely(!buf))
        LOGERR("Failure in send_recv_proc from %s %s:%d", file, func, line);
    return buf;
}

static const char *rpc_method(const char *rpc_req)
{
    const char *ptr = strchr(rpc_req, ':');
    if (ptr)
        return ptr+1;
    return rpc_req;
}

/* All of these calls are made to bitcoind which prefers open/close instead
 * of persistent connections so cs->fd is always invalid. */
static json_t *my_json_rpc_call(connsock_t *cs, const struct rpc_req_part *rpc_req, const bool info_only)
{
    float timeout = RPC_TIMEOUT;
    char *http_req = NULL;
    json_error_t err_val;
    char *warning = NULL;
    json_t *val = NULL;
    tv_t stt_tv, fin_tv;
    double elapsed;
    int len, ret;
    const struct rpc_req_part *cur;

    /* Serialise all calls in case we use cs from multiple threads */
    cksem_wait(&cs->sem);
    cs->fd = connect_socket(cs->url, cs->port);
    if (unlikely(cs->fd < 0)) {
        ASPRINTF(&warning, "Unable to connect socket to %s:%s in %s", cs->url, cs->port, __func__);
        goto out;
    }
    if (unlikely(!cs->url)) {
        ASPRINTF(&warning, "No URL in %s", __func__);
        goto out;
    }
    if (unlikely(!cs->port)) {
        ASPRINTF(&warning, "No port in %s", __func__);
        goto out;
    }
    if (unlikely(!cs->auth)) {
        ASPRINTF(&warning, "No auth in %s", __func__);
        goto out;
    }
    if (unlikely(!rpc_req)) {
        ASPRINTF(&warning, "Null rpc_req passed to %s", __func__);
        goto out;
    }
    if (unlikely(rpc_req[0].length == 0)) {
        ASPRINTF(&warning, "Zero length rpc_req passed to %s", __func__);
        goto out;
    }
    const int len2 = strlen(cs->auth) + strlen(cs->url) + strlen(cs->port);
    http_req = ckalloc(256 + len2); // Leave room for headers
    len = 0;
    for (cur = rpc_req; cur->string != NULL; cur++) {
        //assert(strlen(cur->string) == cur->length);
        len += cur->length;
    }
    sprintf(http_req,
         "POST / HTTP/1.1\n"
         "Authorization: Basic %s\n"
         "Host: %s:%s\n"
         "Content-type: application/json\n"
         "Content-Length: %d\n\n",
         cs->auth, cs->url, cs->port, len);

    len = strlen(http_req);

    tv_time(&stt_tv);
    ret = write_socket(cs->fd, http_req, len);
    if (ret != len) {
        tv_time(&fin_tv);
        elapsed = tvdiff(&fin_tv, &stt_tv);
        ASPRINTF(&warning, "Failed to write to socket in %s (%.20s...) %.3fs",
                 __func__, rpc_method(rpc_req[0].string), elapsed);
        goto out_empty;
    }

    tv_time(&stt_tv);
    for (cur = rpc_req; cur->string != NULL; cur++) {
        ret = write_socket(cs->fd, cur->string, cur->length);
        if (ret != cur->length) {
            tv_time(&fin_tv);
            elapsed = tvdiff(&fin_tv, &stt_tv);
            ASPRINTF(&warning, "Failed to write to socket in %s (%.20s...) %.3fs",
                    __func__, rpc_method(rpc_req[0].string), elapsed);
            goto out_empty;
        }
    }

    ret = read_socket_line(cs, &timeout);
    if (ret < 1) {
        tv_time(&fin_tv);
        elapsed = tvdiff(&fin_tv, &stt_tv);
        ASPRINTF(&warning, "Failed to read socket line in %s (%.20s...) %.3fs",
             __func__, rpc_method(rpc_req[0].string), elapsed);
        goto out_empty;
    }
    if (strncasecmp(cs->buf, "HTTP/1.1 200 OK", 15)) {
        tv_time(&fin_tv);
        elapsed = tvdiff(&fin_tv, &stt_tv);
        ASPRINTF(&warning, "HTTP response to (%.20s...) %.3fs not ok: %s",
             rpc_method(rpc_req[0].string), elapsed, cs->buf);
        timeout = 0;
        /* Look for a json response if there is one */
        while (read_socket_line(cs, &timeout) > 0) {
            timeout = 0;
            if (*cs->buf != '{')
                continue;
            free(warning);
            /* Replace the warning with the json response */
            ASPRINTF(&warning, "JSON response to (%.20s...) %.3fs not ok: %s",
                 rpc_method(rpc_req[0].string), elapsed, cs->buf);
            break;
        }
        goto out_empty;
    }
    int contentlen = -1;
    while (contentlen < 0) {
        ret = read_socket_line(cs, &timeout);
        if (ret < 1) {
            tv_time(&fin_tv);
            elapsed = tvdiff(&fin_tv, &stt_tv);
            ASPRINTF(&warning, "Failed to read http socket lines in %s (%.20s...) %.3fs",
                 __func__, rpc_method(rpc_req[0].string), elapsed);
            goto out_empty;
        }
        if (0 == strncasecmp("Content-Length: ", cs->buf, 16)) {
            // parse content-length: header line
            if (1 != sscanf(cs->buf + 16, "%d", &contentlen) || contentlen < 0) {
                // parse error
                tv_time(&fin_tv);
                elapsed = tvdiff(&fin_tv, &stt_tv);
                ASPRINTF(&warning, "Failed to read content-length lines in %s (%.20s...) %.3fs",
                         __func__, rpc_method(rpc_req[0].string), elapsed);
                goto out_empty;
            }
            // read blank line
            if ((ret = read_socket_line(cs, &timeout)) != 1) {
                tv_time(&fin_tv);
                elapsed = tvdiff(&fin_tv, &stt_tv);
                ASPRINTF(&warning, "Failed to read a blank line after content-length: %d in %s (%.20s...) %.3fs, got ret: %d",
                         contentlen, __func__, rpc_method(rpc_req[0].string), elapsed, ret);
                ret = -1;
                goto out_empty;
            }
            // at this point we parsed the content length and we break out of this loop
        }
    }
    // read exactly contentlen bytes
    ret = read_socket_contentlen(cs, contentlen, &timeout);
    if (ret != contentlen) {
        tv_time(&fin_tv);
        elapsed = tvdiff(&fin_tv, &stt_tv);
        ASPRINTF(&warning, "Failed to read content of length %d (got %d) in %s (%.20s...) %.3fs",
                 contentlen, ret, __func__, rpc_method(rpc_req[0].string), elapsed);
        ret = -1;
        goto out_empty;
    }
    tv_time(&fin_tv);
    elapsed = tvdiff(&fin_tv, &stt_tv);
    if (elapsed > 5.0) {
        ASPRINTF(&warning, "HTTP socket read+write took %.3fs in %s (%.20s...)",
                 elapsed, __func__, rpc_method(rpc_req[0].string));
    }
    {
        // parse json, if it takes longer than 0.1 seconds to parse, print to debug log
        const int64_t t0 = time_micros();
        val = json_loads(cs->buf, 0, &err_val);
        const double elapsed = (time_micros() - t0) / 1e6;
        if (elapsed >= 0.1)
            LOGDEBUG("%s: json_loads (%.20s...) took %1.6f secs", __func__,
                     rpc_method(rpc_req[0].string), elapsed);
    }
    if (!val) {
        ASPRINTF(&warning, "JSON decode (%.20s...) failed(%d): %s",
                 rpc_method(rpc_req[0].string), err_val.line, err_val.text);
    }
out_empty:
    empty_socket(cs->fd);
    empty_buffer(cs);
out:
    if (warning) {
        if (info_only)
            LOGINFO("%s", warning);
        else
            LOGWARNING("%s", warning);
        free(warning);
    }
    Close(cs->fd);
    free(http_req);
    dealloc(cs->buf);
    cksem_post(&cs->sem);
    return val;
}

json_t *json_rpc_call_parts(connsock_t *cs, const struct rpc_req_part *rpc_req)
{
    return my_json_rpc_call(cs, rpc_req, false);
}

json_t *json_rpc_call(connsock_t *cs, const char *rpc_req)
{
    struct rpc_req_part parts[] = {
        { rpc_req, strlen(rpc_req) },
        { NULL, 0 }
    };
    return my_json_rpc_call(cs, parts, false);
}

json_t *json_rpc_response(connsock_t *cs, const char *rpc_req)
{
    struct rpc_req_part parts[] = {
        { rpc_req, strlen(rpc_req) },
        { NULL, 0 }
    };
    return my_json_rpc_call(cs, parts, true);
}

/* For when we are submitting information that is not important and don't care
 * about the response. */
void json_rpc_msg(connsock_t *cs, const char *rpc_req)
{
    struct rpc_req_part parts[] = {
        { rpc_req, strlen(rpc_req) },
        { NULL, 0 }
    };
    json_t *val = my_json_rpc_call(cs, parts, true);

    /* We don't care about the result */
    json_decref(val);
}

static void terminate_oldpid(const pool_t *ckp, proc_instance_t *pi, const pid_t oldpid)
{
    if (!ckp->killold) {
        quit(1, "Process %s pid %d still exists, start "POOL_PROGNAME" with -H to get a handover or -k if you wish to kill it",
                pi->processname, oldpid);
    }
    LOGNOTICE("Terminating old process %s pid %d", pi->processname, oldpid);
    if (kill_pid(oldpid, 15))
        quit(1, "Unable to kill old process %s pid %d", pi->processname, oldpid);
    LOGWARNING("Terminating old process %s pid %d", pi->processname, oldpid);
    if (pid_wait(oldpid, 500))
        return;
    LOGWARNING("Old process %s pid %d failed to respond to terminate request, killing",
            pi->processname, oldpid);
    if (kill_pid(oldpid, 9) || !pid_wait(oldpid, 3000))
        quit(1, "Unable to kill old process %s pid %d", pi->processname, oldpid);
}

/* This is for blocking sends of json messages */
bool send_json_msg(connsock_t *cs, const json_t *json_msg)
{
    int len, sent;
    char *s;

    s = json_dumps(json_msg, JSON_ESCAPE_SLASH | JSON_EOL);
    LOGDEBUG("Sending json msg: %s", s);
    len = strlen(s);
    sent = write_socket(cs->fd, s, len);
    dealloc(s);
    if (sent != len) {
        LOGNOTICE("Failed to send %d bytes sent %d in send_json_msg", len, sent);
        return false;
    }
    return true;
}

/* Decode a string that should have a json message and return just the contents
 * of the result key or NULL. */
static json_t *json_result(json_t *val)
{
    json_t *res_val = NULL, *err_val;

    res_val = json_object_get(val, "result");
    /* (null) is a valid result while no value is an error, so mask out
     * (null) and only handle lack of result */
    if (json_is_null(res_val))
        res_val = NULL;
    else if (!res_val) {
        char *ss;

        err_val = json_object_get(val, "error");
        if (err_val)
            ss = json_dumps(err_val, 0);
        else
            ss = strdup("(unknown reason)");

        LOGNOTICE("JSON-RPC decode of json_result failed: %s", ss);
        free(ss);
    }
    return res_val;
}

/* Return the error value if one exists */
static json_t *json_errval(json_t *val)
{
    json_t *err_val = json_object_get(val, "error");

    return err_val;
}

/* Parse a string and return the json value it contains, if any, and the
 * result in res_val. Return NULL if no result key is found. */
json_t *json_msg_result(const char *msg, json_t **res_val, json_t **err_val)
{
    json_error_t err;
    json_t *val;

    *res_val = NULL;
    val = json_loads(msg, 0, &err);
    if (!val) {
        LOGWARNING("Json decode failed(%d): %s", err.line, err.text);
        goto out;
    }
    *res_val = json_result(val);
    *err_val = json_errval(val);

out:
    return val;
}

/* Open the file in path, check if there is a pid in there that still exists
 * and if not, write the pid into that file. */
static bool write_pid(pool_t *ckp, const char *path, proc_instance_t *pi, const pid_t pid, const pid_t oldpid)
{
    FILE *fp;

    if (ckp->handover && oldpid && !pid_wait(oldpid, 500)) {
        LOGWARNING("Old process pid %d failed to shutdown cleanly, terminating", oldpid);
        terminate_oldpid(ckp, pi, oldpid);
    }

    fp = fopen(path, "we");
    if (!fp) {
        LOGERR("Failed to open file %s", path);
        return false;
    }
    fprintf(fp, "%d", pid);
    fclose(fp);

    return true;
}

static void name_process_sockname(unixsock_t *us, const proc_instance_t *pi)
{
    us->path = strdup(pi->ckp->socket_dir);
    realloc_strcat(&us->path, pi->sockname);
}

static void open_process_sock(pool_t *ckp, const proc_instance_t *pi, unixsock_t *us)
{
    LOGDEBUG("Opening %s", us->path);
    us->sockd = open_unix_server(us->path);
    if (unlikely(us->sockd < 0))
        quit(1, "Failed to open %s socket", pi->sockname);
    if (chown(us->path, -1, ckp->gr_gid))
        quit(1, "Failed to set %s to group id %d", us->path, ckp->gr_gid);
}

static void create_process_unixsock(proc_instance_t *pi)
{
    unixsock_t *us = &pi->us;
    pool_t *ckp = pi->ckp;

    name_process_sockname(us, pi);
    open_process_sock(ckp, pi, us);
}

static void write_namepid(proc_instance_t *pi)
{
    char s[256];

    pi->pid = getpid();
    sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
    if (!write_pid(pi->ckp, s, pi, pi->pid, pi->oldpid))
        quit(1, "Failed to write %s pid %d", pi->processname, pi->pid);
}

static void rm_namepid(const proc_instance_t *pi)
{
    char s[256];

    sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
    unlink(s);
}

static void launch_logger(pool_t *ckp)
{
    ckp->logger = create_ckmsgq(ckp, "logger", &proclog);
    ckp->console_logger = create_ckmsgq(ckp, "conlog", &console_log);
    // spin waiting for a time for loggers to be alive before proceeding.
    for (int backoff = 1; !ckp->logger->active && !ckp->console_logger->active; backoff <<= 1) {
        if (backoff >= 16384)
            quit(1, "Timed out waiting for logger threads to start, exiting!");
        cksleep_ms(backoff);
    }
    if (ckp->daemon) {
        // daemon mode -- we have no need for stdout/stderr/stdin anymore since we have
        // successfully launched the loggers.  Replace these fd's to be safe.
        int fd = open("/dev/null",O_RDWR, 0);
        if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
        }
    }
}

static void clean_up(pool_t *ckp)
{
    rm_namepid(&ckp->main);
    dealloc(ckp->socket_dir);
}

static pthread_t quitter_thread;
static int quit_signal = 0;  // sighandler uses this to communicate to quitter_thread_func the signal that was actually received

static void *quitter_thread_func(void *arg)
{
#define handle_error(en, msg) do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)
    sigset_t set;
    int s, dummy;
    pool_t *ckp = (pool_t *)arg;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    s = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (s != 0)
        handle_error(s, "pthread_sigmask");

    // wait for a signal to arrive from sighandler
    s = sigwait(&set, &dummy);
    if (s != 0)
        handle_error(s, "sigwait");

    // we were woken up and notified by sighandler that we should quit
    signal(quit_signal, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    LOGWARNING("\n-- Process %s received signal %d, shutting down", ckp->name, quit_signal);
    pthread_cancel(ckp->pth_listener);
    usleep(250000); // wait for printing, cancel to take effect
    exit(0);
    return NULL; // not reached
#undef handle_error
}

static void sighandler(const int sig)
{
    quit_signal = sig;
    // signal thread to wake and exit app gracefully
    // according to POSIX, pthread_kill is signal safe
    // see: https://man7.org/linux/man-pages/man7/signal-safety.7.html
    pthread_kill(quitter_thread, SIGUSR2);
}

static bool my_json_get_string(char **store, const json_t *entry, const char *res)
{
    bool ret = false;
    const char *buf;

    *store = NULL;
    if (!entry || json_is_null(entry)) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_string(entry)) {
        LOGWARNING("Json entry %s is not a string", res);
        goto out;
    }
    buf = json_string_value(entry);
    *store = strdup(buf);
    LOGDEBUG("Json found entry %s: %s", res, buf);
    ret = true;
out:
    return ret;
}

bool json_get_string(char **store, const json_t *val, const char *res)
{
    return my_json_get_string(store, json_object_get(val, res), res);
}

bool json_get_int64(int64_t *store, const json_t *val, const char *res)
{
    json_t *entry = json_object_get(val, res);
    bool ret = false;

    if (!entry) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_integer(entry)) {
        LOGINFO("Json entry %s is not an integer", res);
        goto out;
    }
    *store = json_integer_value(entry);
    LOGDEBUG("Json found entry %s: %"PRId64, res, *store);
    ret = true;
out:
    return ret;
}

bool json_get_int(int *store, const json_t *val, const char *res)
{
    json_t *entry = json_object_get(val, res);
    bool ret = false;

    if (!entry) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_integer(entry)) {
        LOGWARNING("Json entry %s is not an integer", res);
        goto out;
    }
    *store = json_integer_value(entry);
    LOGDEBUG("Json found entry %s: %d", res, *store);
    ret = true;
out:
    return ret;
}

bool json_get_double(double *store, const json_t *val, const char *res)
{
    json_t *entry = json_object_get(val, res);
    bool ret = false;

    if (!entry) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_real(entry)) {
        LOGWARNING("Json entry %s is not a double", res);
        goto out;
    }
    *store = json_real_value(entry);
    LOGDEBUG("Json found entry %s: %f", res, *store);
    ret = true;
out:
    return ret;
}

bool json_get_uint32(uint32_t *store, const json_t *val, const char *res)
{
    json_t *entry = json_object_get(val, res);
    bool ret = false;

    if (!entry) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_integer(entry)) {
        LOGWARNING("Json entry %s is not an integer", res);
        goto out;
    }
    *store = json_integer_value(entry);
    LOGDEBUG("Json found entry %s: %u", res, *store);
    ret = true;
out:
    return ret;
}

bool json_get_bool(bool *store, const json_t *val, const char *res)
{
    json_t *entry = json_object_get(val, res);
    bool ret = false;

    if (!entry) {
        LOGDEBUG("Json did not find entry %s", res);
        goto out;
    }
    if (!json_is_boolean(entry)) {
        LOGINFO("Json entry %s is not a boolean", res);
        goto out;
    }
    *store = json_is_true(entry);
    LOGDEBUG("Json found entry %s: %s", res, *store ? "true" : "false");
    ret = true;
out:
    return ret;
}

bool json_getdel_int(int *store, json_t *val, const char *res)
{
    bool ret;

    ret = json_get_int(store, val, res);
    if (ret)
        json_object_del(val, res);
    return ret;
}

bool json_getdel_int64(int64_t *store, json_t *val, const char *res)
{
    bool ret;

    ret = json_get_int64(store, val, res);
    if (ret)
        json_object_del(val, res);
    return ret;
}

static void parse_btcds(pool_t *ckp, const json_t *arr_val, const int arr_size)
{
    json_t *val;
    int i;

    assert(arr_size > 0);
    ckp->btcds = arr_size;
    ckp->btcdurl = ckzalloc(sizeof(char *) * arr_size);
    ckp->btcdauth = ckzalloc(sizeof(char *) * arr_size);
    ckp->btcdpass = ckzalloc(sizeof(char *) * arr_size);
    ckp->btcdnotify = ckzalloc(sizeof(bool *) * arr_size);
    ckp->btcdzmqblock = ckzalloc(sizeof(char *) * arr_size);
    for (i = 0; i < arr_size; i++) {
        val = json_array_get(arr_val, i);
        json_get_string(&ckp->btcdurl[i], val, "url");
        json_get_string(&ckp->btcdauth[i], val, "auth");
        json_get_string(&ckp->btcdpass[i], val, "pass");
        json_get_bool(&ckp->btcdnotify[i], val, "notify");
        char *zmq = NULL;
        // "zmq", "zmqblock", or "zmqpubhashblock" are equivalent
        if (json_get_string(&zmq, val, "zmq")
                || json_get_string(&zmq, val, "zmqblock")
                || json_get_string(&zmq, val, "zmqpubhashblock")) {
            ckp->btcdzmqblock[i] = zmq;
        }
    }
}

static void assert_json_get_ok(bool b, const char *obj, const char *key)
{
    if (!b) {
        quit(1, "Required key '%s' in json object '%s' missing!", key ? key : "null", obj ? obj : "null");
    }
}

static void parse_proxies(pool_t *ckp, const json_t *arr_val, const int arr_size)
{
    json_t *val;
    int i;

    ckp->proxies = arr_size;
    ckp->proxyurl = ckzalloc(sizeof(char *) * arr_size);
    ckp->proxyauth = ckzalloc(sizeof(char *) * arr_size);
    ckp->proxypass = ckzalloc(sizeof(char *) * arr_size);
    for (i = 0; i < arr_size; i++) {
        val = json_array_get(arr_val, i);
        // we need to use this assert boilerplate here because
        // downstream code assumes all these pointers are valid
        // and never checks for NULL, hence segfaults.
        assert_json_get_ok(
            json_get_string(&ckp->proxyurl[i], val, "url"),
            "proxies", "url" );
        assert_json_get_ok(
            json_get_string(&ckp->proxyauth[i], val, "auth"),
            "proxies", "auth" );
        assert_json_get_ok(
            json_get_string(&ckp->proxypass[i], val, "pass"),
            "proxies", "pass" );
    }
}

static bool parse_serverurls(pool_t *ckp, const json_t *arr_val)
{
    bool ret = false;
    int arr_size, i;

    if (!arr_val)
        goto out;
    if (!json_is_array(arr_val)) {
        LOGINFO("Unable to parse serverurl entries as an array");
        goto out;
    }
    arr_size = json_array_size(arr_val);
    if (!arr_size) {
        LOGWARNING("Serverurl array empty");
        goto out;
    }
    ckp->serverurls = arr_size;
    ckp->serverurl = ckalloc(sizeof(char *) * arr_size);
    ckp->nodeserver = ckzalloc(sizeof(bool) * arr_size);
    ckp->trusted = ckzalloc(sizeof(bool) * arr_size);
    for (i = 0; i < arr_size; i++) {
        json_t *val = json_array_get(arr_val, i);

        if (!my_json_get_string(&ckp->serverurl[i], val, "serverurl"))
            LOGWARNING("Invalid serverurl entry number %d", i);
    }
    ret = true;
out:
    return ret;
}

static void parse_nodeservers(pool_t *ckp, const json_t *arr_val)
{
    int arr_size, i, j, total_urls;

    if (!arr_val)
        return;
    if (!json_is_array(arr_val)) {
        LOGWARNING("Unable to parse nodeservers entries as an array");
        return;
    }
    arr_size = json_array_size(arr_val);
    if (!arr_size) {
        LOGWARNING("Nodeserver array empty");
        return;
    }
    total_urls = ckp->serverurls + arr_size;
    ckp->serverurl = realloc(ckp->serverurl, sizeof(char *) * total_urls);
    ckp->nodeserver = realloc(ckp->nodeserver, sizeof(bool) * total_urls);
    ckp->trusted = realloc(ckp->trusted, sizeof(bool) * total_urls);
    for (i = 0, j = ckp->serverurls; j < total_urls; i++, j++) {
        json_t *val = json_array_get(arr_val, i);

        if (!my_json_get_string(&ckp->serverurl[j], val, "nodeserver"))
            LOGWARNING("Invalid nodeserver entry number %d", i);
        ckp->nodeserver[j] = true;
        ckp->nodeservers++;
    }
    ckp->serverurls = total_urls;
}

static void parse_trusted(pool_t *ckp, const json_t *arr_val)
{
    int arr_size, i, j, total_urls;

    if (!arr_val)
        return;
    if (!json_is_array(arr_val)) {
        LOGWARNING("Unable to parse trusted server entries as an array");
        return;
    }
    arr_size = json_array_size(arr_val);
    if (!arr_size) {
        LOGWARNING("Trusted array empty");
        return;
    }
    total_urls = ckp->serverurls + arr_size;
    ckp->serverurl = realloc(ckp->serverurl, sizeof(char *) * total_urls);
    ckp->nodeserver = realloc(ckp->nodeserver, sizeof(bool) * total_urls);
    ckp->trusted = realloc(ckp->trusted, sizeof(bool) * total_urls);
    for (i = 0, j = ckp->serverurls; j < total_urls; i++, j++) {
        json_t *val = json_array_get(arr_val, i);

        if (!my_json_get_string(&ckp->serverurl[j], val, "trusted"))
            LOGWARNING("Invalid trusted server entry number %d", i);
        ckp->trusted[j] = true;
    }
    ckp->serverurls = total_urls;
}


static bool parse_redirecturls(pool_t *ckp, const json_t *arr_val)
{
    bool ret = false;
    int arr_size, i;
    char *redirecturl, url[INET6_ADDRSTRLEN], port[8];
    redirecturl = alloca(INET6_ADDRSTRLEN);

    if (!arr_val)
        goto out;
    if (!json_is_array(arr_val)) {
        LOGNOTICE("Unable to parse redirecturl entries as an array");
        goto out;
    }
    arr_size = json_array_size(arr_val);
    if (!arr_size) {
        LOGWARNING("redirecturl array empty");
        goto out;
    }
    ckp->redirecturls = arr_size;
    ckp->redirecturl = ckalloc(sizeof(char *) * arr_size);
    ckp->redirectport = ckalloc(sizeof(char *) * arr_size);
    for (i = 0; i < arr_size; i++) {
        json_t *val = json_array_get(arr_val, i);

        strncpy(redirecturl, json_string_value(val), INET6_ADDRSTRLEN - 1);
        /* See that the url properly resolves */
        if (!url_from_serverurl(redirecturl, url, port))
            quit(1, "Invalid redirecturl entry %d %s", i, redirecturl);
        ckp->redirecturl[i] = strdup(strsep(&redirecturl, ":"));
        ckp->redirectport[i] = strdup(port);
    }
    ret = true;
out:
    return ret;
}

static void parse_mindiff_overrides(pool_t *ckp, json_t *obj, const size_t n_keys)
{
    if (!n_keys || !obj || !ckp) return; // paranoia
    mindiff_override_t *arr = ckzalloc(sizeof(mindiff_override_t) * n_keys);
    size_t n_ok = 0;
    for (void *it = json_object_iter(obj); it; it = json_object_iter_next(obj, it)) {
        const char * const useragent = json_object_iter_key(it);
        const json_t * const jval = json_object_iter_value(it);
        int64_t mindiff = 0;
        if (json_is_integer(jval))
            mindiff = json_integer_value(jval);
        else if (json_is_real(jval))
            mindiff = json_real_value(jval);
        if (mindiff > 0 && useragent && *useragent) {
            if (mindiff <= ckp->mindiff || (ckp->maxdiff > 0 && mindiff > ckp->maxdiff)) {
                // ignore mindiff overrides above global maximum or below global minimum
                LOGWARNING("mindiff_overrides: override value %"PRId64" for \"%s\" is out of range of global maximum/minimum set in config, skipping",
                           mindiff, useragent);
                continue;
            }
            arr[n_ok].useragent = strdup(useragent);
            arr[n_ok].ualen = strlen(arr[n_ok].useragent); // cache strlen to save cycles later
            arr[n_ok].mindiff = mindiff;
            ++n_ok;
        }  else {
            LOGWARNING("mindiff_overrides: failed to parse \"%s\", expected numeric value > 0", useragent ? useragent : "");
        }
        assert(n_ok <= n_keys);
    }
    if (n_ok) {
        // Save info to ckp struct. Note we are being stingy with memory here and we realloc
        // the array to the smaller size, just to be tidy.
        ckp->mindiff_overrides = realloc(arr, sizeof(mindiff_override_t) * n_ok);
        if (unlikely(!ckp->mindiff_overrides))
            // realloc failure on startup.. this can't be good -- just re-use array.
            ckp->mindiff_overrides = arr;
        ckp->n_mindiff_overrides = n_ok;
        // debug sanity check, print out to log what we parsed
        for (size_t i = 0; i < n_ok; ++i) {
            LOGDEBUG("mindiff_overrides: parsed \"%s\" mindiff %"PRId64,
                     ckp->mindiff_overrides[i].useragent,
                     ckp->mindiff_overrides[i].mindiff);
        }
        LOGDEBUG("mindiff_overrides: %d override(s) parsed ok", (int)ckp->n_mindiff_overrides);
    } else
        dealloc(arr); // none parsed, just free memory for the pre-allocated array.
}

static void parse_fee_discounts(pool_t *ckp, json_t *obj, const size_t n_keys)
{
    if (!n_keys || !obj || !ckp) return; // paranoia
    for (void *it = json_object_iter(obj); it; it = json_object_iter_next(obj, it)) {
        const char * const username = json_object_iter_key(it);
        const json_t * const jval = json_object_iter_value(it);
        double discount = -1.;
        if (json_is_real(jval))
            discount = json_real_value(jval);
        if (discount < 0.0 || discount > 1.0 || !username || !*username) {
            quit(1, "fee_discounts: Bad entry \"%s\". Fix your config file!", username ? username : "");
        }
        user_fee_discount_t *ufd = NULL;
        HASH_FIND_STR(ckp->user_fee_discounts, username, ufd);
        if (ufd) {
            quit(1, "fee_discounts: Dupe entry \"%s\". Fix your config file!", username);
        }

        ufd = ckzalloc(sizeof(user_fee_discount_t));
        ufd->username = strdup(username);
        ufd->discount = discount;
        HASH_ADD_STR(ckp->user_fee_discounts, username, ufd);
        LOGDEBUG("fee_discounts: Parsed discount \"%s\" -> %0.3f", username, discount);
    }
}

// Returns a value from 0.0 (no discount) to 1.0 (full discount) for a particular
// username.  This is set in the config file as a dict named "fee_discounts".
// Called by stratifier.c when creating a user_instance_t.
double username_get_fee_discount(pool_t *ckp, const char *username)
{
    double discount = 0.;
    user_fee_discount_t *ufd = NULL;
    HASH_FIND_STR(ckp->user_fee_discounts, username, ufd);
    if (ufd) {
        discount = ufd->discount;
        LOGDEBUG("fee_discounts: User \"%s\" has discount: %0.3f", username, discount);
    }
    return discount;
}

static void parse_bchsigs(pool_t *ckp, json_t *obj)
{
    if (!obj)
        return;
    if (json_is_string(obj)) {
        // single item string
        ckp->n_bchsigs = 1;
        ckp->bchsigs = ckzalloc(sizeof(*ckp->bchsigs));
        const bool res = my_json_get_string(&ckp->bchsigs[0].sig, obj, "bchsig");
        assert(res);
        normalize_bchsig(ckp->bchsigs[0].sig, &ckp->bchsigs[0].siglen); // modifies buffer in-place, noop if NULL
    } else if (json_is_array(obj)) {
        // array of strings (may be empty)
        const int array_len = json_array_size(obj);
        ckp->bchsigs = array_len ? ckzalloc(array_len * sizeof(*ckp->bchsigs)) : NULL;
        for (int i = 0; i < array_len; ++i) {
            char namebuf[24];
            json_t *item = json_array_get(obj, i);
            snprintf(namebuf, 24, "bchsig[%d]", i);
            if (!my_json_get_string(&ckp->bchsigs[i].sig, item, namebuf)) {
                quit(1, "\"bchsig\" entry %d is invalid, expected string", i);
            }
            normalize_bchsig(ckp->bchsigs[i].sig, &ckp->bchsigs[i].siglen); // modifies buffer in-place, noop if NULL
            ++ckp->n_bchsigs;
        }
    } else {
        quit(1, "\"bchsig\" is invalid. Expected a single string or an array of strings.");
    }
}

static void parse_config(pool_t *ckp)
{
    json_t *json_conf, *arr_val;
    json_error_t err_val;
    char *url, *vmask;
    int arr_size;

    json_conf = json_load_file(ckp->config, JSON_DISABLE_EOF_CHECK, &err_val);
    if (!json_conf) {
        LOGWARNING("Json decode error for config file %s: (%d): %s", ckp->config,
               err_val.line, err_val.text);
        return;
    }
    arr_val = json_object_get(json_conf, "btcd");
    if (arr_val && json_is_array(arr_val)) {
        arr_size = json_array_size(arr_val);
        if (arr_size)
            parse_btcds(ckp, arr_val, arr_size);
    }
    // Obsolete key detection (keys were renamed from btc* to bch*)
    if (json_object_get(json_conf, "btcaddress"))
        quit(1, "\"btcaddress\" key has been renamed to \"bchaddress\". Please update your config file!");
    if (json_object_get(json_conf, "btcsig"))
        quit(1, "\"btcsig\" key has been renamed to \"bchsig\". Please update your config file!");
    // /End obsolete key detection
    json_get_string(&ckp->bchaddress, json_conf, "bchaddress");
    json_get_string(&ckp->single_payout_override, json_conf, "single_payout_override");
    // bchsig
    parse_bchsigs(ckp, json_object_get(json_conf, "bchsig"));
    // pool_fee
    if (! json_get_double(&ckp->pool_fee, json_conf, "pool_fee") ) {
        ckp->pool_fee = 1.0; // default fee is 1%
    } else {
        // verify sanity
        if (ckp->pool_fee < 0.0) ckp->pool_fee = 0.0;
        else if (ckp->pool_fee > 100.0) ckp->pool_fee = 100.0;
    }
    json_get_int(&ckp->blockpoll, json_conf, "blockpoll");
    json_get_int(&ckp->nonce1length, json_conf, "nonce1length");
    json_get_int(&ckp->nonce2length, json_conf, "nonce2length");
    json_get_int(&ckp->update_interval, json_conf, "update_interval");
    json_get_string(&vmask, json_conf, "version_mask");
    if (vmask && strlen(vmask) && validhex(vmask))
        sscanf(vmask, "%x", &ckp->version_mask);
    else
        ckp->version_mask = 0x1fffe000;
    /* Look for an array first and then a single entry */
    arr_val = json_object_get(json_conf, "serverurl");
    if (!parse_serverurls(ckp, arr_val)) {
        if (json_get_string(&url, json_conf, "serverurl")) {
            ckp->serverurl = ckalloc(sizeof(char *));
            ckp->serverurl[0] = url;
            ckp->serverurls = 1;
        }
    }
    arr_val = json_object_get(json_conf, "nodeserver");
    parse_nodeservers(ckp, arr_val);
    arr_val = json_object_get(json_conf, "trusted");
    parse_trusted(ckp, arr_val);
    json_get_string(&ckp->upstream, json_conf, "upstream");
    json_get_int64(&ckp->mindiff, json_conf, "mindiff");
    json_get_int64(&ckp->startdiff, json_conf, "startdiff");
    json_get_int64(&ckp->maxdiff, json_conf, "maxdiff");
    {
        // parse mindiff_overrides -- this must be called after mindiff and maxdiff above are already set up
        json_t * obj = json_object_get(json_conf, "mindiff_overrides");
        if (obj) {
            size_t n_keys = 0;
            if (!json_is_object(obj)) {
                LOGWARNING("\"mindiff_overrides\" invalid, expected object, e.g. { ... } ");
            } else if ((n_keys = json_object_size(obj))) {
                parse_mindiff_overrides(ckp, obj, n_keys);
            }
        }
    }
    {
        // parse fee_discounts
        json_t * obj = json_object_get(json_conf, "fee_discounts");
        if (obj) {
            size_t n_keys = 0;
            if (!json_is_object(obj)) {
                LOGWARNING("\"fee_discounts\" invalid, expected object, e.g. { ... } ");
            } else if ((n_keys = json_object_size(obj))) {
                parse_fee_discounts(ckp, obj, n_keys);
            }
        }
    }
    json_get_string(&ckp->logdir, json_conf, "logdir");
    json_get_int(&ckp->maxclients, json_conf, "maxclients");
    arr_val = json_object_get(json_conf, "proxy");
    if (arr_val && json_is_array(arr_val)) {
        arr_size = json_array_size(arr_val);
        if (arr_size)
            parse_proxies(ckp, arr_val, arr_size);
    }
    arr_val = json_object_get(json_conf, "redirecturl");
    if (arr_val)
        parse_redirecturls(ckp, arr_val);

    json_get_bool(&ckp->disable_dev_donation, json_conf, "disable_dev_donation");

    {
        // parse blocking_timeout
        int64_t blocking_timeout = 0;
        if (!json_get_int64(&blocking_timeout, json_conf, "blocking_timeout") || blocking_timeout < 1)
            blocking_timeout = 60; // default: 60 seconds
        ckp->blocking_timeout = (time_t)blocking_timeout;
        LOGDEBUG("blocking_timeout: %" PRId64 " seconds", (int64_t)ckp->blocking_timeout);
        if (ckp->blocking_timeout < 10)
            LOGWARNING("blocking_timeout of %" PRId64 " seconds is very low!", (int64_t)ckp->blocking_timeout);
    }

    json_decref(json_conf);
}

static void manage_old_instance(pool_t *ckp, proc_instance_t *pi)
{
    struct stat statbuf;
    char path[256];
    FILE *fp;

    sprintf(path, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
    if (!stat(path, &statbuf)) {
        int oldpid, ret;

        LOGNOTICE("File %s exists", path);
        fp = fopen(path, "re");
        if (!fp)
            quit(1, "Failed to open file %s", path);
        ret = fscanf(fp, "%d", &oldpid);
        fclose(fp);
        if (ret == 1 && !(kill_pid(oldpid, 0))) {
            LOGNOTICE("Old process %s pid %d still exists", pi->processname, oldpid);
            if (ckp->handover) {
                LOGINFO("Saving pid to be handled at handover");
                pi->oldpid = oldpid;
                return;
            }
            terminate_oldpid(ckp, pi, oldpid);
        }
    }
}

static void prepare_child(pool_t *ckp, proc_instance_t *pi, void *process, char *name)
{
    pi->ckp = ckp;
    pi->processname = name;
    pi->sockname = pi->processname;
    create_process_unixsock(pi);
    create_pthread(&pi->pth_process, process, pi);
    create_unix_receiver(pi);
}

static struct option long_options[] = {
    {"solo",        no_argument,       0,    'B'},
    {"config",      required_argument, 0,    'c'},
    {"daemonise",   no_argument,       0,    'D'},
    {"group",       required_argument, 0,    'g'},
    {"handover",    no_argument,       0,    'H'},
    {"help",        no_argument,       0,    'h'},
    {"killold",     no_argument,       0,    'k'},
    {"log-shares",  no_argument,       0,    'L'},
    {"loglevel",    required_argument, 0,    'l'},
    {"name",        required_argument, 0,    'n'},
    {"node",        no_argument,       0,    'N'},
    {"passthrough", no_argument,       0,    'P'},
    {"proxy",       no_argument,       0,    'p'},
    {"quiet",       no_argument,       0,    'q'},
    {"redirector",  no_argument,       0,    'R'},
    {"sockdir",     required_argument, 0,    's'},
    {"tslocal",     no_argument,       0,    'T'},
    {"trusted",     no_argument,       0,    't'},
    {"userproxy",   no_argument,       0,    'u'},
    {"version",     no_argument,       0,    'v'},
    {0, 0, 0, 0}
};

static bool send_recv_path(const char *path, const char *msg)
{
    int sockd = open_unix_client(path);
    bool ret = false;
    char *response;

    send_unix_msg(sockd, msg);
    response = recv_unix_msg(sockd);
    if (response) {
        ret = true;
        LOGWARNING("Received: %s in response to %s request", response, msg);
        dealloc(response);
    } else
        LOGWARNING("Received no response to %s request", msg);
    Close(sockd);
    return ret;
}

static const char *banner_string(void)
{
    return PACKAGE_STRING " - " PACKAGE_BUGREPORT;
}

#if defined(__APPLE__) && defined(__MACH__) && defined(__clang__)
// Public domain polyfill for feenableexcept on OS X
// http://www-personal.umich.edu/~williams/archive/computation/fe-handling-example.c
static int feenableexcept(unsigned int excepts)
{
    static fenv_t fenv;
    unsigned int new_excepts = excepts & FE_ALL_EXCEPT;
    // previous masks
    unsigned int old_excepts;

    if (fegetenv(&fenv)) {
        return -1;
    }
    old_excepts = fenv.__control & FE_ALL_EXCEPT;

    // unmask
    fenv.__control &= ~new_excepts;
    fenv.__mxcsr   &= ~(new_excepts << 7);

    return fesetenv(&fenv) ? -1 : old_excepts;
}
#endif

int main(int argc, char **argv)
{
    struct sigaction handler;
    int c, ret, i = 0, j;
    char buf[512] = {0};
    pool_t ckp;

    /* Make significant floating point errors fatal to avoid subtle bugs being missed */
    feenableexcept(FE_DIVBYZERO | FE_INVALID);
    json_set_alloc_funcs(json_ckalloc, free);

    global_ckp = &ckp;
    global_loglevel_ptr = &ckp.loglevel; // set the pointer to suppress verbose logs efficiently
    memset(&ckp, 0, sizeof(ckp));
    ckp.starttime = time(NULL);
    ckp.startpid = getpid();
    ckp.loglevel = LOG_NOTICE;
    ckp.initial_args = ckalloc(sizeof(char *) * (argc + 2)); /* Leave room for extra -H */
    for (ckp.args = 0; ckp.args < argc; ckp.args++)
        ckp.initial_args[ckp.args] = strdup(argv[ckp.args]);
    ckp.initial_args[ckp.args] = NULL;

    while ((c = getopt_long(argc, argv, "ABc:Dg:HhkLl:Nn:PpqRs:Ttuv", long_options, &i)) != -1) {
        switch (c) {
            case 'A':
                /* legacy compat. */
                fprintf(stderr, "Warning: Since ckdb has been removed, `-A` option is always active; ignoring `-A` from command-line.\n");
                break;
            case 'B':
                ckp.solo = true;
                break;
            case 'c':
                ckp.config = optarg;
                break;
            case 'D':
                ckp.daemon = true;
                break;
            case 'g':
                ckp.grpnam = optarg;
                break;
            case 'H':
                ckp.handover = true;
                ckp.killold = true;
                break;
            case 'h':
                for (j = 0; long_options[j].val; j++) {
                    struct option *jopt = &long_options[j];

                    if (jopt->has_arg) {
                        char *upper = alloca(strlen(jopt->name) + 1);
                        int offset = 0;

                        do {
                            upper[offset] = toupper(jopt->name[offset]);
                        } while (upper[offset++] != '\0');
                        printf("-%c %s | --%s %s\n", jopt->val,
                               upper, jopt->name, upper);
                    } else
                        printf("-%c | --%s\n", jopt->val, jopt->name);
                }
                exit(0);
            case 'k':
                ckp.killold = true;
                break;
            case 'L':
                ckp.logshares = true;
                break;
            case 'l':
                ckp.loglevel = atoi(optarg);
                if (ckp.loglevel < LOG_EMERG || ckp.loglevel > LOG_DEBUG) {
                    quit(1, "Invalid loglevel (range %d - %d): %d",
                         LOG_EMERG, LOG_DEBUG, ckp.loglevel);
                }
                break;
            case 'N':
                if (ckp.proxy || ckp.redirector || ckp.userproxy || ckp.passthrough)
                    quit(1, "Cannot set another proxy type or redirector and node mode");
                ckp.proxy = ckp.passthrough = ckp.node = true;
                break;
            case 'n':
                ckp.name = optarg;
                break;
            case 'P':
                if (ckp.proxy || ckp.redirector || ckp.userproxy || ckp.node)
                    quit(1, "Cannot set another proxy type or redirector and passthrough mode");
                ckp.proxy = ckp.passthrough = true;
                break;
            case 'p':
                if (ckp.passthrough || ckp.redirector || ckp.userproxy || ckp.node)
                    quit(1, "Cannot set another proxy type or redirector and proxy mode");
                ckp.proxy = true;
                break;
            case 'q':
                ckp.quiet = true;
                break;
            case 'R':
                if (ckp.proxy || ckp.passthrough || ckp.userproxy || ckp.node)
                    quit(1, "Cannot set a proxy type or passthrough and redirector modes");
                ckp.proxy = ckp.passthrough = ckp.redirector = true;
                break;
            case 's':
                ckp.socket_dir = strdup(optarg);
                break;
            case 'T':
                ckp.localtime_logging = true;
                break;
            case 't':
                if (ckp.proxy)
                    quit(1, "Cannot set a proxy type and trusted remote mode");
                ckp.remote = true;
                break;
            case 'u':
                if (ckp.proxy || ckp.redirector || ckp.passthrough || ckp.node)
                    quit(1, "Cannot set both userproxy and another proxy type or redirector");
                ckp.userproxy = ckp.proxy = true;
                break;
            case 'v':
                printf("%s\n", banner_string());
                exit(0);
                break; // not reached
        }
    }

    if ((ckp.proxy || ckp.node || ckp.passthrough || ckp.redirector || ckp.remote) && ckp.solo) {
        quit(1, "Solo mode requires stand-alone/non-proxy/non-redirector/non-passhtrough/non-node mode.");
    }

    if (ckp.daemon) {
        // Daemonize immediately. We must do this before any threads are started because
        // fork() stops all other threads besides the calling thread.  Code previous to v1.0.2
        // had a bug here in that it daemonized too late, so we moved this call up to the top
        // immediately after parsing args when no threads are started.
        const pid_t pid = fork();

        if (pid > 0)
            // parent
            quit(0, "Daemonizing...");
        else if (unlikely(pid < 0))
            // fork error
            quit(1, "fork() system call failed, cannot daemonize");
        // child
        setsid();
    }

    if (!ckp.name) {
        if (ckp.node)
            ckp.name = NODE_PROGNAME;
        else if (ckp.redirector)
            ckp.name = REDIRECTOR_PROGNAME;
        else if (ckp.passthrough)
            ckp.name = PASSTHROUGH_PROGNAME;
        else if (ckp.proxy)
            ckp.name = PROXY_PROGNAME;
        else
            ckp.name = POOL_PROGNAME;
    }
    rename_proc(ckp.name);

    sha256_selftest(); // may exit if there is a problem
    cashaddr_selftest(); // won't exit app, will just warn if there's a problem

    if (ckp.grpnam) {
        struct group *group = getgrnam(ckp.grpnam);

        if (!group)
            quit(1, "Failed to find group %s", ckp.grpnam);
        ckp.gr_gid = group->gr_gid;
    } else
        ckp.gr_gid = getegid();

    if (!ckp.config) {
        ckp.config = strdup(ckp.name);
        realloc_strcat(&ckp.config, ".conf");
    }
    if (!ckp.socket_dir) {
        ckp.socket_dir = strdup("/tmp/");
        realloc_strcat(&ckp.socket_dir, ckp.name);
    }
    trail_slash(&ckp.socket_dir);

    // setup default chain and prefix
    {
        const size_t len1 = sizeof(ckp.chain);
        const size_t len2 = sizeof(ckp.cashaddr_prefix);
        assert(len1 && len2);
        strncpy(ckp.chain, "main", len1); ckp.chain[len1-1] = 0;
        strncpy(ckp.cashaddr_prefix, CASHADDR_PREFIX_MAIN, len2); ckp.cashaddr_prefix[len2-1] = 0;
    }

    /* Ignore sigpipe */
    signal(SIGPIPE, SIG_IGN);

    ret = mkdir(ckp.socket_dir, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make directory %s", ckp.socket_dir);

    parse_config(&ckp);
    /* Set defaults if not found in config file */
    if (!ckp.btcds) {
        ckp.btcds = 1;
        ckp.btcdurl = ckzalloc(sizeof(char *));
        ckp.btcdauth = ckzalloc(sizeof(char *));
        ckp.btcdpass = ckzalloc(sizeof(char *));
        ckp.btcdnotify = ckzalloc(sizeof(bool));
        ckp.btcdzmqblock = ckzalloc(sizeof(char *));
    }
    for (i = 0; i < ckp.btcds; i++) {
        if (!ckp.btcdurl[i])
            ckp.btcdurl[i] = strdup("localhost:8332");
        if (!ckp.btcdauth[i])
            ckp.btcdauth[i] = strdup("user");
        if (!ckp.btcdpass[i])
            ckp.btcdpass[i] = strdup("pass");
        if (ckp.btcdzmqblock[i]) {
            ckp.n_zmq_btcds++; // increment number of btcds using zmq
            ckp.btcdnotify[i] = true;  // if zmq is not NULL -> force set the notify flag (so we don't poll this btcd)
        }
        if (ckp.btcdnotify[i])
            ckp.n_notify_btcds++;
    }

    // refuse to proceed if single_payout_override is specified and solo mode is also specified
    if (ckp.single_payout_override && ckp.solo)
        quit(1, "Cannot use single_payout_override mode with SOLO mode (-B)");

    // set up donation addresses
    {
        ckp.dev_donations[0].address = (char *) DONATION_ADDRESS_CALIN;
        ckp.dev_donations[1].address = (char *) DONATION_ADDRESS_BCHN;
    }
    if (!ckp.bchaddress) {
        if (!ckp.proxy)
            // non-proxy: we require a valid bchaddress, so give up if no address is specified
            quit(0, "Please specify a bchaddress in the configuration file");
        else
            // in proxy mode we don't do any gbt so we don't equire a valid bchaddress; just fill in anything, such
            // as first dev donation, in order to not have this pointer be NULL
            ckp.bchaddress = ckp.dev_donations[0].address;
    }
    if (!ckp.blockpoll)
        ckp.blockpoll = 100;
    if (!ckp.nonce1length)
        ckp.nonce1length = 4;
    else if (ckp.nonce1length < 2 || ckp.nonce1length > 8)
        quit(0, "Invalid nonce1length %d specified, must be 2~8", ckp.nonce1length);
    if (!ckp.nonce2length) {
        /* nonce2length is zero by default in proxy mode */
        if (!ckp.proxy)
            ckp.nonce2length = 8;
    } else if (ckp.nonce2length < 2 || ckp.nonce2length > 8)
        quit(0, "Invalid nonce2length %d specified, must be 2~8", ckp.nonce2length);
    if (!ckp.update_interval)
        ckp.update_interval = 30;
    if (!ckp.mindiff)
        ckp.mindiff = 1;
    if (!ckp.startdiff)
        ckp.startdiff = 42;
    if (!ckp.logdir)
        ckp.logdir = strdup("logs");
    if (!ckp.serverurls)
        ckp.serverurl = ckzalloc(sizeof(char *));
    if (ckp.proxy && !ckp.proxies)
        quit(0, "No proxy entries found in config file %s", ckp.config);
    if (ckp.redirector && !ckp.redirecturls)
        quit(0, "No redirect entries found in config file %s", ckp.config);

    /* Create the log directory */
    trail_slash(&ckp.logdir);
    ret = mkdir(ckp.logdir, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make log directory %s", ckp.logdir);

    /* Create the workers logdir */
    sprintf(buf, "%s/workers", ckp.logdir);
    ret = mkdir(buf, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make workers log directory %s", buf);

    /* Create the user logdir */
    sprintf(buf, "%s/users", ckp.logdir);
    ret = mkdir(buf, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make user log directory %s", buf);

    /* Create the pool logdir */
    sprintf(buf, "%s/pool", ckp.logdir);
    ret = mkdir(buf, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make pool log directory %s", buf);

    sprintf(buf, "%s/pool/blocks", ckp.logdir);
    ret = mkdir(buf, 0750);
    if (ret && errno != EEXIST)
        quit(1, "Failed to make pool blocks log directory %s", buf);

    /* Create the logfile */
    ASPRINTF(&ckp.logfilename, "%s%s.log", ckp.logdir, ckp.name);
    if (!open_logfile(&ckp))
        quit(1, "Failed to make open log file %s", buf);
    launch_logger(&ckp); // note that at this point, if ckp.daemon is true, stdout, stderr, and stdin are all closed here.

    LOGNOTICE("%s", banner_string()); // print banner to log so users know what version was running

    LOGNOTICE("Using pool fee: %1.3f%%", ckp.pool_fee);
    for (int i = 0; i < ckp.n_bchsigs; ++i) {
        if (ckp.bchsigs[i].sig && *ckp.bchsigs[i].sig)
            LOGNOTICE("Using coinbase signature #%d: %s", i+1, ckp.bchsigs[i].sig);
    }
    if (ckp.solo) {
        LOGWARNING("Solo mode activated: miners that find a solution get the full block reward (minus pool fees)");
    }
    ckp.main.ckp = &ckp;
    ckp.main.processname = strdup("main");
    ckp.main.sockname = strdup("listener");
    name_process_sockname(&ckp.main.us, &ckp.main);
    ckp.oldconnfd = ckzalloc(sizeof(int *) * ckp.serverurls);
    manage_old_instance(&ckp, &ckp.main);
    if (ckp.handover) {
        const char *path = ckp.main.us.path;

        if (send_recv_path(path, "ping")) {
            for (i = 0; i < ckp.serverurls; i++) {
                char oldurl[INET6_ADDRSTRLEN], oldport[8];
                char getfd[16];
                int sockd;

                const int nprt = snprintf(getfd, 15, "getxfd%d", i);
                if (nprt >= 0) // we need to do check return of snprintf() to prevent compiler warning
                    getfd[MIN(nprt, 15)] = '\0';
                sockd = open_unix_client(path);
                if (sockd < 1)
                    break;
                if (!send_unix_msg(sockd, getfd))
                    break;
                ckp.oldconnfd[i] = get_fd(sockd);
                Close(sockd);
                sockd = ckp.oldconnfd[i];
                if (!sockd)
                    break;
                if (url_from_socket(sockd, oldurl, oldport)) {
                    LOGWARNING("Inherited old server socket %d url %s:%s !",
                           i, oldurl, oldport);
                } else {
                    LOGWARNING("Inherited old server socket %d with new file descriptor %d!",
                           i, ckp.oldconnfd[i]);
                }
            }
            send_recv_path(path, "reject");
            send_recv_path(path, "reconnect");
            send_recv_path(path, "shutdown");
        }
    }

    write_namepid(&ckp.main);
    open_process_sock(&ckp, &ckp.main, &ckp.main.us);

    {
        const mofr_t res = raise_max_open_files_to_hard_limit();
        if (!res.ok) {
            LOGWARNING("Failed to raise max open files: %s", res.err_msg);
        } else if (res.old_limit != res.new_limit) {
            LOGDEBUG("Raised max open files from %ld to %ld", res.old_limit, res.new_limit);
        }
    }

    ret = sysconf(_SC_OPEN_MAX);
    if (ckp.maxclients > ret * 9 / 10) {
        LOGWARNING("Cannot set maxclients to %d due to max open file limit of %d, reducing to %d",
               ckp.maxclients, ret, ret * 9 / 10);
        ckp.maxclients = ret * 9 / 10;
    } else if (!ckp.maxclients) {
        LOGNOTICE("Setting maxclients to %d due to max open file limit of %d",
              ret * 9 / 10, ret);
        ckp.maxclients = ret * 9 / 10;
    }

    // ckp.ckpapi = create_ckmsgq(&ckp, "api", &asicseer_pool_api);
    create_pthread(&ckp.pth_listener, listener, &ckp.main);

    create_pthread(&quitter_thread, quitter_thread_func, &ckp); // this does the actual quitting on Ctrl-C
    handler.sa_handler = &sighandler;
    handler.sa_flags = 0;
    sigemptyset(&handler.sa_mask);
    sigaction(SIGTERM, &handler, NULL);
    sigaction(SIGINT, &handler, NULL);
    sigaction(SIGQUIT, &handler, NULL);

    /* Launch separate processes from here */
    prepare_child(&ckp, &ckp.generator, generator, "generator");
    prepare_child(&ckp, &ckp.stratifier, stratifier, "stratifier");
    prepare_child(&ckp, &ckp.connector, connector, "connector");

    /* Shutdown from here if the listener is sent a shutdown message */
    if (ckp.pth_listener)
        join_pthread(ckp.pth_listener);

    clean_up(&ckp);

    return 0;
}
