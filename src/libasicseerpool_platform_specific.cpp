#define _GNU_SOURCE 1
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <random>
#include <thread>

#include "config.h"
#include "util_cxx.h"

#if HAVE_ARPA_INET_H && HAVE_NETINET_IN_H && HAVE_SYS_SOCKET_H && (HAVE_POLL_H || HAVE_SYS_POLL_H) && HAVE_UNISTD_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#  if HAVE_POLL_H
#    include <poll.h>
#  else
#    include <sys/poll.h>
#  endif
#include <unistd.h>
#endif

#include "libasicseerpool.h"

#if HAVE_SYS_EPOLL_H && HAVE_EPOLL
#include <sys/epoll.h>
#  define USE_EPOLL 1
#elif HAVE_SYS_EVENT_H && HAVE_KEVENT
#include <sys/event.h>
#  define USE_KEVENT 1
#else
#  error "Unsupported platform! FIXME!"
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h> // For prctl, PR_SET_NAME, PR_GET_NAME
#endif

#include <pthread.h>

#if HAVE_PTHREAD_NP_H
#include <pthread_np.h> // for pthread_*_np
#endif

namespace {
timespec normalize(timespec ret) noexcept
{
    if (auto absns = std::abs(ret.tv_nsec); absns >= 1'000'000'000L) {
        ret.tv_sec += ret.tv_nsec / 1'000'000'000L;
        ret.tv_nsec %= 1'000'000'000L;
    }
    if (ret.tv_nsec < 0) {
        long sec = std::ceil(std::fabs(ret.tv_nsec / 1e9));
        ret.tv_sec -= sec;
        ret.tv_nsec += sec * 1'000'000'000L;
    }
    return ret;
}

timespec operator-(const timespec &a, const timespec &b) noexcept
{
    return normalize(timespec{.tv_sec = a.tv_sec - b.tv_sec, .tv_nsec = a.tv_nsec - b.tv_nsec});
}

timespec operator+(const timespec &a, const timespec &b) noexcept
{
    return normalize(timespec{.tv_sec = a.tv_sec + b.tv_sec, .tv_nsec = a.tv_nsec + b.tv_nsec});
}

[[maybe_unused]]
double tsToSecs(const timespec &t) noexcept { return double(t.tv_sec) + double(t.tv_nsec / 1e9); }

std::timespec getMonotonicTime() noexcept {
    std::timespec t;
    if (unlikely(clock_gettime(CLOCK_MONOTONIC, &t) != 0)) {
        LOGERR("Got bad return value from clock_gettime CLOCK_MONOTONIC: %s", std::strerror(errno));
        timeval tv;
        gettimeofday(&tv, nullptr); // try again with gettimeofday...
        tv_to_ts(&t, &tv);
    }
    return t;
}

#if USE_KEVENT
enum class KFilt { Read, Write };
int emulate_epoll_using_kevent(KFilt kfilt, int sockd, float timeout, bool eof_only)
{
    // Emulate POLLRDHUP using kevent.. kind of awkward but it works
    int kq = kqueue();
    if (unlikely(kq < 0)) {
        LOGERR("kqueue returned %d", kq);
        return 0;
    }
    Defer d([kq]{ close(kq); });
    const char *verb = "???";
    int16_t filt = 0;
    if (kfilt == KFilt::Read) {
        verb = "read";
        filt = EVFILT_READ;
    } else if (kfilt == KFilt::Write) {
        verb = "write";
        filt = EVFILT_WRITE;
        if (eof_only) LOGWARNING("%s: EVFILT_WRITE with eof_only mode is not really supported. FIXME!", __func__);
    } else
        LOGERR("Got bad 'filter' arg to %s: %d", __func__, int(kfilt));
    struct kevent kev;
    const int fflags = eof_only ? NOTE_LOWAT: 0;
    const int data = eof_only ? 262144 /* read "low water mark" */ : 0;
    EV_SET(&kev, sockd, filt, EV_ADD | EV_CLEAR, fflags, data, nullptr);
    int r [[maybe_unused]] = kevent(kq, &kev, 1, nullptr, 0, nullptr);
    //LOGDEBUG("kevent(0) returned %d", r);
    std::memset(&kev, 0, sizeof(kev));
    const std::timespec ttimeout{.tv_sec = long(timeout), .tv_nsec = long(std::fmod(timeout, 1.0) * 1e9)};
    const timespec tstart = getMonotonicTime();
    for (;;) {
        const timespec tnow = getMonotonicTime();
        const timespec ts = (tstart + ttimeout) - tnow;
        //LOGDEBUG("%s on %d, mode: %s, timeout: %1.3f, eof_only: %d", __func__, sockd, verb, tsToSecs(ts), int(eof_only));
        r = kevent(kq, nullptr, 0, &kev, 1, &ts);
        //LOGDEBUG("kevent(1) returned %d (data: %lld)", r, static_cast<long long>(kev.data));
        if (r < 1) {
            if (unlikely(r == -1 && errno == EINTR)) {
                LOGDEBUG("%s: got just a signal, continuing to wait ...", __func__);
                continue; // signal arrived, try again
            }
            return 0;
        }
        // else ...
        if (eof_only && !(kev.flags & EV_EOF)) {
            // NB: this relies on EV_CLEAR to make things be edge-triggered and not level-triggered
            LOGDEBUG("%s: got just a %s event, but we are in \"eof_only\" mode, continuing to wait ...", __func__, verb);
            continue;
        }
        return 1;
    }
}
#endif

} // namespace

/* Wait till a socket has been closed at the other end */
// extern "C"
int wait_close(int sockd, int timeout)
{
    int ret;
#if USE_KEVENT /* macOS, BSD, etc */
    ret = emulate_epoll_using_kevent(KFilt::Read, sockd, timeout, true);
#elif USE_EPOLL /* Linux */
    struct pollfd sfd;

    if (unlikely(sockd < 0))
        return -1;
    sfd.fd = sockd;
    sfd.events = POLLRDHUP;
    sfd.revents = 0;
    timeout *= 1000;
    ret = poll(&sfd, 1, timeout);
    if (ret < 1)
        ret = 0;
    else
        ret = sfd.revents & (POLLHUP | POLLRDHUP | POLLERR);
#else
#error "Unsupported platform!"
#endif
    //LOGDEBUG("%s: returning %d", __func__, ret);
    return ret;
}

/* Emulate a select read wait for high fds that select doesn't support. */
// extern "C"
int wait_read_select(int sockd, float timeout)
{
#if USE_EPOLL /* Linux */
    struct epoll_event event = {0, {NULL}};
    int epfd, ret;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    event.events = EPOLLIN | EPOLLRDHUP;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sockd, &event);
    timeout *= 1000;
    for(;;) {
        ret = epoll_wait(epfd, &event, 1, timeout);
        if (unlikely(ret == -1 && errno == EINTR))
            continue;
        break;
    }
    close(epfd);
    return ret;
#elif USE_KEVENT /* macOS, BSD, etc */
    return emulate_epoll_using_kevent(KFilt::Read, sockd, timeout, false);
#else
#error "Unsupported platform!"
#endif
}

/* Emulate a select write wait for high fds that select doesn't support */
// extern "C"
int wait_write_select(int sockd, float timeout)
{
#if USE_EPOLL /* Linux */
    struct epoll_event event = {0, {NULL}};
    int epfd, ret;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    event.events = EPOLLOUT | EPOLLRDHUP ;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sockd, &event);
    timeout *= 1000;
    for(;;) {
        ret = epoll_wait(epfd, &event, 1, timeout);
        if (unlikely(ret == -1 && errno == EINTR))
            continue;
        break;
    }
    close(epfd);
    return ret;
#elif USE_KEVENT /* macOS, BSD, etc */
    return emulate_epoll_using_kevent(KFilt::Write, sockd, timeout, false);
#else
#error "Unsupported platform!"
#endif
}

// extern "C"
void rename_proc(const char *name)
{
#if defined(PR_SET_NAME)
    char buf[16];

    snprintf(buf, 15, "asp@%s", name);
    buf[15] = '\0';
    prctl(PR_SET_NAME, buf, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);
#elif defined(__APPLE__) /* macOS */
    pthread_setname_np(name);
#else
#error "Unsupported platform!"
#endif
}

// extern "C"
int random_threadsafe(int range)
{
    static std::mutex mut;
#if HAVE_ARC4RANDOM
    if (range <= 1)
        return 0;
    std::unique_lock l(mut);
    return static_cast<int>(arc4random_uniform(static_cast<unsigned>(range)));
#elif HAVE_RANDOM_R
    static struct random_data buf = {};
    static char state[256] = {};
    static bool initted = false;

    if (range <= 1)
        return 0;
    assert(range <= RAND_MAX);

    std::unique_lock l(mut);
    if (!initted) {
        if (initstate_r((unsigned int)(time_micros() % 1000000LL), state, sizeof(state), &buf)) {
            quit(1, "Got error result from initstate_r with errno %d", errno);
        }
        initted = true;
    }
    int32_t result = 0;
    if (random_r(&buf, &result)) {
        quit(1, "Got error result from random_r with errno %d", errno);
    }
    return result % range;
#else
    // Fall back to the C++ std random generator
    static std::mt19937 rgen = []{
        std::random_device rd;
        return std::mt19937(rd());
    }();
    std::uniform_int_distribution<> distrib(0, range - 1);
    std::unique_lock l(mut);
    return distrib(rgen);
#endif
}

// extern "C"
void nanosleep_abstime(const ts_t *ts_end)
{
#ifdef HAVE_CLOCK_NANOSLEEP /* Linux */
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ts_end, NULL);
#else /* Etc... */
    const ts_t ts_diff = *ts_end - getMonotonicTime();
    const int64_t micros = int64_t(ts_diff.tv_sec) * 1'000'000LL + int64_t(ts_diff.tv_nsec) / 1000LL;
    const auto ts = std::chrono::steady_clock::now() + std::chrono::microseconds(micros);
    std::this_thread::sleep_until(ts);
#endif
}

// extern "C"
int epfd_create_(const char *const file, const char *const func, int const line)
{
    const int ret = []{
#if USE_EPOLL /* Linux */
        return epoll_create1(EPOLL_CLOEXEC);
#elif USE_KEVENT /* macOS, BSD, etc */
        return kqueue();
#else
#error "Unsupported platform!"
#endif
    }();
    if (ret < 0)
        LOGDEBUG("%s: returning: %d (%s) [%s:%d in %s]", __func__, ret, std::strerror(errno), file, line, func);
    return ret;
}

// extern "C"
int epfd_add_or_mod_(int epfd, int fd, uint64_t userdata, bool isAdd, bool forRead, bool oneShot, bool edgeTriggered,
                     const char *const file, const char *const func, int const line)
{
    const int ret = [&]{
#if USE_EPOLL /* Linux */
        const int op = isAdd ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        struct epoll_event event;
        std::memset(&event, 0, sizeof(event));
        event.data.u64 = userdata;
        event.events = EPOLLRDHUP | (forRead ? EPOLLIN : EPOLLOUT) | (oneShot ? EPOLLONESHOT : 0) | (edgeTriggered ? EPOLLET : 0);
        return epoll_ctl(epfd, op, fd, &event);
#elif USE_KEVENT /* macOS, BSD, etc */
        struct kevent kev;
        std::memset(&kev, 0, sizeof(kev));
        int16_t filter = 0;
        uint16_t flags = EV_ADD;
        if (forRead) filter = EVFILT_READ;
        else filter = EVFILT_WRITE;
        if (edgeTriggered) flags |= EV_CLEAR;
        if (oneShot) flags |= EV_ONESHOT;
        EV_SET(&kev, fd, filter, flags, 0, 0, reinterpret_cast<void *>(static_cast<uintptr_t>(userdata)) /* paranoia for 32-bit */);
        return kevent(epfd, &kev, 1, nullptr, 0, nullptr);
#else
#error "Unsupported platform!"
#endif
    }();
    if (ret < 0)
        LOGDEBUG("%s: epfd: %d, fd: %d, op: %s, flags: %d%d%d, userdata: %llu, returning: %d (%s) [%s:%d in %s]",
                 __func__, epfd, fd, isAdd ? "ADD" : "MOD", int(forRead), int(oneShot), int(edgeTriggered),
                 static_cast<unsigned long long>(userdata), ret,
                 std::strerror(errno), file, line, func);
    return ret;
}

// extern "C"
int epfd_wait_(int epfd, aevt_t *event, int timeout_msec, const char *const file, const char *const func, int const line)
{
    const int ret = [&] {
        std::memset(event, 0, sizeof(*event));
#ifdef USE_EPOLL /* Linux */
        struct epoll_event ev;
        std::memset(&ev, 0, sizeof(ev));
        int r = epoll_wait(epfd, &ev, 1, timeout_msec);
        if (r >= 1) {
            event->userdata = ev.data.u64;
            event->in = ev.events & EPOLLIN;
            event->out = ev.events & EPOLLOUT;
            event->hup = ev.events & EPOLLHUP;
            event->rdhup = ev.events & EPOLLRDHUP;
            event->err = ev.events & EPOLLERR;
            if (event->err) event->data = errno;
        }
        return r;
#elif USE_KEVENT /* macOS, BSD, etc */
        struct kevent kev;
        std::memset(&kev, 0, sizeof(kev));
        struct timespec ts{.tv_sec = timeout_msec / 1000, .tv_nsec = (timeout_msec % 1000) * 1'000'000L};
        int r = kevent(epfd, nullptr, 0, &kev, 1, &ts);
        if (r >= 1) {
            event->fd = kev.ident;
            event->userdata = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(kev.udata));
            event->data = kev.data;
            event->rdhup = event->hup = kev.flags & EV_EOF;
            event->in = kev.filter == EVFILT_READ;
            event->out = kev.filter == EVFILT_WRITE;
            event->err = kev.flags & EV_ERROR;
            if (event->err && !event->data) event->data = errno;
        }
        return r;
#else
#error "Unsupported platform!"
#endif
    }();
    if (ret < 0)
        LOGDEBUG("%s: epfd: %d, fd: %d, userdata: %llu, returning: %d (%s) [%s:%d in %s]",
                 __func__, epfd, event->fd, (unsigned long long)event->userdata, ret,
                 std::strerror(errno), file, line, func);
    return ret;
}

// extern "C"
int epfd_rm_(int epfd, int fd, const char *const file, const char *const func, int const line)
{
    const int ret = [&] {
#ifdef USE_EPOLL /* Linux */
        return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
#elif USE_KEVENT /* macOS, BSD, etc */
        struct kevent kev;
        std::memset(&kev, 0, sizeof(kev));
        EV_SET(&kev, fd, 0, EV_DELETE, 0, 0, nullptr);
        return kevent(epfd, &kev, 1, nullptr, 0, nullptr);
#else
#error "Unsupported platform!"
#endif
    }();
    if (ret < 0)
        LOGDEBUG("%s: epfd: %d, fd: %d, returning: %d (%s) [%s:%d in %s]",
                 __func__, epfd, fd, ret,
                 std::strerror(errno), file, line, func);
    return ret;
}
