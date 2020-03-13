/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 2013-2014 Andrew Smith - BlackArrow Ltd
 * Copyright 2015-2016 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef KLIST_H
#define KLIST_H

#include "libasicseerpool.h"

#define quithere(status, fmt, ...) \
	quitfrom(status, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#define KLIST_FFL " - from %s %s() line %d"
#define KLIST_SFFL " - from %s %s():%d"
#define KLIST_AFFL "at %s %s():%d"
#define KLIST_FFL_HERE __FILE__, __func__, __LINE__
#define KLIST_FFL_PASS file, func, line
#define KLIST_FFL_ARGS  __maybe_unused const char *file, \
			__maybe_unused const char *func, \
			__maybe_unused const int line

extern const char *tree_node_list_name;

/* Code to check the state of locks being requested and also check
 *  the state of locks when accessing the klist or ktree
 * You can disable it with asicseer-pmsg 'locks.ID.locks' so you can compare
 *  CPU usage with and later without it
 *  (or just completely disable it by defining LOCK_CHECK 0 below)
 *
 * If we already hold any lock we ask for, it will report the duplication.
 * Duplication of read locks wont fail the code, but they do represent
 *  code that should be 'fixed'
 *
 * If klist/ktree access expects to have a lock, but doesn't have the
 *  required lock, it will report this bug
 *
 * Any errors found will set my_check_locks false before reporting the error,
 *  to avoid floods of error messages or crashes due to unexpected states
 *  of the thread's lock info
 *  i.e. you can only find one bug per thread each time you run ckdb
 *	 ... they should be rare if ever ... since I used this to attempt to
 *	 find them :)
 */
#define LOCK_CHECK 1

/* Deadlock prediction is quite simple:
 *  alloc_storage gives each K_LIST a unique 'lock priority' order greater
 *  than 1 with the lowest being PRIO_TERMINAL=1
 *  (thus until alloc_storage is run, no deadlock prediction is enabled)
 *  If any code locks a K_LIST with a 'lock priority' higher than one it
 *   already holds, then that means it could result in a deadlock,
 *   since the reverse priority order is expected
 *
 * This is implemented by checking the 'lock priority'
 *  each time we attempt to take out a lock within a lock
 *  It simply checks the previous lock held to see if it's 'lock priority'
 *   is lower than the new lock thus marginal CPU increase is only noticeable
 *   on multi-level locks
 *
 * Any deadlocks predicted will set my_check_deadlocks false before reporting
 *  the error, to avoid possible floods of repeated error messages
 *  i.e. you can only find one deadlock per thread each time you run ckdb
 *	 ... they should be rare if ever ... since I used this to attempt to
 *	 find them :)
 */

/* Deadlock prediction is part of LOCK_CHECK coz it uses the CHECK_LOCK() macro
 * If you want only deadlock checking, edit klist.c and set check_locks
 *  default to false,
 *  or turn off check_locks during asicseer-db startup with a asicseer-pmsg 'locks.ID.locks'
 * If you turn deadlock prediction on with asicseer-pmsg 'locks.1.deadlocks=y'
 *  it will not re-enable it for any thread that has already predicted
 *  a deadlock */

#if LOCK_CHECK
// Disable all lock checks permanently if thread limits are exceeded
extern bool disable_checks;

// We disable lock checking if an error is encountered
extern bool check_locks;
/* Maximum number of threads preallocated
 * This allows access to the lock tables without
 *  using any locks */
#define MAX_THREADS 128
extern const char *thread_noname;
extern int next_thread_id;
extern __thread int my_thread_id;
extern __thread char *my_thread_name;
extern __thread bool my_check_locks;

// This decides if alloc_storage will set 'check_deadlocks' after it's setup
extern bool auto_check_deadlocks;
// This decides if deadlock prediction is happening
extern bool check_deadlocks;
// It should never get to 16 unless there's a bug
#define MAX_LOCKDEPTH 16
extern __thread int my_locks[MAX_LOCKDEPTH];
extern __thread const char *my_locks_n[MAX_LOCKDEPTH];
extern __thread const char *my_locks_fl[MAX_LOCKDEPTH];
extern __thread const char *my_locks_f[MAX_LOCKDEPTH];
extern __thread int my_locks_l[MAX_LOCKDEPTH];
extern __thread int my_lock_level;
extern __thread bool my_check_deadlocks;

extern const char *nullstr;
#endif

typedef struct k_item {
	const char *name;
	struct k_item *prev;
	struct k_item *next;
	void *data;
} K_ITEM;

#if LOCK_CHECK
typedef struct k_lock {
	int r_count;
	int w_count;
	const char *first_held;
	const char *file;
	const char *func;
	int line;
} K_LOCK;
#endif

typedef struct k_list {
	const char *name;
	const char *name2;	// name of the tree if it's a tree node list
	struct k_list *master;
	bool is_store;
	bool is_lock_only;	// a lock emulating a list for lock checking
	bool local_list;	// local (tree) lists doesn't need lock checking at all
	cklock_t *lock;		// NULL for tree lists
	struct k_item *head;
	struct k_item *tail;
	size_t siz;		// item data size
	int total;		// total allocated
	int count;		// in this list
	int count_up;		// incremented every time one is added
	int allocate;		// number to intially allocate and each time we run out
	int limit;		// total limit - 0 means unlimited
	bool do_tail;		// track the tail?
	int item_mem_count;	// how many item memory buffers have been allocated
	void **item_memory;	// allocated item memory buffers
	int data_mem_count;	// how many item data memory buffers have been allocated
	void **data_memory;	// allocated item data memory buffers
	void (*dsp_func)(K_ITEM *, FILE *); // optional data display to a file
	int cull_limit;		// <1 means don't cull, otherwise total to cull at
	int cull_count;		// number of times culled
	uint64_t ram;		// ram allocated for data pointers - code must manage it
	struct k_list *next_store; // list of all stores - the head is next_store in the list master
	struct k_list *prev_store; //  the stores themselves have their prev and next
	int stores;		// how many stores it currently has
#if LOCK_CHECK
	// Since each thread has it's own k_lock no locking is required on this
	K_LOCK k_lock[MAX_THREADS];
	// 0=unset=an error, >=1 is the priority - bigger=higher priority
	int deadlock_priority;
#endif
} K_LIST;

// Required for cmd_stats
extern bool lock_check_init;
extern cklock_t lock_check_lock;
typedef struct k_lists {
	K_LIST *klist;
	struct k_lists *next;
} K_LISTS;
extern K_LISTS *all_klists;

/*
 * K_STORE is for a list of items taken from a K_LIST
 * The restriction is, a K_STORE must not allocate new items,
 * only the K_LIST should do that
 * i.e. all K_STORE items came from a K_LIST
 */
#define K_STORE K_LIST

// Extended ck wlock to allow >1 minute
#define SINGLE_TIMEOUT_S 10
/* 5mins - should never happen, but the longest lock: shift summarisation,
 *  will get slower over time as the share rate rises
 * Currently, only the code that uses the process_pplns_free lock,
 *  uses the k_longwlock function to acquire the lock, so that CKDB doesn't
 *  exit if a shift summarisation takes longer than the normal timeout limit
 * Nothing else should need to */
#define TIMEOUT_RETRIES 30
static inline int wr_timedlock(pthread_rwlock_t *lock, int timeout)
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

static inline void k_longwlock(cklock_t *lock, KLIST_FFL_ARGS)
{
	int ret, retries = 0;

retrym:
	ret = _mutex_timedlock(&(lock->mutex), SINGLE_TIMEOUT_S, file, func, line);
	if (unlikely(ret)) {
		if (likely(ret == ETIMEDOUT)) {
			LOGERR("WARNING: Prolonged mutex longlock contention from %s %s:%d, held by %s %s:%d",
			       file, func, line, lock->mutex.file, lock->mutex.func, lock->mutex.line);
			if (++retries < TIMEOUT_RETRIES)
				goto retrym;
			quitfrom(1, file, func, line, "FAILED TO GRAB LONGMUTEX!");
		}
		quitfrom(1, file, func, line, "WTF MUTEX ERROR ON LONGLOCK!");
	}

	retries = 0;
retry:
	ret = wr_timedlock(&(lock->rwlock.rwlock), SINGLE_TIMEOUT_S);
	if (unlikely(ret)) {
		if (likely(ret == ETIMEDOUT)) {
			LOGERR("WARNING: Prolonged longwrite lock contention from %s %s:%d, held by %s %s:%d",
			       file, func, line, lock->rwlock.file, lock->rwlock.func, lock->rwlock.line);
			if (++retries < TIMEOUT_RETRIES)
				goto retry;
			quitfrom(1, file, func, line, "FAILED TO GRAB LONGWRITE LOCK!");
		}
		quitfrom(1, file, func, line, "WTF ERROR ON LONGWRITE LOCK!");
	}
	lock->rwlock.file = file;
	lock->rwlock.func = func;
	lock->rwlock.line = line;
}
#define ck_KLONGW(_lock) k_longwlock(_lock, __FILE__, __func__, __LINE__)

#if LOCK_CHECK
#define LOCK_MAYBE
/* The simple lock_check_init check is in case someone incorrectly changes ckdb.c ...
 * It's not fool proof :P
 * If LOCK_INIT() is called too many times, i.e. too many threads,
 *  it will report and disable lock checking */
#define LOCK_INIT(_name) do { \
		if (!lock_check_init) { \
			quithere(1, "In thread %s, lock_check_lock has not been " \
				 "initialised!", _name); \
		} \
		ck_wlock(&lock_check_lock); \
		my_thread_id = next_thread_id++; \
		ck_wunlock(&lock_check_lock); \
		if (my_thread_id >= MAX_THREADS) { \
			disable_checks = true; \
			LOGERR("WARNING: all lock checking disabled due to " \
				"initialising too many threads - limit %d", \
				MAX_THREADS); \
		} \
		my_thread_name = strdup(_name); \
	} while (0)
#define FIRST_LOCK_INIT(_name) do { \
		if (lock_check_init) { \
			quithere(1, "In thread %s, lock_check_lock has already been " \
				 "initialised!", (_name)); \
		} \
		cklock_init(&lock_check_lock); \
		lock_check_init = true; \
		LOCK_INIT(_name); \
	} while (0)

#define LOCK_MODE_LOCK 0
#define LOCK_MODE_UNLOCK 1
#define LOCK_TYPE_READ 0
#define LOCK_TYPE_WRITE 1

// Lists with this priority cannot nest any lock inside their lock
#define PRIO_TERMINAL 1

#define LOCKERR(fmt, ...) LOGEMERG("***CHKLOCK %s:%d(now off) " fmt, \
				   my_thread_name ? : thread_noname, \
				   my_thread_id, ##__VA_ARGS__)
#define DLOCKERR(fmt, ...) LOGEMERG("***PREDLOCK %s(now off) " fmt, \
				    my_thread_name ? : thread_noname, \
				    ##__VA_ARGS__)
#define DLOCKOK(fmt, ...) LOGWARNING("***PREDLOCK %s " fmt, \
				     my_thread_name ? : thread_noname, \
				     ##__VA_ARGS__)

// Neither test 'should' ever fail
#define DLPRIO(_list, _p) do { \
		if ((_list ## _free)->is_store) \
			quithere(1, "Can't deadlock prioritise a K_STORE"); \
		if ((_list ## _free)->master != (_list ## _free)) \
			quithere(1, "K_LIST master is not itself"); \
		(_list ## _free)->deadlock_priority = (_p); \
	} while (0)

#define DLPCHECK() do { \
		K_LISTS *_klists; \
		if (!lock_check_init) { \
			quithere(1, "lock_check_lock has not been initialised!"); \
		} \
		ck_wlock(&lock_check_lock); \
		_klists = all_klists; \
		while (_klists) { \
			if (_klists->klist->deadlock_priority < PRIO_TERMINAL) { \
				DLOCKOK("%s priority not set (%d)", \
					_klists->klist->name, \
					_klists->klist->deadlock_priority); \
			} \
			_klists = _klists->next; \
		} \
		ck_wunlock(&lock_check_lock); \
	} while (0)

/* Optimisation should remove the code for all but the required _mode/_type
 *  since all the related ifs are constants */
#define THRLCK(_list) (((_list)->master)->k_lock[my_thread_id])
#define CHECK_LOCK(_list, _func, _mode, _type) do { \
		static const char *_n = #_list " " #_func; \
		static const char *_fl = __FILE__; \
		static const char *_f = __func__; \
		static const int _l =  __LINE__; \
		if (!disable_checks && my_check_locks && check_locks) { \
			if (_mode == LOCK_MODE_LOCK) { \
				if (THRLCK(_list).first_held || \
				    (THRLCK(_list).r_count != 0) || \
				    (THRLCK(_list).w_count != 0)) { \
					my_check_locks = false; \
					LOCKERR("%s " KLIST_AFFL " invalid (r%d:w%d) " \
						"first: %s " KLIST_AFFL, \
						_n, _fl, _f, _l, \
						THRLCK(_list).r_count, \
						THRLCK(_list).w_count, \
						THRLCK(_list).first_held ? : thread_noname, \
						THRLCK(_list).file ? : nullstr, \
						THRLCK(_list).func ? : nullstr, \
						THRLCK(_list).line); \
				} else { \
					THRLCK(_list).first_held = _n; \
					THRLCK(_list).file = _fl; \
					THRLCK(_list).func = _f; \
					THRLCK(_list).line = _l; \
					if (_type == LOCK_TYPE_READ) \
						THRLCK(_list).r_count++; \
					if (_type == LOCK_TYPE_WRITE) \
						THRLCK(_list).w_count++; \
				} \
			} \
			if (_mode == LOCK_MODE_UNLOCK && _type == LOCK_TYPE_READ) { \
				if (!THRLCK(_list).first_held || \
				    (THRLCK(_list).r_count != 1) || \
				    (THRLCK(_list).w_count != 0)) { \
					my_check_locks = false; \
					LOCKERR("%s " KLIST_AFFL " invalid (r%d:w%d) " \
						"first: %s " KLIST_AFFL, \
						_n, _fl, _f, _l, \
						THRLCK(_list).r_count, \
						THRLCK(_list).w_count, \
						THRLCK(_list).first_held ? : thread_noname, \
						THRLCK(_list).file ? : nullstr, \
						THRLCK(_list).func ? : nullstr, \
						THRLCK(_list).line); \
				} else { \
					THRLCK(_list).first_held = NULL; \
					THRLCK(_list).file = NULL; \
					THRLCK(_list).func = NULL; \
					THRLCK(_list).line = 0; \
					THRLCK(_list).r_count--; \
				} \
			} \
			if (_mode == LOCK_MODE_UNLOCK && _type == LOCK_TYPE_WRITE) { \
				if (!THRLCK(_list).first_held || \
				    (THRLCK(_list).r_count != 0) || \
				    (THRLCK(_list).w_count != 1)) { \
					my_check_locks = false; \
					LOCKERR("%s " KLIST_AFFL " invalid (r%d:w%d) " \
						"first: %s " KLIST_AFFL, \
						_n, _fl, _f, _l, \
						THRLCK(_list).r_count, \
						THRLCK(_list).w_count, \
						THRLCK(_list).first_held ? : thread_noname, \
						THRLCK(_list).file ? : nullstr, \
						THRLCK(_list).func ? : nullstr, \
						THRLCK(_list).line); \
				} else { \
					THRLCK(_list).first_held = NULL; \
					THRLCK(_list).file = NULL; \
					THRLCK(_list).func = NULL; \
					THRLCK(_list).line = 0; \
					THRLCK(_list).w_count--; \
				} \
			} \
		} \
		if (!disable_checks && check_deadlocks && my_check_deadlocks) { \
			int _dp = (_list)->deadlock_priority; \
			if (my_lock_level == 0) { \
				if (_mode == LOCK_MODE_LOCK) { \
					if (_dp < PRIO_TERMINAL) { \
						my_check_deadlocks = false; \
						DLOCKERR("%s " KLIST_AFFL \
							 " bad lock prio %d", \
							 _n, _fl, _f, _l, \
							 _dp); \
					} else { \
						my_locks[0] = _dp; \
						my_locks_n[0] = _n; \
						my_locks_fl[0] = _fl; \
						my_locks_f[0] = _f; \
						my_locks_l[0] = _l; \
						my_lock_level = 1; \
					} \
				} \
				if (_mode == LOCK_MODE_UNLOCK) { \
					DLOCKOK("%s " KLIST_AFFL \
						" lock level was 0 - unlock" \
						" prio %d ignored", \
						_n, _fl, _f, _l, \
						_dp); \
				} \
			} else { \
				if (_mode == LOCK_MODE_UNLOCK) { \
					if (my_locks[--my_lock_level] != _dp) { \
						my_check_deadlocks = false; \
						DLOCKERR("%s " KLIST_AFFL \
							 " unlock prio %d" \
							 " doesn't match prev" \
							 " locked prio %d", \
							 _n, _fl, _f, _l, \
							 _dp, \
							 my_locks[my_lock_level]); \
					} \
				} \
				if (_mode == LOCK_MODE_LOCK) { \
					int _i = my_lock_level - 1; \
					if (my_locks[_i] == PRIO_TERMINAL) { \
						my_check_deadlocks = false; \
						DLOCKERR("%s " KLIST_AFFL \
							 " prev lock" \
							 " prio[%d]=TERMINAL" \
							 " ... lock prio[%d]" \
							 "=%d %s " KLIST_AFFL, \
							 _n, _fl, _f, _l, _i, \
							 my_lock_level, _dp, \
							 my_locks_n[_i], \
							 my_locks_fl[_i], \
							 my_locks_f[_i], \
							 my_locks_l[_i]); \
					} else if (my_locks[_i] <= _dp) { \
						my_check_deadlocks = false; \
						DLOCKERR("%s " KLIST_AFFL \
							 " lock prio[%d]=%d" \
							 " >= prev lock" \
							 " prio[%d]=%d" \
							 " %s " KLIST_AFFL, \
							 _n, _fl, _f, _l, \
							 my_lock_level, _dp, \
							 _i, my_locks[_i], \
							 my_locks_n[_i], \
							 my_locks_fl[_i], \
							 my_locks_f[_i], \
							 my_locks_l[_i]); \
					} else { \
						my_locks[my_lock_level] = _dp; \
						my_locks_n[my_lock_level] = _n; \
						my_locks_fl[my_lock_level] = _fl; \
						my_locks_f[my_lock_level] = _f; \
						my_locks_l[my_lock_level++] = _l; \
					} \
				} \
			} \
		} \
		ck_##_func(_list->lock); \
	} while (0)

#define CHECK_WLOCK(_list) CHECK_LOCK(_list, wlock, \
					LOCK_MODE_LOCK, LOCK_TYPE_WRITE)
#define CHECK_KLONGWLOCK(_list) CHECK_LOCK(_list, KLONGW, \
					LOCK_MODE_LOCK, LOCK_TYPE_WRITE)
#define CHECK_WUNLOCK(_list) CHECK_LOCK(_list, wunlock, \
					LOCK_MODE_UNLOCK, LOCK_TYPE_WRITE)
#define CHECK_RLOCK(_list) CHECK_LOCK(_list, rlock, \
					LOCK_MODE_LOCK, LOCK_TYPE_READ)
#define CHECK_RUNLOCK(_list) CHECK_LOCK(_list, runlock, \
					LOCK_MODE_UNLOCK, LOCK_TYPE_READ)

#define _LIST_WRITE(_list, _chklock, _file, _func, _line) do { \
		if (!disable_checks && my_check_locks && check_locks && _chklock) { \
			if (!THRLCK(_list).first_held || \
			    (THRLCK(_list).r_count != 0) || \
			    (THRLCK(_list).w_count != 1)) { \
				my_check_locks = false; \
				LOCKERR("%s " KLIST_AFFL " invalid write " \
					"access (r%d:w%d) first: %s " \
					KLIST_AFFL KLIST_SFFL, \
					(_list)->master->name ? : nullstr, \
					KLIST_FFL_HERE, \
					THRLCK(_list).r_count, \
					THRLCK(_list).w_count, \
					THRLCK(_list).first_held ? : thread_noname, \
					THRLCK(_list).file ? : nullstr, \
					THRLCK(_list).func ? : nullstr, \
					THRLCK(_list).line, \
					_file, _func, _line); \
			} \
		} \
	} while (0)
#define _LIST_WRITE2(_list, _chklock) do { \
		if (!disable_checks && my_check_locks && check_locks && _chklock) { \
			if (!THRLCK(_list).first_held || \
			    (THRLCK(_list).r_count != 0) || \
			    (THRLCK(_list).w_count != 1)) { \
				my_check_locks = false; \
				LOCKERR("%s " KLIST_AFFL " invalid write " \
					"access (r%d:w%d) first: %s " \
					KLIST_AFFL, \
					(_list)->master->name ? : nullstr, \
					KLIST_FFL_HERE, \
					THRLCK(_list).r_count, \
					THRLCK(_list).w_count, \
					THRLCK(_list).first_held ? : thread_noname, \
					THRLCK(_list).file ? : nullstr, \
					THRLCK(_list).func ? : nullstr, \
					THRLCK(_list).line); \
			} \
		} \
	} while (0)
// read is ok under read or write
#define _LIST_READ(_list, _chklock, _file, _func, _line) do { \
		if (!disable_checks && my_check_locks && check_locks && _chklock) { \
			if (!THRLCK(_list).first_held || \
			    (THRLCK(_list).r_count + \
			    THRLCK(_list).w_count) != 1) { \
				my_check_locks = false; \
				LOCKERR("%s " KLIST_AFFL " invalid read " \
					"access (r%d:w%d) first: %s " \
					KLIST_AFFL KLIST_SFFL, \
					(_list)->master->name ? : nullstr, \
					KLIST_FFL_HERE, \
					THRLCK(_list).r_count, \
					THRLCK(_list).w_count, \
					THRLCK(_list).first_held ? : thread_noname, \
					THRLCK(_list).file ? : nullstr, \
					THRLCK(_list).func ? : nullstr, \
					THRLCK(_list).line, \
					_file, _func, _line); \
			} \
		} \
	} while (0)
#define _LIST_READ2(_list, _chklock) do { \
		if (!disable_checks && my_check_locks && check_locks && _chklock) { \
			if (!THRLCK(_list).first_held || \
			    (THRLCK(_list).r_count + \
			    THRLCK(_list).w_count) != 1) { \
				my_check_locks = false; \
				LOCKERR("%s " KLIST_AFFL " invalid read " \
					"access (r%d:w%d) first: %s " \
					KLIST_AFFL, \
					(_list)->master->name ? : nullstr, \
					KLIST_FFL_HERE, \
					THRLCK(_list).r_count, \
					THRLCK(_list).w_count, \
					THRLCK(_list).first_held ? : thread_noname, \
					THRLCK(_list).file ? : nullstr, \
					THRLCK(_list).func ? : nullstr, \
					THRLCK(_list).line); \
			} \
		} \
	} while (0)
#define LIST_WRITE(_list) _LIST_WRITE2(_list, true)
#define LIST_READ(_list) _LIST_READ2(_list, true)
static inline K_ITEM *list_whead(K_LIST *list)
{
	LIST_WRITE(list);
	return list->head;
}
static inline K_ITEM *list_rhead(K_LIST *list)
{
	LIST_READ(list);
	return list->head;
}
static inline K_ITEM *list_wtail(K_LIST *list)
{
	LIST_READ(list);
	return list->head;
}
static inline K_ITEM *list_rtail(K_LIST *list)
{
	LIST_READ(list);
	return list->head;
}
#define LIST_WHEAD(_list) list_whead(_list)
#define LIST_RHEAD(_list) list_rhead(_list)
#define LIST_WTAIL(_list) list_wtail(_list)
#define LIST_RTAIL(_list) list_rtail(_list)
#else
#define LOCK_MAYBE __maybe_unused
#define LOCK_INIT(_name)
#define FIRST_LOCK_INIT(_ignore) do { \
		if (lock_check_init) { \
			quithere(1, "lock_check_lock has already been " \
				 "initialised!"); \
		} \
		cklock_init(&lock_check_lock); \
		lock_check_init = true; \
	} while (0)
#define CHECK_WLOCK(_list) ck_wlock((_list)->lock)
#define CHECK_KLONGWLOCK(_list) ck_KLONGW((_list)->lock)
#define CHECK_WUNLOCK(_list) ck_wunlock((_list)->lock)
#define CHECK_RLOCK(_list) ck_rlock((_list)->lock)
#define CHECK_RUNLOCK(_list) ck_runlock((_list)->lock)
#define _LIST_WRITE(_list, _chklock, _file, _func, _line)
#define _LIST_READ(_list, _chklock, _file, _func, _line)
#define LIST_WRITE(_list)
#define LIST_READ(_list)
#define LIST_WHEAD(_list) (_list)->head
#define LIST_RHEAD(_list) (_list)->head
#define LIST_WTAIL(_list) (_list)->tail
#define LIST_RTAIL(_list) (_list)->tail
#endif

#define LIST_HEAD_NOLOCK(_list) (_list)->head
#define LIST_TAIL_NOLOCK(_list) (_list)->tail

#define CHECK_lock(_list) do { \
		if ((_list)->lock == NULL) { \
			quithere(1, "Attempt to lock list '%s' master '%s' " \
				 " that has no lock", \
				 (_list)->name, (_list)->master->name); \
		} \
	} while (0)

#define K_WLOCK(_list) do { \
		CHECK_lock(_list); \
		CHECK_WLOCK(_list); \
	} while (0)
#define K_KLONGWLOCK(_list) do { \
		CHECK_lock(_list); \
		CHECK_KLONGWLOCK(_list); \
	} while (0)
#define K_WUNLOCK(_list) do { \
		CHECK_lock(_list); \
		CHECK_WUNLOCK(_list); \
	} while (0)
#define K_RLOCK(_list) do { \
		CHECK_lock(_list); \
		CHECK_RLOCK(_list); \
	} while (0)
#define K_RUNLOCK(_list) do { \
		CHECK_lock(_list); \
		CHECK_RUNLOCK(_list); \
	} while (0)

#define STORE_WHEAD(_s) LIST_WHEAD(_s)
#define STORE_RHEAD(_s) LIST_RHEAD(_s)
#define STORE_WTAIL(_s) LIST_WTAIL(_s)
#define STORE_RTAIL(_s) LIST_RTAIL(_s)

// No need to lock temporary/private stores
#define STORE_HEAD_NOLOCK(_s) LIST_HEAD_NOLOCK(_s)
#define STORE_TAIL_NOLOCK(_s) LIST_TAIL_NOLOCK(_s)

extern void _dsp_kstore(K_STORE *store, char *filename, char *msg, KLIST_FFL_ARGS);
#define dsp_kstore(_store, _file, _msg) _dsp_kstore(_store, _file, _msg, KLIST_FFL_HERE)
extern K_STORE *_k_new_store(K_LIST *list, bool gotlock, KLIST_FFL_ARGS);
#define k_new_store(_list) _k_new_store(_list, false, KLIST_FFL_HERE)
#define k_new_store_locked(_list) _k_new_store(_list, true, KLIST_FFL_HERE)
extern K_LIST *_k_new_list(const char *name, size_t siz, int allocate,
			   int limit, bool do_tail, bool lock_only,
			   bool without_lock, bool local_list,
			   const char *name2, int cull_limit, KLIST_FFL_ARGS);
#define k_new_list(_name, _siz, _allocate, _limit, _do_tail) \
	_k_new_list(_name, _siz, _allocate, _limit, _do_tail, false, false, false, NULL, 0, KLIST_FFL_HERE)
#define k_lock_only_list(_name) \
	_k_new_list(_name, 1, 1, 1, true, true, false, false, NULL, 0, KLIST_FFL_HERE)
#define k_new_tree_list(_name, _siz, _allocate, _limit, _do_tail, _local_tree, _name2) \
	_k_new_list(_name, _siz, _allocate, _limit, _do_tail, false, true, _local_tree, _name2, 0, KLIST_FFL_HERE)
#define k_new_list_cull(_name, _siz, _allocate, _limit, _do_tail, _cull) \
	_k_new_list(_name, _siz, _allocate, _limit, _do_tail, false, false, false, NULL, _cull, KLIST_FFL_HERE)
extern K_ITEM *_k_unlink_head(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_unlink_head(_list) _k_unlink_head(_list, true, KLIST_FFL_HERE)
#define k_unlink_head_nolock(_list) _k_unlink_head(_list, false, KLIST_FFL_HERE)
extern K_ITEM *_k_unlink_head_zero(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_unlink_head_zero(_list) _k_unlink_head_zero(_list, true, KLIST_FFL_HERE)
//#define k_unlink_head_zero_nolock(_list) _k_unlink_head_zero(_list, false, KLIST_FFL_HERE)
extern K_ITEM *_k_unlink_tail(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_unlink_tail(_list) _k_unlink_tail(_list, true, KLIST_FFL_HERE)
//#define k_unlink_tail_nolock(_list) _k_unlink_tail(_list, false, KLIST_FFL_HERE)
extern void _k_add_head(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_add_head(_list, _item) _k_add_head(_list, _item, true, KLIST_FFL_HERE)
#define k_add_head_nolock(_list, _item) _k_add_head(_list, _item, false, KLIST_FFL_HERE)
// extern void k_free_head(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_free_head(__list, __item) _k_add_head(__list, __item, true, KLIST_FFL_HERE)
//#define k_free_head_nolock(__list, __item) _k_add_head(__list, __item, false, KLIST_FFL_HERE)
extern void _k_add_tail(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_add_tail(_list, _item) _k_add_tail(_list, _item, true, KLIST_FFL_HERE)
#define k_add_tail_nolock(_list, _item) _k_add_tail(_list, _item, false, KLIST_FFL_HERE)
extern void _k_insert_after(K_LIST *list, K_ITEM *item, K_ITEM *after, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_insert_after(_list, _item, _after) _k_insert_after(_list, _item, _after, true, KLIST_FFL_HERE)
//#define k_insert_after_nolock(_list, _item, _after) _k_insert_after(_list, _item, _after, false, KLIST_FFL_HERE)
extern void _k_unlink_item(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_unlink_item(_list, _item) _k_unlink_item(_list, _item, true, KLIST_FFL_HERE)
#define k_unlink_item_nolock(_list, _item) _k_unlink_item(_list, _item, false, KLIST_FFL_HERE)
extern void _k_list_transfer_to_head(K_LIST *from, K_LIST *to, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_list_transfer_to_head(_from, _to) _k_list_transfer_to_head(_from, _to, true, KLIST_FFL_HERE)
//#define k_list_transfer_to_head_nolock(_from, _to) _k_list_transfer_to_head(_from, _to, false, KLIST_FFL_HERE)
extern void _k_list_transfer_to_tail(K_LIST *from, K_LIST *to, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS);
#define k_list_transfer_to_tail(_from, _to) _k_list_transfer_to_tail(_from, _to, true, KLIST_FFL_HERE)
#define k_list_transfer_to_tail_nolock(_from, _to) _k_list_transfer_to_tail(_from, _to, false, KLIST_FFL_HERE)
extern K_LIST *_k_free_list(K_LIST *list, KLIST_FFL_ARGS);
#define k_free_list(_list) _k_free_list(_list, KLIST_FFL_HERE)
extern K_STORE *_k_free_store(K_STORE *store, KLIST_FFL_ARGS);
#define k_free_store(_store) _k_free_store(_store, KLIST_FFL_HERE)

#endif
