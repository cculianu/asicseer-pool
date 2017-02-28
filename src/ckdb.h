/*
 * Copyright 1995-2016 Andrew Smith
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CKDB_H
#define CKDB_H

#ifdef __GNUC__
#if __GNUC__ >= 6
#pragma GCC diagnostic ignored "-Wtautological-compare"
#endif
#endif

#include "config.h"

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <fenv.h>
#include <getopt.h>
#include <jansson.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <regex.h>
#include <sha2.h>
#ifdef HAVE_LIBPQ_FE_H
#include <libpq-fe.h>
#elif defined (HAVE_POSTGRESQL_LIBPQ_FE_H)
#include <postgresql/libpq-fe.h>
#endif

#include <gsl/gsl_math.h>
#include <gsl/gsl_cdf.h>

#include "ckpool.h"
#include "libckpool.h"

#include "klist.h"
#include "ktree.h"

/* This code's lock implementation is equivalent to table level locking
 * Consider adding row level locking (a per kitem usage count) if needed */

#define DB_VLOCK "1"
#define DB_VERSION "1.0.8"
#define CKDB_VERSION DB_VERSION"-2.718"

#define WHERE_FFL " - from %s %s() line %d"
#define WHERE_FFL_HERE __FILE__, __func__, __LINE__
#define WHERE_FFL_PASS file, func, line
#define WHERE_FFL_ARGS __maybe_unused const char *file, \
			__maybe_unused const char *func, \
			__maybe_unused const int line

#define STRINT(x) STRINT2(x)
#define STRINT2(x) #x

// Same as above but name it what we are using it for
#define STRMACRO(x) STRMAC2(x)
#define STRMAC2(x) #x

// So they can fit into a 1 byte flag field
#define TRUE_STR "Y"
#define TRUE2_STR "T"
#define FALSE_STR "N"
#define FALSE2_STR "F"

#define TRUE_CHR 'Y'
#define TRUE2_CHR 'T'
#define FALSE_CHR 'N'
#define FALSE2_CHR 'F'

/* Set by cmd_setopts() and used by whatever code needs it
 * It's loaded during startup but set to SWITCH_STATE_ALL if it's missing,
 *  meaning all switches are active
 * The idea is that if you need to manually switch code over from one version
 *  up to the next version at an indeterminate time then you can do that by
 *  coding a switch_state test and then externally switch the code over via
 *  the cmd_setopts() socket interface
 * It's not for coding runtime options into the code since that can be done
 *  using optioncontrol directly
 * It's stored in optioncontrol so that it's value is permanent and
 *  activationdate and activationheight have their values overridden to
 *  disable using them
 * N.B. optioncontrol_item_add() intercepts the change by name and updates
 *	switch_state but ONLY if the DB update succeeds */
extern int switch_state;
#define SWITCH_STATE_NAME "SwitchState"
/* Each switch state must be higher than all previous
 * so that future states don't undo old changes */
#define SWITCH_STATE_AUTHWORKERS 1
#define SWITCH_STATE_ALL 666666

extern bool genpayout_auto;
extern bool markersummary_auto;
extern bool exclusive_db;

enum free_modes {
	FREE_MODE_ALL,
	FREE_MODE_NONE,
	FREE_MODE_FAST
};

#define FREE_MODE_ALL_STR "all"
#define FREE_MODE_NONE_STR "none"
#define FREE_MODE_FAST_STR "fast"

extern enum free_modes free_mode;

// Define the array size for thread data
#define THREAD_LIMIT 99
/* To notify thread changes
 * Set/checked under the function's main loop's first lock
 * This is always a 'delta' value meaning add or subtract that many */
extern int reload_queue_threads_delta;
extern int proc_queue_threads_delta;
// To notify thread changes
extern int reload_breakdown_threads_delta;
extern int cmd_breakdown_threads_delta;

extern int cmd_listener_threads;
extern int btc_listener_threads;
extern int cmd_listener_threads_delta;
extern int btc_listener_threads_delta;

#define BLANK " "
extern char *EMPTY;
#define NULLSTR "(null)"
extern const char *nullstr;

extern const char *true_str;
extern const char *false_str;

#define TFSTR(_b) ((_b) ? true_str : false_str)

#define FREENULL(mem) do { \
		if ((mem) && (void *)(mem) != (void *)EMPTY) { \
			free(mem); \
			mem = NULL; \
		} \
	} while (0)

// To ensure there's space for the ticker
#define TICK_PREFIX "  "

// Field patterns
extern const char *userpatt;
extern const char *mailpatt;
extern const char *idpatt;
extern const char *intpatt;
extern const char *hashpatt;
extern const char *addrpatt;
extern const char *strpatt;

/* If a trimmed username is like an address but this many or more characters,
 * disallow it */
#define ADDR_USER_CHECK 16

// BTC address size
#define ADDR_MIN_LEN 26
#define ADDR_MAX_LEN 34
/* All characters in a payaddress are less than this
 * thus setting the 1st char to this will be greater than any payaddress */
#define MAX_PAYADDR '~'

typedef struct loadstatus {
	int64_t newest_workmarker_workinfoid;
	int64_t newest_workinfoid;
	tv_t newest_createdate_workmarker_workinfo;
	tv_t newest_createdate_workinfo;
	tv_t newest_createdate_poolstats;
	tv_t newest_createdate_blocks;
	int32_t newest_height_blocks;
} LOADSTATUS;
extern LOADSTATUS dbstatus;

// So cmd_getopts works on a new empty pool
#define START_POOL_HEIGHT 2

// Share stats since last block
typedef struct poolstatus {
	int64_t workinfoid; // Last block
	int32_t height;
	int64_t reward;
	double diffacc;
	double diffinv; // Non-acc
	double shareacc;
	double shareinv; // Non-acc
	double best_sdiff; // TODO (maybe)
} POOLSTATUS;
extern POOLSTATUS pool;

// size limit on the command string
#define CMD_SIZ 31
#define ID_SIZ 31

// size to allocate for pgsql text and display (bigger than needed)
#define DATE_BUFSIZ (63+1)
#define CDATE_BUFSIZ (127+1)
#define BIGINT_BUFSIZ (63+1)
#define INT_BUFSIZ (63+1)
#define DOUBLE_BUFSIZ (63+1)

#define TXT_BIG 256
#define TXT_MED 128
#define TXT_SML 64
#define TXT_FLAG 1

// TAB
#define FLDSEP 0x09
#define FLDSEPSTR "\011"

#define WORKSEP1 '.'
#define WORKSEP1STR "."
#define WORKSEP1PATT "\\."
#define WORKSEP2 '_'
#define WORKSEP2STR "_"

#define MAXID 0x7fffffffffffffffLL

/* N.B. STRNCPY() truncates, whereas txt_to_str() aborts ckdb if src > trg
 * If copying data from the DB, code should always use txt_to_str() since
 * data should never be lost/truncated if it came from the DB -
 * that simply implies a code bug or a database change that must be fixed */
#define STRNCPY(trg, src) do { \
		strncpy((char *)(trg), (char *)(src), sizeof(trg)); \
		trg[sizeof(trg) - 1] = '\0'; \
	} while (0)

#define STRNCPYSIZ(trg, src, siz) do { \
		strncpy((char *)(trg), (char *)(src), siz); \
		trg[siz - 1] = '\0'; \
	} while (0)

#define AR_SIZ 1024

#define APPEND_REALLOC_INIT(_buf, _off, _len) do { \
		_len = AR_SIZ; \
		(_buf) = malloc(_len); \
		if (!(_buf)) \
			quithere(1, "malloc (%d) OOM", (int)_len); \
		(_buf)[0] = '\0'; \
		_off = 0; \
	} while(0)

#define APPEND_REALLOC(_dst, _dstoff, _dstsiz, _src) do { \
		size_t _newlen, _srclen = strlen(_src); \
		_newlen = (_dstoff) + _srclen; \
		if (_newlen >= (_dstsiz)) { \
			_dstsiz = _newlen + AR_SIZ - (_newlen % AR_SIZ); \
			_dst = realloc(_dst, _dstsiz); \
			if (!(_dst)) \
				quithere(1, "realloc (%d) OOM", (int)_dstsiz); \
		} \
		strcpy((_dst)+(_dstoff), _src); \
		_dstoff += _srclen; \
	} while(0)

#define APPEND_REALLOC_RESET(_buf, _off) do { \
		(_buf)[0] = '\0'; \
		_off = 0; \
	} while(0)

enum data_type {
	TYPE_STR,
	TYPE_BIGINT,
	TYPE_INT,
	TYPE_TV,
	TYPE_TVDB,
	TYPE_BTV,
	TYPE_TVS,
	TYPE_CTV,
	TYPE_FTV,
	TYPE_BLOB,
	TYPE_DOUBLE,
	TYPE_T,
	TYPE_BT,
	TYPE_HMS,
	TYPE_MS
};

// BLOB does what PTR needs
#define TXT_TO_PTR TXT_TO_BLOB

#define TXT_TO_STR(__nam, __fld, __data) txt_to_str(__nam, __fld, (__data), sizeof(__data))
#define TXT_TO_BIGINT(__nam, __fld, __data) txt_to_bigint(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_INT(__nam, __fld, __data) txt_to_int(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_TV(__nam, __fld, __data) txt_to_tv(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_TVDB(__nam, __fld, __data) txt_to_tvdb(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_CTV(__nam, __fld, __data) txt_to_ctv(__nam, __fld, &(__data), sizeof(__data))
#define TXT_TO_BLOB(__nam, __fld, __data) txt_to_blob(__nam, __fld, &(__data))
#define TXT_TO_DOUBLE(__nam, __fld, __data) txt_to_double(__nam, __fld, &(__data), sizeof(__data))

// 6-Jun-6666 06:06:06+00
#define DEFAULT_EXPIRY 148204965966L
// 1-Jun-6666 00:00:00+00
#define COMPARE_EXPIRY 148204512000L

extern const tv_t default_expiry;

// No actual need to test tv_usec
#define CURRENT(_tv) (((_tv)->tv_sec == DEFAULT_EXPIRY) ? true : false)

// 31-Dec-9999 23:59:59+00
#define DATE_S_EOT 253402300799L
#define DATE_uS_EOT 0L
extern const tv_t date_eot;

// All data will be after: 2-Jan-2014 00:00:00+00
#define DATE_BEGIN 1388620800L
extern const tv_t date_begin;

#define DATE_ZERO(_tv) (_tv)->tv_sec = (_tv)->tv_usec = 0L

#define BTC_TO_D(_amt) ((double)((_amt) / 100000000.0))

// argv -K - don't run in ckdb mode, just update keysummaries
extern bool key_update;
extern int64_t key_wi_stt;
extern int64_t key_wi_fin;

// argv -y - don't run in ckdb mode, just confirm sharesummaries
extern bool confirm_sharesummary;

extern int64_t confirm_first_workinfoid;
extern int64_t confirm_last_workinfoid;

/* Stop the reload 11min after the 'last' workinfoid+1 appears
 * ckpool uses 10min - but add 1min to be sure */
#define WORKINFO_AGE 660

/* Allow defining the workinfoid range used in the db load of
 * workinfo and sharesummary */
extern int64_t dbload_workinfoid_start;
extern int64_t dbload_workinfoid_finish;
// Only restrict sharesummary, not workinfo
extern bool dbload_only_sharesummary;

/* If the above restriction - on sharesummaries - is after the last marks
 *  then this means the sharesummaries can't be summarised into
 *  markersummaries and pplns payouts may not be correct */
extern bool sharesummary_marks_limit;

// DB optioncontrol,idcontrol,users,workers,useratts load is complete
extern bool db_users_complete;
// DB load is complete
extern bool db_load_complete;
// Before the reload starts (and during the reload)
extern bool prereload;
// Different input data handling
extern bool reloading;
// Start marks processing during a larger reload
extern bool reloaded_N_files;
// Data load is complete
extern bool startup_complete;
// Set to true when pool0 completes, pool0 = socket data during reload
extern bool reload_queue_complete;
// Tell everyone to die
extern bool everyone_die;

/* These are included in cmd_homepage
 *  to help identify when ckpool locks up (or dies) */
extern tv_t last_heartbeat;
extern tv_t last_workinfo;
extern tv_t last_share;
extern tv_t last_share_acc;
extern tv_t last_share_inv;
extern tv_t last_auth;
extern cklock_t last_lock;

#define JSON_TRANSFER "json="
#define JSON_TRANSFER_LEN (sizeof(JSON_TRANSFER)-1)
#define JSON_BEGIN '{'
// Arrays have limited support in breakdown()
#define JSON_ARRAY '['
#define JSON_ARRAY_END ']'
#define JSON_STR '"'
#define JSON_VALUE ':'
#define JSON_SEP ','
#define JSON_END '}'
#define JSON_ESC '\\'

// Methods for sharelog (common function for all)
#define STR_WORKINFO "workinfo"
#define STR_SHARES "shares"
#define STR_SHAREERRORS "shareerror"
#define STR_AGEWORKINFO "ageworkinfo"

// Fixed size required - increase if you need larger
#define MAX_ALERT_CMD 255
// Access using event_limits_free lock
extern char *ckdb_alert_cmd;

extern tv_t ckdb_start;

extern char *btc_server;
extern char *btc_auth;
extern int btc_timeout;
// Lock access to the above variables so they can be changed
extern cklock_t btc_lock;

#define _EDDB expirydate
#define _CDDB createdate
#define _CDTRF _CDDB
#define _BYDB createby
#define _BYTRF _BYDB
#define _CODEDB createcode
#define _CODETRF _CODEDB
#define _INETDB createinet
#define _INETTRF _INETDB
#define _MDDB modifydate
#define _MBYDB modifyby
#define _MCODEDB modifycode
#define _MINETDB modifyinet

#define EDDB STRMACRO(_EDDB)
#define CDDB STRMACRO(_CDDB)
#define CDTRF STRMACRO(_CDTRF)
#define BYDB STRMACRO(_BYDB)
#define BYTRF STRMACRO(_BYTRF)
#define CODEDB STRMACRO(_CODEDB)
#define CODETRF STRMACRO(_CODETRF)
#define INETDB STRMACRO(_INETDB)
#define INETTRF STRMACRO(_INETTRF)
#define MDDB STRMACRO(_MDDB)
#define MBYDB STRMACRO(_MBYDB)
#define MCODEDB STRMACRO(_MCODEDB)
#define MINETDB STRMACRO(_MINETDB)

extern char *by_default;
extern char *inet_default;
extern char *id_default;

// Emulate a list for lock checking
extern K_LIST *pgdb_free;
// Count of db connections
extern int pgdb_count;
extern __thread char *connect_file;
extern __thread char *connect_func;
extern __thread int connect_line;
extern __thread bool connect_dis;
/* (WHEN FINISHED) Pause all DB IO (permanently) pause.1.name=pgTABconfirm=Y
 * Without confirm=Y it will return the pause state
 * All DB IO commands must take out a read of this lock before
 *  starting anything that shouldn't be done partially
 * This also means that the whole of CKDB can lock up for a short
 *  time if e.g. shift processing has taken the read lock shortly before
 *  the write lock is taken for the pause request to set the flag
 * Once pgdb_paused is true, all DB IO will not access the database
 *  and all web access will be in read only mode i.e. no user changes
 * All connections to the DB will close and thus DB changes and outages
 *  can then occur without affecting CKDB at all
 *   check the connection count with query.1.request=pg
 * Shift generation is unchanged, Payout generation is permanently disabled
 * To restart CKDB you must terminate it then rerun it, then CKDB will
 *  reload/redo all ckpool data it didn't store in the database
 * The aim is to look the same as a normal running CKDB except doing no
 *  DB I/O - that will be deferred until CKDB is later restarted
 * You can't pause CKDB until the dbload has completed, but you can
 *  during the CCL reload
 * The function to take out the pause lock increments the thread's
 *  pause_read_count so each function that expects the lock to be held can
 *  easily test that and incorrectly calling it multiple times is tracked
 * If the read lock code is called incorrectly, i.e. a code bug,
 *  pgdb_pause_disabled will be set to true and the pause command can no
 *  longer be activated, however if it was already activated, this wont
 *  affect anything */
extern cklock_t pgdb_pause_lock;
extern __thread int pause_read_count;
extern __thread char *pause_read_file;
extern __thread char *pause_read_func;
extern __thread int pause_read_line;
extern __thread bool pause_read_unlock;
extern bool pgdb_paused;
extern bool pgdb_pause_disabled;

// Number of seconds per poolinstance message for run
#define POOLINSTANCE_MSG_EVERY 30

#define FAILED_PI "failed.PI"

#define POOLINSTANCE_RESET_MSG(_txt) do { \
		int64_t _workinfo = 0, _ageworkinfo = 0, _auth = 0; \
		int64_t _addrauth = 0, _poolstats = 0, _userstats = 0; \
		int64_t _workerstats = 0, _workmarkers = 0, _marks = 0; \
		bool msg = false; \
		ck_wlock(&poolinstance_lock); \
		if (mismatch_all_total) { \
			msg = true; \
			last_mismatch_message = time(NULL); \
			_workinfo = mismatch_all_workinfo; \
			_ageworkinfo = mismatch_all_ageworkinfo; \
			_auth = mismatch_all_auth; \
			_addrauth = mismatch_all_addrauth; \
			_poolstats = mismatch_all_poolstats; \
			_userstats = mismatch_all_userstats; \
			_workerstats = mismatch_all_workerstats; \
			_workmarkers = mismatch_all_workmarkers; \
			_marks = mismatch_all_marks; \
			mismatch_workinfo = mismatch_ageworkinfo = \
			mismatch_auth = mismatch_addrauth = \
			mismatch_poolstats = mismatch_userstats = \
			mismatch_workerstats = mismatch_workmarkers = \
			mismatch_marks = mismatch_total = 0; \
			mismatch_all_workinfo = mismatch_all_ageworkinfo = \
			mismatch_all_auth = mismatch_all_addrauth = \
			mismatch_all_poolstats = mismatch_all_userstats = \
			mismatch_all_workerstats = mismatch_all_workmarkers = \
			mismatch_all_marks = mismatch_all_total = 0; \
		} \
		ck_wunlock(&poolinstance_lock); \
		if (msg) { \
			char reply[1024], *buf; \
			size_t len, off; \
			APPEND_REALLOC_INIT(buf, off, len); \
			snprintf(reply, sizeof(reply), "%s() %s PI total:", \
				 __func__, _txt); \
			APPEND_REALLOC(buf, off, len, reply); \
			if (_workinfo) { \
				snprintf(reply, sizeof(reply), " wi=%"PRId64, _workinfo); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_ageworkinfo) { \
				snprintf(reply, sizeof(reply), " age=%"PRId64, _ageworkinfo); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_auth) { \
				snprintf(reply, sizeof(reply), " auth=%"PRId64, _auth); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_addrauth) { \
				snprintf(reply, sizeof(reply), " addr=%"PRId64, _addrauth); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_poolstats) { \
				snprintf(reply, sizeof(reply), " ps=%"PRId64, _poolstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_userstats) { \
				snprintf(reply, sizeof(reply), " us=%"PRId64, _userstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_workerstats) { \
				snprintf(reply, sizeof(reply), " ws=%"PRId64, _workerstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_workmarkers) { \
				snprintf(reply, sizeof(reply), " wm=%"PRId64, _workmarkers); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_marks) { \
				snprintf(reply, sizeof(reply), " mark=%"PRId64, _marks); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			LOGWARNING("WARN: %s", buf); \
			FREENULL(buf); \
		} \
	} while (0)

// Checks mismatch_total outside lock since it's not critical
#define POOLINSTANCE_DATA_MSG() do { \
		int64_t _workinfo, _ageworkinfo, _auth, _addrauth, _poolstats; \
		int64_t _userstats, _workerstats, _workmarkers, _marks; \
		bool warn = false; \
		time_t now; \
		if (mismatch_total) { \
			ck_wlock(&poolinstance_lock); \
			if (mismatch_total) { \
				now = time(NULL); \
				if ((now - last_mismatch_message) >= POOLINSTANCE_MSG_EVERY) { \
					warn = true; \
					last_mismatch_message = now; \
					_workinfo = mismatch_workinfo; \
					_ageworkinfo = mismatch_ageworkinfo; \
					_auth = mismatch_auth; \
					_addrauth = mismatch_addrauth; \
					_poolstats = mismatch_poolstats; \
					_userstats = mismatch_userstats; \
					_workerstats = mismatch_workerstats; \
					_workmarkers = mismatch_workmarkers; \
					_marks = mismatch_marks; \
					mismatch_workinfo = mismatch_ageworkinfo = \
					mismatch_auth = mismatch_addrauth = \
					mismatch_poolstats = mismatch_userstats = \
					mismatch_workerstats = mismatch_workmarkers = \
					mismatch_marks = mismatch_total = 0; \
				} \
			} \
			ck_wunlock(&poolinstance_lock); \
		} \
		if (warn) { \
			char reply[1024], *buf; \
			size_t len, off; \
			APPEND_REALLOC_INIT(buf, off, len); \
			snprintf(reply, sizeof(reply), "%s() PI:", __func__); \
			APPEND_REALLOC(buf, off, len, reply); \
			if (_workinfo) { \
				snprintf(reply, sizeof(reply), " wi=%"PRId64, _workinfo); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_ageworkinfo) { \
				snprintf(reply, sizeof(reply), " age=%"PRId64, _ageworkinfo); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_auth) { \
				snprintf(reply, sizeof(reply), " auth=%"PRId64, _auth); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_addrauth) { \
				snprintf(reply, sizeof(reply), " addr=%"PRId64, _addrauth); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_poolstats) { \
				snprintf(reply, sizeof(reply), " ps=%"PRId64, _poolstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_userstats) { \
				snprintf(reply, sizeof(reply), " us=%"PRId64, _userstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_workerstats) { \
				snprintf(reply, sizeof(reply), " ws=%"PRId64, _workerstats); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_workmarkers) { \
				snprintf(reply, sizeof(reply), " wm=%"PRId64, _workmarkers); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			if (_marks) { \
				snprintf(reply, sizeof(reply), " mark=%"PRId64, _marks); \
				APPEND_REALLOC(buf, off, len, reply); \
			} \
			LOGWARNING("WARN: %s", buf); \
			FREENULL(buf); \
		} \
	} while (0)

#define POOLINSTANCE_DATA_SET(_obj, _pi) do { \
		bool warn = false; \
		ck_wlock(&poolinstance_lock); \
		if (mismatch_all_ ## _obj++ == 0) { \
			warn = true; \
		} \
		mismatch_ ## _obj++; \
		mismatch_all_total++; \
		mismatch_total++; \
		ck_wunlock(&poolinstance_lock); \
		if (warn) { \
			char *pist = NULL; \
			LOGWARNING("WARN: %s() " #_obj " first invalid " \
				   "poolinstance '%s'", __func__, \
				   pist = safe_text_nonull(_pi)); \
			FREENULL(pist); \
		} \
		POOLINSTANCE_DATA_MSG(); \
	} while (0)

#define POOLINSTANCE_DBLOAD_SET(_obj, _pi) do { \
		bool warn = false; \
		ck_wlock(&poolinstance_lock); \
		if (mismatch_all_ ## _obj++ == 0) \
			warn = true; \
		mismatch_ ## _obj++; \
		mismatch_all_total++; \
		mismatch_total++; \
		ck_wunlock(&poolinstance_lock); \
		if (warn) { \
			char *pist = NULL; \
			LOGWARNING("WARN: %s() dbload " #_obj " first " \
				   "invalid poolinstance '%s'", __func__, \
				   pist = safe_text_nonull(_pi)); \
			FREENULL(pist); \
		} \
	} while (0)

/* DBLoad message resets _obj and _all_obj back to zero
 *  since it's counting a single table_fill() */
#define POOLINSTANCE_DBLOAD_MSG(_obj) do { \
		int64_t tot = 0; \
		ck_wlock(&poolinstance_lock); \
		if (mismatch_all_ ## _obj) { \
			tot = mismatch_all_ ## _obj; \
			mismatch_all_total -= mismatch_all_ ## _obj; \
			mismatch_all_ ## _obj = 0; \
			mismatch_total -= mismatch_ ## _obj; \
			mismatch_ ## _obj = 0; \
		} \
		ck_wunlock(&poolinstance_lock); \
		if (tot) { \
			LOGWARNING("WARN: %s() dbload " #_obj " total " \
				   "invalid poolinstance %"PRId64, \
				   __func__, tot); \
		} \
	} while (0)

// NULL or poolinstance must match
extern const char *sys_poolinstance;
// lock for accessing all mismatch variables
extern cklock_t poolinstance_lock;
extern time_t last_mismatch_message;

extern int64_t mismatch_workinfo;
extern int64_t mismatch_ageworkinfo;
extern int64_t mismatch_auth;
extern int64_t mismatch_addrauth;
extern int64_t mismatch_poolstats;
extern int64_t mismatch_userstats;
extern int64_t mismatch_workerstats;
extern int64_t mismatch_workmarkers;
extern int64_t mismatch_marks;
extern int64_t mismatch_total;

extern int64_t mismatch_all_workinfo;
extern int64_t mismatch_all_ageworkinfo;
extern int64_t mismatch_all_auth;
extern int64_t mismatch_all_addrauth;
extern int64_t mismatch_all_poolstats;
extern int64_t mismatch_all_userstats;
extern int64_t mismatch_all_workerstats;
extern int64_t mismatch_all_workmarkers;
extern int64_t mismatch_all_marks;
extern int64_t mismatch_all_total;

enum cmd_values {
	CMD_UNSET,
	CMD_DUPSEQ, // Ignore, we've already got it
	CMD_REPLY, // Means something was wrong - send back reply
	CMD_ALERTEVENT, // Means reply with the buf passed
	CMD_ALERTOVENT, // Means reply with the buf passed
	CMD_TERMINATE,
	CMD_PING,
	CMD_VERSION,
	CMD_LOGLEVEL,
	CMD_FLUSH,
	CMD_WORKINFO,
	CMD_SHARES,
	CMD_SHAREERRORS,
	CMD_AGEWORKINFO,
	CMD_AUTH,
	CMD_ADDRAUTH,
	CMD_ADDUSER,
	CMD_HEARTBEAT,
	CMD_NEWPASS,
	CMD_CHKPASS,
	CMD_2FA,
	CMD_USERSET,
	CMD_WORKERSET,
	CMD_POOLSTAT,
	CMD_USERSTAT,
	CMD_WORKERSTAT,
	CMD_BLOCK,
	CMD_BLOCKLIST,
	CMD_BLOCKSTATUS,
	CMD_NEWID,
	CMD_PAYMENTS,
	CMD_WORKERS,
	CMD_ALLUSERS,
	CMD_HOMEPAGE,
	CMD_GETATTS,
	CMD_SETATTS,
	CMD_EXPATTS,
	CMD_GETOPTS,
	CMD_SETOPTS,
	CMD_DSP,
	CMD_STATS,
	CMD_PPLNS,
	CMD_PPLNS2,
	CMD_PAYOUTS,
	CMD_MPAYOUTS,
	CMD_SHIFTS,
	CMD_USERSTATUS,
	CMD_MARKS,
	CMD_PSHIFT,
	CMD_SHSTA,
	CMD_USERINFO,
	CMD_BTCSET,
	CMD_QUERY,
	CMD_LOCKS,
	CMD_EVENTS,
	CMD_HIGH,
	CMD_THREADS,
	CMD_PAUSE,
	CMD_END
};

// For NON-list stack/heap K_ITEMS
#define INIT_GENERIC(_item, _name) do { \
		(_item)->name = _name ## _free->name; \
	} while (0)

#define DATA_GENERIC(_var, _item, _name, _nonull) do { \
		if ((_item) == NULL) { \
			if (_nonull) { \
				quithere(1, "Attempt to cast NULL item data (as '%s')", \
					 _name ## _free->name); \
			} else \
				(_var) = NULL; \
		} else { \
			if ((_item)->name != _name ## _free->name) { \
				quithere(1, "Attempt to cast item '%s' data as '%s'", \
					 (_item)->name, \
					 _name ## _free->name); \
			} \
			(_var) = ((struct _name *)((_item)->data)); \
		} \
	} while (0)

// ***
// *** ckdb.c
// ***

// CCLs are every ...
#define ROLL_S 3600

#define io_msg(stamp, msg, errn, logfd, logerr) \
	_io_msg(stamp, msg, false, errn, logfd, false, logerr, true, true, \
		WHERE_FFL_HERE)
#define cr_msg(stamp, msg) \
	_io_msg(stamp, msg, true, 0, false, true, false, false, true, WHERE_FFL_HERE)
#define lf_msg(stamp, msg) \
	_io_msg(stamp, msg, true, 0, false, true, false, true, true, WHERE_FFL_HERE)
#define err_msg(stamp, msg, errn) \
	_io_msg(stamp, msg, true, errn, false, false, true, true, true, WHERE_FFL_HERE)

extern void _io_msg(bool stamp, char *msg, bool alloc, int errn, bool logfd,
		    bool logout, bool logerr, bool eol, bool flush,
		    WHERE_FFL_ARGS);

#define LOGQUE(_msg, _db) log_queue_message(_msg, _db)
#define LOGFILE(_msg, _prefix) rotating_log_nolock(_msg, _prefix)
#define LOGDUP "dup."

// ***
// *** klists/ktrees ***
// ***

// The size strdup will allocate multiples of
#define MEMBASE 4

#define LIST_MEM_ADD_SIZ(_list, _siz) do { \
		if (_siz % MEMBASE) \
			_siz += MEMBASE - (_siz % MEMBASE); \
		_list->ram += (int)_siz; \
	} while (0)

#define LIST_MEM_ADD(_list, _fld) do { \
		if ((_fld) && (_fld) != EMPTY) { \
			size_t __siz; \
			__siz = strlen(_fld) + 1; \
			LIST_MEM_ADD_SIZ(_list, __siz); \
		} \
	} while (0)

#define LIST_MEM_SUB(_list, _fld) do { \
		if ((_fld) && (_fld) != EMPTY) { \
			size_t __siz; \
			__siz = strlen(_fld) + 1; \
			if (__siz % MEMBASE) \
				__siz += MEMBASE - (__siz % MEMBASE); \
			_list->ram -= (int)__siz; \
		} \
	} while (0)

#define SET_POINTER(_list, _fld, _val, _def) do { \
		if ((_fld) && ((_fld) != EMPTY) && ((_fld) != (_def))) { \
			if (_list) \
				LIST_MEM_SUB(_list, _fld); \
			free(_fld); \
		} \
		if (!(_val) || !(*(_val))) \
			(_fld) = EMPTY; \
		else { \
			if (((_val) == (_def)) || (strcmp(_val, _def) == 0)) \
				(_fld) = (_def); \
			else { \
				if (_list) \
					LIST_MEM_ADD(_list, _val); \
				_fld = strdup(_val); \
				if (!(_fld)) \
					quithere(1, "strdup OOM"); \
			} \
		} \
	} while (0)

#define DUP_POINTER(_list, _fld, _val) do { \
		if ((_fld) && ((_fld) != EMPTY)) { \
			if (_list) \
				LIST_MEM_SUB(_list, _fld); \
			free(_fld); \
		} \
		if (!(_val) || !(*(_val))) \
			(_fld) = EMPTY; \
		else { \
			if (_list) \
				LIST_MEM_ADD(_list, _val); \
			_fld = strdup(_val); \
			if (!(_fld)) \
				quithere(1, "strdup OOM"); \
		} \
	} while (0)

#define SET_CREATEBY(_list, _fld, _val) SET_POINTER(_list, _fld, _val, by_default)
#define SET_CREATECODE(_list, _fld, _val) SET_POINTER(_list, _fld, _val, EMPTY)
#define SET_CREATEINET(_list, _fld, _val) SET_POINTER(_list, _fld, _val, inet_default)
#define SET_MODIFYBY(_list, _fld, _val) SET_POINTER(_list, _fld, _val, by_default)
#define SET_MODIFYCODE(_list, _fld, _val) SET_POINTER(_list, _fld, _val, EMPTY)
#define SET_MODIFYINET(_list, _fld, _val) SET_POINTER(_list, _fld, _val, inet_default)

#define HISTORYDATECONTROL ","CDDB","BYDB","CODEDB","INETDB","EDDB
#define HISTORYDATECOUNT 5
#define HISTORYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t expirydate; \
	bool buffers
#define HISTORYDATECONTROLPOINTERS \
	tv_t createdate; \
	char *createby; \
	char *createcode; \
	char *createinet; \
	tv_t expirydate; \
	bool pointers
#define HISTORYDATECONTROLIN \
	tv_t createdate; \
	char *in_createby; \
	char *in_createcode; \
	char *in_createinet; \
	tv_t expirydate; \
	bool intrans

#define HISTORYDATEINIT(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->createby, _by); \
		STRNCPY((_row)->createcode, _code); \
		STRNCPY((_row)->createinet, _inet); \
		(_row)->expirydate.tv_sec = default_expiry.tv_sec; \
		(_row)->expirydate.tv_usec = default_expiry.tv_usec; \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define HISTORYDATEDEFAULT(_row, _cd) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->createby, by_default); \
		STRNCPY((_row)->createcode, (char *)__func__); \
		STRNCPY((_row)->createinet, inet_default); \
		(_row)->expirydate.tv_sec = default_expiry.tv_sec; \
		(_row)->expirydate.tv_usec = default_expiry.tv_usec; \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define HISTORYDATEPOINTERS(_list, _row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		SET_CREATEBY(_list, (_row)->createby, _by); \
		SET_CREATECODE(_list, (_row)->createcode, _code); \
		SET_CREATEINET(_list, (_row)->createinet, _inet); \
		(_row)->expirydate.tv_sec = default_expiry.tv_sec; \
		(_row)->expirydate.tv_usec = default_expiry.tv_usec; \
		(_row)->pointers = (_row)->pointers; \
	} while (0)

#define HISTORYDATEINTRANS(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		(_row)->in_createby = intransient_str(BYDB, _by); \
		(_row)->in_createcode = intransient_str(CODEDB, _code); \
		(_row)->in_createinet = intransient_str(INETDB, _inet); \
		(_row)->expirydate.tv_sec = default_expiry.tv_sec; \
		(_row)->expirydate.tv_usec = default_expiry.tv_usec; \
		(_row)->intrans = (_row)->intrans; \
	} while (0)

/* Override _row defaults if transfer fields are present
 * We don't care about the reply so it can be small */
#define HISTORYDATETRANSFER(_root, _row) do { \
		if (_root) { \
			char __reply[16]; \
			size_t __siz = sizeof(__reply); \
			K_ITEM *__item; \
			TRANSFER *__transfer; \
			__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				STRNCPY((_row)->createby, __transfer->mvalue); \
			} \
			__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				STRNCPY((_row)->createcode, __transfer->mvalue); \
			} \
			__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				STRNCPY((_row)->createinet, __transfer->mvalue); \
			} \
			(_row)->buffers = (_row)->buffers; \
		} \
	} while (0)

#define HISTORYDATETRANSFERIN(_root, _row) do { \
		if (_root) { \
			char __reply[16]; \
			size_t __siz = sizeof(__reply); \
			K_ITEM *__item; \
			TRANSFER *__transfer; \
			__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createby = __transfer->intransient->str; \
			} \
			__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createcode = __transfer->intransient->str; \
			} \
			__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createinet = __transfer->intransient->str; \
			} \
			(_row)->intrans = (_row)->intrans; \
		} \
	} while (0)

#define MODIFYDATECONTROL ","CDDB","BYDB","CODEDB","INETDB \
			  ","MDDB","MBYDB","MCODEDB","MINETDB
#define MODIFYDATECOUNT 8
#define MODIFYUPDATECOUNT 4
#define MODIFYDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	tv_t modifydate; \
	char modifyby[TXT_SML+1]; \
	char modifycode[TXT_MED+1]; \
	char modifyinet[TXT_MED+1]; \
	bool buffers
#define MODIFYDATECONTROLPOINTERS \
	tv_t createdate; \
	char *createby; \
	char *createcode; \
	char *createinet; \
	tv_t modifydate; \
	char *modifyby; \
	char *modifycode; \
	char *modifyinet; \
	bool pointers
#define MODIFYDATECONTROLIN \
	tv_t createdate; \
	char *in_createby; \
	char *in_createcode; \
	char *in_createinet; \
	tv_t modifydate; \
	char *in_modifyby; \
	char *in_modifycode; \
	char *in_modifyinet; \
	bool intrans

#define MODIFYDATEINIT(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->createby, _by); \
		STRNCPY((_row)->createcode, _code); \
		STRNCPY((_row)->createinet, _inet); \
		DATE_ZERO(&((_row)->modifydate)); \
		(_row)->modifyby[0] = '\0'; \
		(_row)->modifycode[0] = '\0'; \
		(_row)->modifyinet[0] = '\0'; \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define MODIFYUPDATE(_row, _cd, _by, _code, _inet) do { \
		(_row)->modifydate.tv_sec = (_cd)->tv_sec; \
		(_row)->modifydate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->modifyby, _by); \
		STRNCPY((_row)->modifycode, _code); \
		STRNCPY((_row)->modifyinet, _inet); \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define MODIFYDATEPOINTERS(_list, _row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		SET_CREATEBY(_list, (_row)->createby, _by); \
		SET_CREATECODE(_list, (_row)->createcode, _code); \
		SET_CREATEINET(_list, (_row)->createinet, _inet); \
		DATE_ZERO(&((_row)->modifydate)); \
		SET_MODIFYBY(_list, (_row)->modifyby, EMPTY); \
		SET_MODIFYCODE(_list, (_row)->modifycode, EMPTY); \
		SET_MODIFYINET(_list, (_row)->modifyinet, EMPTY); \
		(_row)->pointers = (_row)->pointers; \
	} while (0)

#define MODIFYUPDATEPOINTERS(_list, _row, _cd, _by, _code, _inet) do { \
		(_row)->modifydate.tv_sec = (_cd)->tv_sec; \
		(_row)->modifydate.tv_usec = (_cd)->tv_usec; \
		SET_MODIFYBY(_list, (_row)->modifyby, _by); \
		SET_MODIFYCODE(_list, (_row)->modifycode, _code); \
		SET_MODIFYINET(_list, (_row)->modifyinet, _inet); \
		(_row)->pointers = (_row)->pointers; \
	} while (0)

// Using EMPTY is faster and is OK for in_ fields
#define MODIFYDATEINTRANS(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		(_row)->in_createby = intransient_str(BYDB, _by); \
		(_row)->in_createcode = intransient_str(CODEDB, _code); \
		(_row)->in_createinet = intransient_str(INETDB, _inet); \
		DATE_ZERO(&((_row)->modifydate)); \
		(_row)->in_modifyby = EMPTY; \
		(_row)->in_modifycode = EMPTY; \
		(_row)->in_modifyinet = EMPTY; \
		(_row)->intrans = (_row)->intrans; \
	} while (0)

#define MODIFYUPDATEINTRANS(_row, _cd, _by, _code, _inet) do { \
		(_row)->modifydate.tv_sec = (_cd)->tv_sec; \
		(_row)->modifydate.tv_usec = (_cd)->tv_usec; \
		(_row)->in_modifyby = intransient_str(MBYDB, _by); \
		(_row)->in_modifycode = intransient_str(MCODEDB, _code); \
		(_row)->in_modifyinet = intransient_str(MINETDB, _inet); \
		(_row)->intrans = (_row)->intrans; \
	} while (0)

/* Override _row defaults if transfer fields are present
 * We don't care about the reply so it can be small
 * This is the pointer version */
#define MODIFYDATETRANSFER(_list, _root, _row) do { \
		if (_root) { \
			char __reply[16]; \
			size_t __siz = sizeof(__reply); \
			K_ITEM *__item; \
			TRANSFER *__transfer; \
			__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				SET_CREATEBY(_list, (_row)->createby, __transfer->mvalue); \
			} \
			__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				SET_CREATECODE(_list, (_row)->createcode, __transfer->mvalue); \
			} \
			__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				SET_CREATEINET(_list, (_row)->createinet, __transfer->mvalue); \
			} \
			(_row)->pointers = (_row)->pointers; \
		} \
	} while (0)

// Intransient version
#define MODIFYDATETRANSFERIN(_root, _row) do { \
		if (_root) { \
			char __reply[16]; \
			size_t __siz = sizeof(__reply); \
			K_ITEM *__item; \
			TRANSFER *__transfer; \
			__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createby = __transfer->intransient->str; \
			} \
			__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createcode = __transfer->intransient->str; \
			} \
			__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
			if (__item) { \
				DATA_TRANSFER(__transfer, __item); \
				(_row)->in_createinet = __transfer->intransient->str; \
			} \
			(_row)->intrans = (_row)->intrans; \
		} \
	} while (0)

#define SIMPLEDATECONTROL ","CDDB","BYDB","CODEDB","INETDB
#define SIMPLEDATECOUNT 4
#define SIMPLEDATECONTROLFIELDS \
	tv_t createdate; \
	char createby[TXT_SML+1]; \
	char createcode[TXT_MED+1]; \
	char createinet[TXT_MED+1]; \
	bool buffers
#define SIMPLEDATECONTROLPOINTERS \
	tv_t createdate; \
	char *createby; \
	char *createcode; \
	char *createinet; \
	bool pointers
#define SIMPLEDATECONTROLIN \
	tv_t createdate; \
	char *in_createby; \
	char *in_createcode; \
	char *in_createinet; \
	bool intrans

#define SIMPLEDATEINIT(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->createby, _by); \
		STRNCPY((_row)->createcode, _code); \
		STRNCPY((_row)->createinet, _inet); \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define SIMPLEDATEDEFAULT(_row, _cd) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		STRNCPY((_row)->createby, by_default); \
		STRNCPY((_row)->createcode, (char *)__func__); \
		STRNCPY((_row)->createinet, inet_default); \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define SIMPLEDATEPOINTERS(_list, _row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		SET_CREATEBY(_list, (_row)->createby, _by); \
		SET_CREATECODE(_list, (_row)->createcode, _code); \
		SET_CREATEINET(_list, (_row)->createinet, _inet); \
		(_row)->pointers = (_row)->pointers; \
	} while (0)

#define SIMPLEDATEINTRANS(_row, _cd, _by, _code, _inet) do { \
		(_row)->createdate.tv_sec = (_cd)->tv_sec; \
		(_row)->createdate.tv_usec = (_cd)->tv_usec; \
		(_row)->in_createby = intransient_str(BYDB, _by); \
		(_row)->in_createcode = intransient_str(CODEDB, _code); \
		(_row)->in_createinet = intransient_str(INETDB, _inet); \
		(_row)->intrans = (_row)->intrans; \
	} while (0)

/* Override _row defaults if transfer fields are present
 * We don't care about the reply so it can be small */
#define SIMPLEDATETRANSFER(_root, _row) do { \
		char __reply[16]; \
		size_t __siz = sizeof(__reply); \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY((_row)->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY((_row)->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			STRNCPY((_row)->createinet, __transfer->mvalue); \
		} \
		(_row)->buffers = (_row)->buffers; \
	} while (0)

#define SIMPLEDATETRANSFERPTR(_list, _root, _row) do { \
		char __reply[16]; \
		size_t __siz = sizeof(__reply); \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			SET_CREATEBY(_list, (_row)->createby, __transfer->mvalue); \
		} \
		__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			SET_CREATECODE(_list, (_row)->createcode, __transfer->mvalue); \
		} \
		__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			SET_CREATEINET(_list, (_row)->createinet, __transfer->mvalue); \
		} \
		(_row)->pointers = (_row)->pointers; \
	} while (0)

#define SIMPLEDATETRANSFERIN(_root, _row) do { \
		char __reply[16]; \
		size_t __siz = sizeof(__reply); \
		K_ITEM *__item; \
		TRANSFER *__transfer; \
		__item = optional_name(_root, BYTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			(_row)->in_createby = __transfer->intransient->str; \
		} \
		__item = optional_name(_root, CODETRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			(_row)->in_createcode = __transfer->intransient->str; \
		} \
		__item = optional_name(_root, INETTRF, 1, NULL, __reply, __siz); \
		if (__item) { \
			DATA_TRANSFER(__transfer, __item); \
			(_row)->in_createinet = __transfer->intransient->str; \
		} \
		(_row)->intrans = (_row)->intrans; \
	} while (0)

// IOQUEUE
typedef struct ioqueue {
	char *msg;
	tv_t when;
	int errn;
	bool logfd;
	bool logout;
	bool logerr;
	bool eol;
	bool flush;
} IOQUEUE;

#define ALLOC_IOQUEUE 1024
#define LIMIT_IOQUEUE 0
#define INIT_IOQUEUE(_item) INIT_GENERIC(_item, ioqueue)
#define DATA_IOQUEUE(_var, _item) DATA_GENERIC(_var, _item, ioqueue, true)

extern K_LIST *ioqueue_free;
extern K_STORE *ioqueue_store;
extern K_STORE *console_ioqueue_store;

// LOGQUEUE
typedef struct logqueue {
	char *msg;
	bool db;
} LOGQUEUE;

#define ALLOC_LOGQUEUE 1024
#define LIMIT_LOGQUEUE 0
#define INIT_LOGQUEUE(_item) INIT_GENERIC(_item, logqueue)
#define DATA_LOGQUEUE(_var, _item) DATA_GENERIC(_var, _item, logqueue, true)

extern K_LIST *logqueue_free;
extern K_STORE *logqueue_store;

// NAMERAM - RAM for INTRANSIENT names - 2M per allocation
typedef struct nameram {
	char rem[2*1024*1024-sizeof(void *)-sizeof(size_t)];
	void *next;
	size_t left;
} NAMERAM;

// Items never to be deleted and list never to be culled
#define ALLOC_NAMERAM 1
#define LIMIT_NAMERAM 0
#define INIT_NAMERAM(_item) INIT_GENERIC(_item, nameram)
#define DATA_NAMERAM(_var, _item) DATA_GENERIC(_var, _item, nameram, true)

extern K_LIST *nameram_free;
extern K_STORE *nameram_store;

// INTRANSIENT - a list of common strings, to avoid wasting RAM
typedef struct intransient {
	char *str;
} INTRANSIENT;

/* intransient strings are allowed to be EMPTY (and static "")
 *  but will always be the same RAM for the same non-zero length string */
#define INTREQ(s1, s2) (s1 == s2 || (*(s1) == '\0' && *(s2) == '\0'))

/* Some functions assume the string passed is intransient, so you must
 *  ensure all calls to those functions do pass an intransient string
 * e.g. in the case of workername this is solved by simply making all
 *  workername fields in all tables intransient
 * Using stack ram instead of an intransient would lead to having random,
 *  changing string values in the field
 * Using a static (other than EMPTY or static "") would mean that use of
 *  INTREQ() could return an incorrect result */

// Items never to be deleted and list never to be culled
#define ALLOC_INTRANSIENT 1024
#define LIMIT_INTRANSIENT 0
#define INIT_INTRANSIENT(_item) INIT_GENERIC(_item, intransient)
#define DATA_INTRANSIENT(_var, _item) DATA_GENERIC(_var, _item, intransient, true)
#define DATA_INTRANSIENT_NULL(_var, _item) DATA_GENERIC(_var, _item, intransient, false)

extern K_TREE *intransient_root;
extern K_LIST *intransient_free;
extern K_STORE *intransient_store;

extern char *intransient_fields[];
extern INTRANSIENT *in_empty;

// MSGLINE
typedef struct msgline {
	int which_cmds;
	tv_t now;
	tv_t cd;
	tv_t accepted; // copied from breakqueue
	tv_t broken; // breakdown done
	tv_t processed; // not all are processed
	tv_t replied;
	char id[ID_SIZ+1];
	char cmd[CMD_SIZ+1];
	char *msg;
	size_t msgsiz;
	bool hasseq;
	char *seqcmdnam;
	uint64_t n_seqall;
	uint64_t n_seqcmd;
	uint64_t n_seqstt;
	uint64_t n_seqpid;
	int seqentryflags;
	INTRANSIENT *in_code;
	K_TREE *trf_root;
	K_STORE *trf_store;
	int sockd;
} MSGLINE;

#define ALLOC_MSGLINE 8192
#define LIMIT_MSGLINE 0
#define CULL_MSGLINE (8 * ALLOC_MSGLINE)
#define INIT_MSGLINE(_item) INIT_GENERIC(_item, msgline)
#define DATA_MSGLINE(_var, _item) DATA_GENERIC(_var, _item, msgline, true)
#define DATA_MSGLINE_NULL(_var, _item) DATA_GENERIC(_var, _item, msgline, false)

extern K_LIST *msgline_free;
extern K_STORE *msgline_store;

// BREAKQUEUE
typedef struct breakqueue {
	char *buf;
	size_t bufsiz;
	char *source;
	int access;
	tv_t accepted; // socket accepted or line read
	tv_t now; // msg read or line read
	int seqentryflags;
	int sockd;
	enum cmd_values cmdnum;
	K_ITEM *ml_item;
	uint64_t count;
	char *filename;
} BREAKQUEUE;

#define ALLOC_BREAKQUEUE 16384
#define LIMIT_BREAKQUEUE 0
#define CULL_BREAKQUEUE (4 * ALLOC_BREAKQUEUE)
#define INIT_BREAKQUEUE(_item) INIT_GENERIC(_item, breakqueue)
#define DATA_BREAKQUEUE(_var, _item) DATA_GENERIC(_var, _item, breakqueue, true)

/* If a breaker() thread's done break queue count hits the LIMIT, or is empty,
 *  it will sleep for SLEEP ms
 * Also note that LIMIT defines how much RAM can be used by the break queues,
 *  so a limit is required
 *  A breakqueue item can get quite large since it includes both buf
 *   and ml_item (which has the transfer data) in the 'done' queue
 * Of course the processing speed of the ml_items will also decide how big the
 *  break queue count can get
 * Note that if the CMD queues get too large they will be too slow responding
 *  to the sockets that sent the message, however the CMD ml_item processing
 *  responds immediately before processing the ml_item for all but ADDRAUTH,
 *  AUTHORISE and HEARTBEAT
 * The reload also uses this limit when filling the reload break queue
 *  thus limiting the line processing of reload files
 */
#define RELOAD_QUEUE_LIMIT 16300
#define RELOAD_QUEUE_SLEEP_MS 42
// Don't really limit the cmd queue
#define CMD_QUEUE_LIMIT 1048500
#define CMD_QUEUE_SLEEP_MS 42

extern K_LIST *breakqueue_free;
extern K_STORE *reload_breakqueue_store;
extern K_STORE *reload_done_breakqueue_store;
extern K_STORE *cmd_breakqueue_store;
extern K_STORE *cmd_done_breakqueue_store;

// Locked access with breakqueue_free
extern int reload_processing;
extern int cmd_processing;
extern int sockd_count;
extern int max_sockd_count;
extern ts_t breaker_sleep_stt;
extern int breaker_sleep_ms;

// Trigger breaker() processing
extern mutex_t bq_reload_waitlock;
extern mutex_t bq_cmd_waitlock;
extern pthread_cond_t bq_reload_waitcond;
extern pthread_cond_t bq_cmd_waitcond;

extern uint64_t bq_reload_signals, bq_cmd_signals;
extern uint64_t bq_reload_wakes, bq_cmd_wakes;
extern uint64_t bq_reload_timeouts, bq_cmd_timeouts;

// Trigger reload/socket *_done_* processing
extern mutex_t process_reload_waitlock;
extern mutex_t process_socket_waitlock;
extern pthread_cond_t process_reload_waitcond;
extern pthread_cond_t process_socket_waitcond;

extern uint64_t process_reload_signals, process_socket_signals;
extern uint64_t process_reload_wakes, process_socket_wakes;
extern uint64_t process_reload_timeouts, process_socket_timeouts;

// WORKQUEUE
typedef struct workqueue {
	K_ITEM *msgline_item;
	char *by;
	char *code;
	char *inet;
} WORKQUEUE;

#define ALLOC_WORKQUEUE 1024
#define LIMIT_WORKQUEUE 0
#define CULL_WORKQUEUE (32 * ALLOC_WORKQUEUE)
#define INIT_WORKQUEUE(_item) INIT_GENERIC(_item, workqueue)
#define DATA_WORKQUEUE(_var, _item) DATA_GENERIC(_var, _item, workqueue, true)

extern K_LIST *workqueue_free;
// pool0 is all pool data during the reload
extern K_STORE *pool0_workqueue_store;
extern K_STORE *pool_workqueue_store;
extern K_STORE *cmd_workqueue_store;
extern K_STORE *btc_workqueue_store;
// this counter ensures we don't switch early from pool0 to pool
extern int64_t earlysock_left;
extern int64_t pool0_tot;
extern int64_t pool0_discarded;

// Trigger workqueue threads
extern mutex_t wq_pool_waitlock;
extern mutex_t wq_cmd_waitlock;
extern mutex_t wq_btc_waitlock;
extern pthread_cond_t wq_pool_waitcond;
extern pthread_cond_t wq_cmd_waitcond;
extern pthread_cond_t wq_btc_waitcond;

extern uint64_t wq_pool_signals, wq_cmd_signals, wq_btc_signals;
extern uint64_t wq_pool_wakes, wq_cmd_wakes, wq_btc_wakes;
extern uint64_t wq_pool_timeouts, wq_cmd_timeouts, wq_btc_timeouts;

// REPLIES
typedef struct replies {
	tv_t now;
	tv_t createdate;
	tv_t accepted;
	tv_t broken;
	tv_t processed;
	int sockd;
	char *reply;
	struct epoll_event event;
	const char *file;
	const char *func;
	int line;
} REPLIES;

#define ALLOC_REPLIES 65536
#define LIMIT_REPLIES 0
#define INIT_REPLIES(_item) INIT_GENERIC(_item, replies)
#define DATA_REPLIES(_var, _item) DATA_GENERIC(_var, _item, replies, true)

extern K_LIST *replies_free;
extern K_STORE *replies_store;
extern K_TREE *replies_pool_root;
extern K_TREE *replies_cmd_root;
extern K_TREE *replies_btc_root;

// Close the socket and discard the reply, X ms after it gets in a list
#define REPLIES_LIMIT_MS 10000

extern int epollfd_pool;
extern int epollfd_cmd;
extern int epollfd_btc;

extern int rep_tot_sockd;
extern int rep_failed_sockd;
extern int rep_max_sockd;
// maximum counts and fd values
extern int rep_max_pool_sockd;
extern int rep_max_cmd_sockd;
extern int rep_max_btc_sockd;
extern int rep_max_pool_sockd_fd;
extern int rep_max_cmd_sockd_fd;
extern int rep_max_btc_sockd_fd;

// HEARTBEATQUEUE
typedef struct heartbeatqueue {
	char *in_workername;
	int32_t difficultydefault;
	tv_t createdate;
} HEARTBEATQUEUE;

#define ALLOC_HEARTBEATQUEUE 128
#define LIMIT_HEARTBEATQUEUE 0
#define INIT_HEARTBEATQUEUE(_item) INIT_GENERIC(_item, heartbeatqueue)
#define DATA_HEARTBEATQUEUE(_var, _item) DATA_GENERIC(_var, _item, heartbeatqueue, true)

extern K_LIST *heartbeatqueue_free;
extern K_STORE *heartbeatqueue_store;

// TRANSFER
#define NAME_SIZE 63
#define VALUE_SIZE 63
typedef struct transfer {
	char name[NAME_SIZE+1];
	char svalue[VALUE_SIZE+1];
	char *mvalue;
	size_t msiz;
	INTRANSIENT *intransient;
} TRANSFER;

// Suggest malloc use MMAP = largest under 2MB
#define ALLOC_TRANSFER ((int)(2*1024*1024/sizeof(TRANSFER)))
#define LIMIT_TRANSFER 0
// ALLOC_TRANSFER is ~14k, allocated often is 3
#define CULL_TRANSFER (4 * ALLOC_TRANSFER)
#define INIT_TRANSFER(_item) INIT_GENERIC(_item, transfer)
#define DATA_TRANSFER(_var, _item) DATA_GENERIC(_var, _item, transfer, true)

extern K_LIST *transfer_free;

/* Allow defining and adjusting it on a running system
 *  cull_limit is set to the optionvalue * ALLOC_TRANSFER */
#define CULL_TRANSFER_NAME "CullTransfer"
extern int cull_transfer;

#define transfer_data(_item) _transfer_data(_item, WHERE_FFL_HERE)

extern const char Transfer[];

extern K_ITEM auth_preauth;
extern K_ITEM poolstats_elapsed;
extern K_ITEM userstats_elapsed;
extern INTRANSIENT *userstats_workername;
extern K_ITEM userstats_idle;
extern K_ITEM userstats_eos;
extern K_ITEM shares_secondaryuserid;
extern K_ITEM shareerrors_secondaryuserid;
extern tv_t missing_secuser_min;
extern tv_t missing_secuser_max;

/* The aim of the sequence data is to identify and ignore duplicate records -
 *  which should usually only be during a reload -
 *  and to identify missing records when their sequence numbers are skipped
 *
 * If at any time there is a problem with a sequence number, an error is
 *  reported, then the record being processed is simply processed normally by
 *  the cmd_func() it was intended for - which may or may not produce other
 *  processing error messages depending on the validity of the rest of the data
 *
 * Field explanation:
 *  Normal sequence processing would be that we first get seq N, then N+1
 *   then N+2 ... etc.
 *   seqbase,minseq,maxseq are all set to the first N for the given sequence
 *   maxseq is incremented to the current maximum N+x each time a record is
 *   processed
 *  If we get up to N+3 but it is unexpectedly followed by N+5, that means N+4
 *   is currently missing - so it is flagged as missing by MISSFLAG=0 and the
 *   missing counters are incremented - maxseq will now be N+5
 *  Once we reach N+size we need to discard N and use it as N+size
 *   and increment seqbase N
 *   When we discard the oldest entry due to needing more, if that oldest
 *    entry was missing, it is now considered lost and the lost counters
 *    are incremented (and missing counters decremented)
 *  If we receive an entry N+x where N+x-maxseq>highlimit we reject it as high
 *   and increment the high counters - this avoids creating a high bad sequence
 *   number and flagging any missing sequence numbers, most likely incorrectly,
 *   as lost in the range N to N+x-size
 *  If we receive an entry N-x i.e. less than seqbase N, then:
 *   If maxseq-N = size then N-x is considered stale and the stale counters
 *    are incremented since there's no unused entries below N available
 *    This shouldn't normally happen after we've received size seq numbers
 *   Else maxseq-N is less than size, that means there are unused entries below N
 *    This will usually only be with a new sequence and the first seq was out
 *     of order, before lower sequence numbers, thus maxseq should be close to
 *     seqbase N and no where near N+size and there should be x unused below N
 *    If there are x unused entries below N then we can move seqbase down to N-x
 *     after we flag all N-1,N-2,N-3..N-(x-1) as missing
 *    Else there aren't enough unused entries below N, then N-x is considered
 *     stale and the stale counters are incremented
 *
 * timelimit is an early limit to flag missing sequence numbers as 'transient'
 * Normally, if a missing entry at N is later reused, it will be discarded and
 *  reported as lost
 * After the reload queue is complete, timelimit reports missing sequence
 *  numbers early, as transient, if they have been missing for 'timelimit' but
 *  not already lost
 *  missing isn't decremented, since it is still treated as missing
 * This is needed in case a size limit on a sequence means it may take a long
 *  time before it reports messages as lost - this also means that after the
 *  reload queue has cleared after ckdb startup, it will report the transient
 *  missing sequence numbers shortly after the timelimit
 * When they are later found or lost they will again be reported, this time as
 *  found or lost
 *
 * The sequence fields are checked for validity when the message arrives
 * Sequence order checking of reload lines are done immediately
 * Checking of ckpool lines isn't done until after the reload completes
 *  This solves the problem of the overlap from reload to queue
 *   If we stop the reload when we first match the queue, there's the issue
 *    that data order in the reload file may not match the data order in the
 *    queue and thus we could lose a record that is late in the reload file
 *    but was before the queue start
 *   To solve this unlikely (but not impossible) issue we reload all reload
 *    files to the end and then sequence process the queued data after the
 *    reload completes
 *   This however produces another (solvable) problem that the queue start
 *    may be stale when we finally complete the reload
 *   To handle this we keep a list of all lost records in the reload and check
 *    the stale queue records against those to see if we found them
 *    If a queue line is lower than minseq then that's a sequence error
 *    If a queue line is stale but above minseq, we check if it is in the
 *     lost list and then report it as recovered (and process it)
 *    If it wasn't lost then it's an expected duplicate and ignored
 *    Once the queue exceeds the reload maxseq, the lost records are no longer
 *     needed and are discarded */

// ckpool sequence numbers
#define SEQALL "seqall"
#define SEQSTT "seqstart"
#define SEQPID "seqpid"
#define SEQPRE "seq"

/* Value to use for SEQSTT when manually sending messages,
 *  to make ckdb not check the seq numbers
 * The message must have a SEQALL but the value is ignored
 * SEQPID and SEQcmd don't need to exist and are ignored */
#define SEQSTTIGN 42

enum seq_num {
	SEQ_NONE = -1, // Invalid to have ckpool seq numbers
	SEQ_ALL,
	SEQ_BLOCK,
	SEQ_SHARES,
	SEQ_WORKINFO,
	SEQ_AGEWORKINFO,
	SEQ_AUTH,
	SEQ_ADDRAUTH,
	SEQ_HEARTBEAT,
	SEQ_SHAREERRORS,
	SEQ_WORKERSTAT,
	SEQ_POOLSTATS,
	SEQ_MAX
};

#define SECHR(_sif) (((_sif) == SE_EARLYSOCK) ? 'E' : \
			(((_sif) == SE_RELOAD) ? 'R' : \
			(((_sif) == SE_SOCKET) ? 'S' : '?')))

// Msg from the socket before startup completed
#define SE_EARLYSOCK 1
// Msg was from reload
#define SE_RELOAD 2
// Msg from the socket after startup completed
#define SE_SOCKET 4

typedef struct seqentry {
	int flags;
	tv_t cd; // sec:0=missing, usec:0=miss !0=trans
	tv_t time;
	char *in_code;
} SEQENTRY;

typedef struct seqdata {
	size_t	size; // entry count - MUST be a power of 2
	uint64_t highlimit;
	int timelimit;
	uint64_t minseq;
	uint64_t maxseq;
	uint64_t seqbase;
	uint64_t missing;
	uint64_t trans;
	uint64_t lost;
	uint64_t stale;
	uint64_t high;
	uint64_t recovered;
	uint64_t ok;
	uint64_t reloadmax;
	tv_t firsttime;
	tv_t lasttime;
	tv_t firstcd;
	tv_t lastcd;
	SEQENTRY *entry;
	K_STORE *reload_lost;
} SEQDATA;

// SEQSET
typedef struct seqset {
	uint64_t seqstt; // 0 if unused/unallocated
	uint64_t seqpid;
	uint64_t missing; // total from seqdata
	uint64_t trans; // total from seqdata
	uint64_t lost; // total from seqdata
	uint64_t stale; // total from seqdata
	uint64_t high; // total from seqdata
	uint64_t recovered; // total from seqdata
	uint64_t ok; // total from seqdata
	SEQDATA seqdata[SEQ_MAX];
} SEQSET;

/* All *_SIZ must be >= 64 and a power of 2
 *  but if any aren't, the code checks this and quit()s
 *  the first time it processes a record with sequences */

// SEQALL and SHARES */
#define SEQ_LARGE_TRANS_LIM 32
#define SEQ_LARGE_SIZ (65536*16)
// WORKERSTATS, AUTH and ADDRAUTH
#define SEQ_MEDIUM_TRANS_LIM 32
#define SEQ_MEDIUM_SIZ 65536
// The rest
#define SEQ_SMALL_TRANS_LIM 64
#define SEQ_SMALL_SIZ 16384

// Give SEQ_ALL a much higher limit to allow for all type processing times
#define SEQ_ALL_HIGHLIMIT (SEQ_LARGE_SIZ << 3)

// highlimit ratio (shift down bits)
#define HIGH_SHIFT 8
// Smallest highlimit allowed
#define HIGH_MIN 32 
// Smallest _SIZ allowed
#define BASE_SIZ (HIGH_MIN << HIGH_SHIFT)

#define ALLOC_SEQSET 1
#define LIMIT_SEQSET 16
#define INIT_SEQSET(_item) INIT_GENERIC(_item, seqset)
#define DATA_SEQSET(_var, _item) DATA_GENERIC(_var, _item, seqset, true)

// other variables are static in ckdb.c
extern K_LIST *seqset_free;

// SEQTRANS also used for reload_lost
typedef struct seqtrans {
	int seq;
	uint64_t seqnum;
	SEQENTRY entry;
} SEQTRANS;

// The stores are created and freed each time required
extern K_LIST *seqtrans_free;

#define ALLOC_SEQTRANS 1024
#define LIMIT_SEQTRANS 0
#define CULL_SEQTRANS (16 * ALLOC_SEQTRANS)
#define INIT_SEQTRANS(_item) INIT_GENERIC(_item, seqtrans)
#define DATA_SEQTRANS(_var, _item) DATA_GENERIC(_var, _item, seqtrans, true)
#define DATA_SEQTRANS_NULL(_var, _item) DATA_GENERIC(_var, _item, seqtrans, false)

// USERS
typedef struct users {
	int64_t userid;
	char *in_username;
	char usertrim[TXT_BIG+1]; // non-DB field
	// Anything in 'status' fails mining authentication
	char status[TXT_BIG+1];
	char emailaddress[TXT_BIG+1];
	tv_t joineddate;
	char passwordhash[TXT_BIG+1];
	char secondaryuserid[TXT_SML+1];
	char salt[TXT_BIG+1];
	char *userdata;
	int64_t databits; // non-DB field, Bitmask of userdata content
	int64_t userbits; // Bitmask of user attributes
	int32_t lastvalue; // non-DB field
	HISTORYDATECONTROLFIELDS;
} USERS;

#define ALLOC_USERS 1024
#define LIMIT_USERS 0
#define INIT_USERS(_item) INIT_GENERIC(_item, users)
#define DATA_USERS(_var, _item) DATA_GENERIC(_var, _item, users, true)
#define DATA_USERS_NULL(_var, _item) DATA_GENERIC(_var, _item, users, false)

#define MIN_USERNAME 3

#define SHA256SIZHEX	64
#define SHA256SIZBIN	32
#define SALTSIZHEX	32
#define SALTSIZBIN	16

#define DATABITS_SEP ','
#define DATABITS_SEP_STR ","

/* databits attributes
 * These are generated at dbload time from userdata
 *  and when the userdata is changed */
// TOTP Auth 2FA
#define USER_TOTPAUTH_NAME "totpauth"
#define USER_TOTPAUTH 0x1
// 2FA Key untested
#define USER_TEST2FA_NAME "test2fa"
#define USER_TEST2FA 0x2

#define USER_TOTP_ENA(_users) \
	(((_users)->databits & (USER_TOTPAUTH | USER_TEST2FA)) == USER_TOTPAUTH)

// userbits attributes
// Address account, not a username account
#define USER_ADDRESS 0x1

// Username created due to a share that had an unknown username
#define USER_MISSING 0x2

// 16 x base 32 (5 bits) = 10 bytes (8 bits)
#define TOTPAUTH_KEYSIZE 10
#define TOTPAUTH_DSP_KEYSIZE 16
// Optioncontrol name
#define TOTPAUTH_ISSUER "taissuer"
// Currently only:
#define TOTPAUTH_AUTH "totp"
#define TOTPAUTH_HASH "SHA256"
#define TOTPAUTH_TIME 30

extern K_TREE *users_root;
extern K_TREE *userid_root;
extern K_LIST *users_free;
extern K_STORE *users_store;
// Emulate a list for lock checking
extern K_LIST *users_db_free;

// USERATTS
typedef struct useratts {
	int64_t userid;
	char attname[TXT_SML+1];
	char status[TXT_BIG+1];
	char attstr[TXT_BIG+1];
	char attstr2[TXT_BIG+1];
	int64_t attnum;
	int64_t attnum2;
	tv_t attdate;
	tv_t attdate2;
	HISTORYDATECONTROLFIELDS;
} USERATTS;

#define ALLOC_USERATTS 1024
#define LIMIT_USERATTS 0
#define INIT_USERATTS(_item) INIT_GENERIC(_item, useratts)
#define DATA_USERATTS(_var, _item) DATA_GENERIC(_var, _item, useratts, true)
#define DATA_USERATTS_NULL(_var, _item) DATA_GENERIC(_var, _item, useratts, false)

extern K_TREE *useratts_root;
extern K_LIST *useratts_free;
extern K_STORE *useratts_store;

// This att means the user uses multiple % based payout addresses
#define USER_MULTI_PAYOUT "PayAddresses"
// If they have multi, then: the default address limit if the useratt num < 1
#define USER_ADDR_LIMIT 2

#define USER_OLD_WORKERS "OldWorkersDays"
#define USER_OLD_WORKERS_DEFAULT 7

// WORKERS
typedef struct workers {
	int64_t workerid;
	int64_t userid;
	char *in_workername; // includes username
	int32_t difficultydefault;
	char idlenotificationenabled[TXT_FLAG+1];
	int32_t idlenotificationtime;
	int64_t workerbits; // Bitmask of worker attributes
	HISTORYDATECONTROLFIELDS;
} WORKERS;

#define ALLOC_WORKERS 1024
#define LIMIT_WORKERS 0
#define INIT_WORKERS(_item) INIT_GENERIC(_item, workers)
#define DATA_WORKERS(_var, _item) DATA_GENERIC(_var, _item, workers, true)
#define DATA_WORKERS_NULL(_var, _item) DATA_GENERIC(_var, _item, workers, false)

extern K_TREE *workers_root;
extern K_LIST *workers_free;
extern K_STORE *workers_store;
// Emulate a list for lock checking
extern K_LIST *workers_db_free;

// Currently no workerbits attributes

#define DIFFICULTYDEFAULT_MIN 10
#define DIFFICULTYDEFAULT_MAX 0x7fffffff
// 0 means it's not set
#define DIFFICULTYDEFAULT_DEF 0
#define DIFFICULTYDEFAULT_DEF_STR STRINT(DIFFICULTYDEFAULT_DEF)
#define IDLENOTIFICATIONENABLED "y"
#define IDLENOTIFICATIONDISABLED " "
#define IDLENOTIFICATIONENABLED_DEF IDLENOTIFICATIONDISABLED
#define IDLENOTIFICATIONTIME_MIN 10
#define IDLENOTIFICATIONTIME_MAX 60
// 0 means it's not set and will be flagged disabled
#define IDLENOTIFICATIONTIME_DEF 0
#define IDLENOTIFICATIONTIME_DEF_STR STRINT(IDLENOTIFICATIONTIME_DEF)

#define WORKERS_SEL_SEP ','
#define WORKERS_SEL_SEP_STR ","
/* There are 2 special select workernames
 * A DB workername can't accidentally match them
 *  when including the WORKSEPx at the front of the workername,
 *  since these 2 don't start with WORKSEP1 or WORKSEP2 */
#define WORKERS_ALL "all"
// Empty has a value rather than "", so that "" means nothing selected
#define WORKERS_EMPTY "noname"

// PAYMENTADDRESSES
typedef struct paymentaddresses {
	int64_t paymentaddressid;
	int64_t userid;
	char *in_payaddress;
	int32_t payratio;
	char payname[TXT_SML+1];
	HISTORYDATECONTROLIN;
	bool match; // non-DB field
} PAYMENTADDRESSES;

#define ALLOC_PAYMENTADDRESSES 1024
#define LIMIT_PAYMENTADDRESSES 0
#define INIT_PAYMENTADDRESSES(_item) INIT_GENERIC(_item, paymentaddresses)
#define DATA_PAYMENTADDRESSES(_var, _item) DATA_GENERIC(_var, _item, paymentaddresses, true)
#define DATA_PAYMENTADDRESSES_NULL(_var, _item) DATA_GENERIC(_var, _item, paymentaddresses, false)

extern K_TREE *paymentaddresses_root;
extern K_TREE *paymentaddresses_create_root;
extern K_LIST *paymentaddresses_free;
extern K_STORE *paymentaddresses_store;

#define PAYRATIODEF 1000000

// PAYMENTS
typedef struct payments {
	int64_t paymentid;
	int64_t payoutid;
	int64_t userid;
	char *in_subname;
	tv_t paydate;
	char *in_payaddress;
	char *in_originaltxn;
	int64_t amount;
	double diffacc;
	char *in_committxn;
	char *in_commitblockhash;
	HISTORYDATECONTROLIN;
	K_ITEM *old_item; // non-DB field
} PAYMENTS;

#define ALLOC_PAYMENTS 1024
#define LIMIT_PAYMENTS 0
#define INIT_PAYMENTS(_item) INIT_GENERIC(_item, payments)
#define DATA_PAYMENTS(_var, _item) DATA_GENERIC(_var, _item, payments, true)
#define DATA_PAYMENTS_NULL(_var, _item) DATA_GENERIC(_var, _item, payments, false)

extern K_TREE *payments_root;
extern K_LIST *payments_free;
extern K_STORE *payments_store;

// ACCOUNTBALANCE
typedef struct accountbalance {
	int64_t userid;
	int64_t confirmedpaid;
	int64_t confirmedunpaid;
	int64_t pendingconfirm;
	int32_t heightupdate;
	MODIFYDATECONTROLFIELDS;
} ACCOUNTBALANCE;

#define ALLOC_ACCOUNTBALANCE 1024
#define LIMIT_ACCOUNTBALANCE 0
#define INIT_ACCOUNTBALANCE(_item) INIT_GENERIC(_item, accountbalance)
#define DATA_ACCOUNTBALANCE(_var, _item) DATA_GENERIC(_var, _item, accountbalance, true)

extern K_TREE *accountbalance_root;
extern K_LIST *accountbalance_free;
extern K_STORE *accountbalance_store;

// ACCOUNTADJUSTMENT
typedef struct accountadjustment {
	int64_t userid;
	char authority[TXT_BIG+1];
	char *reason;
	int64_t amount;
	HISTORYDATECONTROLFIELDS;
} ACCOUNTADJUSTMENT;

#define ALLOC_ACCOUNTADJUSTMENT 100
#define LIMIT_ACCOUNTADJUSTMENT 0
#define INIT_ACCOUNTADJUSTMENT(_item) INIT_GENERIC(_item, accountadjustment)
#define DATA_ACCOUNTADJUSTMENT(_var, _item) DATA_GENERIC(_var, _item, accountadjustment, true)

extern K_TREE *accountadjustment_root;
extern K_LIST *accountadjustment_free;
extern K_STORE *accountadjustment_store;

// IDCONTROL
typedef struct idcontrol {
	char idname[TXT_SML+1];
	int64_t lastid;
	MODIFYDATECONTROLIN;
} IDCONTROL;

#define ALLOC_IDCONTROL 16
#define LIMIT_IDCONTROL 0
#define INIT_IDCONTROL(_item) INIT_GENERIC(_item, idcontrol)
#define DATA_IDCONTROL(_var, _item) DATA_GENERIC(_var, _item, idcontrol, true)

extern K_TREE *idcontrol_root;
extern K_LIST *idcontrol_free;
extern K_STORE *idcontrol_store;

// OPTIONCONTROL
typedef struct optioncontrol {
	char optionname[TXT_SML+1];
	char *optionvalue;
	tv_t activationdate;
	int32_t activationheight;
	HISTORYDATECONTROLFIELDS;
} OPTIONCONTROL;

#define ALLOC_OPTIONCONTROL 64
#define LIMIT_OPTIONCONTROL 0
#define INIT_OPTIONCONTROL(_item) INIT_GENERIC(_item, optioncontrol)
#define DATA_OPTIONCONTROL(_var, _item) DATA_GENERIC(_var, _item, optioncontrol, true)
#define DATA_OPTIONCONTROL_NULL(_var, _item) DATA_GENERIC(_var, _item, optioncontrol, false)

// Value it must default to (to work properly)
#define OPTIONCONTROL_HEIGHT 1
#define MAX_HEIGHT 999999999

// Test it here rather than obscuring the #define elsewhere
#if ((OPTIONCONTROL_HEIGHT+1) != START_POOL_HEIGHT)
#error "START_POOL_HEIGHT must = (OPTIONCONTROL_HEIGHT+1)"
#endif

/* If set, then cmd_auth() will create unknown users
 * It will use the optionvalue as the hex sha256 password hash
 * A blank or random/invalid hash will mean the accounts created
 *  are password locked, like an address account is */
#define OPTIONCONTROL_AUTOADDUSER "AutoAddUser"

extern K_TREE *optioncontrol_root;
extern K_LIST *optioncontrol_free;
extern K_STORE *optioncontrol_store;

typedef struct oc_trigger {
	char *match;
	bool exact;
	void (*func)(OPTIONCONTROL *, const char *);
} OC_TRIGGER;

// ESM (Early Share/Shareerror Messages)
typedef struct esm {
	int64_t workinfoid;
	int queued;
	int procured;
	int discarded;
	int errqueued;
	int errprocured;
	int errdiscarded;
	tv_t createdate;
} ESM;

/* This is to reduce the number of console Early messages
 * The first queued message is displayed LOG_ERR
 *  then the rest, for the given workinfoid, are LOG_NOTICE
 * A final summary for the workinfoid will be displayed later with LOG_ERR,
 *  if there were any */
#define ALLOC_ESM 10
#define LIMIT_ESM 0
#define INIT_ESM(_item) INIT_GENERIC(_item, esm)
#define DATA_ESM(_var, _item) DATA_GENERIC(_var, _item, esm, true)
#define DATA_ESM_NULL(_var, _item) DATA_GENERIC(_var, _item, esm, false)

extern K_TREE *esm_root;
extern K_LIST *esm_free;
extern K_STORE *esm_store;

/* Age limit, in seconds, before displaying ESM summary messages and
 *  deleting the associated ESM record */
#define ESM_LIMIT 60.0

// TODO: discarding workinfo
// WORKINFO workinfo.id.json={...}
typedef struct workinfo {
	int64_t workinfoid;
	char *in_poolinstance;
	char *transactiontree;
	char *merklehash;
	char *in_prevhash;
	char *coinbase1;
	char *coinbase2;
	char *in_version;
	char *in_bits;
	char ntime[TXT_SML+1];
	int64_t reward;
	int32_t height; // non-DB field
	double diff_target; // non-DB field
	HISTORYDATECONTROLIN;
} WORKINFO;

// ~10 hrs
#define ALLOC_WORKINFO 1400
#define LIMIT_WORKINFO 0
#define INIT_WORKINFO(_item) INIT_GENERIC(_item, workinfo)
#define DATA_WORKINFO(_var, _item) DATA_GENERIC(_var, _item, workinfo, true)
#define DATA_WORKINFO_NULL(_var, _item) DATA_GENERIC(_var, _item, workinfo, false)

extern K_TREE *workinfo_root;
// created during data load then destroyed since not needed later
extern K_TREE *workinfo_height_root;
extern K_LIST *workinfo_free;
extern K_STORE *workinfo_store;
// one in the current block
extern K_ITEM *workinfo_current;
// first workinfo of current block
extern tv_t last_bc;
// current network diff
extern double current_ndiff;
extern bool txn_tree_store;
// avoid trying to run 2 ages at the same time
extern bool workinfo_age_lock;

// Offset in binary coinbase1 of the block number
#define BLOCKNUM_OFFSET 42
// Initial block reward (satoshi)
#define REWARD_BASE 5000000000.0
// How many blocks per halving
#define REWARD_HALVE 210000.0

// SHARES shares.id.json={...}
typedef struct shares {
	int64_t workinfoid;
	int64_t userid;
	char *in_workername;
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char nonce2[TXT_BIG+1];
	char nonce[TXT_SML+1];
	double diff;
	double sdiff;
	int32_t errn;
	char error[TXT_SML+1];
	char secondaryuserid[TXT_SML+1];
	char ntime[TXT_SML+1];
	double minsdiff;
	char agent[TXT_MED+1];
	char address[TXT_MED+1];
	HISTORYDATECONTROLFIELDS;
	int32_t redo; // non-DB field
	int32_t oldcount; // non-DB field
} SHARES;

#define ALLOC_SHARES 10000
#define LIMIT_SHARES 0
#define INIT_SHARES(_item) INIT_GENERIC(_item, shares)
#define DATA_SHARES(_var, _item) DATA_GENERIC(_var, _item, shares, true)
#define DATA_SHARES_NULL(_var, _item) DATA_GENERIC(_var, _item, shares, false)

extern K_TREE *shares_root;
extern K_LIST *shares_free;
extern K_STORE *shares_store;
// shares unexpectedly before the workinfo
extern K_TREE *shares_early_root;
extern K_STORE *shares_early_store;
/* DB stored high sdiff shares N.B. they are duplicated,
 *  not relinked, since an item can't be in 2 lists
 * New high shares are placed in both trees then removed from shares_hi_root
 *  after they are stored in the db */
extern K_TREE *shares_hi_root;
extern K_TREE *shares_db_root;
extern K_STORE *shares_hi_store;

/* Once a share is this old, it can only once more be
    check for it's workinfoid and then be discarded */
#define EARLYSHARESLIMIT 60.0

/* All shares this % less than beng a block, or higher,
    will be reported on the console */
#define DIFF_PERCENT_DEFAULT 5
// OptionControl can override it, > 100 means don't do it
#define DIFF_PERCENT_NAME "ShareDiffPercent"

// int diff % -> ratio
#define DIFF_VAL(_v) (1.0 - ((double)(_v) / 100.0))

extern double diff_percent;

/* Record shares in the DB >= this
 * The default of 0 means don't store shares
 * This is set only via the runtime parameter -D or --minsdiff */
extern double share_min_sdiff;

// workinfoid to start loading shares, unset = shares_fill() decides
extern int64_t shares_begin;

// SHAREERRORS shareerrors.id.json={...}
typedef struct shareerrors {
	int64_t workinfoid;
	int64_t userid;
	char *in_workername;
	int32_t clientid;
	int32_t errn;
	char error[TXT_SML+1];
	char secondaryuserid[TXT_SML+1];
	HISTORYDATECONTROLFIELDS;
	int32_t redo; // non-DB field
	int32_t oldcount; // non-DB field
} SHAREERRORS;

#define ALLOC_SHAREERRORS 1000
#define LIMIT_SHAREERRORS 0
#define INIT_SHAREERRORS(_item) INIT_GENERIC(_item, shareerrors)
#define DATA_SHAREERRORS(_var, _item) DATA_GENERIC(_var, _item, shareerrors, true)

extern K_TREE *shareerrors_root;
extern K_LIST *shareerrors_free;
extern K_STORE *shareerrors_store;
// shareerrors unexpectedly before the workinfo
extern K_TREE *shareerrors_early_root;
extern K_STORE *shareerrors_early_store;

// SHARESUMMARY
typedef struct sharesummary {
	int64_t userid;
	char *in_workername;
	int64_t workinfoid;
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
	int64_t sharecount;
	int64_t errorcount;
	tv_t firstshare;
	tv_t lastshare;
	tv_t firstshareacc;
	tv_t lastshareacc;
	double lastdiffacc;
	char complete[TXT_FLAG+1];
} SHARESUMMARY;

/* After this many shares added, we need to update the DB record
   The DB record is added with the 1st share */
#define SHARESUMMARY_UPDATE_EVERY 10

#define ALLOC_SHARESUMMARY 10000
#define LIMIT_SHARESUMMARY 0
#define INIT_SHARESUMMARY(_item) INIT_GENERIC(_item, sharesummary)
#define DATA_SHARESUMMARY(_var, _item) DATA_GENERIC(_var, _item, sharesummary, true)
#define DATA_SHARESUMMARY_NULL(_var, _item) DATA_GENERIC(_var, _item, sharesummary, false)

#define SUMMARY_NEW 'n'
#define SUMMARY_COMPLETE 'a'
#define SUMMARY_CONFIRM 'y'

extern K_TREE *sharesummary_root;
extern K_TREE *sharesummary_workinfoid_root;
extern K_LIST *sharesummary_free;
extern K_STORE *sharesummary_store;
// Pool total sharesummary stats
extern K_TREE *sharesummary_pool_root;
extern K_STORE *sharesummary_pool_store;

#define LUCKNUM 100

// BLOCKS block.id.json={...}
typedef struct blocks {
	int32_t height;
	char blockhash[TXT_BIG+1];
	int64_t workinfoid;
	int64_t userid;
	char *in_workername;
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char nonce2[TXT_BIG+1];
	char nonce[TXT_SML+1];
	int64_t reward;
	char confirmed[TXT_FLAG+1];
	// block Short:Description to use vs default for 'R' in page_blocks.php
	char info[TXT_SML+1];
	double diffacc;
	double diffinv;
	double shareacc;
	double shareinv;
	int64_t elapsed;
	char statsconfirmed[TXT_FLAG+1];
	HISTORYDATECONTROLFIELDS;
	bool ignore; // non-DB field

	// Calculated only when = 0
	double netdiff;

	/* non-DB fields for the web page
	 * Calculate them once off/recalc them when required */
	double blockdiffratio;
	double blockcdf;
	double blockluck;

	/* diffacc for range calculations - includes orphans before it
	 * orphans have this set to 0 so they can't be double counted */
	double diffcalc;

	/* From the last found block to this one
	 * Orphans have these set to zero */
	double diffratio;
	double diffmean;
	double cdferl;
	double luck;
	/* Last LUCKNUM block luck - or
	 *  back to the first block if there aren't LUCKNUM blocks before it */
	double luckhistory;

	// Mean reward ratio per block from last to this
	double txmean;

	// To save looking them up when needed
	tv_t prevcreatedate; // non-DB field
	tv_t blockcreatedate; // non-DB field
} BLOCKS;

#define ALLOC_BLOCKS 100
#define LIMIT_BLOCKS 0
#define INIT_BLOCKS(_item) INIT_GENERIC(_item, blocks)
#define DATA_BLOCKS(_var, _item) DATA_GENERIC(_var, _item, blocks, true)
#define DATA_BLOCKS_NULL(_var, _item) DATA_GENERIC(_var, _item, blocks, false)

#define BLOCKS_NEW 'n'
#define BLOCKS_NEW_STR "n"
#define BLOCKS_CONFIRM '1'
#define BLOCKS_CONFIRM_STR "1"
// 42 doesn't actually mean '42' it means matured
#define BLOCKS_42 'F'
#define BLOCKS_42_STR "F"
// Current block maturity is ...
#define BLOCKS_42_VALUE 101
#define BLOCKS_ORPHAN 'O'
#define BLOCKS_ORPHAN_STR "O"
#define BLOCKS_REJECT 'R'
#define BLOCKS_REJECT_STR "R"

#define BLOCKS_N_C_STR BLOCKS_NEW_STR " or " BLOCKS_CONFIRM_STR
#define BLOCKS_N_C_O_STR BLOCKS_NEW_STR ", " BLOCKS_CONFIRM_STR " or " \
	BLOCKS_ORPHAN_STR
#define BLOCKS_N_C_O_R_STR BLOCKS_NEW_STR ", " BLOCKS_CONFIRM_STR ", " \
	BLOCKS_ORPHAN_STR " or " BLOCKS_REJECT_STR

/* Block height difference required before checking if it's orphaned
 * TODO: add a cmd_blockstatus option to un-orphan a block */
#define BLOCKS_ORPHAN_CHECK 1

#define BLOCKS_STATSPENDING FALSE_CHR
#define BLOCKS_STATSPENDING_STR FALSE_STR
#define BLOCKS_STATSCONFIRMED TRUE_CHR
#define BLOCKS_STATSCONFIRMED_STR TRUE_STR

extern const char *blocks_new;
extern const char *blocks_confirm;
extern const char *blocks_42;
extern const char *blocks_orphan;
extern const char *blocks_reject;
extern const char *blocks_unknown;

#define KANO -27972

extern K_TREE *blocks_root;
extern K_LIST *blocks_free;
extern K_STORE *blocks_store;
// Access both under blocks_free lock
extern tv_t blocks_stats_time;
extern bool blocks_stats_rebuild;

// Default number of blocks to display on web
#define BLOCKS_DEFAULT 42
// OptionControl can override it
#define BLOCKS_SETTING_NAME "BlocksPageSize"

// MININGPAYOUTS
typedef struct miningpayouts {
	int64_t payoutid;
	int64_t userid;
	double diffacc;
	int64_t amount;
	HISTORYDATECONTROLIN;
	K_ITEM *old_item; // non-DB field
} MININGPAYOUTS;

#define ALLOC_MININGPAYOUTS 1000
#define LIMIT_MININGPAYOUTS 0
#define INIT_MININGPAYOUTS(_item) INIT_GENERIC(_item, miningpayouts)
#define DATA_MININGPAYOUTS(_var, _item) DATA_GENERIC(_var, _item, miningpayouts, true)
#define DATA_MININGPAYOUTS_NULL(_var, _item) DATA_GENERIC(_var, _item, miningpayouts, false)

extern K_TREE *miningpayouts_root;
extern K_LIST *miningpayouts_free;
extern K_STORE *miningpayouts_store;

// PAYOUTS
typedef struct payouts {
	int64_t payoutid;
	int32_t height;
	char blockhash[TXT_BIG+1];
	tv_t blockcreatedate; // non-DB field
	int64_t minerreward;
	int64_t workinfoidstart;
	int64_t workinfoidend;
	int64_t elapsed;
	char status[TXT_FLAG+1];
	double diffwanted;
	double diffused;
	double shareacc;
	tv_t lastshareacc;
	char *stats;
	HISTORYDATECONTROLFIELDS;
} PAYOUTS;

#define ALLOC_PAYOUTS 1000
#define LIMIT_PAYOUTS 0
#define INIT_PAYOUTS(_item) INIT_GENERIC(_item, payouts)
#define DATA_PAYOUTS(_var, _item) DATA_GENERIC(_var, _item, payouts, true)
#define DATA_PAYOUTS_NULL(_var, _item) DATA_GENERIC(_var, _item, payouts, false)

extern K_TREE *payouts_root;
extern K_TREE *payouts_id_root;
extern K_TREE *payouts_wid_root;
extern K_LIST *payouts_free;
extern K_STORE *payouts_store;
// Emulate a list for lock checking
extern K_LIST *process_pplns_free;

// N.B. status should be checked under r/w lock
#define PAYOUTS_GENERATED 'G'
#define PAYOUTS_GENERATED_STR "G"
#define PAYGENERATED(_status) ((_status)[0] == PAYOUTS_GENERATED)
// A processing payout must be ignored
#define PAYOUTS_PROCESSING 'P'
#define PAYOUTS_PROCESSING_STR "P"
#define PAYPROCESSING(_status) ((_status)[0] == PAYOUTS_PROCESSING)
// An orphaned payout must be ignored
#define PAYOUTS_ORPHAN 'O'
#define PAYOUTS_ORPHAN_STR "O"
#define PAYORPHAN(_status) ((_status)[0] == PAYOUTS_ORPHAN)
// A rejected payout must be ignored
#define PAYOUTS_REJECT 'R'
#define PAYOUTS_REJECT_STR "R"
#define PAYREJECT(_status) ((_status)[0] == PAYOUTS_REJECT)

// UserAtts to hold payouts
#define HOLD_PAYOUTS "HoldPayouts"
#define HOLD_ADDRESS "hold"
#define NONE_ADDRESS "none"

// Default number of shifts (payouts) to display on web
#define SHIFTS_DEFAULT 99
/* OptionControl can override it
 * UserAtts can also at the user level */
#define SHIFTS_SETTING_NAME "ShiftsPageSize"

// IPS
typedef struct ips {
	char group[TXT_SML+1];
	char ip[TXT_MED+1];
	char eventname[TXT_SML+1];
	bool is_event;
	int lifetime;
	bool log;
	char *description;
	HISTORYDATECONTROLFIELDS;
} IPS;

#define ALLOC_IPS 16
#define LIMIT_IPS 0
#define INIT_IPS(_item) INIT_GENERIC(_item, ips)
#define DATA_IPS(_var, _item) DATA_GENERIC(_var, _item, ips, true)
#define DATA_IPS_NULL(_var, _item) DATA_GENERIC(_var, _item, ips, false)

extern K_TREE *ips_root;
extern K_LIST *ips_free;
extern K_STORE *ips_store;

// Only used by OK
#define EVENTNAME_ALL "*E"
#define OVENTNAME_ALL "*O"

// All eventnames will be less than this
#define EVENTNAME_MAX "~"

#define IPS_GROUP_OK "OK"
#define IPS_GROUP_BAD "BAD"
#define IPS_GROUP_BAN "BAN"

// OptionControl records for IPS_GROUP_OK
#define OC_IPS "ips_"
#define OC_IPS_OK OC_IPS "ok_"
#define OC_IPS_BAN OC_IPS "ban_"

// EVENTS RAM only
typedef struct events {
	int id;
	// class C truncated version of createinet or full IP for IPv6
	char ipc[TXT_MED+1];
	// check for repeated use of the same hash
	char hash[TXT_BIG+1];
	// How many trees the item is still in
	int trees;
	// who: createby, createinet, createdate
	HISTORYDATECONTROLFIELDS;
} EVENTS;

#define ALLOC_EVENTS 1000
#define LIMIT_EVENTS 0
#define INIT_EVENTS(_item) INIT_GENERIC(_item, events)
#define DATA_EVENTS(_var, _item) DATA_GENERIC(_var, _item, events, true)
#define DATA_EVENTS_NULL(_var, _item) DATA_GENERIC(_var, _item, events, false)

extern K_TREE *events_user_root;
extern K_TREE *events_ip_root;
extern K_TREE *events_ipc_root;
extern K_TREE *events_hash_root;
extern K_LIST *events_free;
extern K_STORE *events_store;
// Emulate a list for lock checking     
extern K_LIST *event_limits_free;

#define OC_LIMITS "event_limits_"

// Any password failure
#define EVENTID_PASSFAIL 0
// Add/Change address
#define EVENTID_CREADDR 1
// Create an account
#define EVENTID_CREACC 2
// API unkatts
#define EVENTID_UNKATTS 3
// 2FA rubbish
#define EVENTID_INV2FA 4
// 2FA incorrect
#define EVENTID_WRONG2FA 5
// Attempt change to an invalid BTC address (that required btcd checking)
#define EVENTID_INVBTC 6
// Attempt change to an incorrect BTC address (that failed the ckdb test)
#define EVENTID_INCBTC 7
// Attempt change to another used BTC address
#define EVENTID_BTCUSED 8
// Auto create account
#define EVENTID_AUTOACC 9
// Unknown auth username
#define EVENTID_INVAUTH 10
// Unknown chkpass username
#define EVENTID_INVUSER 11
#define EVENTID_NONE 12

#define EVENT_OK -1

// Homepage valid access
#define OVENTID_HOMEPAGE 0
// Blocks valid access
#define OVENTID_BLOCKS 1
// API valid access
#define OVENTID_API 2
// Add/Update single payment address
#define OVENTID_ONEADDR 3
// Add/Update multi payment address
#define OVENTID_MULTIADDR 4
// Workers valid access
#define OVENTID_WORKERS 5
// Other valid access
#define OVENTID_OTHER 6
#define OVENTID_NONE 7

// OVENTS RAM only (OK EVENTS)
typedef struct ovents {
	// user, ip or ipc
	char key[TXT_SML+1];
	// One record per hour time/3600
	int hour;
	// per id per minute
	int count[OVENTID_NONE * 60];
	HISTORYDATECONTROLFIELDS;
} OVENTS;

#define ALLOC_OVENTS 1000
#define LIMIT_OVENTS 0
#define INIT_OVENTS(_item) INIT_GENERIC(_item, ovents)
#define DATA_OVENTS(_var, _item) DATA_GENERIC(_var, _item, ovents, true)
#define DATA_OVENTS_NULL(_var, _item) DATA_GENERIC(_var, _item, ovents, false)

extern K_TREE *ovents_root;
extern K_LIST *ovents_free;
extern K_STORE *ovents_store;

#define SEC_TO_HOUR(_s) ((int)((_s) / 3600))
#define TV_TO_HOUR(_tv) SEC_TO_HOUR((_tv)->tv_sec)
#define SEC_TO_MIN(_s) ((int)(((_s) % 3600) / 60))
#define TV_TO_MIN(_tv) SEC_TO_MIN((_tv)->tv_sec)
#define IDMIN(_id, _min) ((_id) * 60 + (_min))

#define OC_OLIMITS "ovent_limits_"

#define OVENT_OK EVENT_OK

// Web uses this, so only check IP for this user
#define ANON_USER "Anon"

/* user limits are checked for matching id+user
 * ip limits are checked for matching id+ip,
 *  however, it requires more than one user found with the given ip
 * i.e. a single user will not fail the test result for ip */
typedef struct event_limits {
	int id;
	// optioncontrol/display name
	char *name;
	// enable/disable event/ovent generation
	bool enabled;
	int user_low_time;
	// how many in above limit = ok (+1 = alert)
	int user_low_time_limit;
	int user_hi_time;
	// how many in above limit = ok (+1 = alert)
	int user_hi_time_limit;
	int ip_low_time;
	// how many in above limit = ok (+1 = alert)
	int ip_low_time_limit;
	int ip_hi_time;
	// how many in above limit = ok (+1 = alert)
	int ip_hi_time_limit;
	// expire events
	int lifetime;
} EVENT_LIMITS;

extern EVENT_LIMITS e_limits[];
// Has a fixed limit of 1 event allowed
extern int event_limits_hash_lifetime;

// o_limits uses the event_limits_free lock (since it must)
extern EVENT_LIMITS o_limits[];
// multiply IP limit by this to get IPC limit
extern double ovent_limits_ipc_factor;
// maximum lifetime of all o_limits - set by code
extern int o_limits_max_lifetime;

#define APIKEY "KAPIKey"

// AUTHS authorise.id.json={...}
typedef struct auths {
	int64_t authid;
	char *in_poolinstance;
	int64_t userid;
	char *in_workername;
	int32_t clientid;
	char enonce1[TXT_SML+1];
	char useragent[TXT_BIG+1];
	char preauth[TXT_FLAG+1];
	HISTORYDATECONTROLFIELDS;
} AUTHS;

#define ALLOC_AUTHS 1000
#define LIMIT_AUTHS 0
#define INIT_AUTHS(_item) INIT_GENERIC(_item, auths)
#define DATA_AUTHS(_var, _item) DATA_GENERIC(_var, _item, auths, true)

extern K_TREE *auths_root;
extern K_LIST *auths_free;
extern K_STORE *auths_store;

// POOLSTATS poolstats.id.json={...}
// Store every > 9.5m?
// TODO: redo like userstats, but every 10min
#define STATS_PER (9.5*60.0)

typedef struct poolstats {
	char *in_poolinstance;
	int64_t elapsed;
	int32_t users;
	int32_t workers;
	double hashrate;
	double hashrate5m;
	double hashrate1hr;
	double hashrate24hr;
	bool stored; // non-DB field
	SIMPLEDATECONTROLFIELDS;
} POOLSTATS;

#define ALLOC_POOLSTATS 1000
#define LIMIT_POOLSTATS 0
#define INIT_POOLSTATS(_item) INIT_GENERIC(_item, poolstats)
#define DATA_POOLSTATS(_var, _item) DATA_GENERIC(_var, _item, poolstats, true)
#define DATA_POOLSTATS_NULL(_var, _item) DATA_GENERIC(_var, _item, poolstats, false)

extern K_TREE *poolstats_root;
extern K_LIST *poolstats_free;
extern K_STORE *poolstats_store;

/* USERSTATS userstats.id.json={...}
 * Pool sends each user (staggered) once per 10m
 * As from CKDB V0.840 we don't store any userstats
 *  other than the last one we received,
 *  and we don't store them in the DB at all.
 * Historical stats will come from markersummary
 * Most of the #defines for USERSTATS are no longer needed
 *  but are left here for now for historical reference */
typedef struct userstats {
	char *in_poolinstance;
	int64_t userid;
	char *in_workername;
	int64_t elapsed;
	double hashrate;
	double hashrate5m;
	double hashrate1hr;
	double hashrate24hr;
	bool idle; // non-DB field
	int instances;
	char summarylevel[TXT_FLAG+1]; // SUMMARY_NONE in RAM
	int32_t summarycount;
	tv_t statsdate;
	SIMPLEDATECONTROLFIELDS;
} USERSTATS;

/* The old USERSTATS protocol included a boolean 'eos' that when true,
 * we had received the full set of data for the given
 * createdate batch, and thus could move all (complete) records
 * matching the createdate from userstats_eos_store into the tree */

#define ALLOC_USERSTATS 1000
#define LIMIT_USERSTATS 0
#define INIT_USERSTATS(_item) INIT_GENERIC(_item, userstats)
#define DATA_USERSTATS(_var, _item) DATA_GENERIC(_var, _item, userstats, true)
#define DATA_USERSTATS_NULL(_var, _item) DATA_GENERIC(_var, _item, userstats, false)

extern K_TREE *userstats_root;
extern K_LIST *userstats_free;
extern K_STORE *userstats_store;
// Awaiting EOS
extern K_STORE *userstats_eos_store;

#define NO_INSTANCE_DATA -1

/* 1.5 x how often we expect to get user's stats from ckpool
 * This is used when grouping the sub-worker stats into a single user
 * We add each worker's latest stats to the total - except we ignore
 * any worker with newest stats being older than USERSTATS_PER_S */
#define USERSTATS_PER_S 900

/* on the allusers page, show any with stats in the last ... */
#define ALLUSERS_LIMIT_S 3600

#define SUMMARY_NONE '0'
#define SUMMARY_DB '1'
#define SUMMARY_FULL '2'

/* Userstats get stored in the DB for each time band of this
 * amount from midnight (UTC+00)
 * Thus we simply put each stats value in the time band of the
 * stat's timestamp
 * Userstats are sumarised in the the same userstats table
 * If USERSTATS_DB_S is close to the expected time per USERSTATS
 * then it will have higher variance i.e. obviously: a higher
 * average of stats per sample will mean a lower SD of the number
 * of stats per sample
 * The #if below ensures USERSTATS_DB_S times an integer = a day
 * so the last band is the same size as the rest -
 * and will graph easily
 * Obvious WARNING - the smaller this is, the more stats in the DB
 * This is summary level '1'
 */
#define USERSTATS_DB_S 3600

#if (((24*60*60) % USERSTATS_DB_S) != 0)
#error "USERSTATS_DB_S times an integer must = a day"
#endif

#if ((24*60*60) < USERSTATS_DB_S)
#error "USERSTATS_DB_S must be at most 1 day"
#endif

/* We summarise and discard userstats that are older than the
 * maximum of USERSTATS_DB_S, USERSTATS_PER_S, ALLUSERS_LIMIT_S
 */
#if (USERSTATS_PER_S > ALLUSERS_LIMIT_S)
 #if (USERSTATS_PER_S > USERSTATS_DB_S)
  #define USERSTATS_AGE USERSTATS_PER_S
 #else
  #define USERSTATS_AGE USERSTATS_DB_S
 #endif
#else
 #if (ALLUSERS_LIMIT_S > USERSTATS_DB_S)
  #define USERSTATS_AGE ALLUSERS_LIMIT_S
 #else
  #define USERSTATS_AGE USERSTATS_DB_S
 #endif
#endif

/* TODO: summarisation of the userstats after this many days are done
 * at the day level and the above stats are deleted from the db
 * Obvious WARNING - the larger this is, the more stats in the DB
 * This is summary level '2'
 */
#define USERSTATS_DB_D 7
#define USERSTATS_DB_DS (USERSTATS_DB_D * (60*60*24))

// true if _new is newer, i.e. _old is before _new
#define tv_newer(_old, _new) (((_old)->tv_sec == (_new)->tv_sec) ? \
				((_old)->tv_usec < (_new)->tv_usec) : \
				((_old)->tv_sec < (_new)->tv_sec))
#define tv_equal(_a, _b) (((_a)->tv_sec == (_b)->tv_sec) && \
				((_a)->tv_usec == (_b)->tv_usec))
// newer OR equal
#define tv_newer_eq(_old, _new) (!(tv_newer(_new, _old)))

#define copy_ts(_dest, _src) do { \
		(_dest)->tv_sec = (_src)->tv_sec; \
		(_dest)->tv_nsec = (_src)->tv_nsec; \
	} while(0)

// WORKERSTATUS from various incoming data
typedef struct workerstatus {
	int64_t userid;
	char *in_workername;
	tv_t last_auth;
	tv_t last_share;
	tv_t last_share_acc;
	double last_diff_acc;
	tv_t last_stats;
	tv_t last_idle;
	// Below gets reset on each block
	double block_diffacc;
	double block_diffinv; // Non-acc
	double block_diffsta;
	double block_diffdup;
	double block_diffhi;
	double block_diffrej;
	double block_shareacc;
	double block_shareinv; // Non-acc
	double block_sharesta;
	double block_sharedup;
	double block_sharehi;
	double block_sharerej;
	// Below gets reset on each idle
	double active_diffacc;
	double active_diffinv; // Non-acc
	double active_diffsta;
	double active_diffdup;
	double active_diffhi;
	double active_diffrej;
	double active_shareacc;
	double active_shareinv; // Non-acc
	double active_sharesta;
	double active_sharedup;
	double active_sharehi;
	double active_sharerej;
	tv_t active_start;
} WORKERSTATUS;

#define ALLOC_WORKERSTATUS 1000
#define LIMIT_WORKERSTATUS 0
#define INIT_WORKERSTATUS(_item) INIT_GENERIC(_item, workerstatus)
#define DATA_WORKERSTATUS(_var, _item) DATA_GENERIC(_var, _item, workerstatus, true)

extern K_TREE *workerstatus_root;
extern K_LIST *workerstatus_free;
extern K_STORE *workerstatus_store;

// MARKERSUMMARY
typedef struct markersummary {
	int64_t markerid;
	int64_t userid;
	char *in_workername;
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
	int64_t sharecount;
	int64_t errorcount;
	tv_t firstshare;
	tv_t lastshare;
	tv_t firstshareacc;
	tv_t lastshareacc;
	double lastdiffacc;
	MODIFYDATECONTROLIN;
} MARKERSUMMARY;

#define ALLOC_MARKERSUMMARY 1000
#define LIMIT_MARKERSUMMARY 0
#define INIT_MARKERSUMMARY(_item) INIT_GENERIC(_item, markersummary)
#define DATA_MARKERSUMMARY(_var, _item) DATA_GENERIC(_var, _item, markersummary, true)
#define DATA_MARKERSUMMARY_NULL(_var, _item) DATA_GENERIC(_var, _item, markersummary, false)

extern K_TREE *markersummary_root;
extern K_TREE *markersummary_userid_root;
extern K_LIST *markersummary_free;
extern K_STORE *markersummary_store;
// Pool total markersummary stats
extern K_TREE *markersummary_pool_root;
extern K_STORE *markersummary_pool_store;

// The markerid load start for markersummary
extern char mark_start_type;
extern int64_t mark_start;

// KEYSHARESUMMARY
typedef struct keysharesummary {
	int64_t workinfoid;
	char keytype[TXT_FLAG+1];
	char *key;
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
	int64_t sharecount;
	int64_t errorcount;
	tv_t firstshare;
	tv_t lastshare;
	tv_t firstshareacc;
	tv_t lastshareacc;
	double lastdiffacc;
	char complete[TXT_FLAG+1];
} KEYSHARESUMMARY;

#define ALLOC_KEYSHARESUMMARY 1000
#define LIMIT_KEYSHARESUMMARY 0
#define INIT_KEYSHARESUMMARY(_item) INIT_GENERIC(_item, keysharesummary)
#define DATA_KEYSHARESUMMARY(_var, _item) DATA_GENERIC(_var, _item, keysharesummary, true)
#define DATA_KEYSHARESUMMARY_NULL(_var, _item) DATA_GENERIC(_var, _item, keysharesummary, false)

extern K_TREE *keysharesummary_root;
extern K_LIST *keysharesummary_free;
extern K_STORE *keysharesummary_store;

// KEYSUMMARY
typedef struct keysummary {
	int64_t markerid;
	char keytype[TXT_FLAG+1];
	char *key;
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
	int64_t sharecount;
	int64_t errorcount;
	tv_t firstshare;
	tv_t lastshare;
	tv_t firstshareacc;
	tv_t lastshareacc;
	double lastdiffacc;
	SIMPLEDATECONTROLIN;
} KEYSUMMARY;

#define ALLOC_KEYSUMMARY 1000
#define LIMIT_KEYSUMMARY 0
#define INIT_KEYSUMMARY(_item) INIT_GENERIC(_item, keysummary)
#define DATA_KEYSUMMARY(_var, _item) DATA_GENERIC(_var, _item, keysummary, true)
#define DATA_KEYSUMMARY_NULL(_var, _item) DATA_GENERIC(_var, _item, keysummary, false)

extern K_TREE *keysummary_root;
extern K_LIST *keysummary_free;
extern K_STORE *keysummary_store;

#define KEYTYPE_IP 'i'
#define KEYTYPE_IP_STR "i"
#define KEYIP(_keytype) (tolower((_keytype)[0]) == KEYTYPE_IP)
#define KEYTYPE_AGENT 'a'
#define KEYTYPE_AGENT_STR "a"
#define KEYAGENT(_keytype) (tolower((_keytype)[0]) == KEYTYPE_AGENT)

// WORKMARKERS
typedef struct workmarkers {
	int64_t markerid;
	char *in_poolinstance;
	int64_t workinfoidend;
	int64_t workinfoidstart;
	char *description;
	char status[TXT_FLAG+1];
	int rewards; // non-DB field
	double pps_value; // non-DB field
	double rewarded; // non-DB field
	HISTORYDATECONTROLFIELDS;
} WORKMARKERS;

#define ALLOC_WORKMARKERS 100
#define LIMIT_WORKMARKERS 0
#define INIT_WORKMARKERS(_item) INIT_GENERIC(_item, workmarkers)
#define DATA_WORKMARKERS(_var, _item) DATA_GENERIC(_var, _item, workmarkers, true)
#define DATA_WORKMARKERS_NULL(_var, _item) DATA_GENERIC(_var, _item, workmarkers, false)

extern K_TREE *workmarkers_root;
extern K_TREE *workmarkers_workinfoid_root;
extern K_LIST *workmarkers_free;
extern K_STORE *workmarkers_store;

#define MARKER_READY 'x'
#define MARKER_READY_STR "x"
#define WMREADY(_status) (tolower((_status)[0]) == MARKER_READY)
#define MARKER_PROCESSED 'p'
#define MARKER_PROCESSED_STR "p"
#define WMPROCESSED(_status) (tolower((_status)[0]) == MARKER_PROCESSED)

// MARKS
typedef struct marks {
	char *in_poolinstance;
	int64_t workinfoid;
	char *description;
	char *extra;
	char marktype[TXT_FLAG+1];
	char status[TXT_FLAG+1];
	HISTORYDATECONTROLFIELDS;
} MARKS;

/* marks:
 *  marktype is one of:
 *   b - block end
 *   p - pplns begin
 *   s - shift begin (not used)
 *   e - shift end
 *   o - other begin
 *   f - other finish/end
 *  description generated will be:
 *   b - Block NNN fin
 *   p - Payout NNN stt (where NNN is the block number of the payout)
 *   s - Shift AAA stt
 *   e - Shift AAA fin
 *   o - The string passed to the marks command
 *   f - The string passed to the marks command
 *
 * workmarkers are from a begin workinfoid to an end workinfoid
 *  the "-1" and "+1" below mean adding to or subtracting from
 *  the workinfoid number - but should move forward/back to the
 *  next/prev valid workinfoid, not simply +1 or -1
 *  i.e. all workinfoid in marks and workmarkers must exist in workinfo
 *
 * Until we started using shifts:
 *  workmarkers can be created up to ending in the largest 'p' "-1"
 *  workmarkers will always be the smallest of:
 *   Block NNN-1 "+1" to Block NNN
 *   Block NNN "+1" to Payout MMM "-1"
 *   Payout MMM to Block NNN
 *   Payout MMM-1 to Payout MMM "-1"
 * Thus to generate the workmarkers from the marks:
 *  Find the last USED mark then create a workmarker from each pair of
 *   marks going forward for each READY mark
 *  Set each mark as USED when we use it
 *  Stop when either we run out of marks or find a non-READY mark
 *  Finding a workmarker that already exists is an error
 */

#define ALLOC_MARKS 1000
#define LIMIT_MARKS 0
#define INIT_MARKS(_item) INIT_GENERIC(_item, marks)
#define DATA_MARKS(_var, _item) DATA_GENERIC(_var, _item, marks, true)
#define DATA_MARKS_NULL(_var, _item) DATA_GENERIC(_var, _item, marks, false)

extern K_TREE *marks_root;
extern K_LIST *marks_free;
extern K_STORE *marks_store;

// 'b' used for manual marks and 'extra' description in shifts
#define MARKTYPE_BLOCK 'b'
// 'p' used for manual marks
#define MARKTYPE_PPLNS 'p'
// 's' isn't used - but could be needed for manual marks
#define MARKTYPE_SHIFT_BEGIN 's'
// 'e' used for shifts
#define MARKTYPE_SHIFT_END 'e'
// 'o' used for manual marks
#define MARKTYPE_OTHER_BEGIN 'o'
#define MARKTYPE_OTHER_BEGIN_STR "o"
// 'f' used for manual marks
#define MARKTYPE_OTHER_FINISH 'f'

extern const char *marktype_block;
extern const char *marktype_pplns;
extern const char *marktype_shift_begin;
extern const char *marktype_shift_end;
extern const char *marktype_other_begin;
extern const char *marktype_other_finish;

extern const char *marktype_block_fmt;
extern const char *marktype_pplns_fmt;
extern const char *marktype_shift_begin_fmt;
extern const char *marktype_shift_end_fmt;
extern const char *marktype_other_begin_fmt;
extern const char *marktype_other_finish_fmt;

// For getting back the shift code/name
extern const char *marktype_shift_begin_skip;
extern const char *marktype_shift_end_skip;

#define MARK_READY 'x'
#define MARK_READY_STR "x"
#define MREADY(_status) (tolower((_status)[0]) == MARK_READY)
#define MARK_USED 'u'
#define MARK_USED_STR "u"
#define MUSED(_status) (tolower((_status)[0]) == MARK_USED)

enum info_type {
	INFO_NEW,
	INFO_ORPHAN,
	INFO_REJECT
};

// USERINFO from various incoming data
typedef struct userinfo {
	int64_t userid;
	char *in_username;
	int blocks;
	int orphans; // How many blocks are orphans
	int rejects; // How many blocks are rejects
	tv_t last_block;
	// For all time
	double diffacc;
	double diffsta;
	double diffdup;
	double diffhi;
	double diffrej;
	double shareacc;
	double sharesta;
	double sharedup;
	double sharehi;
	double sharerej;
} USERINFO;

#define ALLOC_USERINFO 1000
#define LIMIT_USERINFO 0
#define INIT_USERINFO(_item) INIT_GENERIC(_item, userinfo)
#define DATA_USERINFO(_var, _item) DATA_GENERIC(_var, _item, userinfo, true)

extern K_TREE *userinfo_root;
extern K_LIST *userinfo_free;
extern K_STORE *userinfo_store;

enum reply_type {
	REPLIER_POOL,
	REPLIER_CMD,
	REPLIER_BTC
};

extern void logmsg(int loglevel, const char *fmt, ...);
extern void setnowts(ts_t *now);
extern void setnow(tv_t *now);
extern void status_report(tv_t *now, bool showseq);
extern void tick();
extern PGconn *dbconnect();
extern void sequence_report(bool lock);

// ***
// *** ckdb_data.c ***
// ***

// optioncontrol names for PPLNS N diff calculation
#define PPLNSDIFFTIMES "pplns_diff_times"
#define PPLNSDIFFADD "pplns_diff_add"

#define REWARDOVERRIDE "MinerReward"

#define PPSOVERRIDE "PPSValue"

// Data free functions (first)
#define FREE_ITEM(item) do { } while(0)
// TODO: make a macro for all other to use above macro
extern void free_transfer_data(TRANSFER *transfer);
extern void free_msgline_data(K_ITEM *item, bool t_lock);
extern void free_users_data(K_ITEM *item);
extern void free_workinfo_data(K_ITEM *item);
#define free_sharesummary_data(_i) FREE_ITEM(_i)
extern void free_payouts_data(K_ITEM *item);
extern void free_ips_data(K_ITEM *item);
extern void free_optioncontrol_data(K_ITEM *item);
#define free_markersummary_data(_i) FREE_ITEM(_i)
extern void free_keysharesummary_data(K_ITEM *item);
extern void free_keysummary_data(K_ITEM *item);
extern void free_workmarkers_data(K_ITEM *item);
extern void free_marks_data(K_ITEM *item);
#define free_seqset_data(_item) _free_seqset_data(_item)
extern void _free_seqset_data(K_ITEM *item);

#define pcom(_n, _buf, _siz) _pcom(_n, _buf, _siz, WHERE_FFL_HERE);
extern void _pcom(int n, char *buf, size_t bufsiz, WHERE_FFL_ARGS);

// Data copy functions
#define COPY_DATA(_new, _old) memcpy(_new, _old, sizeof(*(_new)))

extern void copy_users(USERS *newu, USERS *oldu);
#define copy_blocks(_newb, _oldb) COPY_DATA(_newb, _oldb)

#define safe_text(_txt) _safe_text(_txt, true)
#define safe_text_nonull(_txt) _safe_text(_txt, false)
extern char *_safe_text(char *txt, bool shownull);
extern void username_trim(USERS *users);
extern bool like_address(char *username);

extern void _txt_to_data(enum data_type typ, char *nam, char *fld, void *data, size_t siz, WHERE_FFL_ARGS);

#define txt_to_str(_nam, _fld, _data, _siz) _txt_to_str(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_bigint(_nam, _fld, _data, _siz) _txt_to_bigint(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_int(_nam, _fld, _data, _siz) _txt_to_int(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_tv(_nam, _fld, _data, _siz) _txt_to_tv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_tvdb(_nam, _fld, _data, _siz) _txt_to_tvdb(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_ctv(_nam, _fld, _data, _siz) _txt_to_ctv(_nam, _fld, _data, _siz, WHERE_FFL_HERE)
#define txt_to_blob(_nam, _fld, _data) _txt_to_blob(_nam, _fld, _data, WHERE_FFL_HERE)
#define txt_to_double(_nam, _fld, _data, _siz) _txt_to_double(_nam, _fld, _data, _siz, WHERE_FFL_HERE)

// N.B. STRNCPY* macros truncate, whereas this aborts ckdb if src > trg
extern void _txt_to_str(char *nam, char *fld, char data[], size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_bigint(char *nam, char *fld, int64_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_int(char *nam, char *fld, int32_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_tv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_tvdb(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS);
// Convert msg S,nS to tv_t
extern void _txt_to_ctv(char *nam, char *fld, tv_t *data, size_t siz, WHERE_FFL_ARGS);
extern void _txt_to_blob(char *nam, char *fld, char **data, WHERE_FFL_ARGS);
extern void _txt_to_double(char *nam, char *fld, double *data, size_t siz, WHERE_FFL_ARGS);

extern char *_data_to_buf(enum data_type typ, void *data, char *buf, size_t siz, WHERE_FFL_ARGS);

#define str_to_buf(_data, _buf, _siz) _str_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define bigint_to_buf(_data, _buf, _siz) _bigint_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define int_to_buf(_data, _buf, _siz) _int_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tv_to_buf(_data, _buf, _siz) _tv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define ctv_to_buf(_data, _buf, _siz) _ctv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define ftv_to_buf(_data, _buf, _siz) _ftv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define tvs_to_buf(_data, _buf, _siz) _tvs_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define btv_to_buf(_data, _buf, _siz) _btv_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
//#define blob_to_buf(_data, _buf, _siz) _blob_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define double_to_buf(_data, _buf, _siz) _double_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define t_to_buf(_data, _buf, _siz) _t_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define bt_to_buf(_data, _buf, _siz) _bt_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define btu64_to_buf(_data, _buf, _siz) _btu64_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define hms_to_buf(_data, _buf, _siz) _hms_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)
#define ms_to_buf(_data, _buf, _siz) _ms_to_buf(_data, _buf, _siz, WHERE_FFL_HERE)

extern char *_str_to_buf(char data[], char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_bigint_to_buf(int64_t data, char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_int_to_buf(int32_t data, char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_tv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to S,uS
extern char *_ctv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to S.uS
extern char *_ftv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to seconds (ignore uS)
extern char *_tvs_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert tv to (brief) DD/HH:MM:SS
extern char *_btv_to_buf(tv_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
/* unused yet
extern char *_blob_to_buf(char *data, char *buf, size_t siz, WHERE_FFL_ARGS);
*/
extern char *_double_to_buf(double data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert seconds (only) time to date
extern char *_t_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert seconds (only) time to (brief) M-DD/HH:MM:SS
extern char *_bt_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
extern char *_btu64_to_buf(uint64_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert to HH:MM:SS
extern char *_hms_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);
// Convert to MM:SS
extern char *_ms_to_buf(time_t *data, char *buf, size_t siz, WHERE_FFL_ARGS);

extern cmp_t cmp_intransient(K_ITEM *a, K_ITEM *b);
#define get_intransient(_fld, _val) \
	_get_intransient(_fld, _val, 0, WHERE_FFL_HERE)
#define get_intransient_siz(_fld, _val, _siz) \
	_get_intransient(_fld, _val , _siz, WHERE_FFL_HERE)
extern INTRANSIENT *_get_intransient(const char *fldnam, char *value,
					size_t siz, WHERE_FFL_ARGS);
#define intransient_str(_fld, _val) \
	_intransient_str(_fld, _val, WHERE_FFL_HERE)
extern char *_intransient_str(char *fldnam, char *value, WHERE_FFL_ARGS);
extern void dsp_msgline(K_ITEM *item, FILE *stream);
extern char *_transfer_data(K_ITEM *item, WHERE_FFL_ARGS);
extern void dsp_transfer(K_ITEM *item, FILE *stream);
extern cmp_t cmp_transfer(K_ITEM *a, K_ITEM *b);
#define find_transfer(_trf_root, _name) \
	_find_transfer(_trf_root, _name, WHERE_FFL_HERE)
extern K_ITEM *_find_transfer(K_TREE *trf_root, char *name, WHERE_FFL_ARGS);
#define optional_name(_root, _name, _len, _patt, _reply, _siz) \
		_optional_name(_root, _name, _len, _patt, _reply, _siz, \
				WHERE_FFL_HERE)
extern K_ITEM *_optional_name(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS);
#define require_name(_root, _name, _len, _patt, _reply, _siz) \
		_require_name(_root, _name, _len, _patt, _reply, \
				_siz, WHERE_FFL_HERE)
extern K_ITEM *_require_name(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS);
#define optional_in(_root, _name, _len, _patt, _reply, _siz) \
		_optional_in(_root, _name, _len, _patt, _reply, _siz, \
				WHERE_FFL_HERE)
extern INTRANSIENT *_optional_in(K_TREE *trf_root, char *name, int len,
				 char *patt, char *reply, size_t siz,
				 WHERE_FFL_ARGS);
#define require_in(_root, _name, _len, _patt, _reply, _siz) \
		_require_in(_root, _name, _len, _patt, _reply, \
				_siz, WHERE_FFL_HERE)
extern INTRANSIENT *_require_in(K_TREE *trf_root, char *name, int len, char *patt,
				char *reply, size_t siz, WHERE_FFL_ARGS);
extern cmp_t cmp_workerstatus(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_workerstatus(bool gotlock, int64_t userid, char *workername);
#define find_create_workerstatus(_gl, _ac, _u, _w, _hw, _file, _func, _line) \
	_find_create_workerstatus(_gl, _ac, _u, _w, _hw, _file, _func, _line, \
				  WHERE_FFL_HERE)
extern K_ITEM *_find_create_workerstatus(bool gotlock, bool alertcreate,
					 int64_t userid, char *workername,
					 bool hasworker, const char *file2,
					 const char *func2, const int line2,
					 WHERE_FFL_ARGS);
extern void zero_all_active(tv_t *when);
extern void workerstatus_ready();
#define workerstatus_update(_auths, _shares, _userstats) \
	_workerstatus_update(_auths, _shares, _userstats, WHERE_FFL_HERE)
extern void _workerstatus_update(AUTHS *auths, SHARES *shares,
				 USERSTATS *userstats, WHERE_FFL_ARGS);
extern cmp_t cmp_replies(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_users(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_userid(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_users(char *username);
extern K_ITEM *find_userid(int64_t userid);
extern void make_salt(USERS *users);
extern void password_hash(char *username, char *passwordhash, char *salt,
			  char *result, size_t siz);
extern bool check_hash(USERS *users, char *passwordhash);
extern void users_databits(USERS *users);
#define users_userdata_get_hex(_users, _name, _bit, _hexlen) \
	_users_userdata_get_hex(_users, _name, _bit, _hexlen, WHERE_FFL_HERE)
extern char *_users_userdata_get_hex(USERS *users, char *name, int64_t bit,
				     size_t *hexlen, WHERE_FFL_ARGS);
#define users_userdata_get_bin(_users, _name, _bit, _binlen) \
	_users_userdata_get_bin(_users, _name, _bit, _binlen, WHERE_FFL_HERE)
extern unsigned char *_users_userdata_get_bin(USERS *users, char *name,
					      int64_t bit, size_t *binlen,
					      WHERE_FFL_ARGS);
#define users_userdata_del(_users, _name, _bit) \
	_users_userdata_del(_users, _name, _bit, WHERE_FFL_HERE)
extern void _users_userdata_del(USERS *users, char *name, int64_t bit,
				WHERE_FFL_ARGS);
// If we want to store a simple string, no point encoding it
#define users_userdata_add_txt(_users, _name, _bit, _hex) \
	_users_userdata_add_hex(_users, _name, _bit, _hex, WHERE_FFL_HERE)
#define users_userdata_add_hex(_users, _name, _bit, _hex) \
	_users_userdata_add_hex(_users, _name, _bit, _hex, WHERE_FFL_HERE)
extern void _users_userdata_add_hex(USERS *users, char *name, int64_t bit,
				    char *hex, WHERE_FFL_ARGS);
#define users_userdata_add_bin(_users, _name, _bit, _bin, _len) \
	_users_userdata_add_bin(_users, _name, _bit, _bin, _len, WHERE_FFL_HERE)
extern void _users_userdata_add_bin(USERS *users, char *name, int64_t bit,
				    unsigned char *bin, size_t len,
				    WHERE_FFL_ARGS);
extern cmp_t cmp_useratts(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_useratts(int64_t userid, char *attname);
extern cmp_t cmp_workers(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_workers(bool gotlock, int64_t userid, char *workername);
extern K_ITEM *first_workers(int64_t userid, K_TREE_CTX *ctx);
extern K_ITEM *new_worker(PGconn *conn, bool update, int64_t userid, char *workername,
			  char *diffdef, char *idlenotificationenabled,
			  char *idlenotificationtime, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern K_ITEM *new_default_worker(PGconn *conn, bool update, int64_t userid, char *workername,
				  char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern void dsp_paymentaddresses(K_ITEM *item, FILE *stream);
extern cmp_t cmp_paymentaddresses(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_payaddr_create(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_paymentaddresses(int64_t userid, K_TREE_CTX *ctx);
extern K_ITEM *find_paymentaddresses_create(int64_t userid, K_TREE_CTX *ctx);
extern K_ITEM *find_one_payaddress(int64_t userid, char *payaddress, K_TREE_CTX *ctx);
extern K_ITEM *find_any_payaddress(char *payaddress);
extern cmp_t cmp_payments(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_payments(int64_t payoutid, int64_t userid, char *subname);
extern K_ITEM *find_first_payments(int64_t userid, K_TREE_CTX *ctx);
extern K_ITEM *find_first_paypayid(int64_t userid, int64_t payoutid, K_TREE_CTX *ctx);
extern cmp_t cmp_accountbalance(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_accountbalance(int64_t userid);
extern void dsp_idcontrol(K_ITEM *item, FILE *stream);
extern cmp_t cmp_idcontrol(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_idcontrol(char *idname);
extern cmp_t cmp_optioncontrol(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_optioncontrol(char *optionname, const tv_t *now, int32_t height);
#define sys_setting(_name, _def, _now) user_sys_setting(0, _name, _def, _now)
extern int64_t user_sys_setting(int64_t userid, char *setting_name,
				int64_t setting_default, const tv_t *now);
extern cmp_t cmp_esm(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_esm(int64_t workinfoid);
extern bool esm_flag(int64_t workinfoid, bool error, bool procured);
extern void esm_check(tv_t *now);
extern cmp_t cmp_workinfo(K_ITEM *a, K_ITEM *b);
#define coinbase1height(_wi) _coinbase1height(_wi, WHERE_FFL_HERE)
extern int32_t _coinbase1height(WORKINFO *wi, WHERE_FFL_ARGS);
extern cmp_t cmp_workinfo_height(K_ITEM *a, K_ITEM *b);
#define find_workinfo(_wid, _ctx) _find_workinfo(_wid, false, _ctx);
extern K_ITEM *_find_workinfo(int64_t workinfoid, bool gotlock, K_TREE_CTX *ctx);
extern K_ITEM *next_workinfo(int64_t workinfoid, K_TREE_CTX *ctx);
extern K_ITEM *find_workinfo_esm(int64_t workinfoid, bool error, bool *created,
				 tv_t *createdate);
extern bool workinfo_age(int64_t workinfoid, INTRANSIENT *in_poolinstance,
			 tv_t *cd, tv_t *ss_first, tv_t *ss_last,
			 int64_t *ss_count, int64_t *s_count, int64_t *s_diff);
extern double coinbase_reward(int32_t height);
extern double workinfo_pps(K_ITEM *w_item, int64_t workinfoid);
extern cmp_t cmp_shares(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_shares_db(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_shareerrors(K_ITEM *a, K_ITEM *b);
extern void dsp_sharesummary(K_ITEM *item, FILE *stream);
extern cmp_t cmp_sharesummary(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_sharesummary_workinfoid(K_ITEM *a, K_ITEM *b);
extern void zero_sharesummary(SHARESUMMARY *row);
#define find_sharesummary(_userid, _workername, _workinfoid) \
	_find_sharesummary(_userid, _workername, _workinfoid, false)
#define find_sharesummary_p(_workinfoid) \
	_find_sharesummary(KANO, EMPTY, _workinfoid, true)
#define POOL_SS(_row) do { \
		(_row)->userid = KANO; \
		(_row)->in_workername = EMPTY; \
	} while (0)
extern K_ITEM *_find_sharesummary(int64_t userid, char *workername,
				  int64_t workinfoid, bool pool);
extern K_ITEM *find_last_sharesummary(int64_t userid, char *workername);
extern void auto_age_older(int64_t workinfoid, INTRANSIENT *in_poolinstance,
			   tv_t *cd);
#define dbhash2btchash(_hash, _buf, _siz) \
	_dbhash2btchash(_hash, _buf, _siz, WHERE_FFL_HERE)
void _dbhash2btchash(char *hash, char *buf, size_t siz, WHERE_FFL_ARGS);
#define dsp_hash(_hash, _buf, _siz) \
	_dsp_hash(_hash, _buf, _siz, WHERE_FFL_HERE)
extern void _dsp_hash(char *hash, char *buf, size_t siz, WHERE_FFL_ARGS);
#define blockhash_diff(_hash) _blockhash_diff(_hash, WHERE_FFL_HERE)
extern double _blockhash_diff(char *hash, WHERE_FFL_ARGS);
extern void dsp_blocks(K_ITEM *item, FILE *stream);
extern cmp_t cmp_blocks(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_blocks(int32_t height, char *blockhash, K_TREE_CTX *ctx);
extern K_ITEM *find_prev_blocks(int32_t height, K_TREE_CTX *ctx);
extern const char *blocks_confirmed(char *confirmed);
extern void zero_on_new_block(bool gotlock);
extern void set_block_share_counters();
extern bool check_update_blocks_stats(tv_t *stats);
#define set_blockcreatedate(_h) _set_blockcreatedate(_h, WHERE_FFL_HERE)
extern bool _set_blockcreatedate(int32_t oldest_height, WHERE_FFL_ARGS);
#define set_prevcreatedate(_oh) _set_prevcreatedate(_oh, WHERE_FFL_HERE)
extern bool _set_prevcreatedate(int32_t oldest_height, WHERE_FFL_ARGS);
extern cmp_t cmp_miningpayouts(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_miningpayouts(int64_t payoutid, int64_t userid);
extern K_ITEM *first_miningpayouts(int64_t payoutid, K_TREE_CTX *ctx);
extern cmp_t cmp_mu(K_ITEM *a, K_ITEM *b);
extern void upd_add_mu(K_TREE *mu_root, K_STORE *mu_store, int64_t userid,
			double diffacc);
extern cmp_t cmp_payouts(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_payouts_id(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_payouts_wid(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_payouts(int32_t height, char *blockhash);
extern K_ITEM *first_payouts(int32_t height, K_TREE_CTX *ctx);
extern K_ITEM *find_last_payouts();
extern K_ITEM *find_payoutid(int64_t payoutid);
extern K_ITEM *find_payouts_wid(int64_t workinfoidend, K_TREE_CTX *ctx);
extern double payout_stats(PAYOUTS *payouts, char *statname);
extern bool process_pplns(int32_t height, char *blockhash, tv_t *now);
extern cmp_t cmp_ips(K_ITEM *a, K_ITEM *b);
extern bool _is_limitname(bool is_event, char *eventname, bool allow_all);
#define is_elimitname(_name, _all) _is_limitname(true, _name, _all)
#define is_olimitname(_name, _all) _is_limitname(false, _name, _all)
extern K_ITEM *find_ips(char *group, char *ip, char *eventname, K_TREE_CTX *ctx);
extern K_ITEM *last_ips(char *group, char *ip, K_TREE_CTX *ctx);
extern bool _ok_ips(bool is_event, char *ip, char *eventname, tv_t *now);
#define ok_ips_event(_ip, _name, _now) _ok_ips(true, _ip, _name, _now)
#define ok_ips_ovent(_ip, _name, _now) _ok_ips(false, _ip, _name, _now)
extern bool banned_ips(char *ip, tv_t *now, bool *is_event);
extern cmp_t cmp_events_user(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_events_ip(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_events_ipc(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_events_hash(K_ITEM *a, K_ITEM *b);
extern K_ITEM *last_events_user(int id, char *user, K_TREE_CTX *ctx);
extern K_ITEM *last_events_ip(int id, char *ip, K_TREE_CTX *ctx);
extern K_ITEM *last_events_ipc(int id, char *ipc, K_TREE_CTX *ctx);
extern K_ITEM *last_events_hash(int id, char *hash, K_TREE_CTX *ctx);
extern int check_events(EVENTS *events);
extern char *_reply_event(bool is_event, int event, char *buf, bool fre);
#define reply_event(_event, _buf) _reply_event(true, _event, _buf, false)
#define reply_event_free(_event, _buf) _reply_event(true, _event, _buf, true)
#define reply_ovent(_event, _buf) _reply_event(false, _event, _buf, false)
#define reply_ovent_free(_event, _buf) _reply_event(false, _event, _buf, true)
extern cmp_t cmp_ovents(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_ovents(char *key, int hour, K_TREE_CTX *ctx);
extern K_ITEM *last_ovents(char *key, K_TREE_CTX *ctx);
extern int check_ovents(int id, char *u_key, char *i_key, char *c_key, tv_t *now);
extern cmp_t cmp_auths(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_poolstats(K_ITEM *a, K_ITEM *b);
extern void dsp_userstats(K_ITEM *item, FILE *stream);
extern cmp_t cmp_userstats(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_userstats(int64_t userid, char *workername);
extern void dsp_markersummary(K_ITEM *item, FILE *stream);
extern cmp_t cmp_markersummary(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_markersummary_userid(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_markersummary_userid(int64_t userid, char *workername,
					 K_TREE_CTX *ctx);
#define find_markersummary(_workinfoid, _userid, _workername) \
	_find_markersummary(0, _workinfoid, _userid, _workername, false)
#define find_markersummary_p(_markerid) \
	_find_markersummary(_markerid, 0, KANO, EMPTY, true)
#define POOL_MS(_row) do { \
		(_row)->userid = KANO; \
		(_row)->in_workername = EMPTY; \
	} while (0)
extern K_ITEM *_find_markersummary(int64_t markerid, int64_t workinfoid,
				   int64_t userid, char *workername, bool pool);
extern bool make_markersummaries(bool msg, char *by, char *code, char *inet,
				 tv_t *cd, K_TREE *trf_root);
extern cmp_t cmp_keysharesummary(K_ITEM *a, K_ITEM *b);
extern void zero_keysharesummary(KEYSHARESUMMARY *row);
extern K_ITEM *find_keysharesummary(int64_t workinfoid, char keytype, char *key);
extern cmp_t cmp_keysummary(K_ITEM *a, K_ITEM *b);
extern void dsp_workmarkers(K_ITEM *item, FILE *stream);
extern cmp_t cmp_workmarkers(K_ITEM *a, K_ITEM *b);
extern cmp_t cmp_workmarkers_workinfoid(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_workmarkers(int64_t workinfoid, bool anystatus, char status, K_TREE_CTX *ctx);
extern K_ITEM *find_workmarkerid(int64_t markerid, bool anystatus, char status);
extern bool workmarkers_generate(PGconn *conn, char *err, size_t siz,
				 char *by, char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root, bool none_error);
extern bool reward_shifts(PAYOUTS *payouts, int delta);
extern bool shift_rewards(K_ITEM *wm_item);
extern cmp_t cmp_marks(K_ITEM *a, K_ITEM *b);
extern K_ITEM *find_marks(int64_t workinfoid);
extern const char *marks_marktype(char *marktype);
#define marks_description(_description, _siz, _marktype, _height, _shift, _other) \
	_marks_description(_description, _siz, _marktype, _height, _shift, _other, WHERE_FFL_HERE)
extern bool _marks_description(char *description, size_t siz, char *marktype,
				int32_t height, char *shift, char *other,
				WHERE_FFL_ARGS);
extern char *shiftcode(tv_t *createdate);
extern cmp_t cmp_userinfo(K_ITEM *a, K_ITEM *b);
extern K_ITEM *get_userinfo(int64_t userid);
#define find_create_userinfo(_userid) _find_create_userinfo(_userid, WHERE_FFL_HERE)
extern K_ITEM *_find_create_userinfo(int64_t userid, WHERE_FFL_ARGS);
extern void userinfo_update(SHARES *shares, SHARESUMMARY *sharesummary,
			    MARKERSUMMARY *markersummary, bool ss_sub);
extern void userinfo_block(BLOCKS *blocks, enum info_type isnew, int delta);

// ***
// *** PostgreSQL functions ckdb_dbio.c
// ***

/* These PG/PQ defines need to exist outside ckdb_dbio.c
 * since external functions can choose to run a single transaction
 * over a set of dbio functions */
#define PGOK(_res) ((_res) == PGRES_COMMAND_OK || \
			(_res) == PGRES_TUPLES_OK || \
			(_res) == PGRES_EMPTY_QUERY)

#define SQL_UNIQUE_VIOLATION "23505"

#define CKPQ_READ true
#define CKPQ_WRITE false

#define CKPQExec(_conn, _qry, _isread) _CKPQExec(_conn, _qry, _isread, WHERE_FFL_HERE)
extern PGresult *_CKPQExec(PGconn *conn, const char *qry, bool isread, WHERE_FFL_ARGS);
#define CKPQExecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, _isread) \
			_CKPQExecParams(_conn, _qry, _p1, _p2, _p3, _p4, _p5, _p6, \
			_isread, WHERE_FFL_HERE)
extern PGresult *_CKPQExecParams(PGconn *conn, const char *qry,
				 int nParams,
				 const Oid *paramTypes,
				 const char *const * paramValues,
				 const int *paramLengths,
				 const int *paramFormats,
				 int resultFormat,
				 bool isread, WHERE_FFL_ARGS);
extern ExecStatusType _CKPQResultStatus(PGresult *res, WHERE_FFL_ARGS);
#define CKPQResultStatus(_res) _CKPQResultStatus(_res, WHERE_FFL_HERE)
extern void _CKPQClear(PGresult *res, WHERE_FFL_ARGS);
#define CKPQClear(_res) _CKPQClear(_res, WHERE_FFL_HERE)

#define PGLOG(__LOG, __str, __rescode, __conn) do { \
		char *__buf = pqerrmsg(__conn); \
		__LOG("%s(): %s failed (%d) '%s'", __func__, \
			__str, (int)rescode, __buf); \
		free(__buf); \
	} while (0)

#define PGLOGERR(_str, _rescode, _conn) PGLOG(LOGERR, _str, _rescode, _conn)
#define PGLOGEMERG(_str, _rescode, _conn) PGLOG(LOGEMERG, _str, _rescode, _conn)
#define PGLOGNOTICE(_str, _rescode, _conn) PGLOG(LOGNOTICE, _str, _rescode, _conn)

extern void _pause_read_lock(WHERE_FFL_ARGS);
#define pause_read_lock() _pause_read_lock(WHERE_FFL_HERE)
extern void _pause_read_unlock(WHERE_FFL_ARGS);
#define pause_read_unlock() _pause_read_unlock(WHERE_FFL_HERE)
extern char *pqerrmsg(PGconn *conn);
extern bool _CKPQConn(PGconn **conn, WHERE_FFL_ARGS);
#define CKPQConn(_conn) _CKPQConn(_conn, WHERE_FFL_HERE)
extern bool _CKPQDisco(PGconn **conn, bool conned, WHERE_FFL_ARGS);
#define CKPQDisco(_conn, _conned) _CKPQDisco(_conn, _conned, WHERE_FFL_HERE)
#define CKPQFinish(_conn) CKPQDisco(_conn, true)
extern bool _CKPQBegin(PGconn *conn, WHERE_FFL_ARGS);
#define CKPQBegin(_conn) _CKPQBegin(conn, WHERE_FFL_HERE)
extern void _CKPQEnd(PGconn *conn, bool commit, WHERE_FFL_ARGS);
#define CKPQEnd(_conn, _commit) _CKPQEnd(_conn, _commit, WHERE_FFL_HERE)
#define CKPQCommit(_conn) _CKPQEnd(_conn, true, WHERE_FFL_HERE)

extern int64_t nextid(PGconn *conn, char *idname, int64_t increment,
			tv_t *cd, char *by, char *code, char *inet);
extern bool users_update(PGconn *conn, K_ITEM *u_item, char *oldhash,
			 char *newhash, char *email, char *by, char *code,
			 char *inet, tv_t *cd, K_TREE *trf_root, char *status,
			 int *event);
extern K_ITEM *users_add(PGconn *conn, INTRANSIENT *in_username,
			 char *emailaddress, char *passwordhash,
			 char *secondaryuserid, int64_t userbits, char *by,
			 char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool users_replace(PGconn *conn, K_ITEM *u_item, K_ITEM *old_u_item,
			  char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root);
extern K_ITEM *create_missing_user(PGconn *conn, char *username,
				   char *secondaryuserid, char *by, char *code,
				   char *inet, tv_t *cd, K_TREE *trf_root);
extern bool users_fill(PGconn *conn);
extern bool useratts_item_add(PGconn *conn, K_ITEM *ua_item, tv_t *cd,
				bool begun);
extern K_ITEM *useratts_add(PGconn *conn, char *username, char *attname,
				char *status, char *attstr, char *attstr2,
				char *attnum, char *attnum2,  char *attdate,
				char *attdate2, char *by, char *code,
				char *inet, tv_t *cd, K_TREE *trf_root,
				bool begun);
extern bool useratts_item_expire(PGconn *conn, K_ITEM *ua_item, tv_t *cd);
extern bool useratts_fill(PGconn *conn);
extern K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername,
			   bool add_ws, char *difficultydefault,
			   char *idlenotificationenabled,
			   char *idlenotificationtime, char *by,
			   char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool workers_update(PGconn *conn, K_ITEM *item, char *difficultydefault,
			   char *idlenotificationenabled,
			   char *idlenotificationtime, char *by, char *code,
			   char *inet, tv_t *cd, K_TREE *trf_root, bool check);
extern bool workers_fill(PGconn *conn);
extern bool paymentaddresses_set(PGconn *conn, int64_t userid, K_LIST *pa_store,
				 char *by, char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root);
extern bool paymentaddresses_fill(PGconn *conn);
extern void payments_add_ram(bool ok, K_ITEM *mp_item, K_ITEM *old_mp_item,
				tv_t *cd);
extern bool payments_add(PGconn *conn, bool add, K_ITEM *p_item,
			 K_ITEM **old_p_item, char *by, char *code, char *inet,
			 tv_t *cd, K_TREE *trf_root, bool already);
extern bool payments_fill(PGconn *conn);
extern bool idcontrol_add(PGconn *conn, char *idname, char *idvalue, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool idcontrol_fill(PGconn *conn);
extern K_ITEM *optioncontrol_item_add(PGconn *conn, K_ITEM *oc_item, tv_t *cd, bool begun);
extern K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
				 char *activationdate, char *activationheight,
				 char *by, char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root, bool begun);
extern bool optioncontrol_fill(PGconn *conn);
extern int64_t workinfo_add(PGconn *conn, char *workinfoidstr,
				INTRANSIENT *in_poolinstance, char *transactiontree,
				char *merklehash, INTRANSIENT *in_prevhash,
				char *coinbase1, char *coinbase2, INTRANSIENT *in_version,
				INTRANSIENT *in_bits, char *ntime, char *reward, char *by,
				char *code, char *inet, tv_t *cd, bool igndup,
				K_TREE *trf_root);
extern bool workinfo_fill(PGconn *conn);
extern bool shares_add(PGconn *conn, char *workinfoid, char *username,
			INTRANSIENT *in_workername, char *clientid, char *errn,
			char *enonce1, char *nonce2, char *nonce, char *diff,
			char *sdiff, char *secondaryuserid, char *ntime,
			char *address, char *agent, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root);
extern bool shares_db(PGconn *conn, K_ITEM *s_item);
extern bool shares_fill(PGconn *conn);
extern bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
				INTRANSIENT *in_workername, char *clientid,
				char *errn, char *error, char *secondaryuserid,
				char *by, char *code, char *inet, tv_t *cd,
				K_TREE *trf_root);
extern bool sharesummaries_to_markersummaries(PGconn *conn, WORKMARKERS *workmarkers,
						char *by, char *code, char *inet,
						tv_t *cd, K_TREE *trf_root);
extern bool delete_markersummaries(PGconn *conn, WORKMARKERS *wm);
extern char *ooo_status(char *buf, size_t siz);
#define sharesummary_update(_s_row, _e_row, _cd) \
	_sharesummary_update(_s_row, _e_row, _cd, WHERE_FFL_HERE)
extern bool _sharesummary_update(SHARES *s_row, SHAREERRORS *e_row, tv_t *cd,
				 WHERE_FFL_ARGS);
extern bool sharesummary_age(K_ITEM *ss_item);
extern bool keysharesummary_age(K_ITEM *kss_item);
extern bool sharesummary_fill(PGconn *conn);
extern bool blocks_stats(PGconn *conn, int32_t height, char *blockhash,
			 double diffacc, double diffinv, double shareacc,
			 double shareinv, int64_t elapsed,
			 char *by, char *code, char *inet, tv_t *cd);
extern bool blocks_add(PGconn *conn, int32_t height, char *blockhash,
			char *confirmed, char *info, char *workinfoid,
			char *username, INTRANSIENT *in_workername,
			char *clientid, char *enonce1, char *nonce2,
			char *nonce, char *reward, char *by, char *code,
			char *inet, tv_t *cd, bool igndup, char *id,
			K_TREE *trf_root);
extern bool blocks_fill(PGconn *conn);
extern void miningpayouts_add_ram(bool ok, K_ITEM *mp_item, K_ITEM *old_mp_item,
				  tv_t *cd);
extern bool miningpayouts_add(PGconn *conn, bool add, K_ITEM *mp_item,
				K_ITEM **old_mp_item, char *by, char *code,
				char *inet, tv_t *cd, K_TREE *trf_root,
				bool already);
extern bool miningpayouts_fill(PGconn *conn);
extern void payouts_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item,
			    tv_t *cd);
extern bool payouts_add(PGconn *conn, bool add, K_ITEM *p_item,
			K_ITEM **old_p_item, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root, bool already);
extern K_ITEM *payouts_full_expire(PGconn *conn, int64_t payoutid, tv_t *now,
				bool lock);
extern bool payouts_fill(PGconn *conn);
extern void ips_add(char *group, char *ip, char *eventname, bool is_event,
		    char *des, bool log, bool cclass, int life, bool locked);
extern int _events_add(int id, char *by, char *inet, tv_t *cd, K_TREE *trf_root);
#define events_add(_id, _trf_root) _events_add(_id, NULL, NULL, NULL, _trf_root)
extern int _ovents_add(int id, char *by, char *inet, tv_t *cd, K_TREE *trf_root);
#define ovents_add(_id, _trf_root) _ovents_add(_id, NULL, NULL, NULL, _trf_root)
extern bool auths_add(PGconn *conn, INTRANSIENT *in_poolinstance,
			INTRANSIENT *in_username, INTRANSIENT *in_workername,
			char *clientid, char *enonce1, char *useragent,
			char *preauth, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root, bool addressuser,
			USERS **users, WORKERS **workers, int *event,
			bool reload_data);
extern bool poolstats_add(PGconn *conn, bool store, INTRANSIENT *in_poolinstance,
				char *elapsed, char *users, char *workers,
				char *hashrate, char *hashrate5m,
				char *hashrate1hr, char *hashrate24hr,
				char *by, char *code, char *inet, tv_t *cd,
				bool igndup, K_TREE *trf_root);
extern bool poolstats_fill(PGconn *conn);
extern bool userstats_add_db(PGconn *conn, USERSTATS *row);
extern bool userstats_add(INTRANSIENT *in_poolinstance, char *elapsed, char *username,
			  INTRANSIENT *in_workername, char *hashrate,
			  char *hashrate5m, char *hashrate1hr,
			  char *hashrate24hr, bool idle, bool eos, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root);
extern bool workerstats_add(INTRANSIENT *in_poolinstance, char *elapsed, char *username,
			    INTRANSIENT *in_workername, char *hashrate,
			    char *hashrate5m, char *hashrate1hr,
			    char *hashrate24hr, bool idle, char *instances,
			    char *by, char *code, char *inet, tv_t *cd,
			    K_TREE *trf_root);
extern bool userstats_fill(PGconn *conn);
extern bool markersummary_add(PGconn *conn, K_ITEM *ms_item, char *by, char *code,
				char *inet, tv_t *cd, K_TREE *trf_root);
extern bool markersummary_fill(PGconn *conn);
extern bool keysummary_add(PGconn *conn, K_ITEM *ks_item, char *by, char *code,
			   char *inet, tv_t *cd);
#define workmarkers_process(_conn, _already, _add, _markerid, _poolinstance, \
			    _workinfoidend, _workinfoidstart, _description, \
			    _status, _by, _code, _inet, _cd, _trf_root) \
	_workmarkers_process(_conn, _already, _add, _markerid, _poolinstance, \
			     _workinfoidend, _workinfoidstart, _description, \
			     _status, _by, _code, _inet, _cd, _trf_root, \
			     WHERE_FFL_HERE)
extern bool _workmarkers_process(PGconn *conn, bool already, bool add,
				 int64_t markerid, char *poolinstance,
				 int64_t workinfoidend, int64_t workinfoidstart,
				 char *description, char *status, char *by,
				 char *code, char *inet, tv_t *cd,
				 K_TREE *trf_root, WHERE_FFL_ARGS);
extern bool workmarkers_fill(PGconn *conn);
#define marks_process(_conn, _add, _poolinstance, _workinfoid, _description, \
		      _extra, _marktype, _status, _by, _code, _inet, _cd, \
		      _trf_root) \
	_marks_process(_conn, _add, _poolinstance, _workinfoid, _description, \
		      _extra, _marktype, _status, _by, _code, _inet, _cd, \
		      _trf_root, WHERE_FFL_HERE)
extern bool _marks_process(PGconn *conn, bool add, char *poolinstance,
			   int64_t workinfoid, char *description,
			   char *extra, char *marktype, char *status,
			   char *by, char *code, char *inet, tv_t *cd,
			   K_TREE *trf_root, WHERE_FFL_ARGS);
extern bool marks_fill(PGconn *conn);
extern bool check_db_version(PGconn *conn);

// ***
// *** ckdb_cmd.c
// ***

#define ACCESS_POOL	(1 << 0)
#define ACCESS_SYSTEM	(1 << 1)
#define ACCESS_WEB	(1 << 2)
#define ACCESS_PROXY	(1 << 3)
#define ACCESS_CKDB	(1 << 4)
#define ACCESS_ALL (ACCESS_POOL | ACCESS_SYSTEM | ACCESS_WEB | ACCESS_PROXY | \
		    ACCESS_CKDB)

struct CMDS {
	enum cmd_values cmd_val;
	char *cmd_str;
	bool noid; // doesn't require an id
	bool createdate; // requires a createdate
	char *(*func)(PGconn *, char *, char *, tv_t *, char *, char *,
			char *, tv_t *, K_TREE *, bool);
	enum seq_num seq;
	int access;
};

extern struct CMDS ckdb_cmds[];

// ***
// *** ckdb_btc.c
// ***

extern bool btc_valid_address(char *addr);
extern bool btc_orphancheck(BLOCKS *blocks);
extern void btc_blockstatus(BLOCKS *blocks);

// ***
// *** ckdb_crypt.c
// ***

#define tob32(_users, _bin, _len, _name, _olen) \
	_tob32(_users, _bin, _len, _name, _olen, WHERE_FFL_HERE)
extern char *_tob32(USERS *users, unsigned char *bin, size_t len, char *name,
		    size_t olen, WHERE_FFL_ARGS);
extern bool gen_data(USERS *users, unsigned char *buf, size_t len,
		     int32_t entropy);
extern K_ITEM *gen_2fa_key(K_ITEM *old_u_item, int32_t entropy, char *by,
			   char *code, char *inet, tv_t *cd,  K_TREE *trf_root);
extern bool check_2fa(USERS *users, int32_t value);
extern bool tst_2fa(K_ITEM *old_u_item, int32_t value, char *by, char *code,
		    char *inet, tv_t *cd, K_TREE *trf_root);
extern K_ITEM *remove_2fa(K_ITEM *old_u_item, int32_t value, char *by,
			  char *code, char *inet, tv_t *cd, K_TREE *trf_root,
			  bool check);

#endif
