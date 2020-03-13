/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 1995-2016 Andrew Smith
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "asicseer-db.h"

/* This code's lock implementation is equivalent to table level locking
 * Consider adding row level locking (a per kitem usage count) if needed
 */

/* Thread layout
 * -------------
 * Any thread that manages a thread count will have 00 in it's name
 *  and name each subsequent thread it creates, with the same name
 *  but with 01, 02 etc, and then wait on them all before exiting
 * The 2 digit 00 relates to THREAD_LIMIT which is 99
 *	there's a limit of THREAD_LIMIT active threads per thread manager
 * WARNING - however the total number of threads created is limited by the
 *	LOCK_CHECK code which allows only MAX_THREADS total ckdb thread to
 *	be created irrelevant of any being deleted
 *
 * The threads that can be managed have a command option to set them when
 *  starting ckdb and can also be changed via the cmd_threads socket command
 *
 * The main() 'asicseer-db' thread starts:
 *	iomsgs() for filelog '_fiomsgs' and console '_ciomsgs'
 *	listener() '_p00qproc'
 *		which manages it's thread count in pqproc()
 *
 * listener() starts:
 *	breakdown() for reload '_r00breaker' and cmd '_c00breaker'
 *		each of which manage their thead counts
 *	logger() '_logger'
 *	socksetup() '_socksetup'
 *	summariser() '_summarise'
 *	marker() '_marker'
 *  then calls setup_data() which calls reload()
 *  then calls pqproc()
 *	which manages the thread count
 *
 * socksetup() starts:
 *	replier() for pool '_preplier' cmd '_creplier' and btc '_breplier'
 *	listener_all() for cmd '_c00listen' and btc '_b00listen'
 *		each of which manage their thead counts
 *	process_socket() '_procsock'
 *	sockrun() for asicseer-pool '_psockrun' web '_wsockrun' and cmd '_csockrun'
 *
 * reload() starts:
 *	process_reload() '_p00rload'
 *		which manages it's thread count
 */

/* Startup
 * -------
 * During startup we load the DB and track where it is up to with
 *  dbstatus, we then reload "asicseer-pool's asicseer-db logfiles" (CCLs) based
 *  on dbstatus
 * Once the DB is loaded, we can immediately start receiving asicseer-pool
 *  messages since asicseer-pool already has logged all messages to the CLLs
 *  and asicseer-pool only verifies authorise responses
 *  Thus we can queue all messages:
 *	workinfo, shares, shareerror, ageworkinfo, poolstats, userstats
 *	and blocks
 *  with an ok.queued reply to asicseer-pool, to be processed after the reload
 *  completes and just process authorise messages immediately while the
 *  reload runs
 * However, we start the asicseer-pool message queue after loading
 *  the optioncontrol, idcontrol, users, workers and useratts DB tables,
 *  before loading the much larger DB tables, so that ckdb is effectively
 *  ready for messages almost immediately
 * The first asicseer-pool message allows us to know where asicseer-pool is up to
 *  in the CCLs - see reload_from() for how this is handled
 * The users table, required for the authorise messages, is always updated
 *  in the disk DB immediately
 */

/* Reload data needed
 * ------------------
 * After the DB load completes, load "asicseer-pool's asicseer-db logfile" (CCL), and
 * all later CCLs, that contains the oldest date of all of the following:
 *  RAM shares: oldest DB sharesummary firstshare where complete='n'
 *	All shares before this have been summarised to the DB with
 *	complete='a' (or 'y') and were deleted from RAM
 *	If there are none with complete='n' but are others in the DB,
 *	then the newest firstshare is used
 *  DB shares: no current processing done with the shares_hi tree inside
 *	CKDB. DB load gets the past 1 day to resolve duplicates
 *  RAM shareerrors: as above
 *  RAM sharesummary: created from shares, so as above
 *	Some shares after this may have been summarised to other
 *	sharesummary complete='n', but for any such sharesummary
 *	we reset it back to the first share found and it will
 *	correct itself during the CCL reload
 *	TODO: Verify that all DB sharesummaries with complete='n'
 *	have done this
 *  DB+RAM workinfo: start from newest DB createdate workinfo
 *  RAM auths: none (we store them in RAM only)
 *  DB+RAM poolstats: newest createdate poolstats
 *	TODO: subtract how much we need in RAM of the 'between'
 *	non db records - will depend on TODO: pool stats reporting
 *	requirements
 *  RAM userstats: none (we simply store the last one found)
 *  DB+RAM workers: created by auths so are simply ignore if they
 *	already exist
 *  DB+RAM blocks: resolved by workinfo - any unsaved blocks (if any)
 *	will be after the last DB workinfo
 *  RAM workerstatus: all except last_idle are set at the end of the
 *	CCL reload
 *	Code currently doesn't use last_idle
 *  RAM accountbalance: TODO: created as data is loaded
 *
 *  idcontrol: only userid reuse is critical and the user is added
 *	immeditately to the disk DB before replying to the add message
 *
 *  Tables that are/will be written straight to the DB, so are OK:
 *	users, useraccounts, paymentaddresses, payments,
 *	accountadjustment, optioncontrol, miningpayouts, payouts,
 *	eventlog, workmarkers, markersummary
 *
 * The code deals with the issue of 'now' when reloading by:
 *  createdate is considered 'now' for all data during a reload and is
 *  a mandatory field always checked for in asicseer-pool data
 * Implementing this is simple by assuming 'now' is always createdate
 *  i.e. during reload but also during normal running to avoid timing
 *  issues with asicseer-pool data
 * Other data supplies the current time to the functions that require
 *  'now' since that data is not part of a reload
 *
 * During reload, any data before the calculated reload stamp for
 *  that data is discarded
 * Any data that matches the reload stamp is processed with an
 *  ignore duplicates flag for all except as below.
 * Any data after the stamp, is processed normally for all except:
 *  1) shares/shareerrors: any record that matches an incomplete DB
 *	sharesummary that hasn't been reset, will reset the sharesummary
 *	so that the sharesummary will be recalculated
 *	The record is processed normally with or without the reset
 *	If the sharesummary is complete, the record is discarded
 *  2) ageworkinfo records are also handled by the shares date
 *	while processing, any records already aged are not updated
 *	and a warning is displayed if there were any matching shares
 *	Any ageworkinfos that match a workmarker are ignored with an error
 *	message
 */

// sockets
static pool_t ckp, ckpweb, ckpcmd;
static int accesspool, accessweb, accesscmd;
static const char *ispool = "pool";
static const char *isweb = "web";
static const char *iscmd = "cmd";
#define SOCKISPOOL(_name) (_name == ispool)
#define SOCKISWEB(_name) (_name == isweb)
#define SOCKISCMD(_name) (_name == iscmd)
#define POOLSOCK 0
#define WEBSOCK 1
#define CMDSOCK 2
#define MAXSOCK 3
#define SOCKNAME(_n) (((_n) == POOLSOCK) ? ispool : \
			(((_n) == WEBSOCK) ? isweb : \
			(((_n) == CMDSOCK) ? iscmd : "?")))
#define SOCKNUM(_name) (SOCKISPOOL(_name) ? POOLSOCK : \
			(SOCKISWEB(_name) ? WEBSOCK : \
			(SOCKISCMD(_name) ? CMDSOCK : MAXSOCK)))

static bool socksetup_using_data;
static bool summariser_using_data;
static bool marker_using_data;
static bool logger_using_data;
static bool plistener_using_data;
static bool clistener_using_data;
static bool blistener_using_data;
static bool breakdown_using_data;
static bool replier_using_data;

/* To notify thread changes
 * Set/checked under the function's main loop's first lock
 * This is always a 'delta' value meaning add or subtract that many */
int reload_queue_threads_delta = 0;
int proc_queue_threads_delta = 0;
/* Use -Q to set them higher
 * Setting them higher can degrade performance if the CPUs can't
 *  handle the extra locking or the threads are swapping */
static int reload_queue_threads = 1;
static int proc_queue_threads = 1;
// -B to override calculated value
static int reload_breakdown_threads = -1;
// This is normally the same as above, but key_update only requires 1
static int cmd_breakdown_threads = -1;
// cpu count to breakdown thread ratio
#define BREAKDOWN_RATIO 3
// To notify thread changes
int reload_breakdown_threads_delta = 0;
int cmd_breakdown_threads_delta = 0;

int cmd_listener_threads = 2;
int btc_listener_threads = 2;
int cmd_listener_threads_delta = 0;
int btc_listener_threads_delta = 0;

// Lock used to determine when the last breakdown thread exits
static cklock_t breakdown_lock;

static int replier_count = 0;
static cklock_t replier_lock;

char *EMPTY = "";
const char *nullstr = NULLSTR;

const char *true_str = "true";
const char *false_str = "false";

static char *db_name;
static char *db_user;
static char *db_pass;

// Currently hard coded at 4 characters
static char *status_chars = "|/-\\";

static char *restorefrom;
static char *restorename;

static bool ignore_seq = false;
static bool ignore_seqall = false;
bool genpayout_auto;
bool markersummary_auto;
bool exclusive_db = true;

enum free_modes free_mode = FREE_MODE_FAST;

int switch_state = SWITCH_STATE_ALL;

// disallow: '/' WORKSEP1 WORKSEP2 and FLDSEP
const char *userpatt = "^[^/"WORKSEP1PATT WORKSEP2STR FLDSEPSTR"]*$";
const char *mailpatt = "^[A-Za-z0-9_-][A-Za-z0-9_\\.-]*@[A-Za-z0-9][A-Za-z0-9\\.-]*[A-Za-z0-9]$";
const char *idpatt = "^[_A-Za-z][_A-Za-z0-9]*$";
const char *intpatt = "^[0-9][0-9]*$";
const char *hashpatt = "^[A-Fa-f0-9]*$";
/* BCH Legacy addresses start with '1' (one) or '3' (three),
 *  exclude: capital 'I' (eye), capital 'O' (oh),
 *  lowercase 'l' (elle) and '0' (zero)
 *  and with a simple test must be ADDR_MIN_LEN to ADDR_MAX_LEN (asicseer-db.h)
 * Additionally we support CashAddr by matching on that character set as well, with the optional prefix.
 * bitcoind is used to fully validate them when required */
const char *addrpatt =
	"^([13][A-HJ-NP-Za-km-z1-9]{23,33})"
	"|(((bchtest:)|(bitcoincash:))?[qQpPzZrRyY9xX8gGfF2tTvVdDwW0sS3jJnN54kKhHcCeE6mMuUaA7lL]{35,65})$";
// Strings in socket transfer: space to '~' excluding '='
const char *strpatt = "^[ -<>-~]*$";

// So the records below have the same 'name' as the klist
const char Transfer[] = "Transfer";

// older version missing field defaults
// see end of alloc_storage()
static TRANSFER auth_2 = { "preauth", FALSE_STR, auth_2.svalue, 0, NULL };
K_ITEM auth_preauth = { Transfer, NULL, NULL, (void *)(&auth_2) };
static TRANSFER poolstats_1 = { "elapsed", "0", poolstats_1.svalue, 0, NULL };
K_ITEM poolstats_elapsed = { Transfer, NULL, NULL, (void *)(&poolstats_1) };
static TRANSFER userstats_1 = { "elapsed", "0", userstats_1.svalue, 0, NULL };
K_ITEM userstats_elapsed = { Transfer, NULL, NULL, (void *)(&userstats_1) };
// see end of alloc_storage()
INTRANSIENT *userstats_workername = NULL;
static TRANSFER userstats_3 = { "idle", FALSE_STR, userstats_3.svalue, 0, NULL };
K_ITEM userstats_idle = { Transfer, NULL, NULL, (void *)(&userstats_3) };
static TRANSFER userstats_4 = { "eos", TRUE_STR, userstats_4.svalue, 0, NULL };
K_ITEM userstats_eos = { Transfer, NULL, NULL, (void *)(&userstats_4) };

static TRANSFER shares_1 = { "secondaryuserid", TRUE_STR, shares_1.svalue, 0, NULL };
K_ITEM shares_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shares_1) };
static TRANSFER shareerrors_1 = { "secondaryuserid", TRUE_STR, shareerrors_1.svalue, 0, NULL };
K_ITEM shareerrors_secondaryuserid = { Transfer, NULL, NULL, (void *)(&shareerrors_1) };
// Time limit that this problem occurred
// 24-Aug-2014 05:20+00 (1st one shortly after this)
tv_t missing_secuser_min = { 1408857600L, 0L };
// 24-Aug-2014 06:00+00
tv_t missing_secuser_max = { 1408860000L, 0L };

LOADSTATUS dbstatus;

POOLSTATUS pool = { 0, START_POOL_HEIGHT, 0, 0, 0, 0, 0, 0 };

// Ensure long long and int64_t are both 8 bytes (and thus also the same)
#define ASSERT1(condition) __maybe_unused static char sizeof_longlong_must_be_8[(condition)?1:-1]
#define ASSERT2(condition) __maybe_unused static char sizeof_int64_t_must_be_8[(condition)?1:-1]
ASSERT1(sizeof(long long) == 8);
ASSERT2(sizeof(int64_t) == 8);

const tv_t default_expiry = { DEFAULT_EXPIRY, 0L };
const tv_t date_eot = { DATE_S_EOT, DATE_uS_EOT };
const tv_t date_begin = { DATE_BEGIN, 0L };

// argv -K - don't run in ckdb mode, just update keysummary
bool key_update;
/* Requires all workmarkers and workinfo present in the database
 *  they are all loaded during startup, but you can limit the
 *  workinfo loaded with -w - if any required are missing,
 *  it will stop with an error saying what was missing
 * keysummary records are not loaded, but SQL stores of duplicate
 *  keysummary records are reported and ignored
 *
 * Valid options are:
 *	mNNN-MMM workmarker markerid range to process
 *		 this determines the CCL file range loaded
 *		 and the workinfoid range processed
 */
static char *key_range;
int64_t key_wi_stt;
int64_t key_wi_fin;

// argv -y - don't run in ckdb mode, just confirm sharesummaries
bool confirm_sharesummary;

/* Optional workinfoid range -Y to supply when confirming sharesummaries
 * N.B. if you specify -Y it will enable -y, so -y isn't also required
 *
 * TODO: update to include markersummaries
 *	-Y/-y isn't currently usable since it won't work without the update
 *
 * Default (NULL) is to confirm all aged sharesummaries
 * Default should normally be used every time
 *  The below options are mainly for debugging or
 *   a quicker confirm if required due to not running confirms regularly
 *  TODO: ... once the code includes flagging confirmed sharesummaries
 * Valid options are:
 *	bNNN - confirm all workinfoid's from the previous db block before
 *		NNN (or 0) up to the workinfoid of the 1st db block height
 *		equal or after NNN
 *	wNNN - confirm all workinfoid's from NNN up to the last aged
 *		sharesummary
 *	rNNN-MMM - confirm all workinfoid's from NNN to MMM inclusive
 *	cNNN-MMM - check the CCL record timestamps then exit
 *	i - just show the DB load information then exit
 */
static char *confirm_range;
static int confirm_block;
static int64_t confirm_range_start;
static int64_t confirm_range_finish;
static bool confirm_check_createdate;
static int64_t ccl_mismatch_abs;
static int64_t ccl_mismatch;
static double ccl_mismatch_min;
static double ccl_mismatch_max;
static int64_t ccl_unordered_abs;
static int64_t ccl_unordered;
static double ccl_unordered_most;

// The workinfoid range we are processing
int64_t confirm_first_workinfoid;
int64_t confirm_last_workinfoid;
/* Stop the reload 11min after the 'last' workinfoid+1 appears
 * asicseer-pool uses 10min - but add 1min to be sure */
#define WORKINFO_AGE 660

static tv_t reload_timestamp;
// CDTRF in the last reloaded record - locked under breakqueue_free
static char last_reload_cd[CDATE_BUFSIZ];
// Shared by threads - accessed under breakqueue_free lock
static uint64_t reload_processed = 0;
// Shared by threads - accessed under workqueue_free lock
static uint64_t workqueue_proc0 = 0, workqueue_proc1 = 0;

/* Allow overriding the workinfoid range used in the db load of
 * workinfo and sharesummary */
int64_t dbload_workinfoid_start = -1;
int64_t dbload_workinfoid_finish = MAXID;
// Only restrict sharesummary, not workinfo
bool dbload_only_sharesummary = false;

/* If the above restriction - on sharesummaries - is after the last marks
 *  then this means the sharesummaries can't be summarised into
 *  markersummaries and pplns payouts may not be correct */
bool sharesummary_marks_limit = false;

// DB optioncontrol,idcontrol,users,workers,useratts load is complete
bool db_users_complete = false;
// DB load is complete
bool db_load_complete = false;
// Before the reload starts (and during the reload)
bool prereload = true;
// Different input data handling
bool reloading = false;
// Start marks processing during a larger reload
bool reloaded_N_files = false;
// Data load is complete
bool startup_complete = false;
// Set to true when pool0 completes, pool0 = socket data during reload
bool reload_queue_complete = false;
// Tell everyone to die
bool everyone_die = false;
// Set to true every time a store is created
static bool seqdata_reload_lost = false;
// Tell the ioqueue thread to exit
static bool ioqueue_die = false;
/* Tell the console ioqueue to clear it's list as fast as possible
 * In the case where a console log unexpectedly ends up having a very large
 *  number of messages, since it limits the number of messages per second
 *  this could take a long time to clear
 *  To resolve this, you can disconnect from the console if your IO speed to
 *   the console is slow, then send it all by sending flush.2 */
static bool ioqueue_flush = false;

static int reload_access = ACCESS_POOL;

/* These are included in cmd_homepage
 *  to help identify when asicseer-pool locks up (or dies) */
tv_t last_heartbeat;
tv_t last_workinfo;
tv_t last_share;
tv_t last_share_acc;
tv_t last_share_inv;
tv_t last_auth;
cklock_t last_lock;

// Running stats
// replier()
static double reply_full_us;
static uint64_t reply_sent, reply_cant, reply_discarded, reply_fails;
// sockrun()
static tv_t sock_stt[MAXSOCK];
static double sock_us[MAXSOCK], sock_recv_us[MAXSOCK];
static double sock_lock_wq_us[MAXSOCK], sock_lock_br_us[MAXSOCK];
static uint64_t sock_proc_early[MAXSOCK], sock_processed[MAXSOCK];
static uint64_t sock_acc[MAXSOCK], sock_recv[MAXSOCK];
// breaker() summarised
static tv_t break_reload_stt, break_cmd_stt, break_reload_fin;
static uint64_t break_reload_processed, break_cmd_processed;
// listener_all()
static cklock_t listener_all_lock;
static double clis_us;
static uint64_t clis_processed;
static double blis_us;
static uint64_t blis_processed;

static cklock_t fpm_lock;
static char *first_pool_message;
static sem_t socksetup_sem;

// command called for any ckdb alerts
char *ckdb_alert_cmd = NULL;

tv_t ckdb_start;

char *btc_server = "http://127.0.0.1:8330";
char *btc_auth;
int btc_timeout = 5;
cklock_t btc_lock;

char *by_default = "code";
char *inet_default = "127.0.0.1";
char *id_default = "42";

// Emulate a list for lock checking
K_LIST *pgdb_free;
// Count of db connections
int pgdb_count;
__thread char *connect_file = NULLSTR;
__thread char *connect_func = NULLSTR;
__thread int connect_line = 0;
__thread bool connect_dis = true;
// Pause all DB IO (permanently)
cklock_t pgdb_pause_lock;
__thread int pause_read_count = 0;
__thread char *pause_read_file = NULLSTR;
__thread char *pause_read_func = NULLSTR;
__thread int pause_read_line = 0;
__thread bool pause_read_unlock = false;
bool pgdb_paused = false;
bool pgdb_pause_disabled = false;

// NULL or poolinstance must match
const char *sys_poolinstance = NULL;
// lock for accessing all mismatch variables
cklock_t poolinstance_lock;
time_t last_mismatch_message;

int64_t mismatch_workinfo;
int64_t mismatch_ageworkinfo;
int64_t mismatch_auth;
int64_t mismatch_addrauth;
int64_t mismatch_poolstats;
int64_t mismatch_userstats;
int64_t mismatch_workerstats;
int64_t mismatch_workmarkers;
int64_t mismatch_marks;
int64_t mismatch_total;

int64_t mismatch_all_workinfo;
int64_t mismatch_all_ageworkinfo;
int64_t mismatch_all_auth;
int64_t mismatch_all_addrauth;
int64_t mismatch_all_poolstats;
int64_t mismatch_all_userstats;
int64_t mismatch_all_workerstats;
int64_t mismatch_all_workmarkers;
int64_t mismatch_all_marks;
int64_t mismatch_all_total;

// IOQUEUE
K_LIST *ioqueue_free;
K_STORE *ioqueue_store;
K_STORE *console_ioqueue_store;
// Trigger ioqueue_store processing
static mutex_t f_ioqueue_waitlock;
static pthread_cond_t f_ioqueue_waitcond;

// LOGQUEUE
K_LIST *logqueue_free;
K_STORE *logqueue_store;

static bool db_logger = true;

// NAMERAM
K_LIST *nameram_free;
K_STORE *nameram_store;

// INTRANSIENT
K_TREE *intransient_root;
K_LIST *intransient_free;
K_STORE *intransient_store;

/* *** WARNING *** all incoming field names processed by breakdown(),
 *  that are used as intransient anywhere, MUST be here
 * TODO: this should be a hash table */
char *intransient_fields[] = {
	"workername",
	"blockhash",
	BYTRF,
	CODETRF,
	INETTRF,
	"username",
	"admin",
	"agent",
	"useragent",
	"address",
	"prevhash",
	"bits",
	"version",
	"poolinstance",
	"payaddress",
	"subname",
	"originaltxn",
	"committxn",
	"commitblockhash",
	NULL
};

INTRANSIENT *in_empty;

// MSGLINE
K_LIST *msgline_free;
K_STORE *msgline_store;

// This can be set with the -q option
static int reload_queue_limit = RELOAD_QUEUE_LIMIT;

// BREAKQUEUE
K_LIST *breakqueue_free;
K_STORE *reload_breakqueue_store;
K_STORE *reload_done_breakqueue_store;
K_STORE *cmd_breakqueue_store;
K_STORE *cmd_done_breakqueue_store;

// Locked access with breakqueue_free
int reload_processing;
int cmd_processing;
int sockd_count;
int max_sockd_count;
ts_t breaker_sleep_stt;
int breaker_sleep_ms;

// Trigger breaker() processing
mutex_t bq_reload_waitlock;
mutex_t bq_cmd_waitlock;
pthread_cond_t bq_reload_waitcond;
pthread_cond_t bq_cmd_waitcond;

uint64_t bq_reload_signals, bq_cmd_signals;
uint64_t bq_reload_wakes, bq_cmd_wakes;
uint64_t bq_reload_timeouts, bq_cmd_timeouts;

// Trigger reload/socket *_done_* processing
mutex_t process_reload_waitlock;
mutex_t process_socket_waitlock;
pthread_cond_t process_reload_waitcond;
pthread_cond_t process_socket_waitcond;

uint64_t process_reload_signals, process_socket_signals;
uint64_t process_reload_wakes, process_socket_wakes;
uint64_t process_reload_timeouts, process_socket_timeouts;

// WORKQUEUE
K_LIST *workqueue_free;
// pool0 is all pool data during the reload
K_STORE *pool0_workqueue_store;
K_STORE *pool_workqueue_store;
K_STORE *cmd_workqueue_store;
K_STORE *btc_workqueue_store;
// this counter ensures we don't switch early from pool0 to pool
int64_t earlysock_left;
int64_t pool0_tot;
int64_t pool0_discarded;

// Trigger workqueue threads
mutex_t wq_pool_waitlock;
mutex_t wq_cmd_waitlock;
mutex_t wq_btc_waitlock;
pthread_cond_t wq_pool_waitcond;
pthread_cond_t wq_cmd_waitcond;
pthread_cond_t wq_btc_waitcond;

uint64_t wq_pool_signals, wq_cmd_signals, wq_btc_signals;
uint64_t wq_pool_wakes, wq_cmd_wakes, wq_btc_wakes;
uint64_t wq_pool_timeouts, wq_cmd_timeouts, wq_btc_timeouts;

// REPLIES
K_LIST *replies_free;
K_STORE *replies_store;
K_TREE *replies_pool_root;
K_TREE *replies_cmd_root;
K_TREE *replies_btc_root;

int epollfd_pool;
int epollfd_cmd;
int epollfd_btc;

int rep_tot_sockd;
int rep_failed_sockd;
int rep_max_sockd;
// maximum counts and fd values
int rep_max_pool_sockd;
int rep_max_cmd_sockd;
int rep_max_btc_sockd;
int rep_max_pool_sockd_fd;
int rep_max_cmd_sockd_fd;
int rep_max_btc_sockd_fd;

// HEARTBEATQUEUE
K_LIST *heartbeatqueue_free;
K_STORE *heartbeatqueue_store;

// TRANSFER
K_LIST *transfer_free;
int cull_transfer = CULL_TRANSFER;

// SEQSET
K_LIST *seqset_free;
// each new seqset is added to the head, so head is the current one
static K_STORE *seqset_store;
// Initialised when seqset_free is allocated
static char *seqnam[SEQ_MAX];
// Lock access to the static found data in update_seq()
static cklock_t seq_found_lock;

// Full lock for access to sequence processing data
#define SEQLOCK() K_WLOCK(seqset_free);
#define SEQUNLOCK() K_WUNLOCK(seqset_free);

/* Set to 1 to enable compiling in the SEQALL_LOG logging
 * Any compiler optimisation should remove the code if it's 0 */
#define SEQALL_LOG 0

// SEQTRANS
K_LIST *seqtrans_free;

// USERS
K_TREE *users_root;
K_TREE *userid_root;
K_LIST *users_free;
K_STORE *users_store;
// Emulate a list for lock checking
K_LIST *users_db_free;

// USERATTS
K_TREE *useratts_root;
K_LIST *useratts_free;
K_STORE *useratts_store;

// WORKERS
K_TREE *workers_root;
K_LIST *workers_free;
K_STORE *workers_store;
// Emulate a list for lock checking
K_LIST *workers_db_free;

// PAYMENTADDRESSES
K_TREE *paymentaddresses_root;
K_TREE *paymentaddresses_create_root;
K_LIST *paymentaddresses_free;
K_STORE *paymentaddresses_store;

// PAYMENTS
K_TREE *payments_root;
K_LIST *payments_free;
K_STORE *payments_store;

// ACCOUNTBALANCE
K_TREE *accountbalance_root;
K_LIST *accountbalance_free;
K_STORE *accountbalance_store;

// ACCOUNTADJUSTMENT
K_TREE *accountadjustment_root;
K_LIST *accountadjustment_free;
K_STORE *accountadjustment_store;

// IDCONTROL
K_TREE *idcontrol_root;
K_LIST *idcontrol_free;
K_STORE *idcontrol_store;

// OPTIONCONTROL
K_TREE *optioncontrol_root;
K_LIST *optioncontrol_free;
K_STORE *optioncontrol_store;

// ESM (Early Share/Shareerror Messages)
K_TREE *esm_root;
K_LIST *esm_free;
K_STORE *esm_store;

// WORKINFO workinfo.id.json={...}
K_TREE *workinfo_root;
// created during data load then destroyed since not needed later
K_TREE *workinfo_height_root;
K_LIST *workinfo_free;
K_STORE *workinfo_store;
// one in the current block
K_ITEM *workinfo_current;
// first workinfo of current block
tv_t last_bc;
// current network diff
double current_ndiff;
bool txn_tree_store = true;
// avoid trying to run 2 ages at the same time
bool workinfo_age_lock = false;

// SHARES shares.id.json={...}
K_TREE *shares_root;
K_LIST *shares_free;
K_STORE *shares_store;
K_TREE *shares_early_root;
K_STORE *shares_early_store;
K_TREE *shares_hi_root;
K_TREE *shares_db_root;
K_STORE *shares_hi_store;

double diff_percent = DIFF_VAL(DIFF_PERCENT_DEFAULT);
double share_min_sdiff = 0;
int64_t shares_begin = -1;

// SHAREERRORS shareerrors.id.json={...}
K_TREE *shareerrors_root;
K_LIST *shareerrors_free;
K_STORE *shareerrors_store;
K_TREE *shareerrors_early_root;
K_STORE *shareerrors_early_store;

// SHARESUMMARY
K_TREE *sharesummary_root;
K_TREE *sharesummary_workinfoid_root;
K_LIST *sharesummary_free;
K_STORE *sharesummary_store;
// Pool total sharesummary stats
K_TREE *sharesummary_pool_root;
K_STORE *sharesummary_pool_store;

// BLOCKS block.id.json={...}
const char *blocks_new = "New";
const char *blocks_confirm = "1-Confirm";
const char *blocks_42 = "Matured";
const char *blocks_orphan = "Orphan";
const char *blocks_reject = "Unworthy";
const char *blocks_unknown = "?Unknown?";

K_TREE *blocks_root;
K_LIST *blocks_free;
K_STORE *blocks_store;
// Access both under blocks_free lock
tv_t blocks_stats_time;
bool blocks_stats_rebuild = true;

// MININGPAYOUTS
K_TREE *miningpayouts_root;
K_LIST *miningpayouts_free;
K_STORE *miningpayouts_store;

// PAYOUTS
K_TREE *payouts_root;
K_TREE *payouts_id_root;
K_TREE *payouts_wid_root;
K_LIST *payouts_free;
K_STORE *payouts_store;
// Emulate a list for lock checking
K_LIST *process_pplns_free;

// IPS
K_TREE *ips_root;
K_LIST *ips_free;
K_STORE *ips_store;

// EVENTS
K_TREE *events_user_root;
K_TREE *events_ip_root;
K_TREE *events_ipc_root;
K_TREE *events_hash_root;
K_LIST *events_free;
K_STORE *events_store;
// Emulate a list for lock checking
K_LIST *event_limits_free;

// OVENTS (OK EVENTS)
K_TREE *ovents_root;
K_LIST *ovents_free;
K_STORE *ovents_store;

/* N.B. these limits are not production quality
 *  They'll block anyone who makes a mistake 2 or 3 times :)
 * Use optioncontrol OC_LIMITS to set/store them in the database */
EVENT_LIMITS e_limits[] = {
 { EVENTID_PASSFAIL,	"PASSFAIL",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // It's only possible to create an address account once, so user_lo/hi can never trigger
 { EVENTID_CREADDR,	"CREADDR",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // It's only possible to create an account once, so user_lo/hi can never trigger
 { EVENTID_CREACC,	"CREACC",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // page_api.php with an invalid username
 { EVENTID_UNKATTS,	"UNKATTS",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // 2fa missing/invalid format
 { EVENTID_INV2FA,	"INV2FA",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Wrong 2fa value
 { EVENTID_WRONG2FA,	"WRONG2FA",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Invalid address according to btcd
 { EVENTID_INVBTC,	"INVBTC",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Incorrect format/length address
 { EVENTID_INCBTC,	"INCBTC",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Address belongs to some other account
 { EVENTID_BTCUSED,	"BTCUSED",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // It's only possible to create an account once, so user_lo/hi can never trigger
 { EVENTID_AUTOACC,	"AUTOACC",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Invalid user on auth, asicseer-pool will throttle these
 { EVENTID_INVAUTH,	"INVAUTH",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Invalid user on chkpass
 { EVENTID_INVUSER,	"INVUSER",	true,	60,	1,	2*60,	2,	60,	1,	2*60,	2,	24*60*60 },
 // Terminated by NULL name
 { -1, NULL, false, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
// All access to above and below limits requires the event_limits_free lock
int event_limits_hash_lifetime = 24*60*60;

/* N.B. these limits are not production quality
 *  They'll block anyone who does anything more than once a minute
 * Use optioncontrol OC_OLIMITS to set/store them in the database */
EVENT_LIMITS o_limits[] = {
// Homepage valid access - most web access includes Homepage - so this isn't actually counted
{ OVENTID_HOMEPAGE,	"HOMEPAGE",	false,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// Blocks valid access
{ OVENTID_BLOCKS,	"BLOCKS",	true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// API valid access
{ OVENTID_API,		"API",		true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// Add/Update single payment address
{ OVENTID_ONEADDR,	"ONEADDR",	true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// Add/Update multi payment address
{ OVENTID_MULTIADDR,	"MULTIADDR",	true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// Workers valid access
{ OVENTID_WORKERS,	"WORKERS",	true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
// Other valid access
{ OVENTID_OTHER,	"OTHER",	true,	60,	1,	10*60,	10,	60,	1,	10*60,	10,	24*60*60 },
 // Terminated by NULL name
 { -1, NULL, false, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

// mulitply IP limit by this to get IPC limit
double ovent_limits_ipc_factor = 2.0;
// maximum lifetime of all o_limits - set by code
int o_limits_max_lifetime = -1;

// AUTHS authorise.id.json={...}
K_TREE *auths_root;
K_LIST *auths_free;
K_STORE *auths_store;

// POOLSTATS poolstats.id.json={...}
K_TREE *poolstats_root;
K_LIST *poolstats_free;
K_STORE *poolstats_store;

// USERSTATS userstats.id.json={...}
K_TREE *userstats_root;
K_LIST *userstats_free;
K_STORE *userstats_store;
// Awaiting EOS
K_STORE *userstats_eos_store;

// WORKERSTATUS from various incoming data
K_TREE *workerstatus_root;
K_LIST *workerstatus_free;
K_STORE *workerstatus_store;

// MARKERSUMMARY
K_TREE *markersummary_root;
K_TREE *markersummary_userid_root;
K_LIST *markersummary_free;
K_STORE *markersummary_store;
// Pool total markersummary stats
K_TREE *markersummary_pool_root;
K_STORE *markersummary_pool_store;

// The markerid load start for markersummary
char mark_start_type = '\0';
int64_t mark_start = -1;

// KEYSHARESUMMARY
K_TREE *keysharesummary_root;
K_LIST *keysharesummary_free;
K_STORE *keysharesummary_store;

// KEYSUMMARY
K_TREE *keysummary_root;
K_LIST *keysummary_free;
K_STORE *keysummary_store;

// WORKMARKERS
K_TREE *workmarkers_root;
K_TREE *workmarkers_workinfoid_root;
K_LIST *workmarkers_free;
K_STORE *workmarkers_store;
// static for key_update
static K_STORE *workmarkers_key_store;

// MARKS
K_TREE *marks_root;
K_LIST *marks_free;
K_STORE *marks_store;

const char *marktype_block = "Block End";
const char *marktype_pplns = "Payout Begin";
const char *marktype_shift_begin = "Shift Begin";
const char *marktype_shift_end = "Shift End";
const char *marktype_other_begin = "Other Begin";
const char *marktype_other_finish = "Other Finish";

const char *marktype_block_fmt = "Block %"PRId32" fin";
const char *marktype_pplns_fmt = "Payout %"PRId32" stt";
const char *marktype_shift_begin_fmt = "Shift stt: %s";
const char *marktype_shift_end_fmt = "Shift fin: %s";
const char *marktype_other_begin_fmt = "stt: %s";
const char *marktype_other_finish_fmt = "fin: %s";

// For getting back the shift code/name
const char *marktype_shift_begin_skip = "Shift stt: ";
const char *marktype_shift_end_skip = "Shift fin: ";

// USERINFO from various incoming data
K_TREE *userinfo_root;
K_LIST *userinfo_free;
K_STORE *userinfo_store;

static char *listener_base = "listener";
static char *process_name = "main";
static char logname_db[512];
static char logname_io[512];
static char *dbcode;
static bool no_data_log = false;

/* added before the hour filename - can include:
 *'%yyy' replaced with 4 digit year
 * '%m' replaced with 2 digit month
 * '%d' replaced with 2 digit day
 * and must exactly match the above strings
 * e.g. '%yyy/%m/' if the CCLs are in yearly+monthly sub-directories of
 *	'restorefrom/'  */
static char *logpath;

static IOQUEUE byebye = {
	"Exiting", { 0L, 0L }, 0, false, true, false, true, true
};

static void ioprocess(IOQUEUE *io)
{
	char stamp[128], tzinfo[16], tzch;
	long minoff, hroff;
	struct tm tm;
	int ms;

	if (io->when.tv_sec == 0)
		stamp[0] = '\0';
	else {
		ms = (int)(io->when.tv_usec / 1000);
		localtime_r(&(io->when.tv_sec), &tm);
		minoff = tm.tm_gmtoff / 60;
		if (minoff < 0) {
			tzch = '-';
			minoff *= -1;
		} else
			tzch = '+';
		hroff = minoff / 60;
		if (minoff % 60) {
			snprintf(tzinfo, sizeof(tzinfo),
				 "%c%02ld:%02ld",
				 tzch, hroff, minoff % 60);
		} else {
			snprintf(tzinfo, sizeof(tzinfo),
				 "%c%02ld",
				 tzch, hroff);
		}
		snprintf(stamp, sizeof(stamp),
				"[%d-%02d-%02d %02d:%02d:%02d.%03d%s] ",
				tm.tm_year + 1900,
				tm.tm_mon + 1,
				tm.tm_mday,
				tm.tm_hour,
				tm.tm_min,
				tm.tm_sec, ms,
				tzinfo);
	}

	if (io->logfd && global_ckp) {
		int logfd = global_ckp->logfd;
		if (logfd) {
			FILE *LOGFP = global_ckp->logfp;

			flock(logfd, LOCK_EX);
			if (io->errn) {
				fprintf(LOGFP, "%s%s with errno %d: %s\n",
						stamp, io->msg,
						io->errn, strerror(io->errn));
			} else
				fprintf(LOGFP, "%s%s\n", stamp, io->msg);
			flock(logfd, LOCK_UN);
		}
	}

	if (io->logout) {
		if (io->errn) {
			fprintf(stdout, "%s%s with errno %d: %s%s",
					stamp, io->msg,
					io->errn, strerror(io->errn),
					io->eol ? "\n" : "\r");
		} else {
			fprintf(stdout, "%s%s%s",
					stamp, io->msg,
					io->eol ? "\n" : "\r");
		}
		if (io->flush)
			fflush(stdout);
	}

	if (io->logerr) {
		if (io->errn) {
			fprintf(stderr, "%s%s with errno %d: %s%s",
					stamp, io->msg,
					io->errn, strerror(io->errn),
					io->eol ? "\n" : "\r");
		} else {
			fprintf(stderr, "%s%s%s",
					stamp, io->msg,
					io->eol ? "\n" : "\r");
		}
		if (io->flush)
			fflush(stderr);
	}
}

static void *iomsgs(void *consol)
{
	ts_t when, when_add;
	K_ITEM *io_item;
	IOQUEUE *io;
	char buf[64];

	snprintf(buf, sizeof(buf),
		 "db%s_%s%s",
		 dbcode, consol ? "c" : "f", __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	when_add.tv_sec = 0;
	when_add.tv_nsec = 100000000; // 100ms

	while (0x80085) {
		// WARNING taking locks can produce messages ...
		K_WLOCK(ioqueue_free);
		if (consol)
			io_item = k_unlink_head(console_ioqueue_store);
		else
			io_item = k_unlink_head(ioqueue_store);
		K_WUNLOCK(ioqueue_free);

		if (io_item) {
			DATA_IOQUEUE(io, io_item);
			ioprocess(io);
			free(io->msg);
			// WARNING taking locks can produce messages ...
			K_WLOCK(ioqueue_free);
			k_add_head(ioqueue_free, io_item);
			K_WUNLOCK(ioqueue_free);
		} else {
			if (ioqueue_die)
				break;
			if (consol) {
				// The queue is clear
				ioqueue_flush = false;
			}
		}

		if (consol) {
			if (!ioqueue_flush && !everyone_die) {
				// max 50 per second
				cksleep_ms(20);
			}
		} else {
			if (!io_item) {
				setnowts(&when);
				timeraddspec(&when, &when_add);

				mutex_lock(&f_ioqueue_waitlock);
				cond_timedwait(&f_ioqueue_waitcond,
						&f_ioqueue_waitlock,
						&when);
				mutex_unlock(&f_ioqueue_waitlock);
			}
		}
	}

	return NULL;
}

void _io_msg(bool stamp, char *msg, bool alloc, int errn, bool logfd,
	     bool logout, bool logerr, bool eol, bool flush, WHERE_FFL_ARGS)
{
	K_ITEM *fio_item = NULL, *cio_item = NULL;
	bool msgused = false;
	IOQUEUE *io;
	tv_t now;

	if (!logfd && !logout && !logerr) {
		quitfrom(1, file, func, line,
			 "%s() called without output", __func__);
	}

	if (stamp)
		setnow(&now);
	else
		now.tv_sec = 0;

	// WARNING taking locks can produce messages ...
	K_WLOCK(ioqueue_free);
	if (logfd)
		fio_item = k_unlink_head(ioqueue_free);
	if (logout || logerr)
		cio_item = k_unlink_head(ioqueue_free);
	K_WUNLOCK(ioqueue_free);

	if (logfd) {
		DATA_IOQUEUE(io, fio_item);
		if (!alloc) {
			io->msg = msg;
			msgused = true;
		} else {
			io->msg = strdup(msg);
			if (!(io->msg))
				quithere(1, "strdup (%d) OOM", (int)strlen(msg));
		}
		copy_tv(&(io->when), &now);
		io->errn = errn;
		io->logfd = logfd;
		io->logout = false;
		io->logerr = false;
		io->eol = eol;
		io->flush = flush;
	}

	if (logout || logerr) {
		DATA_IOQUEUE(io, cio_item);
		if (!alloc && !msgused)
			io->msg = msg;
		else {
			io->msg = strdup(msg);
			if (!(io->msg))
				quithere(1, "strdup (%d) OOM", (int)strlen(msg));
		}
		copy_tv(&(io->when), &now);
		io->errn = errn;
		io->logfd = false;
		io->logout = logout;
		io->logerr = logerr;
		io->eol = eol;
		io->flush = flush;
	}

	// WARNING taking locks can produce messages ...
	K_WLOCK(ioqueue_free);
	if (fio_item)
		k_add_tail(ioqueue_store, fio_item);
	if (cio_item)
		k_add_tail(console_ioqueue_store, cio_item);
	K_WUNLOCK(ioqueue_free);

	if (fio_item) {
		mutex_lock(&f_ioqueue_waitlock);
		pthread_cond_signal(&f_ioqueue_waitcond);
		mutex_unlock(&f_ioqueue_waitlock);
	}
}

static void replace_ymd(char *srch, char *match, int val)
{
	char buf[32], *ptr, *found;
	size_t len;

	len = strlen(match);
	snprintf(buf, sizeof(buf), "%0*d", (int)len, val);
	if (strlen(buf) != len) {
		quithere(1, "ERR: val=%d conversion '%%0*d' failed to be "
				"length %d '%s'=%d", val, (int)len,
				buf, (int)strlen(buf));
	}
	found = srch;
	while (found && *found) {
		ptr = strstr(found, match);
		if (ptr) {
			memcpy(ptr, buf, len);
			found = ptr + len;
		} else
			found = NULL;
	}
}

static char *hour_filename(const char *path, const char *name, time_t when)
{
	char *filename;
	struct tm tm;
	char log_path[1024];

	gmtime_r(&when, &tm);
	if (!logpath)
		log_path[0] = '\0';
	else {
		STRNCPY(log_path, logpath);
		replace_ymd(log_path, "%yyy", tm.tm_year + 1900);
		replace_ymd(log_path, "%m", tm.tm_mon + 1);
		replace_ymd(log_path, "%d", tm.tm_mday);
	}
	ASPRINTF(&filename, "%s%s%s%04d%02d%02d%02d.log",
				path, log_path, name,
				tm.tm_year + 1900,
				tm.tm_mon + 1,
				tm.tm_mday,
				tm.tm_hour);
	return filename;
}

// low spec version of rotating_log() - no locking
static bool rotating_log_nolock(char *msg, char *prefix)
{
	char *filename;
	FILE *fp;
	bool ok = false;

	filename = rotating_filename(prefix, time(NULL));
	fp = fopen(filename, "a+e");
	if (unlikely(!fp)) {
		LOGERR("Failed to fopen %s in rotating_log!", filename);
		goto stageleft;
	}
	fprintf(fp, "%s\n", msg);
	fclose(fp);
	ok = true;

stageleft:
	free(filename);

	return ok;
}

static void log_queue_message(char *msg, bool db)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;

	if (no_data_log)
		return;

	K_WLOCK(logqueue_free);
	lq_item = k_unlink_head(logqueue_free);
	DATA_LOGQUEUE(lq, lq_item);
	lq->msg = strdup(msg);
	if (!(lq->msg))
		quithere(1, "malloc (%d) OOM", (int)strlen(msg));
	lq->db = db;
	k_add_tail(logqueue_store, lq_item);
	K_WUNLOCK(logqueue_free);
}

void logmsg(int loglevel, const char *fmt, ...)
{
	char *buf = NULL;
	va_list ap;
	int errn;

	errn = errno;
	errno = 0;

	if (!fmt) {
		err_msg(true, "logmsg() called without fmt", errn);
		return;
	}

	if (loglevel > global_ckp->loglevel)
		return;

	va_start(ap, fmt);
	VASPRINTF(&buf, fmt, ap);
	va_end(ap);

	// iomsgs() will free buf
	if (loglevel <= LOG_ERR)
		io_msg(true, buf, errn, true, loglevel <= LOG_WARNING);
	else
		io_msg(true, buf, 0, true, loglevel <= LOG_WARNING);
}

void setnowts(ts_t *now)
{
	now->tv_sec = 0;
	now->tv_nsec = 0;
	clock_gettime(CLOCK_REALTIME, now);
}

void setnow(tv_t *now)
{
	ts_t spec;
	setnowts(&spec);
	now->tv_sec = spec.tv_sec;
	now->tv_usec = spec.tv_nsec / 1000;
}

void status_report(tv_t *now, bool showseq)
{
	char ooo_buf[256];
	int relq_count, _reload_processing, relqd_count;
	int cmdq_count, _cmd_processing, cmdqd_count, _max_sockd_count;
	int pool0_count, poolq_count, rep_max_fd, i;
	int64_t _earlysock_left, _pool0_discarded, _pool0_tot;
	uint64_t count1, count2, count3, count4;
	double tot1, tot2;
	tv_t now0;

	if (now == NULL) {
		setnow(&now0);
		now = &now0;
	}

	LOGWARNING("OoO %s", ooo_status(ooo_buf, sizeof(ooo_buf)));
	if (showseq)
		sequence_report(true);

	K_RLOCK(breakqueue_free);
	relq_count = reload_breakqueue_store->count;
	_reload_processing = reload_processing;
	relqd_count = reload_done_breakqueue_store->count;
	cmdq_count = cmd_breakqueue_store->count;
	_cmd_processing = cmd_processing;
	cmdqd_count = cmd_done_breakqueue_store->count;
	_max_sockd_count = max_sockd_count;
	K_RUNLOCK(breakqueue_free);

	K_RLOCK(workqueue_free);
	_earlysock_left = earlysock_left;
	pool0_count = pool0_workqueue_store->count;
	_pool0_discarded = pool0_discarded;
	_pool0_tot = pool0_tot;
	poolq_count = pool_workqueue_store->count;
	K_RUNLOCK(workqueue_free);

	LOGWARNING(" reload=rq%d/rp%d/rd%d cmd=cq%d/cp%d/cd%d es=%"PRId64
		   " pool0=c%d/d%"PRId64"/t%"PRId64" poolq=c%d max_sockd=%d",
		   relq_count, _reload_processing, relqd_count,
		   cmdq_count, _cmd_processing, cmdqd_count,
		   _earlysock_left,
		   pool0_count, _pool0_discarded, _pool0_tot,
		   poolq_count, _max_sockd_count);

	for (i = 0; i < MAXSOCK; i++) {
		count1 = sock_acc[i] ? : 1;
		count2 = sock_recv[i] ? : 1;
		count3 = sock_proc_early[i] ? : 1;
		count4 = sock_processed[i] ? : 1;
		LOGWARNING(" %s sock: t%fs sock t%fs/t%"PRIu64"/av%fs"
			   " recv t%fs/t%"PRIu64"/av%fs"
			   " lckw t%fs/t%"PRIu64"/av%fs"
			   " lckb t%fs/t%"PRIu64"/av%fs",
			   SOCKNAME(i), tvdiff(now, &(sock_stt[i])),
			   sock_us[i]/1000000, sock_acc[i],
			   (sock_us[i]/count1)/1000000,
			   sock_recv_us[i]/1000000, sock_recv[i],
			   (sock_recv_us[i]/count2)/1000000,
			   sock_lock_wq_us[i]/1000000, sock_proc_early[i],
			   (sock_lock_wq_us[i]/count3)/1000000,
			   sock_lock_br_us[i]/1000000, sock_processed[i],
			   (sock_lock_br_us[i]/count4)/1000000);
	}

	if (!break_reload_stt.tv_sec)
		tot1 = 0;
	else {
		if (!break_reload_fin.tv_sec)
			tot1 = tvdiff(now, &break_reload_stt);
		else
			tot1 = tvdiff(&break_reload_fin, &break_reload_stt);
	}
	if (!break_cmd_stt.tv_sec)
		tot2 = 0;
	else
		tot2 = tvdiff(now, &break_cmd_stt);
	count1 = break_reload_processed ? : 1;
	count2 = break_cmd_processed ? : 1;
	LOGWARNING(" break reload: t%fs/t%"PRIu64"/av%fs "
		   "%"PRIu64"s/%"PRIu64"w/%"PRIu64"t"
		   " cmd: t%fs/t%"PRIu64"/av%fs "
		   "%"PRIu64"s/%"PRIu64"w/%"PRIu64"t",
		   tot1, break_reload_processed, tot1/count1,
		   bq_reload_signals, bq_reload_wakes, bq_reload_timeouts,
		   tot2, break_cmd_processed, tot2/count2,
		   bq_cmd_signals, bq_cmd_wakes, bq_cmd_timeouts);

	LOGWARNING(" queue reload: %"PRIu64"s/%"PRIu64"w/%"PRIu64"t"
		   " cmd: %"PRIu64"s/%"PRIu64"w/%"PRIu64"t",
		   process_reload_signals, process_reload_wakes,
		   process_reload_timeouts,
		   process_socket_signals, process_socket_wakes,
		   process_socket_timeouts);

	LOGWARNING(" process pool: %"PRIu64"s/%"PRIu64"w/%"PRIu64"t"
		   " cmd: %"PRIu64"s/%"PRIu64"w/%"PRIu64"t"
		   " btc: %"PRIu64"s/%"PRIu64"w/%"PRIu64"t",
		   wq_pool_signals, wq_pool_wakes, wq_pool_timeouts,
		   wq_cmd_signals, wq_cmd_wakes, wq_cmd_timeouts,
		   wq_btc_signals, wq_btc_wakes, wq_btc_timeouts);

	count1 = clis_processed ? : 1;
	count2 = blis_processed ? : 1;
	LOGWARNING(" clistener: t%fs/t%"PRIu64"/av%fs"
		   " blistener: t%fs/t%"PRIu64"/av%fs",
		   clis_us/1000000, clis_processed, (clis_us/count1)/1000000,
		   blis_us/1000000, blis_processed, (blis_us/count2)/1000000);

	rep_max_fd = rep_max_pool_sockd_fd;
	if (rep_max_fd < rep_max_cmd_sockd_fd)
		rep_max_fd = rep_max_cmd_sockd_fd;
	if (rep_max_fd < rep_max_btc_sockd_fd)
		rep_max_fd = rep_max_btc_sockd_fd;
	LOGWARNING(" replies t%d/^%d/^%dfd/f%d pool ^%d/^%dfd cmd ^%d/^%dfd"
		   " btc ^%d/^%dfd",
		   rep_tot_sockd, rep_max_sockd, rep_max_fd, rep_failed_sockd,
		   rep_max_pool_sockd, rep_max_pool_sockd_fd,
		   rep_max_cmd_sockd, rep_max_cmd_sockd_fd,
		   rep_max_btc_sockd, rep_max_btc_sockd_fd);

	count1 = reply_sent ? : 1;
	LOGWARNING(" sent t%"PRIu64"/x%"PRIu64"/d%"PRIu64"/f%"PRIu64
		   "/t%fs/av%fs",
		   reply_sent, reply_cant, reply_discarded, reply_fails,
		   reply_full_us/1000000, (reply_full_us/count1)/1000000);

}

/* Limits are all +/-1s since on the live machine all were well within that
 * TODO: not thread safe */
static void check_createdate_ccl(char *cmd, tv_t *cd)
{
	static tv_t last_cd;
	static char last_cmd[CMD_SIZ+1];
	char cd_buf1[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];
	char *filename;
	double td;

	if (cd->tv_sec < reload_timestamp.tv_sec ||
	    cd->tv_sec >= (reload_timestamp.tv_sec + ROLL_S)) {
		ccl_mismatch_abs++;
		td = tvdiff(cd, &reload_timestamp);
		if (td < -1 || td > ROLL_S + 1) {
			ccl_mismatch++;
			filename = hour_filename("", "", reload_timestamp.tv_sec);
			tv_to_buf(cd, cd_buf1, sizeof(cd_buf1));
			LOGERR("%s(): CCL contains mismatch data: cmd:%s CCL:%.10s cd:%s",
				__func__, cmd, filename, cd_buf1);
			free(filename);
		}
		if (ccl_mismatch_min > td)
			ccl_mismatch_min = td;
		if (ccl_mismatch_max < td)
			ccl_mismatch_max = td;
	}

	td = tvdiff(cd, &last_cd);
	if (td < 0.0) {
		ccl_unordered_abs++;
		if (ccl_unordered_most > td)
			ccl_unordered_most = td;
	}
	if (td < -1.0) {
		ccl_unordered++;
		tv_to_buf(&last_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(cd, cd_buf2, sizeof(cd_buf2));
		LOGERR("%s(): CCL time unordered: %s<->%s %ld,%ld<->%ld,%ld %s<->%s",
			__func__, last_cmd, cmd, last_cd.tv_sec,last_cd.tv_usec,
			cd->tv_sec, cd->tv_usec, cd_buf1, cd_buf2);
	}

	copy_tv(&last_cd, cd);
	STRNCPY(last_cmd, cmd);
}

static int _ckdb_unix_write(int sockd, const char *msg, int len, WHERE_FFL_ARGS)
{
	int ret, ofs = 0;

	while (len) {
		ret = write(sockd, msg + ofs, len);
		if (ret < 0) {
			int e = errno;
			LOGERR("%s() Failed to write %d bytes (%d:%s)" WHERE_FFL,
			       __func__, len, e, strerror(e), WHERE_FFL_PASS);
			return -1;
		}
		ofs += ret;
		len -= ret;
	}
	return ofs;
}

static void _ckdb_unix_send(int sockd, const char *msg, WHERE_FFL_ARGS)
{
	bool warn = true;
	uint32_t msglen;
	size_t len;
	int ret;

	if (sockd < 0) {
		LOGWARNING("%s() invalid socket %d" WHERE_FFL,
			   __func__, sockd, WHERE_FFL_PASS);
		goto tamanee;
	}

	if (!msg) {
		LOGWARNING("%s() null msg on socket %d" WHERE_FFL,
			   __func__, sockd, WHERE_FFL_PASS);
		warn = false;
		goto tamanee;
	}

	len = strlen(msg);
	if (!len) {
		LOGWARNING("%s() zero length msg on socket %d" WHERE_FFL,
			   __func__, sockd, WHERE_FFL_PASS);
		warn = false;
		goto tamanee;
	}

	msglen = htole32(len);
	ret = _ckdb_unix_write(sockd, (const char *)(&msglen), 4,
				WHERE_FFL_PASS);
	if (ret < 4) {
		LOGERR("%s() failed to write four bytes on socket %d" WHERE_FFL,
			__func__, sockd, WHERE_FFL_PASS);
		goto tamanee;
	}

	ret = _ckdb_unix_write(sockd, msg, len, WHERE_FFL_PASS);
	if (ret < (int)len) {
		LOGERR("%s() failed2 to write %d bytes on socket %d" WHERE_FFL,
			__func__, (int)len, sockd, WHERE_FFL_PASS);
		goto tamanee;
	}

	warn = false;
tamanee:
	if (warn) {
		LOGWARNING(" msg was %d %.42s%s",
			   sockd, msg ? : nullstr, msg ? "..." : EMPTY);
	}
}

#define ckdb_unix_msg(_typ, _sockd, _msg, _ml, _dup) \
	_ckdb_unix_msg(_typ, _sockd, _msg, _ml, _dup, WHERE_FFL_HERE)

static void _ckdb_unix_msg(enum reply_type reply_typ, int sockd, char *msg,
			   MSGLINE *ml, bool dup, WHERE_FFL_ARGS)
{
	K_TREE *reply_root = NULL;
	REPLIES *replies = NULL;
	K_ITEM *r_item = NULL;
	int epollfd, ret, *rep_max, *rep_max_fd;
	char *ptr;
	tv_t now;

	switch(reply_typ) {
		case REPLIER_POOL:
			reply_root = replies_pool_root;
			epollfd = epollfd_pool;
			rep_max = &rep_max_pool_sockd;
			rep_max_fd = &rep_max_pool_sockd_fd;
			break;
		case REPLIER_CMD:
			reply_root = replies_cmd_root;
			epollfd = epollfd_cmd;
			rep_max = &rep_max_cmd_sockd;
			rep_max_fd = &rep_max_cmd_sockd_fd;
			break;
		case REPLIER_BTC:
			// Let the btc thread handle unknowns
		default:
			reply_root = replies_btc_root;
			epollfd = epollfd_btc;
			rep_max = &rep_max_btc_sockd;
			rep_max_fd = &rep_max_btc_sockd_fd;
			if (reply_typ != REPLIER_BTC) {
				char *st = NULL;
				LOGEMERG("%s() CODE ERROR unknown reply_type %d"
					 " msg %.32s...",
					 __func__, reply_typ,
					 st = safe_text_nonull(msg));
				FREENULL(st);
			}
			break;
	}

	if (!dup)
		ptr = msg;
	else {
		ptr = strdup(msg);
		if (!ptr)
			quithere(1, "strdup (%d) OOM", (int)strlen(msg));
	}

	K_WLOCK(replies_free);
	// ensure now is unique
	setnow(&now);
	r_item = k_unlink_head(replies_free);
	K_WUNLOCK(replies_free);
	DATA_REPLIES(replies, r_item);
	copy_tv(&(replies->now), &now);
	copy_tv(&(replies->createdate), &(ml->now));
	copy_tv(&(replies->accepted), &(ml->accepted));
	copy_tv(&(replies->broken), &(ml->broken));
	copy_tv(&(replies->processed), &(ml->processed));
	replies->event.events = EPOLLOUT | EPOLLHUP;
	replies->event.data.ptr = r_item;
	replies->sockd = sockd;
	replies->reply = ptr;
	replies->file = file;
	replies->func = func;
	replies->line = line;
	K_WLOCK(replies_free);
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, replies->sockd, &(replies->event));
	if (ret == 0) {
		k_add_head(replies_store, r_item);
		add_to_ktree(reply_root, r_item);
		rep_tot_sockd++;
		if (rep_max_sockd < replies_store->count)
			rep_max_sockd = replies_store->count;
		if (*rep_max < reply_root->node_store->count)
			*rep_max = reply_root->node_store->count;
		if (*rep_max_fd < sockd)
			*rep_max_fd = sockd;
	} else {
		k_add_head(replies_free, r_item);
		rep_failed_sockd++;
	}
	K_WUNLOCK(replies_free);
	if (ret != 0) {
		char *st = NULL;
		int e = errno;
		LOGEMERG("%s() failed to epoll add reply (%d:%s) msg=%.32s...",
			 __func__, e, strerror(e), st = safe_text(msg));
		FREENULL(st);
		free(ptr);
	}
}

static uint64_t ticks;
static time_t last_tick;

void tick()
{
	time_t now;
	char ch[2];

	now = time(NULL);
	if (now != last_tick) {
		last_tick = now;
		ch[0] = status_chars[ticks++ & 0x3];
		ch[1] = '\0';
		cr_msg(false, ch);
	}
}

PGconn *dbconnect()
{
	char conninfo[256];
	PGconn *conn;
	int i, retry = 10;

	snprintf(conninfo, sizeof(conninfo),
		 "host=127.0.0.1 dbname=%s user=%s%s%s",
		 db_name, db_user,
		 db_pass ? " password=" : "",
		 db_pass ? db_pass : "");

	conn = PQconnectdb(conninfo);
	if (PQstatus(conn) != CONNECTION_OK) {
		LOGERR("%s(): Failed 1st connect to db '%s'", __func__, pqerrmsg(conn));
		LOGERR("%s(): Retrying for %d seconds ...", __func__, retry);
		for (i = 0; i < retry; i++) {
			sleep(1);
			conn = PQconnectdb(conninfo);
			if (PQstatus(conn) == CONNECTION_OK) {
				LOGWARNING("%s(): Connected on attempt %d", __func__, i+2);
				return conn;
			}
		}
		quithere(1, "ERR: Failed to connect %d times to db '%s'",
			 retry+1, pqerrmsg(conn));
	}
	return conn;
}

/* Load tables required to support auths,adduser,chkpass and newid
 * OptionControl is loaded first in case it is needed by other loads
 *  (though not yet)
 */
static bool getdata1()
{
	PGconn *conn = NULL;
	bool ok = true;

	CKPQConn(&conn);

	if (!(ok = check_db_version(conn)))
		goto matane;
	if (!(ok = optioncontrol_fill(conn)))
		goto matane;
	if (!(ok = idcontrol_fill(conn)))
		goto matane;
	if (!(ok = users_fill(conn)))
		goto matane;
	if (!(ok = workers_fill(conn)))
		goto matane;
	ok = useratts_fill(conn);

matane:

	CKPQFinish(&conn);
	return ok;
}

/* Load blocks first to allow data range settings to know
 * the blocks info for setting limits for tables in getdata3()
 */
static bool getdata2()
{
	PGconn *conn = NULL;
	bool ok;

	CKPQConn(&conn);

	ok = blocks_fill(conn);

	CKPQFinish(&conn);

	return ok;
}

static bool getdata3()
{
	PGconn *conn = NULL;
	bool ok = true;

	CKPQConn(&conn);

	if (!key_update && !confirm_sharesummary) {
		if (!(ok = paymentaddresses_fill(conn)) || everyone_die)
			goto sukamudai;
		/* FYI must be after blocks */
		if (!(ok = payments_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!(ok = miningpayouts_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	CKPQFinish(&conn);
	CKPQConn(&conn);
	if (!(ok = workinfo_fill(conn)) || everyone_die)
		goto sukamudai;
	CKPQFinish(&conn);
	CKPQConn(&conn);
	if (!(ok = marks_fill(conn)) || everyone_die)
		goto sukamudai;
	/* must be after workinfo */
	if (!(ok = workmarkers_fill(conn)) || everyone_die)
		goto sukamudai;
	if (!key_update && !confirm_sharesummary) {
		/* must be after workmarkers */
		if (!(ok = payouts_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	CKPQFinish(&conn);
	CKPQConn(&conn);
	if (!key_update) {
		if (!(ok = markersummary_fill(conn)) || everyone_die)
			goto sukamudai;
	}
	CKPQFinish(&conn);
	CKPQConn(&conn);
	if (!key_update) {
		if (!(ok = shares_fill(conn)) || everyone_die)
			goto sukamudai;
		if (!confirm_sharesummary && !everyone_die)
			ok = poolstats_fill(conn);
	}

sukamudai:

	CKPQFinish(&conn);
	return ok;
}

static bool reload_from(tv_t *start, const tv_t *finish);

static bool reload()
{
	char buf[DATE_BUFSIZ+1];
	char *filename;
	tv_t start;
	char *reason;
	FILE *fp;

	tv_to_buf(&(dbstatus.newest_createdate_workmarker_workinfo),
		  buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB workmarker wid %"PRId64,
		   __func__, buf,
		   dbstatus.newest_workmarker_workinfoid);
	tv_to_buf(&(dbstatus.newest_createdate_workinfo), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB workinfo wid %"PRId64,
		   __func__, buf, dbstatus.newest_workinfoid);
	tv_to_buf(&(dbstatus.newest_createdate_poolstats), buf, sizeof(buf));
	LOGWARNING("%s(): %s newest DB poolstats (ignored)", __func__, buf);
	tv_to_buf(&(dbstatus.newest_createdate_blocks), buf, sizeof(buf));
	LOGWARNING("%s(): %"PRId32"/%s newest DB blocks (ignored)",
		   __func__, dbstatus.newest_height_blocks, buf);

	copy_tv(&start, &(dbstatus.newest_createdate_workmarker_workinfo));
	reason = "workmarkers";
	if (!tv_newer(&start, &(dbstatus.newest_createdate_workinfo))) {
		copy_tv(&start, &(dbstatus.newest_createdate_workinfo));
		reason = "workinfo";
	}

	tv_to_buf(&start, buf, sizeof(buf));
	LOGWARNING("%s() restart timestamp %s for %s", __func__, buf, reason);

	if (start.tv_sec < DATE_BEGIN) {
		start.tv_sec = DATE_BEGIN;
		start.tv_usec = 0L;
		filename = hour_filename(restorefrom, restorename, start.tv_sec);
		fp = fopen(filename, "re");
		if (fp)
			fclose(fp);
		else {
			mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(filename, O_CREAT|O_RDONLY, mode);
			if (fd == -1) {
				int ern = errno;
				quithere(1, "Couldn't create '%s' (%d) %s",
					 filename, ern, strerror(ern));
			}
			close(fd);
		}
		free(filename);
	}
	return reload_from(&start, &date_eot);
}

/* Open the file in path, check if there is a pid in there that still exists
 * and if not, write the pid into that file. */
static bool write_pid(pool_t *ckp, const char *path, pid_t pid)
{
	struct stat statbuf;
	FILE *fp;
	int ret;

	if (!stat(path, &statbuf)) {
		int oldpid;

		LOGWARNING("File %s exists", path);
		fp = fopen(path, "re");
		if (!fp) {
			LOGEMERG("Failed to open file %s", path);
			return false;
		}
		ret = fscanf(fp, "%d", &oldpid);
		fclose(fp);
		if (ret == 1 && !(kill(oldpid, 0))) {
			if (!ckp->killold) {
				LOGEMERG("Process %s pid %d still exists, start "
					 POOL_PROGNAME " with -k if you wish to kill it",
					 path, oldpid);
				return false;
			}
			if (kill(oldpid, 9)) {
				LOGEMERG("Unable to kill old process %s pid %d",
					 path, oldpid);
				return false;
			}
			LOGWARNING("Killing off old process %s pid %d",
				   path, oldpid);
		}
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

static void create_process_unixsock(proc_instance_t *pi)
{
	unixsock_t *us = &pi->us;

	us->path = strdup(pi->ckp->socket_dir);
	realloc_strcat(&us->path, pi->sockname);
	LOGDEBUG("Opening %s", us->path);
	us->sockd = open_unix_server(us->path);
	if (unlikely(us->sockd < 0))
		quit(1, "Failed to open %s socket", pi->sockname);
}

static void write_namepid(proc_instance_t *pi)
{
	char s[256];

	pi->pid = getpid();
	sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
	if (!write_pid(pi->ckp, s, pi->pid))
		quit(1, "Failed to write %s pid %d", pi->processname, pi->pid);
}

static void rm_namepid(proc_instance_t *pi)
{
	char s[256];

	sprintf(s, "%s%s.pid", pi->ckp->socket_dir, pi->processname);
	unlink(s);

}

static void clean_up(pool_t *ckp)
{
	rm_namepid(&ckp->main);
	dealloc(ckp->socket_dir);
	fclose(ckp->logfp);
}

// Allocate all but ioqueue here
static void alloc_storage()
{
	size_t len;
	int seq;

	// Emulate a list for lock checking
	process_pplns_free = k_lock_only_list("ProcessPPLNS");
	workers_db_free = k_lock_only_list("WorkersDB");
	users_db_free = k_lock_only_list("UsersDB");
	event_limits_free = k_lock_only_list("EventLimits");

#if LOCK_CHECK
	DLPRIO(process_pplns, 99);
	DLPRIO(workers_db, 98);
	DLPRIO(users_db, 97);
	DLPRIO(event_limits, 46); // events-2
#endif

	logqueue_free = k_new_list("LogQueue", sizeof(LOGQUEUE),
					ALLOC_LOGQUEUE, LIMIT_LOGQUEUE, true);
	logqueue_store = k_new_store(logqueue_free);

	breakqueue_free = k_new_list_cull("BreakQueue", sizeof(BREAKQUEUE),
					  ALLOC_BREAKQUEUE, LIMIT_BREAKQUEUE,
					  true, CULL_BREAKQUEUE);
	reload_breakqueue_store = k_new_store(breakqueue_free);
	reload_done_breakqueue_store = k_new_store(breakqueue_free);
	cmd_breakqueue_store = k_new_store(breakqueue_free);
	cmd_done_breakqueue_store = k_new_store(breakqueue_free);

	intransient_free = k_new_list("Intransient", sizeof(INTRANSIENT),
					ALLOC_INTRANSIENT, LIMIT_INTRANSIENT,
					true);
	intransient_store = k_new_store(intransient_free);
	intransient_root = new_ktree(NULL, cmp_intransient, intransient_free);

	nameram_free = k_new_list("NameRAM", sizeof(NAMERAM), ALLOC_NAMERAM,
				  LIMIT_NAMERAM, true);
	nameram_store = k_new_store(nameram_free);

#if LOCK_CHECK
	DLPRIO(logqueue, 94);
	DLPRIO(breakqueue, PRIO_TERMINAL);

	DLPRIO(intransient, 2);
	DLPRIO(nameram, 1);
#endif

	seqset_free = k_new_list("SeqSet", sizeof(SEQSET),
				 ALLOC_SEQSET, LIMIT_SEQSET, true);
	seqset_store = k_new_store(seqset_free);

	// Map the SEQ_NNN values to their cmd names
	seqnam[0] = strdup(SEQALL);
	for (seq = 0; ckdb_cmds[seq].cmd_val != CMD_END; seq++) {
		if (ckdb_cmds[seq].seq != SEQ_NONE) {
			if (seqnam[ckdb_cmds[seq].seq]) {
				quithere(1, "Name map in cddb_cmds[] to seqnam"
					    " isn't unique - seq %d is listed"
					    " twice as %s and %s",
					    seq, seqnam[ckdb_cmds[seq].seq],
					    ckdb_cmds[seq].cmd_str);
			}
			len = strlen(SEQPRE) + strlen(ckdb_cmds[seq].cmd_str) + 1;
			seqnam[ckdb_cmds[seq].seq] = malloc(len);
			if (!(seqnam[ckdb_cmds[seq].seq]))
				quithere(1, "malloc (%d) OOM", (int)len);
			snprintf(seqnam[ckdb_cmds[seq].seq], len, "%s%s",
				 SEQPRE, ckdb_cmds[seq].cmd_str);
		}
	}
	for (seq = 0; seq < SEQ_MAX; seq++) {
		if (seqnam[seq] == NULL) {
			quithere(1, "Name map in cddb_cmds[] is incomplete - "
				    " %d is missing", seq);
		}
	}

	seqtrans_free = k_new_list_cull("SeqTrans", sizeof(SEQTRANS),
					ALLOC_SEQTRANS, LIMIT_SEQTRANS, true,
					CULL_SEQTRANS);

	msgline_free = k_new_list_cull("MsgLine", sizeof(MSGLINE),
					ALLOC_MSGLINE, LIMIT_MSGLINE, true,
					CULL_MSGLINE);
	msgline_store = k_new_store(msgline_free);
	msgline_free->dsp_func = dsp_msgline;

	workqueue_free = k_new_list_cull("WorkQueue", sizeof(WORKQUEUE),
					 ALLOC_WORKQUEUE, LIMIT_WORKQUEUE,
					 true, CULL_WORKQUEUE);
	pool0_workqueue_store = k_new_store(workqueue_free);
	pool_workqueue_store = k_new_store(workqueue_free);
	cmd_workqueue_store = k_new_store(workqueue_free);
	btc_workqueue_store = k_new_store(workqueue_free);

	replies_free = k_new_list("Replies", sizeof(REPLIES),
					ALLOC_REPLIES, LIMIT_REPLIES, true);
	replies_store = k_new_store(replies_free);
	replies_pool_root = new_ktree("RepliesPool", cmp_replies, replies_free);
	replies_cmd_root = new_ktree("RepliesCmd", cmp_replies, replies_free);
	replies_btc_root = new_ktree("RepliesBTC", cmp_replies, replies_free);

	heartbeatqueue_free = k_new_list("HeartBeatQueue",
					 sizeof(HEARTBEATQUEUE),
					 ALLOC_HEARTBEATQUEUE,
					 LIMIT_HEARTBEATQUEUE, true);
	heartbeatqueue_store = k_new_store(heartbeatqueue_free);

	transfer_free = k_new_list_cull(Transfer, sizeof(TRANSFER),
					ALLOC_TRANSFER, LIMIT_TRANSFER, true,
					cull_transfer);
	transfer_free->dsp_func = dsp_transfer;

	users_free = k_new_list("Users", sizeof(USERS),
					ALLOC_USERS, LIMIT_USERS, true);
	users_store = k_new_store(users_free);
	users_root = new_ktree(NULL, cmp_users, users_free);
	userid_root = new_ktree("UsersId", cmp_userid, users_free);

	useratts_free = k_new_list("Useratts", sizeof(USERATTS),
					ALLOC_USERATTS, LIMIT_USERATTS, true);
	useratts_store = k_new_store(useratts_free);
	useratts_root = new_ktree(NULL, cmp_useratts, useratts_free);

	optioncontrol_free = k_new_list("OptionControl", sizeof(OPTIONCONTROL),
					ALLOC_OPTIONCONTROL,
					LIMIT_OPTIONCONTROL, true);
	optioncontrol_store = k_new_store(optioncontrol_free);
	optioncontrol_root = new_ktree(NULL, cmp_optioncontrol,
					optioncontrol_free);

	workers_free = k_new_list("Workers", sizeof(WORKERS),
					ALLOC_WORKERS, LIMIT_WORKERS, true);
	workers_store = k_new_store(workers_free);
	workers_root = new_ktree(NULL, cmp_workers, workers_free);

	paymentaddresses_free = k_new_list("PayAddr", sizeof(PAYMENTADDRESSES),
					   ALLOC_PAYMENTADDRESSES,
					   LIMIT_PAYMENTADDRESSES, true);
	paymentaddresses_store = k_new_store(paymentaddresses_free);
	paymentaddresses_root = new_ktree(NULL, cmp_paymentaddresses,
					  paymentaddresses_free);
	paymentaddresses_create_root = new_ktree("PayAddrCreate",
						 cmp_payaddr_create,
						 paymentaddresses_free);
	paymentaddresses_free->dsp_func = dsp_paymentaddresses;

	payments_free = k_new_list("Payments", sizeof(PAYMENTS),
					ALLOC_PAYMENTS, LIMIT_PAYMENTS, true);
	payments_store = k_new_store(payments_free);
	payments_root = new_ktree(NULL, cmp_payments, payments_free);

	accountbalance_free = k_new_list("AccountBalance",
					 sizeof(ACCOUNTBALANCE),
					 ALLOC_ACCOUNTBALANCE,
					 LIMIT_ACCOUNTBALANCE, true);
	accountbalance_store = k_new_store(accountbalance_free);
	accountbalance_root = new_ktree(NULL, cmp_accountbalance,
					accountbalance_free);

	idcontrol_free = k_new_list("IDControl", sizeof(IDCONTROL),
					ALLOC_IDCONTROL, LIMIT_IDCONTROL, true);
	idcontrol_store = k_new_store(idcontrol_free);
	idcontrol_root = new_ktree(NULL, cmp_idcontrol, idcontrol_free);
	idcontrol_free->dsp_func = dsp_idcontrol;

	esm_free = k_new_list("ESM", sizeof(ESM), ALLOC_ESM, LIMIT_ESM, true);
	esm_store = k_new_store(esm_free);
	esm_root = new_ktree(NULL, cmp_esm, esm_free);

	workinfo_free = k_new_list("WorkInfo", sizeof(WORKINFO),
					ALLOC_WORKINFO, LIMIT_WORKINFO, true);
	workinfo_store = k_new_store(workinfo_free);
	workinfo_root = new_ktree(NULL, cmp_workinfo, workinfo_free);
	if (!confirm_sharesummary) {
		workinfo_height_root = new_ktree("WorkInfoHeight",
						 cmp_workinfo_height,
						 workinfo_free);
	}

	shares_free = k_new_list("Shares", sizeof(SHARES),
					ALLOC_SHARES, LIMIT_SHARES, true);
	shares_store = k_new_store(shares_free);
	shares_early_store = k_new_store(shares_free);
	shares_root = new_ktree(NULL, cmp_shares, shares_free);
	shares_early_root = new_ktree("SharesEarly", cmp_shares, shares_free);
	shares_hi_store = k_new_store(shares_free);
	shares_hi_root = new_ktree("SharesHi", cmp_shares_db, shares_free);
	shares_db_root = new_ktree("SharesDB", cmp_shares_db, shares_free);

	shareerrors_free = k_new_list("ShareErrors", sizeof(SHAREERRORS),
					ALLOC_SHAREERRORS, LIMIT_SHAREERRORS,
					true);
	shareerrors_store = k_new_store(shareerrors_free);
	shareerrors_early_store = k_new_store(shareerrors_free);
	shareerrors_root = new_ktree(NULL, cmp_shareerrors, shareerrors_free);
	shareerrors_early_root = new_ktree("ShareErrorsEarly", cmp_shareerrors,
					   shareerrors_free);

	sharesummary_free = k_new_list("ShareSummary", sizeof(SHARESUMMARY),
					ALLOC_SHARESUMMARY, LIMIT_SHARESUMMARY,
					true);
	sharesummary_store = k_new_store(sharesummary_free);
	sharesummary_root = new_ktree(NULL, cmp_sharesummary,
					sharesummary_free);
	sharesummary_workinfoid_root = new_ktree("ShareSummaryWId",
						 cmp_sharesummary_workinfoid,
						 sharesummary_free);
	sharesummary_free->dsp_func = dsp_sharesummary;
	sharesummary_pool_store = k_new_store(sharesummary_free);
	sharesummary_pool_root = new_ktree("ShareSummaryPool",
					   cmp_sharesummary, sharesummary_free);

	blocks_free = k_new_list("Blocks", sizeof(BLOCKS),
					ALLOC_BLOCKS, LIMIT_BLOCKS, true);
	blocks_store = k_new_store(blocks_free);
	blocks_root = new_ktree(NULL, cmp_blocks, blocks_free);
	blocks_free->dsp_func = dsp_blocks;

	miningpayouts_free = k_new_list("MiningPayouts", sizeof(MININGPAYOUTS),
					ALLOC_MININGPAYOUTS, LIMIT_MININGPAYOUTS,
					true);
	miningpayouts_store = k_new_store(miningpayouts_free);
	miningpayouts_root = new_ktree(NULL, cmp_miningpayouts,
					miningpayouts_free);

	payouts_free = k_new_list("Payouts", sizeof(PAYOUTS),
					ALLOC_PAYOUTS, LIMIT_PAYOUTS, true);
	payouts_store = k_new_store(payouts_free);
	payouts_root = new_ktree(NULL, cmp_payouts, payouts_free);
	payouts_id_root = new_ktree("PayoutsId", cmp_payouts_id, payouts_free);
	payouts_wid_root = new_ktree("PayoutsWId", cmp_payouts_wid,
					payouts_free);

	ips_free = k_new_list("IPs", sizeof(IPS), ALLOC_IPS, LIMIT_IPS, true);
	ips_store = k_new_store(ips_free);
	ips_root = new_ktree(NULL, cmp_ips, ips_free);
	// Always default to allow localhost
	K_WLOCK(ips_free);
	ips_add(IPS_GROUP_OK, "127.0.0.1", EVENTNAME_ALL, true, "localhost",
		false, true, 0, true);
	ips_add(IPS_GROUP_OK, "127.0.0.1", OVENTNAME_ALL, false, "localhost",
		false, true, 0, true);
	K_WUNLOCK(ips_free);

	events_free = k_new_list("Events", sizeof(EVENTS),
					ALLOC_EVENTS, LIMIT_EVENTS, true);
	events_store = k_new_store(events_free);
	events_user_root = new_ktree("EventsUser", cmp_events_user, events_free);
	events_ip_root = new_ktree("EventsIP", cmp_events_ip, events_free);
	events_ipc_root = new_ktree("EventsIPC", cmp_events_ipc, events_free);
	events_hash_root = new_ktree("EventsHash", cmp_events_hash, events_free);

	ovents_free = k_new_list("OKEvents", sizeof(OVENTS),
					ALLOC_OVENTS, LIMIT_OVENTS, true);
	ovents_store = k_new_store(ovents_free);
	ovents_root = new_ktree(NULL, cmp_ovents, ovents_free);

	auths_free = k_new_list("Auths", sizeof(AUTHS),
					ALLOC_AUTHS, LIMIT_AUTHS, true);
	auths_store = k_new_store(auths_free);
	auths_root = new_ktree(NULL, cmp_auths, auths_free);

	poolstats_free = k_new_list("PoolStats", sizeof(POOLSTATS),
					ALLOC_POOLSTATS, LIMIT_POOLSTATS, true);
	poolstats_store = k_new_store(poolstats_free);
	poolstats_root = new_ktree(NULL, cmp_poolstats, poolstats_free);

	userstats_free = k_new_list("UserStats", sizeof(USERSTATS),
					ALLOC_USERSTATS, LIMIT_USERSTATS, true);
	userstats_store = k_new_store(userstats_free);
	userstats_eos_store = k_new_store(userstats_free);
	userstats_root = new_ktree(NULL, cmp_userstats, userstats_free);
	userstats_free->dsp_func = dsp_userstats;

	workerstatus_free = k_new_list("WorkerStatus", sizeof(WORKERSTATUS),
					ALLOC_WORKERSTATUS, LIMIT_WORKERSTATUS,
					true);
	workerstatus_store = k_new_store(workerstatus_free);
	workerstatus_root = new_ktree(NULL, cmp_workerstatus, workerstatus_free);

	markersummary_free = k_new_list("MarkerSummary", sizeof(MARKERSUMMARY),
					ALLOC_MARKERSUMMARY, LIMIT_MARKERSUMMARY,
					true);
	markersummary_store = k_new_store(markersummary_free);
	markersummary_root = new_ktree(NULL, cmp_markersummary,
					markersummary_free);
	markersummary_userid_root = new_ktree("MarkerSummaryUserId",
					      cmp_markersummary_userid,
					      markersummary_free);
	markersummary_free->dsp_func = dsp_markersummary;
	markersummary_pool_store = k_new_store(markersummary_free);
	markersummary_pool_root = new_ktree("MarkerSummaryPool",
					    cmp_markersummary,
					    markersummary_free);

	keysharesummary_free = k_new_list("KeyShareSummary",
					  sizeof(KEYSHARESUMMARY),
					  ALLOC_KEYSHARESUMMARY,
					  LIMIT_KEYSHARESUMMARY, true);
	keysharesummary_store = k_new_store(keysharesummary_free);
	keysharesummary_root = new_ktree(NULL, cmp_keysharesummary,
					 keysharesummary_free);

	keysummary_free = k_new_list("KeySummary", sizeof(KEYSUMMARY),
					ALLOC_KEYSUMMARY, LIMIT_KEYSUMMARY,
					true);
	keysummary_store = k_new_store(keysummary_free);
	keysummary_root = new_ktree(NULL, cmp_keysummary, keysummary_free);

	workmarkers_free = k_new_list("WorkMarkers", sizeof(WORKMARKERS),
					ALLOC_WORKMARKERS, LIMIT_WORKMARKERS, true);
	workmarkers_store = k_new_store(workmarkers_free);
	workmarkers_root = new_ktree(NULL, cmp_workmarkers, workmarkers_free);
	workmarkers_workinfoid_root = new_ktree("WorkMarkersWId",
						cmp_workmarkers_workinfoid,
						workmarkers_free);
	workmarkers_free->dsp_func = dsp_workmarkers;

	marks_free = k_new_list("Marks", sizeof(MARKS),
				ALLOC_MARKS, LIMIT_MARKS, true);
	marks_store = k_new_store(marks_free);
	marks_root = new_ktree(NULL, cmp_marks, marks_free);

	userinfo_free = k_new_list("UserInfo", sizeof(USERINFO),
					ALLOC_USERINFO, LIMIT_USERINFO, true);
	userinfo_store = k_new_store(userinfo_free);
	userinfo_root = new_ktree(NULL, cmp_userinfo, userinfo_free);

	// Emulate a list for lock checking
	pgdb_free = k_lock_only_list("PGDB");

#if LOCK_CHECK
	DLPRIO(seqset, 91);

	DLPRIO(transfer, 90);

	DLPRIO(payouts, 87);
	DLPRIO(miningpayouts, 86);
	DLPRIO(payments, 85);

	DLPRIO(accountbalance, 80);

	DLPRIO(workerstatus, 69);
	DLPRIO(sharesummary, 68);
	DLPRIO(keysharesummary, 67);
	DLPRIO(markersummary, 65);
	DLPRIO(keysummary, 64);
	DLPRIO(workmarkers, 62);

	DLPRIO(marks, 60);

	DLPRIO(workinfo, 56);

	DLPRIO(blocks, 53);

	DLPRIO(userinfo, 50);

	// Uses event_limits
	DLPRIO(optioncontrol, 49);

	// Needs to check users and ips and uses events_limits
	DLPRIO(events, 48);
	DLPRIO(ovents, 47);

	// events_limits 46 (events-2) above users

	DLPRIO(auths, 44);
	DLPRIO(users, 43);
	DLPRIO(useratts, 42);

	DLPRIO(shares, 31);
	DLPRIO(shareerrors, 30);

	DLPRIO(seqset, 21);
	DLPRIO(seqtrans, 20);

	DLPRIO(msgline, 17);
	DLPRIO(workqueue, 16);
	DLPRIO(heartbeatqueue, 15);

	DLPRIO(poolstats, 11);
	DLPRIO(userstats, 10);

	DLPRIO(paymentaddresses, 5);

	// Must be above instransient
	DLPRIO(idcontrol, 3);

	// Don't currently nest any locks in these:
	DLPRIO(esm, PRIO_TERMINAL);
	DLPRIO(workers, PRIO_TERMINAL);
	DLPRIO(ips, PRIO_TERMINAL);
	DLPRIO(replies, PRIO_TERMINAL);
	DLPRIO(pgdb, PRIO_TERMINAL);

	DLPCHECK();

	if (auto_check_deadlocks)
		check_deadlocks = true;
#endif

	// setup intransients
	in_empty = get_intransient("empty", EMPTY);
	userstats_workername = get_intransient("workername", "all");
}

static void share_reports()
{
	SHAREERRORS *shareerrors;
	char *st = NULL;
	K_ITEM *s_item;
	SHARES *shares;

	if (shareerrors_free && shareerrors_early_store->count > 0) {
		LOGERR("%s() *** shareerrors_early count %d ***",
			__func__, shareerrors_early_store->count);
		s_item = STORE_HEAD_NOLOCK(shareerrors_early_store);
		while (s_item) {
			DATA_SHAREERRORS(shareerrors, s_item);
			LOGNOTICE("%s(): %"PRId64"/%s/%"PRId32"/%s/%ld,%ld",
				  __func__,
				  shareerrors->workinfoid,
				  st = safe_text_nonull(shareerrors->in_workername),
				  shareerrors->errn,
				  shareerrors->error,
				  shareerrors->createdate.tv_sec,
				  shareerrors->createdate.tv_usec);
			FREENULL(st);
			s_item = s_item->next;
		}
	}

	if (shares_free && shares_early_store->count > 0) {
		LOGERR("%s() *** shares_early count %d ***",
			__func__, shares_early_store->count);
		s_item = STORE_HEAD_NOLOCK(shares_early_store);
		while (s_item) {
			DATA_SHARES(shares, s_item);
			LOGNOTICE("%s(): %"PRId64"/%s/%s/%"PRId32
				  "/%ld,%ld", __func__,
				  shares->workinfoid,
				  st = safe_text_nonull(shares->in_workername),
				  shares->nonce,
				  shares->errn,
				  shares->createdate.tv_sec,
				  shares->createdate.tv_usec);
			FREENULL(st);
			s_item = s_item->next;
		}
	}
}

static void esm_report()
{
	K_ITEM *esm_item;
	ESM *esm;

	if (esm_free && esm_store->count > 0) {
		LOGWARNING("%s() *** ESM had %d record%s ***",
			   __func__, esm_store->count,
			   (esm_store->count == 1) ? EMPTY : "s");
		esm_item = STORE_HEAD_NOLOCK(esm_store);
		while (esm_item) {
			DATA_ESM(esm, esm_item);
			LOGNOTICE("%s(): %"PRId64" %d/%d/%d err:%d/%d/%d"
				  " %ld,%ld", __func__,
				  esm->workinfoid, esm->queued, esm->procured,
				  esm->discarded, esm->errqueued,
				  esm->errprocured, esm->errdiscarded,
				  esm->createdate.tv_sec,
				  esm->createdate.tv_usec);
			esm_item = esm_item->next;
		}
	}
}

#define SEQSETMSG(_set, _seqset, _msgtxt, _endtxt) do { \
	char _t_buf[DATE_BUFSIZ]; \
	bool _warn = ((_seqset)->seqdata[SEQ_SHARES].missing > 0) || \
		     ((_seqset)->seqdata[SEQ_SHARES].lost > 0); \
	btu64_to_buf(&((_seqset)->seqstt), _t_buf, sizeof(_t_buf)); \
	LOGWARNING("%s %s: %d/"SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64 \
		   " M%"PRIu64"/T%"PRIu64"/L%"PRIu64"/S%"PRIu64"/H%"PRIu64 \
		   "/R%"PRIu64"/OK%"PRIu64" %s v%"PRIu64"/^%"PRIu64"/M%"PRIu64 \
		   "/T%"PRIu64"/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/R%"PRIu64 \
		   "/OK%"PRIu64" %s v%"PRIu64"/^%"PRIu64"/M%"PRIu64"/T%"PRIu64 \
		   "/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/R%"PRIu64 \
		   "/OK%"PRIu64"%s", \
		   _warn ? "SEQ" : "Seq", \
		   _msgtxt, _set, (_seqset)->seqstt, _t_buf, \
		   (_seqset)->seqpid, (_seqset)->missing, (_seqset)->trans, \
		   (_seqset)->lost, (_seqset)->stale, (_seqset)->high, \
		   (_seqset)->recovered, (_seqset)->ok, \
		   seqnam[SEQ_ALL], \
		   (_seqset)->seqdata[SEQ_ALL].minseq, \
		   (_seqset)->seqdata[SEQ_ALL].maxseq, \
		   (_seqset)->seqdata[SEQ_ALL].missing, \
		   (_seqset)->seqdata[SEQ_ALL].trans, \
		   (_seqset)->seqdata[SEQ_ALL].lost, \
		   (_seqset)->seqdata[SEQ_ALL].stale, \
		   (_seqset)->seqdata[SEQ_ALL].high, \
		   (_seqset)->seqdata[SEQ_ALL].recovered, \
		   (_seqset)->seqdata[SEQ_ALL].ok, \
		   seqnam[SEQ_SHARES], \
		   (_seqset)->seqdata[SEQ_SHARES].minseq, \
		   (_seqset)->seqdata[SEQ_SHARES].maxseq, \
		   (_seqset)->seqdata[SEQ_SHARES].missing, \
		   (_seqset)->seqdata[SEQ_SHARES].trans, \
		   (_seqset)->seqdata[SEQ_SHARES].lost, \
		   (_seqset)->seqdata[SEQ_SHARES].stale, \
		   (_seqset)->seqdata[SEQ_SHARES].high, \
		   (_seqset)->seqdata[SEQ_SHARES].recovered, \
		   (_seqset)->seqdata[SEQ_SHARES].ok, _endtxt); \
	} while(0)

#define FREE_TREE(_tree) \
	if (_tree ## _root) \
		free_ktree(_tree ## _root, NULL) \

#define FREE_STORE(_list) \
	if (_list ## _store) \
		_list ## _store = k_free_store(_list ## _store) \

#define FREE_LIST(_list) \
	if (_list ## _free) \
		_list ## _free = k_free_list(_list ## _free) \

#define FREE_STORE_DATA(_list) \
	if (_list ## _store) { \
		K_ITEM *_item = STORE_HEAD_NOLOCK(_list ## _store); \
		while (_item) { \
			free_ ## _list ## _data(_item); \
			_item = _item->next; \
		} \
		_list ## _store = k_free_store(_list ## _store); \
	}

#define FREE_LIST_DATA(_list) \
	if (_list ## _free) { \
		K_ITEM *_item = LIST_HEAD_NOLOCK(_list ## _free); \
		while (_item) { \
			free_ ## _list ## _data(_item); \
			_item = _item->next; \
		} \
		_list ## _free = k_free_list(_list ## _free); \
	}

#define FREE_LISTS(_list) FREE_STORE(_list); FREE_LIST(_list)

#define FREE_ALL(_list) FREE_TREE(_list); FREE_LISTS(_list)

/* Write a share missing/lost report to the console - always report set 0
 * It's possible for the set numbers to be wrong and the output to report one
 *  seqset twice if a new seqset arrives between the unlock/lock for writing
 *  the console message - since a new seqset would shuffle the sets down and
 *  if the list was full, move the last one back to the top of the setset_store
 *  list, but this would normally only be when asicseer-pool restarts and also wont
 *  cause a problem since only the last set can be moved and the code checks
 *  if it is the end and also duplicates the set before releasing the lock */
void sequence_report(bool lock)
{
	SEQSET *seqset, seqset_copy;
	K_ITEM *ss_item;
	bool last, miss;
	int set;

	last = false;
	set = 0;
	if (lock) {
		SEQLOCK();
		ss_item = STORE_RHEAD(seqset_store);
	} else {
		ss_item = STORE_HEAD_NOLOCK(seqset_store);
	}
	while (!last && ss_item) {
		if (!ss_item->next)
			last = true;
		DATA_SEQSET(seqset, ss_item);
		/* Missing/Trans/Lost should all be 0 for shares */
		if (seqset->seqstt && (set == 0 ||
		    seqset->seqdata[SEQ_SHARES].missing ||
		    seqset->seqdata[SEQ_SHARES].trans ||
		    seqset->seqdata[SEQ_SHARES].lost)) {
			miss = (seqset->seqdata[SEQ_SHARES].missing > 0) ||
				(seqset->seqdata[SEQ_SHARES].lost > 0);
			if (lock) {
				memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
				SEQUNLOCK();
				seqset = &seqset_copy;
			}
			SEQSETMSG(set, seqset,
				  miss ? "SHARES MISSING" : "status" , EMPTY);
			if (lock)
				SEQLOCK();
		}
		ss_item = ss_item->next;
		set++;
	}
	if (lock)
		SEQUNLOCK();
}

static void dealloc_storage()
{
	int seq;

	if (free_mode == FREE_MODE_NONE) {
		share_reports();
		esm_report();
		sequence_report(false);

		LOGWARNING("%s() skipped", __func__);
		return;
	}

	if (logqueue_free) {
		LOGWARNING("%s() logqueue ...", __func__);
		FREE_LISTS(logqueue);
	}

	LOGWARNING("%s() user/marks ...", __func__);
	FREE_ALL(userinfo);

	FREE_TREE(marks);
	FREE_STORE_DATA(marks);
	FREE_LIST_DATA(marks);

	FREE_TREE(workmarkers_workinfoid);
	FREE_TREE(workmarkers);
	if (workmarkers_key_store) {
		k_list_transfer_to_tail_nolock(workmarkers_key_store,
					       workmarkers_store);
	}
	FREE_STORE_DATA(workmarkers);
	FREE_LIST_DATA(workmarkers);

	if (free_mode != FREE_MODE_ALL)
		LOGWARNING("%s() key/markersummary skipped", __func__);
	else {
		LOGWARNING("%s() key/markersummary ...", __func__);

		FREE_TREE(keysummary);
		FREE_STORE_DATA(keysummary);
		FREE_LIST(keysummary);

		FREE_TREE(keysharesummary);
		FREE_STORE_DATA(keysharesummary);
		FREE_LIST(keysharesummary);

		FREE_TREE(markersummary_pool);
		k_list_transfer_to_tail_nolock(markersummary_pool_store,
					       markersummary_store);
		FREE_STORE(markersummary_pool);
		FREE_TREE(markersummary_userid);
		FREE_TREE(markersummary);
		FREE_STORE_DATA(markersummary);
		FREE_LIST_DATA(markersummary);
	}

	FREE_ALL(workerstatus);

	LOGWARNING("%s() userstats ...", __func__);

	FREE_STORE(userstats_eos);
	FREE_ALL(userstats);

	LOGWARNING("%s() poolstats ...", __func__);

	FREE_ALL(poolstats);
	FREE_TREE(events_user);
	FREE_TREE(events_ip);
	FREE_TREE(events_ipc);
	FREE_TREE(events_hash);
	FREE_LISTS(events);
	FREE_ALL(ovents);
	FREE_TREE(ips);
	FREE_STORE_DATA(ips);
	FREE_LIST(ips);
	FREE_ALL(auths);

	FREE_TREE(payouts_wid);
	FREE_TREE(payouts_id);
	FREE_TREE(payouts);
	FREE_STORE_DATA(payouts);
	FREE_LIST_DATA(payouts);

	FREE_ALL(miningpayouts);
	FREE_ALL(blocks);

	if (sharesummary_free) {
		LOGWARNING("%s() sharesummary ...", __func__);
		FREE_TREE(sharesummary_pool);
		k_list_transfer_to_tail_nolock(sharesummary_pool_store,
					       sharesummary_store);
		FREE_STORE(sharesummary_pool);
		FREE_TREE(sharesummary_workinfoid);
		FREE_TREE(sharesummary);
		FREE_STORE_DATA(sharesummary);
		FREE_LIST_DATA(sharesummary);
	}

	if (shares_free) {
		LOGWARNING("%s() shares ...", __func__);
		share_reports();
		FREE_TREE(shareerrors_early);
		FREE_STORE(shareerrors_early);
		FREE_ALL(shareerrors);

		FREE_TREE(shares_hi);
		FREE_TREE(shares_db);
		FREE_STORE(shares_hi);
		FREE_TREE(shares_early);
		FREE_STORE(shares_early);
		FREE_ALL(shares);
	}

	if (free_mode != FREE_MODE_ALL)
		LOGWARNING("%s() workinfo skipped", __func__);
	else {
		LOGWARNING("%s() workinfo ...", __func__);
		FREE_TREE(workinfo_height);
		FREE_TREE(workinfo);
		FREE_STORE_DATA(workinfo);
		FREE_LIST_DATA(workinfo);
	}

	LOGWARNING("%s() etc ...", __func__);

	esm_report();
	FREE_ALL(esm);

	FREE_ALL(idcontrol);
	FREE_ALL(accountbalance);
	FREE_ALL(payments);

	FREE_TREE(paymentaddresses_create);
	FREE_ALL(paymentaddresses);
	FREE_ALL(workers);

	FREE_TREE(optioncontrol);
	FREE_STORE_DATA(optioncontrol);
	FREE_LIST_DATA(optioncontrol);

	FREE_ALL(useratts);

	FREE_TREE(userid);
	FREE_TREE(users);
	FREE_STORE_DATA(users);
	FREE_LIST_DATA(users);

	LOGWARNING("%s() transfer/heartbeatqueue/workqueue ...", __func__);

	FREE_LIST(transfer);
	FREE_LISTS(heartbeatqueue);
	FREE_TREE(replies_pool);
	FREE_TREE(replies_cmd);
	FREE_TREE(replies_btc);
	FREE_STORE(replies);
	FREE_LIST(replies);
	// TODO: msgline
	FREE_STORE(pool0_workqueue);
	FREE_STORE(pool_workqueue);
	FREE_STORE(cmd_workqueue);
	FREE_STORE(btc_workqueue);
	FREE_LIST(workqueue);
	// TODO: sockets/buf/msgline
	FREE_STORE(cmd_done_breakqueue);
	FREE_STORE(cmd_breakqueue);
	FREE_STORE(reload_done_breakqueue);
	FREE_STORE(reload_breakqueue);
	FREE_LIST(breakqueue);
	FREE_LISTS(msgline);

	sequence_report(false);
	if (seqset_free) {
		if (free_mode != FREE_MODE_ALL)
			LOGWARNING("%s() seqset skipped", __func__);
		else {
			LOGWARNING("%s() seqset ...", __func__);

			FREE_STORE_DATA(seqset);
			FREE_LIST_DATA(seqset);
			FREE_LISTS(seqset);

			// Must be after seqset
			FREE_LIST(seqtrans);

			for (seq = 0; seq < SEQ_MAX; seq++)
				FREENULL(seqnam[seq]);
		}
	}

	LOGWARNING("%s() finished", __func__);
}

static bool setup_data()
{
	K_TREE_CTX ctx[1];
	K_ITEM look, *found;
	WORKINFO wi, *wic, *wif;
	tv_t db_stt, db_fin, rel_stt, rel_fin;
	double min, sec;

	LOGWARNING("%sSequence processing is %s",
		   ignore_seq ? "ALERT: " : "",
		   ignore_seq ? "Off" : "On");
	LOGWARNING("%sStartup payout generation state is %s",
		   genpayout_auto ? "" : "WARNING: ",
		   genpayout_auto ? "On" : "Off");
	LOGWARNING("%sStartup mark generation state is %s",
		   markersummary_auto ? "" : "WARNING: ",
		   markersummary_auto ? "On" : "Off");
	LOGWARNING("Workinfo transaction storage is %s",
		   txn_tree_store ? "On" : "Off");

	setnow(&db_stt);

	if (!getdata1() || everyone_die)
		return false;

	db_users_complete = true;
	cksem_post(&socksetup_sem);

	if (!getdata2() || everyone_die)
		return false;

	if (dbload_workinfoid_start != -1) {
		LOGWARNING("WARNING: dbload starting at workinfoid %"PRId64,
			   dbload_workinfoid_start);
		if (dbload_only_sharesummary)
			LOGWARNING("NOTICE: dbload only restricting sharesummary");
	}

	if (!getdata3() || everyone_die)
		return false;

	/* This should never display anything since POOLINSTANCE_DBLOAD_MSG()
	 *  resets each _obj's modified counters */
	POOLINSTANCE_RESET_MSG("dbload");
	setnow(&db_fin);
	sec = tvdiff(&db_fin, &db_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("dbload complete %.0fm %.3fs", min, sec);

	db_load_complete = true;

	setnow(&rel_stt);

	if (!reload() || everyone_die)
		return false;

	POOLINSTANCE_RESET_MSG("reload");
	setnow(&rel_fin);
	sec = tvdiff(&rel_fin, &rel_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("reload complete %.0fm %.3fs", min, sec);

	// full lock access since mark processing can occur
	K_KLONGWLOCK(process_pplns_free);

	K_WLOCK(workerstatus_free);
	K_RLOCK(sharesummary_free);
	K_RLOCK(markersummary_free);
	K_RLOCK(workmarkers_free);

	set_block_share_counters();

	if (!everyone_die)
		workerstatus_ready();

	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(sharesummary_free);
	K_WUNLOCK(workerstatus_free);

	K_WUNLOCK(process_pplns_free);

	if (everyone_die)
		return false;

	K_WLOCK(workinfo_free);
	workinfo_current = last_in_ktree(workinfo_height_root, ctx);
	if (workinfo_current) {
		DATA_WORKINFO(wic, workinfo_current);
		wi.coinbase1 = wic->coinbase1;
		DATE_ZERO(&(wi.createdate));
		INIT_WORKINFO(&look);
		look.data = (void *)(&wi);
		// Find the first workinfo for this height
		found = find_after_in_ktree(workinfo_height_root, &look, ctx);
		if (found) {
			DATA_WORKINFO(wif, found);
			copy_tv(&last_bc,  &(wif->createdate));
		}
		// No longer needed
		free_ktree(workinfo_height_root, NULL);
	}
	K_WUNLOCK(workinfo_free);

	return true;
}

#define SEQINUSE firstcd.tv_sec

#define RESETSET(_seqset, _n_seqstt, _n_seqpid) do { \
		int _i; \
		(_seqset)->seqstt = (_n_seqstt); \
		(_seqset)->seqpid = (_n_seqpid); \
		for (_i = 0; _i < SEQ_MAX; _i++) { \
			(_seqset)->seqdata[_i].minseq = \
			(_seqset)->seqdata[_i].maxseq = \
			(_seqset)->seqdata[_i].seqbase = \
			(_seqset)->seqdata[_i].missing = \
			(_seqset)->seqdata[_i].trans = \
			(_seqset)->seqdata[_i].lost = \
			(_seqset)->seqdata[_i].stale = \
			(_seqset)->seqdata[_i].high = \
			(_seqset)->seqdata[_i].recovered = \
			(_seqset)->seqdata[_i].ok = 0; \
			(_seqset)->seqdata[_i].SEQINUSE = \
			(_seqset)->seqdata[_i].firstcd.tv_usec = \
			(_seqset)->seqdata[_i].lastcd.tv_sec = \
			(_seqset)->seqdata[_i].lastcd.tv_usec = \
			(_seqset)->seqdata[_i].firsttime.tv_sec = \
			(_seqset)->seqdata[_i].firsttime.tv_usec = \
			(_seqset)->seqdata[_i].lasttime.tv_sec = \
			(_seqset)->seqdata[_i].lasttime.tv_usec = 0L; \
		} \
	} while (0);

#define MISSFLAG cd.tv_sec
#define TRANSFLAG cd.tv_usec

// Test if an item is missing/transient
#define ENTRYISMIS(_seqentry) ((_seqentry)->MISSFLAG == 0)
#define DATAISMIS(_seqdata, _u) \
	ENTRYISMIS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

#define ENTRYONLYMIS(_seqentry) (((_seqentry)->MISSFLAG == 0) && \
				 ((_seqentry)->TRANSFLAG == 0))

#define ENTRYISTRANS(_seqentry) (((_seqentry)->MISSFLAG == 0) && \
				 ((_seqentry)->TRANSFLAG != 0))
#define DATAISTRANS(_seqdata, _u) \
	ENTRYISTRANS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

// Flag an item as missing
#define ENTRYSETMIS(_seqentry, _now) do { \
		(_seqentry)->MISSFLAG = 0; \
		(_seqentry)->TRANSFLAG = 0; \
		(_seqentry)->time.tv_sec = now->tv_sec; \
		(_seqentry)->time.tv_usec = now->tv_usec; \
	} while(0)
#define DATASETMIS(_seqdata, _u, _now) \
	ENTRYSETMIS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]), _now)

/* Flag an item directly as transient missing -
 *  it will already be missing but we set both flags */
#define ENTRYSETTRANS(_seqentry) do { \
		(_seqentry)->MISSFLAG = 0; \
		(_seqentry)->TRANSFLAG = 1; \
	} while(0)
#define DATASETTRANS(_seqdata, _u) \
	ENTRYSETTRANS(&((_seqdata)->entry[(_u) & ((_seqdata)->size - 1)]))

// Check for transient missing every X seconds
#define TRANCHECKLIMIT 2.0
static tv_t last_trancheck;
// Don't let these messages be slowed down by a trans_process()
#define TRANCHKSEQOK(_seq) ((_seq) != SEQ_SHARES && (_seq) != SEQ_AUTH && \
			    (_seq) != SEQ_ADDRAUTH && (_seq) != SEQ_BLOCK)

// How many seconds to allow the build up of trans range messages
#define TRANSAGELIMIT 10.0

/* time (now) is used, not cd, since cd is only relevant to reloading
 *  and we don't run trans_process() during reloading
 * We also only know now, not cd, for a missing item
 * This fills in store with a copy of the details of all the new transients
 * N.B. this is called under SEQLOCK() */
static void trans_process(SEQSET *seqset, tv_t *now, K_STORE *store)
{
	SEQDATA *seqdata = NULL;
	SEQENTRY *seqentry = NULL;
	uint64_t zero, top, u;
	SEQTRANS *seqtrans;
	K_ITEM *st_item;
	int seq;

	for (seq = 0; seq < SEQ_MAX; seq++) {
		seqdata = &(seqset->seqdata[seq]);
		if (seqdata->SEQINUSE == 0)
			continue;

		/* run as 2 loops from seqbase to top, then bottom to maxseq
		 * thus we can use seqentry++ rather than calculating it
		 * each time */
		zero = seqdata->seqbase - (seqdata->seqbase & (seqdata->size - 1));
		top = zero + seqdata->size - 1;
		if (top > seqdata->maxseq)
			top = seqdata->maxseq;
		u = seqdata->seqbase;
		seqentry = &(seqdata->entry[seqdata->seqbase & (seqdata->size - 1)]);
		while (u <= top) {
			if (ENTRYONLYMIS(seqentry) &&
			    tvdiff(now, &(seqentry->time)) > seqdata->timelimit) {
				ENTRYSETTRANS(seqentry);
				seqdata->trans++;
				seqset->trans++;
				// N.B. lock inside lock
				K_WLOCK(seqtrans_free);
				st_item = k_unlink_head(seqtrans_free);
				K_WUNLOCK(seqtrans_free);
				DATA_SEQTRANS(seqtrans, st_item);
				seqtrans->seq = seq;
				seqtrans->seqnum = u;
				memcpy(&(seqtrans->entry), seqentry, sizeof(SEQENTRY));
				k_add_head_nolock(store, st_item);
			}
			u++;
			seqentry++;
		}

		// 2nd loop isn't needed, we've already covered the full range
		if (top == seqdata->maxseq)
			continue;

		u = zero + seqdata->size;
		seqentry = &(seqdata->entry[0]);
		while (u <= seqdata->maxseq) {
			if (ENTRYONLYMIS(seqentry) &&
			    tvdiff(now, &(seqentry->time)) > seqdata->timelimit) {
				ENTRYSETTRANS(seqentry);
				seqdata->trans++;
				seqset->trans++;
				// N.B. lock inside lock
				K_WLOCK(seqtrans_free);
				st_item = k_unlink_head(seqtrans_free);
				K_WUNLOCK(seqtrans_free);
				DATA_SEQTRANS(seqtrans, st_item);
				seqtrans->seq = seq;
				seqtrans->seqnum = u;
				memcpy(&(seqtrans->entry), seqentry, sizeof(SEQENTRY));
				k_add_head_nolock(store, st_item);
			}
			u++;
			seqentry++;
		}
	}
}

static void trans_seq(tv_t *now)
{
	char t_buf[DATE_BUFSIZ], t_buf2[DATE_BUFSIZ];
	char range[64];
	K_STORE *store;
	SEQSET *seqset = NULL;
	K_ITEM *item = NULL, *lastitem = NULL;
	SEQTRANS *seqtrans;
	K_ITEM *st_item;
	uint64_t seqstt = 0, seqpid = 0, seqnum0, seqnum1;
	tv_t seqsec;
	bool more = true, gotseq;
	int i, j, nam;

	store = k_new_store(seqtrans_free);
	for (i = 0; more; i++) {
		SEQLOCK();
		if (seqset_store->count <= i)
			more = false;
		else {
			item = STORE_RHEAD(seqset_store);
			for (j = 0; item && j < 0; j++)
				item = item->next;
			if (!item)
				more = false;
			else {
				/* Avoid wasting time reprocessing the item
				 *  if a new set was added outside the lock
				 *  and pushed the sets along one */
				if (item != lastitem) {
					DATA_SEQSET(seqset, item);
					seqstt = seqset->seqstt;
					seqpid = seqset->seqpid;
					if (seqstt)
						trans_process(seqset, now, store);
					else
						more = false;
				}
				lastitem = item;
			}
		}
		if (seqset_store->count <= (i + 1))
			more = false;
		SEQUNLOCK();

		st_item = STORE_TAIL_NOLOCK(store);
		/* Display one line for all records that would display the same
		 *  excluding the sequence number - displayed as a continuous
		 *  range */
		seqnum0 = seqnum1 = 0;
		seqsec.tv_sec = 0;
		gotseq = false;
		nam = -1;
		while (st_item) {
			DATA_SEQTRANS(seqtrans, st_item);
			if (!gotseq) {
				seqnum0 = seqnum1 = seqtrans->seqnum;
				nam = seqtrans->seq;
				seqsec.tv_sec = seqtrans->entry.time.tv_sec;
				gotseq = true;
			} else {
				if (seqtrans->seqnum == seqnum1+1 &&
				    seqtrans->seq == nam &&
				    seqtrans->entry.time.tv_sec == seqsec.tv_sec) {
					seqnum1++;
				} else {
					// Display the previous range

					if (seqnum0 == seqnum1) {
						snprintf(range, sizeof(range),
							 "%"PRIu64, seqnum1);
					} else {
						snprintf(range, sizeof(range),
							 "%"PRIu64"-%"PRIu64
							 " (%"PRIu64")",
							 seqnum0, seqnum1,
							 1 + seqnum1 - seqnum0);
					}
					btu64_to_buf(&seqstt, t_buf,
							sizeof(t_buf));
					bt_to_buf(&(seqsec.tv_sec), t_buf2,
						  sizeof(t_buf2));
					LOGWARNING("Seq trans %s %s set:%d/"
						   "%"PRIu64"=%s/%"PRIu64" %s",
						   seqnam[nam], range,
						   i, seqstt, t_buf, seqpid,
						   t_buf2);

					// Current record is a new range
					seqnum0 = seqnum1 = seqtrans->seqnum;
					nam = seqtrans->seq;
					seqsec.tv_sec = seqtrans->entry.time.tv_sec;
					gotseq = true;
				}
			}
			st_item = st_item->prev;
		}
		// Display the last range if there was one
		if (gotseq) {
			if (seqnum0 == seqnum1) {
				snprintf(range, sizeof(range),
					 "%"PRIu64, seqnum1);
			} else {
				snprintf(range, sizeof(range),
					 "%"PRIu64"-%"PRIu64" (%"PRIu64")",
					 seqnum0, seqnum1,
					 1 + seqnum1 - seqnum0);
			}
			btu64_to_buf(&seqstt, t_buf, sizeof(t_buf));
			bt_to_buf(&(seqsec.tv_sec), t_buf2, sizeof(t_buf2));
			LOGWARNING("Seq trans %s %s set:%d/"
				   "%"PRIu64"=%s/%"PRIu64" %s",
				   seqnam[nam], range, i, seqstt, t_buf,
				   seqpid, t_buf2);
		}
		if (store->count) {
			K_WLOCK(seqtrans_free);
			k_list_transfer_to_head(store, seqtrans_free);
			K_WUNLOCK(seqtrans_free);
		}
	}
	store = k_free_store(store);
}

/* Only called once just before flagging reload as finished
 * Set all the reloadmax variables in all seqdata */
static void seq_reloadmax()
{
	K_ITEM *seqset_item;
	SEQSET *seqset;
	SEQDATA *seqdata;
	int i;

	SEQLOCK();
	if (seqset_store->count > 0) {
		seqset_item = STORE_WHEAD(seqset_store);
		while (seqset_item) {
			DATA_SEQSET(seqset, seqset_item);
			if (seqset->seqstt) {
				seqdata = seqset->seqdata;
				for (i = 0; i < SEQ_MAX; i++) {
					if (seqdata->SEQINUSE)
						seqdata->reloadmax = seqdata->maxseq;
					seqdata++;
				}
			}
			seqset_item = seqset_item->next;
		}
	}
	SEQUNLOCK();
}

/* Local structure for update_seq() to remember trans found as ranges
 * It's in use if last.tv_sec != 0 */
typedef struct seqfound {
	tv_t last;
	int set;
	uint64_t seqstt;
	uint64_t seqpid;
	// seq range
	uint64_t seq1, seq2;
	// cd range
	tv_t cd1, cd2;
	bool forced_msg;
} SEQFOUND;

static void msgs_seq(SEQFOUND *found_msgs)
{
	char t_buf[DATE_BUFSIZ], t_buf2[DATE_BUFSIZ];
	char r_buf[64], t_buf3[DATE_BUFSIZ], c_buf[64];
	int i;

	for (i = 0; i < SEQ_MAX; i++) {
		if (found_msgs[i].last.tv_sec != 0) {
			btu64_to_buf(&(found_msgs[i].seqstt), t_buf,
				     sizeof(t_buf));
			bt_to_buf(&(found_msgs[i].cd1.tv_sec), t_buf2,
				  sizeof(t_buf2));
			if (found_msgs[i].seq2 == found_msgs[i].seq1) {
				r_buf[0] = '\0';
				c_buf[0] = '\0';
			} else {
				snprintf(r_buf, sizeof(r_buf),
					 "-%"PRIu64,
					 found_msgs[i].seq2);
				snprintf(c_buf, sizeof(c_buf),
					 " (%"PRIu64")",
					 found_msgs[i].seq2 + 1 -
					 found_msgs[i].seq1);
			}
			if (found_msgs[i].cd1.tv_sec == found_msgs[i].cd2.tv_sec)
				t_buf3[0] = '\0';
			else {
				ms_to_buf(&(found_msgs[i].cd2.tv_sec),
					  t_buf3, sizeof(t_buf3));
			}
			LOGWARNING("Seq found trans %s %"PRIu64"%s%s"
				   " set:%d/%"PRIu64"=%s/%"PRIu64
				   " %s%s%s",
				   seqnam[i], found_msgs[i].seq1, r_buf, c_buf,
				   found_msgs[i].set,
				   found_msgs[i].seqstt, t_buf,
				   found_msgs[i].seqpid, t_buf2,
				   t_buf3[0] ? ".." : EMPTY, t_buf3);
		}
	}
}

/* Most of the extra message logic in here is to avoid putting too many
 *  messages or incorrect messages on the console when errors occur
 * It wont lose msglines from the reload or the queue, since if there is any
 *  problem with any msgline, it will be processed rather than skipped
 * Only valid duplicates, with all 4 sequence numbers (all, cmd, stt, pid)
 *  matching a previous msgline, are flagged DUP to be skipped by the
 *  sequence code */
static bool update_seq(enum seq_num seq, uint64_t n_seqcmd,
			uint64_t n_seqstt, uint64_t n_seqpid,
			char *nam, tv_t *now, tv_t *cd, INTRANSIENT *in_code,
			int seqentryflags, char *msg)
{
	static SEQFOUND found[SEQ_MAX];
	// flag to avoid always accessing the lock since trans is extremely rare
	static bool has_found;

	char t_buf[DATE_BUFSIZ], t_buf2[DATE_BUFSIZ], *st = NULL;
	bool firstseq, newseq, expseq, gothigh, okhi, gotstale, gotstalestart;
	SEQSET *seqset = NULL, *seqset0 = NULL, seqset_pre = { 0 };
	SEQSET seqset_exp = { 0 }, seqset_copy = { 0 };
	bool dup, wastrans, doitem, dotime, gotrecover, used;
	SEQDATA *seqdata;
	SEQENTRY *seqentry, seqentry_copy, *u_entry;
	K_ITEM *seqset_item = NULL, *st_item = NULL, *stl_item = NULL;
	SEQTRANS *seqtrans = NULL, *seqtrans2 = NULL;
	size_t siz, end;
	void *off0, *offn;
	uint64_t u;
	int set = -1, expset = -1, highlimit, i;
	K_STORE *lost = NULL;
	SEQFOUND found_msgs[SEQ_MAX];
	tv_t found_now;

	LOGDEBUG("%s() SQ %c:%d/%s/%"PRIu64"/%"PRIu64"/%"PRIu64"/%s '%.80s...",
		 __func__, SECHR(seqentryflags), seq, nam, n_seqcmd, n_seqstt,
		 n_seqpid, in_code->str, st = safe_text(msg));
	FREENULL(st);

	firstseq = newseq = expseq = gothigh = okhi = gotstale =
	gotstalestart = dup = wastrans = gotrecover = false;
	SEQLOCK();
	// Get the seqset
	if (seqset_store->count == 0)
		firstseq = true;
	else {
		// Normal processing is: count=1 and head is current
		seqset_item = STORE_WHEAD(seqset_store);
		DATA_SEQSET(seqset, seqset_item);
		set = 0;
		if (n_seqstt == seqset->seqstt && n_seqpid == seqset->seqpid)
			goto gotseqset;
		// It's not the current set, check the older ones
		while ((seqset_item = seqset_item->next)) {
			DATA_SEQSET(seqset, seqset_item);
			set++;
			if (seqset->seqstt && n_seqstt == seqset->seqstt &&
			    n_seqpid == seqset->seqpid) {
				goto gotseqset;
			}
		}
	}

	// Need to setup a new seqset
	newseq = true;
	if (!firstseq) {
		// If !STORE_WHEAD(seqset_store) (i.e. a bug) this will quit()
		DATA_SEQSET(seqset0, STORE_WHEAD(seqset_store));
		// The current seqset (may become the previous)
		memcpy(&seqset_pre, seqset0, sizeof(seqset_pre));
	}
	seqset_item = k_unlink_head_zero(seqset_free);
	if (seqset_item) {
		// Setup a new set - everything is already zero
		DATA_SEQSET(seqset, seqset_item);
		seqset->seqstt = n_seqstt;
		seqset->seqpid = n_seqpid;
		for (i = 0; i < SEQ_MAX; i++) {
			// Unnecessary - but as a reminder
			seqset->seqdata[i].SEQINUSE = 0;
			seqset->seqdata[i].highlimit = 0;
			switch (i) {
			    case SEQ_ALL:
				seqset->seqdata[i].highlimit = SEQ_ALL_HIGHLIMIT;
			    case SEQ_SHARES:
				seqset->seqdata[i].size = SEQ_LARGE_SIZ;
				seqset->seqdata[i].timelimit = SEQ_LARGE_TRANS_LIM;
				break;
			    case SEQ_WORKERSTAT:
			    case SEQ_AUTH:
			    case SEQ_ADDRAUTH:
				seqset->seqdata[i].size = SEQ_MEDIUM_SIZ;
				seqset->seqdata[i].timelimit = SEQ_MEDIUM_TRANS_LIM;
				break;
			    default:
				seqset->seqdata[i].size = SEQ_SMALL_SIZ;
				seqset->seqdata[i].timelimit = SEQ_SMALL_TRANS_LIM;
				break;
			}
			siz = seqset->seqdata[i].size;
			if (siz < BASE_SIZ || (siz & (siz-1))) {
				// On the first ever seq record
				quithere(1, "seqdata[%d] size %d (0x%x) is %s %d",
					    i, (int)siz, (int)siz,
					    (siz < BASE_SIZ) ?
						"too small, must be >=" :
						"not a power of",
					    (siz < BASE_SIZ) ? BASE_SIZ : 2);
			}
			if (seqset->seqdata[i].highlimit == 0) {
				highlimit = siz >> HIGH_SHIFT;
				if (highlimit < HIGH_MIN) {
					// On the first ever seq record
					quithere(1, "seqdata[%d] highlimit %d "
						    "(0x%x) is too small, must"
						    " be >= %d",
						    i, highlimit, highlimit,
						    HIGH_MIN);
				}
				seqset->seqdata[i].highlimit = highlimit;
			}
			seqset->seqdata[i].entry = calloc(siz,
							  sizeof(SEQENTRY));
			end = siz * sizeof(SEQENTRY);
			off0 = &(seqset->seqdata[i].entry[0]);
			offn = &(seqset->seqdata[i].entry[siz]);
			if ((int)end != (offn - off0)) {
				// On the first ever seq record
				quithere(1, "memory size (%d) != structure "
					    "offset (%d) - your cc sux",
					    (int)end, (int)(offn - off0));
			}
			LIST_MEM_ADD_SIZ(seqset_free, end);
		}
	} else {
		/* Expire the oldest set and overwrite it
		 * If this happens during a reload and the expired set is in
		 *  the queue, then this will most likely end up spitting out
		 *  lots of errors since this will cause a chain reaction,
		 *  after the reload completes, of expiring the last set, that
		 *  is ahead in the unprocessed queue, each time the queue
		 *  advances to the next set
		 * This can only happen if the pool restarts SEQ_MAX times
		 *  during the reload ... so it's extremely unlikely but
		 *  also will be obvious in the console log if it happens
		 * The (very unlikely) side effect would be that it could miss
		 *  spotting lost sequence numbers: between the maxseq of a set
		 *  in the reload, and the base of the same set in the queue
		 * The fix is simply to stop asicseer-db immediately if asicseer-pool is
		 *  constantly failing (SEQ_MAX times during the reload) and
		 *  restart asicseer-db when asicseer-pool isn't aborting, or if asicseer-pool is
		 *  in a problematic state, start asicseer-db while asicseer-pool isn't
		 *  running, then start asicseer-pool when asicseer-db completes it's full
		 *  startup */
		K_ITEM *ss_item;
		SEQSET *ss = NULL;
		int s = 0;
		seqset = NULL;
		seqset_item = NULL;
		ss_item = STORE_WHEAD(seqset_store);
		while (ss_item) {
			DATA_SEQSET(ss, ss_item);
			if (!seqset) {
				seqset = ss;
				seqset_item = ss_item;
				expset = s;
			} else {
				// choose the last match
				if (ss->seqstt >= seqset->seqstt) {
					seqset = ss;
					seqset_item = ss_item;
					expset = s;
				}
			}
			ss_item = ss_item->next;
			s++;
		}
		// If !seqset_item (i.e. a bug) k_unlink_item() will quit()
		k_unlink_item(seqset_store, seqset_item);
		DATA_SEQSET(seqset, seqset_item);
		memcpy(&seqset_exp, seqset, sizeof(seqset_exp));
		expseq = true;
		RESETSET(seqset, n_seqstt, n_seqpid);
	}
	/* To avoid putting an old set as first in the list, if they are out
	 *  of order, each new set is added depending upon the value of seqstt
	 *  so the current pool is first, to minimise searching seqset_store
	 * The order of the rest isn't as important
	 * N.B. a new set is only created once per asicseer-pool start */
	if (firstseq) {
		k_add_head(seqset_store, seqset_item);
		set = 0;
	} else {
		// seqset0 already is the head
		if (n_seqstt >= seqset0->seqstt) {
			// if new set is >= head then make it the head
			k_add_head(seqset_store, seqset_item);
			set = 0;
		} else {
			// put it next after the head
			k_insert_after(seqset_store, seqset_item,
					STORE_WHEAD(seqset_store));
			set = 1;
		}
	}

gotseqset:
	doitem = dotime = false;

	seqdata = &(seqset->seqdata[seq]);
	seqentry = &(seqdata->entry[n_seqcmd & (seqdata->size - 1)]);
	if (seqdata->SEQINUSE == 0) {
		// First n_seqcmd for the given seq
		copy_tv(&(seqdata->firsttime), now);
		copy_tv(&(seqdata->lasttime), now);
		copy_tv(&(seqdata->firstcd), cd); // In use
		copy_tv(&(seqdata->lastcd), cd);
		seqdata->minseq = seqdata->maxseq =
		seqdata->seqbase = n_seqcmd;
		doitem = true;
		goto setitemdata;
		// TODO: add a check/message if minseq!=0 and
		//	 it's a 2nd or later set
	}

	if (n_seqcmd > seqdata->maxseq) {
		/* New seq above maxseq */
		if ((n_seqcmd - seqdata->maxseq) > seqdata->highlimit) {
			/* During a reload there may be missing data/gaps if
			 *  there was some problem with the reload data
			 * When we switch from the reload data to the queue
			 *  data, it is also flagged ok since it may also be
			 *  due to lost data at the end, or missing reload files
			 * In both these cases the message will be 'OKHI'
			 *  instead of 'HIGH'
			 * If however this is caused by a corrupt seq number
			 *  then the result will be a large range of lost
			 *  msglines followed by continuous stale msglines
			 *  until it catches up to the corrupt seq number
			 *  Currently the only fix to get rid of the console
			 *   messages is to fix/remove the corrupt high
			 *   msgline from the reload data and restart asicseer-db
			 *   You would have to stop asicseer-db first if it is in the
			 *    current hour reload file
			 *  Note of course if it came from the queue it will
			 *   be in the reload data when you restart asicseer-db */
			if ((seqentryflags & SE_RELOAD) ||
			    (seqdata->maxseq == seqdata->reloadmax))
				okhi = true;

			seqdata->high++;
			seqset->high++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gothigh = true;
		}
		for (u = seqdata->maxseq + 1; u <= n_seqcmd; u++) {
			if ((u - seqdata->seqbase) < seqdata->size) {
				// u is unused
				if (u < n_seqcmd) {
					// Flag skipped ones as missing
					DATASETMIS(seqdata, u, now);
					seqdata->missing++;
					seqset->missing++;
				}
			} else {
				// u is used by (u-size)
				u_entry = &(seqdata->entry[u & (seqdata->size - 1)]);
				if (ENTRYISMIS(u_entry)) {
					/* (u-size) was missing
					 * N.B. lock inside lock */
					K_WLOCK(seqtrans_free);
					st_item = k_unlink_head(seqtrans_free);
					if (u_entry->flags & SE_RELOAD)
						stl_item = k_unlink_head(seqtrans_free);
					K_WUNLOCK(seqtrans_free);
					DATA_SEQTRANS(seqtrans, st_item);
					seqtrans->seqnum = u - seqdata->size;
					memcpy(&(seqtrans->entry), u_entry,
						sizeof(SEQENTRY));
					if (!lost)
						lost = k_new_store(seqtrans_free);
					k_add_tail_nolock(lost, st_item);
					seqdata->lost++;
					seqset->lost++;
					if (ENTRYISTRANS(u_entry)) {
						// no longer trans
						seqdata->trans--;
						seqset->trans--;
					}
					if (u == n_seqcmd) {
						// new wont be missing
						seqdata->missing--;
						seqset->missing--;
					} else {
						// new will also be missing
						ENTRYSETMIS(u_entry, now);
					}

					/* Store stale reload entries so we can
					 *  check against any stale queue
					 *  entries and flag them as recovered
					 *  or DUP */
					if (u_entry->flags & SE_RELOAD) {
						DATA_SEQTRANS(seqtrans, stl_item);
						seqtrans->seqnum = u - seqdata->size;
						memcpy(&(seqtrans->entry), u_entry,
							sizeof(SEQENTRY));
						if (!seqdata->reload_lost) {
							seqdata->reload_lost = k_new_store(seqtrans_free);
							seqdata_reload_lost = true;
						}
						k_add_tail_nolock(seqdata->reload_lost, stl_item);
					}
				} else {
					// (u-size) wasn't missing
					if (u < n_seqcmd) {
						// Flag skipped as missing
						DATASETMIS(seqdata, u, now);
						seqdata->missing++;
						seqset->missing++;
					}
				}
				seqdata->seqbase++;
			}
			seqdata->maxseq++;
		}
		// store n_seqcmd
		doitem = true;
		dotime = true;
	} else if (n_seqcmd >= seqdata->seqbase) {
		/* It's within the range thus DUP or missing */
		if (!ENTRYISMIS(seqentry)) {
			dup = true;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			memcpy(&seqentry_copy, seqentry, sizeof(seqentry_copy));
		} else {
			// Found a missing one
			seqdata->missing--;
			seqset->missing--;
			if (ENTRYISTRANS(seqentry)) {
				seqdata->trans--;
				seqset->trans--;
				wastrans = true;
			}
			doitem = true;
			dotime = true;
		}
	} else if (n_seqcmd < seqdata->minseq) {
		/* This would be early during startup, less than minseq
		 * This requires lowering minseq if there's space to lower it
		 *  to n_seqcmd */
		if ((n_seqcmd + seqdata->size) > seqdata->maxseq) {
			// Set all after n_seqcmd but before minseq as missing
			for (u = seqdata->minseq - 1; u > n_seqcmd; u--) {
				DATASETMIS(seqdata, u, now);
				seqdata->minseq--;
				seqdata->seqbase--;
				seqset->missing++;
				seqdata->missing++;
			}
			seqdata->minseq--;
			seqdata->seqbase--;
			doitem = true;
			dotime = true;
		} else {
			// Can't go back that far, so it's stale
			seqdata->stale++;
			seqset->stale++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gotstalestart = true;
		}
	} else {
		/* >=minseq but <seqbase means it's stale
		 * However we want to flag it as a DUP if it is a queued
		 *  msgline that was already processed during the reload
		 *  This can happen if the reload finish seq numbers is
		 *   greater than the first queue seq number + siz
		 *   i.e. a long reload where the queue gets large enough
		 *	  to cause this */
		st_item = NULL;
		if (seqdata->reload_lost) {
			st_item = STORE_WHEAD(seqdata->reload_lost);
			// seqnum order is not guaranteed
			while (st_item) {
				DATA_SEQTRANS(seqtrans, st_item);
				if (seqtrans->seqnum == n_seqcmd)
					break;
				st_item = st_item->next;
			}
		}
		if (st_item) {
			// recovered a lost entry
			k_unlink_item_nolock(seqdata->reload_lost, st_item);
			K_WLOCK(seqtrans_free);
			k_add_head(seqtrans_free, st_item);
			K_WUNLOCK(seqtrans_free);
			seqdata->lost--;
			seqset->lost--;
			seqdata->recovered++;
			seqset->recovered++;
			seqdata->ok++;
			seqset->ok++;
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			gotrecover = true;
			goto setitemdata;
		}

		/* Reload will still have all the lost entries
		 *  thus since it's not lost/recovered, it must be a DUP */
		if (seqentryflags & SE_RELOAD) {
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			dup = true;
			goto setitemdata;
		}

		/* Before we've synced up the queue and still not discarded
		 *  the reload lost list, if it's not lost/recovered but
		 *  still in the reload range, it must be a DUP */
		if (seqentryflags & SE_EARLYSOCK && n_seqcmd <= seqdata->reloadmax) {
			memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
			dup = true;
			goto setitemdata;
		}

		// Reload lost list is gone or it's after the reload range
		seqdata->stale++;
		seqset->stale++;
		memcpy(&seqset_copy, seqset, sizeof(seqset_copy));
		gotstale = true;
	}

setitemdata:
	// Store the new seq if flagged to do so
	if (doitem) {
		seqentry->flags = seqentryflags;
		copy_tv(&(seqentry->time), now);
		copy_tv(&(seqentry->cd), cd);
		seqentry->in_code = in_code->str;
		seqdata->ok++;
		seqset->ok++;
	}
	if (dotime) {
		if (tv_newer(now, &(seqdata->firsttime)))
			copy_tv(&(seqdata->firsttime), now);
		if (tv_newer(&(seqdata->lasttime), now))
			copy_tv(&(seqdata->lasttime), now);
		if (tv_newer(cd, &(seqdata->firstcd)))
			copy_tv(&(seqdata->firstcd), cd);
		if (tv_newer(&(seqdata->lastcd), cd))
			copy_tv(&(seqdata->lastcd), cd);
	}

	SEQUNLOCK();

	if (firstseq) {
		// The first ever SEQ_ALL
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		LOGWARNING("Seq first init: %s:%"PRIu64" "
			   SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64,
			   nam, n_seqcmd, n_seqstt, t_buf, n_seqpid);
	} else {
		if (newseq) {
			if (set == 0)
				SEQSETMSG(0, &seqset_pre, "previous", EMPTY);
			else
				SEQSETMSG(0, &seqset_pre, "current", EMPTY);
		}
		if (expseq) {
			SEQSETMSG(expset, &seqset_exp, "discarded old", " for:");
		}
		if (newseq || expseq) {
			btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
			LOGWARNING("Seq created new: set:%d %s:%"PRIu64" "
				   SEQSTT":%"PRIu64"=%s "SEQPID":%"PRIu64,
				   set, nam, n_seqcmd, n_seqstt, t_buf,
				   n_seqpid);
		}
	}

	if (dup) {
		int level = LOG_WARNING;
		/* If one is SE_RELOAD and the other is SE_EARLYSOCK or
		 *  SE_SOCKET then it's not unexpected, so only use LOG_DEBUG
		 * Technically SE_SOCKET is unexpected, except that at the end
		 *  of the reload sync there may still be pool messages that
		 *  haven't got into the queue yet - it wouldn't be expected
		 *  for there to be many since it would be asicseer-db emptying the
		 *  queue faster than it is filling due to the reload delay -
		 *  but either way they don't need to be reported */
		if (((seqentry_copy.flags | seqentryflags) & SE_RELOAD) &&
		    ((seqentry_copy.flags | seqentryflags) & (SE_EARLYSOCK | SE_SOCKET)))
			level = LOG_DEBUG;
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGMSG(level, "SEQ dup%s %c:%c %s %"PRIu64" set:%d/%"PRIu64
				"=%s/%"PRIu64" %s/%s -vs- v%"PRIu64"/^%"PRIu64
				"/M%"PRIu64"/T%"PRIu64"/L%"PRIu64"/S%"PRIu64
				"/H%"PRIu64"/OK%"PRIu64" cmd=%.42s...",
				(level == LOG_DEBUG) ? "*" : EMPTY,
				SECHR(seqentryflags), SECHR(seqentry_copy.flags),
				nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
				t_buf2, in_code->str,
				seqset_copy.seqdata[seq].minseq,
				seqset_copy.seqdata[seq].maxseq,
				seqset_copy.seqdata[seq].missing,
				seqset_copy.seqdata[seq].trans,
				seqset_copy.seqdata[seq].lost,
				seqset_copy.seqdata[seq].stale,
				seqset_copy.seqdata[seq].high,
				seqset_copy.seqdata[seq].ok,
				st = safe_text(msg));
		FREENULL(st);
	}

	if (wastrans) {
		for (i = 0; i < SEQ_MAX; i++)
			found_msgs[i].last.tv_sec = 0;
		used = false;
		setnow(&found_now);
		ck_wlock(&seq_found_lock);
		if (found[seq].last.tv_sec != 0) {
			// Can we append it?
			if (found[seq].seq2 == (n_seqcmd - 1) &&
			    found[seq].set == set &&
			    found[seq].seqstt == n_seqstt &&
			    found[seq].seqpid == n_seqpid) {
				found[seq].seq2++;
				if (tv_newer(cd, &(found[seq].cd1)))
					copy_tv(&(found[seq].cd1), cd);
				if (tv_newer(&(found[seq].cd2), cd))
					copy_tv(&(found[seq].cd2), cd);
				used = true;
			} else {
				// No, so force display it
				found[seq].forced_msg = true;
			}
		}
		// Check if there are any ranges >= the limit (or forced)
		for (i = 0; i < SEQ_MAX; i++) {
			if (found[i].forced_msg || (found[i].last.tv_sec != 0 &&
			    tvdiff(&found_now, &(found[i].last)) >= TRANSAGELIMIT)) {
				memcpy(&(found_msgs[i]), &(found[i]),
					sizeof(SEQFOUND));
				// will be displayed, so erase it
				found[i].last.tv_sec = 0;
				found[i].forced_msg = false;
			}
		}
		// Store it - found[seq] will (now) be unused
		if (!used) {
			copy_tv(&(found[seq].last), &found_now);
			found[seq].set = set;
			found[seq].seqstt = n_seqstt;
			found[seq].seqpid = n_seqpid;
			found[seq].seq1 = found[seq].seq2 = n_seqcmd;
			copy_tv(&(found[seq].cd1), cd);
			copy_tv(&(found[seq].cd2), cd);
		}
		has_found = false;
		for (i = 0; i < SEQ_MAX; i++) {
			if (found[i].last.tv_sec != 0)
				has_found = true;
		}
		ck_wunlock(&seq_found_lock);
		msgs_seq(found_msgs);
	} else {
		if (has_found) {
			for (i = 0; i < SEQ_MAX; i++)
				found_msgs[i].last.tv_sec = 0;
			ck_wlock(&seq_found_lock);
			if (has_found) {
				setnow(&found_now);
				for (i = 0; i < SEQ_MAX; i++) {
					if (found[i].last.tv_sec != 0 &&
					    tvdiff(&found_now, &(found[i].last)) >= TRANSAGELIMIT) {
						memcpy(&(found_msgs[i]),
							&(found[i]),
							sizeof(SEQFOUND));
						// will be displayed, so erase it
						found[i].last.tv_sec = 0;
						found[i].forced_msg = false;
					}
				}
				has_found = false;
				for (i = 0; i < SEQ_MAX; i++) {
					if (found[i].last.tv_sec != 0)
						has_found = true;
				}
			}
			ck_wunlock(&seq_found_lock);
			msgs_seq(found_msgs);
		}
	}

	if (gotrecover) {
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGWARNING("SEQ recovered %s %"PRIu64" set:%d/%"PRIu64
			   "=%s/%"PRIu64" %s/%s",
			   nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
			   t_buf2, in_code->str);
	}

	if (gotstale || gotstalestart || gothigh) {
		btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
		bt_to_buf(&(cd->tv_sec), t_buf2, sizeof(t_buf2));
		LOGWARNING("SEQ %s %s%s %"PRIu64" set:%d/%"PRIu64"=%s/%"PRIu64
			   " %s/%s v%"PRIu64"/^%"PRIu64"/M%"PRIu64"/T%"PRIu64
			   "/L%"PRIu64"/S%"PRIu64"/H%"PRIu64"/OK%"PRIu64
			   " cmd=%.42s...",
			   gothigh ? (okhi ? "OKHI" : "HIGH") : "stale",
			   gotstalestart ? "STARTUP " : EMPTY,
			   nam, n_seqcmd, set, n_seqstt, t_buf, n_seqpid,
			   t_buf2, in_code->str,
			   seqset_copy.seqdata[seq].minseq,
			   seqset_copy.seqdata[seq].maxseq,
			   seqset_copy.seqdata[seq].missing,
			   seqset_copy.seqdata[seq].trans,
			   seqset_copy.seqdata[seq].lost,
			   seqset_copy.seqdata[seq].stale,
			   seqset_copy.seqdata[seq].high,
			   seqset_copy.seqdata[seq].ok,
			   st = safe_text(msg));
		FREENULL(st);
	}
	if (reload_queue_complete && TRANCHKSEQOK(seq)) {
		if (last_trancheck.tv_sec == 0)
			setnow(&last_trancheck);
		else {
			if (tvdiff(now, &last_trancheck) > TRANCHECKLIMIT) {
				trans_seq(now);
				setnow(&last_trancheck);
			}
		}
	}

	if (lost && lost->count) {
		int tran = 0, miss = 0;
		uint64_t prev = 0;
		char range_buf[256];
		bool isrange = false;
		st_item = STORE_HEAD_NOLOCK(lost);
		while (st_item) {
			DATA_SEQTRANS(seqtrans, st_item);
			st_item = st_item->next;
			DATA_SEQTRANS_NULL(seqtrans2, st_item);

			if (ENTRYISTRANS(&(seqtrans->entry)))
				tran++;
			else
				miss++;

			// Output the messages as ranges if they are
			if (st_item && seqtrans2->seqnum == (seqtrans->seqnum+1)) {
				if (!prev)
					prev = seqtrans->seqnum;
				continue;
			}
			if (prev) {
				isrange = true;
				snprintf(range_buf, sizeof(range_buf),
					 "RANGE %d tran %d miss %"PRIu64
					 "-%"PRIu64,
					 tran, miss, prev,
					 seqtrans->seqnum);
				prev = 0;
			} else {
				isrange = false;
				snprintf(range_buf, sizeof(range_buf),
					 "%s %"PRIu64,
					 ENTRYISTRANS(&(seqtrans->entry)) ?
					 "tran" : "miss",
					 seqtrans->seqnum);
			}
			// consumed
			tran = miss = 0;

			btu64_to_buf(&n_seqstt, t_buf, sizeof(t_buf));
			bt_to_buf(&(seqtrans->entry.time.tv_sec), t_buf2,
				   sizeof(t_buf2));
			LOGWARNING("SEQ lost %s %s set:%d/%"PRIu64"=%s/%"PRIu64
				   " %s%s/%s",
				   seqnam[seq], range_buf, set,
				   n_seqstt, t_buf, n_seqpid,
				   isrange ? "last: " : EMPTY,
				   t_buf2, seqtrans->entry.in_code);
		}
		K_WLOCK(seqtrans_free);
		k_list_transfer_to_head(lost, seqtrans_free);
		K_WUNLOCK(seqtrans_free);
	}

	if (lost)
		lost = k_free_store(lost);

	return dup;
}

static enum cmd_values process_seq(MSGLINE *msgline)
{
	bool dupall = false, dupcmd = false;
	char *st = NULL;

	if (ignore_seq)
		return ckdb_cmds[msgline->which_cmds].cmd_val;

	/* If non-seqall data was in a CCL reload file,
	 *  it can't be processed by update_seq(), so don't */
	if (msgline->n_seqall == 0 && msgline->n_seqstt == 0 &&
	    msgline->n_seqpid == 0) {
		if (SEQALL_LOG) {
			LOGNOTICE("%s() SEQALL 0 skipping %.42s...",
				  __func__,
				  st = safe_text(msgline->msg));
			FREENULL(st);
		}
		return ckdb_cmds[msgline->which_cmds].cmd_val;
	}

	if (SEQALL_LOG) {
		LOGNOTICE("%s() SEQALL %"PRIu64" %"PRIu64" %"PRIu64,
			  __func__, msgline->n_seqall, msgline->n_seqstt,
			  msgline->n_seqpid);
	}

	if (!ignore_seqall) {
		dupall = update_seq(SEQ_ALL, msgline->n_seqall,
				    msgline->n_seqstt, msgline->n_seqpid,
				    SEQALL, &(msgline->now), &(msgline->cd),
				    msgline->in_code, msgline->seqentryflags,
				    msgline->msg);
	}
	dupcmd = update_seq(ckdb_cmds[msgline->which_cmds].seq,
			    msgline->n_seqcmd, msgline->n_seqstt,
			    msgline->n_seqpid, msgline->seqcmdnam,
			    &(msgline->now), &(msgline->cd), msgline->in_code,
			    msgline->seqentryflags, msgline->msg);

	if (ignore_seqall)
		dupall = dupcmd;

	if (dupall != dupcmd) {
		// Bad/corrupt data or a code bug
		LOGEMERG("SEQ INIMICAL %s/%"PRIu64"=%s %s/%"PRIu64"=%s "
			 "cmd=%.32s...",
			 seqnam[SEQ_ALL], msgline->n_seqall,
			 dupall ? "DUP" : "notdup",
			 msgline->seqcmdnam, msgline->n_seqcmd,
			 dupcmd ? "DUP" : "notdup",
			 st = safe_text_nonull(msgline->msg));
		FREENULL(st);
	}

	/* The norm is: neither is a dup, so reply with ok to process
	 * If only one is a dup then that's a corrupt message or a bug
	 *  so simply try to process it as normal */
	if (!dupall || !dupcmd)
		return ckdb_cmds[msgline->which_cmds].cmd_val;

	if (SEQALL_LOG) {
		LOGNOTICE("%s() SEQALL DUP %"PRIu64,
			  __func__, msgline->n_seqall);
	}
	/* It's a dup */
	return CMD_DUPSEQ;
}

static void setup_seq(K_ITEM *seqall, MSGLINE *msgline)
{
	K_ITEM *seqstt, *seqpid, *seqcmd;
	char *err = NULL, *st = NULL;
	size_t len, off;
	char reply[16] = "";
	size_t siz = sizeof(reply);

	msgline->n_seqall = atol(transfer_data(seqall));
	if ((seqstt = find_transfer(msgline->trf_root, SEQSTT)))
		msgline->n_seqstt = atol(transfer_data(seqstt));

	/* Ignore SEQSTTIGN sequence information
	 * This allows us to manually generate asicseer-pool data and send it
	 *  to asicseer-db using asicseer-pmsg - if SEQSTT == SEQSTTIGN
	 * SEQALL must exist but the value is ignored
	 * SEQPID and SEQcmd don't need to exist and are ignored */
	if (msgline->n_seqstt == SEQSTTIGN) {
		LOGWARNING("%s(): SEQIGN in %.42s...",
			   __func__, st = safe_text(msgline->msg));
		FREENULL(st);
		return;
	}

	if ((seqpid = find_transfer(msgline->trf_root, SEQPID)))
		msgline->n_seqpid = atol(transfer_data(seqpid));
	msgline->seqcmdnam = seqnam[ckdb_cmds[msgline->which_cmds].seq];
	if ((seqcmd = find_transfer(msgline->trf_root, msgline->seqcmdnam)))
		msgline->n_seqcmd = atol(transfer_data(seqcmd));

	/* Make one message with the initial seq missing/value problems ...
	 *  that should never happen if seqall is present */
	if (!seqstt || !seqpid || !seqcmd ||
	    (seqstt && msgline->n_seqstt < DATE_BEGIN) ||
	    (seqpid && msgline->n_seqpid <= 0)) {
		APPEND_REALLOC_INIT(err, off, len);
		APPEND_REALLOC(err, off, len, "SEQ ERROR: command ");
		APPEND_REALLOC(err, off, len, msgline->cmd);
		if (!seqstt || !seqpid || !seqcmd) {
			APPEND_REALLOC(err, off, len, " - missing");
			if (!seqstt)
				APPEND_REALLOC(err, off, len, BLANK SEQSTT);
			if (!seqpid)
				APPEND_REALLOC(err, off, len, BLANK SEQPID);
			if (!seqcmd) {
				APPEND_REALLOC(err, off, len, BLANK);
				APPEND_REALLOC(err, off, len,
						msgline->seqcmdnam);
			}
		}
		if (seqstt && msgline->n_seqstt < DATE_BEGIN) {
			APPEND_REALLOC(err, off, len, " - invalid "SEQSTT":'");
			st = safe_text_nonull(transfer_data(seqstt));
			APPEND_REALLOC(err, off, len, st);
			FREENULL(st);
			APPEND_REALLOC(err, off, len, "'");
		}
		if (seqpid && msgline->n_seqpid <= 0) {
			APPEND_REALLOC(err, off, len, " - invalid "SEQPID":'");
			st = safe_text_nonull(transfer_data(seqpid));
			APPEND_REALLOC(err, off, len, st);
			FREENULL(st);
			APPEND_REALLOC(err, off, len, "'");
		}
		APPEND_REALLOC(err, off, len, " - msg='");
		APPEND_REALLOC(err, off, len, msgline->msg);
		APPEND_REALLOC(err, off, len, "'");
		LOGMSGBUF(LOG_EMERG, err);
		FREENULL(err);

		return;
	}

	msgline->hasseq = true;

	msgline->in_code = optional_in(msgline->trf_root, CODETRF, 1, NULL,
					reply, siz);
	if (!(msgline->in_code)) {
		msgline->in_code = optional_in(msgline->trf_root, BYTRF,
						0, NULL, reply, siz);
		if (!msgline->in_code)
			msgline->in_code = in_empty;
	}
}

static enum cmd_values breakdown(K_ITEM **ml_item, char *buf, tv_t *now,
				 int seqentryflags, char *source, int access)
{
	char reply[1024] = "";
	TRANSFER *transfer;
	K_TREE_CTX ctx[1];
	MSGLINE *msgline;
	K_ITEM *t_item = NULL, *cd_item = NULL, *seqall;
	char *cmdptr, *idptr, *next, *eq, *end, *was;
	char *data = NULL, *st = NULL, *st2 = NULL, *ip = NULL;
	bool noid = false, intrans, anstr, wasend = false;
	uint64_t ram2 = 0;
	size_t siz;
	int i;

	siz = strlen(buf)+1;
	K_WLOCK(msgline_free);
	*ml_item = k_unlink_head_zero(msgline_free);
	msgline_free->ram += siz;
	K_WUNLOCK(msgline_free);
	DATA_MSGLINE(msgline, *ml_item);
	msgline->which_cmds = CMD_UNSET;
	copy_tv(&(msgline->now), now);
	copy_tv(&(msgline->cd), now); // default cd to 'now'
	DATE_ZERO(&(msgline->accepted));
	DATE_ZERO(&(msgline->broken));
	DATE_ZERO(&(msgline->processed));
	msgline->msg = strdup(buf);
	msgline->msgsiz = siz;
	msgline->seqentryflags = seqentryflags;

	cmdptr = strdup(buf);
	idptr = strchr(cmdptr, '.');
	if (!idptr || !*idptr)
		noid = true;
	else {
		*(idptr++) = '\0';
		data = strchr(idptr, '.');
		if (data)
			*(data++) = '\0';
		STRNCPY(msgline->id, idptr);
	}

	STRNCPY(msgline->cmd, cmdptr);
	for (msgline->which_cmds = 0;
	     ckdb_cmds[msgline->which_cmds].cmd_val != CMD_END;
	     (msgline->which_cmds)++) {
		if (strcasecmp(msgline->cmd,
				ckdb_cmds[msgline->which_cmds].cmd_str) == 0)
			break;
	}

	if (ckdb_cmds[msgline->which_cmds].cmd_val == CMD_END) {
		LOGQUE(buf, false);
		LOGERR("Listener received unknown command: '%.42s...",
			st2 = safe_text(buf));
		FREENULL(st2);
		goto nogood;
	}

	/* If you want to manually replay a log file with asicseer-pmsg,
	 *  you can ignore the access failed items by skipping items
	 *  that start with a capital, since all (currently) are lower case
	 *  however, command checks are case insensitive, so replaying
	 *   the file will try these commands, if they are present */
	if ((ckdb_cmds[msgline->which_cmds].access & access) == 0)
		buf[0] = toupper(buf[0]);

	if (ckdb_cmds[msgline->which_cmds].access & ACCESS_POOL)
		LOGQUE(buf, true);
	else
		LOGQUE(buf, false);

	if ((ckdb_cmds[msgline->which_cmds].access & access) == 0) {
		LOGERR("Command disallowed for %s: '%.42s...",
			source, st2 = safe_text(buf));
		FREENULL(st2);
		goto nogood;
	}

	if (noid) {
		if (ckdb_cmds[msgline->which_cmds].noid) {
			free(cmdptr);
			return ckdb_cmds[msgline->which_cmds].cmd_val;
		}

		LOGERR("Listener received invalid (noid) message: '%.42s...",
			st2 = safe_text(buf));
		FREENULL(st2);
		goto nogood;
	}

	// N.B. these aren't shared so they use _nolock, below
	msgline->trf_root = new_ktree_auto("MsgTrf", cmp_transfer, transfer_free);
	msgline->trf_store = k_new_store(transfer_free);
	next = data;
	if (next && strncmp(next, JSON_TRANSFER, JSON_TRANSFER_LEN) == 0) {
		// It's json
		next += JSON_TRANSFER_LEN;
		was = next;
		while (*next == ' ')
			next++;
		if (*next != JSON_BEGIN) {
			LOGERR("JSON_BEGIN '%c' was:%.32s... buf=%.32s...",
				JSON_BEGIN, st = safe_text(was),
				st2 = safe_text(buf));
			FREENULL(st);
			FREENULL(st2);
			goto nogood;
		}
		next++;
		// while we have a new quoted name
		while (*next == JSON_STR) {
			anstr = wasend = false;
			was = next;
			end = ++next;
			// look for the end quote
			while (*end && *end != JSON_STR) {
				if (*(end++) == JSON_ESC)
					end++;
			}
			if (!*end) {
				LOGERR("JSON name no trailing '%c' "
					"was:%.32s... buf=%.32s...",
					JSON_STR, st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
			}
			if (next == end) {
				LOGERR("JSON zero length name was:%.32s..."
					" buf=%.32s...",
					st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
			}
			// LOGERR of buf could be truncated
			*(end++) = '\0';
			K_WLOCK(transfer_free);
			t_item = k_unlink_head_zero(transfer_free);
			K_WUNLOCK(transfer_free);
			DATA_TRANSFER(transfer, t_item);
			STRNCPY(transfer->name, next);
			was = next = end;
			while (*next == ' ')
				next++;
			// we have a name, now expect a value after it
			if (*next != JSON_VALUE) {
				LOGERR("JSON_VALUE '%c' '%s' was:%.32s..."
					" buf=%.32s...",
					JSON_VALUE, transfer->name,
					st = safe_text(was),
					st2 = safe_text(buf));
				FREENULL(st);
				FREENULL(st2);
				goto nogood;
			}
			was = ++next;
			while (*next == ' ')
				next++;
			if (*next == JSON_STR) {
				anstr = true;
				end = ++next;
				// A quoted value must have a terminating quote
				while (*end && *end != JSON_STR) {
					if (*(end++) == JSON_ESC)
						end++;
				}
				if (!*end) {
					LOGERR("JSON '%s' value was:%.32s..."
						" buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
				}
				siz = end - next;
				end++;
			} else if (*next == JSON_ARRAY) {
				// Only merklehash for now
				if (strcmp(transfer->name, "merklehash")) {
					LOGERR("JSON '%s' can't be an array"
						" buf=%.32s...",
						transfer->name,
						st2 = safe_text(buf));
					FREENULL(st2);
					goto nogood;
				}
				end = ++next;
				/* No structure testing for now since we
				 *  don't expect merklehash to get it wrong,
				 *  and if it does, it will show up as some
				 *  other error anyway */
				while (*end && *end != JSON_ARRAY_END)
					end++;
				if (end < next+1) {
					LOGWARNING("JSON '%s' zero length array"
						" was:%.32s... buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
				}
				siz = end - next;
				end++;
			} else {
				end = next;
				// A non quoted value ends on SEP, END or space
				while (*end && *end != JSON_SEP &&
				       *end != JSON_END && *end != ' ') {
						end++;
				}
				if (!*end) {
					LOGERR("JSON '%s' value was:%.32s..."
						" buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
					goto nogood;
				}
				if (next == end) {
					LOGWARNING("JSON '%s' zero length value"
						" was:%.32s... buf=%.32s...",
						transfer->name,
						st = safe_text(was),
						st2 = safe_text(buf));
					FREENULL(st);
					FREENULL(st2);
				}
				siz = end - next;
			}
			intrans = false;
			for (i = 0; intransient_fields[i]; i++) {
				if (strcmp(transfer->name,
					   intransient_fields[i]) == 0) {
					intrans = true;
					/* If this is the last field & it wasn't
					 *  a string, it will wipe the closing
					 *  JSON_END - so flag it */
					if (!anstr && *(next + siz) == JSON_END)
						wasend = true;
					// This will affect 'was' if JSON_END is missing
					*(next + siz) = '\0';
					transfer->intransient =
						get_intransient_siz(transfer->name,
								    next, siz+1);
					transfer->mvalue = transfer->intransient->str;
					break;
				}
			}
			if (!intrans) {
				transfer->intransient = NULL;
				if (siz >= sizeof(transfer->svalue)) {
					transfer->msiz = siz+1;
					ram2 += siz+1;
					transfer->mvalue = malloc(siz+1);
					STRNCPYSIZ(transfer->mvalue, next,
						   siz+1);
				} else {
					STRNCPYSIZ(transfer->svalue, next,
						   siz+1);
					transfer->mvalue = transfer->svalue;
				}
			}
			add_to_ktree_nolock(msgline->trf_root, t_item);
			k_add_head_nolock(msgline->trf_store, t_item);
			t_item = NULL;

			// find the separator then move to the next name
			next = end;
			while (*next == ' ')
				next++;
			if (*next == JSON_SEP) {
				next++;
				while (*next == ' ')
					next++;
			}
		}
		/* If the last field was intransient and not a string, then it
		 *  wiped the closing JSON_END - but flagged that with wasend */
		if (*next != JSON_END && (!wasend)) {
			LOGERR("JSON_END '%c' was:%.32s... buf=%.32s...",
				JSON_END, st = safe_text(next),
				st2 = safe_text(buf));
			FREENULL(st);
			FREENULL(st2);
			goto nogood;
		}
	} else {
		while (next && *next) {
			data = next;
			next = strchr(data, FLDSEP);
			if (next)
				*(next++) = '\0';

			eq = strchr(data, '=');
			if (!eq)
				eq = EMPTY;
			else
				*(eq++) = '\0';

			K_WLOCK(transfer_free);
			t_item = k_unlink_head_zero(transfer_free);
			K_WUNLOCK(transfer_free);
			DATA_TRANSFER(transfer, t_item);
			STRNCPY(transfer->name, data);
			siz = strlen(eq) + 1;
			intrans = false;
			for (i = 0; intransient_fields[i]; i++) {
				if (strcmp(transfer->name,
					   intransient_fields[i]) == 0) {
					intrans = true;
					transfer->intransient =
						get_intransient_siz(transfer->name,
								    eq, siz);
					transfer->mvalue = transfer->intransient->str;
					break;
				}
			}
			if (!intrans) {
				transfer->intransient = NULL;
				if (siz > sizeof(transfer->svalue)) {
					ram2 += siz;
					transfer->msiz = siz;
					transfer->mvalue = malloc(siz);
					STRNCPYSIZ(transfer->mvalue, eq, siz);
				} else {
					STRNCPYSIZ(transfer->svalue, eq, siz);
					transfer->mvalue = transfer->svalue;
				}
			}

			// Discard duplicates
			if (find_in_ktree_nolock(msgline->trf_root, t_item, ctx)) {
				if (transfer->msiz)
					ram2 -= transfer->msiz;
				free_transfer_data(transfer);
				K_WLOCK(transfer_free);
				k_add_head(transfer_free, t_item);
				K_WUNLOCK(transfer_free);
			} else {
				if (strcmp(data, INETTRF) == 0)
					ip = transfer->mvalue;
				add_to_ktree_nolock(msgline->trf_root, t_item);
				k_add_head_nolock(msgline->trf_store, t_item);
			}
			t_item = NULL;
		}
	}

	if (ram2) {
		K_WLOCK(transfer_free);
		transfer_free->ram += ram2;
		K_WUNLOCK(transfer_free);
		ram2 = 0;
	}

	seqall = find_transfer(msgline->trf_root, SEQALL);
	if (ckdb_cmds[msgline->which_cmds].createdate) {
		cd_item = require_name(msgline->trf_root, CDTRF, 10, NULL,
					reply, sizeof(reply));
		if (!cd_item)
			goto nogood;

		DATA_TRANSFER(transfer, cd_item);
		txt_to_ctv(CDTRF, transfer->mvalue, &(msgline->cd),
			   sizeof(msgline->cd));
		if (msgline->cd.tv_sec == 0) {
			LOGERR("%s(): failed, %s has invalid "CDTRF" '%s'",
				__func__, cmdptr, transfer->mvalue);
			goto nogood;
		}
		if (confirm_check_createdate)
			check_createdate_ccl(msgline->cmd, &(msgline->cd));
		if (seqall) {
			if (!ignore_seq)
				setup_seq(seqall, msgline);
			free(cmdptr);
			return ckdb_cmds[msgline->which_cmds].cmd_val;
		} else {
			/* It's OK to load old data from the CCLs
			 *  but socket data must contain SEQALL ...
			 *  even in manually generated data */
			if (startup_complete) {
				LOGEMERG("%s(): *** "POOL_PROGNAME" needs upgrading? - "
					 "missing "SEQALL" from '%s' "POOL_PROGNAME" "
					 "data in '%s'",
					 __func__, cmdptr,
					 st = safe_text_nonull(buf));
				FREENULL(st);
			}
		}
	} else {
		/* Bug somewhere or createdate flag missing
		 * This ignores/discards all seq info */
		if (seqall) {
			LOGWARNING("%s(): msg '%s' shouldn't contain "SEQALL
				   " in '%s'",
				   __func__, cmdptr,
				   st = safe_text_nonull(buf));
			FREENULL(st);
		}
	}
	free(cmdptr);

	if (!seqall && ip) {
		bool alert, is_event;
		K_WLOCK(ips_free);
		alert = banned_ips(ip, now, &is_event);
		K_WUNLOCK(ips_free);
		if (alert)
			return is_event ? CMD_ALERTEVENT : CMD_ALERTOVENT;
	}

	return ckdb_cmds[msgline->which_cmds].cmd_val;
nogood:
	if (t_item || ram2) {
		K_WLOCK(transfer_free);
		if (t_item) {
			DATA_TRANSFER(transfer, t_item);
			if (transfer->msiz)
				ram2 -= transfer->msiz;
			free_transfer_data(transfer);
			k_add_head(transfer_free, t_item);
		}
		if (ram2)
			transfer_free->ram += ram2;
		K_WUNLOCK(transfer_free);
	}
	free(cmdptr);
	return CMD_REPLY;
}

struct breaker_setup {
	bool reload;
	int thread;
};

#define ISRELOAD 0
#define ISCMD 1

static void *breaker(void *arg)
{
	static pthread_t breaker_pt[2][THREAD_LIMIT];
	static struct breaker_setup breaker_setup[2][THREAD_LIMIT];
	static bool breaker_running[2][THREAD_LIMIT];
	static bool reload0 = false;
	static bool cmd0 = false;

	struct breaker_setup *setup;
	K_ITEM *bq_item = NULL, *cd_item = NULL;
	BREAKQUEUE *bq = NULL;
	MSGLINE *msgline = NULL;
	TRANSFER *cd_trf;
	char buf[128];
	bool reload, was_null, msg;
	int queue_sleep, queue_limit, count;
	uint64_t processed = 0;
	ts_t when, when_add;
	int i, typ, mythread, done, tot, ret;
	int breaker_delta = 0;
	ts_t last_sleep = { 0L, 0L };
	int last_sleep_ms = 0;
	bool do_sleep = false;

	setup = (struct breaker_setup *)(arg);
	mythread = setup->thread;
	if ((reload = setup->reload))
		typ = ISRELOAD;
	else
		typ = ISCMD;

	snprintf(buf, sizeof(buf), "db%s_%c%02d%s",
		 dbcode, reload ? 'r' : 'c', mythread, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	if (mythread == 0) {
		pthread_detach(pthread_self());

		for (i = 0; i < THREAD_LIMIT; i++) {
			breaker_setup[typ][i].thread = i;
			breaker_setup[typ][i].reload = reload;
			breaker_running[typ][i] = false;
		}
		breaker_running[typ][0] = true;

		if (reload) {
			reload0 = true;
			breaker_delta = reload_breakdown_threads - 1;
		} else {
			cmd0 = true;
			breaker_delta = cmd_breakdown_threads - 1;
		}

		LOGNOTICE("%s() %s initialised - delta %d",
			  __func__, reload ? "reload" : "cmd", breaker_delta);
	}

	if (reload) {
		queue_limit = reload_queue_limit;
		queue_sleep = RELOAD_QUEUE_SLEEP_MS;
		when_add.tv_sec = RELOAD_QUEUE_SLEEP_MS / 1000;
		when_add.tv_nsec = (RELOAD_QUEUE_SLEEP_MS % 1000) * 1000000;
	} else {
		queue_limit = CMD_QUEUE_LIMIT;
		queue_sleep = CMD_QUEUE_SLEEP_MS;
		when_add.tv_sec = CMD_QUEUE_SLEEP_MS / 1000;
		when_add.tv_nsec = (CMD_QUEUE_SLEEP_MS % 1000) * 1000000;
	}

	LOGNOTICE("%s() %s starting", __func__, buf);

	if (reload) {
		/* reload has to wait for the reload to start, however, also
		 *  check for startup_complete in case we miss the reload */
		while (!everyone_die && !reloading && !startup_complete)
			cksleep_ms(queue_sleep);
	}

	LOGNOTICE("%s() %s processing", __func__, buf);

	// The first one to start
	K_WLOCK(breakqueue_free);
	if (reload) {
		if (!break_reload_stt.tv_sec)
			setnow(&break_reload_stt);
	} else {
		if (!break_cmd_stt.tv_sec)
			setnow(&break_cmd_stt);
	}
	K_WUNLOCK(breakqueue_free);
	while (!everyone_die) {
		if (mythread && !breaker_running[typ][mythread])
			break;

		K_WLOCK(breakqueue_free);
		bq_item = NULL;
		was_null = false;
		if (breaker_sleep_stt.tv_sec > last_sleep.tv_sec) {
			copy_ts(&last_sleep, &breaker_sleep_stt);
			last_sleep_ms = breaker_sleep_ms;
			do_sleep = true;
		} else if (mythread == 0 && reload && reload_breakdown_threads_delta != 0) {
			breaker_delta = reload_breakdown_threads_delta;
			reload_breakdown_threads_delta = 0;
		} else if (mythread == 0 && !reload && cmd_breakdown_threads_delta != 0) {
			breaker_delta = cmd_breakdown_threads_delta;
			cmd_breakdown_threads_delta = 0;
		} else {
			if (reload)
				count = reload_done_breakqueue_store->count;
			else
				count = cmd_done_breakqueue_store->count;

			// Don't unlink if we are above the limit
			if (count <= queue_limit) {
				if (reload)
					bq_item = k_unlink_head(reload_breakqueue_store);
				else
					bq_item = k_unlink_head(cmd_breakqueue_store);
				if (!bq_item)
					was_null = true;
			}
			if (bq_item) {
				if (reload)
					break_reload_processed++;
				else
					break_cmd_processed++;
			}
		}
		K_WUNLOCK(breakqueue_free);

		if (do_sleep) {
			do_sleep = false;
			cksleep_ms_r(&last_sleep, last_sleep_ms);
			continue;
		}

		// TODO: deal with thread creation/shutdown failure
		if (breaker_delta != 0) {
			if (breaker_delta > 0) {
				// Add threads
				tot = 1;
				done = 0;
				for (i = 1; i < THREAD_LIMIT; i++) {
					if (!breaker_running[typ][i]) {
						if (breaker_delta > 0) {
							breaker_delta--;
							breaker_running[typ][i] = true;
							create_pthread(&(breaker_pt[typ][i]),
									breaker,
									&(breaker_setup[typ][i]));
							done++;
							tot++;
						}
					} else
						tot++;
				}
				LOGWARNING("%s() created %d %s thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__,
					   done,
					   reload ? "reload" : "cmd",
					   (done == 1) ? EMPTY : "s",
					   tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			} else {
				// Notify and wait for each to exit
				tot = 1;
				done = 0;
				for (i = THREAD_LIMIT - 1; i > 0; i--) {
					if (breaker_running[typ][i]) {
						if (breaker_delta < 0) {
							breaker_delta++;
							LOGNOTICE("%s() %s stopping %d",
								  __func__,
								  reload ? "reload" : "cmd",
								  i);
							breaker_running[typ][i] = false;
							join_pthread(breaker_pt[typ][i]);
							done++;
						} else
							tot++;
					}
				}
				LOGWARNING("%s() stopped %d %s thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__,
					   done,
					   reload ? "reload" : "cmd",
					   (done == 1) ? EMPTY : "s",
					   tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			}
			breaker_delta = 0;
			continue;
		}

		if (!bq_item) {
			// Is the queue empty and the reload completed?
			if (was_null && reload && !reloading)
				break;

			setnowts(&when);
			timeraddspec(&when, &when_add);

			if (reload) {
				mutex_lock(&bq_reload_waitlock);
				ret = cond_timedwait(&bq_reload_waitcond,
						     &bq_reload_waitlock, &when);
				if (ret == 0)
					bq_reload_wakes++;
				else if (errno == ETIMEDOUT)
					bq_reload_timeouts++;
				mutex_unlock(&bq_reload_waitlock);
			} else {
				mutex_lock(&bq_cmd_waitlock);
				ret = cond_timedwait(&bq_cmd_waitcond,
						     &bq_cmd_waitlock, &when);
				if (ret == 0)
					bq_cmd_wakes++;
				else if (errno == ETIMEDOUT)
					bq_cmd_timeouts++;
				mutex_unlock(&bq_cmd_waitlock);
			}
			continue;
		}

		processed++;

		DATA_BREAKQUEUE(bq, bq_item);

		if (reload) {
			bool matched = false;
			ck_wlock(&fpm_lock);
			if (first_pool_message &&
			    strcmp(first_pool_message, bq->buf) == 0) {
				matched = true;
				FREENULL(first_pool_message);
			}
			ck_wunlock(&fpm_lock);
			if (matched) {
				LOGERR("%s() reload "POOL_PROGNAME" queue match at line %"PRIu64,
					__func__, bq->count);
			}
		}

		bq->cmdnum = breakdown(&(bq->ml_item), bq->buf, &(bq->now),
					bq->seqentryflags, bq->source, bq->access);
		DATA_MSGLINE(msgline, bq->ml_item);
		setnow(&(msgline->broken));
		copy_tv(&(msgline->accepted), &(bq->accepted));
		if (SEQALL_LOG) {
			K_ITEM *seqall;
			if (bq->ml_item) {
				DATA_MSGLINE(msgline, bq->ml_item);
				if (msgline->trf_root) {
					seqall = find_transfer(msgline->trf_root, SEQALL);
					if (seqall) {
						LOGNOTICE("%s() SEQALL %s %s",
							  __func__,
							  reload ? "reload" : "cmd",
							  transfer_data(seqall));
					}
				}
			}
		}
		if (reload)
			cd_item = find_transfer(msgline->trf_root, CDTRF);
		K_WLOCK(breakqueue_free);
		if (reload) {
			if (cd_item) {
				DATA_TRANSFER(cd_trf, cd_item);
				STRNCPY(last_reload_cd, cd_trf->mvalue);
			}
			k_add_tail(reload_done_breakqueue_store, bq_item);
			mutex_lock(&process_reload_waitlock);
			process_reload_signals++;
			pthread_cond_signal(&process_reload_waitcond);
			mutex_unlock(&process_reload_waitlock);
		} else {
			// Prioritise workinfo processing
			if (bq->cmdnum == CMD_WORKINFO)
				k_add_head(cmd_done_breakqueue_store, bq_item);
			else
				k_add_tail(cmd_done_breakqueue_store, bq_item);
			mutex_lock(&process_socket_waitlock);
			process_socket_signals++;
			pthread_cond_signal(&process_socket_waitcond);
			mutex_unlock(&process_socket_waitlock);
		}
		K_WUNLOCK(breakqueue_free);
	}

	LOGNOTICE("%s() %s %s exiting, processed %"PRIu64,
		  __func__, buf, reload ? "reload" : "cmd", processed);

	// Get it now while the lock still exists, in case we need it
	K_RLOCK(breakqueue_free);
	// Not 100% exact since it could still increase, but close enough
	count = max_sockd_count;
	K_RUNLOCK(breakqueue_free);

	if (mythread == 0) {
		for (i = 1; i < THREAD_LIMIT; i++) {
			if (breaker_running[typ][i]) {
				breaker_running[typ][i] = false;
				LOGNOTICE("%s() %s waiting for %d",
					  __func__, buf, i);
				join_pthread(breaker_pt[typ][i]);
			}
		}

		if (reload)
			setnow(&break_reload_fin);

		msg = false;
		ck_wlock(&breakdown_lock);
		if (reload)
			reload0 = false;
		else
			cmd0 = false;

		if (reload0 == false && cmd0 == false) {
			breakdown_using_data = false;
			msg = true;
		}
		ck_wunlock(&breakdown_lock);

		if (msg) {
			LOGWARNING("%s() threads shut down - "
				   "max_sockd_count=%d",
				   __func__, count);
		}
	}

	return NULL;
}

static void check_orphans()
{
	K_TREE_CTX ctx[1];
	K_ITEM *b_item;
	BLOCKS *blocks = NULL;
	uint32_t currhi = 0;

	K_RLOCK(blocks_free);
	// Find the most recent block BLOCKS_NEW or BLOCKS_CONFIRM
	b_item = last_in_ktree(blocks_root, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (!blocks->ignore &&
		    CURRENT(&(blocks->expirydate)) &&
		    (blocks->confirmed[0] == BLOCKS_NEW ||
		     blocks->confirmed[0] == BLOCKS_CONFIRM))
			break;
		b_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);

	// None
	if (!b_item)
		return;

	K_RLOCK(workinfo_free);
	if (workinfo_current) {
		WORKINFO *wic;
		DATA_WORKINFO(wic, workinfo_current);
		currhi = wic->height - 1;
	}
	K_RUNLOCK(workinfo_free);

	LOGDEBUG("%s() currhi=%"PRIu32" block=%"PRIu32,
		 __func__, currhi, blocks->height);
	// Keep checking for 6 blocks
	if (currhi && (currhi - blocks->height) < 6)
		btc_orphancheck(blocks);
}

static void check_blocks()
{
	K_TREE_CTX ctx[1];
	K_ITEM *b_item;
	BLOCKS *blocks;

	K_RLOCK(blocks_free);
	/* Find the oldest block BLOCKS_NEW or BLOCKS_CONFIRM
	 * ... that's summarised, so processing order is correct */
	b_item = first_in_ktree(blocks_root, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (!blocks->ignore &&
		    CURRENT(&(blocks->expirydate)) &&
		    blocks->statsconfirmed[0] != BLOCKS_STATSPENDING &&
		    (blocks->confirmed[0] == BLOCKS_NEW ||
		     blocks->confirmed[0] == BLOCKS_CONFIRM))
			break;
		b_item = next_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);

	// None
	if (!b_item)
		return;

	if (btc_orphancheck(blocks))
		btc_blockstatus(blocks);
}

static void pplns_block(BLOCKS *blocks)
{
	if (sharesummary_marks_limit) {
		LOGEMERG("%s() sharesummary marks limit, block %"PRId32" payout skipped",
			 __func__, blocks->height);
		return;
	}

	// Give it a sec after the block summarisation
	sleep(1);

	process_pplns(blocks->height, blocks->blockhash, NULL);
}

static void summarise_blocks()
{
	K_ITEM *b_item, *b_prev, *wi_item, ss_look, *ss_item;
	K_ITEM wm_look, *wm_item, ms_look, *ms_item;
	K_TREE_CTX ctx[1], ss_ctx[1], ms_ctx[1];
	double diffacc, diffinv, shareacc, shareinv;
	tv_t now, elapsed_start, elapsed_finish;
	int64_t elapsed, wi_start, wi_finish;
	BLOCKS *blocks = NULL, *prev_blocks;
	WORKINFO *prev_workinfo;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKMARKERS lookworkmarkers, *workmarkers;
	MARKERSUMMARY lookmarkersummary, *markersummary;
	bool has_ss = false, has_ms = false, ok;
	int32_t hi, prev_hi;

	setnow(&now);

	K_RLOCK(blocks_free);
	// Find the oldest, stats pending, not new, block
	b_item = first_in_ktree(blocks_root, ctx);
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate)) &&
		    blocks->statsconfirmed[0] == BLOCKS_STATSPENDING &&
		    blocks->confirmed[0] != BLOCKS_NEW)
			break;
		b_item = next_in_ktree(ctx);
	}
	K_RUNLOCK(blocks_free);

	// None
	if (!b_item)
		return;

	wi_finish = blocks->workinfoid;
	hi = 0;
	K_RLOCK(workinfo_free);
	if (workinfo_current) {
		WORKINFO *wic;
		DATA_WORKINFO(wic, workinfo_current);
		hi = wic->height;
	}
	K_RUNLOCK(workinfo_free);

	// Wait at least for the (badly named) '2nd' confirm
	if (hi == 0 || blocks->height >= (hi - 1))
		return;

	diffacc = diffinv = shareacc = shareinv = 0;
	elapsed = 0;
	K_RLOCK(blocks_free);
	b_prev = find_prev_blocks(blocks->height, NULL);
	K_RUNLOCK(blocks_free);
	if (!b_prev) {
		wi_start = 0;
		DATE_ZERO(&elapsed_start);
		prev_hi = 0;
	} else {
		DATA_BLOCKS(prev_blocks, b_prev);
		wi_start = prev_blocks->workinfoid;
		wi_item = find_workinfo(wi_start, NULL);
		if (!wi_item) {
			// This will repeat until fixed ...
			LOGERR("%s() block %d, but prev %d wid "
				"%"PRId64" is missing",
				__func__, blocks->height,
				prev_blocks->height,
				prev_blocks->workinfoid);
			return;
		}
		DATA_WORKINFO(prev_workinfo, wi_item);
		copy_tv(&elapsed_start, &(prev_workinfo->createdate));
		prev_hi = prev_blocks->height;
	}
	DATE_ZERO(&elapsed_finish);

	// Add up the sharesummaries, abort if any SUMMARY_NEW
	looksharesummary.workinfoid = wi_finish;
	looksharesummary.userid = MAXID;
	looksharesummary.in_workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);

	// We don't want them in an indeterminate state due to pplns
	K_KLONGWLOCK(process_pplns_free);

	// For now, just lock all 3
	K_RLOCK(sharesummary_free);
	K_RLOCK(markersummary_free);
	K_RLOCK(workmarkers_free);

	ss_item = find_before_in_ktree(sharesummary_workinfoid_root, &ss_look,
					ss_ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	while (ss_item && sharesummary->workinfoid > wi_start) {
		if (sharesummary->complete[0] == SUMMARY_NEW) {
			// Not aged yet
			K_RUNLOCK(workmarkers_free);
			K_RUNLOCK(markersummary_free);
			K_RUNLOCK(sharesummary_free);

			K_WUNLOCK(process_pplns_free);
			return;
		}
		has_ss = true;
		if (sharesummary->diffacc > 0) {
			if (elapsed_start.tv_sec == 0 ||
			    !tv_newer(&elapsed_start, &(sharesummary->firstshareacc))) {
				copy_tv(&elapsed_start, &(sharesummary->firstshareacc));
			}
			if (tv_newer(&elapsed_finish, &(sharesummary->lastshareacc)))
				copy_tv(&elapsed_finish, &(sharesummary->lastshareacc));
		}

		diffacc += sharesummary->diffacc;
		diffinv += sharesummary->diffsta + sharesummary->diffdup +
			   sharesummary->diffhi + sharesummary-> diffrej;
		shareacc += sharesummary->shareacc;
		shareinv += sharesummary->sharesta + sharesummary->sharedup +
			    sharesummary->sharehi + sharesummary-> sharerej;

		ss_item = prev_in_ktree(ss_ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}

	// Add in the workmarkers...markersummaries
	lookworkmarkers.expirydate.tv_sec = default_expiry.tv_sec;
	lookworkmarkers.expirydate.tv_usec = default_expiry.tv_usec;
	lookworkmarkers.workinfoidend = wi_finish+1;
	INIT_WORKMARKERS(&wm_look);
	wm_look.data = (void *)(&lookworkmarkers);
	wm_item = find_before_in_ktree(workmarkers_workinfoid_root, &wm_look,
				       ctx);
	DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	while (wm_item &&
	       CURRENT(&(workmarkers->expirydate)) &&
	       workmarkers->workinfoidend > wi_start) {

		if (workmarkers->workinfoidstart < wi_start) {
			LOGEMERG("%s() workmarkers %"PRId64"/%s/%"PRId64
				 "/%"PRId64"/%s/%s crosses block "
				 "%"PRId32"/%"PRId64" boundary",
				 __func__, workmarkers->markerid,
				 workmarkers->in_poolinstance,
				 workmarkers->workinfoidstart,
				 workmarkers->workinfoidend,
				 workmarkers->description,
				 workmarkers->status, hi, wi_finish);
		}
		if (WMPROCESSED(workmarkers->status)) {
			lookmarkersummary.markerid = workmarkers->markerid;
			lookmarkersummary.userid = MAXID;
			lookmarkersummary.in_workername = EMPTY;
			INIT_MARKERSUMMARY(&ms_look);
			ms_look.data = (void *)(&lookmarkersummary);
			ms_item = find_before_in_ktree(markersummary_root, &ms_look,
						       ms_ctx);
			DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
			while (ms_item && markersummary->markerid == workmarkers->markerid) {
				has_ms = true;
				if (markersummary->diffacc > 0) {
					if (elapsed_start.tv_sec == 0 ||
					    !tv_newer(&elapsed_start, &(markersummary->firstshareacc))) {
						copy_tv(&elapsed_start, &(markersummary->firstshareacc));
					}
					if (tv_newer(&elapsed_finish, &(markersummary->lastshareacc)))
						copy_tv(&elapsed_finish, &(markersummary->lastshareacc));
				}

				diffacc += markersummary->diffacc;
				diffinv += markersummary->diffsta + markersummary->diffdup +
					   markersummary->diffhi + markersummary-> diffrej;
				shareacc += markersummary->shareacc;
				shareinv += markersummary->sharesta + markersummary->sharedup +
					    markersummary->sharehi + markersummary-> sharerej;

				ms_item = prev_in_ktree(ms_ctx);
				DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
			}
		}
		wm_item = prev_in_ktree(ctx);
		DATA_WORKMARKERS_NULL(workmarkers, wm_item);
	}

	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(sharesummary_free);

	K_WUNLOCK(process_pplns_free);

	if (!has_ss && !has_ms) {
		// This will repeat each call here until fixed ...
		LOGERR("%s() block %d, after block %d, no sharesummaries "
			"or markersummaries after %"PRId64" up to %"PRId64,
			__func__, blocks->height,
			prev_hi, wi_start, wi_finish);
		return;
	}

	elapsed = (int64_t)(tvdiff(&elapsed_finish, &elapsed_start) + 0.5);
	ok = blocks_stats(NULL, blocks->height, blocks->blockhash,
			  diffacc, diffinv, shareacc, shareinv, elapsed,
			  by_default, (char *)__func__, inet_default, &now);

	if (ok) {
		LOGWARNING("%s() block %d, stats confirmed "
			   "%0.f/%.0f/%.0f/%.0f/%"PRId64,
			   __func__, blocks->height,
			   diffacc, diffinv, shareacc, shareinv, elapsed);

		// Now the summarisation is confirmed, generate the payout data
		if (genpayout_auto)
			pplns_block(blocks);
		else {
			LOGWARNING("%s() Auto payout generation disabled",
				   __func__);
		}
	} else {
		LOGERR("%s() block %d, failed to confirm stats",
			__func__, blocks->height);
	}
}

static void *summariser(__maybe_unused void *arg)
{
	bool orphan_check = false;
	char buf[128];
	int i;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_%s", dbcode, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	/* Don't do any summarisation until the reload queue completes coz:
	 * 1) It locks/accesses a lot of data - workinfo/markersummary that
	 *    can slow down the reload
	 * 2) If you stop and restart asicseer-db this wont affect the restart point
	 *    Thus it's OK to do it later
	 * 3) It does I/O to bitcoind which is slow ...
	 * 4) It triggers the payout generation which also accesses a lot of
	 *    data - workinfo/markersummary - but it wont affect a later
	 *    restart point if it hasn't been done. Thus it's OK to do it later
	 */
	while (!everyone_die && !reload_queue_complete)
		cksleep_ms(42);

	if (!everyone_die) {
		LOGWARNING("%s() Start processing...", __func__);
		summariser_using_data = true;
	}

	while (!everyone_die) {
		for (i = 0; i < 5; i++) {
			if (!everyone_die)
				sleep(1);
		}

		if (everyone_die)
			break;
		else {
			orphan_check = !orphan_check;
			// Check every 2nd time
			if (orphan_check)
				check_orphans();
		}

		if (!everyone_die)
			sleep(1);

		if (everyone_die)
			break;
		else
			check_blocks();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else
			summarise_blocks();

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
	}

	summariser_using_data = false;

	return NULL;
}

#define SHIFT_WORDS 26
static char *shift_words[] =
{
	"ako",
	"belldandy",
	"charlotte",
	"darkchii",
	"elen",
	"frey",
	"gin",
	"hitagi",
	"ichiko",
	"juvia",
	"kosaki",
	"lucy",
	"mutsumi",
	"nodoka",
	"origami",
	"paru",
	"quinn",
	"rem",
	"sena",
	"tenshi",
	"ur",
	"valentina",
	"winry",
	"xenovia",
	"yuno",
	"zekken"
};

#define ASSERT4(condition) __maybe_unused static char shift_words_must_have_ ## SHIFT_WORDS ## _words[(condition)?1:-1]
ASSERT4((sizeof(shift_words) == (sizeof(char *) * SHIFT_WORDS)));

// Number of workinfoids per shift
#define WID_PER_SHIFT 100

// A diff change will end the current shift if it occurs after this block
#define SHIFT_DIFF_BLOCK 376500

// optioncontrol name to override the SHIFT_DIFF_BLOCK value
#define SHIFT_DIFF_BLOCK_STR "ShiftDiffBlock"

#define BLOCK_HALVING 210000

static void make_a_shift_mark()
{
	K_TREE_CTX ss_ctx[1], m_ctx[1], wi_ctx[1], b_ctx[1];
	K_ITEM *ss_item = NULL, *m_item = NULL, *m_sh_item = NULL, *wi_item;
	K_ITEM *b_item = NULL;
	K_ITEM wi_look, ss_look;
	SHARESUMMARY *sharesummary, looksharesummary;
	WORKINFO *workinfo = NULL, lookworkinfo;
	BLOCKS *blocks = NULL;
	MARKS *marks = NULL, *sh_marks = NULL;
	int64_t ss_age_wid, last_marks_wid, marks_wid, prev_wid;
	int64_t shiftdiffblock = SHIFT_DIFF_BLOCK;
	int32_t prev_height;
	char wi_bits[TXT_SML+1];
	bool was_block = false, ok, oc_look = true;
	char cd_buf[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];
	int used_wid;

	/* If there are no CURRENT marks, make the first one by
	 *  finding the first CURRENT workinfo and use that
	 *  to create a MARKTYPE_OTHER_BEGIN for the pool
	 * This will keep being checked when the pool first starts
	 *  until the first workinfo is created, but once the first
	 *  marks has been created it will skip over the if code
	 *  forever after that */
	K_RLOCK(marks_free);
	m_item = last_in_ktree(marks_root, m_ctx);
	K_RUNLOCK(marks_free);
	DATA_MARKS_NULL(marks, m_item);
	// Mark sorting means all CURRENT will be on the end
	if (!m_item || !CURRENT(&(marks->expirydate))) {
		K_RLOCK(workinfo_free);
		wi_item = first_in_ktree(workinfo_root, wi_ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		if (!wi_item) {
			K_RUNLOCK(workinfo_free);
			LOGWARNING("%s() "DB_PROGNAME" workinfo:'%s' marks:'%s' ..."
				   " start "POOL_PROGNAME"!", __func__,
				   "none", m_item ? "expired" : "none");
			return;
		}
		while (wi_item && !CURRENT(&(workinfo->expirydate))) {
			wi_item = next_in_ktree(wi_ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		if (!wi_item) {
			K_RUNLOCK(workinfo_free);
			LOGWARNING("%s() "DB_PROGNAME" workinfo:'%s' marks:'%s' ..."
				   " start "POOL_PROGNAME"!", __func__,
				   "expired", m_item ? "expired" : "none");
			return;
		}
		K_RUNLOCK(workinfo_free);
		char description[TXT_BIG+1];
		tv_t now;
		ok = marks_description(description, sizeof(description),
					MARKTYPE_OTHER_BEGIN_STR, 0, NULL,
					"Pool Start");
		if (!ok)
			return;

		setnow(&now);
		ok = marks_process(NULL, true, workinfo->in_poolinstance,
				   workinfo->workinfoid, description, EMPTY,
				   MARKTYPE_OTHER_BEGIN_STR, MARK_USED_STR,
				   (char *)by_default, (char *)__func__,
				   (char *)inet_default, &now, NULL);
		if (ok) {
			LOGWARNING("%s() FIRST mark %"PRId64"/%s/%s/%s/",
				   __func__, workinfo->workinfoid,
				   MARKTYPE_OTHER_BEGIN_STR, MARK_USED_STR,
				   description);
		}
		return;
	}

	/* Find the last !new sharesummary workinfoid
	 * If the shift needs to go beyond this, then it's not ready yet
	 * keysharesummaries will have the same workinfoid,
	 *  so don't need checking */
	ss_age_wid = 0;
	K_RLOCK(sharesummary_free);
	ss_item = first_in_ktree(sharesummary_workinfoid_root, ss_ctx);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->complete[0] == SUMMARY_NEW)
			break;
		if (ss_age_wid < sharesummary->workinfoid)
			ss_age_wid = sharesummary->workinfoid;
		ss_item = next_in_ktree(ss_ctx);
	}
	K_RUNLOCK(sharesummary_free);
	if (ss_item) {
		tv_to_buf(&(sharesummary->lastshareacc), cd_buf, sizeof(cd_buf));
		tv_to_buf(&(sharesummary->lastshare), cd_buf2, sizeof(cd_buf2));
		LOGDEBUG("%s() last sharesummary %s/%s/%"PRId64"/%s/%s",
			 __func__, sharesummary->complete,
			 sharesummary->in_workername,
			 ss_age_wid, cd_buf, cd_buf2);
	}
	LOGDEBUG("%s() age sharesummary limit wid %"PRId64, __func__, ss_age_wid);

	// Find the last CURRENT mark, the shift starts after this
	K_RLOCK(marks_free);
	m_item = last_in_ktree(marks_root, m_ctx);
	if (m_item) {
		DATA_MARKS(marks, m_item);
		if (!CURRENT(&(marks->expirydate))) {
			/* This means there are no CURRENT marks
			 *  since they are sorted all CURRENT last */
			m_item = NULL;
		} else {
			wi_item = find_workinfo(marks->workinfoid, wi_ctx);
			if (!wi_item) {
				K_RUNLOCK(marks_free);
				LOGEMERG("%s() ERR last mark "
					 "%"PRId64"/%s/%s/%s/%s"
					 " workinfoid is missing!",
					 __func__, marks->workinfoid,
					 marks_marktype(marks->marktype),
					 marks->status, marks->description,
					 marks->extra);
				return;
			}
			/* Find the last shift so we can determine
			 *  the next shift description
			 * This will normally be the last mark,
			 *  but manual marks may change that */
			m_sh_item = m_item;
			while (m_sh_item) {
				DATA_MARKS(sh_marks, m_sh_item);
				if (!CURRENT(&(sh_marks->expirydate))) {
					m_sh_item = NULL;
					break;
				}
				if (sh_marks->marktype[0] == MARKTYPE_SHIFT_END ||
				    sh_marks->marktype[0] == MARKTYPE_SHIFT_BEGIN)
					break;
				m_sh_item = prev_in_ktree(m_ctx);
			}
			if (m_sh_item) {
				wi_item = find_workinfo(sh_marks->workinfoid, wi_ctx);
				if (!wi_item) {
					K_RUNLOCK(marks_free);
					LOGEMERG("%s() ERR last shift mark "
						 "%"PRId64"/%s/%s/%s/%s "
						 "workinfoid is missing!",
						 __func__,
						 sh_marks->workinfoid,
						 marks_marktype(sh_marks->marktype),
						 sh_marks->status,
						 sh_marks->description,
						 sh_marks->extra);
					return;
				}
			}
		}
	}
	K_RUNLOCK(marks_free);

	if (m_item) {
		last_marks_wid = marks->workinfoid;
		LOGDEBUG("%s() last mark %"PRId64"/%s/%s/%s/%s",
			 __func__, marks->workinfoid,
			 marks_marktype(marks->marktype),
			 marks->status, marks->description,
			 marks->extra);
	} else {
		last_marks_wid = 0;
		LOGDEBUG("%s() no last mark", __func__);
	}

	if (m_sh_item) {
		if (m_sh_item == m_item)
			LOGDEBUG("%s() last shift mark = last mark", __func__);
		else {
			LOGDEBUG("%s() last shift mark %"PRId64"/%s/%s/%s/%s",
				 __func__, sh_marks->workinfoid,
				 marks_marktype(sh_marks->marktype),
				 sh_marks->status, sh_marks->description,
				 sh_marks->extra);
		}
	} else
		LOGDEBUG("%s() no last shift mark", __func__);

	if (m_item) {
		/* First block after the last mark
		 * Shift must stop at or before this
		 * N.B. any block, even 'New' */
		K_RLOCK(blocks_free);
		b_item = first_in_ktree(blocks_root, b_ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate)) &&
			    blocks->workinfoid > marks->workinfoid)
				break;
			b_item = next_in_ktree(b_ctx);
		}
		K_RUNLOCK(blocks_free);
	}

	if (b_item) {
		tv_to_buf(&(blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGDEBUG("%s() block after last mark %"PRId32"/%"PRId64"/%s",
			 __func__, blocks->height, blocks->workinfoid,
			 blocks_confirmed(blocks->confirmed));
	} else {
		if (!m_item)
			LOGDEBUG("%s() no last mark = no last block", __func__);
		else
			LOGDEBUG("%s() no block since last mark", __func__);
	}

	INIT_WORKINFO(&wi_look);
	INIT_SHARESUMMARY(&ss_look);

	// Start from the workinfoid after the last mark
	lookworkinfo.workinfoid = last_marks_wid;
	lookworkinfo.expirydate.tv_sec = default_expiry.tv_sec;
	lookworkinfo.expirydate.tv_usec = default_expiry.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	K_RLOCK(workinfo_free);
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, wi_ctx);
	K_RUNLOCK(workinfo_free);
	marks_wid = 0;
	used_wid = 0;
	prev_wid = 0;
	wi_bits[0] = '\0';
	prev_height = 0;
	while (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		if (CURRENT(&(workinfo->expirydate))) {
			/* Did we meet or exceed the !new ss limit?
			 *  for now limit it to BEFORE ss_age_wid
			 * This will mean the shifts are created ~30s later */
			if (workinfo->workinfoid >= ss_age_wid) {
				LOGDEBUG("%s() not enough aged workinfos (%d)",
					 __func__, used_wid);
				return;
			}
			if (wi_bits[0] == '\0')
				STRNCPY(wi_bits, workinfo->in_bits);
			else {
				/* Make sure you set the SHIFT_DIFF_BLOCK_STR
				 *  optioncontrol if you changed ckdb to V1.323
				 *  before the diff change, before the block=
				 *  SHIFT_DIFF_BLOCK default value
				 * This however, would only affect a reload
				 *  after that if the reload crossed the
				 *  previous diff change and the shifts had not
				 *  already been stored in the DB (i.e. next to
				 *  zero probability)
				 * However a DB rollback and reload across that
				 *  diff change would be affected */
				if (oc_look) {
					shiftdiffblock = sys_setting(SHIFT_DIFF_BLOCK_STR,
								     SHIFT_DIFF_BLOCK,
								     &date_eot);
					oc_look = false;
				}
				/* Did difficulty change?
				 * Stop at the last workinfo, before the diff
				 *  changed */
				if (strcmp(wi_bits, workinfo->in_bits) != 0) {
					if (workinfo->height > (int32_t)shiftdiffblock) {
						LOGDEBUG("%s() OK shift stops for a diff"
							 " change '%s->%s' %"PRId64
							 "->%"PRId64" height %"PRId32
							 " limit %"PRId64,
							 __func__, wi_bits,
							 workinfo->in_bits, prev_wid,
							 workinfo->workinfoid,
							 workinfo->height,
							 shiftdiffblock);
						marks_wid = prev_wid;
						break;
					}
				}
				// Halving? Stop at the last workinfo before it
				if (workinfo->height != prev_height &&
				    (workinfo->height % BLOCK_HALVING) == 0) {
					LOGDEBUG("%s() OK shift stops for a "
						 "halving wid %"PRId64
						 "->%"PRId64" height %"PRId32
						 " halving every %d",
						 __func__, prev_wid,
						 workinfo->workinfoid,
						 workinfo->height,
						 BLOCK_HALVING);
					marks_wid = prev_wid;
					break;
				}
			}
			/* Did we find a pool restart? i.e. a wid skip
			 * These will usually be a much larger jump,
			 *  however the pool should never skip any */
			if (prev_wid > 0 &&
			    (workinfo->workinfoid - prev_wid) > 6) {
				marks_wid = prev_wid;
				LOGDEBUG("%s() OK shift stops at pool restart"
					 " count %d(%d) workinfoid %"PRId64
					 " next wid %"PRId64,
					 __func__, used_wid, WID_PER_SHIFT,
					 marks_wid, workinfo->workinfoid);
				break;
			}
			prev_wid = workinfo->workinfoid;
			prev_height = workinfo->height;
			// Did we hit the next block?
			if (b_item && workinfo->workinfoid == blocks->workinfoid) {
				LOGDEBUG("%s() OK shift stops at block limit",
					 __func__);
				marks_wid = workinfo->workinfoid;
				was_block = true;
				break;
			}
			/* Does workinfo have (aged) sharesummaries?
			 * keysharesummary will be the same,
			 *  so doesn't need checking (and doesn't matter) */
			looksharesummary.workinfoid = workinfo->workinfoid;
			looksharesummary.userid = MAXID;
			looksharesummary.in_workername = EMPTY;
			ss_look.data = (void *)(&looksharesummary);
			K_RLOCK(sharesummary_free);
			ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
							&ss_look, ss_ctx);
			K_RUNLOCK(sharesummary_free);
			DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
			if (ss_item &&
			    sharesummary->workinfoid == workinfo->workinfoid) {
				/* Not aged = shift not complete
				 * Though, it shouldn't happen */
				if (sharesummary->complete[0] == SUMMARY_NEW) {
					tv_to_buf(&(sharesummary->lastshareacc),
						  cd_buf, sizeof(cd_buf));
					tv_to_buf(&(sharesummary->lastshare),
						  cd_buf2, sizeof(cd_buf2));
					LOGEMERG("%s() ERR unaged sharesummary "
						 "%s/%s/%"PRId64"/%s/%s",
						 __func__, sharesummary->complete,
						 sharesummary->in_workername,
						 sharesummary->workinfoid,
						 cd_buf, cd_buf2);
					return;
				}
			}
			if (++used_wid >= WID_PER_SHIFT) {
				// We've got a full shift
				marks_wid = workinfo->workinfoid;
				LOGDEBUG("%s() OK shift stops at count"
					 " %d(%d) workinfoid %"PRId64,
					 __func__, used_wid,
					 WID_PER_SHIFT, marks_wid);
				break;
			}
		}
		K_RLOCK(workinfo_free);
		wi_item = next_in_ktree(wi_ctx);
		K_RUNLOCK(workinfo_free);
	}

	// Create the shift mark
	if (marks_wid) {
		char shift[TXT_BIG+1] = { '\0' };
		char des[TXT_BIG+1] = { '\0' };
		char extra[TXT_BIG+1] = { '\0' };
		char shifttype[TXT_FLAG+1] = { MARKTYPE_SHIFT_END, '\0' };
		char blocktype[TXT_FLAG+1] = { MARKTYPE_BLOCK, '\0' };
		char status[TXT_FLAG+1] = { MARK_READY, '\0' };
		int word = 0;
		char *invalid = NULL, *code, *space;
		const char *skip = NULL;
		size_t len;
		tv_t now;

		/* Shift description is shiftcode(createdate)
		 *  + a space + shift_words
		 * shift_words is incremented every shift */
		if (m_sh_item) {
			skip = NULL;
			switch (sh_marks->marktype[0]) {
				case MARKTYPE_BLOCK:
				case MARKTYPE_PPLNS:
				case MARKTYPE_OTHER_BEGIN:
				case MARKTYPE_OTHER_FINISH:
					// Reset
					word = 0;
					break;
				case MARKTYPE_SHIFT_END:
					skip = marktype_shift_end_skip;
					break;
				case MARKTYPE_SHIFT_BEGIN:
					skip = marktype_shift_begin_skip;
					break;
				default:
					invalid = "unkown marktype";
					break;
			}
			if (skip) {
				len = strlen(skip);
				if (strncmp(sh_marks->description, skip, len) != 0)
					invalid = "inv des (skip)";
				else {
					code = sh_marks->description + len;
					space = strchr(code, ' ');
					if (!space)
						invalid = "inv des (space)";
					else {
						space++;
						if (*space < 'a' || *space > 'z')
							invalid = "inv des (a-z)";
						else
							word = (*space - 'a' + 1) % SHIFT_WORDS;
					}
				}
			}
			if (invalid) {
				LOGEMERG("%s() ERR %s mark %"PRId64"/%s/%s/%s",
					 __func__, invalid,
					 sh_marks->workinfoid,
					 marks_marktype(sh_marks->marktype),
					 sh_marks->status,
					 sh_marks->description);
				return;
			}
		}
		snprintf(shift, sizeof(shift), "%s %s",
			 shiftcode(&(workinfo->createdate)),
			 shift_words[word]);

		LOGDEBUG("%s() shift='%s'", __func__, shift);

		if (!marks_description(des, sizeof(des), shifttype, 0, shift, NULL))
			return;

		LOGDEBUG("%s() des='%s'", __func__, des);

		if (was_block) {
			// Put the block description in extra
			if (!marks_description(extra, sizeof(extra), blocktype,
						blocks->height, NULL, NULL))
				return;

			LOGDEBUG("%s() extra='%s'", __func__, extra);
		}

		setnow(&now);
		ok = marks_process(NULL, true, workinfo->in_poolinstance,
				   marks_wid, des, extra, shifttype, status,
				   (char *)by_default, (char *)__func__,
				   (char *)inet_default, &now, NULL);

		if (ok) {
			LOGWARNING("%s() mark %"PRId64"/%s/%s/%s/%s/",
				   __func__, marks_wid, shifttype, status,
				   des, extra);
		}
	} else
		LOGDEBUG("%s() no marks wid", __func__);
}

static void make_a_workmarker()
{
	char msg[1024] = "";
	tv_t now;
	bool ok;

	setnow(&now);
	ok = workmarkers_generate(NULL, msg, sizeof(msg),
				  (char *)by_default, (char *)__func__,
				  (char *)inet_default, &now, NULL, false);
	if (!ok)
		LOGERR("%s() ERR %s", __func__, msg);
}

static void *marker(__maybe_unused void *arg)
{
	char buf[128];
	int i;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_%s", dbcode, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	/* We want this to start during the CCL reload so that if we run a
	 *  large reload and it fails at some point, the next reload will not
	 *  always have to go back to the same reload point as before due to
	 *  no new workmarkers being completed/processed
	 * However, don't start during the first N reload files so that a
	 *  normal asicseer-db restart reload won't slow down */
	while (!everyone_die && !reloaded_N_files && !reload_queue_complete)
		cksleep_ms(42);

	if (sharesummary_marks_limit) {
		LOGEMERG("%s() ALERT: dbload -w disables shift processing",
			 __func__);
		return NULL;
	}

	if (!everyone_die) {
		LOGWARNING("%s() Start processing...", __func__);
		marker_using_data = true;
	}

	while (!everyone_die) {
		for (i = 0; i < 5; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_a_shift_mark();
		}

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_a_workmarker();
		}

		for (i = 0; i < 4; i++) {
			if (!everyone_die)
				sleep(1);
		}
		if (everyone_die)
			break;
		else {
			if (markersummary_auto)
				make_markersummaries(false, NULL, NULL, NULL, NULL, NULL);
		}
	}

	marker_using_data = false;

	return NULL;
}

static void *logger(__maybe_unused void *arg)
{
	K_ITEM *lq_item;
	LOGQUEUE *lq;
	char buf[128];
	tv_t now, then;
	int count;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_%s", dbcode, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	LOGWARNING("%s() Start processing...", __func__);
	logger_using_data = true;

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstart.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);

	while (!everyone_die) {
		K_WLOCK(logqueue_free);
		lq_item = k_unlink_head(logqueue_store);
		K_WUNLOCK(logqueue_free);
		while (lq_item) {
			DATA_LOGQUEUE(lq, lq_item);
			if (lq->db) {
				if (db_logger)
					LOGFILE(lq->msg, logname_db);
			} else
				LOGFILE(lq->msg, logname_io);
			FREENULL(lq->msg);

			K_WLOCK(logqueue_free);
			k_add_head(logqueue_free, lq_item);
			if (!everyone_die)
				lq_item = k_unlink_head(logqueue_store);
			else
				lq_item = NULL;
			K_WUNLOCK(logqueue_free);
		}
		cksleep_ms(42);
	}

	K_WLOCK(logqueue_free);
	count = logqueue_store->count;
	setnow(&now);
	snprintf(buf, sizeof(buf), "logstopping.%d.%ld,%ld",
				   count, now.tv_sec, now.tv_usec);
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);
	if (count)
		LOGERR("%s", buf);
	lq_item = STORE_WHEAD(logqueue_store);
	copy_tv(&then, &now);
	while (lq_item) {
		DATA_LOGQUEUE(lq, lq_item);
		if (lq->db)
			LOGFILE(lq->msg, logname_db);
		else
			LOGFILE(lq->msg, logname_io);
		FREENULL(lq->msg);
		count--;
		setnow(&now);
		if ((now.tv_sec - then.tv_sec) > 10) {
			snprintf(buf, sizeof(buf), "logging ... %d", count);
			LOGERR("%s", buf);
			copy_tv(&then, &now);
		}
		lq_item = lq_item->next;
	}
	K_WUNLOCK(logqueue_free);

	logger_using_data = false;

	setnow(&now);
	snprintf(buf, sizeof(buf), "logstop.%ld,%ld",
				   now.tv_sec, now.tv_usec);
	LOGFILE(buf, logname_db);
	LOGFILE(buf, logname_io);
	LOGWARNING("%s", buf);

	return NULL;
}

static void *replier(void *arg)
{
	K_TREE *reply_root = NULL;
	REPLIES *replies = NULL;
	K_ITEM *r_item = NULL, *tmp_item;
	K_TREE_CTX ctx[1];
	enum reply_type reply_typ;
	struct epoll_event ready;
	int epollfd, ret, fails = 0, fails_tot = 0;
	char buf[128], *ptr, *st;
	bool msg = false;
	char typ = '?';
	int discarded, count;
	double full_us;
	tv_t now;

	pthread_detach(pthread_self());

	reply_typ = *(enum reply_type *)(arg);
	switch (reply_typ) {
		case REPLIER_POOL:
			typ = 'p';
			reply_root = replies_pool_root;
			epollfd = epollfd_pool;
			break;
		case REPLIER_CMD:
			typ = 'c';
			reply_root = replies_cmd_root;
			epollfd = epollfd_cmd;
			break;
		case REPLIER_BTC:
			typ = 'b';
			reply_root = replies_btc_root;
			epollfd = epollfd_btc;
			break;
		default:
			quithere(1, "%s() started with unknown reply_type %d",
				 __func__, reply_typ);
			break;
	}

	snprintf(buf, sizeof(buf), "db%s_%c%s", dbcode, typ, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	ck_wlock(&replier_lock);
	replier_count++;
	replier_using_data = true;
	ck_wunlock(&replier_lock);

	LOGNOTICE("%s() %s processing", __func__, buf);

	// _ckdb_unix_msg() deals with adding events
	while (!everyone_die) {
		ret = epoll_wait(epollfd, &ready, 1, 142);
		if (ret == 0)
			fails = 0;
		else if (ret < 0) {
			int e = errno;
			fails++;
			fails_tot++;
			K_WLOCK(replies_free);
			reply_fails++;
			K_WUNLOCK(replies_free);
			LOGEMERG("%s() %c epoll_wait (%d/%d) failed (%d:%s)",
				 __func__, typ, fails, fails_tot,
				 e, strerror(e));
			if (fails < 10 && fails_tot < 100)
				cksleep_ms(1000);
			else {
				// Abort on 10 consecutive fails or 100 total
				quithere(1, "%c aborting "DB_PROGNAME": epoll_wait "
					 "(%d/%d) failed (%d:%s)",
					 typ, fails, fails_tot,
					 e, strerror(e));
			}
		} else {
			fails = 0;
			// This is OK if there is one thread per reply_root
			r_item = (K_ITEM *)(ready.data.ptr);
			DATA_REPLIES(replies, r_item);
			if (ready.events & EPOLLOUT) {
				K_WLOCK(replies_free);
				remove_from_ktree(reply_root, r_item);
				k_unlink_item(replies_store, r_item);
				K_WUNLOCK(replies_free);
				_ckdb_unix_send(replies->sockd, replies->reply,
						replies->file, replies->func,
						replies->line);
				FREENULL(replies->reply);
				setnow(&now);
				full_us = us_tvdiff(&now, &(replies->accepted));
				K_WLOCK(replies_free);
				ret = epoll_ctl(epollfd, EPOLL_CTL_DEL,
						replies->sockd, &(replies->event));
				close(replies->sockd);
				k_add_head(replies_free, r_item);
				reply_sent++;
				reply_full_us += full_us;
				K_WUNLOCK(replies_free);
			} else {
				K_WLOCK(replies_free);
				remove_from_ktree(reply_root, r_item);
				k_unlink_item(replies_store, r_item);
				ptr = replies->reply;
				ret = epoll_ctl(epollfd, EPOLL_CTL_DEL,
						replies->sockd, &(replies->event));
				close(replies->sockd);
				k_add_head(replies_free, r_item);
				reply_cant++;
				K_WUNLOCK(replies_free);
				LOGWARNING("%s() %c discarding (%"PRIu32") "
					   "%.42s...",
					   __func__, typ, ready.events,
					   st = safe_text(ptr));
				FREENULL(st);
				FREENULL(ptr);
			}
		}
		setnow(&now);
		discarded = 0;
		K_WLOCK(replies_free);
		r_item = first_in_ktree(reply_root, ctx);
		while (r_item) {
			DATA_REPLIES(replies, r_item);
			// If the oldest hasn't reached the limit
			if (ms_tvdiff(&now, &(replies->now)) < REPLIES_LIMIT_MS)
				break;
			tmp_item = r_item;
			r_item = next_in_ktree(ctx);
			discarded++;
			remove_from_ktree(reply_root, tmp_item);
			k_unlink_item(replies_store, tmp_item);
			free(replies->reply);
			ret = epoll_ctl(epollfd, EPOLL_CTL_DEL,
					replies->sockd, &(replies->event));
			close(replies->sockd);
			k_add_head(replies_free, tmp_item);
			reply_discarded++;
		}
		K_WUNLOCK(replies_free);
		if (discarded) {
			LOGWARNING("%s() %c closed %d old (>=%dms)",
				   __func__, typ, discarded, REPLIES_LIMIT_MS);
		}
	}

	K_RLOCK(replies_free);
	count = reply_root->node_store->count;
	K_RUNLOCK(replies_free);

	LOGNOTICE("%s() %s exiting with tree count %d", __func__, buf, count);

	ck_wlock(&replier_lock);
	if (--replier_count < 1) {
		msg = true;
		replier_using_data = false;
	}
	ck_wunlock(&replier_lock);

	if (msg)
		LOGWARNING("%s() threads shut down", __func__);

	return NULL;
}

static void process_sockd(PGconn *conn, K_ITEM *wq_item, enum reply_type reply_typ)
{
	WORKQUEUE *workqueue;
	MSGLINE *msgline;
	K_ITEM *ml_item;
	char *ans, *rep;
	size_t siz;

	DATA_WORKQUEUE(workqueue, wq_item);
	ml_item = workqueue->msgline_item;
	DATA_MSGLINE(msgline, ml_item);

	ans = ckdb_cmds[msgline->which_cmds].func(conn,
						  msgline->cmd,
						  msgline->id,
						  &(msgline->now),
						  workqueue->by,
						  workqueue->code,
						  workqueue->inet,
						  &(msgline->cd),
						  msgline->trf_root, false);
	siz = strlen(ans) + strlen(msgline->id) + 32;
	rep = malloc(siz);
	snprintf(rep, siz, "%s.%ld.%s",
		 msgline->id,
		 msgline->now.tv_sec, ans);
	setnow(&(msgline->processed));
	ckdb_unix_msg(reply_typ, msgline->sockd, rep, msgline, false);
	K_WLOCK(breakqueue_free);
	sockd_count--;
	K_WUNLOCK(breakqueue_free);
	FREENULL(ans);

	free_msgline_data(ml_item, true);
	K_WLOCK(msgline_free);
	msgline_free->ram -= msgline->msgsiz;
	k_add_head(msgline_free, ml_item);
	K_WUNLOCK(msgline_free);

	K_WLOCK(workqueue_free);
	k_add_head(workqueue_free, wq_item);
	K_WUNLOCK(workqueue_free);

	tick();
}

struct listener_setup {
	int bc;
	int thread;
};

#define BC_B 0
#define BC_C 1

static pthread_t listener_pt[2][THREAD_LIMIT];
static struct listener_setup listener_setup[2][THREAD_LIMIT];

static void *listener_all(void *arg)
{
	static bool running[2][THREAD_LIMIT];

	struct listener_setup *setup;
	PGconn *conn = NULL;
	K_ITEM *wq_item;
	tv_t now1, now2;
	char buf[128];
	time_t now;
	ts_t when, when_add;
	int i, typ, mythread, done, tot, ret;
	int listener_delta = 0;

	setup = (struct listener_setup *)(arg);
	typ = setup->bc;
	mythread = setup->thread;

	snprintf(buf, sizeof(buf), "db%s_%c%02d%s",
		 dbcode, (typ == BC_B) ? 'b' : 'c', mythread, "listen");
	LOCK_INIT(buf);
	rename_proc(buf);

	if (mythread == 0) {
		pthread_detach(pthread_self());

		for (i = 1; i < THREAD_LIMIT; i++) {
			listener_setup[typ][i].thread = i;
			listener_setup[typ][i].bc = typ;
			running[typ][i] = false;
		}
		running[typ][0] = true;

		if (typ == BC_B)
			listener_delta = btc_listener_threads - 1;
		else
			listener_delta = cmd_listener_threads - 1;

		LOGNOTICE("%s() %s initialised - delta %d",
			  __func__, (typ == BC_B) ? "btc" : "cmd", listener_delta);
	}
	LOGNOTICE("%s() %s processing", __func__, buf);

	when_add.tv_sec = CMD_QUEUE_SLEEP_MS / 1000;
	when_add.tv_nsec = (CMD_QUEUE_SLEEP_MS % 1000) * 1000000;

	if (typ == BC_B)
		blistener_using_data = true;
	else
		clistener_using_data = true;

	CKPQConn(&conn);
	now = time(NULL);

	while (!everyone_die) {
		if (mythread && !running[typ][mythread])
			break;

		wq_item = NULL;
		K_WLOCK(workqueue_free);
		if (mythread == 0 && typ == BC_B &&
		    btc_listener_threads_delta != 0) {
			listener_delta = btc_listener_threads_delta;
			btc_listener_threads_delta = 0;
		} else if (mythread == 0 && typ == BC_C &&
		    cmd_listener_threads_delta != 0) {
			listener_delta = cmd_listener_threads_delta;
			cmd_listener_threads_delta = 0;
		} else {
			if (typ == BC_B)
				wq_item = k_unlink_head(btc_workqueue_store);
			else
				wq_item = k_unlink_head(cmd_workqueue_store);
		}
		K_WUNLOCK(workqueue_free);

		// TODO: deal with thread creation/shutdown failure
		if (listener_delta != 0) {
			if (listener_delta > 0) {
				// Add threads
				tot = 1;
				done = 0;
				for (i = 1; i < THREAD_LIMIT; i++) {
					if (!running[typ][i]) {
						if (listener_delta > 0) {
							listener_delta--;
							running[typ][i] = true;
							create_pthread(&(listener_pt[typ][i]),
									listener_all,
									&(listener_setup[typ][i]));
							done++;
							tot++;
						}
					} else
						tot++;
				}
				LOGWARNING("%s() created %d %s thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__,
					   done,
					   (typ == BC_B) ? "btc" : "cmd",
					   (done == 1) ? EMPTY : "s",
					   tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			} else {
				// Notify and wait for each to exit
				tot = 1;
				done = 0;
				for (i = THREAD_LIMIT - 1; i > 0; i--) {
					if (running[typ][i]) {
						if (listener_delta < 0) {
							listener_delta++;
							LOGNOTICE("%s() %s stopping %d",
								  __func__,
								  (typ == BC_B) ? "btc" : "cmd",
								  i);
							running[typ][i] = false;
							join_pthread(listener_pt[typ][i]);
							done++;
						} else
							tot++;
					}
				}
				LOGWARNING("%s() stopped %d %s thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__,
					   done,
					   (typ == BC_B) ? "btc" : "cmd",
					   (done == 1) ? EMPTY : "s",
					   tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			}
			listener_delta = 0;
			continue;
		}

		// Don't keep a connection for more than ~10s
		if ((time(NULL) - now) > 10) {
			CKPQFinish(&conn);
			CKPQConn(&conn);
			now = time(NULL);
		}

		if (wq_item) {
			setnow(&now1);
			process_sockd(conn, wq_item,
				      (typ == BC_B) ? REPLIER_BTC : REPLIER_CMD);
			setnow(&now2);
			ck_wlock(&listener_all_lock);
			if (typ == BC_B) {
				blis_us += us_tvdiff(&now2, &now1);
				blis_processed++;
			} else {
				clis_us += us_tvdiff(&now2, &now1);
				clis_processed++;
			}
			ck_wunlock(&listener_all_lock);
		} else {
			setnowts(&when);
			timeraddspec(&when, &when_add);

			if (typ == BC_B) {
				mutex_lock(&wq_btc_waitlock);
				ret = cond_timedwait(&wq_btc_waitcond,
						     &wq_btc_waitlock, &when);
				if (ret == 0)
					wq_btc_wakes++;
				else if (errno == ETIMEDOUT)
					wq_btc_timeouts++;
				mutex_unlock(&wq_btc_waitlock);
			} else {
				mutex_lock(&wq_cmd_waitlock);
				ret = cond_timedwait(&wq_cmd_waitcond,
						     &wq_cmd_waitlock, &when);
				if (ret == 0)
					wq_cmd_wakes++;
				else if (errno == ETIMEDOUT)
					wq_cmd_timeouts++;
				mutex_unlock(&wq_cmd_waitlock);
			}
		}
	}
	CKPQFinish(&conn);

	if (mythread != 0)
		LOGNOTICE("%s() %s exiting", __func__, buf);
	else {
		for (i = 1; i < THREAD_LIMIT; i++) {
			if (running[typ][i]) {
				running[typ][i] = false;
				LOGNOTICE("%s() %s waiting for %d",
					  __func__, buf, i);
				join_pthread(listener_pt[typ][i]);
			}
		}

		if (typ == BC_B) {
			LOGNOTICE("%s() %s exiting, processed %"PRIu64, __func__, buf, blis_processed);
			blistener_using_data = false;
		} else {
			LOGNOTICE("%s() %s exiting, processed %"PRIu64, __func__, buf, clis_processed);
			clistener_using_data = false;
		}
	}

	return NULL;
}

static void *process_socket(__maybe_unused void *arg)
{
	K_ITEM *bq_item = NULL, *wq_item = NULL;
	WORKQUEUE *workqueue = NULL;
	BREAKQUEUE *bq = NULL;
	MSGLINE *msgline = NULL;
	bool want_first, replied, btc, dec_sockd;
	int loglevel, oldloglevel, ret;
	char reply[1024+1];
	char *ans = NULL, *rep = NULL, *tmp, *st;
	size_t siz;
	char buf[128];
	ts_t when, when_add;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_procsock", dbcode);
	LOCK_INIT(buf);
	rename_proc(buf);

	when_add.tv_sec = CMD_QUEUE_SLEEP_MS / 1000;
	when_add.tv_nsec = (CMD_QUEUE_SLEEP_MS % 1000) * 1000000;

	want_first = true;
	while (!everyone_die) {
		K_WLOCK(breakqueue_free);
		bq_item = k_unlink_head(cmd_done_breakqueue_store);
		if (bq_item)
			cmd_processing++;
		K_WUNLOCK(breakqueue_free);

		if (!bq_item) {
			setnowts(&when);
			timeraddspec(&when, &when_add);

			mutex_lock(&process_socket_waitlock);
			ret = cond_timedwait(&process_socket_waitcond,
					     &process_socket_waitlock, &when);
			if (ret == 0)
				process_socket_wakes++;
			else if (errno == ETIMEDOUT)
				process_socket_timeouts++;
			mutex_unlock(&process_socket_waitlock);

			continue;
		}

		DATA_BREAKQUEUE(bq, bq_item);
		DATA_MSGLINE(msgline, bq->ml_item);

		// Limited commands available during key_update
		if (key_update) {
			switch (bq->cmdnum) {
				case CMD_TERMINATE:
				case CMD_PING:
				case CMD_VERSION:
				case CMD_LOGLEVEL:
				case CMD_FLUSH:
				case CMD_STATS:
				case CMD_SHSTA:
				case CMD_CHKPASS:
				case CMD_GETATTS:
				case CMD_THREADS:
				case CMD_PAUSE:
				case CMD_HOMEPAGE:
				case CMD_QUERY:
					break;
				default:
					snprintf(reply, sizeof(reply),
						 "%s.%ld.unavailable.%s",
						 msgline->id,
						 bq->now.tv_sec,
						 msgline->cmd);
					setnow(&(msgline->processed));
					ckdb_unix_msg(REPLIER_CMD, bq->sockd,
						      reply, msgline, true);
					goto skippy;
			}
		}

		if (SEQALL_LOG) {
			K_ITEM *seqall;
			if (msgline->trf_root) {
				seqall = find_transfer(msgline->trf_root, SEQALL);
				if (seqall) {
					LOGNOTICE("%s() SEQALL %d %s",
						  __func__, bq->cmdnum,
						  transfer_data(seqall));
				}
			}
		}

		replied = btc = false;
		switch (bq->cmdnum) {
			case CMD_AUTH:
			case CMD_ADDRAUTH:
			case CMD_HEARTBEAT:
			case CMD_WORKINFO:
			case CMD_SHARES:
			case CMD_SHAREERRORS:
			case CMD_AGEWORKINFO:
			case CMD_POOLSTAT:
			case CMD_USERSTAT:
			case CMD_WORKERSTAT:
			case CMD_BLOCK:
				break;
			default:
				// Non-pool commands can't affect pool0
				if (bq->seqentryflags == SE_EARLYSOCK) {
					K_WLOCK(workqueue_free);
					earlysock_left--;
					K_WUNLOCK(workqueue_free);
				}
				break;
		}
		switch (bq->cmdnum) {
			case CMD_REPLY:
				snprintf(reply, sizeof(reply),
					 "%s.%ld.?.",
					 msgline->id,
					 bq->now.tv_sec);
				setnow(&(msgline->processed));
				// Just use REPLIER_CMD ...
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				break;
			case CMD_ALERTEVENT:
			case CMD_ALERTOVENT:
				snprintf(reply, sizeof(reply),
					 "%s.%ld.failed.ERR",
					 msgline->id,
					 bq->now.tv_sec);
				if (bq->cmdnum == CMD_ALERTEVENT)
					tmp = reply_event(EVENTID_NONE, reply);
				else
					tmp = reply_ovent(OVENTID_NONE, reply);
				setnow(&(msgline->processed));
				// Just use REPLIER_CMD ...
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, tmp,
					      msgline, false);
				break;
			case CMD_TERMINATE:
				LOGWARNING("Listener received"
					   " terminate message,"
					   " terminating "DB_PROGNAME);
				snprintf(reply, sizeof(reply),
					 "%s.%ld.ok.exiting",
					 msgline->id,
					 bq->now.tv_sec);
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				everyone_die = true;
				break;
			case CMD_PING:
				LOGDEBUG("Listener received ping"
					 " request");
				snprintf(reply, sizeof(reply),
					 "%s.%ld.ok.pong",
					 msgline->id,
					 bq->now.tv_sec);
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				break;
			case CMD_VERSION:
				LOGDEBUG("Listener received"
					 " version request");
				snprintf(reply, sizeof(reply),
					 "%s.%ld.ok.CKDB V%s",
					 msgline->id,
					 bq->now.tv_sec,
					 CKDB_VERSION);
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				break;
			case CMD_LOGLEVEL:
				if (!*(msgline->id)) {
					LOGDEBUG("Listener received"
						 " loglevel, currently %d",
						 ckp.loglevel);
					snprintf(reply, sizeof(reply),
						 "%s.%ld.ok.loglevel"
						 " currently %d",
						 msgline->id,
						 bq->now.tv_sec,
						 ckp.loglevel);
				} else {
					oldloglevel = ckp.loglevel;
					loglevel = atoi(msgline->id);
					LOGDEBUG("Listener received loglevel"
						 " %d currently %d A",
						 loglevel, oldloglevel);
					if (loglevel < LOG_EMERG ||
					    loglevel > LOG_DEBUG) {
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ERR.invalid"
							 " loglevel %d"
							 " - currently %d",
							 msgline->id,
							 bq->now.tv_sec,
							 loglevel,
							 oldloglevel);
					} else {
						ckp.loglevel = loglevel;
						snprintf(reply, sizeof(reply),
							 "%s.%ld.ok.loglevel"
							 " now %d - was %d",
							 msgline->id,
							 bq->now.tv_sec,
							 ckp.loglevel,
							 oldloglevel);
					}
					// Do this twice since the loglevel may have changed
					LOGDEBUG("Listener received loglevel"
						 " %d currently %d B",
						 loglevel, oldloglevel);
				}
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				break;
			case CMD_FLUSH:
				LOGDEBUG("Listener received"
					 " flush request");
				snprintf(reply, sizeof(reply),
					 "%s.%ld.ok.splash",
					 msgline->id, bq->now.tv_sec);
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				fflush(stdout);
				fflush(stderr);
				if (global_ckp && global_ckp->logfd)
					fflush(global_ckp->logfp);
				if (*(msgline->id)) {
					// If you set the flush id to 2
					if (atoi(msgline->id) == 2)
						ioqueue_flush = true;
				}
				setnow(&(msgline->processed));
				break;
			case CMD_USERSET:
			case CMD_BTCSET:
				btc = true;
			case CMD_CHKPASS:
			case CMD_2FA:
			case CMD_ADDUSER:
			case CMD_NEWPASS:
			case CMD_WORKERSET:
			case CMD_GETATTS:
			case CMD_SETATTS:
			case CMD_EXPATTS:
			case CMD_GETOPTS:
			case CMD_SETOPTS:
			case CMD_BLOCKLIST:
			case CMD_NEWID:
			case CMD_STATS:
			case CMD_USERSTATUS:
			case CMD_SHSTA:
			case CMD_USERINFO:
			case CMD_LOCKS:
			case CMD_EVENTS:
			case CMD_HIGH:
			case CMD_THREADS:
			case CMD_PAUSE:
			case CMD_QUERY:
				msgline->sockd = bq->sockd;
				bq->sockd = -1;
				K_WLOCK(workqueue_free);
				wq_item = k_unlink_head(workqueue_free);
				DATA_WORKQUEUE(workqueue, wq_item);
				workqueue->msgline_item = bq->ml_item;
				workqueue->by = by_default;
				workqueue->code =  (char *)__func__;
				workqueue->inet = inet_default;
				if (btc)
					k_add_tail(btc_workqueue_store, wq_item);
				else
					k_add_tail(cmd_workqueue_store, wq_item);
				K_WUNLOCK(workqueue_free);
				if (btc) {
					mutex_lock(&wq_btc_waitlock);
					wq_btc_signals++;
					pthread_cond_signal(&wq_btc_waitcond);
					mutex_unlock(&wq_btc_waitlock);
				} else {
					mutex_lock(&wq_cmd_waitlock);
					wq_cmd_signals++;
					pthread_cond_signal(&wq_cmd_waitcond);
					mutex_unlock(&wq_cmd_waitlock);
				}
				wq_item = bq->ml_item = NULL;
				break;
			// Process, but reject (loading) until startup_complete
			case CMD_HOMEPAGE:
			case CMD_ALLUSERS:
			case CMD_WORKERS:
			case CMD_PAYMENTS:
			case CMD_PPLNS:
			case CMD_PPLNS2:
			case CMD_PAYOUTS:
			case CMD_MPAYOUTS:
			case CMD_SHIFTS:
			case CMD_PSHIFT:
			case CMD_DSP:
			case CMD_BLOCKSTATUS:
			case CMD_MARKS:
				if (!startup_complete && !key_update) {
					snprintf(reply, sizeof(reply),
						 "%s.%ld.loading.%s",
						 msgline->id,
						 bq->now.tv_sec,
						 msgline->cmd);
					setnow(&(msgline->processed));
					ckdb_unix_msg(REPLIER_CMD, bq->sockd,
						      reply, msgline, true);
				} else {
					msgline->sockd = bq->sockd;
					bq->sockd = -1;
					K_WLOCK(workqueue_free);
					wq_item = k_unlink_head(workqueue_free);
					DATA_WORKQUEUE(workqueue, wq_item);
					workqueue->msgline_item = bq->ml_item;
					workqueue->by = by_default;
					workqueue->code =  (char *)__func__;
					workqueue->inet = inet_default;
					if (btc)
						k_add_tail(btc_workqueue_store, wq_item);
					else
						k_add_tail(cmd_workqueue_store, wq_item);
					K_WUNLOCK(workqueue_free);
					wq_item = bq->ml_item = NULL;
					if (btc) {
						mutex_lock(&wq_btc_waitlock);
						wq_btc_signals++;
						pthread_cond_signal(&wq_btc_waitcond);
						mutex_unlock(&wq_btc_waitlock);
					} else {
						mutex_lock(&wq_cmd_waitlock);
						wq_cmd_signals++;
						pthread_cond_signal(&wq_cmd_waitcond);
						mutex_unlock(&wq_cmd_waitlock);
					}
				}
				break;
			// Always process immediately:
			case CMD_AUTH:
			case CMD_ADDRAUTH:
			case CMD_HEARTBEAT:
				// First message from the pool
				if (want_first) {
					want_first = false;
					ck_wlock(&fpm_lock);
					first_pool_message = strdup(bq->buf);
					ck_wunlock(&fpm_lock);
				}
				DATA_MSGLINE(msgline, bq->ml_item);
				ans = ckdb_cmds[msgline->which_cmds].func(NULL,
						msgline->cmd,
						msgline->id,
						&(msgline->now),
						by_default,
						(char *)__func__,
						inet_default,
						&(msgline->cd),
						msgline->trf_root, false);
				setnow(&(msgline->processed));
				siz = strlen(ans) + strlen(msgline->id) + 32;
				rep = malloc(siz);
				snprintf(rep, siz, "%s.%ld.%s",
					 msgline->id,
					 bq->now.tv_sec, ans);
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_POOL, bq->sockd, rep,
					      msgline, false);
				FREENULL(ans);
				replied = true;
			// Always queue (ok.queued)
			case CMD_WORKINFO:
			case CMD_SHARES:
			case CMD_SHAREERRORS:
			case CMD_AGEWORKINFO:
			case CMD_POOLSTAT:
			case CMD_USERSTAT:
			case CMD_WORKERSTAT:
			case CMD_BLOCK:
				if (!replied) {
					// First message from the pool
					if (want_first) {
						want_first = false;
						ck_wlock(&fpm_lock);
						first_pool_message = strdup(bq->buf);
						ck_wunlock(&fpm_lock);
					}
					snprintf(reply, sizeof(reply),
						 "%s.%ld.ok.queued",
						 msgline->id,
						 bq->now.tv_sec);
					ckdb_unix_msg(REPLIER_POOL, bq->sockd,
						      reply, msgline, true);
				}

				K_WLOCK(workqueue_free);
				wq_item = k_unlink_head(workqueue_free);
				DATA_WORKQUEUE(workqueue, wq_item);
				workqueue->msgline_item = bq->ml_item;
				workqueue->by = by_default;
				workqueue->code =  (char *)__func__;
				workqueue->inet = inet_default;
				if (bq->seqentryflags == SE_SOCKET)
					k_add_tail(pool_workqueue_store, wq_item);
				else {
					k_add_tail(pool0_workqueue_store, wq_item);
					pool0_tot++;
					/* Stop the reload queue from growing too big
					 * Use a size that 'should be big enough' */
					if (reloading && pool0_workqueue_store->count > 250000) {
						K_ITEM *wq2_item = k_unlink_head(pool0_workqueue_store);
						earlysock_left--;
						pool0_discarded++;
						K_WUNLOCK(workqueue_free);
						WORKQUEUE *wq;
						DATA_WORKQUEUE(wq, wq2_item);
						K_ITEM *ml_item = wq->msgline_item;
						MSGLINE *ml;
						DATA_MSGLINE(ml, ml_item);
						free_msgline_data(ml_item, true);
						K_WLOCK(msgline_free);
						msgline_free->ram -= ml->msgsiz;
						k_add_head(msgline_free, ml_item);
						K_WUNLOCK(msgline_free);
						K_WLOCK(workqueue_free);
						k_add_head(workqueue_free, wq2_item);
					}
				}
				K_WUNLOCK(workqueue_free);
				wq_item = bq->ml_item = NULL;
				mutex_lock(&wq_pool_waitlock);
				wq_pool_signals++;
				pthread_cond_signal(&wq_pool_waitcond);
				mutex_unlock(&wq_pool_waitlock);
				break;
			// Code error
			default:
				LOGEMERG("%s() CODE ERROR unhandled"
					 " message %d %.32s...",
					 __func__, bq->cmdnum,
					 st = safe_text(bq->buf));
				FREENULL(st);
				snprintf(reply, sizeof(reply),
					 "%s.%ld.failed.code",
					 msgline->id,
					 bq->now.tv_sec);
				setnow(&(msgline->processed));
				ckdb_unix_msg(REPLIER_CMD, bq->sockd, reply,
					      msgline, true);
				break;
		}

skippy:

		if (bq->sockd >= 0)
			dec_sockd = true;
		else
			dec_sockd = false;

		if (bq->ml_item) {
			MSGLINE *ml;
			DATA_MSGLINE(ml, bq->ml_item);
			free_msgline_data(bq->ml_item, true);
			K_WLOCK(msgline_free);
			msgline_free->ram -= ml->msgsiz;
			k_add_head(msgline_free, bq->ml_item);
			K_WUNLOCK(msgline_free);
			bq->ml_item = NULL;
		}
		free(bq->buf);

		K_WLOCK(breakqueue_free);
		if (dec_sockd)
			sockd_count--;
		cmd_processing--;
		breakqueue_free->ram -= bq->bufsiz;
		k_add_head(breakqueue_free, bq_item);
		K_WUNLOCK(breakqueue_free);
	}

	return NULL;
}

static void *sockrun(void *arg)
{
	pool_t *this = (pool_t *)arg;
	unixsock_t *us = &(this->main.us);
	char *end, *buf = NULL;
	K_ITEM *bq_item = NULL;
	BREAKQUEUE *bq = NULL;
	int ret, sockd, thissock;
	fd_set rfds;
	char *name = (char *)(this->gdata);
	char nbuf[64];
	tv_t now, nowacc, now1, now2, tmo;

	thissock = SOCKNUM(name);
	if (thissock == MAXSOCK) {
		quithere(1, "thread started with invalid pool_t %p %p",
			 this, name);
	}

	snprintf(nbuf, sizeof(nbuf), "db%s_%c%s", dbcode, name[0], __func__);
	LOCK_INIT(nbuf);
	rename_proc(nbuf);

	ret = 0;
	setnow(&sock_stt[thissock]);
	while (!everyone_die) {
		setnow(&now1);
		while (!everyone_die) {
			FD_ZERO(&rfds);
			FD_SET(us->sockd, &rfds);
			tmo.tv_sec = 1;
			tmo.tv_usec = 0;
			ret = select(us->sockd + 1, &rfds, NULL, NULL, &tmo);
			if (ret > 0)
				break;
			if (ret < 0) {
				int e = errno;
				LOGERR("%s() Failed to select on %s socket "
					"(%d:%s)",
					__func__, name, e, strerror(e));
				break;
			}
		}
		// If one fails, stop everything
		if (ret < 0)
			everyone_die = true;

		if (everyone_die)
			break;

		sockd = accept(us->sockd, NULL, NULL);
		if (sockd < 0) {
			int e = errno;
			LOGERR("%s() Failed to accept on %s socket (%d:%s)",
			       __func__, name, e, strerror(e));
			break;
		}
		setnow(&nowacc);
		sock_us[thissock] += us_tvdiff(&nowacc, &now1);
		sock_acc[thissock]++;

		setnow(&now1);
		buf = recv_unix_msg_tmo2(sockd, RECV_UNIX_TIMEOUT1, RECV_UNIX_TIMEOUT2);
		// Once we've read the message
		setnow(&now);
		sock_recv_us[thissock] += us_tvdiff(&now, &now1);
		sock_recv[thissock]++;
		if (buf) {
			end = buf + strlen(buf) - 1;
			// strip trailing \n and \r
			while (end >= buf && (*end == '\n' || *end == '\r'))
				*(end--) = '\0';
		}
		if (!buf || !*buf) {
			// An empty message wont get a reply
			if (!buf) {
				LOGWARNING("%s() Failed to get %s message",
					   __func__, name);
			} else {
				LOGWARNING("%s() Empty %s message",
					   __func__, name);
				free(buf);
			}
		} else {
			int seqentryflags = SE_SOCKET;
			// Flag all work for pool0 until the reload completes
			if (prereload || reloading) {
				seqentryflags = SE_EARLYSOCK;
				setnow(&now1);
				K_WLOCK(workqueue_free);
				earlysock_left++;
				K_WUNLOCK(workqueue_free);
				setnow(&now2);
				sock_proc_early[thissock]++;
				sock_lock_wq_us[thissock] += us_tvdiff(&now2, &now1);
			}

			if (SEQALL_LOG) {
				char *pos, *col, *com;
				pos = strstr(buf, SEQALL);
				if (pos) {
					col = strchr(pos, JSON_VALUE);
					if (col) {
						com = strchr(col, JSON_SEP);
						if (!com)
							com = strchr(col, JSON_END);
						if (com) {
							LOGNOTICE("%s() SEQALL %s %.*s",
								  __func__,
								  seqentryflags == SE_SOCKET
								   ? "S" : "ES",
								  (int)(com-col-1),
								  col+1);
						}
					}
				}
			}

			sock_processed[thissock]++;
			// Don't limit the speed filling up cmd_breakqueue_store
			setnow(&now1);
			K_WLOCK(breakqueue_free);
			bq_item = k_unlink_head(breakqueue_free);
			K_WUNLOCK(breakqueue_free);
			DATA_BREAKQUEUE(bq, bq_item);
			bq->buf = buf;
			bq->bufsiz = strlen(buf)+1;
			bq->source = (char *)(this->gdata);
			bq->access = *(int *)(this->cdata);
			copy_tv(&(bq->accepted), &nowacc);
			copy_tv(&(bq->now), &now);
			bq->seqentryflags = seqentryflags;
			bq->sockd = sockd;
			K_WLOCK(breakqueue_free);
			if (max_sockd_count < ++sockd_count)
				max_sockd_count = sockd_count;
			k_add_tail(cmd_breakqueue_store, bq_item);
			breakqueue_free->ram += bq->bufsiz;
			K_WUNLOCK(breakqueue_free);
			setnow(&now2);
			sock_lock_br_us[thissock] += us_tvdiff(&now2, &now1);

			mutex_lock(&bq_cmd_waitlock);
			bq_cmd_signals++;
			pthread_cond_signal(&bq_cmd_waitcond);
			mutex_unlock(&bq_cmd_waitlock);
		}
	}

	close_unix_socket(us->sockd, us->path);

	LOGWARNING("%s() %s exiting: early=%"PRIu64" after=%"PRIu64
		   " (%"PRIu64")",
		   __func__, name, sock_proc_early[thissock],
		   sock_processed[thissock] - sock_proc_early[thissock],
		   sock_processed[thissock]);

	return NULL;
}

static void *socksetup(__maybe_unused void *arg)
{
	pthread_t prep_pt, crep_pt, brep_pt;
	enum reply_type p_typ, c_typ, b_typ;
	pthread_t proc_pt;
	pthread_t psock_pt, wsock_pt, csock_pt;
	char nbuf[64];

	pthread_detach(pthread_self());

	snprintf(nbuf, sizeof(nbuf), "db%s_%s", dbcode, __func__);
	LOCK_INIT(nbuf);
	rename_proc(nbuf);

	while (!everyone_die && !db_users_complete)
		cksem_mswait(&socksetup_sem, 420);

	if (!everyone_die) {
		epollfd_pool = epoll_create1(EPOLL_CLOEXEC);
		epollfd_cmd = epoll_create1(EPOLL_CLOEXEC);
		epollfd_btc = epoll_create1(EPOLL_CLOEXEC);
		p_typ = REPLIER_POOL;
		c_typ = REPLIER_CMD;
		b_typ = REPLIER_BTC;
		create_pthread(&prep_pt, replier, &p_typ);
		create_pthread(&crep_pt, replier, &c_typ);
		create_pthread(&brep_pt, replier, &b_typ);

		LOGWARNING("%s() Start processing...", __func__);
		socksetup_using_data = true;

		listener_setup[BC_B][0].bc = BC_B;
		listener_setup[BC_B][0].thread = 0;
		create_pthread(&listener_pt[BC_B][0], listener_all,
				&(listener_setup[BC_B][0]));

		listener_setup[BC_C][0].bc = BC_C;
		listener_setup[BC_C][0].thread = 0;
		create_pthread(&listener_pt[BC_C][0], listener_all,
				&(listener_setup[BC_C][0]));

		create_pthread(&proc_pt, process_socket, NULL);

		create_pthread(&psock_pt, sockrun, &ckp);
		create_pthread(&wsock_pt, sockrun, &ckpweb);
		create_pthread(&csock_pt, sockrun, &ckpcmd);

		join_pthread(psock_pt);
		join_pthread(wsock_pt);
		join_pthread(csock_pt);
	}

	socksetup_using_data = false;

	// Since the sockets are dead ...
	everyone_die = true;

	return NULL;
}

static void process_reload_item(PGconn *conn, K_ITEM *bq_item)
{
	MSGLINE *msgline = NULL;
	BREAKQUEUE *bq = NULL;
	enum cmd_values cmdnum;
	char *ans, *st = NULL;

	DATA_BREAKQUEUE(bq, bq_item);
	DATA_MSGLINE(msgline, bq->ml_item);
	if (SEQALL_LOG) {
		K_ITEM *seqall;
		if (msgline->trf_root) {
			seqall = find_transfer(msgline->trf_root, SEQALL);
			if (seqall) {
				LOGNOTICE("%s() SEQALL %d %s",
					  __func__, bq->cmdnum,
					  transfer_data(seqall));
			}
		}
	}
	switch (bq->cmdnum) {
		// Ignore
		case CMD_REPLY:
		case CMD_ALERTEVENT:
		case CMD_ALERTOVENT:
			break;
		// Shouldn't be there
		case CMD_TERMINATE:
		case CMD_PING:
		case CMD_VERSION:
		case CMD_LOGLEVEL:
		case CMD_FLUSH:
		// Non pool commands, shouldn't be there
		case CMD_ADDUSER:
		case CMD_NEWPASS:
		case CMD_CHKPASS:
		case CMD_2FA:
		case CMD_USERSET:
		case CMD_WORKERSET:
		case CMD_BLOCKLIST:
		case CMD_BLOCKSTATUS:
		case CMD_NEWID:
		case CMD_PAYMENTS:
		case CMD_WORKERS:
		case CMD_ALLUSERS:
		case CMD_HOMEPAGE:
		case CMD_GETATTS:
		case CMD_SETATTS:
		case CMD_EXPATTS:
		case CMD_GETOPTS:
		case CMD_SETOPTS:
		case CMD_DSP:
		case CMD_STATS:
		case CMD_PPLNS:
		case CMD_PPLNS2:
		case CMD_PAYOUTS:
		case CMD_MPAYOUTS:
		case CMD_SHIFTS:
		case CMD_USERSTATUS:
		case CMD_MARKS:
		case CMD_PSHIFT:
		case CMD_SHSTA:
		case CMD_USERINFO:
		case CMD_BTCSET:
		case CMD_QUERY:
		case CMD_LOCKS:
		case CMD_EVENTS:
		case CMD_HIGH:
		case CMD_THREADS:
		case CMD_PAUSE:
			LOGERR("%s() INVALID message line %"PRIu64
				" ignored '%.42s...",
				__func__, bq->count,
				st = safe_text(msgline->msg));
			FREENULL(st);
			break;
		case CMD_HEARTBEAT:
		case CMD_POOLSTAT:
		case CMD_USERSTAT:
		case CMD_WORKERSTAT:
		case CMD_BLOCK:
			if (key_update)
				break;
		case CMD_AUTH:
		case CMD_ADDRAUTH:
			if (confirm_sharesummary)
				break;
		case CMD_WORKINFO:
		case CMD_SHARES:
		case CMD_SHAREERRORS:
		case CMD_AGEWORKINFO:
			// This will return the same cmdnum or DUP
			cmdnum = process_seq(msgline);
			if (cmdnum != CMD_DUPSEQ) {
				ans = ckdb_cmds[msgline->which_cmds].func(conn,
						msgline->cmd,
						msgline->id,
						&(msgline->now),
						by_default,
						(char *)__func__,
						inet_default,
						&(msgline->cd),
						msgline->trf_root, true);
				FREENULL(ans);
			}
			// TODO: time stats from each msgline tv_t
			break;
		default:
			// Force this switch to be updated if new cmds are added
			quithere(1, "%s line %"PRIu64" '%s' - not "
				 "handled by reload",
				 bq->filename, bq->count,
				 st = safe_text_nonull(msgline->cmd));
			// Won't get here ...
			FREENULL(st);
			break;
	}

	if (bq->ml_item) {
		DATA_MSGLINE(msgline, bq->ml_item);
		free_msgline_data(bq->ml_item, true);
		K_WLOCK(msgline_free);
		msgline_free->ram -= msgline->msgsiz;
		k_add_head(msgline_free, bq->ml_item);
		K_WUNLOCK(msgline_free);
		bq->ml_item = NULL;
	}
	free(bq->buf);
}

static void *process_reload(__maybe_unused void *arg)
{
	static pthread_t procrel_pt[THREAD_LIMIT];
	static int n[THREAD_LIMIT];
	static bool running[THREAD_LIMIT];

	PGconn *conn = NULL;
	K_ITEM *bq_item = NULL;
	BREAKQUEUE *bq;
	char buf[128];
	time_t now;
	ts_t when, when_add;
	int i, mythread, threads_delta = 0, done, tot, ret;

	if (arg)
		mythread = *(int *)(arg);
	else
		mythread = 0;

	snprintf(buf, sizeof(buf), "db%s_p%02drload", dbcode, mythread);
	LOCK_INIT(buf);
	rename_proc(buf);

	if (!arg) {
		pthread_detach(pthread_self());

		for (i = 0; i < THREAD_LIMIT; i++) {
			n[i] = i;
			running[i] = false;
		}

		running[0] = true;

		// Set to create the rest of the threads
		reload_queue_threads_delta = reload_queue_threads - 1;

		LOGNOTICE("%s() starting", __func__);
	}

	when_add.tv_sec = RELOAD_QUEUE_SLEEP_MS / 1000;
	when_add.tv_nsec = (RELOAD_QUEUE_SLEEP_MS % 1000) * 1000000;

	CKPQConn(&conn);
	now = time(NULL);

	while (!everyone_die) {
		if (mythread && !running[mythread])
			break;

		K_WLOCK(breakqueue_free);
		if (mythread == 0 && reload_queue_threads_delta != 0) {
			threads_delta = reload_queue_threads_delta;
			reload_queue_threads_delta = 0;
		} else {
			bq_item = k_unlink_head(reload_done_breakqueue_store);
			if (bq_item) {
				reload_processing++;
				reload_processed++;
			}
		}
		K_WUNLOCK(breakqueue_free);

		// TODO: deal with thread creation/shutdown failure
		if (threads_delta != 0) {
			if (threads_delta > 0) {
				// Add threads
				tot = 1;
				done = 0;
				for (i = 1; i < THREAD_LIMIT; i++) {
					if (!running[i]) {
						if (threads_delta > 0) {
							threads_delta--;
							running[i] = true;
							create_pthread(&(procrel_pt[i]),
									process_reload,
									&(n[i]));
							done++;
							tot++;
						}
					} else
						tot++;
				}
				LOGWARNING("%s() created %d thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__, done,
					   (done == 1) ? EMPTY : "s", tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			} else {
				// Notify and wait for each to exit
				tot = 1;
				done = 0;
				for (i = THREAD_LIMIT - 1; i > 0; i--) {
					if (running[i]) {
						if (threads_delta < 0) {
							threads_delta++;
							LOGNOTICE("%s() stopping %d",
								  __func__, i);
							running[i] = false;
							join_pthread(procrel_pt[i]);
							done++;
						} else
							tot++;
					}
				}
				LOGWARNING("%s() stopped %d thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__, done,
					   (done == 1) ? EMPTY : "s", tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			}
			threads_delta = 0;
			continue;
		}

		if (!bq_item) {
			// Finished reloading?
			if (!reloading)
				break;

			setnowts(&when);
			timeraddspec(&when, &when_add);

			mutex_lock(&process_reload_waitlock);
			ret = cond_timedwait(&process_reload_waitcond,
					     &process_reload_waitlock, &when);
			if (ret == 0)
				process_reload_wakes++;
			else if (errno == ETIMEDOUT)
				process_reload_timeouts++;
			mutex_unlock(&process_reload_waitlock);

			continue;
		}

		// Don't keep a connection for more than ~10s ... of processing
		if ((time(NULL) - now) > 10) {
			CKPQFinish(&conn);
			CKPQConn(&conn);
			now = time(NULL);
		}

		process_reload_item(conn, bq_item);

		DATA_BREAKQUEUE(bq, bq_item);
		K_WLOCK(breakqueue_free);
		reload_processing--;
		breakqueue_free->ram -= bq->bufsiz;
		k_add_head(breakqueue_free, bq_item);
		K_WUNLOCK(breakqueue_free);

		tick();
	}
	CKPQFinish(&conn);

	if (mythread == 0) {
		for (i = 1; i < THREAD_LIMIT; i++) {
			if (running[i]) {
				running[i] = false;
				LOGNOTICE("%s() waiting for %d", __func__, i);
				join_pthread(procrel_pt[i]);
			}
		}

		LOGNOTICE("%s() exiting, processed %"PRIu64,
			  __func__, reload_processed);
	}

	return NULL;
}

static void reload_line(char *filename, char *buf, uint64_t count)
{
	K_ITEM *bq_item = NULL;
	BREAKQUEUE *bq = NULL;
	int qcount;
	char *end;
	tv_t now;

	// Once we've read the message
	setnow(&now);
	if (buf) {
		end = buf + strlen(buf) - 1;
		// strip trailing \n and \r
		while (end >= buf && (*end == '\n' || *end == '\r'))
			*(end--) = '\0';
	}
	if (!buf || !*buf) {
		if (!buf) {
			LOGERR("%s() NULL message line %"PRIu64,
				__func__, count);
		} else {
			LOGERR("%s() Empty message line %"PRIu64,
				__func__, count);
		}
	} else {
		if (SEQALL_LOG) {
			char *pos, *col, *com;
			pos = strstr(buf, SEQALL);
			if (pos) {
				col = strchr(pos, JSON_VALUE);
				if (col) {
					com = strchr(col, JSON_SEP);
					if (!com)
						com = strchr(col, JSON_END);
					if (com) {
						LOGNOTICE("%s() SEQALL %.*s",
							  __func__,
							  (int)(com-col-1),
							  col+1);
					}
				}
			}
		}
		K_WLOCK(breakqueue_free);
		bq_item = k_unlink_head(breakqueue_free);
		K_WUNLOCK(breakqueue_free);

		// release the lock since strdup could be slow, but rarely
		DATA_BREAKQUEUE(bq, bq_item);
		bq->buf = strdup(buf);
		bq->bufsiz = strlen(buf)+1;
		// reloads are normally all pool data but access can be changed
		bq->source = (char *)ispool;
		bq->access = reload_access;
		copy_tv(&(bq->accepted), &now);
		copy_tv(&(bq->now), &now);
		bq->seqentryflags = SE_RELOAD;
		bq->sockd = -1;
		bq->count = count;
		bq->filename = filename;

		K_WLOCK(breakqueue_free);
		k_add_tail(reload_breakqueue_store, bq_item);
		qcount = reload_breakqueue_store->count;
		breakqueue_free->ram += bq->bufsiz;
		K_WUNLOCK(breakqueue_free);

		mutex_lock(&bq_reload_waitlock);
		bq_reload_signals++;
		pthread_cond_signal(&bq_reload_waitcond);
		mutex_unlock(&bq_reload_waitlock);

		while (qcount > reload_queue_limit) {
			cksleep_ms(RELOAD_QUEUE_SLEEP_MS);
			K_RLOCK(breakqueue_free);
			qcount = reload_breakqueue_store->count;
			K_RUNLOCK(breakqueue_free);
		}
	}
}

// 10Mb for now - transactiontree can be large
#define MAX_READ (10 * 1024 * 1024)
static char *reload_buf;

static bool logline(char *buf, int siz, FILE *fp, char *filename)
{
	char *ret;

	ret = fgets_unlocked(buf, siz, fp);
	if (!ret && ferror(fp)) {
		int err = errno;
		quithere(1, "Read failed on %s (%d) '%s'",
			    filename, err, strerror(err));
	}
	if (ret)
		return true;
	else
		return false;
}

static struct decomp {
	char *ext;
	char *fmt;
} dec_list[] = {
	{ ".bz2", "bzcat -q '%s'" },
	{ ".gz",  "zcat -q '%s'" },
	{ ".lrz", "lrzip -q -d -o - '%s'" },
	{ NULL, NULL }
};

static bool logopen(char **filename, FILE **fp, bool *apipe)
{
	char buf[1024];
	char *name;
	size_t len;
	int i;

	*apipe = false;

	*fp = NULL;
	*fp = fopen(*filename, "re");
	if (*fp)
		return true;

	for (i = 0; dec_list[i].ext; i++) {
		len = strlen(*filename) + strlen(dec_list[i].ext);
		name = malloc(len + 1);
		if (!name)
			quithere(1, "(%d) OOM", (int)len);
		strcpy(name, *filename);
		strcat(name, dec_list[i].ext);
		if (access(name, R_OK))
			free(name);
		else {
			snprintf(buf, sizeof(buf), dec_list[i].fmt, name);
			*fp = popen(buf, "re");
			if (!(*fp)) {
				int errn = errno;
				quithere(1, "Failed to pipe (%d) \"%s\"",
					 errn, buf);
			} else {
				*apipe = true;
				/* Don't free the old filename since
				 *  process_reload() could still access it */
				*filename = name;
				return true;
			}
		}
	}
	return false;
}

// How many files need to be processed before flagging reloaded_N_files
#define RELOAD_N_FILES 2
// optioncontrol name to override the above value
#define RELOAD_N_FILES_STR "ReloadNFiles"

// How many lines in a reload file required to count it
#define RELOAD_N_COUNT 1000

/* If the reload start file is missing and -r was specified correctly:
 *	touch the filename reported in "Failed to open 'filename'",
 *	if ckdb aborts at the beginning of the reload, then start again */
static bool reload_from(tv_t *start, const tv_t *finish)
{
	// proc_pt could exit after this returns
	static pthread_t proc_pt;
	char buf[DATE_BUFSIZ+1], run[DATE_BUFSIZ+1], tickmsg[256];
	size_t rflen = strlen(restorefrom);
	char *missingfirst = NULL, *missinglast = NULL, *st = NULL;
	int missing_count, processing, counter;
	bool finished = false, ret = true, ok, apipe = false;
	char *filename = NULL;
	uint64_t count, total;
	tv_t now, begin, file_begin, file_end, last_cd;
	time_t last_file = 0;
	double diff, ratio;
	FILE *fp = NULL;
	int file_N_limit;
	time_t tick_time, tmp_time, last_sec, tot_sec = 0;

	reload_buf = malloc(MAX_READ);
	if (!reload_buf)
		quithere(1, "(%d) OOM", MAX_READ);

	file_N_limit = (int)sys_setting(RELOAD_N_FILES_STR, RELOAD_N_FILES,
					&date_eot);

	reloading = true;

	copy_tv(&reload_timestamp, start);
	reload_timestamp.tv_sec -= reload_timestamp.tv_sec % ROLL_S;

	tv_to_buf(start, buf, sizeof(buf));
	tv_to_buf(&reload_timestamp, run, sizeof(run));
	LOGWARNING("%s(): from %s (stamp %s)", __func__, buf, run);

	filename = hour_filename(restorefrom, restorename, reload_timestamp.tv_sec);
	if (!logopen(&filename, &fp, &apipe))
		quithere(1, "Failed to open '%s'", filename);
	last_file = reload_timestamp.tv_sec;

	setnow(&now);
	copy_tv(&begin, &now);
	tvs_to_buf(&now, run, sizeof(run));
	snprintf(reload_buf, MAX_READ, "reload.%s.s0", run);
	LOGQUE(reload_buf, true);
	LOGQUE(reload_buf, false);

	// Start after reloading = true
	create_pthread(&proc_pt, process_reload, NULL);

	total = 0;
	processing = 0;
	tick_time = time(NULL);
	while (!everyone_die && !finished) {
		LOGWARNING("%s(): processing %s", __func__, filename);
		processing++;
		count = 0;
		setnow(&file_begin);

		/* Don't abort when matched since breakdown() will remove
		 *  the matching message sequence numbers queued from asicseer-pool
		 * Also since asicseer-pool messages are not in order, we could be
		 *  aborting early and not get the few slightly later out of
		 *  order messages in the log file */
		while (!everyone_die &&
			logline(reload_buf, MAX_READ, fp, filename)) {
				reload_line(filename, reload_buf, ++count);

			tmp_time = time(NULL);
			// Report stats every 15s
			if ((tmp_time - tick_time) > 14) {
				int relq, relqd, cmdq, cmdqd, mx, pool0q, poolq;
				K_RLOCK(breakqueue_free);
				relq = reload_breakqueue_store->count +
					reload_processing;
				relqd = reload_done_breakqueue_store->count;
				cmdq = cmd_breakqueue_store->count +
					cmd_processing;
				cmdqd = cmd_done_breakqueue_store->count;
				mx = max_sockd_count;
				K_RUNLOCK(breakqueue_free);
				K_RLOCK(workqueue_free);
				pool0q = pool0_workqueue_store->count;
				poolq = pool_workqueue_store->count;
				// pool_workqueue_store should be zero
				K_RUNLOCK(workqueue_free);
				snprintf(tickmsg, sizeof(tickmsg),
					TICK_PREFIX"reload %"PRIu64"/%d/%d"
					" ckp %d/%d/%d/%d (%d)    ",
					total+count, relq, relqd,
					cmdq, cmdqd, pool0q, poolq, mx);
				cr_msg(false, tickmsg);
				tick_time = tmp_time;
			}
		}

		setnow(&file_end);
		diff = tvdiff(&file_end, &file_begin);
		if (diff == 0)
			diff = 1;
		// Work out how long the file was
		K_RLOCK(breakqueue_free);
		txt_to_ctv(CDTRF, last_reload_cd, &last_cd, sizeof(last_cd));
		K_RUNLOCK(breakqueue_free);
		last_sec = last_cd.tv_sec - last_file;
		if (last_cd.tv_usec)
			last_sec++;
		if (last_sec < 2 || last_sec > ROLL_S)
			last_sec = ROLL_S;
		ratio = (double)last_sec / diff;
		tot_sec += last_sec;

		LOGWARNING("%s(): %sread %"PRIu64" line%s %.2f/s (%.1fx)"
			   " from %s",
			   __func__,
			   everyone_die ? "Terminate, aborting - " : "",
			   count, count == 1 ? "" : "s", (count / diff),
			   ratio, filename);
		total += count;
		if (apipe) {
			pclose(fp);
			if (count == 0) {
				quithere(1, "ABORTING - No data returned from "
					    "compressed file \"%s\"",
					    filename);
			}
		} else
			fclose(fp);
		/* Don't free the old filename since
		 *  process_reload() could access it */
		if (everyone_die)
			break;
		reload_timestamp.tv_sec += ROLL_S;
		if (tv_newer(finish, &reload_timestamp)) {
			tv_to_buf(&reload_timestamp, buf, sizeof(buf));
			LOGWARNING("%s(): finish range (%s) exceeded",
				   __func__, buf);
			break;
		}

		/* Used by marker() to start mark generation during a longer
		 *  than normal reload */
		if (count > RELOAD_N_COUNT) {
			if (file_N_limit-- < 1)
				reloaded_N_files = true;
		}

		filename = hour_filename(restorefrom, restorename, reload_timestamp.tv_sec);
		ok = logopen(&filename, &fp, &apipe);
		if (ok)
			last_file = reload_timestamp.tv_sec;
		else {
			missingfirst = strdup(filename);
			FREENULL(filename);
			errno = 0;
			missing_count = 1;
			setnow(&now);
			now.tv_sec += ROLL_S;
			while (42) {
				reload_timestamp.tv_sec += ROLL_S;
				/* WARNING: if the system clock is wrong, any CCLs
				 * missing or not created due to a asicseer-pool outage of
				 * an hour or more can stop the reload early and
				 * cause DB problems! Though, the clock being wrong
				 * can screw up asicseer-pool and ckdb anyway ... */
				if (!tv_newer(&reload_timestamp, &now)) {
					finished = true;
					break;
				}
				filename = hour_filename(restorefrom, restorename, reload_timestamp.tv_sec);
				ok = logopen(&filename, &fp, &apipe);
				if (ok) {
					last_file = reload_timestamp.tv_sec;
					break;
				}
				errno = 0;
				if (missing_count++ > 1)
					free(missinglast);
				missinglast = strdup(filename);
				FREENULL(filename);
			}
			if (missing_count == 1)
				LOGWARNING("%s(): skipped %s", __func__, missingfirst+rflen);
			else {
				LOGWARNING("%s(): skipped %d files from %s to %s",
					   __func__, missing_count, missingfirst+rflen, missinglast+rflen);
				FREENULL(missinglast);
			}
			FREENULL(missingfirst);
		}
	}

	while (!everyone_die) {
		K_RLOCK(breakqueue_free);
		counter = reload_done_breakqueue_store->count +
			  reload_breakqueue_store->count + reload_processing;
		K_RUNLOCK(breakqueue_free);
		if (counter == 0)
			break;
		cksleep_ms(142);
	}

	setnow(&now);
	diff = tvdiff(&now, &begin);
	if (diff == 0)
		diff = 1;
	ratio = (double)tot_sec / diff;

	snprintf(reload_buf, MAX_READ, "reload.%s.%"PRIu64, run, total);
	LOGQUE(reload_buf, true);
	LOGQUE(reload_buf, false);
	LOGWARNING("%s(): read %d file%s, total %"PRIu64" line%s %.2f/s (%.1fx)",
		   __func__,
		   processing, processing == 1 ? "" : "s",
		   total, total == 1 ? "" : "s", (total / diff), ratio);

	if (everyone_die)
		return true;

	ck_wlock(&fpm_lock);
	if (first_pool_message) {
		LOGEMERG("%s() reload didn't find the first "POOL_PROGNAME" queue '%.32s...",
			 __func__, st = safe_text(first_pool_message));
		FREENULL(st);
		FREENULL(first_pool_message);
	}
	ck_wunlock(&fpm_lock);

	seq_reloadmax();

	prereload = false;
	reloading = false;
	FREENULL(reload_buf);
	return ret;
}

static void process_queued(PGconn *conn, K_ITEM *wq_item)
{
	enum cmd_values cmdnum;
	WORKQUEUE *workqueue;
	MSGLINE *msgline;
	K_ITEM *ml_item;
	char *ans;

	DATA_WORKQUEUE(workqueue, wq_item);
	ml_item = workqueue->msgline_item;
	DATA_MSGLINE(msgline, ml_item);
	if (SEQALL_LOG) {
		K_ITEM *seqall;
		if (msgline->trf_root) {
			seqall = find_transfer(msgline->trf_root, SEQALL);
			if (seqall) {
				LOGNOTICE("%s() SEQALL %d %s",
					  __func__,
					  ckdb_cmds[msgline->which_cmds].cmd_val,
					  transfer_data(seqall));
			}
		}
	}

	/* Queued messages haven't had their seq number check yet
	 * This will return the entries cmdnum or DUP */
	cmdnum = process_seq(msgline);
	switch (cmdnum) {
		case CMD_DUPSEQ:
		// Already replied
		case CMD_AUTH:
		case CMD_ADDRAUTH:
		case CMD_HEARTBEAT:
			break;
		default:
			ans = ckdb_cmds[msgline->which_cmds].func(conn,
					msgline->cmd,
					msgline->id,
					&(msgline->now),
					workqueue->by,
					workqueue->code,
					workqueue->inet,
					&(msgline->cd),
					msgline->trf_root, false);
			FREENULL(ans);
			break;
	}

	free_msgline_data(ml_item, true);
	K_WLOCK(msgline_free);
	msgline_free->ram -= msgline->msgsiz;
	k_add_head(msgline_free, ml_item);
	K_WUNLOCK(msgline_free);

	K_WLOCK(workqueue_free);
	k_add_head(workqueue_free, wq_item);
	K_WUNLOCK(workqueue_free);
}

static void free_lost(SEQDATA *seqdata)
{
	if (seqdata->reload_lost) {
		K_WLOCK(seqtrans_free);
		k_list_transfer_to_head(seqdata->reload_lost, seqtrans_free);
		K_WUNLOCK(seqtrans_free);
		seqdata->reload_lost = NULL;
	}
}

static void *pqproc(void *arg)
{
	static pthread_t pqproc_pt[THREAD_LIMIT];
	static int n[THREAD_LIMIT];
	static bool running[THREAD_LIMIT];

	/* Process queued work - ensure pool0 is emptied first,
	 *  even if there is pending pool0 data being processed by breaker() */
	static bool pool0 = true;
	static tv_t wq_stt, wq_fin;

	PGconn *conn = NULL;
	K_ITEM *wq_item;
	time_t now = 0;
	bool switch_msg = false, complete_msg;
	int wqcount, wqgot;
	char buf[128];
	double min, sec = 0;
	SEQSET *seqset = NULL;
	SEQDATA *seqdata;
	K_ITEM *ss_item;
	ts_t when, when_add;
	int i, mythread, threads_delta = 0, done, tot, ret;

	if (!arg) {
		setnow(&wq_stt);

		for (i = 0; i < THREAD_LIMIT; i++) {
			n[i] = i;
			running[i] = false;
		}

		mythread = 0;
		running[0] = true;

		// Set to create the rest of the threads
		proc_queue_threads_delta = proc_queue_threads - 1;
	} else {
		mythread = *(int *)(arg);

		snprintf(buf, sizeof(buf), "db%s_p%02dqproc", dbcode, mythread);
		LOCK_INIT(buf);
		rename_proc(buf);
	}

	when_add.tv_sec = CMD_QUEUE_SLEEP_MS / 1000;
	when_add.tv_nsec = (CMD_QUEUE_SLEEP_MS % 1000) * 1000000;

	now = time(NULL);
	CKPQConn(&conn);
	wqgot = 0;

	// Override checking until pool0 is complete
	wqcount = -1;
	while (!everyone_die) {
		if (mythread && !running[mythread])
			break;

		wq_item = NULL;
		K_WLOCK(workqueue_free);
		if (mythread == 0 && proc_queue_threads_delta != 0) {
			threads_delta = proc_queue_threads_delta;
			proc_queue_threads_delta = 0;
		} else {
			if (pool0) {
				if (earlysock_left == 0) {
					pool0 = false;
					switch_msg = true;
				 } else {
					wq_item = k_unlink_head(pool0_workqueue_store);
					if (wq_item)
						earlysock_left--;
				}
			}
			if (!pool0) {
				wq_item = k_unlink_head(pool_workqueue_store);
				wqcount = pool_workqueue_store->count;
			}

			if (wqcount == 0 && wq_stt.tv_sec != 0L)
				setnow(&wq_fin);

			if (wq_item) {
				if (pool0)
					workqueue_proc0++;
				else
					workqueue_proc1++;
			}
		}
		K_WUNLOCK(workqueue_free);

		// TODO: deal with thread creation/shutdown failure
		if (threads_delta != 0) {
			if (threads_delta > 0) {
				// Add threads
				tot = 1;
				done = 0;
				for (i = 1; i < THREAD_LIMIT; i++) {
					if (!running[i]) {
						if (threads_delta > 0) {
							threads_delta--;
							running[i] = true;
							create_pthread(&(pqproc_pt[i]),
									pqproc,
									&(n[i]));
							done++;
							tot++;
						}
					} else
						tot++;
				}
				LOGWARNING("%s() created %d thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__, done,
					   (done == 1) ? EMPTY : "s", tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			} else {
				// Notify and wait for each to exit
				tot = 1;
				done = 0;
				for (i = THREAD_LIMIT - 1; i > 0; i--) {
					if (running[i]) {
						if (threads_delta < 0) {
							threads_delta++;
							LOGNOTICE("%s() stopping %d",
								  __func__, i);
							running[i] = false;
							join_pthread(pqproc_pt[i]);
							done++;
						} else
							tot++;
					}
				}
				LOGWARNING("%s() stopped %d thread%s total=%d"
#if LOCK_CHECK
					   " next_thread_id=%d"
#endif
					   , __func__, done,
					   (done == 1) ? EMPTY : "s", tot
#if LOCK_CHECK
					   , next_thread_id
#endif
					   );
			}
			threads_delta = 0;
			continue;
		}

		if (switch_msg) {
			switch_msg = false;
			LOGNOTICE("%s() pool0 complete, processed %"PRIu64,
				  __func__, workqueue_proc0);
		}

		/* Don't keep a connection for more than ~10s or ~10000 items
		 *  but always have a connection open */
		if ((time(NULL) - now) > 10 || wqgot > 10000) {
			CKPQFinish(&conn);
			CKPQConn(&conn);
			now = time(NULL);
			wqgot = 0;
		}

		if (wq_item) {
			wqgot++;
			process_queued(conn, wq_item);
			tick();
		}

		complete_msg = false;
		K_WLOCK(workqueue_free);
		if (wqcount == 0 && wq_stt.tv_sec != 0L) {
			sec = tvdiff(&wq_fin, &wq_stt);
			complete_msg = true;
			// Used as the flag to display the message once
			wq_stt.tv_sec = 0L;
			reload_queue_complete = true;
		}
		K_WUNLOCK(workqueue_free);
		if (complete_msg) {
			min = floor(sec / 60.0);
			sec -= min * 60.0;
			LOGWARNING("%s() pool queue completed %.0fm %.3fs",
				   __func__, min, sec);
		}

		/* Checked outside lock but only changed under lock
		 * This avoids taking out the lock repeatedly and the cleanup
		 *  code is ok if there is nothing to clean up
		 * This would normally only ever be done once */
		if (seqdata_reload_lost && reload_queue_complete) {
			/* Cleanup all the reload_lost stores since
			 *  they should no longer be needed and the ram
			 *  they use should be freed by the next cull */
			SEQLOCK();
			if (seqset_store->count > 0) {
				ss_item = STORE_WHEAD(seqset_store);
				while (ss_item) {
					DATA_SEQSET(seqset, ss_item);
					if (seqset->seqstt) {
						seqdata = &(seqset->seqdata[0]);
						for (i = 0; i < SEQ_MAX; i++) {
							free_lost(seqdata);
							seqdata++;
						}
					}
					ss_item = ss_item->next;
				}
			}
			seqdata_reload_lost = false;
			SEQUNLOCK();
		}

		if (!wq_item) {
			POOLINSTANCE_DATA_MSG();
			setnowts(&when);
			timeraddspec(&when, &when_add);

			mutex_lock(&wq_pool_waitlock);
			ret = cond_timedwait(&wq_pool_waitcond,
					     &wq_pool_waitlock, &when);
			if (ret == 0)
				wq_pool_wakes++;
			else if (errno == ETIMEDOUT)
				wq_pool_timeouts++;
			mutex_unlock(&wq_pool_waitlock);
		}
	}
	CKPQFinish(&conn);

	if (mythread == 0) {
		for (i = 1; i < THREAD_LIMIT; i++) {
			if (running[i]) {
				running[i] = false;
				LOGNOTICE("%s() waiting for %d", __func__, i);
				join_pthread(pqproc_pt[i]);
			}
		}
	}

	return NULL;
}

static void *listener(__maybe_unused void *arg)
{
	pthread_t log_pt;
	pthread_t sock_pt;
	pthread_t summ_pt;
	pthread_t mark_pt;
	pthread_t reload_break_pt;
	pthread_t cmd_break_pt;
	int bq, bqp, bqd, wq0count, wqcount;
	char ooo_buf[256];
	char buf[128];
	int cpus;
	struct breaker_setup reloader, cmder;

	pthread_detach(pthread_self());

	snprintf(buf, sizeof(buf), "db%s_p00qproc", dbcode);
	LOCK_INIT(buf);
	rename_proc(buf);

	if (reload_breakdown_threads <= 0) {
		cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if (cpus < 1)
			cpus = 1;
		reload_breakdown_threads = (int)(cpus / BREAKDOWN_RATIO) ? : 1;
	}
	cmd_breakdown_threads = reload_breakdown_threads;
	LOGWARNING("%s(): creating %d*2 breaker threads ...",
		   __func__, reload_breakdown_threads);

	breakdown_using_data = true;

	reloader.reload = true;
	reloader.thread = 0;
	create_pthread(&reload_break_pt, breaker, &reloader);

	cmder.reload = false;
	cmder.thread = 0;
	create_pthread(&cmd_break_pt, breaker, &cmder);

	if (no_data_log == false)
		create_pthread(&log_pt, logger, NULL);

	if (!confirm_sharesummary)
		create_pthread(&sock_pt, socksetup, NULL);

	create_pthread(&summ_pt, summariser, NULL);

	create_pthread(&mark_pt, marker, NULL);

	plistener_using_data = true;

	if (!setup_data()) {
		if (!everyone_die) {
			LOGEMERG("ABORTING");
			everyone_die = true;
		}
	}

	if (!everyone_die) {
		K_RLOCK(workqueue_free);
		wq0count = pool0_workqueue_store->count;
		wqcount = pool_workqueue_store->count;
		K_RUNLOCK(workqueue_free);
		K_RLOCK(breakqueue_free);
		bq = cmd_breakqueue_store->count;
		bqp = cmd_processing;
		bqd = cmd_done_breakqueue_store->count;
		K_RUNLOCK(breakqueue_free);

		LOGWARNING("reload shares OoO %s",
			   ooo_status(ooo_buf, sizeof(ooo_buf)));
		sequence_report(true);

		LOGWARNING("%s(): "DB_PROGNAME" ready, pool queue %d (%d/%d/%d/%d/%d)",
			   __func__, bq+bqp+bqd+wq0count+wqcount,
			   bq, bqp, bqd, wq0count, wqcount);

		/* Until startup_complete, the values should be ignored
		 * Setting them to 'now' means that they won't time out
		 *  until after startup_complete */
		ck_wlock(&last_lock);
		setnow(&last_heartbeat);
		copy_tv(&last_workinfo, &last_heartbeat);
		copy_tv(&last_share, &last_heartbeat);
		copy_tv(&last_share_acc, &last_heartbeat);
		copy_tv(&last_share_inv, &last_heartbeat);
		copy_tv(&last_auth, &last_heartbeat);
		ck_wunlock(&last_lock);

		startup_complete = true;

		LOGNOTICE("%s() processing pool0", __func__);
		pqproc(NULL);
	}

	LOGNOTICE("%s() exiting, pool0 %"PRIu64" pool %"PRIu64,
		  __func__, workqueue_proc0, workqueue_proc1);

	plistener_using_data = false;

	POOLINSTANCE_RESET_MSG("exiting");

	return NULL;
}

static bool make_keysummaries()
{
	K_TREE_CTX ctx[1];
	KEYSHARESUMMARY *keysharesummary;
	WORKMARKERS *workmarkers;
	K_ITEM *kss_item, *wm_item, *wm_last = NULL;
	tv_t proc_lock_stt, proc_lock_got, proc_lock_fin, now;
	int64_t kss_ready_wid;
	bool ok = false, pending;

	// Find the highest complete keysharesummary workinfoid
	kss_ready_wid = 0;
	K_RLOCK(keysharesummary_free);
	kss_item = first_in_ktree(keysharesummary_root, ctx);
	while (kss_item) {
		DATA_KEYSHARESUMMARY(keysharesummary, kss_item);
		if (keysharesummary->complete[0] == SUMMARY_COMPLETE &&
		    kss_ready_wid < keysharesummary->workinfoid) {
			kss_ready_wid = keysharesummary->workinfoid;
		}
		kss_item = next_in_ktree(ctx);
	}
	K_RUNLOCK(keysharesummary_free);

	if (kss_ready_wid > 0 && workmarkers_key_store->count > 0) {
		pending = true;
		wm_item = STORE_HEAD_NOLOCK(workmarkers_key_store);
		while (wm_item) {
			DATA_WORKMARKERS(workmarkers, wm_item);
			if (workmarkers->workinfoidend > kss_ready_wid)
				break;
			// move the item into the processing trees/store
			k_unlink_item_nolock(workmarkers_key_store, wm_item);
			K_WLOCK(workmarkers_free);
			add_to_ktree(workmarkers_root, wm_item);
			add_to_ktree(workmarkers_workinfoid_root, wm_item);
			k_add_head(workmarkers_store, wm_item);
			K_WUNLOCK(workmarkers_free);
			wm_item = STORE_HEAD_NOLOCK(workmarkers_key_store);
		}
	}

	pending = false;
	K_RLOCK(workmarkers_free);
	// Any workmarkers still pending in the key_store?
	if (workmarkers_key_store->count > 0)
		pending = true;
	wm_item = last_in_ktree(workmarkers_workinfoid_root, ctx);
	while (wm_item) {
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (!CURRENT(&(workmarkers->expirydate)))
			break;
		// find the oldest READY workmarker
		if (WMREADY(workmarkers->status))
			wm_last = wm_item;
		wm_item = prev_in_ktree(ctx);
	}
	K_RUNLOCK(workmarkers_free);

	// all false means we've finished
	if (!wm_last)
		return (pending || reloading);

	DATA_WORKMARKERS(workmarkers, wm_last);

	// Not ready to be processed yet
	if (kss_ready_wid < workmarkers->workinfoidend)
		return true;

	LOGDEBUG("%s() processing workmarkers %"PRId64"/%s/End %"PRId64"/"
		 "Stt %"PRId64"/%s/%s",
		 __func__, workmarkers->markerid, workmarkers->in_poolinstance,
		 workmarkers->workinfoidend, workmarkers->workinfoidstart,
		 workmarkers->description, workmarkers->status);

	setnow(&now);
	setnow(&proc_lock_stt);
	K_KLONGWLOCK(process_pplns_free);
	setnow(&proc_lock_got);
	ok = sharesummaries_to_markersummaries(NULL, workmarkers, by_default,
						(char *)__func__, inet_default,
						&now, NULL);
	K_WUNLOCK(process_pplns_free);
	setnow(&proc_lock_fin);
	LOGWARNING("%s() pplns lock time %.3f+%.3fs",
		   __func__, tvdiff(&proc_lock_got, &proc_lock_stt),
		   tvdiff(&proc_lock_fin, &proc_lock_got));

	return ok;
}

static void *keymarker(__maybe_unused void *arg)
{
	pthread_detach(pthread_self());
	char buf[128];
	bool ok = true;

	snprintf(buf, sizeof(buf), "db%s_%s", dbcode, __func__);
	LOCK_INIT(buf);
	rename_proc(buf);

	if (!everyone_die) {
		LOGWARNING("%s() Start key processing...", __func__);
		marker_using_data = true;
	}

	while (!everyone_die && ok) {
		if (!everyone_die)
			sleep(1);
		if (!everyone_die)
			ok = make_keysummaries();
	}

	marker_using_data = false;

	// No unprocessed workmarkers, or an error
	everyone_die = true;

	return NULL;
}

static void update_reload(WORKINFO *wi_stt, WORKINFO *wi_fin)
{
	K_TREE_CTX ctx[1];
	WORKMARKERS *workmarkers;
	K_ITEM *wm_item, *wm_prev;
	pthread_t keymark_pt;
	tv_t *start;
	tv_t finish;
	int counter;
	bool status_failure = false;

	/* Now that we know the workmarkers of interest,
	 *  switch them from MARKER_PROCESSED to MARKER_READY,
	 *  remove them and add them to key_store,
	 *  then remove all after them
	 * The markersummaries already exist
	 *  We are generating the missing keysummaries */
	K_WLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, ctx);
	while (wm_item) {
		wm_prev = prev_in_ktree(ctx);
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (CURRENT(&(workmarkers->expirydate))) {
			if (workmarkers->workinfoidstart > wi_fin->workinfoid) {
				remove_from_ktree(workmarkers_workinfoid_root,
						  wm_item);
				remove_from_ktree(workmarkers_root, wm_item);
				free_workmarkers_data(wm_item);
				k_unlink_item(workmarkers_store, wm_item);
				k_add_head(workmarkers_free, wm_item);
			} else if (workmarkers->workinfoidstart >=
				   wi_stt->workinfoid) {
				if (!WMPROCESSED(workmarkers->status)) {
					status_failure = true;
					LOGERR("%s() workmarker %"PRId64
						" invalid status '%s' != %c",
						__func__,
						workmarkers->markerid,
						workmarkers->status,
						MARKER_PROCESSED);
				} else {
					remove_from_ktree(workmarkers_workinfoid_root,
							  wm_item);
					remove_from_ktree(workmarkers_root, wm_item);
					k_unlink_item(workmarkers_store, wm_item);
					STRNCPY(workmarkers->status, MARKER_READY_STR);
					// key_store will be in workinfoid ascending order
					k_add_head(workmarkers_key_store, wm_item);
				}
			} else
				break;
		}
		wm_item = wm_prev;
	}
	K_WUNLOCK(workmarkers_free);

	if (status_failure) {
		LOGERR("%s() Aborting ...", __func__);
		return;
	}

	create_pthread(&keymark_pt, keymarker, NULL);

	start = &(wi_stt->createdate);
	if (start->tv_sec < DATE_BEGIN)
		start = (tv_t *)&date_begin;

	copy_tv(&finish, &(wi_fin->createdate));
	// include the reload file after wi_fin
	finish.tv_sec += ROLL_S;

	reload_from(start, &finish);

	// wait for all loaded data to be used
	while (!everyone_die) {
		K_RLOCK(breakqueue_free);
		counter = reload_done_breakqueue_store->count +
			  reload_breakqueue_store->count + reload_processing;
		K_RUNLOCK(breakqueue_free);
		if (counter == 0)
			break;
		cksleep_ms(142);
	}

	while (!everyone_die)
		cksleep_ms(142);
}

static void update_check(int64_t markerid_stt, int64_t markerid_fin)
{
	K_ITEM *wm_stt_item, *wm_fin_item, *wi_stt_item, *wi_fin_item;
	char buf[DATE_BUFSIZ+1], buf2[DATE_BUFSIZ+1];
	WORKMARKERS *wm_stt = NULL, *wm_fin = NULL;
	WORKINFO *wi_stt = NULL, *wi_fin = NULL;
	tv_t up_stt, up_fin;
	double min, sec;

	K_RLOCK(workmarkers_free);
	wm_stt_item = find_workmarkerid(markerid_stt, false, MARKER_PROCESSED);
	wm_fin_item = find_workmarkerid(markerid_fin, false, MARKER_PROCESSED);
	K_RUNLOCK(workmarkers_free);

	if (!wm_stt_item || !wm_fin_item) {
		if (!wm_stt_item) {
			LOGERR("%s() unknown start markerid %"PRId64,
				__func__, markerid_stt);
		}
		if (!wm_fin_item) {
			LOGERR("%s() unknown finish markerid %"PRId64,
				__func__, markerid_fin);
		}
		return;
	}

	DATA_WORKMARKERS(wm_stt, wm_stt_item);
	DATA_WORKMARKERS(wm_fin, wm_fin_item);

	key_wi_stt = wm_stt->workinfoidstart;
	key_wi_fin = wm_fin->workinfoidend;

	wi_stt_item = find_workinfo(key_wi_stt, NULL);
	wi_fin_item = find_workinfo(key_wi_fin, NULL);

	if (!wi_stt_item || !wi_fin_item) {
		if (!wi_stt_item) {
			LOGEMERG("%s() missing workinfoid data! %"PRId64
				 " for start markerid %"PRId64,
				 __func__, key_wi_stt, markerid_stt);
		}
		if (!wi_fin_item) {
			LOGEMERG("%s() missing workinfoid data! %"PRId64
				 " for finish markerid %"PRId64,
				 __func__, key_wi_fin, markerid_fin);
		}
		return;
	}

	DATA_WORKINFO(wi_stt, wi_stt_item);
	DATA_WORKINFO(wi_fin, wi_fin_item);

	tv_to_buf(&(wi_stt->createdate), buf, sizeof(buf));
	tv_to_buf(&(wi_fin->createdate), buf2, sizeof(buf2));
	LOGWARNING("%s() processing from start markerid %"PRId64" %s to "
		   "finish markerid %"PRId64" %s",
		   __func__, markerid_stt, buf, markerid_fin, buf2);

	setnow(&up_stt);

	update_reload(wi_stt, wi_fin);

	POOLINSTANCE_RESET_MSG("reload");
	setnow(&up_fin);
	sec = tvdiff(&up_fin, &up_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("update complete %.0fm %.3fs", min, sec);
}

static void update_keysummary()
{
	int64_t markerid_stt, markerid_fin;
	char *tmp, *minus;
	tv_t db_stt, db_fin;
	pthread_t reload_break_pt;
	pthread_t cmd_break_pt;
	pthread_t sock_pt;
	double min, sec;
	int cpus;
	struct breaker_setup reloader, cmder;

	// Simple value check to abort early
	if (!key_range || !(*key_range)) {
		LOGEMERG("%s() -K option can't be blank", __func__);
		return;
	}

	switch(tolower(key_range[0])) {
		case 'm':
			tmp = strdup(key_range);
			minus = strchr(tmp+1, '-');
			if (!minus || minus == tmp+1) {
				LOGEMERG("%s() invalid workmarker range '%s' "
					 "- must be %cNNN-MMM",
					 __func__, key_range, tolower(key_range[0]));
				return;
			}
			*(minus++) = '\0';
			markerid_stt = atoll(tmp+1);
			if (markerid_stt <= 0) {
				LOGEMERG("%s() invalid markerid start in '%s' "
					 "- must be >0",
					 __func__, key_range);
				return;
			}
			markerid_fin = atoll(minus);
			if (markerid_fin <= 0) {
				LOGEMERG("%s() invalid markerid finish in '%s' "
					 "- must be >0",
					 __func__, key_range);
				return;
			}
			if (markerid_fin < markerid_stt) {
				LOGEMERG("%s() invalid markerid range in '%s' "
					 "- finish < start",
					 __func__, key_range);
				return;
			}
			free(tmp);
			break;
		default:
			LOGEMERG("%s() unknown key range '%c' in '%s'",
				 __func__, key_range[0], key_range);
			return;
	}

	LOCK_INIT("dbk_updater");
	rename_proc("dbk_updater");

	if (reload_breakdown_threads <= 0) {
		cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if (cpus < 1)
			cpus = 1;
		reload_breakdown_threads = (int)(cpus / BREAKDOWN_RATIO) ? : 1;
	}
	// Only needs one
	cmd_breakdown_threads = 1;
	LOGWARNING("%s(): creating %d+1 breaker threads ...",
		   __func__, reload_breakdown_threads);

	breakdown_using_data = true;

	reloader.reload = true;
	reloader.thread = 0;
	create_pthread(&reload_break_pt, breaker, &reloader);

	cmder.reload = false;
	cmder.thread = 0;
	create_pthread(&cmd_break_pt, breaker, &cmder);

	workmarkers_key_store = k_new_store(workmarkers_free);

	setnow(&db_stt);

	create_pthread(&sock_pt, socksetup, NULL);

	if (!getdata1() || everyone_die)
		return;

	db_users_complete = true;

	if (!getdata2() || everyone_die)
		return;

	if (dbload_workinfoid_start != -1) {
		LOGWARNING("WARNING: dbload starting at workinfoid %"PRId64,
			   dbload_workinfoid_start);
	}

	if (!getdata3() || everyone_die)
		return;

	POOLINSTANCE_RESET_MSG("dbload");
	setnow(&db_fin);
	sec = tvdiff(&db_fin, &db_stt);
	min = floor(sec / 60.0);
	sec -= min * 60.0;
	LOGWARNING("dbload complete %.0fm %.3fs", min, sec);

	db_load_complete = true;

	update_check(markerid_stt, markerid_fin);
}
#if 0
/* TODO: This will be way faster traversing both trees simultaneously
 *  rather than traversing one and searching the other, then repeating
 *  in reverse. Will change it later */
static void compare_summaries(K_TREE *leftsum, char *leftname,
			      K_TREE *rightsum, char *rightname,
			      bool show_missing, bool show_diff)
{
	K_TREE_CTX ctxl[1], ctxr[1];
	K_ITEM look, *lss, *rss;
	char cd_buf[DATE_BUFSIZ];
	SHARESUMMARY looksharesummary, *l_ss, *r_ss;
	uint64_t total, ok, missing, diff;
	uint64_t first_used = 0, last_used = 0;
	int64_t miss_first = 0, miss_last = 0;
	tv_t miss_first_cd = {0,0}, miss_last_cd = {0,0};
	int64_t diff_first = 0, diff_last = 0;
	tv_t diff_first_cd = {0,0}, diff_last_cd = {0,0};
	char cd_buf1[DATE_BUFSIZ], cd_buf2[DATE_BUFSIZ];

	looksharesummary.workinfoid = confirm_first_workinfoid;
	looksharesummary.userid = -1;
	looksharesummary.workername = EMPTY;
	INIT_SHARESUMMARY(&look);
	look.data = (void *)(&looksharesummary);

	total = ok = missing = diff = 0;
	lss = find_after_in_ktree(leftsum, &look, ctxl);
	while (lss) {
		DATA_SHARESUMMARY(l_ss, lss);
		if (l_ss->workinfoid > confirm_last_workinfoid)
			break;

		total++;

		if (first_used == 0)
			first_used = l_ss->workinfoid;
		last_used = l_ss->workinfoid;

		rss = find_in_ktree(rightsum, lss, ctxr);
		DATA_SHARESUMMARY_NULL(r_ss, rss);
		if (!rss) {
			missing++;
			if (miss_first == 0) {
				miss_first = l_ss->workinfoid;
				copy_tv(&miss_first_cd, &(l_ss->createdate));
			}
			miss_last = l_ss->workinfoid;
			copy_tv(&miss_last_cd, &(l_ss->createdate));
			if (show_missing) {
				LOGERR("ERROR: %s %"PRId64"/%s/%ld,%ld %.19s missing from %s",
					leftname,
					l_ss->workinfoid,
					l_ss->workername,
					l_ss->createdate.tv_sec,
					l_ss->createdate.tv_usec,
					tv_to_buf(&(l_ss->createdate), cd_buf, sizeof(cd_buf)),
					rightname);
			}
		} else if (r_ss->diffacc != l_ss->diffacc) {
			diff++;
			if (show_diff) {
				if (diff_first == 0) {
					diff_first = l_ss->workinfoid;
					copy_tv(&diff_first_cd, &(l_ss->createdate));
				}
				diff_last = l_ss->workinfoid;
				copy_tv(&diff_last_cd, &(l_ss->createdate));
				LOGERR("ERROR: %"PRId64"/%s/%ld,%ld %.19s - diffacc: %s: %.0f %s: %.0f",
					l_ss->workinfoid,
					l_ss->workername,
					l_ss->createdate.tv_sec,
					l_ss->createdate.tv_usec,
					tv_to_buf(&(l_ss->createdate), cd_buf, sizeof(cd_buf)),
					leftname,
					l_ss->diffacc,
					rightname,
					r_ss->diffacc);
			}
		} else
			ok++;

		lss = next_in_ktree(ctxl);
	}

	LOGERR("RESULT: %s->%s Total %"PRIu64" workinfoid %"PRId64"-%"PRId64
		" %s missing: %"PRIu64" different: %"PRIu64,
		leftname, rightname, total, first_used, last_used,
		rightname, missing, diff);
	if (miss_first) {
		tv_to_buf(&miss_first_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(&miss_last_cd, cd_buf2, sizeof(cd_buf2));
		LOGERR(" workinfoid range for missing: %"PRId64"-%"PRId64
			" (%s .. %s)",
			miss_first, miss_last, cd_buf1, cd_buf2);
	}
	if (show_diff && diff_first) {
		tv_to_buf(&diff_first_cd, cd_buf1, sizeof(cd_buf1));
		tv_to_buf(&diff_last_cd, cd_buf2, sizeof(cd_buf2));
		LOGERR(" workinfoid range for differences: %"PRId64"-%"PRId64
			" (%s .. %s)",
			diff_first, diff_last, cd_buf1, cd_buf2);
	}
}
#endif

/* TODO: have a seperate option to find/store missing workinfo/shares/etc
 *  from the reload files, in a supplied UTC time range
 *  since there is no automatic way to get them in the DB after later ones
 *  have been stored e.g. a database failure/recovery or short outage but
 *  later workinfos/shares/etc have been stored so earlier ones will not be
 *  picked up by the reload
 * However, will need to deal with, via reporting an error and/or abort,
 *  if a stored workinfoid is in a range that has already been paid
 *  and the payment is now wrong */
static void confirm_reload()
{
#if 0
	TODO: redo this using workmarkers

	K_TREE *sharesummary_workinfoid_save;
	__maybe_unused K_TREE *sharesummary_save;
	__maybe_unused K_TREE *workinfo_save;
	K_ITEM b_look, wi_look, *wi_item, *wif_item, *wil_item;
	K_ITEM *b_begin_item, *b_end_item;
	K_ITEM *ss_begin_item, *ss_end_item;
	WORKINFO lookworkinfo, *workinfo;
	BLOCKS lookblocks, *b_blocks, *e_blocks;
	SHARESUMMARY *b_ss, *e_ss;
	K_TREE_CTX ctx[1];
	char buf[DATE_BUFSIZ+1];
	char *first_reason;
	char *last_reason;
	char cd_buf[DATE_BUFSIZ];
	char first_buf[64], last_buf[64];
	char *filename;
	tv_t start;
	FILE *fp;

// TODO: // abort reload when we get an age after the end of a workinfo after the Xs after the last workinfo before the end

	wif_item = first_in_ktree(workinfo_root, ctx);
	wil_item = last_in_ktree(workinfo_root, ctx);

	if (!wif_item || !wil_item) {
		LOGWARNING("%s(): DB contains no workinfo records", __func__);
		return;
	}

	DATA_WORKINFO(workinfo, wif_item);
	tv_to_buf(&(workinfo->createdate), cd_buf, sizeof(cd_buf));
	LOGWARNING("%s(): DB first workinfoid %"PRId64" %s",
		   __func__, workinfo->workinfoid, cd_buf);

	DATA_WORKINFO(workinfo, wil_item);
	tv_to_buf(&(workinfo->createdate), cd_buf, sizeof(cd_buf));
	LOGWARNING("%s(): DB last workinfoid %"PRId64" %s",
		   __func__, workinfo->workinfoid, cd_buf);

	b_begin_item = first_in_ktree(blocks_root, ctx);
	b_end_item = last_in_ktree(blocks_root, ctx);

	if (!b_begin_item || !b_end_item)
		LOGWARNING("%s(): DB contains no blocks :(", __func__);
	else {
		DATA_BLOCKS(b_blocks, b_begin_item);
		DATA_BLOCKS(e_blocks, b_end_item);
		tv_to_buf(&(b_blocks->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB first block %d/%"PRId64" %s",
			   __func__,
			   b_blocks->height,
			   b_blocks->workinfoid,
			   cd_buf);
		tv_to_buf(&(e_blocks->createdate),
			  cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB last block %d/%"PRId64" %s",
			   __func__,
			   e_blocks->height,
			   e_blocks->workinfoid,
			   cd_buf);
	}

	ss_begin_item = first_in_ktree(sharesummary_workinfoid_root, ctx);
	ss_end_item = last_in_ktree(sharesummary_workinfoid_root, ctx);

	if (!ss_begin_item || !ss_end_item)
		LOGWARNING("%s(): DB contains no sharesummary records", __func__);
	else {
		DATA_SHARESUMMARY(b_ss, ss_begin_item);
		DATA_SHARESUMMARY(e_ss, ss_end_item);
		tv_to_buf(&(b_ss->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB first sharesummary %"PRId64"/%s %s",
			   __func__,
			   b_ss->workinfoid,
			   b_ss->workername,
			   cd_buf);
		tv_to_buf(&(e_ss->createdate), cd_buf, sizeof(cd_buf));
		LOGWARNING("%s(): DB last sharesummary %"PRId64"/%s %s",
			   __func__,
			   e_ss->workinfoid,
			   e_ss->workername,
			   cd_buf);
	}

	/* The first workinfo we should process
	 * With no y records we should start from the beginning (0)
	 * With any y records, we should start from the oldest of: y+1 and a
	 *  which can produce y records as reload a's, if a is used */
	if (dbstatus.newest_workinfoid_y > 0) {
		confirm_first_workinfoid = dbstatus.newest_workinfoid_y + 1;
		if (confirm_first_workinfoid > dbstatus.oldest_workinfoid_a) {
			confirm_first_workinfoid = dbstatus.oldest_workinfoid_a;
			first_reason = "oldest aged";
		} else
			first_reason = "newest confirmed+1";
	} else
		first_reason = "0 - none confirmed";

	/* The last workinfo we should process
	 * The reason for going past the last 'a' up to before
	 *  the first 'n' is in case there were shares missed between them -
	 *  but that should only be the case with a code bug -
	 *  so it checks that */
	if (dbstatus.newest_workinfoid_a > 0) {
		confirm_last_workinfoid = dbstatus.newest_workinfoid_a;
		last_reason = "newest aged";
	}
	if (confirm_last_workinfoid < dbstatus.oldest_workinfoid_n) {
		confirm_last_workinfoid = dbstatus.oldest_workinfoid_n - 1;
		last_reason = "oldest new-1";
	}
	if (confirm_last_workinfoid == 0) {
		LOGWARNING("%s(): there are no unconfirmed sharesummary records in the DB",
			   __func__);
		return;
	}

	INIT_BLOCKS(&b_look);
	INIT_WORKINFO(&wi_look);

	// Do this after above code for checking and so we can use the results
	if (confirm_range && *confirm_range) {
		switch(tolower(confirm_range[0])) {
			case 'b':
				// First DB record of the block = or after confirm_block
				lookblocks.height = confirm_block;
				lookblocks.blockhash[0] = '\0';
				b_look.data = (void *)(&lookblocks);
				b_end_item = find_after_in_ktree(blocks_root, &b_look, ctx);
				if (!b_end_item) {
					LOGWARNING("%s(): no DB block height found matching or after %d",
						   __func__, confirm_block);
					return;
				}
				DATA_BLOCKS(e_blocks, b_end_item);
				confirm_last_workinfoid = e_blocks->workinfoid;

				// Now find the last DB record of the previous block
				lookblocks.height = e_blocks->height;
				lookblocks.blockhash[0] = '\0';
				b_look.data = (void *)(&lookblocks);
				b_begin_item = find_before_in_ktree(blocks_root, &b_look, ctx);
				if (!b_begin_item)
					confirm_first_workinfoid = 0;
				else {
					DATA_BLOCKS(b_blocks, b_begin_item);
					// First DB record of the block 'begin'
					lookblocks.height = b_blocks->height;
					lookblocks.blockhash[0] = '\0';
					b_look.data = (void *)(&lookblocks);
					b_begin_item = find_after_in_ktree(blocks_root, &b_look, ctx);
					// Not possible
					if (!b_begin_item)
						confirm_first_workinfoid = 0;
					else {
						DATA_BLOCKS(b_blocks, b_begin_item);
						confirm_first_workinfoid = b_blocks->workinfoid;
					}
				}
				snprintf(first_buf, sizeof(first_buf),
					 "block %d",
					 b_begin_item ? b_blocks->height : 0);
				first_reason = first_buf;
				snprintf(last_buf, sizeof(last_buf),
					 "block %d",
					 e_blocks->height);
				last_reason = last_buf;
				break;
			case 'i':
				LOGWARNING("%s(): info displayed - exiting", __func__);
				exit(0);
			case 'c':
			case 'r':
				confirm_first_workinfoid = confirm_range_start;
				confirm_last_workinfoid = confirm_range_finish;
				first_reason = "start range";
				last_reason = "end range";
				break;
			case 'w':
				confirm_first_workinfoid = confirm_range_start;
				// last from default
				if (confirm_last_workinfoid < confirm_first_workinfoid) {
					LOGWARNING("%s(): no unconfirmed sharesummary records before start",
						   __func__);
					return;
				}
				first_reason = "start range";
				break;
			default:
				quithere(1, "Code fail");
		}
	}

	/* These two below find the closest valid workinfo to the ones chosen
	 * however we still use the original ones chosen to select/ignore data */

	/* Find the workinfo before confirm_first_workinfoid+1
	 * i.e. the one we want or the previous before it */
	lookworkinfo.workinfoid = confirm_first_workinfoid + 1;
	lookworkinfo.expirydate.tv_sec = date_begin.tv_sec;
	lookworkinfo.expirydate.tv_usec = date_begin.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	wi_item = find_before_in_ktree(workinfo_root, &wi_look, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		copy_tv(&start, &(workinfo->createdate));
		if (workinfo->workinfoid != confirm_first_workinfoid) {
			LOGWARNING("%s() start workinfo not found ... using time of %"PRId64,
				   __func__, workinfo->workinfoid);
		}
	} else {
		if (confirm_first_workinfoid == 0) {
			DATE_ZERO(&start);
			LOGWARNING("%s() no start workinfo found ... "
				   "using time 0", __func__);
		} else {
			// Abort, otherwise reload will reload all log files
			LOGERR("%s(): Start workinfoid doesn't exist, "
			       "use 0 to mean from the beginning of time",
			       __func__);
			return;
		}
	}

	/* Find the workinfo after confirm_last_workinfoid-1
	 * i.e. the one we want or the next after it */
	lookworkinfo.workinfoid = confirm_last_workinfoid - 1;
	lookworkinfo.expirydate.tv_sec = date_eot.tv_sec;
	lookworkinfo.expirydate.tv_usec = date_eot.tv_usec;
	wi_look.data = (void *)(&lookworkinfo);
	wi_item = find_after_in_ktree(workinfo_root, &wi_look, ctx);
	if (wi_item) {
		DATA_WORKINFO(workinfo, wi_item);
		/* Now find the one after the one we found to determine the
		 * confirm_finish timestamp */
		lookworkinfo.workinfoid = workinfo->workinfoid;
		lookworkinfo.expirydate.tv_sec = date_eot.tv_sec;
		lookworkinfo.expirydate.tv_usec = date_eot.tv_usec;
		wi_look.data = (void *)(&lookworkinfo);
		wi_item = find_after_in_ktree(workinfo_root, &wi_look, ctx);
		if (wi_item) {
			DATA_WORKINFO(workinfo, wi_item);
			copy_tv(&confirm_finish, &(workinfo->createdate));
			confirm_finish.tv_sec += WORKINFO_AGE;
		} else {
			confirm_finish.tv_sec = date_eot.tv_sec;
			confirm_finish.tv_usec = date_eot.tv_usec;
		}
	} else {
		confirm_finish.tv_sec = date_eot.tv_sec;
		confirm_finish.tv_usec = date_eot.tv_usec;
		LOGWARNING("%s() no finish workinfo found ... using EOT", __func__);
	}

	LOGWARNING("%s() workinfo range: %"PRId64" to %"PRId64" ('%s' to '%s')",
		   __func__, confirm_first_workinfoid, confirm_last_workinfoid,
		   first_reason, last_reason);

	tv_to_buf(&start, buf, sizeof(buf));
	LOGWARNING("%s() load start timestamp %s", __func__, buf);
	tv_to_buf(&confirm_finish, buf, sizeof(buf));
	LOGWARNING("%s() load finish timestamp %s", __func__, buf);

	/* Save the DB info for comparing to the reload
	 * i.e. the reload will generate from scratch all the
	 * sharesummaries and workinfo from the CCLs */
	sharesummary_workinfoid_save = sharesummary_workinfoid_root;
	sharesummary_save = sharesummary_root;
	workinfo_save = workinfo_root;

	sharesummary_workinfoid_root = new_ktree(cmp_sharesummary_workinfoid);
	sharesummary_root = new_ktree(cmp_sharesummary);
	workinfo_root = new_ktree(cmp_workinfo);

	if (start.tv_sec < DATE_BEGIN) {
		start.tv_sec = DATE_BEGIN;
		start.tv_usec = 0L;
		filename = hour_filename(restorefrom, restorename, start.tv_sec);
		fp = fopen(filename, "re");
		if (fp)
			fclose(fp);
		else {
			mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
			int fd = open(filename, O_CREAT|O_RDONLY, mode);
			if (fd == -1) {
				int ern = errno;
				quithere(1, "Couldn't create '%s' (%d) %s",
					 filename, ern, strerror(ern));
			}
			close(fd);
		}
		free(filename);
	}

	if (!reload_from(&start, &date_eot)) {
		LOGEMERG("%s() ABORTING from reload_from()", __func__);
		return;
	}

	if (confirm_check_createdate) {
		LOGERR("%s(): CCL mismatches %"PRId64"/%"PRId64" %.6f/%.6f unordered "
			"%"PRId64"/%"PRId64" %.6f",
			__func__, ccl_mismatch, ccl_mismatch_abs,
			ccl_mismatch_min, ccl_mismatch_max,
			ccl_unordered, ccl_unordered_abs, ccl_unordered_most);
		return;
	}

	compare_summaries(sharesummary_workinfoid_save, "DB",
			  sharesummary_workinfoid_root, "ReLoad",
			  true, true);
	compare_summaries(sharesummary_workinfoid_root, "ReLoad",
			  sharesummary_workinfoid_save, "DB",
			  true, false);
#endif
}

// TODO: handle workmarkers/markersummaries
static void confirm_summaries()
{
	pthread_t log_pt;
	char *range, *minus;

	// Simple value check to abort early
	if (confirm_range && *confirm_range) {
		switch(tolower(confirm_range[0])) {
			case 'b':
			case 'c':
			case 'r':
			case 'w':
				if (strlen(confirm_range) < 2) {
					LOGEMERG("%s() invalid confirm range length '%s'",
						 __func__, confirm_range);
					return;
				}
				break;
			case 'i':
				break;
			default:
				LOGEMERG("%s() invalid confirm range '%s'",
					 __func__, confirm_range);
				return;
		}
		switch(tolower(confirm_range[0])) {
			case 'b':
				confirm_block = atoi(confirm_range+1);
				if (confirm_block <= 0) {
					LOGEMERG("%s() invalid confirm block '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				break;
			case 'i':
				break;
			case 'c':
				confirm_check_createdate = true;
			case 'r':
				range = strdup(confirm_range);
				minus = strchr(range+1, '-');
				if (!minus || minus == range+1) {
					LOGEMERG("%s() invalid confirm range '%s' - must be %cNNN-MMM",
						 __func__, confirm_range, tolower(confirm_range[0]));
					return;
				}
				*(minus++) = '\0';
				confirm_range_start = atoll(range+1);
				if (confirm_range_start <= 0) {
					LOGEMERG("%s() invalid confirm start in '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				confirm_range_finish = atoll(minus);
				if (confirm_range_finish <= 0) {
					LOGEMERG("%s() invalid confirm finish in '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
				if (confirm_range_finish < confirm_range_start) {
					LOGEMERG("%s() invalid confirm range in '%s' - finish < start",
						 __func__, confirm_range);
					return;
				}
				free(range);
				dbload_workinfoid_start = confirm_range_start - 1;
				dbload_workinfoid_finish = confirm_range_finish + 1;
				break;
			case 'w':
				confirm_range_start = atoll(confirm_range+1);
				if (confirm_range_start <= 0) {
					LOGEMERG("%s() invalid confirm start '%s' - must be >0",
						 __func__, confirm_range);
					return;
				}
		}
	}

	create_pthread(&log_pt, logger, NULL);

	LOCK_INIT("dby_confirmer");
	rename_proc("dby_confirmer");

	if (!getdata1()) {
		LOGEMERG("%s() ABORTING from getdata1()", __func__);
		return;
	}

	if (!getdata2()) {
		LOGEMERG("%s() ABORTING from getdata2()", __func__);
		return;
	}

	if (!getdata3()) {
		LOGEMERG("%s() ABORTING from getdata3()", __func__);
		return;
	}

	confirm_reload();
}

static void check_restore_dir(char *name)
{
	struct stat statbuf;

	if (!restorefrom) {
		restorefrom = strdup("logs");
		if (!restorefrom)
			quithere(1, "OOM");
	}

	if (!(*restorefrom))
		quit(1, "ERR: '-r dir' can't be empty");

	trail_slash(&restorefrom);

	if (stat(restorefrom, &statbuf))
		quit(1, "ERR: -r '%s' directory doesn't exist", restorefrom);

	restorename = name;
}

static struct option long_options[] = {
	// script to call when alerts happen
	{ "alert",		required_argument,	0,	'a' },
	// allow reload files to contain non-pool data
	{ "allow-all",		no_argument,		0,	'A' },
	// workinfoid to start shares_fill() default is 1 day
	{ "shares-begin",	required_argument,	0,	'b' },
	// override calculated value
	{ "breakdown-threads",	required_argument,	0,	'B' },
	{ "config",		required_argument,	0,	'c' },
	{ "cmd-listener-threads", required_argument,	0,	'C' },
	{ "dbname",		required_argument,	0,	'd' },
	{ "minsdiff",		required_argument,	0,	'D' },
	{ "free",		required_argument,	0,	'f' },
	// generate = enable payout pplns auto generation
	{ "generate",		no_argument,		0,	'g' },
	{ "help",		no_argument,		0,	'h' },
	{ "pool-instance",	required_argument,	0,	'i' },
	// only use 'I' for reloading lots of known valid data via asicseer-db,
	// DON'T use when connected to asicseer-pool
	{ "ignore-seq",		required_argument,	0,	'I' },
	{ "killold",		no_argument,		0,	'k' },
	// Generate old keysummary records
	{ "key",		required_argument,	0,	'K' },
	{ "loglevel",		required_argument,	0,	'l' },
	{ "logpath",		required_argument,	0,	'L' },
	// marker = enable mark/workmarker/markersummary auto generation
	{ "marker",		no_argument,		0,	'm' },
	{ "markstart",		required_argument,	0,	'M' },
	{ "name",		required_argument,	0,	'n' },
	// base socket name to use instead of 'listener'
	{ "listener",		required_argument,	0,	'N' },
	// process name to use instead of "main"
	{ "process",		required_argument,	0,	'o' },
	{ "dbpass",		required_argument,	0,	'p' },
	{ "btc-pass",		required_argument,	0,	'P' },
	{ "reload-queue-limit",	required_argument,	0,	'q' },
	{ "queue-threads",	required_argument,	0,	'Q' },
	{ "pool-logdir",	required_argument,	0,	'r' },
	{ "logdir",		required_argument,	0,	'R' },
	{ "sockdir",		required_argument,	0,	's' },
	{ "btc-server",		required_argument,	0,	'S' },
	{ "btc-timeout",	required_argument,	0,	't' },
	// Don't store the workinfo txn tree in the DB
	{ "no-txn-store",	no_argument,		0,	'T' },
	{ "dbuser",		required_argument,	0,	'u' },
	{ "btc-user",		required_argument,	0,	'U' },
	{ "version",		no_argument,		0,	'v' },
	{ "workinfoid",		required_argument,	0,	'w' },
	// Disable writing to the db-log file (for testing environments)
	{ "no-db-log",		no_argument,		0,	'x' },
	// force disable the exclusive db load locks
	{ "no-exclusive",	required_argument,	0,	'X' },
	{ "confirm",		no_argument,		0,	'y' },
	{ "confirmrange",	required_argument,	0,	'Y' },
	{ 0, 0, 0, 0 }
};

static void sighandler(int sig)
{
	LOGWARNING("Received signal %d, shutting down", sig);
	everyone_die = true;
	cksleep_ms(420);
	exit(0);
}

int main(int argc, char **argv)
{
	struct sigaction handler;
	char *btc_user = "user";
	char *btc_pass = "p";
	pthread_t f_iomsgs_pt, c_iomsgs_pt;
	char buf[512], lbuf[64];
	int c, ret, i = 0, j;
	size_t len;
	char *kill;
	tv_t now;

	setnow(&ckdb_start);

	printf("ASICseer-DB Master V%s (C) Kano & ASICseer (see source code)\n", CKDB_VERSION);

	feenableexcept(FE_DIVBYZERO | FE_INVALID | FE_OVERFLOW);

	// Zombie no go zone
	signal(SIGCHLD, SIG_IGN);

	global_ckp = &ckp;
	memset(&ckp, 0, sizeof(ckp));
	memset(&ckpweb, 0, sizeof(ckp));
	memset(&ckpcmd, 0, sizeof(ckp));
	ckp.loglevel = LOG_NOTICE;

	while ((c = getopt_long(argc, argv, "a:Ab:B:c:C:d:D:f:ghi:IkK:l:L:mM:n:N:o:p:P:q:Q:r:R:s:S:t:Tu:U:vw:xXyY:", long_options, &i)) != -1) {
		switch(c) {
			case '?':
			case ':':
				quit(1, "exiting");
				break;
			case 'a':
				len = strlen(optarg);
				if (len > MAX_ALERT_CMD)
					quit(1, "db_alert_cmd (%d) too large,"
						" limit %d",
						(int)len, MAX_ALERT_CMD);
				ckdb_alert_cmd = strdup(optarg);
				break;
			case 'A':
				reload_access = ACCESS_ALL;
				break;
			case 'b':
				{
					int64_t beg = atoll(optarg);
					if (beg < 0) {
						quit(1, "Invalid shares begin "
						     "%"PRId64" - must be >= 0",
						     beg);
					}
					shares_begin = beg;
				}
				break;
			case 'B':
				{
					int bt = atoi(optarg);
					if (bt < 1 || bt > THREAD_LIMIT) {
						quit(1, "Invalid breakdown "
						     "thread count %d "
						     "- must be >0 and <=%d",
						     bt, THREAD_LIMIT);
					}
					reload_breakdown_threads = bt;
				}
				break;
			case 'c':
				ckp.config = strdup(optarg);
				break;
			case 'C':
				{
					int cl = atoi(optarg);
					if (cl < 1 || cl > THREAD_LIMIT) {
						quit(1, "Invalid listener "
						     "thread count %d "
						     "- must be >0 and <=%d",
						     cl, THREAD_LIMIT);
					}
					cmd_listener_threads = cl;
				}
				break;
			case 'd':
				db_name = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'D':
				share_min_sdiff = atof(optarg);
				if (share_min_sdiff < 0) {
					quit(1, "Invalid share_min_sdiff '%s' "
						"must be >= 0", optarg);
				}
				break;
			case 'f':
				if (strcasecmp(optarg, FREE_MODE_ALL_STR) == 0)
					free_mode = FREE_MODE_ALL;
				else if (strcasecmp(optarg, FREE_MODE_NONE_STR) == 0)
					free_mode = FREE_MODE_NONE;
				else if (strcasecmp(optarg, FREE_MODE_FAST_STR) == 0)
					free_mode = FREE_MODE_FAST;
				else {
					quit(1, "Invalid free '%s' must be: "
						FREE_MODE_ALL_STR", "
						FREE_MODE_NONE_STR" or "
						FREE_MODE_FAST_STR,
						optarg);
				}
				break;
			case 'g':
				genpayout_auto = true;
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
			/* WARNING - enabling -i will require a DB data update
			 *  if you've used ckdb before 1.920
			 * All (old) marks and workmarkers in the DB will need
			 *  to have poolinstance set to the given -i value
			 *  since they will be blank */
			case 'i':
				sys_poolinstance = (const char *)strdup(optarg);
				break;
			case 'I':
				ignore_seq = true;
				break;
			case 'k':
				ckp.killold = true;
				break;
			case 'K':
				key_range = strdup(optarg);
				key_update = true;
				break;
			case 'l':
				ckp.loglevel = atoi(optarg);
				if (ckp.loglevel < LOG_EMERG || ckp.loglevel > LOG_DEBUG) {
					quit(1, "Invalid loglevel (range %d - %d): %d",
					     LOG_EMERG, LOG_DEBUG, ckp.loglevel);
				}
				break;
			case 'L':
				logpath = strdup(optarg);
				break;
			case 'm':
				markersummary_auto = true;
				break;
			case 'M':
				{
					bool ok = true;
					switch (optarg[0]) {
						case 'D': // Days * mark_start
							mark_start_type = 'D';
							mark_start = atoll(optarg+1);
							break;
						case 'S': // Shifts * mark_start
							mark_start_type = 'S';
							mark_start = atoll(optarg+1);
							break;
						case 'M': // Markerid = mark_start
							mark_start_type = 'M';
							mark_start = atoll(optarg+1);
							break;
						default:
							ok = false;
							break;
					}
					if (!ok || mark_start <= 0)
						quit(1, "Invalid -M must be D, S or"
							" M followed by a number>0");
				}
				break;
			case 'n':
				ckp.name = strdup(optarg);
				break;
			case 'N':
				listener_base = strdup(optarg);
				break;
			case 'o':
				process_name = strdup(optarg);
				break;
			case 'p':
				db_pass = strdup(optarg);
				kill = optarg;
				if (*kill)
					*(kill++) = ' ';
				while (*kill)
					*(kill++) = '\0';
				break;
			case 'P':
				btc_pass = strdup(optarg);
				kill = optarg;
				if (*kill)
					*(kill++) = ' ';
				while (*kill)
					*(kill++) = '\0';
				break;
			case 'q':
				{
					int rql = atoi(optarg);
					if (rql < 1) {
						quit(1, "Invalid reload queue "
						     "limit %d - must be > 0",
						     rql);
					}
					reload_queue_limit = rql;
				}
				break;
			case 'Q':
				{
					// N for both or N:M
					char *q = strdup(optarg);
					char *colon = strchr(q, ':');
					int qt;
					if (colon)
						*(colon++) = '\0';
					qt = atoi(q);
					if (qt < 1 || qt > THREAD_LIMIT) {
						quit(1, "Invalid queue "
						     "thread count '%s' "
						     "- must be >0 and <=%d",
						     colon ? q : optarg,
						     THREAD_LIMIT);
					}
					reload_queue_threads = qt;
					if (!colon)
						proc_queue_threads = qt;
					else {
						qt = atoi(colon);
						if (qt < 1 || qt > THREAD_LIMIT) {
							quit(1, "Invalid 2nd queue "
							     "thread count '%s' "
							     "- must be >0 and <=%d",
							     colon, THREAD_LIMIT);
						}
						proc_queue_threads = qt;
					}
				}
				break;
			case 'r':
				restorefrom = strdup(optarg);
				break;
			case 'R':
				ckp.logdir = strdup(optarg);
				break;
			case 's':
				ckp.socket_dir = strdup(optarg);
				break;
			case 'S':
				btc_server = strdup(optarg);
				break;
			case 't':
				btc_timeout = atoi(optarg);
				break;
			case 'T':
				txn_tree_store = false;
				break;
			case 'u':
				db_user = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'U':
				btc_user = strdup(optarg);
				kill = optarg;
				while (*kill)
					*(kill++) = ' ';
				break;
			case 'v':
				exit(0);
			case 'w':
				// Don't use this :)
				{
					char *ptr = optarg;
					int64_t start;

					if (*ptr == 's') {
						dbload_only_sharesummary = true;
						ptr++;
					}

					start = atoll(ptr);
					if (start < 0) {
						quit(1, "Invalid workinfoid start"
						     " %"PRId64" - must be >= 0",
						     start);
					}
					dbload_workinfoid_start = start;
				}
				break;
			case 'x':
				db_logger = false;
				break;
			case 'X':
				exclusive_db = false;
				break;
			case 'y':
				confirm_sharesummary = true;
				break;
			case 'Y':
				confirm_range = strdup(optarg);
				// Auto enable it also
				confirm_sharesummary = true;
				break;
		}
	}

	snprintf(buf, sizeof(buf), "%s:%s", btc_user, btc_pass);
	btc_auth = http_base64(buf);
	bzero(buf, sizeof(buf));

	if (key_update) {
		dbcode = "k";
		no_data_log = true;
		ignore_seqall = true;
		exclusive_db = false;
	} else {
		if (confirm_sharesummary) {
			dbcode = "y";
			no_data_log = true;
			ignore_seqall = true;
			exclusive_db = false;
		} else
			dbcode = "";
	}

	if (!db_name)
		db_name = "ckdb";
	if (!db_user)
		db_user = "postgres";
	if (!ckp.name)
		ckp.name = DB_PROGNAME;
	snprintf(buf, 15, "%s%s", ckp.name, dbcode);
	FIRST_LOCK_INIT(buf);
	prctl(PR_SET_NAME, buf, 0, 0, 0);

	memset(buf, 0, 15);

	check_restore_dir(ckp.name);

	if (!ckp.config) {
		ckp.config = strdup(ckp.name);
		realloc_strcat(&ckp.config, ".conf");
	}

	if (!ckp.socket_dir) {
		ckp.socket_dir = strdup("/opt/");
		realloc_strcat(&ckp.socket_dir, ckp.name);
	}
	trail_slash(&ckp.socket_dir);

	/* Ignore sigpipe */
	signal(SIGPIPE, SIG_IGN);

	ret = mkdir(ckp.socket_dir, 0770);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make directory %s", ckp.socket_dir);

//	parse_config(&ckp);

	if (!ckp.logdir)
		ckp.logdir = strdup("dblogs");

	/* Create the log directory */
	trail_slash(&ckp.logdir);
	ret = mkdir(ckp.logdir, 0700);
	if (ret && errno != EEXIST)
		quit(1, "Failed to make log directory %s", ckp.logdir);

	/* Create the logfile */
	sprintf(buf, "%s%s%s.log", ckp.logdir, ckp.name, dbcode);
	ckp.logfp = fopen(buf, "ae");
	if (!ckp.logfp)
		quit(1, "Failed to open log file %s", buf);
	ckp.logfd = fileno(ckp.logfp);

	// -db is asicseer-pool messages
	snprintf(logname_db, sizeof(logname_db), "%s%s-db%s-",
				ckp.logdir, ckp.name, dbcode);
	// -io is everything else
	snprintf(logname_io, sizeof(logname_io), "%s%s-io%s-",
				ckp.logdir, ckp.name, dbcode);

	setnow(&now);
	srandom((unsigned int)(now.tv_usec * 4096 + now.tv_sec % 4096));

	ckp.main.ckp = &ckp;
	ckp.main.processname = strdup(process_name);
	snprintf(lbuf, sizeof(lbuf), "%s%s", dbcode, listener_base);
	ckp.main.sockname = strdup(lbuf);
	accesspool = ACCESS_POOL;
	ckp.cdata = &accesspool;
	ckp.gdata = (void *)ispool;

	ckpweb.main.ckp = &ckpweb;
	ckpweb.name = strdup(ckp.name);
	ckpweb.socket_dir = strdup(ckp.socket_dir);
	snprintf(lbuf, sizeof(lbuf), "%s%sweb", dbcode, listener_base);
	ckpweb.main.sockname = strdup(lbuf);
	accessweb = ACCESS_WEB;
	ckpweb.cdata = &accessweb;
	ckpweb.gdata = (void *)isweb;

	ckpcmd.main.ckp = &ckpcmd;
	ckpcmd.name = strdup(ckp.name);
	ckpcmd.socket_dir = strdup(ckp.socket_dir);
	snprintf(lbuf, sizeof(lbuf), "%s%scmd", dbcode, listener_base);
	ckpcmd.main.sockname = strdup(lbuf);
	accesscmd = ACCESS_ALL;
	ckpcmd.cdata = &accesscmd;
	ckpcmd.gdata = (void *)iscmd;

	cklock_init(&breakdown_lock);
	cklock_init(&replier_lock);
	cklock_init(&listener_all_lock);
	cklock_init(&last_lock);
	cklock_init(&btc_lock);
	cklock_init(&pgdb_pause_lock);
	cklock_init(&poolinstance_lock);
	cklock_init(&seq_found_lock);

	mutex_init(&bq_reload_waitlock);
	mutex_init(&bq_cmd_waitlock);
	cond_init(&bq_reload_waitcond);
	cond_init(&bq_cmd_waitcond);

	mutex_init(&process_reload_waitlock);
	mutex_init(&process_socket_waitlock);
	cond_init(&process_reload_waitcond);
	cond_init(&process_socket_waitcond);

	mutex_init(&wq_pool_waitlock);
	mutex_init(&wq_cmd_waitlock);
	mutex_init(&wq_btc_waitlock);
	cond_init(&wq_pool_waitcond);
	cond_init(&wq_cmd_waitcond);
	cond_init(&wq_btc_waitcond);

	mutex_init(&f_ioqueue_waitlock);
	cond_init(&f_ioqueue_waitcond);

	cklock_init(&fpm_lock);
	cksem_init(&socksetup_sem);

	// Initialise IOQUEUE before anything needs it
	ioqueue_free = k_new_list("IOQueue", sizeof(IOQUEUE),
					ALLOC_IOQUEUE, LIMIT_IOQUEUE, true);
	ioqueue_store = k_new_store(ioqueue_free);
	console_ioqueue_store = k_new_store(ioqueue_free);

#if LOCK_CHECK
	DLPRIO(ioqueue, PRIO_TERMINAL);
#endif

	create_pthread(&f_iomsgs_pt, iomsgs, NULL);
	bool consol = true;
	create_pthread(&c_iomsgs_pt, iomsgs, &consol);

	alloc_storage();

	// set initial value
	o_limits_max_lifetime = -1;
	i = -1;
	while (o_limits[++i].name) {
		if (o_limits_max_lifetime < o_limits[i].lifetime)
			o_limits_max_lifetime = o_limits[i].lifetime;
	}

	if (key_update) {
		write_namepid(&ckp.main);
		create_process_unixsock(&ckp.main);
		fcntl(ckp.main.us.sockd, F_SETFD, FD_CLOEXEC);

		create_process_unixsock(&ckpweb.main);
		fcntl(ckpweb.main.us.sockd, F_SETFD, FD_CLOEXEC);

		create_process_unixsock(&ckpcmd.main);
		fcntl(ckpcmd.main.us.sockd, F_SETFD, FD_CLOEXEC);

		update_keysummary();
		everyone_die = true;

		status_report(NULL, false);
	} else if (confirm_sharesummary) {
		// TODO: add a system lock to stop running 2 at once?
		confirm_summaries();
		everyone_die = true;
	} else {
		write_namepid(&ckp.main);
		create_process_unixsock(&ckp.main);
		fcntl(ckp.main.us.sockd, F_SETFD, FD_CLOEXEC);

		create_process_unixsock(&ckpweb.main);
		fcntl(ckpweb.main.us.sockd, F_SETFD, FD_CLOEXEC);

		create_process_unixsock(&ckpcmd.main);
		fcntl(ckpcmd.main.us.sockd, F_SETFD, FD_CLOEXEC);

		create_pthread(&ckp.pth_listener, listener, NULL);

		handler.sa_handler = sighandler;
		handler.sa_flags = 0;
		sigemptyset(&handler.sa_mask);
		sigaction(SIGTERM, &handler, NULL);
		sigaction(SIGINT, &handler, NULL);

		/* Terminate from here if the listener is sent a terminate message */
		join_pthread(ckp.pth_listener);

		status_report(NULL, false);
	}

	time_t start, trigger, curr;
	char *msg = NULL;

	everyone_die = true;
	trigger = start = time(NULL);
	while (socksetup_using_data || summariser_using_data ||
		logger_using_data || plistener_using_data ||
		clistener_using_data || blistener_using_data ||
		marker_using_data || breakdown_using_data) {
		msg = NULL;
		curr = time(NULL);
		if (curr - start > 4) {
			if (curr - trigger > 4) {
				msg = "Terminate initial delay";
			} else if (curr - trigger > 2) {
				msg = "Terminate delay";
			}
		}
		if (msg) {
			trigger = curr;
			snprintf(buf, sizeof(buf),
				"%s %ds due to%s%s%s%s%s%s%s%s%s",
				msg, (int)(curr - start),
				socksetup_using_data ? " socksetup" : EMPTY,
				summariser_using_data ? " summariser" : EMPTY,
				logger_using_data ? " logger" : EMPTY,
				plistener_using_data ? " plistener" : EMPTY,
				clistener_using_data ? " clistener" : EMPTY,
				blistener_using_data ? " blistener" : EMPTY,
				marker_using_data ? " marker" : EMPTY,
				breakdown_using_data ? " breakdown" : EMPTY,
				replier_using_data ? " replier" : EMPTY);
			lf_msg(true, buf);
		}
		sleep(1);
	}

	dealloc_storage();

	ioqueue_die = true;
	join_pthread(f_iomsgs_pt);
	join_pthread(c_iomsgs_pt);
	FREE_STORE(console_ioqueue);
	FREE_LISTS(ioqueue);

	clean_up(&ckp);

	setnow(&(byebye.when));
	ioprocess(&byebye);

	return 0;
}
