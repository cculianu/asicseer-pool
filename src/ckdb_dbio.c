/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 1995-2016 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "asicseer-db.h"

void _pause_read_lock(WHERE_FFL_ARGS)
{
	if (pgdb_pause_disabled)
		return;

	if (pause_read_count > 0) {
		LOGEMERG("%s() ERR lock >0 (%d) (%s/%s/%d/%c) pause disabled"
			 WHERE_FFL,
			 __func__, pause_read_count, pause_read_file,
			 pause_read_func, pause_read_line,
			 pause_read_unlock ? 'U' : 'L', WHERE_FFL_PASS);
		pgdb_pause_disabled = true;
		return;
	}

	ck_rlock(&pgdb_pause_lock);
	pause_read_count++;
	pause_read_file = (char *)file;
	pause_read_func = (char *)func;
	pause_read_line = line;
	pause_read_unlock = false;
}

void _pause_read_unlock(WHERE_FFL_ARGS)
{
	if (pgdb_pause_disabled)
		return;

	if (pause_read_count != 1) {
		LOGEMERG("%s() ERR lock !=1 (%d) (%s/%s/%d/%c) pause disabled"
			 WHERE_FFL,
			 __func__, pause_read_count, pause_read_file,
			 pause_read_func, pause_read_line,
			 pause_read_unlock ? 'U' : 'L', WHERE_FFL_PASS);
		pgdb_pause_disabled = true;
		return;
	}

	ck_runlock(&pgdb_pause_lock);
	pause_read_count--;
	pause_read_file = (char *)file;
	pause_read_func = (char *)func;
	pause_read_line = line;
	pause_read_unlock = true;
}

char *pqerrmsg(PGconn *conn)
{
	char *ptr, *buf;

	if (pgdb_paused)
		return strdup("pgdb_paused");

	buf = strdup(PQerrorMessage(conn));
	if (!buf)
		quithere(1, "malloc OOM");
	ptr = buf + strlen(buf) - 1;
	while (ptr >= buf && (*ptr == '\n' || *ptr == '\r'))
		*(ptr--) = '\0';
	while (--ptr >= buf) {
		if (*ptr == '\n' || *ptr == '\r' || *ptr == '\t')
			*ptr = ' ';
	}
	return buf;
}

/* *** WARNING: each field used in PQ_VAL_FLD() must (of course) have __num
 *  defined, but must also (re)initialise it to -1 with each call to PQexec
 * N.B. it may? not be necessary to reinitialise them with each subsequent
 *  fetch, however I can't find that clearly documented anywhere, it may change
 *  in the future, and once per fetch reduces the number of times by a rather
 *  large factor of 9999 so it doesn't really matter repeating it each fetch */
#define CKPQFETCHSIZ 9999
#define CKPQFETCHSTR STRINT(CKPQFETCHSIZ)
#define FETCHTICK 100000
#define CKPQFUNDEF -1
#define CKPQ_VAL_FLD(__res, __row, __num, __name, __fld, __ok) do { \
		if (pgdb_paused) \
			break; \
		if (__num == CKPQFUNDEF) { \
			__num = PQfnumber(__res, __name); \
			if (__num == CKPQFUNDEF) { \
				LOGERR("%s():%d: Unknown field '%s' row %d", \
					__func__, __LINE__, __name, __row); \
				__ok = false; \
			} \
		} \
		__fld = PQgetvalue(__res, __row, __num); \
		if (__fld == NULL) { \
			LOGERR("%s():%d Invalid field '%s' or row %d", \
				__func__, __LINE__, __name, __row); \
			__ok = false; \
		}\
	} while (0)

// Allow params to be macros

#define CKPQ_VAL_FLD_tail2(__res, __row, __name, __fld, __ok) \
	CKPQ_VAL_FLD(__res, __row, __name ## _num__, #__name, __fld, __ok)
#define CKPQ_VAL_FLD_tail(__res, __row, __name, __fld, __ok) \
	CKPQ_VAL_FLD_tail2(__res, __row, __name, __fld, __ok)
#define CKPQ_VAL_FLD_num2(__res, __row, __name, __fld, __ok) \
	CKPQ_VAL_FLD(__res, __row, __name ## _num, #__name, __fld, __ok)
#define CKPQ_VAL_FLD_num(__res, __row, __name, __fld, __ok) \
	CKPQ_VAL_FLD_num2(__res, __row, __name, __fld, __ok)
#define CKPQADDNUM2(__name) __name ## _num__
#define CKPQADDNUM(__name) CKPQADDNUM2(__name)

// HISTORY FIELDS
#define HISTORYDATE_num \
	int CKPQADDNUM(_CDDB), CKPQADDNUM(_BYDB), CKPQADDNUM(_CODEDB), \
		CKPQADDNUM(_INETDB), CKPQADDNUM(_EDDB)

#define HISTORYDATE_init \
	CKPQADDNUM(_CDDB) = CKPQADDNUM(_BYDB) = CKPQADDNUM(_CODEDB) = \
	CKPQADDNUM(_INETDB) = CKPQADDNUM(_EDDB) = CKPQFUNDEF

#define HISTORYDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		if (pgdb_paused) \
			break; \
		CKPQ_VAL_FLD_tail(_res, _row, _CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(CDDB, _fld, (_data)->createdate); \
		CKPQ_VAL_FLD_tail(_res, _row, _BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(BYDB, _fld, (_data)->createby); \
		CKPQ_VAL_FLD_tail(_res, _row, _CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(CODEDB, _fld, (_data)->createcode); \
		CKPQ_VAL_FLD_tail(_res, _row, _INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(INETDB, _fld, (_data)->createinet); \
		CKPQ_VAL_FLD_tail(_res, _row, _EDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(EDDB, _fld, (_data)->expirydate); \
		(_data)->buffers = (_data)->buffers; \
	} while (0)

#define HISTORYDATEIN(_res, _row, _data, _ok) do { \
		char *_fld; \
		if (pgdb_paused) \
			break; \
		CKPQ_VAL_FLD_tail(_res, _row, _CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(CDDB, _fld, (_data)->createdate); \
		CKPQ_VAL_FLD_tail(_res, _row, _BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createby = intransient_str(BYDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createcode = intransient_str(CODEDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createinet = intransient_str(INETDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _EDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(EDDB, _fld, (_data)->expirydate); \
		(_data)->intrans = (_data)->intrans; \
	} while (0)

#define HISTORYDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
		_params[_his_pos++] = tv_to_buf(&(_row->expirydate), NULL, 0); \
	} while (0)

#define HISTORYDATEPARAMSIN(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createinet, NULL, 0); \
		_params[_his_pos++] = tv_to_buf(&(_row->expirydate), NULL, 0); \
	} while (0)

// MODIFY FIELDS
#define MODIFYDATE_num \
	int CKPQADDNUM(_CDDB), CKPQADDNUM(_BYDB), CKPQADDNUM(_CODEDB), \
		CKPQADDNUM(_INETDB), CKPQADDNUM(_MDDB), CKPQADDNUM(_MBYDB), \
		CKPQADDNUM(_MCODEDB), CKPQADDNUM(_MINETDB)

#define MODIFYDATE_init \
	CKPQADDNUM(_CDDB) = CKPQADDNUM(_BYDB) = CKPQADDNUM(_CODEDB) = \
	CKPQADDNUM(_INETDB) = CKPQADDNUM(_MDDB) = CKPQADDNUM(_MBYDB) = \
	CKPQADDNUM(_MCODEDB) = CKPQADDNUM(_MINETDB) = CKPQFUNDEF

#define MODIFYDATEIN(_res, _row, _data, _ok) do { \
		char *_fld; \
		if (pgdb_paused) \
			break; \
		CKPQ_VAL_FLD_tail(_res, _row, _CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(CDDB, _fld, (_data)->createdate); \
		CKPQ_VAL_FLD_tail(_res, _row, _BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createby = intransient_str(BYDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createcode = intransient_str(CODEDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_createinet = intransient_str(INETDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _MDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(MDDB, _fld, (_data)->modifydate); \
		CKPQ_VAL_FLD_tail(_res, _row, _MBYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_modifyby = intransient_str(MBYDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _MCODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_modifycode = intransient_str(MCODEDB, _fld); \
		CKPQ_VAL_FLD_tail(_res, _row, _MINETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		(_data)->in_modifyinet = intransient_str(MINETDB, _fld); \
		(_data)->intrans = (_data)->intrans; \
	} while (0)

#define MODIFYDATEPARAMS(_params, _mod_pos, _row) do { \
		_params[_mod_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->createinet, NULL, 0); \
		_params[_mod_pos++] = tv_to_buf(&(_row->modifydate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifycode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyinet, NULL, 0); \
	} while (0)

#define MODIFYDATEPARAMSIN(_params, _mod_pos, _row) do { \
		_params[_mod_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_createby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_createcode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_createinet, NULL, 0); \
		_params[_mod_pos++] = tv_to_buf(&(_row->modifydate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_modifyby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_modifycode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->in_modifyinet, NULL, 0); \
	} while (0)

#define MODIFYUPDATEPARAMS(_params, _mod_pos, _row) do { \
		_params[_mod_pos++] = tv_to_buf(&(_row->modifydate), NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyby, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifycode, NULL, 0); \
		_params[_mod_pos++] = str_to_buf(_row->modifyinet, NULL, 0); \
	} while (0)

// SIMPLE FIELDS
#define SIMPLEDATE_num \
	int CKPQADDNUM(_CDDB), CKPQADDNUM(_BYDB), CKPQADDNUM(_CODEDB), \
		CKPQADDNUM(_INETDB)

#define SIMPLEDATE_init \
	CKPQADDNUM(_CDDB) = CKPQADDNUM(_BYDB) = CKPQADDNUM(_CODEDB) = \
	CKPQADDNUM(_INETDB) = CKPQFUNDEF

#define SIMPLEDATEFLDS(_res, _row, _data, _ok) do { \
		char *_fld; \
		if (pgdb_paused) \
			break; \
		CKPQ_VAL_FLD_tail(_res, _row, _CDDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_TVDB(CDDB, _fld, (_data)->createdate); \
		CKPQ_VAL_FLD_tail(_res, _row, _BYDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(BYDB, _fld, (_data)->createby); \
		CKPQ_VAL_FLD_tail(_res, _row, _CODEDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(CODEDB, _fld, (_data)->createcode); \
		CKPQ_VAL_FLD_tail(_res, _row, _INETDB, _fld, _ok); \
		if (!_ok) \
			break; \
		TXT_TO_STR(INETDB, _fld, (_data)->createinet); \
		(_data)->buffers = (_data)->buffers; \
	} while (0)

#define SIMPLEDATEPARAMS(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->createinet, NULL, 0); \
	} while (0)

#define SIMPLEDATEPARAMSIN(_params, _his_pos, _row) do { \
		_params[_his_pos++] = tv_to_buf(&(_row->createdate), NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createby, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createcode, NULL, 0); \
		_params[_his_pos++] = str_to_buf(_row->in_createinet, NULL, 0); \
	} while (0)

// For easy parameter constant strings
#define PQPARAM1  "$1"
#define PQPARAM2  "$1,$2"
#define PQPARAM3  "$1,$2,$3"
#define PQPARAM4  "$1,$2,$3,$4"
#define PQPARAM5  "$1,$2,$3,$4,$5"
#define PQPARAM6  "$1,$2,$3,$4,$5,$6"
#define PQPARAM7  "$1,$2,$3,$4,$5,$6,$7"
#define PQPARAM8  "$1,$2,$3,$4,$5,$6,$7,$8"
#define PQPARAM9  PQPARAM8 ",$9"
#define PQPARAM10 PQPARAM8 ",$9,$10"
#define PQPARAM11 PQPARAM8 ",$9,$10,$11"
#define PQPARAM12 PQPARAM8 ",$9,$10,$11,$12"
#define PQPARAM13 PQPARAM8 ",$9,$10,$11,$12,$13"
#define PQPARAM14 PQPARAM8 ",$9,$10,$11,$12,$13,$14"
#define PQPARAM15 PQPARAM8 ",$9,$10,$11,$12,$13,$14,$15"
#define PQPARAM16 PQPARAM8 ",$9,$10,$11,$12,$13,$14,$15,$16"
#define PQPARAM17 PQPARAM16 ",$17"
#define PQPARAM18 PQPARAM16 ",$17,$18"
#define PQPARAM21 PQPARAM16 ",$17,$18,$19,$20,$21"
#define PQPARAM22 PQPARAM16 ",$17,$18,$19,$20,$21,$22"
#define PQPARAM23 PQPARAM22 ",$23"
#define PQPARAM24 PQPARAM22 ",$23,$24"
#define PQPARAM26 PQPARAM22 ",$23,$24,$25,$26"
#define PQPARAM27 PQPARAM26 ",$27"
#define PQPARAM28 PQPARAM26 ",$27,$28"

#define PARCHK(_par, _params) do { \
		if (_par != (int)(sizeof(_params)/sizeof(_params[0]))) { \
			quithere(1, "params[] usage (%d) != size (%d)", \
					_par, (int)(sizeof(_params)/sizeof(_params[0]))); \
		} \
	} while (0)

#define PARCHKVAL(_par, _val, _params) do { \
		if (_par != _val) { \
			quithere(1, "params[] usage (%d) != expected (%d)", \
					_par, _val); \
		} \
		if (_val > (int)(sizeof(_params)/sizeof(_params[0]))) { \
			quithere(1, "params[] usage (%d) > size (%d)", \
					_val, (int)(sizeof(_params)/sizeof(_params[0]))); \
		} \
	} while (0)

/* Debug level to display write transactions - 0 removes the code
 * Also enables checking the isread flag */
#define CKPQ_SHOW_WRITE 0

#define CKPQ_ISREAD1 "select "
#define CKPQ_ISREAD1LEN (sizeof(CKPQ_ISREAD1)-1)
#define CKPQ_ISREAD2 "declare "
#define CKPQ_ISREAD2LEN (sizeof(CKPQ_ISREAD2)-1)
#define CKPQ_ISREAD3 "fetch "
#define CKPQ_ISREAD3LEN (sizeof(CKPQ_ISREAD3)-1)

// Bug check to ensure no unexpected write txns occur
PGresult *_CKPQExec(PGconn *conn, const char *qry, bool isread, WHERE_FFL_ARGS)
{
	if (pgdb_paused)
		return NULL;

	// It would slow it down, but could check qry for insert/update/...
	if (!isread && confirm_sharesummary)
		quitfrom(1, file, func, line, "BUG: write txn during confirm");

#if CKPQ_SHOW_WRITE
	if (isread) {
		if ((strncmp(qry, CKPQ_ISREAD1, CKPQ_ISREAD1LEN) != 0) &&
		    (strncmp(qry, CKPQ_ISREAD2, CKPQ_ISREAD2LEN) != 0) &&
		    (strncmp(qry, CKPQ_ISREAD3, CKPQ_ISREAD3LEN) != 0)) {
			LOGERR("%s() ERR: query flagged as read, but isn't"
				WHERE_FFL, __func__, WHERE_FFL_PASS);
			isread = false;
		}
	} else {
		if ((strncmp(qry, CKPQ_ISREAD1, CKPQ_ISREAD1LEN) == 0) ||
		    (strncmp(qry, CKPQ_ISREAD2, CKPQ_ISREAD2LEN) == 0) ||
		    (strncmp(qry, CKPQ_ISREAD3, CKPQ_ISREAD3LEN) == 0)) {
			LOGERR("%s() ERR: query flagged as write, but isn't"
				WHERE_FFL, __func__, WHERE_FFL_PASS);
			isread = true;
		}
	}
	if (!isread) {
		char *buf = NULL, ffl[128];
		size_t len, off;

		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, __func__);
		APPEND_REALLOC(buf, off, len, "() W: '");
		APPEND_REALLOC(buf, off, len, qry);
		APPEND_REALLOC(buf, off, len, "'");
		snprintf(ffl, sizeof(ffl), WHERE_FFL, WHERE_FFL_PASS);
		APPEND_REALLOC(buf, off, len, ffl);
		LOGMSGBUF(CKPQ_SHOW_WRITE, buf);
		FREENULL(buf);
	}
#endif

	return PQexec(conn, qry);
}

PGresult *_CKPQExecParams(PGconn *conn, const char *qry,
			  int nParams,
			  const Oid *paramTypes,
			  const char *const * paramValues,
			  const int *paramLengths,
			  const int *paramFormats,
			  int resultFormat,
			  bool isread, WHERE_FFL_ARGS)
{
	if (pgdb_paused)
		return NULL;

	// It would slow it down, but could check qry for insert/update/...
	if (!isread && confirm_sharesummary)
		quitfrom(1, file, func, line, "BUG: write txn during confirm");

#if CKPQ_SHOW_WRITE
	if (isread) {
		if ((strncmp(qry, CKPQ_ISREAD1, CKPQ_ISREAD1LEN) != 0) &&
		    (strncmp(qry, CKPQ_ISREAD2, CKPQ_ISREAD2LEN) != 0) &&
		    (strncmp(qry, CKPQ_ISREAD3, CKPQ_ISREAD3LEN) != 0)) {
			LOGERR("%s() ERR: query flagged as read, but isn't"
				WHERE_FFL, __func__, WHERE_FFL_PASS);
			isread = false;
		}
	} else {
		if ((strncmp(qry, CKPQ_ISREAD1, CKPQ_ISREAD1LEN) == 0) ||
		    (strncmp(qry, CKPQ_ISREAD2, CKPQ_ISREAD2LEN) == 0) ||
		    (strncmp(qry, CKPQ_ISREAD3, CKPQ_ISREAD3LEN) == 0)) {
			LOGERR("%s() ERR: query flagged as write, but isn't"
				WHERE_FFL, __func__, WHERE_FFL_PASS);
			isread = true;
		}
	}
	if (!isread) {
		char *buf = NULL, num[16], ffl[128];
		size_t len, off;
		int i;

		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, __func__);
		APPEND_REALLOC(buf, off, len, "() W: '");
		APPEND_REALLOC(buf, off, len, qry);
		APPEND_REALLOC(buf, off, len, "'");
		for (i = 0; i < nParams; i++) {
			snprintf(num, sizeof(num), " $%d='", i+1);
			APPEND_REALLOC(buf, off, len, num);
			APPEND_REALLOC(buf, off, len, paramValues[i]);
			APPEND_REALLOC(buf, off, len, "'");
		}
		snprintf(ffl, sizeof(ffl), WHERE_FFL, WHERE_FFL_PASS);
		APPEND_REALLOC(buf, off, len, ffl);
		LOGMSGBUF(CKPQ_SHOW_WRITE, buf);
		FREENULL(buf);
	}
#endif

	return PQexecParams(conn, qry, nParams, paramTypes, paramValues, paramLengths,
			    paramFormats, resultFormat);
}

ExecStatusType _CKPQResultStatus(PGresult *res, WHERE_FFL_ARGS)
{
	if (pgdb_paused)
		return PGRES_COMMAND_OK;

	return PQresultStatus(res);
}

void _CKPQClear(PGresult *res, WHERE_FFL_ARGS)
{
	if (!pgdb_paused)
		PQclear(res);
}

bool _CKPQConn(PGconn **conn, WHERE_FFL_ARGS)
{
	if (*conn == NULL) {
		if (connect_dis == false) {
			LOGNOTICE("%s() already (%s/%s/%d)" WHERE_FFL
#if LOCK_CHECK
				  " @%s"
#endif
				  , __func__, connect_file, connect_func,
				  connect_line, WHERE_FFL_PASS
#if LOCK_CHECK
				  , my_thread_name
#endif
			);
		}
		if (!pgdb_paused) {
			LOGDEBUG("%s(): connecting", __func__);
			*conn = dbconnect();
			K_WLOCK(pgdb_free);
			pgdb_count++;
			K_WUNLOCK(pgdb_free);
			connect_file = (char *)file;
			connect_func = (char *)func;
			connect_line = line;
			connect_dis = false;
		}
		return true;
	}
	return false;
}

bool _CKPQDisco(PGconn **conn, bool conned, WHERE_FFL_ARGS)
{
	if (conned && *conn) {
		LOGDEBUG("%s(): disco", __func__);
		PQfinish(*conn);
		*conn = NULL;
		K_WLOCK(pgdb_free);
		pgdb_count--;
		K_WUNLOCK(pgdb_free);
		connect_file = (char *)file;
		connect_func = (char *)func;
		connect_line = line;
		connect_dis = true;
	}
	return false;
}

bool _CKPQBegin(PGconn *conn, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res;

	if (pgdb_paused)
		return true;

	res = _CKPQExec(conn, "Begin", CKPQ_WRITE, WHERE_FFL_PASS);
	rescode = _CKPQResultStatus(res, WHERE_FFL_PASS);
	_CKPQClear(res, WHERE_FFL_PASS);
	if (!PGOK(rescode)) {
		char *buf = pqerrmsg(conn);
		LOGEMERG("%s(): Begin failed (%d) '%s'" WHERE_FFL,
			 __func__, (int)rescode, buf, WHERE_FFL_PASS);
		free(buf);
		return false;
	}
	LOGDEBUG("%s(): begin", __func__);
	return true;
}

void _CKPQEnd(PGconn *conn, bool commit, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	PGresult *res;

	if (pgdb_paused)
		return;

	if (commit) {
		LOGDEBUG("%s(): commit", __func__);
		res = _CKPQExec(conn, "Commit", CKPQ_WRITE, WHERE_FFL_PASS);
	} else {
		LOGDEBUG("%s(): rollback", __func__);
		res = _CKPQExec(conn, "Rollback", CKPQ_WRITE, WHERE_FFL_PASS);
	}
	rescode = _CKPQResultStatus(res, WHERE_FFL_PASS);
	_CKPQClear(res, WHERE_FFL_PASS);
	if (!PGOK(rescode)) {
		char *buf = pqerrmsg(conn);
		LOGEMERG("%s(): %s failed (%d) '%s'" WHERE_FFL,
			 __func__, commit ? "commit" : "rollback",
			 (int)rescode, buf, WHERE_FFL_PASS);
		free(buf);
	}
}

int64_t nextid(PGconn *conn, char *idname, int64_t increment,
		tv_t *cd, char *by, char *code, char *inet)
{
	ExecStatusType rescode;
	bool conned = false;
	IDCONTROL *idcontrol;
	K_ITEM *item;
	PGresult *res;
	char qry[1024];
	char *params[5];
	int n, f, par = 0;
	int64_t lastid;
	char *field = NULL;
	bool ok;

	lastid = 0;

	K_WLOCK(idcontrol_free);
	item = find_idcontrol(idname);
	if (!item)
	{
		LOGERR("%s(): No matching idname='%s' in tree", __func__, idname);
		goto cleanup;
	}

	snprintf(qry, sizeof(qry), "select lastid from idcontrol "
				   "where idname='%s' for update",
				   idname);

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExec(conn, qry, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		goto cleanup;
	}

	n = PQnfields(res);
	if (n != 1) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, 1, n);
		goto cleanup;
	}

	n = PQntuples(res);
	if (n < 1) {
		LOGERR("%s(): No matching idname='%s'", __func__, idname);
		goto cleanup;
	}

	ok = true;
	f = CKPQFUNDEF;
	CKPQ_VAL_FLD(res, 0, f, "lastid", field, ok);
	if (!ok)
		goto cleanup;
	TXT_TO_BIGINT("lastid", field, lastid);

	CKPQClear(res);

	lastid += increment;
	snprintf(qry, sizeof(qry), "update idcontrol set "
				   "lastid=$1,"MDDB"=$2,"MBYDB"=$3,"
				   MCODEDB"=$4,"MINETDB"=$5 "
				   "where idname='%s'",
				   idname);

	par = 0;
	params[par++] = bigint_to_buf(lastid, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = str_to_buf(by, NULL, 0);
	params[par++] = str_to_buf(code, NULL, 0);
	params[par++] = str_to_buf(inet, NULL, 0);
	PARCHK(par, params);

	res = CKPQExecParams(conn, qry, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		lastid = 0;
	} else {
		DATA_IDCONTROL(idcontrol, item);
		idcontrol->lastid = lastid;
		copy_tv(&(idcontrol->modifydate), cd);
		idcontrol->in_modifyby = intransient_str(MBYDB, by);
		idcontrol->in_modifycode = intransient_str(MCODEDB, code);
		idcontrol->in_modifyinet = intransient_str(MINETDB, inet);
	}

	for (n = 0; n < par; n++)
		free(params[n]);
cleanup:
	K_WUNLOCK(idcontrol_free);
	CKPQDisco(&conn, conned);
	return lastid;
}

bool users_update(PGconn *conn, K_ITEM *u_item, char *oldhash,
		  char *newhash, char *email, char *by, char *code,
		  char *inet, tv_t *cd, K_TREE *trf_root, char *status,
		  int *event)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item;
	USERS *row, *users;
	char *upd, *ins;
	bool ok = false;
	char *params[6 + HISTORYDATECOUNT];
	bool hash;
	int n, par = 0;

	LOGDEBUG("%s(): change", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	if (oldhash != NULL)
		hash = true;
	else
		hash = false;

	DATA_USERS(users, u_item);
	// i.e. if oldhash == EMPTY, just overwrite with new
	if (hash && oldhash != EMPTY && !check_hash(users, oldhash)) {
		if (event)
			*event = events_add(EVENTID_PASSFAIL, trf_root);
		return false;
	}

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);
	copy_users(row, users);

	// Update each one supplied
	if (hash) {
		// New salt each password change
		make_salt(row);
		password_hash(row->in_username, newhash, row->salt,
			      row->passwordhash, sizeof(row->passwordhash));
	}
	if (email)
		STRNCPY(row->emailaddress, email);
	if (status)
		STRNCPY(row->status, status);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update users set "EDDB"=$1 where userid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (CKPQConn(&conn))
		conned = true;
	if (!CKPQBegin(conn))
		goto unparam;

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	par = 0;
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	// Copy them all in - at least one will be new
	params[par++] = str_to_buf(row->status, NULL, 0);
	params[par++] = str_to_buf(row->emailaddress, NULL, 0);
	params[par++] = str_to_buf(row->passwordhash, NULL, 0);
	// New salt for each password change (or recopy old)
	params[par++] = str_to_buf(row->salt, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHKVAL(par, 6 + HISTORYDATECOUNT, params); // 11 as per ins

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") select "
		"userid,username,$3,$4,joineddate,"
		"$5,secondaryuserid,$6,userdata,userbits,"
		"$7,$8,$9,$10,$11 from users where "
		"userid=$1 and "EDDB"=$2";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(users_free);
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	} else {
		remove_from_ktree(users_root, u_item);
		remove_from_ktree(userid_root, u_item);
		copy_tv(&(users->expirydate), cd);
		add_to_ktree(users_root, u_item);
		add_to_ktree(userid_root, u_item);

		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

	return ok;
}

K_ITEM *users_add(PGconn *conn, INTRANSIENT *in_username, char *emailaddress,
			char *passwordhash, char *secondaryuserid,
			int64_t userbits, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item, *u_item;
	USERS *row, *users;
	char *ins;
	char tohash[64];
	uint64_t hash;
	bool dup, ok = false;
	char *params[10 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused && userbits != USER_MISSING)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	/* 2 attempts to add the same user at the same time will only do it once
	 * The 2nd attempt will get back the data provided by the 1st
	 *  and thus throw away any differences in the 2nd */
	K_WLOCK(users_db_free);

	K_RLOCK(users_free);
	item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (item) {
		ok = true;
		goto already;
	}

	K_WLOCK(users_free);
	item = k_unlink_head(users_free);
	K_WUNLOCK(users_free);

	DATA_USERS(row, item);
	bzero(row, sizeof(*row));

	row->in_username = in_username->str;
	username_trim(row);

	dup = false;
	K_RLOCK(users_free);
	u_item = STORE_RHEAD(users_store);
	while (u_item) {
		DATA_USERS(users, u_item);
		if (strcmp(row->usertrim, users->usertrim) == 0) {
			dup = true;
			break;
		}
		u_item = u_item->next;
	}
	K_RUNLOCK(users_free);

	if (dup)
		goto unitem;

	row->userid = nextid(conn, "userid", (int64_t)(666 + (random() % 334)),
				cd, by, code, inet);
	if (row->userid == 0)
		goto unitem;

	row->status[0] = '\0';
	STRNCPY(row->emailaddress, emailaddress);

	if (secondaryuserid == NULL) {
		snprintf(tohash, sizeof(tohash), "%s&#%s",
						 in_username->str,
						 emailaddress);
		HASH_BER(tohash, strlen(tohash), hash);
		__bin2hex(row->secondaryuserid, (void *)(&hash), sizeof(hash));
	} else
		STRNCPY(row->secondaryuserid, secondaryuserid);

	make_salt(row);
	if (passwordhash == EMPTY) {
		// Make it impossible to login for a BTC Address username
		row->passwordhash[0] = '\0';
	} else {
		password_hash(row->in_username, passwordhash, row->salt,
			      row->passwordhash, sizeof(row->passwordhash));
	}

	row->userdata = EMPTY;
	row->userbits = userbits;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	// copy createdate
	row->joineddate.tv_sec = row->createdate.tv_sec;
	row->joineddate.tv_usec = row->createdate.tv_usec;

	par = 0;
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->in_username, NULL, 0);
	params[par++] = str_to_buf(row->status, NULL, 0);
	params[par++] = str_to_buf(row->emailaddress, NULL, 0);
	params[par++] = tv_to_buf(&(row->joineddate), NULL, 0);
	params[par++] = str_to_buf(row->passwordhash, NULL, 0);
	params[par++] = str_to_buf(row->secondaryuserid, NULL, 0);
	params[par++] = str_to_buf(row->salt, NULL, 0);
	params[par++] = str_to_buf(row->userdata, NULL, 0);
	params[par++] = bigint_to_buf(row->userbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,passwordhash,"
		"secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") values (" PQPARAM15 ")";

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ok = true;
unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	K_WLOCK(users_free);
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	} else {
		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	K_WUNLOCK(users_free);

already:

	K_WUNLOCK(users_db_free);

	if (ok)
		return item;
	else
		return NULL;
}

// Replace the current users record with u_item, and expire the old one
bool users_replace(PGconn *conn, K_ITEM *u_item, K_ITEM *old_u_item, char *by,
		   char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false;
	USERS *users, *old_users;
	char *upd, *ins;
	char *params[10 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): replace", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	DATA_USERS(users, u_item);
	DATA_USERS(old_users, old_u_item);

	HISTORYDATEINIT(users, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, users);

	upd = "update users set "EDDB"=$1 where userid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(old_users->userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (CKPQConn(&conn))
		conned = true;
	if (!CKPQBegin(conn))
		goto unparam;

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	par = 0;
	params[par++] = bigint_to_buf(users->userid, NULL, 0);
	params[par++] = str_to_buf(users->in_username, NULL, 0);
	params[par++] = str_to_buf(users->status, NULL, 0);
	params[par++] = str_to_buf(users->emailaddress, NULL, 0);
	params[par++] = tv_to_buf(&(users->joineddate), NULL, 0);
	params[par++] = str_to_buf(users->passwordhash, NULL, 0);
	params[par++] = str_to_buf(users->secondaryuserid, NULL, 0);
	params[par++] = str_to_buf(users->salt, NULL, 0);
	params[par++] = str_to_buf(users->userdata, NULL, 0);
	params[par++] = bigint_to_buf(users->userbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, users);
	PARCHKVAL(par, 10 + HISTORYDATECOUNT, params);

	ins = "insert into users "
		"(userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL ") values (" PQPARAM15 ")";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(users_free);
	if (!ok) {
		// cleanup done here
		free_users_data(u_item);
		k_add_head(users_free, u_item);
	} else {
		remove_from_ktree(users_root, old_u_item);
		remove_from_ktree(userid_root, old_u_item);
		copy_tv(&(old_users->expirydate), cd);
		add_to_ktree(users_root, old_u_item);
		add_to_ktree(userid_root, old_u_item);

		add_to_ktree(users_root, u_item);
		add_to_ktree(userid_root, u_item);
		k_add_head(users_store, u_item);
	}
	K_WUNLOCK(users_free);

	return ok;
}

/* If a share contains an unknown username then it will most likely be from
 *  reloading a data file when the users table is incomplete or corrupt
 * Since the share is valid, it should be counted against the pool stats and
 *  creating a user also means the payout rewards are calculated correctly
 * This also gives 2 options to resolve it later:
 *  1) Correct the database/redistribute the rewards to the correct user
 *  2) Rollback the database and reload it with a corrected users table
 *  Option 1) gives a simpler solution vs option 2) if 2) is too far in
 *   the past to easily do a reload */
K_ITEM *create_missing_user(PGconn *conn, char *username, char *secondaryuserid,
			    char *by, char *code, char *inet, tv_t *cd,
			    K_TREE *trf_root)
{
	INTRANSIENT *in_username;

	in_username = get_intransient("username", username);

	return users_add(conn, in_username, EMPTY, EMPTY, secondaryuserid,
			 USER_MISSING, by, code, inet, cd, trf_root);
}

bool users_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERS *row;
	char *field = NULL;
	char *sel;
	int fields = 10;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int userid_num, username_num, status_num, emailaddress_num;
	int joineddate_num, passwordhash_num, secondaryuserid_num, salt_num;
	int userdata_num, userbits_num;
	HISTORYDATE_num;

	sel = "select "
		"userid,username,status,emailaddress,joineddate,"
		"passwordhash,secondaryuserid,salt,userdata,userbits"
		HISTORYDATECONTROL
		" from users";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	userid_num = username_num = status_num = emailaddress_num =
	joineddate_num = passwordhash_num = secondaryuserid_num = salt_num =
	userdata_num = userbits_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(users_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(users_free);
		DATA_USERS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, userid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		CKPQ_VAL_FLD_num(res, i, username, field, ok);
		if (!ok)
			break;
		row->in_username = intransient_str("username", field);

		CKPQ_VAL_FLD_num(res, i, status, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		CKPQ_VAL_FLD_num(res, i, emailaddress, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("emailaddress", field, row->emailaddress);

		CKPQ_VAL_FLD_num(res, i, joineddate, field, ok);
		if (!ok)
			break;
		TXT_TO_TVDB("joineddate", field, row->joineddate);

		CKPQ_VAL_FLD_num(res, i, passwordhash, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("passwordhash", field, row->passwordhash);

		CKPQ_VAL_FLD_num(res, i, secondaryuserid, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("secondaryuserid", field, row->secondaryuserid);

		CKPQ_VAL_FLD_num(res, i, salt, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("salt", field, row->salt);

		// TODO: good case for invariant
		CKPQ_VAL_FLD_num(res, i, userdata, field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("userdata", field, row->userdata);
		LIST_MEM_ADD(users_free, row->userdata);
		users_databits(row);

		CKPQ_VAL_FLD_num(res, i, userbits, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userbits", field, row->userbits);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		username_trim(row);

		add_to_ktree(users_root, item);
		add_to_ktree(userid_root, item);
		k_add_head(users_store, item);
	}
	if (!ok) {
		free_users_data(item);
		k_add_head(users_free, item);
	}

	K_WUNLOCK(users_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s users records",
			   __func__, pcombuf);
	}

	return ok;
}

bool useratts_item_add(PGconn *conn, K_ITEM *ua_item, tv_t *cd, bool begun)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *old_item;
	USERATTS *old_useratts, *useratts;
	char *upd, *ins;
	bool ok = false;
	char *params[9 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	DATA_USERATTS(useratts, ua_item);

	K_RLOCK(useratts_free);
	old_item = find_useratts(useratts->userid, useratts->attname);
	K_RUNLOCK(useratts_free);
	DATA_USERATTS_NULL(old_useratts, old_item);

	/* N.B. the values of the old ua_item record, if it exists,
	 * are completely ignored i.e. you must provide all values required */

	if (CKPQConn(&conn))
		conned = true;
	if (!begun) {
		if (!CKPQBegin(conn))
			goto unparam;
	}

	if (old_item) {
		upd = "update useratts set "EDDB"=$1 where userid=$2 and "
			"attname=$3 and "EDDB"=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(old_useratts->userid, NULL, 0);
		params[par++] = str_to_buf(old_useratts->attname, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto unparam;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
	}

	par = 0;
	params[par++] = bigint_to_buf(useratts->userid, NULL, 0);
	params[par++] = str_to_buf(useratts->attname, NULL, 0);
	params[par++] = str_to_buf(useratts->status, NULL, 0);
	params[par++] = str_to_buf(useratts->attstr, NULL, 0);
	params[par++] = str_to_buf(useratts->attstr2, NULL, 0);
	params[par++] = bigint_to_buf(useratts->attnum, NULL, 0);
	params[par++] = bigint_to_buf(useratts->attnum2, NULL, 0);
	params[par++] = tv_to_buf(&(useratts->attdate), NULL, 0);
	params[par++] = tv_to_buf(&(useratts->attdate2), NULL, 0);
	HISTORYDATEPARAMS(params, par, useratts);
	PARCHK(par, params);

	ins = "insert into useratts "
		"(userid,attname,status,attstr,attstr2,attnum,attnum2,"
		"attdate,attdate2"
		HISTORYDATECONTROL ") values (" PQPARAM14 ")";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (!begun)
		CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(useratts_free);
	if (ok) {
		// Update it
		if (old_item) {
			remove_from_ktree(useratts_root, old_item);
			copy_tv(&(old_useratts->expirydate), cd);
			add_to_ktree(useratts_root, old_item);
		}
		add_to_ktree(useratts_root, ua_item);
		k_add_head(useratts_store, ua_item);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

K_ITEM *useratts_add(PGconn *conn, char *username, char *attname,
			char *status, char *attstr, char *attstr2,
			char *attnum, char *attnum2, char *attdate,
			char *attdate2, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root,
			bool begun)
{
	K_ITEM *item, *u_item;
	USERATTS *row;
	USERS *users;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	K_WLOCK(useratts_free);
	item = k_unlink_head(useratts_free);
	K_WUNLOCK(useratts_free);
	DATA_USERATTS(row, item);
	bzero(row, sizeof(*row));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		LOGERR("%s(): unknown user '%s'",
			__func__,
			st = safe_text_nonull(username));
		FREENULL(st);
		goto unitem;
	}
	DATA_USERS(users, u_item);

	row->userid = users->userid;
	STRNCPY(row->attname, attname);
	if (status == NULL)
		row->status[0] = '\0';
	else
		STRNCPY(row->status, status);
	if (attstr == NULL)
		row->attstr[0] = '\0';
	else
		STRNCPY(row->attstr, attstr);
	if (attstr2 == NULL)
		row->attstr2[0] = '\0';
	else
		STRNCPY(row->attstr2, attstr2);
	if (attnum == NULL || attnum[0] == '\0')
		row->attnum = 0;
	else
		TXT_TO_BIGINT("attnum", attnum, row->attnum);
	if (attnum2 == NULL || attnum2[0] == '\0')
		row->attnum2 = 0;
	else
		TXT_TO_BIGINT("attnum2", attnum2, row->attnum2);
	if (attdate == NULL || attdate[0] == '\0')
		DATE_ZERO(&(row->attdate));
	else
		TXT_TO_TV("attdate", attdate, row->attdate);
	if (attdate2 == NULL || attdate2[0] == '\0')
		DATE_ZERO(&(row->attdate2));
	else
		TXT_TO_TV("attdate2", attdate2, row->attdate2);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	ok = useratts_item_add(conn, item, cd, begun);
unitem:
	if (!ok) {
		K_WLOCK(useratts_free);
		k_add_head(useratts_free, item);
		K_WUNLOCK(useratts_free);
	}

	if (ok)
		return item;
	else
		return NULL;
}

bool useratts_item_expire(PGconn *conn, K_ITEM *ua_item, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item;
	USERATTS *useratts;
	char *upd;
	bool ok = false;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	DATA_USERATTS(useratts, ua_item);

	/* This is pointless if ua_item is part of the tree, however,
	 * it allows for if ua_item isn't already part of the tree */
	K_RLOCK(useratts_free);
	item = find_useratts(useratts->userid, useratts->attname);
	K_RUNLOCK(useratts_free);

	if (item) {
		DATA_USERATTS(useratts, item);

		if (CKPQConn(&conn))
			conned = true;
		upd = "update useratts set "EDDB"=$1 where userid=$2 and "
			"attname=$3 and "EDDB"=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(useratts->userid, NULL, 0);
		params[par++] = str_to_buf(useratts->attname, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto unparam;
		}
	}
	ok = true;
unparam:
	if (par) {
		CKPQDisco(&conn, conned);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(useratts_free);
	if (ok && item) {
		remove_from_ktree(useratts_root, item);
		copy_tv(&(useratts->expirydate), cd);
		add_to_ktree(useratts_root, item);
	}
	K_WUNLOCK(useratts_free);

	return ok;
}

bool useratts_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	USERATTS *row;
	char *field = NULL;
	char *sel;
	int fields = 9;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int userid_num, attname_num, status_num, attstr_num, attstr2_num;
	int attnum_num, attnum2_num, attdate_num, attdate2_num;
	HISTORYDATE_num;

	sel = "select "
		"userid,attname,status,attstr,attstr2,attnum,attnum2"
		",attdate,attdate2"
		HISTORYDATECONTROL
		" from useratts";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	userid_num = attname_num = status_num = attstr_num = attstr2_num =
	attnum_num = attnum2_num = attdate_num = attdate2_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(useratts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(useratts_free);
		DATA_USERATTS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, userid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		CKPQ_VAL_FLD_num(res, i, attname, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attname", field, row->attname);

		CKPQ_VAL_FLD_num(res, i, status, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		CKPQ_VAL_FLD_num(res, i, attstr, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attstr", field, row->attstr);

		CKPQ_VAL_FLD_num(res, i, attstr2, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("attstr2", field, row->attstr2);

		CKPQ_VAL_FLD_num(res, i, attnum, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("attnum", field, row->attnum);

		CKPQ_VAL_FLD_num(res, i, attnum2, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("attnum2", field, row->attnum2);

		CKPQ_VAL_FLD_num(res, i, attdate, field, ok);
		if (!ok)
			break;
		TXT_TO_TVDB("attdate", field, row->attdate);

		CKPQ_VAL_FLD_num(res, i, attdate2, field, ok);
		if (!ok)
			break;
		TXT_TO_TVDB("attdate2", field, row->attdate2);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(useratts_root, item);
		k_add_head(useratts_store, item);
	}
	if (!ok)
		k_add_head(useratts_free, item);

	K_WUNLOCK(useratts_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s useratts records",
			   __func__, pcombuf);
	}

	return ok;
}

K_ITEM *workers_add(PGconn *conn, int64_t userid, char *workername, bool add_ws,
			char *difficultydefault, char *idlenotificationenabled,
			char *idlenotificationtime, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_ITEM *item, *ret = NULL;
	WORKERS *row;
	char *ins;
	char *params[7 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	int32_t nottime;

	LOGDEBUG("%s(): add", __func__);

	/* Since shares can add workers and there's lotsa shares :) ...
	 *  and workers_add() and workers_fill() are the only places where
	 *  workers can be added, to ensure that the existence of the worker
	 *  hasn't changed, we check it again under a lock here that's unique
	 *  to workers_add() and workers_fill()
	 *   i.e. multiple threads trying to add the same worker will only end
	 *    up adding one and thus avoid wasted DB IO and avoid DB duplicate
	 *    errors */
	K_WLOCK(workers_db_free);

	ret = find_workers(false, userid, workername);
	if (ret)
		goto hadit;

	K_WLOCK(workers_free);
	item = k_unlink_head(workers_free);
	K_WUNLOCK(workers_free);

	DATA_WORKERS(row, item);

	if (CKPQConn(&conn))
		conned = true;
	bzero(row, sizeof(*row));
	row->workerid = nextid(conn, "workerid", (int64_t)1, cd, by, code, inet);
	if (row->workerid == 0)
		goto unitem;

	row->userid = userid;
	row->in_workername = intransient_str("workername", workername);
	if (difficultydefault && *difficultydefault) {
		diffdef = atoi(difficultydefault);
		// If out of the range, set it in the range
		if (diffdef != DIFFICULTYDEFAULT_DEF) {
			if (diffdef < DIFFICULTYDEFAULT_MIN)
				diffdef = DIFFICULTYDEFAULT_MIN;
			if (diffdef > DIFFICULTYDEFAULT_MAX)
				diffdef = DIFFICULTYDEFAULT_MAX;
		}
		row->difficultydefault = diffdef;
	} else
		row->difficultydefault = DIFFICULTYDEFAULT_DEF;

	row->idlenotificationenabled[1] = '\0';
	if (idlenotificationenabled && *idlenotificationenabled) {
		if (tolower(*idlenotificationenabled) == IDLENOTIFICATIONENABLED[0])
			row->idlenotificationenabled[0] = IDLENOTIFICATIONENABLED[0];
		else
			row->idlenotificationenabled[0] = IDLENOTIFICATIONDISABLED[0];
	} else
		row->idlenotificationenabled[0] = IDLENOTIFICATIONENABLED_DEF[0];

	if (idlenotificationtime && *idlenotificationtime) {
		nottime = atoi(idlenotificationtime);
		if (nottime != IDLENOTIFICATIONTIME_DEF) {
			// If out of the range, set to default
			if (nottime < IDLENOTIFICATIONTIME_MIN ||
			    nottime > IDLENOTIFICATIONTIME_MAX)
				nottime = IDLENOTIFICATIONTIME_DEF;
		}
		row->idlenotificationtime = nottime;
	} else
		row->idlenotificationtime = IDLENOTIFICATIONTIME_DEF;

	// Default is disabled
	if (row->idlenotificationtime == IDLENOTIFICATIONTIME_DEF)
		row->idlenotificationenabled[0] = IDLENOTIFICATIONDISABLED[0];

	row->workerbits = 0;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->in_workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	params[par++] = bigint_to_buf(row->workerbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into workers "
		"(workerid,userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL ") values (" PQPARAM12 ")";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ret = item;
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);
unitem:
	CKPQDisco(&conn, conned);
	K_WLOCK(workers_free);
	if (!ret)
		k_add_head(workers_free, item);
	else {
		add_to_ktree(workers_root, item);
		k_add_head(workers_store, item);
	}
	K_WUNLOCK(workers_free);

hadit:
	;
	K_WUNLOCK(workers_db_free);

	if (ret && add_ws) {
		/* Ensure there is a matching workerstatus
		 * WARNING - find_create_workerstatus() can call workers_add()!
		 *  The hasworker=true argument guarantees it wont and
		 *   add_ws=false above ensures it wont call back */
		find_create_workerstatus(false, false, userid, workername, true,
					 __FILE__, __func__, __LINE__);
	}

	return ret;
}

/* The assumption is that the worker already exists in the DB
 * and in the RAM tables and the item passed is already in the tree
 * Since there is no change to the key, there's no tree reorg required
 * check = false means just update it, ignore the passed char* vars */
bool workers_update(PGconn *conn, K_ITEM *item, char *difficultydefault,
			char *idlenotificationenabled,
			char *idlenotificationtime, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root, bool check)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	WORKERS *row;
	char *upd, *ins;
	bool ok = false;
	char *params[7 + HISTORYDATECOUNT];
	int n, par = 0;
	int32_t diffdef;
	char idlenot;
	int32_t nottime;

	LOGDEBUG("%s(): update", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	/* Two attempts to update the same worker at the same time
	 *  will determine the final state based on which gets the lock last,
	 *  i.e. randomly, but without overwriting at the same time */
	K_WLOCK(workers_db_free);

	DATA_WORKERS(row, item);

	if (check) {
		if (difficultydefault && *difficultydefault) {
			diffdef = atoi(difficultydefault);
			if (diffdef < DIFFICULTYDEFAULT_MIN)
				diffdef = row->difficultydefault;
			if (diffdef > DIFFICULTYDEFAULT_MAX)
				diffdef = row->difficultydefault;
		} else
			diffdef = row->difficultydefault;

		if (idlenotificationenabled && *idlenotificationenabled) {
			if (tolower(*idlenotificationenabled) == IDLENOTIFICATIONENABLED[0])
				idlenot = IDLENOTIFICATIONENABLED[0];
			else
				idlenot = IDLENOTIFICATIONDISABLED[0];
		} else
			idlenot = row->idlenotificationenabled[0];

		if (idlenotificationtime && *idlenotificationtime) {
			nottime = atoi(idlenotificationtime);
			if (nottime < IDLENOTIFICATIONTIME_MIN)
				nottime = row->idlenotificationtime;
			if (nottime > IDLENOTIFICATIONTIME_MAX)
				nottime = row->idlenotificationtime;
		} else
			nottime = row->idlenotificationtime;

		if (diffdef == row->difficultydefault &&
		    idlenot == row->idlenotificationenabled[0] &&
		    nottime == row->idlenotificationtime) {
			ok = true;
			goto early;
		}

		row->difficultydefault = diffdef;
		row->idlenotificationenabled[0] = idlenot;
		row->idlenotificationenabled[1] = '\0';
		row->idlenotificationtime = nottime;
	}

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	upd = "update workers set "EDDB"=$1 where workerid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (CKPQConn(&conn))
		conned = true;
	if (!CKPQBegin(conn))
		goto unparam;

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	ins = "insert into workers "
		"(workerid,userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL ") values (" PQPARAM12 ")";

	par = 0;
	params[par++] = bigint_to_buf(row->workerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->in_workername, NULL, 0);
	params[par++] = int_to_buf(row->difficultydefault, NULL, 0);
	params[par++] = str_to_buf(row->idlenotificationenabled, NULL, 0);
	params[par++] = int_to_buf(row->idlenotificationtime, NULL, 0);
	params[par++] = bigint_to_buf(row->workerbits, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);
early:

	K_WUNLOCK(workers_db_free);

	return ok;
}

bool workers_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item = NULL;
	int n, t, i;
	WORKERS *row;
	char *field = NULL;
	char *sel;
	int fields = 7;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	int userid_num, workername_num, difficultydefault_num;
	int idlenotificationenabled_num, idlenotificationtime_num;
	int workerbits_num, workerid_num;
	HISTORYDATE_num;

	sel = "declare wk cursor for select "
		"userid,workername,difficultydefault,"
		"idlenotificationenabled,idlenotificationtime,workerbits"
		HISTORYDATECONTROL
		",workerid from workers";
	if (!CKPQBegin(conn))
		return false;

	// See workers_add() about this lock
	K_WLOCK(workers_db_free);

	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in wk", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	userid_num = workername_num = difficultydefault_num =
	idlenotificationenabled_num = idlenotificationtime_num =
	workerbits_num = workerid_num = CKPQFUNDEF;
	HISTORYDATE_init;
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			K_WLOCK(workers_free);
			item = k_unlink_head(workers_free);
			K_WUNLOCK(workers_free);
			DATA_WORKERS(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, userid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			CKPQ_VAL_FLD_num(res, i, workername, field, ok);
			if (!ok)
				break;
			row->in_workername = intransient_str("workername", field);

			CKPQ_VAL_FLD_num(res, i, difficultydefault, field, ok);
			if (!ok)
				break;
			TXT_TO_INT("difficultydefault", field, row->difficultydefault);

			CKPQ_VAL_FLD_num(res, i, idlenotificationenabled, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("idlenotificationenabled", field, row->idlenotificationenabled);

			CKPQ_VAL_FLD_num(res, i, idlenotificationtime, field, ok);
			if (!ok)
				break;
			TXT_TO_INT("idlenotificationtime", field, row->idlenotificationtime);

			CKPQ_VAL_FLD_num(res, i, workerbits, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workerbits", field, row->workerbits);

			HISTORYDATEFLDS(res, i, row, ok);
			if (!ok)
				break;

			CKPQ_VAL_FLD_num(res, i, workerid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workerid", field, row->workerid);

			K_WLOCK(workers_free);
			add_to_ktree(workers_root, item);
			k_add_head(workers_store, item);
			K_WUNLOCK(workers_free);

			// Make sure a workerstatus exists for each worker
			find_create_workerstatus(false, false, row->userid,
						 row->in_workername, true,
						 __FILE__, __func__, __LINE__);
			tick();
			n++;
		}
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in wk", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		userid_num = workername_num = difficultydefault_num =
		idlenotificationenabled_num = idlenotificationtime_num =
		workerbits_num = workerid_num = CKPQFUNDEF;
		HISTORYDATE_init;
	}
	if (!ok)
		k_add_head(workers_free, item);

	CKPQClear(res);
flail:

	CKPQCommit(conn);
	K_WUNLOCK(workers_db_free);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s workers records",
			   __func__, pcombuf);
	}

	return ok;
}

// Absolute address limit
#define ABS_ADDR_LIMIT 999

/* Whatever the current paymentaddresses are, replace them with the list
 *  in pa_store
 * Code allows for zero, one or more current payment address */
bool paymentaddresses_set(PGconn *conn, int64_t userid, K_STORE *pa_store,
			  char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item, *match, *next, *prev;
	PAYMENTADDRESSES *row, *pa;
	char *upd = NULL, *ins;
	size_t len, off;
	bool ok = false, first, locked = false;
	char *params[ABS_ADDR_LIMIT+3];
	char tmp[1024];
	int n, par = 0, count, matches;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	// Quick early abort
	if (pa_store->count > ABS_ADDR_LIMIT)
		return false;

	if (CKPQConn(&conn))
		conned = true;
	/* This means the nextid updates will rollback on an error, but also
	 *  means that it will lock the nextid record for the whole update */
	if (!CKPQBegin(conn))
		goto unparam;

	// First step - DB expire all the old/changed records in RAM
	LOGDEBUG("%s(): Step 1 userid=%"PRId64, __func__, userid);
	count = matches = 0;
	APPEND_REALLOC_INIT(upd, off, len);
	APPEND_REALLOC(upd, off, len,
			"update paymentaddresses set "EDDB"=$1 where "
			"userid=$2 and "EDDB"=$3 and payaddress in (");
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = bigint_to_buf(userid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);

	/* Since we are merging the changes in rather than just
	 *  replacing the db contents, lock the data for the duration
	 *  of the update to ensure nothing else changes it
	 * N.B. 'payname' isn't the start of the key
	 *  thus 2 different addresses can have the same 'payname' */
	K_WLOCK(paymentaddresses_free);
	locked = true;

	first = true;
	item = find_paymentaddresses(userid, ctx);
	DATA_PAYMENTADDRESSES_NULL(row, item);
	while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
		/* This is only possible if the DB was directly updated with more
		 * than ABS_ADDR_LIMIT records then reloaded (or a code bug) */
		if (++count > ABS_ADDR_LIMIT)
			break;

		// Find the RAM record in pa_store
		match = STORE_HEAD_NOLOCK(pa_store);
		while (match) {
			DATA_PAYMENTADDRESSES(pa, match);
			if (INTREQ(pa->in_payaddress, row->in_payaddress) &&
			    pa->payratio == row->payratio &&
			    strcmp(pa->payname, row->payname) == 0) {
				pa->match = true; // Don't store it
				matches++;
				break;
			}
			match = match->next;
		}
		if (!match) {
			// No matching replacement, so expire 'row'
			params[par++] = str_to_buf(row->in_payaddress, NULL, 0);
			if (!first)
				APPEND_REALLOC(upd, off, len, ",");
			first = false;
			snprintf(tmp, sizeof(tmp), "$%d", par);
			APPEND_REALLOC(upd, off, len, tmp);
		}
		item = prev_in_ktree(ctx);
		DATA_PAYMENTADDRESSES_NULL(row, item);
	}
	LOGDEBUG("%s(): Step 1 par=%d count=%d matches=%d first=%s", __func__,
		 par, count, matches, TFSTR(first));
	// Too many, or none need expiring = don't do the update
	if (count > ABS_ADDR_LIMIT || first == true) {
		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
		// Too many
		if (count > ABS_ADDR_LIMIT)
			goto rollback;
	} else {
		APPEND_REALLOC(upd, off, len, ")");
		PARCHKVAL(par, par, params);
		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		LOGDEBUG("%s(): Step 1 expired %d", __func__, par-3);

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
	}

	// Second step - add the non-matching records to the DB
	LOGDEBUG("%s(): Step 2", __func__);
	ins = "insert into paymentaddresses "
		"(paymentaddressid,userid,payaddress,payratio,payname"
		HISTORYDATECONTROL ") values (" PQPARAM10 ")";

	count = 0;
	match = STORE_HEAD_NOLOCK(pa_store);
	while (match) {
		DATA_PAYMENTADDRESSES(row, match);
		if (!row->match) {
			row->paymentaddressid = nextid(conn, "paymentaddressid", 1,
							cd, by, code, inet);
			if (row->paymentaddressid == 0)
				goto rollback;

			row->userid = userid;

			HISTORYDATEINTRANS(row, cd, by, code, inet);
			HISTORYDATETRANSFERIN(trf_root, row);

			par = 0;
			params[par++] = bigint_to_buf(row->paymentaddressid, NULL, 0);
			params[par++] = bigint_to_buf(row->userid, NULL, 0);
			params[par++] = str_to_buf(row->in_payaddress, NULL, 0);
			params[par++] = int_to_buf(row->payratio, NULL, 0);
			params[par++] = str_to_buf(row->payname, NULL, 0);
			HISTORYDATEPARAMSIN(params, par, row);
			PARCHKVAL(par, 10, params); // As per PQPARAM10 above

			res = CKPQExecParams(conn, ins, par, NULL, (const char **)params,
					   NULL, NULL, 0, CKPQ_WRITE);
			rescode = CKPQResultStatus(res);
			CKPQClear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto rollback;
			}

			for (n = 0; n < par; n++)
				free(params[n]);
			par = 0;

			count++;
		}
		match = match->next;
	}
	LOGDEBUG("%s(): Step 2 inserted %d", __func__, count);

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);
	FREENULL(upd);
	// Third step - do step 1 and 2 to the RAM version of the DB
	LOGDEBUG("%s(): Step 3, ok=%s", __func__, TFSTR(ok));
	matches = count = n = 0;
	if (ok) {
		// Change the expiry on all records that we expired in the DB
		item = find_paymentaddresses(userid, ctx);
		DATA_PAYMENTADDRESSES_NULL(row, item);
		while (item && CURRENT(&(row->expirydate)) && row->userid == userid) {
			prev = prev_in_ktree(ctx);
			// Find the RAM record in pa_store
			match = STORE_HEAD_NOLOCK(pa_store);
			while (match) {
				DATA_PAYMENTADDRESSES(pa, match);
				if (INTREQ(pa->in_payaddress, row->in_payaddress) &&
				    pa->payratio == row->payratio &&
				    strcmp(pa->payname, row->payname) == 0) {
					break;
				}
				match = match->next;
			}
			if (match)
				matches++;
			else {
				// It wasn't a match, thus it was expired
				n++;
				remove_from_ktree(paymentaddresses_root, item);
				remove_from_ktree(paymentaddresses_create_root, item);
				copy_tv(&(row->expirydate), cd);
				add_to_ktree(paymentaddresses_root, item);
				add_to_ktree(paymentaddresses_create_root, item);
			}
			item = prev;
			DATA_PAYMENTADDRESSES_NULL(row, item);
		}

		// Add in all the non-matching ps_store
		match = STORE_HEAD_NOLOCK(pa_store);
		while (match) {
			next = match->next;
			DATA_PAYMENTADDRESSES(pa, match);
			if (!pa->match) {
				add_to_ktree(paymentaddresses_root, match);
				add_to_ktree(paymentaddresses_create_root, match);
				k_unlink_item(pa_store, match);
				k_add_head(paymentaddresses_store, match);
				count++;
			}
			match = next;
		}
	}
	if (locked)
		K_WUNLOCK(paymentaddresses_free);

	LOGDEBUG("%s(): Step 3, untouched %d expired %d added %d", __func__, matches, n, count);

	// Calling function must clean up anything left in pa_store
	return ok;
}

bool paymentaddresses_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	PAYMENTADDRESSES *row;
	int n, i;
	char *field = NULL;
	char *sel;
	int fields = 5;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int paymentaddressid_num, userid_num, payaddress_num, payratio_num;
	int payname_num;
	HISTORYDATE_num;

	sel = "select "
		"paymentaddressid,userid,payaddress,payratio,payname"
		HISTORYDATECONTROL
		" from paymentaddresses";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	paymentaddressid_num = userid_num = payaddress_num = payratio_num =
	payname_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(paymentaddresses_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(paymentaddresses_free);
		DATA_PAYMENTADDRESSES(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, paymentaddressid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("paymentaddressid", field, row->paymentaddressid);

		CKPQ_VAL_FLD_num(res, i, userid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		CKPQ_VAL_FLD_num(res, i, payaddress, field, ok);
		if (!ok)
			break;
		row->in_payaddress = intransient_str("payaddress", field);

		CKPQ_VAL_FLD_num(res, i, payratio, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("payratio", field, row->payratio);

		CKPQ_VAL_FLD_num(res, i, payname, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("payname", field, row->payname);

		HISTORYDATEIN(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(paymentaddresses_root, item);
		add_to_ktree(paymentaddresses_create_root, item);
		k_add_head(paymentaddresses_store, item);
	}
	if (!ok)
		k_add_head(paymentaddresses_free, item);

	K_WUNLOCK(paymentaddresses_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s paymentaddresses records",
			   __func__, pcombuf);
	}

	return ok;
}

// The timing of the memory table updates depends on 'already'
void payments_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item, tv_t *cd)
{
	PAYMENTS *oldp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(payments_free);
	if (!ok) {
		// Cleanup for the calling function
		k_add_head(payments_free, p_item);
	} else {
		if (old_p_item) {
			DATA_PAYMENTS(oldp, old_p_item);
			remove_from_ktree(payments_root, old_p_item);
			copy_tv(&(oldp->expirydate), cd);
			add_to_ktree(payments_root, old_p_item);
		}
		add_to_ktree(payments_root, p_item);
		k_add_head(payments_store, p_item);
	}
	K_WUNLOCK(payments_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool payments_add(PGconn *conn, bool add, K_ITEM *p_item, K_ITEM **old_p_item,
		  char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root,
		  bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	PAYMENTS *row, *oldp = NULL;
	char *upd, *ins;
	char *params[11 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_PAYMENTS(row, p_item);
	K_RLOCK(payments_free);
	*old_p_item = find_payments(row->payoutid, row->userid, row->in_subname);
	K_RUNLOCK(payments_free);

	if (CKPQConn(&conn))
		conned = true;
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}

	if (*old_p_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_PAYMENTS(oldp, *old_p_item);

		upd = "update payments set "EDDB"=$1 where paymentid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldp->paymentid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;

		// Expiring an old record
		row->paymentid = oldp->paymentid;
	} else {
		if (add) {
			// Creating a new record
			row->paymentid = nextid(conn, "paymentid", (int64_t)1, cd, by, code, inet);
			if (row->paymentid == 0)
				goto rollback;
		}
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINTRANS(row, cd, by, code, inet);
		HISTORYDATETRANSFERIN(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->paymentid, NULL, 0);
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(row->userid, NULL, 0);
		params[par++] = str_to_buf(row->in_subname, NULL, 0);
		params[par++] = tv_to_buf(&(row->paydate), NULL, 0);
		params[par++] = str_to_buf(row->in_payaddress, NULL, 0);
		params[par++] = str_to_buf(row->in_originaltxn, NULL, 0);
		params[par++] = bigint_to_buf(row->amount, NULL, 0);
		params[par++] = double_to_buf(row->diffacc, NULL, 0);
		params[par++] = str_to_buf(row->in_committxn, NULL, 0);
		params[par++] = str_to_buf(row->in_commitblockhash, NULL, 0);
		HISTORYDATEPARAMSIN(params, par, row);
		PARCHK(par, params);

		ins = "insert into payments "
			"(paymentid,payoutid,userid,subname,paydate,payaddress,"
			"originaltxn,amount,diffacc,committxn,commitblockhash"
			HISTORYDATECONTROL ") values (" PQPARAM16 ")";

		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		payments_add_ram(ok, p_item, *old_p_item, cd);

	return ok;
}

bool payments_fill(PGconn *conn)
{
	char tickbuf[256], pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item = NULL;
	PAYMENTS *row;
	int n, t, i;
	char *field = NULL;
	char *sel;
	int fields = 11;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	STRNCPY(tickbuf, TICK_PREFIX"pm 0");
	cr_msg(false, tickbuf);

	int paymentid_num, payoutid_num, userid_num, subname_num, paydate_num;
	int payaddress_num, originaltxn_num, amount_num, diffacc_num;
	int committxn_num, commitblockhash_num;
	HISTORYDATE_num;

	sel = "declare ps cursor for select "
		"paymentid,payoutid,userid,subname,paydate,payaddress,"
		"originaltxn,amount,diffacc,committxn,commitblockhash"
		HISTORYDATECONTROL
		" from payments";
	if (!CKPQBegin(conn))
		return false;

	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in ps", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	paymentid_num = payoutid_num = userid_num = subname_num = paydate_num =
	payaddress_num = originaltxn_num = amount_num = diffacc_num =
	committxn_num = commitblockhash_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(payments_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(payments_free);
			DATA_PAYMENTS(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, paymentid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("paymentid", field, row->paymentid);

			CKPQ_VAL_FLD_num(res, i, payoutid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("payoutid", field, row->payoutid);

			CKPQ_VAL_FLD_num(res, i, userid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			CKPQ_VAL_FLD_num(res, i, subname, field, ok);
			if (!ok)
				break;
			row->in_subname = intransient_str("subname", field);

			CKPQ_VAL_FLD_num(res, i, paydate, field, ok);
			if (!ok)
				break;
			TXT_TO_TVDB("paydate", field, row->paydate);

			CKPQ_VAL_FLD_num(res, i, payaddress, field, ok);
			if (!ok)
				break;
			row->in_payaddress = intransient_str("payaddress", field);

			CKPQ_VAL_FLD_num(res, i, originaltxn, field, ok);
			if (!ok)
				break;
			row->in_originaltxn = intransient_str("originaltxn", field);

			CKPQ_VAL_FLD_num(res, i, amount, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("amount", field, row->amount);

			CKPQ_VAL_FLD_num(res, i, diffacc, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffacc", field, row->diffacc);

			CKPQ_VAL_FLD_num(res, i, committxn, field, ok);
			if (!ok)
				break;
			row->in_committxn = intransient_str("committxn", field);

			CKPQ_VAL_FLD_num(res, i, commitblockhash, field, ok);
			if (!ok)
				break;
			row->in_commitblockhash = intransient_str("commitblockhash", field);

			HISTORYDATEIN(res, i, row, ok);
			if (!ok)
				break;

			add_to_ktree(payments_root, item);
			k_add_head(payments_store, item);

			if (n == 0 || ((n+1) % FETCHTICK) == 0) {
				pcom(n+1, pcombuf, sizeof(pcombuf));
				snprintf(tickbuf, sizeof(tickbuf),
					 TICK_PREFIX"pm %s", pcombuf);
				cr_msg(false, tickbuf);
			}
			tick();
			n++;
		}
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in ps", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		paymentid_num = payoutid_num = userid_num = subname_num =
		paydate_num = payaddress_num = originaltxn_num = amount_num =
		diffacc_num = committxn_num = commitblockhash_num = CKPQFUNDEF;
		HISTORYDATE_init;
	}
	if (!ok)
		k_add_head(payments_free, item);

	K_WUNLOCK(payments_free);
	CKPQClear(res);
flail:

	CKPQCommit(conn);
	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s payments records",
			   __func__, pcombuf);
	}

	return ok;
}

bool idcontrol_add(PGconn *conn, char *idname, char *idvalue, char *by,
		   char *code, char *inet, tv_t *cd,
		   __maybe_unused K_TREE *trf_root)
{
	K_ITEM *item;
	IDCONTROL *row;
	char *params[2 + MODIFYDATECOUNT];
	int n, par = 0;
	bool ok = false;
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	char *ins;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(idcontrol_free);
	item = k_unlink_head(idcontrol_free);
	K_WUNLOCK(idcontrol_free);

	DATA_IDCONTROL(row, item);

	STRNCPY(row->idname, idname);
	TXT_TO_BIGINT("idvalue", idvalue, row->lastid);
	MODIFYDATEINTRANS(row, cd, by, code, inet);

	par = 0;
	params[par++] = str_to_buf(row->idname, NULL, 0);
	params[par++] = bigint_to_buf(row->lastid, NULL, 0);
	MODIFYDATEPARAMSIN(params, par, row);
	PARCHK(par, params);

	ins = "insert into idcontrol "
		"(idname,lastid" MODIFYDATECONTROL ") values (" PQPARAM10 ")";

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto foil;
	}

	ok = true;
foil:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	/* N.B. The DB key matches the tree key,
	 *	the tree depends on this to be valid */
	K_WLOCK(idcontrol_free);
	if (ok) {
		add_to_ktree(idcontrol_root, item);
		k_add_head(idcontrol_store, item);
	} else
		k_add_head(idcontrol_free, item);
	K_WUNLOCK(idcontrol_free);

	return ok;
}

bool idcontrol_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	IDCONTROL *row;
	char *field = NULL;
	char *sel;
	int fields = 2;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int idname_num, lastid_num;
	MODIFYDATE_num;

	sel = "select "
		"idname,lastid"
		MODIFYDATECONTROL
		" from idcontrol";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + MODIFYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + MODIFYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	idname_num = lastid_num = CKPQFUNDEF;
	MODIFYDATE_init;
	K_WLOCK(idcontrol_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(idcontrol_free);
		DATA_IDCONTROL(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, idname, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("idname", field, row->idname);

		CKPQ_VAL_FLD_num(res, i, lastid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("lastid", field, row->lastid);

		MODIFYDATEIN(res, i, row, ok);
		if (!ok)
			break;

		/* N.B. The DB key matches the tree key,
		 *	the tree depends on this to be valid */
		add_to_ktree(idcontrol_root, item);
		k_add_head(idcontrol_store, item);
	}
	if (!ok)
		k_add_head(idcontrol_free, item);

	K_WUNLOCK(idcontrol_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s idcontrol records",
			   __func__, pcombuf);
	}

	return ok;
}

void oc_switch_state(OPTIONCONTROL *oc, const char *from)
{
	switch_state = atoi(oc->optionvalue);
	LOGWARNING("%s(%s) set switch_state to %d",
		   from, __func__, switch_state);
}

void oc_diff_percent(OPTIONCONTROL *oc, __maybe_unused const char *from)
{
	diff_percent = DIFF_VAL(strtod(oc->optionvalue, NULL));
	if (errno == ERANGE)
		diff_percent = DIFF_VAL(DIFF_PERCENT_DEFAULT);
}

/* An event limit setting looks like:
 *	OC_LIMITS + event_limits.name + '_' + Item
 * Item is one of the field names in event_limits
 * 	e.g. user_low_time, user_low_time_limit etc
 * 		as below in the if tests
 *	lifetime values can't = EVENT_OK */
void oc_event_limits(OPTIONCONTROL *oc, const char *from)
{
	bool processed = false;
	size_t len;
	char *ptr, *ptr2;
	int val, i;

	K_WLOCK(event_limits_free);
	val = atoi(oc->optionvalue);
	ptr = oc->optionname + strlen(OC_LIMITS);
	i = -1;
	while (e_limits[++i].name) {
		len = strlen(e_limits[i].name);
		if (strncmp(ptr, e_limits[i].name, len) == 0 &&
		    ptr[len] == '_') {
			ptr2 = ptr + len + 1;
			if (strcmp(ptr2, "user_low_time") == 0) {
				e_limits[i].user_low_time = val;
			} else if (strcmp(ptr2, "user_low_time_limit") == 0) {
				e_limits[i].user_low_time_limit = val;
			} else if (strcmp(ptr2, "user_hi_time") == 0) {
				e_limits[i].user_hi_time = val;
			} else if (strcmp(ptr2, "user_hi_time_limit") == 0) {
				e_limits[i].user_hi_time_limit = val;
			} else if (strcmp(ptr2, "ip_low_time") == 0) {
				e_limits[i].ip_low_time = val;
			} else if (strcmp(ptr2, "ip_low_time_limit") == 0) {
				e_limits[i].ip_low_time_limit = val;
			} else if (strcmp(ptr2, "ip_hi_time") == 0) {
				e_limits[i].ip_hi_time = val;
			} else if (strcmp(ptr2, "ip_hi_time_limit") == 0) {
				e_limits[i].ip_hi_time_limit = val;
			} else if (strcmp(ptr2, "lifetime") == 0) {
				if (val != EVENT_OK)
					e_limits[i].lifetime = val;
				else {
					LOGERR("%s(%s): ERR: lifetime can't be"
						" %d in '%s'",
						from, __func__, EVENT_OK,
						oc->optionname);
				}
			} else if (strcmp(ptr2, "enabled") == 0) {
				char ch = toupper(oc->optionvalue[0]);
				if (ch == TRUE_CHR || ch == TRUE2_CHR)
					e_limits[i].enabled = true;
				else
					e_limits[i].enabled = false;
			} else {
				LOGERR("%s(%s): ERR: Unknown %s item '%s' "
					"in '%s'",
					from, __func__, OC_LIMITS, ptr2,
					oc->optionname);
			}
			processed = true;
			break;
		}
	}
	if (!processed) {
		if (strcmp(ptr, "hash_lifetime") == 0) {
			if (val != EVENT_OK)
				event_limits_hash_lifetime = val;
			else {
				LOGERR("%s(%s): ERR: lifetime can't be"
					" %d in '%s'",
					from, __func__, EVENT_OK,
					oc->optionname);
			}
			processed = true;
		}
	}
	K_WUNLOCK(event_limits_free);
	if (!processed) {
		LOGERR("%s(%s): ERR: Unknown %s name '%s'",
			from, __func__, OC_LIMITS, oc->optionname);
	}
}

/* An ovent limit setting looks like:
 *	OC_OLIMITS + event_limits.name + '_' + Item
 * Item is one of the field names in event_limits
 * 	e.g. user_low_time, user_low_time_limit etc
 * 		as below in the if tests
 *	lifetime values can't = OVENT_OK */
void oc_ovent_limits(OPTIONCONTROL *oc, const char *from)
{
	bool processed = false, lifetime_changed = false;
	size_t len;
	char *ptr, *ptr2;
	int val, i;

	K_WLOCK(event_limits_free);
	val = atoi(oc->optionvalue);
	ptr = oc->optionname + strlen(OC_OLIMITS);
	i = -1;
	while (o_limits[++i].name) {
		len = strlen(o_limits[i].name);
		if (strncmp(ptr, o_limits[i].name, len) == 0 &&
		    ptr[len] == '_') {
			ptr2 = ptr + len + 1;
			if (strcmp(ptr2, "user_low_time") == 0) {
				o_limits[i].user_low_time = val;
			} else if (strcmp(ptr2, "user_low_time_limit") == 0) {
				o_limits[i].user_low_time_limit = val;
			} else if (strcmp(ptr2, "user_hi_time") == 0) {
				o_limits[i].user_hi_time = val;
			} else if (strcmp(ptr2, "user_hi_time_limit") == 0) {
				o_limits[i].user_hi_time_limit = val;
			} else if (strcmp(ptr2, "ip_low_time") == 0) {
				o_limits[i].ip_low_time = val;
			} else if (strcmp(ptr2, "ip_low_time_limit") == 0) {
				o_limits[i].ip_low_time_limit = val;
			} else if (strcmp(ptr2, "ip_hi_time") == 0) {
				o_limits[i].ip_hi_time = val;
			} else if (strcmp(ptr2, "ip_hi_time_limit") == 0) {
				o_limits[i].ip_hi_time_limit = val;
			} else if (strcmp(ptr2, "lifetime") == 0) {
				if (val != OVENT_OK) {
					o_limits[i].lifetime = val;
					lifetime_changed = true;
				} else {
					LOGERR("%s(%s): ERR: lifetime can't be"
						" %d in '%s'",
						from, __func__, OVENT_OK,
						oc->optionname);
				}
			} else if (strcmp(ptr2, "enabled") == 0) {
				char ch = toupper(oc->optionvalue[0]);
				if (ch == TRUE_CHR || ch == TRUE2_CHR)
					o_limits[i].enabled = true;
				else
					o_limits[i].enabled = false;
			} else {
				LOGERR("%s(%s): ERR: Unknown %s item '%s' "
					"in '%s'",
					from, __func__, OC_OLIMITS, ptr2,
					oc->optionname);
			}
			processed = true;
			break;
		}
	}
	if (!processed) {
		if (strcmp(ptr, "ipc_factor") == 0) {
			ovent_limits_ipc_factor = atof(oc->optionvalue);
			processed = true;
		}
	}
	if (lifetime_changed) {
		o_limits_max_lifetime = -1;
		i = -1;
		while (o_limits[++i].name) {
			if (o_limits_max_lifetime < o_limits[i].lifetime)
				o_limits_max_lifetime = o_limits[i].lifetime;
		}
	}
	K_WUNLOCK(event_limits_free);
	if (!processed) {
		LOGERR("%s(%s): ERR: Unknown %s name '%s'",
			from, __func__, OC_OLIMITS, oc->optionname);
	}
}

/* IPS for IPS_GROUP_OK/BAN look like:
 *	optionname: (OC_IPS_OK or OC_IPS_BAN) + description
 *	optionvalue: is the IP address:EVENTNAME
 * If you want to add the cclass subnet of an IP then add it separately
 * 127.0.0.1 is hard coded OK in ckdb.c */
void oc_ips(OPTIONCONTROL *oc, const char *from)
{
	char *colon;
	IPS ips;
	bool e;

	colon = strchr(oc->optionvalue, ':');
	if (!colon) {
		LOGERR("%s(%s): ERR: Missing ':' after IP '%s' name '%s'",
			from, __func__, oc->optionvalue, oc->optionname);
		return;
	}
	STRNCPY(ips.eventname, colon+1);

	STRNCPY(ips.ip, oc->optionvalue);
	colon = strchr(ips.ip, ':');
	if (colon)
		*colon = '\0';

	if (strncmp(oc->optionname, OC_IPS_OK, strlen(OC_IPS_OK)) == 0) {
		e = is_elimitname(ips.eventname, true);
		ips_add(IPS_GROUP_OK, ips.ip, ips.eventname, e,
			oc->optionname, false, false, 0, false);
	} else if (strncmp(oc->optionname, OC_IPS_BAN,
			   strlen(OC_IPS_BAN)) == 0) {
		e = is_elimitname(ips.eventname, true);
		ips_add(IPS_GROUP_BAN, ips.ip, ips.eventname, e,
			oc->optionname, false, false, 0, false);
	} else {
		LOGERR("%s(%s): ERR: Unknown %s name '%s'",
			from, __func__, OC_IPS, oc->optionname);
	}
}

void oc_trf(OPTIONCONTROL *oc, const char *from)
{
	int ct;

	ct = atoi(oc->optionvalue);
	if (ct < 0 || ct > 64) {
		LOGERR("%s(%s) ERR set cull_transfer ignored '%s' (%d)"
			" must be 0..64",
			from, __func__, oc->optionvalue, ct);
	} else {
		K_WLOCK(transfer_free);
		// ct isn't the value, it's the multiplier
		cull_transfer = ct * ALLOC_TRANSFER;
		transfer_free->cull_limit = cull_transfer;
		K_WUNLOCK(transfer_free);
		LOGWARNING("%s(%s) set cull_transfer to %d->%d",
			   from, __func__, ct, cull_transfer);
	}
}

/* Trigger functions shouldn't touch expirydate since the optioncontrol data
 *  isn't locked - that's the only field that could change */
OC_TRIGGER oc_trigger[] = {
	{ SWITCH_STATE_NAME,	true,	oc_switch_state },
	{ DIFF_PERCENT_NAME,	true,	oc_diff_percent },
	{ OC_LIMITS,		false,	oc_event_limits },
	{ OC_OLIMITS,		false,	oc_ovent_limits },
	{ OC_IPS,		false,	oc_ips },
	{ CULL_TRANSFER_NAME,	true,	oc_trf },
	{ NULL, 0, NULL }
};

/* For oc items that aren't date/height controlled, and use global variables
 *  rather than having to look up the value every time it's needed
 * Called from within the write lock that loaded/added the oc_item
 * The write lock is released before calling the trigger function,
 *  and regained after it returns, thus expirydate shouldn't be accessed
 *  since it's value could be changed by another thread, under lock
 *  None of the other oc field values will change */
static void optioncontrol_trigger(K_ITEM *oc_item, const char *from)
{
	char cd_buf[DATE_BUFSIZ], cd2_buf[DATE_BUFSIZ];
	OPTIONCONTROL *oc;
	int got, i;

	DATA_OPTIONCONTROL(oc, oc_item);
	if (CURRENT(&(oc->expirydate))) {
		got = -1;
		for (i = 0; oc_trigger[i].match; i++) {
			if (oc_trigger[i].exact) {
				if (strcmp(oc->optionname,
					   oc_trigger[i].match) == 0) {
					got = i;
					break;
				}
			} else {
				if (strncmp(oc->optionname, oc_trigger[i].match,
					    strlen(oc_trigger[i].match)) == 0) {
					got = i;
					break;
				}
			}
		}
		if (got > -1) {
			/* Don't hold the lock during debug messages or
			 *  during the call to the trigger function */
			K_WUNLOCK(optioncontrol_free);
			// If it's date/height controlled, display an ERR
			if (oc->activationheight != OPTIONCONTROL_HEIGHT ||
			    tv_newer(&date_begin, &(oc->activationdate)))
			{
				tv_to_buf(&(oc->activationdate), cd_buf,
					  sizeof(cd_buf));
				tv_to_buf((tv_t *)&date_begin, cd2_buf,
					  sizeof(cd_buf));
				LOGERR("%s(%s) ERR: ignored '%s' - has "
					"height %"PRId32" & date '%s' - "
					"expect height %d & date <= '%s'",
					from, __func__, oc->optionname,
					oc->activationheight, cd_buf,
					OPTIONCONTROL_HEIGHT, cd2_buf);
			} else
				oc_trigger[i].func(oc, from);
			K_WLOCK(optioncontrol_free);
		}
	}
}

K_ITEM *optioncontrol_item_add(PGconn *conn, K_ITEM *oc_item, tv_t *cd, bool begun)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *old_item, look;
	OPTIONCONTROL *row, *oc;
	char *upd, *ins;
	bool ok = false;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	DATA_OPTIONCONTROL(row, oc_item);

	// Enforce the rule that switch_state isn't date/height controlled
	if (strcmp(row->optionname, SWITCH_STATE_NAME) == 0) {
		row->activationdate.tv_sec = date_begin.tv_sec;
		row->activationdate.tv_usec = date_begin.tv_usec;
		row->activationheight = OPTIONCONTROL_HEIGHT;
	}

	INIT_OPTIONCONTROL(&look);
	look.data = (void *)row;
	K_RLOCK(optioncontrol_free);
	old_item = find_in_ktree(optioncontrol_root, &look, ctx);
	K_RUNLOCK(optioncontrol_free);

	if (CKPQConn(&conn))
		conned = true;
	if (!begun) {
		if (!CKPQBegin(conn))
			goto nostart;
	}

	if (old_item) {
		upd = "update optioncontrol "
			"set "EDDB"=$1 where optionname=$2 and "
			"activationdate=$3 and activationheight=$4 and "
			EDDB"=$5";

		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = str_to_buf(row->optionname, NULL, 0);
		params[par++] = tv_to_buf(&(row->activationdate), NULL, 0);
		params[par++] = int_to_buf(row->activationheight, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 5, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
	}

	par = 0;
	params[par++] = str_to_buf(row->optionname, NULL, 0);
	params[par++] = str_to_buf(row->optionvalue, NULL, 0);
	params[par++] = tv_to_buf(&(row->activationdate), NULL, 0);
	params[par++] = int_to_buf(row->activationheight, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into optioncontrol "
		"(optionname,optionvalue,activationdate,activationheight"
		HISTORYDATECONTROL ") values (" PQPARAM9 ")";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:
	if (!begun)
		CKPQEnd(conn, ok);

nostart:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	/* N.B. if the DB update fails,
	 *	optioncontrol_trigger() will not be called */
	K_WLOCK(optioncontrol_free);
	if (!ok) {
		// Cleanup item passed in
		free_optioncontrol_data(oc_item);
		k_add_head(optioncontrol_free, oc_item);
	} else {
		// Keep old to ensure the new item can be read outside lock
		if (old_item) {
			remove_from_ktree(optioncontrol_root, old_item);
			DATA_OPTIONCONTROL(oc, old_item);
			copy_tv(&(oc->expirydate), cd);
			add_to_ktree(optioncontrol_root, old_item);
		}
		add_to_ktree(optioncontrol_root, oc_item);
		k_add_head(optioncontrol_store, oc_item);

		optioncontrol_trigger(oc_item, __func__);
	}
	K_WUNLOCK(optioncontrol_free);

	if (ok)
		return oc_item;
	else
		return NULL;
}

K_ITEM *optioncontrol_add(PGconn *conn, char *optionname, char *optionvalue,
			  char *activationdate, char *activationheight,
			  char *by, char *code, char *inet, tv_t *cd,
			  K_TREE *trf_root, bool begun)
{
	K_ITEM *item;
	OPTIONCONTROL *row;

	LOGDEBUG("%s(): add", __func__);

	if (pgdb_paused)
		LOGEMERG("ERR: %s() called when paused - data lost", __func__);

	K_WLOCK(optioncontrol_free);
	item = k_unlink_head(optioncontrol_free);
	K_WUNLOCK(optioncontrol_free);

	DATA_OPTIONCONTROL(row, item);
	bzero(row, sizeof(*row));

	STRNCPY(row->optionname, optionname);
	row->optionvalue = strdup(optionvalue);
	if (!(row->optionvalue))
		quithere(1, "malloc (%d) OOM", (int)strlen(optionvalue));
	if (activationdate && *activationdate) {
		TXT_TO_CTV("activationdate", activationdate,
			   row->activationdate);
	} else
		copy_tv(&(row->activationdate), &date_begin);
	if (activationheight && *activationheight) {
		TXT_TO_INT("activationheight", activationheight,
			   row->activationheight);
	} else
		row->activationheight = OPTIONCONTROL_HEIGHT;

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	return optioncontrol_item_add(conn, item, cd, begun);
}

bool optioncontrol_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	OPTIONCONTROL *row;
	K_TREE_CTX ctx[1];
	IPS *ips;
	char *params[1];
	int n, i, par = 0, ban_count, ok_count;
	char *field = NULL;
	char *sel;
	int fields = 4;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int optionname_num, optionvalue_num, activationdate_num;
	int activationheight_num;
	HISTORYDATE_num;

	// No need to keep old versions in ram for now ...
	sel = "select "
		"optionname,optionvalue,activationdate,activationheight"
		HISTORYDATECONTROL
		" from optioncontrol where "EDDB"=$1";
	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	PARCHK(par, params);
	res = CKPQExecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	optionname_num = optionvalue_num = activationdate_num =
	activationheight_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(optioncontrol_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(optioncontrol_free);
		DATA_OPTIONCONTROL(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, optionname, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("optionname", field, row->optionname);

		CKPQ_VAL_FLD_num(res, i, optionvalue, field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("optionvalue", field, row->optionvalue);
		LIST_MEM_ADD(optioncontrol_free, row->optionvalue);

		CKPQ_VAL_FLD_num(res, i, activationdate, field, ok);
		if (!ok)
			break;
		TXT_TO_TVDB("activationdate", field, row->activationdate);

		CKPQ_VAL_FLD_num(res, i, activationheight, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("activationheight", field, row->activationheight);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(optioncontrol_root, item);
		k_add_head(optioncontrol_store, item);

		optioncontrol_trigger(item, __func__);
	}
	if (!ok) {
		free_optioncontrol_data(item);
		k_add_head(optioncontrol_free, item);
	}

	K_WUNLOCK(optioncontrol_free);
	CKPQClear(res);
	for (n = 0; n < par; n++)
		free(params[n]);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s optioncontrol records",
			   __func__, pcombuf);
		LOGWARNING("%s() switch_state initially %d",
			   __func__, switch_state);

		ok_count = ban_count = 0;
		K_RLOCK(ips_free);
		item = first_in_ktree(ips_root, ctx);
		while (item) {
			DATA_IPS(ips, item);
			if (CURRENT(&(ips->expirydate))) {
				if (strcmp(ips->group, IPS_GROUP_OK) == 0)
					ok_count++;
				else if (strcmp(ips->group, IPS_GROUP_BAN) == 0)
					ban_count++;
			}
			item = next_in_ktree(ctx);
		}
		K_RUNLOCK(ips_free);

		LOGWARNING("%s() IPS: %s:%d %s:%d",
			   __func__, IPS_GROUP_OK, ok_count,
			   IPS_GROUP_BAN, ban_count);
	}

	return ok;
}

int64_t workinfo_add(PGconn *conn, char *workinfoidstr,
			INTRANSIENT *in_poolinstance, char *transactiontree,
			char *merklehash, INTRANSIENT *in_prevhash,
			char *coinbase1, char *coinbase2,
			INTRANSIENT *in_version, INTRANSIENT *in_bits,
			char *ntime, char *reward, char *by, char *code,
			char *inet, tv_t *cd, bool igndup, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	K_TREE_CTX ctx[1];
	PGresult *res;
	K_ITEM *item;
	char cd_buf[DATE_BUFSIZ];
	char ndiffbin[TXT_SML+1];
	int64_t workinfoid = -1;
	WORKINFO *row;
	char *ins;
	char *params[11 + HISTORYDATECOUNT];
	int n, par = 0;
	bool zero_active = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(workinfo_free);
	item = k_unlink_head(workinfo_free);
	K_WUNLOCK(workinfo_free);

	DATA_WORKINFO(row, item);
	bzero(row, sizeof(*row));

	TXT_TO_BIGINT("workinfoid", workinfoidstr, row->workinfoid);
	row->in_poolinstance = in_poolinstance->str;
	DUP_POINTER(workinfo_free, row->transactiontree, transactiontree);
	DUP_POINTER(workinfo_free, row->merklehash, merklehash);
	row->in_prevhash = in_prevhash->str;
	DUP_POINTER(workinfo_free, row->coinbase1, coinbase1);
	DUP_POINTER(workinfo_free, row->coinbase2, coinbase2);
	row->in_version = in_version->str;
	row->in_bits = in_bits->str;
	STRNCPY(row->ntime, ntime);
	TXT_TO_BIGINT("reward", reward, row->reward);
	pool.reward = row->reward;

	HISTORYDATEINTRANS(row, cd, by, code, inet);
	HISTORYDATETRANSFERIN(trf_root, row);

	K_WLOCK(workinfo_free);
	if (find_in_ktree(workinfo_root, item, ctx)) {
		workinfoid = row->workinfoid;
		free_workinfo_data(item);
		k_add_head(workinfo_free, item);
		K_WUNLOCK(workinfo_free);

		if (!igndup) {
			tv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s(): Duplicate workinfo ignored %s/%s/%s",
				__func__, workinfoidstr, in_poolinstance->str,
				cd_buf);
		}

		return workinfoid;
	}
	K_WUNLOCK(workinfo_free);

	if (!confirm_sharesummary) {
		par = 0;
		params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
		params[par++] = str_to_buf(row->in_poolinstance, NULL, 0);
		params[par++] = str_to_buf(row->transactiontree, NULL, 0);
		params[par++] = str_to_buf(row->merklehash, NULL, 0);
		params[par++] = str_to_buf(row->in_prevhash, NULL, 0);
		params[par++] = str_to_buf(row->coinbase1, NULL, 0);
		params[par++] = str_to_buf(row->coinbase2, NULL, 0);
		params[par++] = str_to_buf(row->in_version, NULL, 0);
		params[par++] = str_to_buf(row->in_bits, NULL, 0);
		params[par++] = str_to_buf(row->ntime, NULL, 0);
		params[par++] = bigint_to_buf(row->reward, NULL, 0);
		HISTORYDATEPARAMSIN(params, par, row);
		PARCHK(par, params);

		ins = "insert into workinfo "
			"(workinfoid,poolinstance,transactiontree,merklehash,"
			"prevhash,coinbase1,coinbase2,version,bits,ntime,reward"
			HISTORYDATECONTROL ") values (" PQPARAM16 ")";

		if (CKPQConn(&conn))
			conned = true;
		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	workinfoid = row->workinfoid;

unparam:
	if (par) {
		CKPQDisco(&conn, conned);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(workinfo_free);
	if (workinfoid == -1) {
		free_workinfo_data(item);
		k_add_head(workinfo_free, item);
	} else {
		// Not currently needed in RAM
		LIST_MEM_SUB(workinfo_free, row->transactiontree);
		FREENULL(row->transactiontree);
		LIST_MEM_SUB(workinfo_free, row->merklehash);
		FREENULL(row->merklehash);

		row->height = coinbase1height(row);
		hex2bin(ndiffbin, row->in_bits, 4);
		row->diff_target = current_ndiff = diff_from_nbits(ndiffbin);

		add_to_ktree(workinfo_root, item);
		k_add_head(workinfo_store, item);

		// Remember the bc = 'cd' when the height changes
		if (workinfo_current) {
			WORKINFO *wic;
			DATA_WORKINFO(wic, workinfo_current);
			if (wic->height != row->height) {
				copy_tv(&last_bc, cd);
				zero_active = true;
			}
		}

		workinfo_current = item;
	}
	K_WUNLOCK(workinfo_free);

	if (zero_active)
		zero_all_active(cd);

	return workinfoid;
}

bool workinfo_fill(PGconn *conn)
{
	char tickbuf[256], pcombuf[64];
	char ndiffbin[TXT_SML+1];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item = NULL;
	WORKINFO *row;
	char *params[3];
	int n, t, i, par = 0;
	char *field = NULL;
	char *sel = NULL;
	size_t len, off;
	int fields = 10;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	STRNCPY(tickbuf, TICK_PREFIX"wi 0");
	cr_msg(false, tickbuf);

	int workinfoid_num, poolinstance_num, merklehash_num, prevhash_num;
	int coinbase1_num, coinbase2_num, version_num, bits_num, ntime_num;
	int reward_num;
	HISTORYDATE_num;

	APPEND_REALLOC_INIT(sel, off, len);
	APPEND_REALLOC(sel, off, len,
			"declare wi cursor for select "
			"workinfoid,poolinstance,merklehash,prevhash,"
			"coinbase1,coinbase2,version,bits,ntime,reward"
			HISTORYDATECONTROL
			" from workinfo where "EDDB"=$1 and"
			" ((workinfoid>=$2 and workinfoid<=$3)");

	/* If we aren't loading the full range, ensure the necessary ones are loaded
	 * However, don't for key_update to allow a possible lower memory profile */
	if (((!dbload_only_sharesummary && dbload_workinfoid_start != -1) ||
	    dbload_workinfoid_finish != MAXID) && !key_update) {
		APPEND_REALLOC(sel, off, len,
				// we need all blocks workinfoids
				" or workinfoid in (select workinfoid from blocks)"
				// we need all marks workinfoids
				" or workinfoid in (select workinfoid from marks)"
				// we need all workmarkers workinfoids (start and end)
				" or workinfoid in (select workinfoidstart from workmarkers)"
				" or workinfoid in (select workinfoidend from workmarkers)");
	}
	APPEND_REALLOC(sel, off, len, ")");

	par = 0;
	params[par++] = tv_to_buf((tv_t *)(&default_expiry), NULL, 0);
	if (dbload_only_sharesummary)
		params[par++] = bigint_to_buf(-1, NULL, 0);
	else
		params[par++] = bigint_to_buf(dbload_workinfoid_start, NULL, 0);
	params[par++] = bigint_to_buf(dbload_workinfoid_finish, NULL, 0);
	PARCHK(par, params);

	if (!CKPQBegin(conn))
		return false;

	if (exclusive_db) {
		res = CKPQExec(conn, "Lock table workinfo in access exclusive mode", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Lock", rescode, conn);
			goto flail;
		}
	}

	res = CKPQExecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in wi", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	workinfoid_num = poolinstance_num = merklehash_num = prevhash_num =
	coinbase1_num = coinbase2_num = version_num = bits_num = ntime_num =
	reward_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(workinfo_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(workinfo_free);
			DATA_WORKINFO(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, poolinstance, field, ok);
			if (!ok)
				break;
			if (sys_poolinstance && strcmp(field, sys_poolinstance)) {
				k_add_head(workinfo_free, item);
				POOLINSTANCE_DBLOAD_SET(workinfo, field);
				continue;
			}
			row->in_poolinstance = intransient_str("poolinstance", field);

			CKPQ_VAL_FLD_num(res, i, workinfoid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

			row->transactiontree = EMPTY;
			row->merklehash = EMPTY;

			CKPQ_VAL_FLD_num(res, i, prevhash, field, ok);
			if (!ok)
				break;
			row->in_prevhash = intransient_str("prevhash", field);

			CKPQ_VAL_FLD_num(res, i, coinbase1, field, ok);
			if (!ok)
				break;
			TXT_TO_BLOB("coinbase1", field, row->coinbase1);
			LIST_MEM_ADD(workinfo_free, row->coinbase1);

			CKPQ_VAL_FLD_num(res, i, coinbase2, field, ok);
			if (!ok)
				break;
			TXT_TO_BLOB("coinbase2", field, row->coinbase2);
			LIST_MEM_ADD(workinfo_free, row->coinbase2);

			CKPQ_VAL_FLD_num(res, i, version, field, ok);
			if (!ok)
				break;
			row->in_version = intransient_str("version", field);

			CKPQ_VAL_FLD_num(res, i, bits, field, ok);
			if (!ok)
				break;
			row->in_bits = intransient_str("bits", field);

			CKPQ_VAL_FLD_num(res, i, ntime, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("ntime", field, row->ntime);

			CKPQ_VAL_FLD_num(res, i, reward, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("reward", field, row->reward);
			pool.reward = row->reward;

			HISTORYDATEIN(res, i, row, ok);
			if (!ok)
				break;

			row->height = coinbase1height(row);
			hex2bin(ndiffbin, row->in_bits, 4);
			row->diff_target = diff_from_nbits(ndiffbin);

			add_to_ktree(workinfo_root, item);
			if (!confirm_sharesummary)
				add_to_ktree(workinfo_height_root, item);
			k_add_head(workinfo_store, item);

			if (tv_newer(&(dbstatus.newest_createdate_workinfo), &(row->createdate))) {
				copy_tv(&(dbstatus.newest_createdate_workinfo), &(row->createdate));
				dbstatus.newest_workinfoid = row->workinfoid;
			}

			if (n == 0 || ((n+1) % FETCHTICK) == 0) {
				pcom(n+1, pcombuf, sizeof(pcombuf));
				snprintf(tickbuf, sizeof(tickbuf),
					 TICK_PREFIX"wi %s", pcombuf);
				cr_msg(false, tickbuf);
			}
			tick();
			n++;
		}
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in wi", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		workinfoid_num = poolinstance_num = merklehash_num =
		prevhash_num = coinbase1_num = coinbase2_num = version_num =
		bits_num = ntime_num = reward_num = CKPQFUNDEF;
		HISTORYDATE_init;
	}
	if (!ok) {
		free_workinfo_data(item);
		k_add_head(workinfo_free, item);
	} else {
		K_WLOCK(blocks_free);
		ok = set_prevcreatedate(0);
		K_WUNLOCK(blocks_free);
	}

	K_WUNLOCK(workinfo_free);
	CKPQClear(res);
flail:

	CKPQCommit(conn);
	for (i = 0; i < par; i++)
		free(params[i]);
	par = 0;

	free(sel);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s workinfo records",
			   __func__, pcombuf);
	}

	POOLINSTANCE_DBLOAD_MSG(workinfo);
	return ok;
}

static bool shares_process(PGconn *conn, SHARES *shares, K_ITEM *wi_item,
			   K_TREE *trf_root)
{
	K_ITEM *w_item, *wm_item, *ss_item;
	SHARESUMMARY *sharesummary;
	char complete[TXT_FLAG+1];
	WORKINFO *workinfo;
	char *st = NULL;

	LOGDEBUG("%s() add", __func__);

	if (diff_percent >= 0.0) {
		DATA_WORKINFO(workinfo, wi_item);
		if (shares->sdiff >= (workinfo->diff_target * diff_percent)) {
			bool block = (shares->sdiff >= workinfo->diff_target);
			char *sta = NULL, pct[16] = "?", est[16] = "";
			switch (shares->errn) {
				case SE_NONE:
					break;
				case SE_STALE:
					sta = "STALE";
					break;
				case SE_DUPE:
					sta = "Dup";
					break;
				case SE_HIGH_DIFF:
					sta = "HI";
					break;
				default:
					sta = "UNKNOWN";
					break;
			}
			if (pool.diffacc >= 1000.0) {
				est[0] = ' ';
				suffix_string(pool.diffacc, est+1, sizeof(est)-2, 0);
			}
			if (workinfo->diff_target > 0.0) {
				snprintf(pct, sizeof(pct), " %.2f%%",
					 100.0 * pool.diffacc /
					 workinfo->diff_target);
			}
			LOGWARNING("%s (%"PRIu32") %s Diff %.1f%% (%.0f/%.1f) "
				   "%s Pool %.1f%s%s",
				   block ? "BLOCK!" : "Share", workinfo->height,
				   (sta == NULL) ? "ok" : sta,
				   100.0 * shares->sdiff / workinfo->diff_target,
				   shares->sdiff, workinfo->diff_target,
				   st = safe_text_nonull(shares->in_workername),
				   pool.diffacc, est, pct);
			FREENULL(st);
		}
	}

	w_item = new_default_worker(conn, false, shares->userid,
				    shares->in_workername, shares->createby,
				    shares->createcode, shares->createinet,
				    &(shares->createdate), trf_root);
	if (!w_item) {
		LOGERR("%s(): ERR new_default_worker failed"
			" %"PRId64"/%s/%ld,%ld",
			__func__, shares->userid,
			st = safe_text_nonull(shares->in_workername),
			shares->createdate.tv_sec, shares->createdate.tv_usec);
		FREENULL(st);
		return false;
	}

	if (reloading && !key_update && !confirm_sharesummary) {
		// We only need to know if the workmarker is processed
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkers(shares->workinfoid, false,
					   MARKER_PROCESSED, NULL);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			LOGERR("%s(): ERR workmarker exists for wid %"PRId64
				" %"PRId64"/%s/%ld,%ld",
				__func__, shares->workinfoid, shares->userid,
				st = safe_text_nonull(shares->in_workername),
				shares->createdate.tv_sec,
				shares->createdate.tv_usec);
			FREENULL(st);
			return false;
		}

		K_RLOCK(sharesummary_free);
		ss_item = find_sharesummary(shares->userid, shares->in_workername,
					    shares->workinfoid);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				STRNCPY(complete, sharesummary->complete);
				K_RUNLOCK(sharesummary_free);
				LOGDEBUG("%s(): '%s' sharesummary exists "
					 "%"PRId64" %"PRId64"/%s/%ld,%ld",
					 __func__, complete,
					 shares->workinfoid, shares->userid,
					 st = safe_text_nonull(shares->in_workername),
					 shares->createdate.tv_sec,
					 shares->createdate.tv_usec);
				FREENULL(st);
				// Reloading a share already summarised
				return true;
			}
		}
		K_RUNLOCK(sharesummary_free);
	}

	if (!key_update && !confirm_sharesummary) {
		workerstatus_update(NULL, shares, NULL);
		K_WLOCK(userinfo_free);
		userinfo_update(shares, NULL, NULL, false);
		K_WUNLOCK(userinfo_free);
	}

	sharesummary_update(shares, NULL, &(shares->createdate));

	return true;
}

// If it exists and it can be processed, process the oldest early share
static void shares_process_early(PGconn *conn, K_ITEM *wi, tv_t *good_cd,
				 K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *es_item, *wi_item;
	WORKINFO *workinfo;
	SHARES *early_shares;
	char cd_buf[DATE_BUFSIZ];
	char *why = EMPTY;
	char *st = NULL;
	char tmp[1024];
	double delta;
	bool ok, failed;

	LOGDEBUG("%s() add", __func__);

	DATA_WORKINFO(workinfo, wi);
	K_WLOCK(shares_free);
	if (shares_early_store->count == 0) {
		K_WUNLOCK(shares_free);
		// None
		goto out;
	}
	es_item = last_in_ktree(shares_early_root, ctx);
	if (es_item) {
		remove_from_ktree(shares_early_root, es_item);
		k_unlink_item(shares_early_store, es_item);
	}
	K_WUNLOCK(shares_free);
	if (es_item) {
		DATA_SHARES(early_shares, es_item);
		/* If the last (oldest) is newer than the
		 *  current workinfo, leave it til later */
		if (early_shares->workinfoid > workinfo->workinfoid)
			goto redo;

		/* If it matches the 'ok' share we just processed,
		 *  we don't need to check the workinfoid */
		if (early_shares->workinfoid == workinfo->workinfoid) {
			ok = shares_process(conn, early_shares, wi, trf_root);
			if (ok)
				goto keep;
			else
				goto discard;
		} else {
			wi_item = find_workinfo(early_shares->workinfoid, NULL);
			if (!wi_item) {
				// good_cd is 'now'
				delta = tvdiff(good_cd,
						&(early_shares->createdate));
				if (early_shares->oldcount > 0) {
					snprintf(tmp, sizeof(tmp),
						 " too old (%.1fs/%"PRId32")",
						 delta,
						 early_shares->oldcount);
					why = tmp;
					goto discard;
				}
				if (delta > EARLYSHARESLIMIT)
					early_shares->oldcount++;
				early_shares->redo++;
				goto redo;
			} else {
				ok = shares_process(conn, early_shares,
						    wi_item, trf_root);
				if (ok)
					goto keep;
				else
					goto discard;
			}
		}
	}
	goto out;
redo:
	K_WLOCK(shares_free);
	add_to_ktree(shares_early_root, es_item);
	k_add_tail(shares_early_store, es_item);
	K_WUNLOCK(shares_free);
	goto out;
keep:
	failed = esm_flag(early_shares->workinfoid, false, true);
	btv_to_buf(&(early_shares->createdate), cd_buf, sizeof(cd_buf));
	LOGNOTICE("%s() %s%"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		  " Early share procured",
		  __func__, failed ? "***ESM " : EMPTY,
		  early_shares->workinfoid,
		  st = safe_text_nonull(early_shares->in_workername),
		  early_shares->createdate.tv_sec,
		  early_shares->createdate.tv_usec, cd_buf,
		  early_shares->oldcount, early_shares->redo);
	FREENULL(st);
	K_WLOCK(shares_free);
	// Discard it, it's been processed
	k_add_head(shares_free, es_item);
	K_WUNLOCK(shares_free);
	goto out;
discard:
	failed = esm_flag(early_shares->workinfoid, false, false);
	btv_to_buf(&(early_shares->createdate), cd_buf, sizeof(cd_buf));
	LOGNOTICE("%s() %s%"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		  " Early share discarded!%s",
		  __func__, failed ? "***ESM " : EMPTY,
		  early_shares->workinfoid,
		  st = safe_text_nonull(early_shares->in_workername),
		  early_shares->createdate.tv_sec,
		  early_shares->createdate.tv_usec, cd_buf,
		  early_shares->oldcount, early_shares->redo, why);
	FREENULL(st);
	K_WLOCK(shares_free);
	k_add_head(shares_free, es_item);
	K_WUNLOCK(shares_free);
out:
	// accessed outside lock, but esm_check() uses the lock
	if (esm_store->count)
		esm_check(good_cd);
}

static void shareerrors_process_early(PGconn *conn, int64_t good_wid,
				      tv_t *good_cd, K_TREE *trf_root);

// DB Shares are stored by the summariser to ensure the reload is correct
bool shares_add(PGconn *conn, char *workinfoid, char *username,
		INTRANSIENT *in_workername, char *clientid, char *errn,
		char *enonce1, char *nonce2, char *nonce, char *diff,
		char *sdiff, char *secondaryuserid, char *ntime, char *address,
		char *agent, char *by, char *code, char *inet, tv_t *cd,
		K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *s_item = NULL, *s2_item = NULL, *u_item, *wi_item, *tmp_item;
	char cd_buf[DATE_BUFSIZ];
	SHARES *shares = NULL, *shares2 = NULL;
	double sdiff_amt;
	USERS *users;
	bool ok = false, dup = false, created;
	char *st = NULL;
	tv_t share_cd;

	LOGDEBUG("%s(): %s/%s/%s/%s/%ld,%ld",
		 __func__,
		 workinfoid, st = safe_text_nonull(in_workername->str), nonce,
		 errn, cd->tv_sec, cd->tv_usec);
	FREENULL(st);

	TXT_TO_DOUBLE("sdiff", sdiff, sdiff_amt);

	K_WLOCK(shares_free);
	s_item = k_unlink_head(shares_free);
	if (share_min_sdiff > 0 && sdiff_amt >= share_min_sdiff)
		s2_item = k_unlink_head(shares_free);
	K_WUNLOCK(shares_free);

	DATA_SHARES(shares, s_item);
	bzero(shares, sizeof(*shares));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	/* Won't change outside lock since we don't delete users
	 *  or change their *userid */
	if (!u_item) {
		/* This should never happen unless there's a bug in asicseer-pool
		    or the authentication information got to ckdb after
		    the shares or the users table is missing data ...
			which shouldn't ever happen
		   However, since it's a valid share, store it */
		u_item = create_missing_user(conn, username, secondaryuserid,
					     by, code, inet, cd, trf_root);
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		if (!u_item) {
			LOGERR("%s() ERR %s/%ld,%ld %s no/failed user! Share"
				" discarded!",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
			goto tisbad;
		} else {
			DATA_USERS(users, u_item);
			LOGERR("%s() MISSING %s/%ld,%ld %s created",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
	}
	DATA_USERS(users, u_item);
	shares->userid = users->userid;

	TXT_TO_BIGINT("workinfoid", workinfoid, shares->workinfoid);
	shares->in_workername = in_workername->str;
	TXT_TO_INT("clientid", clientid, shares->clientid);
	TXT_TO_INT("errn", errn, shares->errn);
	STRNCPY(shares->enonce1, enonce1);
	STRNCPY(shares->nonce2, nonce2);
	STRNCPY(shares->nonce, nonce);
	TXT_TO_DOUBLE("diff", diff, shares->diff);
	TXT_TO_DOUBLE("sdiff", sdiff, shares->sdiff);
	STRNCPY(shares->secondaryuserid, secondaryuserid);

	if (!(*secondaryuserid)) {
		STRNCPY(shares->secondaryuserid, users->secondaryuserid);
		if (!tv_newer(&missing_secuser_min, cd) ||
		    !tv_newer(cd, &missing_secuser_max)) {
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %s missing secondaryuserid! "
				"Share corrected",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
	}

	STRNCPY(shares->ntime, ntime);
	shares->minsdiff = share_min_sdiff;
	STRNCPY(shares->address, address);
	STRNCPY(shares->agent, agent);

	HISTORYDATEINIT(shares, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shares);

	if (s2_item) {
		DATA_SHARES(shares2, s2_item);
		memcpy(shares2, shares, sizeof(*shares2));
	}

	wi_item = find_workinfo_esm(shares->workinfoid, false, &created,
				    &(shares->createdate));
	if (!wi_item) {
		int sta = (created ? LOG_ERR : LOG_NOTICE);
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGMSG(sta, "%s() %"PRId64"/%s/%ld,%ld %s no workinfo! "
			"Early share queued!",
			__func__, shares->workinfoid,
			st = safe_text_nonull(in_workername->str),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		shares->redo = 0;
		shares->oldcount = 0;
		K_WLOCK(shares_free);
		// They need to be sorted by workinfoid
		add_to_ktree(shares_early_root, s_item);
		k_add_head(shares_early_store, s_item);
		if (s2_item) {
			/* Discard duplicates - this matches the DB index
			   N.B. a duplicate share doesn't have to be SE_DUPE,
				two shares can be SE_NONE and SE_STALE */
			tmp_item = find_in_ktree(shares_db_root, s2_item, ctx);
			if (tmp_item == NULL) {
				// Store them in advance - always
				add_to_ktree(shares_hi_root, s2_item);
				add_to_ktree(shares_db_root, s2_item);
				k_add_head(shares_hi_store, s2_item);
			} else {
				dup = true;
				k_add_head(shares_free, s2_item);
				s2_item = NULL;
			}
		}
		K_WUNLOCK(shares_free);
		if (dup) {
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGWARNING("%s() duplicate DB share discarded: "
				   "%"PRId64"/%s/%"PRId32"/%s/%.0f/%"PRId32"/%ld,%ld %s",
				   __func__, shares->workinfoid,
				   st = safe_text_nonull(in_workername->str),
				   shares->clientid, shares->nonce,
				   shares->sdiff, shares->errn,
				   cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
		/* It was all OK except the missing workinfoid
		 *  and it was queued, so most likely OK */
		return true;
	}

	ok = shares_process(conn, shares, wi_item, trf_root);
	if (ok) {
		copy_tv(&share_cd, &(shares->createdate));
		K_WLOCK(shares_free);
		// Discard it, it's been processed
		k_add_head(shares_free, s_item);
		if (s2_item) {
			// Discard duplicates
			tmp_item = find_in_ktree(shares_db_root, s2_item, ctx);
			if (tmp_item == NULL) {
				add_to_ktree(shares_hi_root, s2_item);
				add_to_ktree(shares_db_root, s2_item);
				k_add_head(shares_hi_store, s2_item);
			} else {
				dup = true;
				k_add_head(shares_free, s2_item);
				s2_item = NULL;
			}
		}
		K_WUNLOCK(shares_free);
		if (dup) {
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGWARNING("%s() duplicate DB share discarded: "
				   "%"PRId64"/%s/%"PRId32"/%s/%.0f/%"PRId32"/%ld,%ld %s",
				   __func__, shares->workinfoid,
				   st = safe_text_nonull(in_workername->str),
				   shares->clientid, shares->nonce,
				   shares->sdiff, shares->errn,
				   cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}

		shares_process_early(conn, wi_item, &share_cd, trf_root);
		// Call both since shareerrors may be rare
		shareerrors_process_early(conn, shares->workinfoid,
					  &share_cd, trf_root);

		// The original share was ok
		return true;
	}

tisbad:
	K_WLOCK(shares_free);
	k_add_head(shares_free, s_item);
	K_WUNLOCK(shares_free);
	return false;
}

bool shares_db(PGconn *conn, K_ITEM *s_item)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	SHARES *row;
	char *ins;
	char *params[16 + HISTORYDATECOUNT];
	int n, par = 0;
	bool ok = false;

	LOGDEBUG("%s(): store", __func__);

	DATA_SHARES(row, s_item);

	par = 0;
	params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->in_workername, NULL, 0);
	params[par++] = int_to_buf(row->clientid, NULL, 0);
	params[par++] = str_to_buf(row->enonce1, NULL, 0);
	params[par++] = str_to_buf(row->nonce2, NULL, 0);
	params[par++] = str_to_buf(row->nonce, NULL, 0);
	params[par++] = double_to_buf(row->diff, NULL, 0);
	params[par++] = double_to_buf(row->sdiff, NULL, 0);
	params[par++] = int_to_buf(row->errn, NULL, 0);
	params[par++] = str_to_buf(row->error, NULL, 0);
	params[par++] = str_to_buf(row->secondaryuserid, NULL, 0);
	params[par++] = str_to_buf(row->ntime, NULL, 0);
	params[par++] = double_to_buf(row->minsdiff, NULL, 0);
	params[par++] = str_to_buf(row->address, NULL, 0);
	params[par++] = str_to_buf(row->agent, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHK(par, params);

	ins = "insert into shares "
		"(workinfoid,userid,workername,clientid,enonce1,nonce2,nonce,"
		"diff,sdiff,errn,error,secondaryuserid,ntime,minsdiff,address,"
		"agent" HISTORYDATECONTROL ") values (" PQPARAM21 ")";

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		char *code = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		if (!code || strcmp(code, SQL_UNIQUE_VIOLATION)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		} else {
			// If the share is already in the db use NOTICE
			PGLOGNOTICE("Insert", rescode, conn);
		}
	}

	ok = true;
unparam:
	if (par) {
		CKPQClear(res);
		CKPQDisco(&conn, conned);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	if (ok) {
		K_WLOCK(shares_free);

		remove_from_ktree(shares_hi_root, s_item);

		K_WUNLOCK(shares_free);
	}

	return ok;
}

bool shares_fill(PGconn *conn)
{
	char tickbuf[256], pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item = NULL, *wi_item;
	WORKINFO *workinfo = NULL;
	SHARES *row;
	int n, t, i;
	char *field = NULL;
	char *sel = NULL;
	char *params[1];
	int fields = 16, par = 0;
	bool ok = false;
	int64_t workinfoid;
	tv_t old;
	int no_addr = 0, no_agent = 0;

	LOGDEBUG("%s(): select", __func__);

	if (shares_begin >= 0)
		workinfoid = shares_begin;
	else {
		/* Workinfo is already loaded
		 * CKDB doesn't currently use shares_db in processing,
		 *  but make sure we have enough to avoid loading duplicates
		 * 1 day should be more than enough for normal running,
		 *  however, if more than 1 day is needed,
		 *  use -b to set the shares_begin workinfoid */
		setnow(&old);
		old.tv_sec -= 60 * 60 * 24; // 1 day
		K_RLOCK(workinfo_free);
		wi_item = last_in_ktree(workinfo_root, ctx);
		while (wi_item) {
			DATA_WORKINFO(workinfo, wi_item);
			if (!tv_newer(&old, &(workinfo->createdate)))
				break;
			wi_item = prev_in_ktree(ctx);
		}
		if (wi_item)
			workinfoid = workinfo->workinfoid;
		else {
			// none old enough, so just load from them all
			workinfoid = 0;
		}
		K_RUNLOCK(workinfo_free);
	}

	LOGWARNING("%s(): loading from workinfoid>=%"PRId64, __func__, workinfoid);

	STRNCPY(tickbuf, TICK_PREFIX"sh 0");
	cr_msg(false, tickbuf);

	int workinfoid_num, userid_num, workername_num, clientid_num;
	int enonce1_num, nonce2_num, nonce_num, diff_num, sdiff_num, errn_num;
	int error_num, secondaryuserid_num, ntime_num, minsdiff_num, agent_num;
	int address_num;
	HISTORYDATE_num;

	sel = "declare sh cursor for select "
		"workinfoid,userid,workername,clientid,enonce1,nonce2,nonce,"
		"diff,sdiff,errn,error,secondaryuserid,ntime,minsdiff,agent,"
		"address"
		HISTORYDATECONTROL
		" from shares where workinfoid>=$1";
	par = 0;
	params[par++] = bigint_to_buf(workinfoid, NULL, 0);
	PARCHK(par, params);

	if (!CKPQBegin(conn))
		return false;

	if (exclusive_db) {
		res = CKPQExec(conn, "Lock table shares in access exclusive mode", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Lock", rescode, conn);
			goto flail;
		}
	}

	res = CKPQExecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in sh", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	workinfoid_num = userid_num = workername_num = clientid_num =
	enonce1_num = nonce2_num = nonce_num = diff_num = sdiff_num = errn_num =
	error_num = secondaryuserid_num = ntime_num = minsdiff_num = agent_num =
	address_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(shares_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(shares_free);
			DATA_SHARES(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, workinfoid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

			CKPQ_VAL_FLD_num(res, i, userid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			CKPQ_VAL_FLD_num(res, i, workername, field, ok);
			if (!ok)
				break;
			row->in_workername = intransient_str("workername", field);

			CKPQ_VAL_FLD_num(res, i, clientid, field, ok);
			if (!ok)
				break;
			TXT_TO_INT("clientid", field, row->clientid);

			CKPQ_VAL_FLD_num(res, i, enonce1, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("enonce1", field, row->enonce1);

			CKPQ_VAL_FLD_num(res, i, nonce2, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("nonce2", field, row->nonce2);

			CKPQ_VAL_FLD_num(res, i, nonce, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("nonce", field, row->nonce);

			CKPQ_VAL_FLD_num(res, i, diff, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diff", field, row->diff);

			CKPQ_VAL_FLD_num(res, i, sdiff, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("sdiff", field, row->sdiff);

			CKPQ_VAL_FLD_num(res, i, errn, field, ok);
			if (!ok)
				break;
			TXT_TO_INT("errn", field, row->errn);

			CKPQ_VAL_FLD_num(res, i, error, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("error", field, row->error);

			CKPQ_VAL_FLD_num(res, i, secondaryuserid, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("secondaryuserid", field, row->secondaryuserid);

			CKPQ_VAL_FLD_num(res, i, ntime, field, ok);
			if (!ok)
				break;
			TXT_TO_STR("ntime", field, row->ntime);

			CKPQ_VAL_FLD_num(res, i, minsdiff, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("minsdiff", field, row->sdiff);

			HISTORYDATEFLDS(res, i, row, ok);
			if (!ok)
				break;

			CKPQ_VAL_FLD_num(res, i, agent, field, ok);
			if (!ok)
				break;
			if (!(*field))
				no_agent++;
			TXT_TO_STR("agent", field, row->agent);

			CKPQ_VAL_FLD_num(res, i, address, field, ok);
			if (!ok)
				break;
			if (!(*field))
				no_addr++;
			TXT_TO_STR("address", field, row->address);

			add_to_ktree(shares_db_root, item);
			k_add_head(shares_hi_store, item);

			if (n == 0 || ((n+1) % FETCHTICK) == 0) {
				pcom(n+1, pcombuf, sizeof(pcombuf));
				snprintf(tickbuf, sizeof(tickbuf),
					 TICK_PREFIX"sh %s", pcombuf);
				cr_msg(false, tickbuf);
			}
			tick();
			n++;
		}
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in sh", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		workinfoid_num = userid_num = workername_num = clientid_num =
		enonce1_num = nonce2_num = nonce_num = diff_num = sdiff_num =
		errn_num = error_num = secondaryuserid_num = ntime_num =
		minsdiff_num = agent_num = address_num = CKPQFUNDEF;
		HISTORYDATE_init;
	}
	if (!ok)
		k_add_head(shares_free, item);

	K_WUNLOCK(shares_free);
	CKPQClear(res);
flail:

	CKPQCommit(conn);
	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s shares records",
			   __func__, pcombuf);
		if (no_addr || no_agent) {
			if (no_addr == no_agent) {
				LOGWARNING(" %d had no address and agent",
					   no_addr);
			} else {
				LOGWARNING(" %d had no address %d had no agent",
					   no_addr, no_agent);
			}
		}
	}

	return ok;
}

static bool shareerrors_process(PGconn *conn, SHAREERRORS *shareerrors,
				K_TREE *trf_root)
{
	K_ITEM *w_item, *wm_item, *ss_item;
	SHARESUMMARY *sharesummary;
	char complete[TXT_FLAG+1];
	char *st = NULL;

	LOGDEBUG("%s() add", __func__);

	w_item = new_default_worker(conn, false, shareerrors->userid,
				    shareerrors->in_workername,
				    shareerrors->createby,
				    shareerrors->createcode,
				    shareerrors->createinet,
				    &(shareerrors->createdate), trf_root);
	if (!w_item) {
		LOGDEBUG("%s(): new_default_worker failed %"PRId64"/%s/%ld,%ld",
			 __func__, shareerrors->userid,
			 st = safe_text_nonull(shareerrors->in_workername),
			 shareerrors->createdate.tv_sec,
			 shareerrors->createdate.tv_usec);
		FREENULL(st);
		return false;
	}

	// key_update skips shareerrors
	if (reloading && !confirm_sharesummary) {
		// We only need to know if the workmarker is processed
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkers(shareerrors->workinfoid, false,
					   MARKER_PROCESSED, NULL);
		K_RUNLOCK(workmarkers_free);
		if (wm_item) {
			LOGDEBUG("%s(): workmarker exists for wid %"PRId64
				 " %"PRId64"/%s/%ld,%ld",
				 __func__, shareerrors->workinfoid,
				 shareerrors->userid,
				 st = safe_text_nonull(shareerrors->in_workername),
				 shareerrors->createdate.tv_sec,
				 shareerrors->createdate.tv_usec);
			FREENULL(st);
			return false;
		}

		K_RLOCK(sharesummary_free);
		ss_item = find_sharesummary(shareerrors->userid,
					    shareerrors->in_workername,
					    shareerrors->workinfoid);
		if (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->complete[0] != SUMMARY_NEW) {
				STRNCPY(complete, sharesummary->complete);
				K_RUNLOCK(sharesummary_free);
				LOGDEBUG("%s(): '%s' sharesummary exists "
					 "%"PRId64" %"PRId64"/%s/%ld,%ld",
					 __func__, complete,
					 shareerrors->workinfoid,
					 shareerrors->userid,
					 st = safe_text_nonull(shareerrors->in_workername),
					 shareerrors->createdate.tv_sec,
					 shareerrors->createdate.tv_usec);
				FREENULL(st);
				return false;
			}
		}
		K_RUNLOCK(sharesummary_free);
	}

	sharesummary_update(NULL, shareerrors, &(shareerrors->createdate));

	return true;
}

// If it exists and it can be processed, process the oldest early shareerror
static void shareerrors_process_early(PGconn *conn, int64_t good_wid,
				      tv_t *good_cd, K_TREE *trf_root)
{
	K_TREE_CTX ctx[1];
	K_ITEM *es_item, *wi_item;
	SHAREERRORS *early_shareerrors;
	char cd_buf[DATE_BUFSIZ];
	char *why = EMPTY;
	char *st = NULL;
	char tmp[1024];
	double delta;
	bool ok, failed;

	LOGDEBUG("%s() add", __func__);

	K_WLOCK(shareerrors_free);
	if (shareerrors_early_store->count == 0) {
		K_WUNLOCK(shareerrors_free);
		// None
		goto out;
	}
	es_item = last_in_ktree(shareerrors_early_root, ctx);
	if (es_item) {
		remove_from_ktree(shareerrors_early_root, es_item);
		k_unlink_item(shareerrors_early_store, es_item);
	}
	K_WUNLOCK(shareerrors_free);
	if (es_item) {
		DATA_SHAREERRORS(early_shareerrors, es_item);
		/* If the last (oldest) is newer than the
		 *  current workinfo, leave it til later */
		if (early_shareerrors->workinfoid > good_wid)
			goto redo;

		/* If it matches the 'ok' share/shareerror we just processed,
		 *  we don't need to check the workinfoid */
		if (early_shareerrors->workinfoid == good_wid) {
			ok = shareerrors_process(conn, early_shareerrors,
						 trf_root);
			if (ok)
				goto keep;
			else
				goto discard;
		} else {
			wi_item = find_workinfo(early_shareerrors->workinfoid, NULL);
			if (!wi_item) {
				// good_cd is 'now'
				delta = tvdiff(good_cd,
						&(early_shareerrors->createdate));
				if (early_shareerrors->oldcount > 0) {
					snprintf(tmp, sizeof(tmp),
						 " too old (%.1fs/%"PRId32")",
						 delta,
						 early_shareerrors->oldcount);
					why = tmp;
					goto discard;
				}
				if (delta > EARLYSHARESLIMIT)
					early_shareerrors->oldcount++;
				early_shareerrors->redo++;
				goto redo;
			} else {
				ok = shareerrors_process(conn,
							 early_shareerrors,
							 trf_root);
				if (ok)
					goto keep;
				else
					goto discard;
			}
		}
	}
	goto out;
redo:
	K_WLOCK(shareerrors_free);
	add_to_ktree(shareerrors_early_root, es_item);
	k_add_tail(shareerrors_early_store, es_item);
	K_WUNLOCK(shareerrors_free);
	goto out;
keep:
	failed = esm_flag(early_shareerrors->workinfoid, true, true);
	btv_to_buf(&(early_shareerrors->createdate), cd_buf, sizeof(cd_buf));
	LOGNOTICE("%s() %s%"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		  " Early shareerror procured",
		  __func__, failed ? "***ESM " : EMPTY,
		  early_shareerrors->workinfoid,
		  st = safe_text_nonull(early_shareerrors->in_workername),
		  early_shareerrors->createdate.tv_sec,
		  early_shareerrors->createdate.tv_usec, cd_buf,
		  early_shareerrors->oldcount, early_shareerrors->redo);
	FREENULL(st);
	K_WLOCK(shareerrors_free);
	add_to_ktree(shareerrors_root, es_item);
	k_add_head(shareerrors_store, es_item);
	K_WUNLOCK(shareerrors_free);
	goto out;
discard:
	failed = esm_flag(early_shareerrors->workinfoid, true, false);
	btv_to_buf(&(early_shareerrors->createdate), cd_buf, sizeof(cd_buf));
	LOGNOTICE("%s() %s%"PRId64"/%s/%ld,%ld %s/%"PRId32"/%"PRId32
		  " Early shareerror discarded!%s",
		  __func__, failed ? "***ESM " : EMPTY,
		  early_shareerrors->workinfoid,
		  st = safe_text_nonull(early_shareerrors->in_workername),
		  early_shareerrors->createdate.tv_sec,
		  early_shareerrors->createdate.tv_usec, cd_buf,
		  early_shareerrors->oldcount, early_shareerrors->redo, why);
	FREENULL(st);
	K_WLOCK(shareerrors_free);
	k_add_head(shareerrors_free, es_item);
	K_WUNLOCK(shareerrors_free);
out:
	// accessed outside lock, but esm_check() uses the lock
	if (esm_store->count)
		esm_check(good_cd);
}

// Memory (and log file) only
bool shareerrors_add(PGconn *conn, char *workinfoid, char *username,
			INTRANSIENT *in_workername, char *clientid, char *errn,
			char *error, char *secondaryuserid, char *by,
			char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *s_item = NULL, *u_item, *wi_item;
	char cd_buf[DATE_BUFSIZ];
	SHAREERRORS *shareerrors = NULL;
	USERS *users;
	bool ok = false, created;
	char *st = NULL;

	LOGDEBUG("%s(): %s/%s/%s/%s/%ld,%ld",
		 __func__,
		 workinfoid, st = safe_text_nonull(in_workername->str), errn,
		 error, cd->tv_sec, cd->tv_usec);
	FREENULL(st);

	K_WLOCK(shareerrors_free);
	s_item = k_unlink_head(shareerrors_free);
	K_WUNLOCK(shareerrors_free);

	DATA_SHAREERRORS(shareerrors, s_item);
	bzero(shareerrors, sizeof(*shareerrors));

	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s() %s/%ld,%ld %s no user! Shareerror discarded!",
			__func__, st = safe_text_nonull(username),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		goto tisbad;
	}
	DATA_USERS(users, u_item);

	shareerrors->userid = users->userid;

	TXT_TO_BIGINT("workinfoid", workinfoid, shareerrors->workinfoid);
	shareerrors->in_workername = in_workername->str;
	TXT_TO_INT("clientid", clientid, shareerrors->clientid);
	TXT_TO_INT("errn", errn, shareerrors->errn);
	STRNCPY(shareerrors->error, error);
	STRNCPY(shareerrors->secondaryuserid, secondaryuserid);

	if (!(*secondaryuserid)) {
		STRNCPY(shareerrors->secondaryuserid, users->secondaryuserid);
		if (!tv_newer(&missing_secuser_min, cd) ||
		    !tv_newer(cd, &missing_secuser_max)) {
			btv_to_buf(cd, cd_buf, sizeof(cd_buf));
			LOGERR("%s() %s/%ld,%ld %s missing secondaryuserid! "
				"Sharerror corrected",
				__func__, st = safe_text_nonull(username),
				cd->tv_sec, cd->tv_usec, cd_buf);
			FREENULL(st);
		}
	}

	HISTORYDATEINIT(shareerrors, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, shareerrors);

	wi_item = find_workinfo_esm(shareerrors->workinfoid, true, &created,
				    &(shareerrors->createdate));
	if (!wi_item) {
		int sta = (created ? LOG_ERR : LOG_NOTICE);
		btv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGMSG(sta, "%s() %"PRId64"/%s/%ld,%ld %s no workinfo! "
			"Early shareerror queued!",
			__func__, shareerrors->workinfoid,
			st = safe_text_nonull(in_workername->str),
			cd->tv_sec, cd->tv_usec, cd_buf);
		FREENULL(st);
		shareerrors->redo = 0;
		shareerrors->oldcount = 0;
		K_WLOCK(shareerrors_free);
		// They need to be sorted by workinfoid
		add_to_ktree(shareerrors_early_root, s_item);
		k_add_head(shareerrors_early_store, s_item);
		K_WUNLOCK(shareerrors_free);
		/* It was all OK except the missing workinfoid
		 *  and it was queued, so most likely OK */
		return true;
	}

	ok = shareerrors_process(conn, shareerrors, trf_root);
	if (ok) {
		K_WLOCK(shareerrors_free);
		add_to_ktree(shareerrors_root, s_item);
		k_add_head(shareerrors_store, s_item);
		K_WUNLOCK(shareerrors_free);

		shareerrors_process_early(conn, shareerrors->workinfoid,
					  &(shareerrors->createdate),
					  trf_root);
		// Call both in case we are only getting errors on bad work
		shares_process_early(conn, wi_item, &(shareerrors->createdate),
				     trf_root);

		// The original share was ok
		return true;
	}

tisbad:
	K_WLOCK(shareerrors_free);
	k_add_head(shareerrors_free, s_item);
	K_WUNLOCK(shareerrors_free);
	return false;
}

bool shareerrors_fill()
{
	return true;
}

static void markersummary_to_pool(MARKERSUMMARY *p_row, MARKERSUMMARY *row)
{
	p_row->diffacc += row->diffacc;
	p_row->diffsta += row->diffsta;
	p_row->diffdup += row->diffdup;
	p_row->diffhi += row->diffhi;
	p_row->diffrej += row->diffrej;
	p_row->shareacc += row->shareacc;
	p_row->sharesta += row->sharesta;
	p_row->sharedup += row->sharedup;
	p_row->sharehi += row->sharehi;
	p_row->sharerej += row->sharerej;
	p_row->sharecount += row->sharecount;
	p_row->errorcount += row->errorcount;
	if (!p_row->firstshare.tv_sec ||
	     !tv_newer(&(p_row->firstshare), &(row->firstshare))) {
		copy_tv(&(p_row->firstshare), &(row->firstshare));
	}
	if (tv_newer(&(p_row->lastshare), &(row->lastshare)))
		copy_tv(&(p_row->lastshare), &(row->lastshare));
	if (row->diffacc > 0) {
		if (!p_row->firstshareacc.tv_sec ||
		     !tv_newer(&(p_row->firstshareacc), &(row->firstshareacc))) {
			copy_tv(&(p_row->firstshareacc), &(row->firstshareacc));
		}
		if (tv_newer(&(p_row->lastshareacc), &(row->lastshareacc))) {
			copy_tv(&(p_row->lastshareacc), &(row->lastshareacc));
			p_row->lastdiffacc = row->lastdiffacc;
		}
	}
}

/* TODO: what to do about a failure?
 *  since it will repeat every ~13s
 * Of course manual intervention is possible via cmd_marks,
 *  so that is probably the best solution since
 *  we should be watching the pool all the time :)
 * The cause would most likely be either a code bug or a DB problem
 *  so there may be no obvious automated fix
 *  and flagging the workmarkers to be skipped may or may not be the solution,
 *  thus manual intervention will be the rule for now */
bool sharesummaries_to_markersummaries(PGconn *conn, WORKMARKERS *workmarkers,
				       char *by, char *code, char *inet, tv_t *cd,
				       K_TREE *trf_root)
{
	// shorter name for log messages
	static const char *shortname = "K/SS_to_K/MS";
	static const char *sshortname = "SS_to_MS";
	static const char *kshortname = "KSS_to_KS";

	K_TREE_CTX ss_ctx[1], kss_ctx[1], ms_ctx[1], ks_ctx[1];
	SHARESUMMARY *sharesummary, looksharesummary;
	KEYSHARESUMMARY *keysharesummary, lookkeysharesummary;
	MARKERSUMMARY *markersummary, lookmarkersummary, *p_markersummary = NULL;
	KEYSUMMARY *keysummary, lookkeysummary;
	K_ITEM *ss_item, *ss_prev, ss_look;
	K_ITEM *kss_item, *kss_prev, kss_look;
	K_ITEM *ms_item, ms_look, *p_ss_item, *p_ms_item;
	K_ITEM *ks_item, ks_look;
	bool ok = false, conned = false, nonblank = false;
	int64_t diffacc = 0, shareacc = 0;
	int64_t kdiffacc = 0, kshareacc = 0;
	char *reason = NULL;
	int ss_count, kss_count, ms_count, ks_count;
	char *st = NULL;
	tv_t add_stt, add_fin, db_stt, db_fin, lck_stt, lck_got, lck_fin;
	tv_t kadd_stt, kadd_fin, kdb_stt, kdb_fin;

	DATE_ZERO(&add_stt);
	DATE_ZERO(&add_fin);
	DATE_ZERO(&db_stt);
	DATE_ZERO(&db_fin);
	DATE_ZERO(&kadd_stt);
	DATE_ZERO(&kadd_fin);
	DATE_ZERO(&kdb_stt);
	DATE_ZERO(&kdb_fin);

	LOGWARNING("%s() Processing: workmarkers %"PRId64"/%s/"
		   "End %"PRId64"/Stt %"PRId64"/%s/%s",
		   shortname, workmarkers->markerid, workmarkers->in_poolinstance,
		   workmarkers->workinfoidend, workmarkers->workinfoidstart,
		   workmarkers->description, workmarkers->status);

	K_STORE *old_sharesummary_store = k_new_store(sharesummary_free);
	K_STORE *old_keysharesummary_store = k_new_store(keysharesummary_free);
	K_STORE *new_markersummary_store = k_new_store(markersummary_free);
	K_STORE *new_keysummary_store = k_new_store(keysummary_free);

	/* Use the master size for these local trees since
	 *  they're large and don't get created often */
	K_TREE *ms_root = new_ktree_local(sshortname, cmp_markersummary,
					  markersummary_free);
	K_TREE *ks_root = new_ktree_local(kshortname, cmp_keysummary,
					  keysummary_free);

	if (!CURRENT(&(workmarkers->expirydate))) {
		reason = "unexpired";
		goto flail;
	}

	if (!WMREADY(workmarkers->status)) {
		reason = "not ready";
		goto flail;
	}

	if (key_update)
		goto dokey;

	setnow(&add_stt);
	/* Check there aren't already any matching markersummaries
	 *  and assume keysummaries are the same */
	lookmarkersummary.markerid = workmarkers->markerid;
	lookmarkersummary.userid = 0;
	lookmarkersummary.in_workername = EMPTY;

	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&lookmarkersummary);
	K_RLOCK(markersummary_free);
	ms_item = find_after_in_ktree(markersummary_root, &ms_look, ms_ctx);
	K_RUNLOCK(markersummary_free);
	DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	if (ms_item && markersummary->markerid == workmarkers->markerid) {
		/* The fix here is either to set the workmarker as processed
		 *  with the marks action=processed
		 *  if the markersummaries are OK but the workmarker failed to
		 *  have it's status set to processed
		 * OR
		 *  delete the markersummaries with the marks action=cancel
		 *  so this will continue and regenerate the markersummaries
		 */
		reason = "markersummaries already exist";
		setnow(&add_fin);
		goto flail;
	}

	ms_item = NULL;

	looksharesummary.workinfoid = workmarkers->workinfoidend;
	looksharesummary.userid = MAXID;
	looksharesummary.in_workername = EMPTY;

	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	/* Since shares come in from asicseer-pool at a high rate,
	 *  we don't want to lock sharesummary for long
	 * Those incoming shares will not be touching the sharesummaries
	 *  we are processing here */
	K_RLOCK(sharesummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
					&ss_look, ss_ctx);
	K_RUNLOCK(sharesummary_free);
	while (ss_item) {
		DATA_SHARESUMMARY(sharesummary, ss_item);
		if (sharesummary->workinfoid < workmarkers->workinfoidstart)
			break;
		K_RLOCK(sharesummary_free);
		ss_prev = prev_in_ktree(ss_ctx);
		K_RUNLOCK(sharesummary_free);

		// Find/create the markersummary only once per worker change
		if (!ms_item || markersummary->userid != sharesummary->userid ||
		    !INTREQ(markersummary->in_workername, sharesummary->in_workername)) {
			lookmarkersummary.markerid = workmarkers->markerid;
			lookmarkersummary.userid = sharesummary->userid;
			lookmarkersummary.in_workername = sharesummary->in_workername;

			ms_look.data = (void *)(&lookmarkersummary);
			ms_item = find_in_ktree_nolock(ms_root, &ms_look, ms_ctx);
			if (!ms_item) {
				K_WLOCK(markersummary_free);
				ms_item = k_unlink_head(markersummary_free);
				K_WUNLOCK(markersummary_free);
				k_add_head_nolock(new_markersummary_store, ms_item);
				DATA_MARKERSUMMARY(markersummary, ms_item);
				bzero(markersummary, sizeof(*markersummary));
				markersummary->markerid = workmarkers->markerid;
				markersummary->userid = sharesummary->userid;
				markersummary->in_workername = sharesummary->in_workername;
				add_to_ktree_nolock(ms_root, ms_item);

				LOGDEBUG("%s() new ms %"PRId64"/%"PRId64"/%s",
					 shortname, markersummary->markerid,
					 markersummary->userid,
					 st = safe_text(markersummary->in_workername));
				FREENULL(st);
			} else {
				DATA_MARKERSUMMARY(markersummary, ms_item);
			}
		}
		markersummary->diffacc += sharesummary->diffacc;
		markersummary->diffsta += sharesummary->diffsta;
		markersummary->diffdup += sharesummary->diffdup;
		markersummary->diffhi += sharesummary->diffhi;
		markersummary->diffrej += sharesummary->diffrej;
		markersummary->shareacc += sharesummary->shareacc;
		markersummary->sharesta += sharesummary->sharesta;
		markersummary->sharedup += sharesummary->sharedup;
		markersummary->sharehi += sharesummary->sharehi;
		markersummary->sharerej += sharesummary->sharerej;
		markersummary->sharecount += sharesummary->sharecount;
		markersummary->errorcount += sharesummary->errorcount;
		if (!markersummary->firstshare.tv_sec ||
		     !tv_newer(&(markersummary->firstshare), &(sharesummary->firstshare))) {
			copy_tv(&(markersummary->firstshare), &(sharesummary->firstshare));
		}
		if (tv_newer(&(markersummary->lastshare), &(sharesummary->lastshare)))
			copy_tv(&(markersummary->lastshare), &(sharesummary->lastshare));
		if (sharesummary->diffacc > 0) {
			if (!markersummary->firstshareacc.tv_sec ||
			     !tv_newer(&(markersummary->firstshareacc), &(sharesummary->firstshareacc))) {
				copy_tv(&(markersummary->firstshareacc), &(sharesummary->firstshareacc));
			}
			if (tv_newer(&(markersummary->lastshareacc), &(sharesummary->lastshareacc))) {
				copy_tv(&(markersummary->lastshareacc), &(sharesummary->lastshareacc));
				markersummary->lastdiffacc = sharesummary->lastdiffacc;
			}
		}

		diffacc += sharesummary->diffacc;
		shareacc += sharesummary->shareacc;

		K_WLOCK(sharesummary_free);
		k_unlink_item(sharesummary_store, ss_item);
		K_WUNLOCK(sharesummary_free);
		k_add_head_nolock(old_sharesummary_store, ss_item);

		ss_item = ss_prev;
	}
	setnow(&add_fin);

dokey:

	if (key_update) {
		setnow(&add_stt);

		// Discard the sharesummaries
		looksharesummary.workinfoid = workmarkers->workinfoidend;
		looksharesummary.userid = MAXID;
		looksharesummary.in_workername = EMPTY;

		INIT_SHARESUMMARY(&ss_look);
		ss_look.data = (void *)(&looksharesummary);
		/* Since shares come in from asicseer-pool at a high rate,
		 *  we don't want to lock sharesummary for long
		 * Those incoming shares will not be touching the sharesummaries
		 *  we are processing here */
		K_RLOCK(sharesummary_free);
		ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
						&ss_look, ss_ctx);
		K_RUNLOCK(sharesummary_free);
		while (ss_item) {
			DATA_SHARESUMMARY(sharesummary, ss_item);
			if (sharesummary->workinfoid < workmarkers->workinfoidstart)
				break;
			K_WLOCK(sharesummary_free);
			ss_prev = prev_in_ktree(ss_ctx);
			k_unlink_item(sharesummary_store, ss_item);
			K_WUNLOCK(sharesummary_free);
			k_add_head_nolock(old_sharesummary_store, ss_item);

			ss_item = ss_prev;
		}
		setnow(&add_fin);
	}

	setnow(&kadd_stt);
	INIT_KEYSUMMARY(&ks_look);

	ks_item = NULL;

	// find before the minimum next kss after what we want
	lookkeysharesummary.workinfoid = workmarkers->workinfoidend+1;
	lookkeysharesummary.keytype[0] = '\0';
	lookkeysharesummary.key = EMPTY;

	INIT_KEYSHARESUMMARY(&kss_look);
	kss_look.data = (void *)(&lookkeysharesummary);
	/* Since shares come in from asicseer-pool at a high rate,
	 *  we don't want to lock keysharesummary for long
	 * Those incoming shares will not be touching the keysharesummaries
	 *  we are processing here */
	K_RLOCK(keysharesummary_free);
	kss_item = find_before_in_ktree(keysharesummary_root,
					&kss_look, kss_ctx);
	K_RUNLOCK(keysharesummary_free);
	while (kss_item) {
		DATA_KEYSHARESUMMARY(keysharesummary, kss_item);
		if (keysharesummary->workinfoid < workmarkers->workinfoidstart)
			break;
		if (keysharesummary->key[0])
			nonblank = true;
		K_RLOCK(keysharesummary_free);
		kss_prev = prev_in_ktree(kss_ctx);
		K_RUNLOCK(keysharesummary_free);

		// Find/create the keysummary only once per key change
		if (!ks_item || strcmp(keysummary->keytype, keysharesummary->keytype) != 0 ||
		    strcmp(keysummary->key, keysharesummary->key) != 0) {
			lookkeysummary.markerid = workmarkers->markerid;
			lookkeysummary.keytype[0] = keysharesummary->keytype[0];
			lookkeysummary.keytype[1] = keysharesummary->keytype[1];
			lookkeysummary.key = keysharesummary->key;

			ks_look.data = (void *)(&lookkeysummary);
			ks_item = find_in_ktree_nolock(ks_root, &ks_look, ks_ctx);
			if (!ks_item) {
				K_WLOCK(keysummary_free);
				ks_item = k_unlink_head(keysummary_free);
				K_WUNLOCK(keysummary_free);
				k_add_head_nolock(new_keysummary_store, ks_item);
				DATA_KEYSUMMARY(keysummary, ks_item);
				bzero(keysummary, sizeof(*keysummary));
				keysummary->markerid = workmarkers->markerid;
				keysummary->keytype[0] = keysharesummary->keytype[0];
				keysummary->keytype[1] = '\0';
				DUP_POINTER(keysummary_free,
					    keysummary->key,
					    keysharesummary->key);
				add_to_ktree_nolock(ks_root, ks_item);

				LOGDEBUG("%s() new ks %"PRId64"/%s/%s",
					 shortname, keysummary->markerid,
					 keysummary->keytype,
					 st = safe_text(keysummary->key));
				FREENULL(st);
			} else {
				DATA_KEYSUMMARY(keysummary, ks_item);
			}
		}
		keysummary->diffacc += keysharesummary->diffacc;
		keysummary->diffsta += keysharesummary->diffsta;
		keysummary->diffdup += keysharesummary->diffdup;
		keysummary->diffhi += keysharesummary->diffhi;
		keysummary->diffrej += keysharesummary->diffrej;
		keysummary->shareacc += keysharesummary->shareacc;
		keysummary->sharesta += keysharesummary->sharesta;
		keysummary->sharedup += keysharesummary->sharedup;
		keysummary->sharehi += keysharesummary->sharehi;
		keysummary->sharerej += keysharesummary->sharerej;
		keysummary->sharecount += keysharesummary->sharecount;
		keysummary->errorcount += keysharesummary->errorcount;
		if (!keysummary->firstshare.tv_sec ||
		     !tv_newer(&(keysummary->firstshare), &(keysharesummary->firstshare))) {
			copy_tv(&(keysummary->firstshare), &(keysharesummary->firstshare));
		}
		if (tv_newer(&(keysummary->lastshare), &(keysharesummary->lastshare)))
			copy_tv(&(keysummary->lastshare), &(keysharesummary->lastshare));
		if (keysharesummary->diffacc > 0) {
			if (!keysummary->firstshareacc.tv_sec ||
			     !tv_newer(&(keysummary->firstshareacc), &(keysharesummary->firstshareacc))) {
				copy_tv(&(keysummary->firstshareacc), &(keysharesummary->firstshareacc));
			}
			if (tv_newer(&(keysummary->lastshareacc), &(keysharesummary->lastshareacc))) {
				copy_tv(&(keysummary->lastshareacc), &(keysharesummary->lastshareacc));
				keysummary->lastdiffacc = keysharesummary->lastdiffacc;
			}
		}

		kdiffacc += keysharesummary->diffacc;
		kshareacc += keysharesummary->shareacc;

		K_WLOCK(keysharesummary_free);
		k_unlink_item(keysharesummary_store, kss_item);
		K_WUNLOCK(keysharesummary_free);
		k_add_head_nolock(old_keysharesummary_store, kss_item);

		kss_item = kss_prev;
	}
	setnow(&kadd_fin);

	setnow(&db_stt);
	if (CKPQConn(&conn))
		conned = true;
	if (!CKPQBegin(conn)) {
		setnow(&db_fin);
		goto flail;
	}

	ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
	while (ms_item) {
		if (!(markersummary_add(conn, ms_item, by, code, inet,
					cd, trf_root))) {
			reason = "db error";
			setnow(&db_fin);
			goto rollback;
		}
		ms_item = ms_item->next;
	}
	setnow(&db_fin);

	setnow(&kdb_stt);
	ks_item = STORE_HEAD_NOLOCK(new_keysummary_store);
	while (ks_item) {
		if (!(keysummary_add(conn, ks_item, by, code, inet, cd))) {
			reason = "db error";
			setnow(&kdb_fin);
			goto rollback;
		}
		ks_item = ks_item->next;
	}

	if (!key_update) {
		ok = workmarkers_process(conn, true, true,
					 workmarkers->markerid,
					 workmarkers->in_poolinstance,
					 workmarkers->workinfoidend,
					 workmarkers->workinfoidstart,
					 workmarkers->description,
					 MARKER_PROCESSED_STR,
					 by, code, inet, cd, trf_root);
	} else {
		// Not part of either tree key
		STRNCPY(workmarkers->status, MARKER_PROCESSED_STR);
		ok = true;
	}
	setnow(&kdb_fin);
rollback:

	CKPQEnd(conn, ok);

flail:
	CKPQDisco(&conn, conned);

	if (reason) {
		// already displayed the full workmarkers detail at the top
		LOGERR("%s() %s: workmarkers %"PRId64"/%s/%s add=%.3fs "
			"kadd=%.3fs db=%.3fs kdb=%.3fs",
			shortname, reason, workmarkers->markerid,
			workmarkers->description, workmarkers->status,
			tvdiff(&add_fin, &add_stt), tvdiff(&kadd_fin, &kadd_stt),
			tvdiff(&db_fin, &db_stt), tvdiff(&kdb_fin, &kdb_stt));

		ok = false;
	}

	if (!ok) {
		if (new_markersummary_store->count > 0) {
			// Throw them away (they don't exist anywhere else)
			ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
			while (ms_item) {
				free_markersummary_data(ms_item);
				ms_item = ms_item->next;
			}
			K_WLOCK(markersummary_free);
			k_list_transfer_to_head(new_markersummary_store, markersummary_free);
			K_WUNLOCK(markersummary_free);
		}
		if (old_sharesummary_store->count > 0) {
			// Put them back in the store where they came from
			K_WLOCK(sharesummary_free);
			k_list_transfer_to_head(old_sharesummary_store, sharesummary_store);
			K_WUNLOCK(sharesummary_free);
		}
		if (new_keysummary_store->count > 0) {
			// Throw them away (they don't exist anywhere else)
			ks_item = STORE_HEAD_NOLOCK(new_keysummary_store);
			while (ks_item) {
				free_keysummary_data(ks_item);
				ks_item = ks_item->next;
			}
			K_WLOCK(keysummary_free);
			k_list_transfer_to_head(new_keysummary_store, keysummary_free);
			K_WUNLOCK(keysummary_free);
		}
		if (old_keysharesummary_store->count > 0) {
			// Put them back in the store where they came from
			K_WLOCK(keysharesummary_free);
			k_list_transfer_to_head(old_keysharesummary_store, keysharesummary_store);
			K_WUNLOCK(keysharesummary_free);
		}
	} else {
		ms_count = new_markersummary_store->count;
		ks_count = new_keysummary_store->count;
		ss_count = old_sharesummary_store->count;
		kss_count = old_keysharesummary_store->count;

		setnow(&lck_stt);
		K_WLOCK(sharesummary_free);
		K_WLOCK(keysharesummary_free);
		K_WLOCK(markersummary_free);
		K_WLOCK(keysummary_free);
		K_RLOCK(workmarkers_free);
		setnow(&lck_got);
		ms_item = STORE_HEAD_NOLOCK(new_markersummary_store);
		while (ms_item) {
			// move the new markersummaries into the trees/stores
			add_to_ktree(markersummary_root, ms_item);
			add_to_ktree(markersummary_userid_root, ms_item);

			// create/update the pool markersummaries
			DATA_MARKERSUMMARY(markersummary, ms_item);
			p_ms_item = find_markersummary_p(markersummary->markerid);
			if (!p_ms_item) {
				p_ms_item = k_unlink_head(markersummary_free);
				DATA_MARKERSUMMARY(p_markersummary, p_ms_item);
				bzero(p_markersummary, sizeof(*p_markersummary));
				p_markersummary->markerid = markersummary->markerid;
				POOL_MS(p_markersummary);
				add_to_ktree(markersummary_pool_root, p_ms_item);
				k_add_head(markersummary_pool_store, p_ms_item);
			}
			markersummary_to_pool(p_markersummary, markersummary);

			ms_item = ms_item->next;
		}
		k_list_transfer_to_head(new_markersummary_store, markersummary_store);

		if (!key_update) {
			ks_item = STORE_HEAD_NOLOCK(new_keysummary_store);
			while (ks_item) {
				// move the new keysummaries into the tree
				add_to_ktree(keysummary_root, ks_item);
				ks_item = ks_item->next;
			}
			k_list_transfer_to_head(new_keysummary_store,
						keysummary_store);
		} else {
			/* Discard the new data to save RAM,
			 *  since we don't actually use it in key_update */
			ks_item = STORE_HEAD_NOLOCK(new_keysummary_store);
			while (ks_item) {
				free_keysummary_data(ks_item);
				ks_item = ks_item->next;
			}
			k_list_transfer_to_head(new_keysummary_store,
						keysummary_free);
		}

		/* For normal shift processing this wont be very quick
		 *  so it will be a 'long' LOCK */
		ss_item = STORE_HEAD_NOLOCK(old_sharesummary_store);
		while (ss_item) {
			// remove the old sharesummaries from the trees
			remove_from_ktree(sharesummary_root, ss_item);
			remove_from_ktree(sharesummary_workinfoid_root, ss_item);

			// remove the pool sharesummaries
			DATA_SHARESUMMARY(sharesummary, ss_item);
			p_ss_item = find_sharesummary_p(sharesummary->workinfoid);
			if (p_ss_item) {
				remove_from_ktree(sharesummary_pool_root, p_ss_item);
				k_unlink_item(sharesummary_pool_store, p_ss_item);
				free_sharesummary_data(p_ss_item);
				k_add_head(sharesummary_free, p_ss_item);
			}

			free_sharesummary_data(ss_item);
			ss_item = ss_item->next;
		}
		k_list_transfer_to_head(old_sharesummary_store, sharesummary_free);

		/* For normal shift processing this wont be very quick
		 *  so it will be a 'long' LOCK */
		kss_item = STORE_HEAD_NOLOCK(old_keysharesummary_store);
		while (kss_item) {
			// remove the old keysharesummaries from the trees
			remove_from_ktree(keysharesummary_root, kss_item);
			free_keysharesummary_data(kss_item);
			kss_item = kss_item->next;
		}
		k_list_transfer_to_head(old_keysharesummary_store, keysharesummary_free);

		K_RUNLOCK(workmarkers_free);
		K_WUNLOCK(keysummary_free);
		K_WUNLOCK(markersummary_free);
		K_WUNLOCK(keysharesummary_free);
		K_WUNLOCK(sharesummary_free);
		setnow(&lck_fin);

		LOGWARNING("%s() Processed: %d ms %d ks %d ss %d kss "
			   "%"PRId64" shares %"PRId64" diff "
			   "k(2*%"PRId64"%s/2*%"PRId64"%s) for workmarkers "
			   "%"PRId64"/%s/End %"PRId64"/Stt %"PRId64"/%s/%s "
			   "add=%.3fs kadd=%.3fs db=%.3fs kdb=%.3fs "
			   "lck=%.3f+%.3fs%s",
			   shortname, ms_count, ks_count, ss_count, kss_count,
			   shareacc, diffacc,
			   kshareacc >> 1, (kshareacc & 1) ? ".5" : "",
			   kdiffacc >> 1, (kdiffacc & 1) ? ".5" : "",
			   workmarkers->markerid, workmarkers->in_poolinstance,
			   workmarkers->workinfoidend,
			   workmarkers->workinfoidstart,
			   workmarkers->description,
			   workmarkers->status, tvdiff(&add_fin, &add_stt),
			   tvdiff(&kadd_fin, &kadd_stt),
			   tvdiff(&db_fin, &db_stt),
			   tvdiff(&kdb_fin, &kdb_stt),
			   tvdiff(&lck_got, &lck_stt),
			   tvdiff(&lck_fin, &lck_got),
			   nonblank ? EMPTY : " ONLY BLANK KEYS");

		// This should never happen
		if (!key_update && (kshareacc != (shareacc << 1) ||
				     kdiffacc != (diffacc << 1))) {
			LOGERR("%s() CODE BUG: keysummary share/diff counts "
				"are wrong!", shortname);
		}
	}
	free_ktree(ms_root, NULL);
	free_ktree(ks_root, NULL);
	new_markersummary_store = k_free_store(new_markersummary_store);
	new_keysummary_store = k_free_store(new_keysummary_store);
	old_sharesummary_store = k_free_store(old_sharesummary_store);
	old_keysharesummary_store = k_free_store(old_keysharesummary_store);

	return ok;
}

// TODO: keysummaries ...
bool delete_markersummaries(PGconn *conn, WORKMARKERS *wm)
{
	// shorter name for log messages
	static const char *shortname = "DEL_MS";
	K_STORE *del_markersummary_store = NULL;
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ms_ctx[1];
	MARKERSUMMARY *markersummary = NULL, lookmarkersummary;
	K_ITEM *ms_item, ms_look, *p_ms_item = NULL;
	bool ok = false, conned = false;
	int64_t diffacc, shareacc;
	char *reason = "unknown";
	int ms_count;
	char *params[1];
	int par = 0, ms_del = 0;
	char *del, *tuples = NULL;

	if (WMPROCESSED(wm->status)) {
		reason = "status processed";
		goto flail;
	}

	LOGWARNING("%s() Deleting: markersummaries for workmarkers "
		   "%"PRId64"/%s/End %"PRId64"/Stt %"PRId64"/%s/%s",
		   shortname, wm->markerid, wm->in_poolinstance,
		   wm->workinfoidend, wm->workinfoidstart, wm->description,
		   wm->status);

	del_markersummary_store = k_new_store(markersummary_free);

	lookmarkersummary.markerid = wm->markerid;
	lookmarkersummary.userid = 0;
	lookmarkersummary.in_workername = EMPTY;

	ms_count = diffacc = shareacc = 0;
	ms_item = NULL;

	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&lookmarkersummary);

	K_WLOCK(markersummary_free);
	K_WLOCK(workmarkers_free);

	ms_item = find_after_in_ktree(markersummary_root, &ms_look, ms_ctx);
	DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	if (!ms_item || markersummary->markerid != wm->markerid) {
		reason = "no markersummaries";
		goto flail;
	}

	// Build the delete list of markersummaries
	while (ms_item && markersummary->markerid == wm->markerid) {
		ms_count++;
		diffacc += markersummary->diffacc;
		shareacc += markersummary->shareacc;

		k_unlink_item(markersummary_store, ms_item);
		k_add_tail(del_markersummary_store, ms_item);

		ms_item = next_in_ktree(ms_ctx);
		DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
	}

	par = 0;
	params[par++] = bigint_to_buf(wm->markerid, NULL, 0);
	PARCHK(par, params);

	del = "delete from markersummary where markerid=$1";

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, del, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Delete", rescode, conn);
		reason = "db error";
		goto unparam;
	}

	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples) {
			ms_del = atoi(tuples);
			if (ms_del != ms_count) {
				LOGERR("%s() deleted markersummaries should be"
					" %d but deleted=%d",
					shortname, ms_count, ms_del);
				reason = "del mismatch";
				goto unparam;
			}
		}
	}

	ok = true;
unparam:
	CKPQClear(res);
flail:
	CKPQDisco(&conn, conned);

	if (!ok) {
		if (del_markersummary_store && del_markersummary_store->count) {
			k_list_transfer_to_head(del_markersummary_store,
						markersummary_store);
		}
	} else {
		/* TODO: add a list garbage collection thread so as to not
		 *  invalidate the data immediately (free_*), rather after
		 *  some delay */
		ms_item = STORE_HEAD_NOLOCK(del_markersummary_store);
		while (ms_item) {
			remove_from_ktree(markersummary_root, ms_item);
			remove_from_ktree(markersummary_userid_root, ms_item);
			free_markersummary_data(ms_item);
			ms_item = ms_item->next;
		}

		k_list_transfer_to_head(del_markersummary_store,
					markersummary_free);

		p_ms_item = find_markersummary_p(wm->markerid);
		if (p_ms_item) {
			remove_from_ktree(markersummary_pool_root, p_ms_item);
			free_markersummary_data(p_ms_item);
			k_unlink_item(markersummary_pool_store, p_ms_item);
			k_add_head(markersummary_free, p_ms_item);
		}
	}

	K_WUNLOCK(workmarkers_free);
	K_WUNLOCK(markersummary_free);

	if (!ok) {
		// already displayed the full workmarkers detail at the top
		LOGERR("%s() %s: workmarkers %"PRId64"/%s/%s",
			shortname, reason, wm->markerid, wm->description,
			wm->status);
	} else {
		LOGWARNING("%s() Deleted: %d ms %"PRId64" shares "
			   "%"PRId64" diff for workmarkers %"PRId64"/%s/"
			   "End %"PRId64"/Stt %"PRId64"/%s/%s",
			   shortname, ms_count, shareacc, diffacc,
			   wm->markerid, wm->in_poolinstance, wm->workinfoidend,
			   wm->workinfoidstart, wm->description, wm->status);
	}

	if (del_markersummary_store)
		del_markersummary_store = k_free_store(del_markersummary_store);

	return ok;
}

// Requires K_WLOCK(sharesummary_free)
static void set_sharesummary_stats(SHARESUMMARY *row, SHARES *s_row,
				   SHAREERRORS *e_row, bool new,
				   double *tdf, double *tdl)
{
	tv_t *createdate;

	if (s_row)
		createdate = &(s_row->createdate);
	else
		createdate = &(e_row->createdate);

	if (new) {
		zero_sharesummary(row);
		copy_tv(&(row->firstshare), createdate);
		copy_tv(&(row->lastshare), createdate);
	} else {
		if (!row->firstshare.tv_sec ||
		     !tv_newer(&(row->firstshare), createdate)) {
			copy_tv(&(row->firstshare), createdate);
		}
		if (tv_newer(&(row->lastshare), createdate))
			copy_tv(&(row->lastshare), createdate);
	}

	if (s_row) {
		row->sharecount += 1;
		switch (s_row->errn) {
			case SE_NONE:
				row->diffacc += s_row->diff;
				row->shareacc++;
				// should always be true
				if (s_row->diff > 0) {
					if (!row->firstshareacc.tv_sec ||
					     !tv_newer(&(row->firstshareacc), createdate)) {
						copy_tv(&(row->firstshareacc), createdate);
					}
					if (tv_newer(&(row->lastshareacc), createdate)) {
						copy_tv(&(row->lastshareacc), createdate);
						row->lastdiffacc = s_row->diff;
					}
				}
				break;
			case SE_STALE:
				row->diffsta += s_row->diff;
				row->sharesta++;
				break;
			case SE_DUPE:
				row->diffdup += s_row->diff;
				row->sharedup++;
				break;
			case SE_HIGH_DIFF:
				row->diffhi += s_row->diff;
				row->sharehi++;
				break;
			default:
				row->diffrej += s_row->diff;
				row->sharerej++;
				break;
		}
	} else
		row->errorcount += 1;

	// Only if required
	if (!new) {
		*tdf = tvdiff(createdate, &(row->firstshare));
		*tdl = tvdiff(createdate, &(row->lastshare));
	}
}

static void set_keysharesummary_stats(KEYSHARESUMMARY *row, SHARES *s_row,
				      bool new)
{
	if (new) {
		zero_keysharesummary(row);
		copy_tv(&(row->firstshare), &(s_row->createdate));
		copy_tv(&(row->lastshare), &(s_row->createdate));
	} else {
		if (!row->firstshare.tv_sec ||
		     !tv_newer(&(row->firstshare), &(s_row->createdate))) {
			copy_tv(&(row->firstshare), &(s_row->createdate));
		}
		if (tv_newer(&(row->lastshare), &(s_row->createdate)))
			copy_tv(&(row->lastshare), &(s_row->createdate));
	}

	row->sharecount += 1;
	switch (s_row->errn) {
		case SE_NONE:
			row->diffacc += s_row->diff;
			row->shareacc++;
			// should always be true
			if (s_row->diff > 0) {
				if (!row->firstshareacc.tv_sec ||
				     !tv_newer(&(row->firstshareacc), &(s_row->createdate))) {
					copy_tv(&(row->firstshareacc), &(s_row->createdate));
				}
				if (tv_newer(&(row->lastshareacc), &(s_row->createdate))) {
					copy_tv(&(row->lastshareacc), &(s_row->createdate));
					row->lastdiffacc = s_row->diff;
				}
			}
			break;
		case SE_STALE:
			row->diffsta += s_row->diff;
			row->sharesta++;
			break;
		case SE_DUPE:
			row->diffdup += s_row->diff;
			row->sharedup++;
			break;
		case SE_HIGH_DIFF:
			row->diffhi += s_row->diff;
			row->sharehi++;
			break;
		default:
			row->diffrej += s_row->diff;
			row->sharerej++;
			break;
	}
}

/* Keep some simple stats on how often shares are out of order
 *  and how often they produce a WARNING due to OOOLIMIT */
static int64_t ooof0, ooof, oool0, oool;
#define OOOLIMIT -2.0

/* This isn't locked so it is possible - but very unlikely -
 *  to get an invalid set of numbers if any ooo variables change
 *  during the snprintf, but that will simply display a wrong number */
char *ooo_status(char *buf, size_t siz)
{
	snprintf(buf, siz,
		 "F%"PRId64":%"PRId64"/L%"PRId64":%"PRId64"/%.1f/T%"PRId64,
		 ooof, ooof0, oool, oool0, OOOLIMIT,
		 ooof + ooof0 + oool + oool0);
	return buf;
}

/* sharesummaries are no longer stored in the DB but fields are updated as b4
 * This creates/updates both the sharesummaries and the keysharesummaries */
bool _sharesummary_update(SHARES *s_row, SHAREERRORS *e_row, tv_t *cd,
			 WHERE_FFL_ARGS)
{
	WORKMARKERS *wm;
	SHARESUMMARY *row, *p_row;
	KEYSHARESUMMARY *ki_row = NULL, *ka_row = NULL;
	K_ITEM *ss_item, *kiss_item = NULL, *kass_item = NULL, *wm_item, *p_item = NULL;
	bool new = false, p_new = false, ki_new = false, ka_new = false;
	int64_t userid, workinfoid, markerid;
	char *workername, *address = NULL, *agent = NULL;
	char *st = NULL, *db = NULL;
	char ooo_buf[256];
	double tdf, tdl;

	LOGDEBUG("%s(): update", __func__);

	if (s_row) {
		if (e_row) {
			quithere(1, "ERR: only one of s_row and e_row allowed"
				    WHERE_FFL,
				    WHERE_FFL_PASS);
		}
		userid = s_row->userid;
		workername = s_row->in_workername;
		workinfoid = s_row->workinfoid;
		address = s_row->address;
		agent = s_row->agent;
	} else {
		if (!e_row) {
			quithere(1, "ERR: both s_row and e_row are NULL"
				    WHERE_FFL,
				    WHERE_FFL_PASS);
		}
		userid = e_row->userid;
		workername = e_row->in_workername;
		workinfoid = e_row->workinfoid;
	}

	K_RLOCK(workmarkers_free);
	wm_item = find_workmarkers(workinfoid, false, MARKER_PROCESSED,
				   NULL);
	if (wm_item) {
		DATA_WORKMARKERS(wm, wm_item);
		markerid = wm->markerid;
		K_RUNLOCK(workmarkers_free);
		LOGERR("%s(): attempt to update sharesummary "
		       "with %s %"PRId64"/%"PRId64"/%s "CDDB" %s"
		       " but processed workmarkers %"PRId64" exists",
			__func__, s_row ? "shares" : "shareerrors",
			workinfoid, userid, st = safe_text(workername),
				db = ctv_to_buf(cd, NULL, 0), markerid);
			FREENULL(st);
			FREENULL(db);
			return false;
	}
	K_RUNLOCK(workmarkers_free);

	K_WLOCK(sharesummary_free);
	ss_item = find_sharesummary(userid, workername, workinfoid);

	if (ss_item) {
		DATA_SHARESUMMARY(row, ss_item);
	} else {
		new = true;
		ss_item = k_unlink_head(sharesummary_free);
		DATA_SHARESUMMARY(row, ss_item);
		bzero(row, sizeof(*row));
		row->userid = userid;
		// workername is intransient
		row->in_workername = workername;
		row->workinfoid = workinfoid;
	}

	// N.B. this directly updates the non-key data
	set_sharesummary_stats(row, s_row, e_row, new, &tdf, &tdl);

	if (new) {
		add_to_ktree(sharesummary_root, ss_item);
		add_to_ktree(sharesummary_workinfoid_root, ss_item);
		k_add_head(sharesummary_store, ss_item);
	}
	K_WUNLOCK(sharesummary_free);

	// Ignore shareerrors for keysummaries
	if (s_row) {
		K_WLOCK(keysharesummary_free);
		kiss_item = find_keysharesummary(workinfoid, KEYTYPE_IP, address);

		if (kiss_item) {
			DATA_KEYSHARESUMMARY(ki_row, kiss_item);
		} else {
			ki_new = true;
			kiss_item = k_unlink_head(keysharesummary_free);
			DATA_KEYSHARESUMMARY(ki_row, kiss_item);
			bzero(ki_row, sizeof(*ki_row));
			ki_row->workinfoid = workinfoid;
			ki_row->keytype[0] = KEYTYPE_IP;
			ki_row->keytype[1] = '\0';
			DUP_POINTER(keysharesummary_free, ki_row->key, address);
		}

		// N.B. this directly updates the non-key data
		set_keysharesummary_stats(ki_row, s_row, ki_new);
		if (ki_new) {
			add_to_ktree(keysharesummary_root, kiss_item);
			k_add_head(keysharesummary_store, kiss_item);
		}
		K_WUNLOCK(keysharesummary_free);

		K_WLOCK(keysharesummary_free);
		kass_item = find_keysharesummary(workinfoid, KEYTYPE_AGENT, agent);

		if (kass_item) {
			DATA_KEYSHARESUMMARY(ka_row, kass_item);
		} else {
			ka_new = true;
			kass_item = k_unlink_head(keysharesummary_free);
			DATA_KEYSHARESUMMARY(ka_row, kass_item);
			bzero(ka_row, sizeof(*ka_row));
			ka_row->workinfoid = workinfoid;
			ka_row->keytype[0] = KEYTYPE_AGENT;
			ka_row->keytype[1] = '\0';
			DUP_POINTER(keysharesummary_free, ka_row->key, agent);
		}

		// N.B. this directly updates the non-key data
		set_keysharesummary_stats(ka_row, s_row, ka_new);
		if (ka_new) {
			add_to_ktree(keysharesummary_root, kass_item);
			k_add_head(keysharesummary_store, kass_item);
		}
		K_WUNLOCK(keysharesummary_free);
	}

	if (!new) {
		// don't LOG '=' in case shares come from asicseer-pool with the same timestamp
		if (tdf < 0.0) {
			char *tmp1 = NULL, *tmp2 = NULL;
			int level = LOG_DEBUG;
			// WARNING for shares exceeding the OOOLIMIT but not during startup
			if (tdf < OOOLIMIT) {
				ooof++;
				if (startup_complete)
					level = LOG_WARNING;
			} else
				ooof0++;
			LOGMSG(level, "%s(): OoO %s "CDDB" (%s) is < summary"
				" firstshare (%s) (%s)",
				__func__, s_row ? "shares" : "shareerrors",
				(tmp1 = ctv_to_buf(cd, NULL, 0)),
				(tmp2 = ctv_to_buf(&(row->firstshare), NULL, 0)),
				ooo_status(ooo_buf, sizeof(ooo_buf)));
			free(tmp2);
			free(tmp1);
		}

		// don't LOG '=' in case shares come from asicseer-pool with the same timestamp
		if (tdl < 0.0) {
			char *tmp1 = NULL, *tmp2 = NULL;
			int level = LOG_DEBUG;
			// WARNING for shares exceeding the OOOLIMIT but not during startup
			if (tdl < OOOLIMIT) {
				oool++;
				if (startup_complete)
					level = LOG_WARNING;
			} else
				oool0++;
			LOGMSG(level, "%s(): OoO %s "CDDB" (%s) is < summary"
				" lastshare (%s) (%s)",
				__func__, s_row ? "shares" : "shareerrors",
				(tmp1 = ctv_to_buf(cd, NULL, 0)),
				(tmp2 = ctv_to_buf(&(row->lastshare), NULL, 0)),
				ooo_status(ooo_buf, sizeof(ooo_buf)));
			free(tmp2);
			free(tmp1);
		}

		if (row->complete[0] != SUMMARY_NEW) {
			LOGDEBUG("%s(): updating sharesummary not '%c'"
				 " %"PRId64"/%s/%"PRId64"/%s",
				__func__, SUMMARY_NEW, row->userid,
				st = safe_text_nonull(row->in_workername),
				row->workinfoid, row->complete);
			FREENULL(st);
		}
	}

	K_WLOCK(sharesummary_free);
	p_item = find_sharesummary_p(workinfoid);

	if (p_item) {
		DATA_SHARESUMMARY(p_row, p_item);
	} else {
		p_new = true;
		p_item = k_unlink_head(sharesummary_free);
		DATA_SHARESUMMARY(p_row, p_item);
		bzero(p_row, sizeof(*p_row));
		POOL_SS(p_row);
		p_row->workinfoid = workinfoid;
	}

	set_sharesummary_stats(p_row, s_row, e_row, p_new, &tdf, &tdl);

	if (p_new) {
		add_to_ktree(sharesummary_pool_root, p_item);
		k_add_head(sharesummary_pool_store, p_item);
	}
	K_WUNLOCK(sharesummary_free);

	return true;
}

// No key fields are modified
bool sharesummary_age(K_ITEM *ss_item)
{
	SHARESUMMARY *row;

	LOGDEBUG("%s(): update", __func__);

	DATA_SHARESUMMARY(row, ss_item);
	row->complete[0] = SUMMARY_COMPLETE;
	row->complete[1] = '\0';

	return true;
}

// No key fields are modified
bool keysharesummary_age(K_ITEM *kss_item)
{
	KEYSHARESUMMARY *row;

	LOGDEBUG("%s(): update", __func__);

	DATA_KEYSHARESUMMARY(row, kss_item);
	row->complete[0] = SUMMARY_COMPLETE;
	row->complete[1] = '\0';

	return true;
}

bool blocks_stats(PGconn *conn, int32_t height, char *blockhash,
			double diffacc, double diffinv, double shareacc,
			double shareinv, int64_t elapsed,
			char *by, char *code, char *inet, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *b_item, *old_b_item;
	BLOCKS *row, *oldblocks;
	char hash_dsp[16+1];
	char *upd, *ins;
	char *params[8 + HISTORYDATECOUNT];
	bool ok = false, update_old = false;
	int n, par = 0;

	LOGDEBUG("%s(): confirm", __func__);

	dsp_hash(blockhash, hash_dsp, sizeof(hash_dsp));

	K_RLOCK(blocks_free);
	old_b_item = find_blocks(height, blockhash, NULL);
	K_RUNLOCK(blocks_free);

	if (!old_b_item) {
		LOGERR("%s(): Non-existent Block: %d/...%s",
			__func__, height, hash_dsp);
		return false;
	}

	DATA_BLOCKS(oldblocks, old_b_item);

	K_WLOCK(blocks_free);
	b_item = k_unlink_head(blocks_free);
	K_WUNLOCK(blocks_free);

	DATA_BLOCKS(row, b_item);
	copy_blocks(row, oldblocks);
	row->diffacc = diffacc;
	row->diffinv = diffinv;
	row->shareacc = shareacc;
	row->shareinv = shareinv;
	row->elapsed = elapsed;
	row->statsconfirmed[0] = BLOCKS_STATSCONFIRMED;
	row->statsconfirmed[1] = '\0';
	HISTORYDATEINIT(row, cd, by, code, inet);

	upd = "update blocks set "EDDB"=$1 where blockhash=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = str_to_buf(row->blockhash, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	if (CKPQConn(&conn))
		conned = true;
	if (!CKPQBegin(conn))
		goto unparam;

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update", rescode, conn);
		goto rollback;
	}

	update_old = true;

	for (n = 0; n < par; n++)
		free(params[n]);

	par = 0;
	params[par++] = str_to_buf(row->blockhash, NULL, 0);
	params[par++] = tv_to_buf(cd, NULL, 0);
	params[par++] = double_to_buf(row->diffacc, NULL, 0);
	params[par++] = double_to_buf(row->diffinv, NULL, 0);
	params[par++] = double_to_buf(row->shareacc, NULL, 0);
	params[par++] = double_to_buf(row->shareinv, NULL, 0);
	params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
	params[par++] = str_to_buf(row->statsconfirmed, NULL, 0);
	HISTORYDATEPARAMS(params, par, row);
	PARCHKVAL(par, 8 + HISTORYDATECOUNT, params); // 13 as per ins

	ins = "insert into blocks "
		"(height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,"
		"diffacc,diffinv,shareacc,shareinv,elapsed,"
		"statsconfirmed"
		HISTORYDATECONTROL ") select "
		"height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,"
		"$3,$4,$5,$6,$7,$8,"
		"$9,$10,$11,$12,$13 from blocks where "
		"blockhash=$1 and "EDDB"=$2";

	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto rollback;
	}

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(blocks_free);
	if (!ok)
		k_add_head(blocks_free, b_item);
	else {
		if (update_old) {
			remove_from_ktree(blocks_root, old_b_item);
			copy_tv(&(oldblocks->expirydate), cd);
			add_to_ktree(blocks_root, old_b_item);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		add_to_ktree(blocks_root, b_item);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
		// 'confirmed' is unchanged so no need to recalc *createdate
	}
	K_WUNLOCK(blocks_free);

	return ok;
}

bool blocks_add(PGconn *conn, int32_t height, char *blockhash,
		char *confirmed, char *info, char *workinfoid,
		char *username, INTRANSIENT *in_workername, char *clientid,
		char *enonce1, char *nonce2, char *nonce, char *reward,
		char *by, char *code, char *inet, tv_t *cd,
		bool igndup, char *id, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *b_item, *u_item, *old_b_item;
	char cd_buf[DATE_BUFSIZ];
	char hash_dsp[16+1];
	double hash_diff;
	BLOCKS *row, *oldblocks;
	USERS *users;
	char *upd, *ins;
	char *params[18 + HISTORYDATECOUNT];
	bool ok = false, update_old = false;
	int n, par = 0;
	char *want = NULL, *st = NULL;
	char *workername;

	LOGDEBUG("%s(): add", __func__);

	if (in_workername)
		workername = in_workername->str;
	else
		workername = EMPTY;

	K_WLOCK(blocks_free);
	b_item = k_unlink_head(blocks_free);
	K_WUNLOCK(blocks_free);

	DATA_BLOCKS(row, b_item);
	bzero(row, sizeof(*row));

	row->height = height;
	STRNCPY(row->blockhash, blockhash);

	dsp_hash(blockhash, hash_dsp, sizeof(hash_dsp));
	hash_diff = blockhash_diff(blockhash);

	K_RLOCK(blocks_free);
	old_b_item = find_blocks(row->height, blockhash, NULL);
	K_RUNLOCK(blocks_free);
	DATA_BLOCKS_NULL(oldblocks, old_b_item);

	switch (confirmed[0]) {
		case BLOCKS_NEW:
			// None should exist - so must be a duplicate
			if (old_b_item) {
				K_WLOCK(blocks_free);
				k_add_head(blocks_free, b_item);
				K_WUNLOCK(blocks_free);
				if (!igndup) {
					tv_to_buf(cd, cd_buf, sizeof(cd_buf));
					LOGERR("%s(): Duplicate (%s) blocks ignored, Status: "
						"%s, Block: %"PRId32"/...%s/%s",
						__func__,
						blocks_confirmed(oldblocks->confirmed),
						blocks_confirmed(confirmed),
						height, hash_dsp, cd_buf);
				}
				return true;
			}

			K_RLOCK(users_free);
			u_item = find_users(username);
			K_RUNLOCK(users_free);
			if (!u_item)
				row->userid = KANO;
			else {
				DATA_USERS(users, u_item);
				row->userid = users->userid;
			}

			STRNCPY(row->confirmed, confirmed);
			STRNCPY(row->info, info);
			TXT_TO_BIGINT("workinfoid", workinfoid, row->workinfoid);
			// workername is intransient or EMPTY
			row->in_workername = workername;
			TXT_TO_INT("clientid", clientid, row->clientid);
			STRNCPY(row->enonce1, enonce1);
			STRNCPY(row->nonce2, nonce2);
			STRNCPY(row->nonce, nonce);
			TXT_TO_BIGINT("reward", reward, row->reward);
			// Specify them
			row->diffacc = 0;
			row->diffinv = 0;
			row->shareacc = 0;
			row->shareinv = 0;
			row->elapsed = 0;
			STRNCPY(row->statsconfirmed, BLOCKS_STATSPENDING_STR);

			HISTORYDATEINIT(row, cd, by, code, inet);
			HISTORYDATETRANSFER(trf_root, row);

			par = 0;
			params[par++] = int_to_buf(row->height, NULL, 0);
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = bigint_to_buf(row->workinfoid, NULL, 0);
			params[par++] = bigint_to_buf(row->userid, NULL, 0);
			params[par++] = str_to_buf(row->in_workername, NULL, 0);
			params[par++] = int_to_buf(row->clientid, NULL, 0);
			params[par++] = str_to_buf(row->enonce1, NULL, 0);
			params[par++] = str_to_buf(row->nonce2, NULL, 0);
			params[par++] = str_to_buf(row->nonce, NULL, 0);
			params[par++] = bigint_to_buf(row->reward, NULL, 0);
			params[par++] = str_to_buf(row->confirmed, NULL, 0);
			params[par++] = str_to_buf(row->info, NULL, 0);
			params[par++] = double_to_buf(row->diffacc, NULL, 0);
			params[par++] = double_to_buf(row->diffinv, NULL, 0);
			params[par++] = double_to_buf(row->shareacc, NULL, 0);
			params[par++] = double_to_buf(row->shareinv, NULL, 0);
			params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
			params[par++] = str_to_buf(row->statsconfirmed, NULL, 0);
			HISTORYDATEPARAMS(params, par, row);
			PARCHK(par, params);

			ins = "insert into blocks "
				"(height,blockhash,workinfoid,userid,workername,"
				"clientid,enonce1,nonce2,nonce,reward,confirmed,"
				"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
				"statsconfirmed"
				HISTORYDATECONTROL ") values (" PQPARAM23 ")";

			if (CKPQConn(&conn))
				conned = true;
			res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = CKPQResultStatus(res);
			CKPQClear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto unparam;
			}
			// We didn't use a Begin
			ok = true;
			userinfo_block(row, INFO_NEW, 1);
			goto unparam;
			break;
		case BLOCKS_ORPHAN:
		case BLOCKS_REJECT:
		case BLOCKS_42:
			// These shouldn't be possible until startup completes
			if (!startup_complete) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Status: %s invalid during startup. "
					"Ignored: Block: %"PRId32"/...%s/%s",
					__func__,
					blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
		case BLOCKS_CONFIRM:
			if (!old_b_item) {
				tv_to_buf(cd, cd_buf, sizeof(cd_buf));
				LOGERR("%s(): Can't %s a non-existent Block: %"PRId32"/...%s/%s",
					__func__, blocks_confirmed(confirmed),
					height, hash_dsp, cd_buf);
				goto flail;
			}
			switch (confirmed[0]) {
				case BLOCKS_CONFIRM:
					if (oldblocks->confirmed[0] != BLOCKS_NEW)
						want = BLOCKS_NEW_STR;
					break;
				case BLOCKS_42:
					if (oldblocks->confirmed[0] != BLOCKS_CONFIRM)
						want = BLOCKS_CONFIRM_STR;
					break;
				case BLOCKS_ORPHAN:
					if (oldblocks->confirmed[0] != BLOCKS_NEW &&
					    oldblocks->confirmed[0] != BLOCKS_CONFIRM)
						want = BLOCKS_N_C_STR;
					break;
				case BLOCKS_REJECT:
					if (oldblocks->confirmed[0] != BLOCKS_NEW &&
					    oldblocks->confirmed[0] != BLOCKS_CONFIRM &&
					    oldblocks->confirmed[0] != BLOCKS_ORPHAN &&
					    oldblocks->confirmed[0] != BLOCKS_REJECT)
						want = BLOCKS_N_C_O_R_STR;
					break;
			}
			if (want) {
				// No mismatch messages during startup
				if (startup_complete) {
					tv_to_buf(cd, cd_buf, sizeof(cd_buf));
					LOGERR("%s(): New Status: (%s)%s requires Status: %s. "
						"Ignored: Status: (%s)%s, Block: %"PRId32"/...%s/%s",
						__func__,
						confirmed, blocks_confirmed(confirmed),
						want, oldblocks->confirmed,
						blocks_confirmed(oldblocks->confirmed),
						height, hash_dsp, cd_buf);
				}
				goto flail;
			}

			upd = "update blocks set "EDDB"=$1 where blockhash=$2 and "EDDB"=$3";
			par = 0;
			params[par++] = tv_to_buf(cd, NULL, 0);
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
			PARCHKVAL(par, 3, params);

			if (CKPQConn(&conn))
				conned = true;
			// New is mostly a copy of the old
			copy_blocks(row, oldblocks);
			STRNCPY(row->confirmed, confirmed);
			if (info && *info)
				STRNCPY(row->info, info);
			if (confirmed[0] == BLOCKS_CONFIRM) {
				row->diffacc = pool.diffacc;
				row->diffinv = pool.diffinv;
				row->shareacc = pool.shareacc;
				row->shareinv = pool.shareinv;
			}

			HISTORYDATEINIT(row, cd, by, code, inet);
			HISTORYDATETRANSFER(trf_root, row);

			if (!CKPQBegin(conn))
				goto unparam;
			res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = CKPQResultStatus(res);
			CKPQClear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Update", rescode, conn);
				goto rollback;
			}

			for (n = 0; n < par; n++)
				free(params[n]);

			par = 0;
			params[par++] = str_to_buf(row->blockhash, NULL, 0);
			params[par++] = tv_to_buf(cd, NULL, 0);
			params[par++] = str_to_buf(row->confirmed, NULL, 0);
			params[par++] = str_to_buf(row->info, NULL, 0);

			if (confirmed[0] == BLOCKS_CONFIRM) {
				params[par++] = double_to_buf(row->diffacc, NULL, 0);
				params[par++] = double_to_buf(row->diffinv, NULL, 0);
				params[par++] = double_to_buf(row->shareacc, NULL, 0);
				params[par++] = double_to_buf(row->shareinv, NULL, 0);
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 8 + HISTORYDATECOUNT, params); // 13 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,$4,$5,$6,$7,$8,elapsed,statsconfirmed,"
					"$9,$10,$11,$12,$13 from blocks where "
					"blockhash=$1 and "EDDB"=$2";
			} else {
				HISTORYDATEPARAMS(params, par, row);
				PARCHKVAL(par, 4 + HISTORYDATECOUNT, params); // 9 as per ins

				ins = "insert into blocks "
					"(height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,confirmed,"
					"info,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed"
					HISTORYDATECONTROL ") select "
					"height,blockhash,workinfoid,userid,workername,"
					"clientid,enonce1,nonce2,nonce,reward,"
					"$3,$4,diffacc,diffinv,shareacc,shareinv,elapsed,"
					"statsconfirmed,"
					"$5,$6,$7,$8,$9 from blocks where "
					"blockhash=$1 and "EDDB"=$2";
			}

			res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
			rescode = CKPQResultStatus(res);
			CKPQClear(res);
			if (!PGOK(rescode)) {
				PGLOGERR("Insert", rescode, conn);
				goto rollback;
			}

			update_old = true;
			/* handle confirmed state changes for userinfo
			 * this case statement handles all possible combinations
			 *  even if they can't happen (yet) */
			switch (oldblocks->confirmed[0]) {
				case BLOCKS_ORPHAN:
					switch (confirmed[0]) {
						case BLOCKS_ORPHAN:
							break;
						case BLOCKS_REJECT:
							userinfo_block(row, INFO_ORPHAN, -1);
							userinfo_block(row, INFO_REJECT, 1);
							break;
						default:
							userinfo_block(row, INFO_ORPHAN, -1);
							break;
					}
					break;
				case BLOCKS_REJECT:
					switch (confirmed[0]) {
						case BLOCKS_REJECT:
							break;
						case BLOCKS_ORPHAN:
							userinfo_block(row, INFO_REJECT, -1);
							userinfo_block(row, INFO_ORPHAN, 1);
							break;
						default:
							userinfo_block(row, INFO_REJECT, -1);
							break;
					}
					break;
				default:
					switch (confirmed[0]) {
						case BLOCKS_ORPHAN:
							userinfo_block(row, INFO_ORPHAN, 1);
							break;
						case BLOCKS_REJECT:
							userinfo_block(row, INFO_REJECT, 1);
							break;
						default:
							break;
					}
					break;
			}
			break;
		default:
			LOGERR("%s(): %s.failed.invalid confirm='%s'",
			       __func__, id, confirmed);
			goto flail;
	}

	ok = true;
rollback:

	CKPQEnd(conn, ok);

unparam:
	for (n = 0; n < par; n++)
		free(params[n]);
flail:
	CKPQDisco(&conn, conned);

	K_RLOCK(workinfo_free);
	K_WLOCK(blocks_free);
	if (!ok)
		k_add_head(blocks_free, b_item);
	else {
		if (update_old) {
			remove_from_ktree(blocks_root, old_b_item);
			copy_tv(&(oldblocks->expirydate), cd);
			add_to_ktree(blocks_root, old_b_item);
			// Copy it over to avoid having to recalculate it
			row->netdiff = oldblocks->netdiff;
		} else
			row->netdiff = 0;
		add_to_ktree(blocks_root, b_item);
		k_add_head(blocks_store, b_item);
		blocks_stats_rebuild = true;
		// recalc the *createdate fields for possibly affected blocks
		set_blockcreatedate(row->height);
		set_prevcreatedate(row->height);
	}
	K_WUNLOCK(blocks_free);
	K_RUNLOCK(workinfo_free);

	if (ok) {
		char pct[16] = "?";
		char est[16] = "";
		char diff[16] = "";
		K_ITEM *w_item;
		char tmp[256] = "";
		bool blk = false;

		suffix_string(hash_diff, diff, sizeof(diff)-1, 0);

		switch (confirmed[0]) {
			case BLOCKS_NEW:
				blk = true;
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp), " UTC:%s", cd_buf);
				break;
			case BLOCKS_CONFIRM:
				blk = true;
				if (pool.diffacc >= 1000.0) {
					suffix_string(pool.diffacc, est, sizeof(est)-2, 0);
					strcat(est, " ");
				}
				w_item = find_workinfo(row->workinfoid, NULL);
				if (w_item) {
					WORKINFO *workinfo;
					DATA_WORKINFO(workinfo, w_item);
					if (workinfo->diff_target > 0.0) {
						snprintf(pct, sizeof(pct), "%.2f%% ",
							 100.0 * pool.diffacc /
							 workinfo->diff_target);
					}
				}
				tv_to_buf(&(row->createdate), cd_buf, sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 " Reward: %f, Worker: %s, ShareEst: %.1f %s%sUTC:%s",
					 BTC_TO_D(row->reward),
					 st = safe_text_nonull(row->in_workername),
					 pool.diffacc, est, pct, cd_buf);
				FREENULL(st);
				if (pool.workinfoid < row->workinfoid) {
					pool.workinfoid = row->workinfoid;
					pool.height = row->height;
					zero_on_new_block(false);
				}
				break;
			case BLOCKS_ORPHAN:
			case BLOCKS_REJECT:
			case BLOCKS_42:
			default:
				break;
		}

		LOGWARNING("%s(): %sStatus: %s, Block: %"PRId32"/...%s Diff %s%s",
			   __func__, blk ? "BLOCK! " : "",
			   blocks_confirmed(confirmed),
			   height, hash_dsp, diff, tmp);
	}

	return ok;
}

bool blocks_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *item;
	int n, i;
	BLOCKS *row;
	char *field = NULL;
	char *sel;
	int fields = 18;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int height_num, blockhash_num, workinfoid_num, userid_num;
	int workername_num, clientid_num, enonce1_num, nonce2_num, nonce_num;
	int reward_num, confirmed_num, info_num, diffacc_num, diffinv_num;
	int shareacc_num, shareinv_num, elapsed_num, statsconfirmed_num;
	HISTORYDATE_num;

	sel = "select "
		"height,blockhash,workinfoid,userid,workername,"
		"clientid,enonce1,nonce2,nonce,reward,confirmed,info,"
		"diffacc,diffinv,shareacc,shareinv,elapsed,statsconfirmed"
		HISTORYDATECONTROL
		" from blocks";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	height_num = blockhash_num = workinfoid_num = userid_num =
	workername_num = clientid_num = enonce1_num = nonce2_num = nonce_num =
	reward_num = confirmed_num = info_num = diffacc_num = diffinv_num =
	shareacc_num = shareinv_num = elapsed_num =
	statsconfirmed_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(blocks_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(blocks_free);
		DATA_BLOCKS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, height, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("height", field, row->height);

		CKPQ_VAL_FLD_num(res, i, blockhash, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("blockhash", field, row->blockhash);

		CKPQ_VAL_FLD_num(res, i, workinfoid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		CKPQ_VAL_FLD_num(res, i, userid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("userid", field, row->userid);

		CKPQ_VAL_FLD_num(res, i, workername, field, ok);
		if (!ok)
			break;
		row->in_workername = intransient_str("workername", field);

		CKPQ_VAL_FLD_num(res, i, clientid, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("clientid", field, row->clientid);

		CKPQ_VAL_FLD_num(res, i, enonce1, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("enonce1", field, row->enonce1);

		CKPQ_VAL_FLD_num(res, i, nonce2, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("nonce2", field, row->nonce2);

		CKPQ_VAL_FLD_num(res, i, nonce, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("nonce", field, row->nonce);

		CKPQ_VAL_FLD_num(res, i, reward, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("reward", field, row->reward);

		CKPQ_VAL_FLD_num(res, i, confirmed, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("confirmed", field, row->confirmed);

		CKPQ_VAL_FLD_num(res, i, info, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("info", field, row->info);

		CKPQ_VAL_FLD_num(res, i, diffacc, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffacc", field, row->diffacc);

		CKPQ_VAL_FLD_num(res, i, diffinv, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffinv", field, row->diffinv);

		CKPQ_VAL_FLD_num(res, i, shareacc, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareacc", field, row->shareacc);

		CKPQ_VAL_FLD_num(res, i, shareinv, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareinv", field, row->shareinv);

		CKPQ_VAL_FLD_num(res, i, elapsed, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		CKPQ_VAL_FLD_num(res, i, statsconfirmed, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("statsconfirmed", field, row->statsconfirmed);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(blocks_root, item);
		k_add_head(blocks_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_blocks), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_blocks), &(row->createdate));

		if (dbstatus.newest_height_blocks < row->height)
			dbstatus.newest_height_blocks = row->height;

		if (pool.workinfoid < row->workinfoid) {
			pool.workinfoid = row->workinfoid;
			pool.height = row->height;
		}

		// first add all the NEW blocks
		if (row->confirmed[0] == BLOCKS_NEW)
			userinfo_block(row, INFO_NEW, 1);
	}

	if (!ok)
		k_add_head(blocks_free, item);
	else
		ok = set_blockcreatedate(0);

	// Now update all the CURRENT orphan/reject stats
	if (ok) {
		item = first_in_ktree(blocks_root, ctx);
		while (item) {
			DATA_BLOCKS(row, item);
			if (CURRENT(&(row->expirydate))) {
				if (row->confirmed[0] == BLOCKS_ORPHAN)
					userinfo_block(row, INFO_ORPHAN, 1);
				else if (row->confirmed[0] == BLOCKS_REJECT)
					userinfo_block(row, INFO_REJECT, 1);
			}
			item = next_in_ktree(ctx);
		}
	}

	K_WUNLOCK(blocks_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s blocks records",
			   __func__, pcombuf);
	}

	return ok;
}

// The timing of the memory table updates depends on 'already'
void miningpayouts_add_ram(bool ok, K_ITEM *mp_item, K_ITEM *old_mp_item, tv_t *cd)
{
	MININGPAYOUTS *oldmp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(miningpayouts_free);
	if (!ok) {
		// Cleanup for the calling function
		k_add_head(miningpayouts_free, mp_item);
	} else {
		if (old_mp_item) {
			DATA_MININGPAYOUTS(oldmp, old_mp_item);
			remove_from_ktree(miningpayouts_root, old_mp_item);
			copy_tv(&(oldmp->expirydate), cd);
			add_to_ktree(miningpayouts_root, old_mp_item);
		}
		add_to_ktree(miningpayouts_root, mp_item);
		k_add_head(miningpayouts_store, mp_item);
	}
	K_WUNLOCK(miningpayouts_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool miningpayouts_add(PGconn *conn, bool add, K_ITEM *mp_item,
			K_ITEM **old_mp_item, char *by, char *code, char *inet,
			tv_t *cd, K_TREE *trf_root, bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	MININGPAYOUTS *row, *oldmp = NULL;
	char *upd, *ins;
	char *params[4 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_MININGPAYOUTS(row, mp_item);
	K_RLOCK(miningpayouts_free);
	*old_mp_item = find_miningpayouts(row->payoutid, row->userid);
	K_RUNLOCK(miningpayouts_free);

	if (CKPQConn(&conn))
		conned = true;
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}

	if (*old_mp_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_MININGPAYOUTS(oldmp, *old_mp_item);

		upd = "update miningpayouts set "EDDB"=$1 where payoutid=$2"
			" and userid=$3 and "EDDB"=$4";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldmp->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(oldmp->userid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 4, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINTRANS(row, cd, by, code, inet);
		HISTORYDATETRANSFERIN(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = bigint_to_buf(row->userid, NULL, 0);
		params[par++] = double_to_buf(row->diffacc, NULL, 0);
		params[par++] = bigint_to_buf(row->amount, NULL, 0);
		HISTORYDATEPARAMSIN(params, par, row);
		PARCHK(par, params);

		ins = "insert into miningpayouts "
			"(payoutid,userid,diffacc,amount"
			HISTORYDATECONTROL ") values (" PQPARAM9 ")";

		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		miningpayouts_add_ram(ok, mp_item, *old_mp_item, cd);

	return ok;
}

bool miningpayouts_fill(PGconn *conn)
{
	char tickbuf[256], pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item = NULL;
	MININGPAYOUTS *row;
	int n, t, i;
	char *field = NULL;
	char *sel;
	int fields = 4;
	bool ok = false;

	LOGDEBUG("%s(): select", __func__);

	STRNCPY(tickbuf, TICK_PREFIX"mp 0");
	cr_msg(false, tickbuf);


	int payoutid_num, userid_num, diffacc_num, amount_num;
	HISTORYDATE_num;

	sel = "declare mp cursor for select "
		"payoutid,userid,diffacc,amount"
		HISTORYDATECONTROL
		" from miningpayouts";
	if (!CKPQBegin(conn))
		return false;

	if (exclusive_db) {
		res = CKPQExec(conn, "Lock table miningpayouts in access exclusive mode", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Lock", rescode, conn);
			goto flail;
		}
	}

	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in mp", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	payoutid_num = userid_num = diffacc_num = amount_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(miningpayouts_free);
	while ((t = PQntuples(res)) > 0) {
		for (i = 0; i < t; i++) {
			item = k_unlink_head(miningpayouts_free);
			DATA_MININGPAYOUTS(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, payoutid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("payoutid", field, row->payoutid);

			CKPQ_VAL_FLD_num(res, i, userid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			CKPQ_VAL_FLD_num(res, i, diffacc, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffacc", field, row->diffacc);

			CKPQ_VAL_FLD_num(res, i, amount, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("amount", field, row->amount);

			HISTORYDATEIN(res, i, row, ok);
			if (!ok)
				break;

			add_to_ktree(miningpayouts_root, item);
			k_add_head(miningpayouts_store, item);

			if (n == 0 || ((n+1) % FETCHTICK) == 0) {
				pcom(n+1, pcombuf, sizeof(pcombuf));
				snprintf(tickbuf, sizeof(tickbuf),
					 TICK_PREFIX"mp %s", pcombuf);
				cr_msg(false, tickbuf);
			}
			tick();
			n++;
		}
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in mp", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		payoutid_num = userid_num = diffacc_num = amount_num = CKPQFUNDEF;
		HISTORYDATE_init;
	}
	if (!ok)
		k_add_head(miningpayouts_free, item);

	K_WUNLOCK(miningpayouts_free);
	CKPQClear(res);
flail:

	CKPQCommit(conn);
	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s miningpayout records",
			   __func__, pcombuf);
	}

	return ok;
}

// The timing of the memory table updates depends on 'already'
void payouts_add_ram(bool ok, K_ITEM *p_item, K_ITEM *old_p_item, tv_t *cd)
{
	PAYOUTS *oldp;

	LOGDEBUG("%s(): ok %c", __func__, ok ? 'Y' : 'N');

	K_WLOCK(payouts_free);
	if (!ok) {
		// Cleanup for the calling function
		free_payouts_data(p_item);
		k_add_head(payouts_free, p_item);
	} else {
		if (old_p_item) {
			DATA_PAYOUTS(oldp, old_p_item);
			remove_from_ktree(payouts_root, old_p_item);
			remove_from_ktree(payouts_id_root, old_p_item);
			remove_from_ktree(payouts_wid_root, old_p_item);
			copy_tv(&(oldp->expirydate), cd);
			add_to_ktree(payouts_root, old_p_item);
			add_to_ktree(payouts_id_root, old_p_item);
			add_to_ktree(payouts_wid_root, old_p_item);
		}
		add_to_ktree(payouts_root, p_item);
		add_to_ktree(payouts_id_root, p_item);
		add_to_ktree(payouts_wid_root, p_item);
		k_add_head(payouts_store, p_item);
	}
	K_WUNLOCK(payouts_free);
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * It's the calling functions job to determine if a new one is required
 *  - i.e. if there is a difference between the old and new
 * already = already begun a transaction - and don't update the ram table */
bool payouts_add(PGconn *conn, bool add, K_ITEM *p_item, K_ITEM **old_p_item,
		 char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root,
		 bool already)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	bool ok = false, begun = false;
	PAYOUTS *row, *oldpayouts = NULL;
	char *upd, *ins;
	char *params[13 + HISTORYDATECOUNT];
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	DATA_PAYOUTS(row, p_item);
	K_RLOCK(payouts_free);
	*old_p_item = find_payouts(row->height, row->blockhash);
	K_RUNLOCK(payouts_free);

	if (CKPQConn(&conn))
		conned = true;
	if (!already) {
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;
	}

	if (*old_p_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_PAYOUTS(oldpayouts, *old_p_item);

		upd = "update payouts set "EDDB"=$1 where payoutid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldpayouts->payoutid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;

		// Expiring an old record
		row->payoutid = oldpayouts->payoutid;
	} else {
		if (add) {
			// Creating a new record
			row->payoutid = nextid(conn, "payoutid", (int64_t)1, cd, by, code, inet);
			if (row->payoutid == 0)
				goto rollback;
		}
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		par = 0;
		params[par++] = bigint_to_buf(row->payoutid, NULL, 0);
		params[par++] = int_to_buf(row->height, NULL, 0);
		params[par++] = str_to_buf(row->blockhash, NULL, 0);
		params[par++] = bigint_to_buf(row->minerreward, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidstart, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidend, NULL, 0);
		params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		params[par++] = double_to_buf(row->diffwanted, NULL, 0);
		params[par++] = double_to_buf(row->diffused, NULL, 0);
		params[par++] = double_to_buf(row->shareacc, NULL, 0);
		params[par++] = tv_to_buf(&(row->lastshareacc), NULL, 0);
		params[par++] = str_to_buf(row->stats, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into payouts "
			"(payoutid,height,blockhash,minerreward,workinfoidstart,"
			"workinfoidend,elapsed,status,diffwanted,diffused,shareacc,"
			"lastshareacc,stats"
			HISTORYDATECONTROL ") values (" PQPARAM18 ")";

		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);
unparam:
	for (n = 0; n < par; n++)
		free(params[n]);

	CKPQDisco(&conn, conned);

	if (!already)
		payouts_add_ram(ok, p_item, *old_p_item, cd);

	return ok;
}

/* Expire the entire payout, miningpayouts and payments
 * If it returns false, nothing was changed
 *  and a console message will say why */
K_ITEM *payouts_full_expire(PGconn *conn, int64_t payoutid, tv_t *now, bool lock)
{
	bool locked = false, conned = false, begun = false, ok = false;
	K_TREE_CTX mp_ctx[1], pm_ctx[1];
	K_ITEM *po_item = NULL, *mp_item, *pm_item, *next_item;
	PAYMENTS *payments = NULL;
	MININGPAYOUTS *mp = NULL;
	PAYOUTS *payouts = NULL;
	ExecStatusType rescode;
	PGresult *res;
	char *params[8];
	int n, par = 0;
	char *upd, *tuples = NULL;
	int po_upd = -7, mp_upd = -7, pm_upd = -7;

	// If not already done before calling
	if (lock)
		K_KLONGWLOCK(process_pplns_free);

	// This will be rare so a full lock is best
	K_WLOCK(payouts_free);
	K_WLOCK(miningpayouts_free);
	K_WLOCK(payments_free);
	locked = true;

	po_item = find_payoutid(payoutid);
	if (!po_item) {
		LOGERR("%s(): unknown payoutid %"PRId64, __func__, payoutid);
		goto matane;
	}

	if (CKPQConn(&conn))
		conned = true;
	begun = CKPQBegin(conn);
	if (!begun)
		goto matane;

	upd = "update payouts set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples) {
			po_upd = atoi(tuples);
			if (po_upd != 1) {
				LOGERR("%s() updated payouts should be 1"
					" but updated=%d",
					__func__, po_upd);
				CKPQClear(res);
				goto matane;
			}
		}
	}
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update payouts", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	upd = "update miningpayouts set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples)
			mp_upd = atoi(tuples);
	}
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update miningpayouts", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);

	upd = "update payments set "EDDB"=$1 where payoutid=$2 and "EDDB"=$3";
	par = 0;
	params[par++] = tv_to_buf(now, NULL, 0);
	params[par++] = bigint_to_buf(payoutid, NULL, 0);
	params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
	PARCHKVAL(par, 3, params);

	res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	if (PGOK(rescode)) {
		tuples = PQcmdTuples(res);
		if (tuples && *tuples)
			pm_upd = atoi(tuples);
	}
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Update payments", rescode, conn);
		goto matane;
	}

	for (n = 0; n < par; n++)
		free(params[n]);
	par = 0;

	// Check miningpayouts failure condition
	mp_item = first_miningpayouts(payoutid, mp_ctx);
	if (!mp_item) {
		if (mp_upd != 0) {
			LOGERR("%s() updated miningpayouts should be 0 but"
				" updated=%d",
				__func__, mp_upd);
			goto matane;
		}
	} else {
		int count = 0;
		DATA_MININGPAYOUTS(mp, mp_item);
		while (mp_item && mp->payoutid == payoutid) {
			if (CURRENT(&(mp->expirydate)))
				count++;
			mp_item = next_in_ktree(mp_ctx);
			DATA_MININGPAYOUTS_NULL(mp, mp_item);
		}
		if (count != mp_upd) {
			LOGERR("%s() updated miningpayouts should be %d but"
				" updated=%d",
				__func__, count, mp_upd);
			goto matane;
		}
	}

	/* Check payments failure condition
	 *
	 * This does a full table search since there is no index
	 * This should be so rare that adding an index/tree for it
	 *  would be a waste */
	pm_item = first_in_ktree(payments_root, pm_ctx);
	if (!pm_item) {
		if (pm_upd != 0) {
			LOGERR("%s() updated payments should be 0 but"
				" updated=%d",
				__func__, pm_upd);
			goto matane;
		}
	} else {
		int count = 0;
		DATA_PAYMENTS(payments, pm_item);
		while (pm_item) {
			if (payments->payoutid == payoutid &&
			    CURRENT(&(payments->expirydate))) {
				count++;
			}
			pm_item = next_in_ktree(pm_ctx);
			DATA_PAYMENTS_NULL(payments, pm_item);
		}
		if (count != pm_upd) {
			LOGERR("%s() updated payments should be %d but"
				" updated=%d",
				__func__, count, pm_upd);
			goto matane;
		}
	}

	// No more possible errors, so update the ram tables
	DATA_PAYOUTS(payouts, po_item);
	remove_from_ktree(payouts_root, po_item);
	remove_from_ktree(payouts_id_root, po_item);
	remove_from_ktree(payouts_wid_root, po_item);
	copy_tv(&(payouts->expirydate), now);
	add_to_ktree(payouts_root, po_item);
	add_to_ktree(payouts_id_root, po_item);
	add_to_ktree(payouts_wid_root, po_item);

	mp_item = first_miningpayouts(payoutid, mp_ctx);
	DATA_MININGPAYOUTS_NULL(mp, mp_item);
	while (mp_item && mp->payoutid == payoutid) {
		if (CURRENT(&(mp->expirydate))) {
			next_item = next_in_ktree(mp_ctx);
			remove_from_ktree(miningpayouts_root, mp_item);
			copy_tv(&(mp->expirydate), now);
			add_to_ktree(miningpayouts_root, mp_item);
			mp_item = next_item;
		} else
			mp_item = next_in_ktree(mp_ctx);

		DATA_MININGPAYOUTS_NULL(mp, mp_item);
	}

	pm_item = first_in_ktree(payments_root, pm_ctx);
	DATA_PAYMENTS_NULL(payments, pm_item);
	while (pm_item) {
		if (payments->payoutid == payoutid &&
		    CURRENT(&(payments->expirydate))) {
			next_item = next_in_ktree(pm_ctx);
			remove_from_ktree(payments_root, pm_item);
			copy_tv(&(payments->expirydate), now);
			add_to_ktree(payments_root, pm_item);
			pm_item = next_item;
		} else
			pm_item = next_in_ktree(pm_ctx);

		DATA_PAYMENTS_NULL(payments, pm_item);
	}

	if (PAYGENERATED(payouts->status)) {
		// Original was generated, so undo the reward
		reward_shifts(payouts, -1);

	}

	ok = true;
matane:
	if (begun)
		CKPQEnd(conn, ok);

	if (locked) {
		K_WUNLOCK(payments_free);
		K_WUNLOCK(miningpayouts_free);
		K_WUNLOCK(payouts_free);
	}

	CKPQDisco(&conn, conned);

	if (lock)
		K_WUNLOCK(process_pplns_free);

	for (n = 0; n < par; n++)
		free(params[n]);

	if (ok)
		return po_item;
	else
		return NULL;
}

bool payouts_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item, *b_item;
	K_TREE_CTX ctx[1];
	PAYOUTS *row;
	BLOCKS *blocks;
	int n, i;
	char *field = NULL;
	char *sel;
	int fields = 13;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int payoutid_num, height_num, blockhash_num, minerreward_num;
	int workinfoidstart_num, workinfoidend_num, elapsed_num, status_num;
	int diffwanted_num, diffused_num, shareacc_num, lastshareacc_num;
	int stats_num;
	HISTORYDATE_num;

	sel = "select "
		"payoutid,height,blockhash,minerreward,workinfoidstart,workinfoidend,"
		"elapsed,status,diffwanted,diffused,shareacc,lastshareacc,stats"
		HISTORYDATECONTROL
		" from payouts";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	payoutid_num = height_num = blockhash_num = minerreward_num =
	workinfoidstart_num = workinfoidend_num = elapsed_num = status_num =
	diffwanted_num = diffused_num = shareacc_num = lastshareacc_num =
	stats_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(payouts_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(payouts_free);
		DATA_PAYOUTS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, payoutid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("payoutid", field, row->payoutid);

		CKPQ_VAL_FLD_num(res, i, height, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("height", field, row->height);

		CKPQ_VAL_FLD_num(res, i, blockhash, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("blockhash", field, row->blockhash);

		CKPQ_VAL_FLD_num(res, i, minerreward, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("minerreward", field, row->minerreward);

		CKPQ_VAL_FLD_num(res, i, workinfoidstart, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidstart", field, row->workinfoidstart);

		CKPQ_VAL_FLD_num(res, i, workinfoidend, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidend", field, row->workinfoidend);

		CKPQ_VAL_FLD_num(res, i, elapsed, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		CKPQ_VAL_FLD_num(res, i, status, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		CKPQ_VAL_FLD_num(res, i, diffwanted, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffwanted", field, row->diffwanted);

		CKPQ_VAL_FLD_num(res, i, diffused, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("diffused", field, row->diffused);

		CKPQ_VAL_FLD_num(res, i, shareacc, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("shareacc", field, row->shareacc);

		CKPQ_VAL_FLD_num(res, i, lastshareacc, field, ok);
		if (!ok)
			break;
		TXT_TO_TVDB("lastshareacc", field, row->lastshareacc);

		CKPQ_VAL_FLD_num(res, i, stats, field, ok);
		if (!ok)
			break;
		TXT_TO_BLOB("stats", field, row->stats);
		LIST_MEM_ADD(payouts_free, row->stats);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		// This also of course, verifies the payouts -> blocks reference
		K_RLOCK(blocks_free);
		b_item = find_blocks(row->height, row->blockhash, ctx);
		K_RUNLOCK(blocks_free);
		if (!b_item) {
			LOGERR("%s(): payoutid %"PRId64" references unknown "
				"block %"PRId32"/%s",
				__func__, row->payoutid, row->height,
				row->blockhash);
			ok = false;
			break;
		} else {
			// blockcreatedate will already be set
			DATA_BLOCKS(blocks, b_item);
			copy_tv(&(row->blockcreatedate),
				&(blocks->blockcreatedate));
		}

		add_to_ktree(payouts_root, item);
		add_to_ktree(payouts_id_root, item);
		add_to_ktree(payouts_wid_root, item);
		k_add_head(payouts_store, item);

		if (CURRENT(&(row->expirydate)) && PAYGENERATED(row->status))
			reward_shifts(row, 1);

		tick();
	}
	if (!ok) {
		free_payouts_data(item);
		k_add_head(payouts_free, item);
	}

	K_WUNLOCK(payouts_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s payout records",
			   __func__, pcombuf);
	}

	return ok;
}

// trf_root overrides by,inet,cd fields
int _events_add(int id, char *by, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM look, *e_item, *i_passwordhash, *i_webtime, *i_username;
	K_TREE_CTX ctx[1];
	EVENTS events, *d_events;
	char reply[1024] = "";
	size_t siz = sizeof(reply);

	LOGDEBUG("%s(): add", __func__);

	if (e_limits[id].enabled == false)
		return EVENT_OK;

	bzero(&events, sizeof(events));
	events.id = id;
	events.expirydate.tv_sec = default_expiry.tv_sec;
	events.expirydate.tv_usec = default_expiry.tv_usec;

	// Default to now if not specified
	setnow(&(events.createdate));

	if (by)
		STRNCPY(events.createby, by);

	if (inet)
		STRNCPY(events.createinet, inet);

	if (cd)
		copy_tv(&(events.createdate), cd);

	// trf_root values overrides parameters
	HISTORYDATETRANSFER(trf_root, &events);

	// username overrides createby
	i_username = optional_name(trf_root, "username", 1, NULL,
					reply, siz);
	if (i_username)
		STRNCPY(events.createby, transfer_data(i_username));

	// webtime overrides
	i_webtime = optional_name(trf_root, "webtime", 1, NULL,
					reply, siz);
	if (i_webtime) {
		TXT_TO_CTV("webtime", transfer_data(i_webtime),
			  events.createdate);
	}

	/* We don't care if it's valid or not, though php should have
	 *  already ensured it's valid */
	i_passwordhash = optional_name(trf_root, "passwordhash", 1, NULL,
					reply, siz);
	if (i_passwordhash)
		STRNCPY(events.hash, transfer_data(i_passwordhash));

	if (events.createinet[0]) {
		char *dot;
		STRNCPY(events.ipc, events.createinet);
		dot = strchr(events.ipc, '.');
		if (dot) {
			dot = strchr(dot+1, '.');
			if (dot) {
				dot = strchr(dot+1, '.');
				if (dot)
					*(dot+1) = '\0';
			}
		}
	}

	// Only store an event that had actual usable data
	if (!events.createby[0] && !events.createinet[0] &&
	    !events.ipc[0] && !events.hash[0])
		return EVENT_OK;

	INIT_EVENTS(&look);
	look.data = (void *)(&events);

	// All processing under lock - since we must be able to delete events
	K_WLOCK(events_free);
	// keep looping incrementing the usec time until it's not a duplicate
	while (find_in_ktree(events_user_root, &look, ctx) ||
	       find_in_ktree(events_ip_root, &look, ctx) ||
	       find_in_ktree(events_ipc_root, &look, ctx) ||
	       find_in_ktree(events_hash_root, &look, ctx)) {
		if (++events.createdate.tv_usec >= 1000000) {
			events.createdate.tv_usec -= 1000000;
			events.createdate.tv_sec++;
		}
	}
	e_item = k_unlink_head(events_free);
	DATA_EVENTS(d_events, e_item);
	COPY_DATA(d_events, &events);
	k_add_head(events_store, e_item);
	if (d_events->createby[0]) {
		add_to_ktree(events_user_root, e_item);
		d_events->trees++;
	}
	if (d_events->createinet[0]) {
		add_to_ktree(events_ip_root, e_item);
		d_events->trees++;
	}
	// Don't bother if it's the same as IP
	if (d_events->ipc[0] &&
	    strcmp(d_events->ipc, d_events->createinet) != 0) {
		add_to_ktree(events_ipc_root, e_item);
		d_events->trees++;
	}
	if (d_events->hash[0]) {
		add_to_ktree(events_hash_root, e_item);
		d_events->trees++;
	}
	K_WUNLOCK(events_free);

	return check_events(&events);
}

// trf_root overrides by,inet,cd fields
int _ovents_add(int id, char *by, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *o_item, *i_webtime, *i_username;
	OVENTS ovents, *d_ovents;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char u_key[TXT_SML+1], i_key[TXT_SML+1], c_key[TXT_SML+1];
	int hour, min;
	bool gotc;

	LOGDEBUG("%s(): add", __func__);

	if (o_limits[id].enabled == false)
		return EVENT_OK;

	bzero(&ovents, sizeof(ovents));

	// Default to now if not specified
	setnow(&(ovents.createdate));

	if (by)
		STRNCPY(ovents.createby, by);

	if (inet)
		STRNCPY(ovents.createinet, inet);

	if (cd)
		copy_tv(&(ovents.createdate), cd);

	// trf_root values overrides parameters
	HISTORYDATETRANSFER(trf_root, &ovents);

	// username overrides createby
	i_username = optional_name(trf_root, "username", 1, NULL,
					reply, siz);
	if (i_username)
		STRNCPY(ovents.createby, transfer_data(i_username));

	// webtime overrides
	i_webtime = optional_name(trf_root, "webtime", 1, NULL,
					reply, siz);
	if (i_webtime) {
		TXT_TO_CTV("webtime", transfer_data(i_webtime),
			  ovents.createdate);
	}

	STRNCPY(u_key, ovents.createby);
	STRNCPY(i_key, ovents.createinet);
	gotc = false;
	if (i_key[0]) {
		char *dot;
		STRNCPY(c_key, i_key);
		dot = strchr(c_key, '.');
		if (dot) {
			dot = strchr(dot+1, '.');
			if (dot) {
				dot = strchr(dot+1, '.');
				if (dot) {
					*(dot+1) = '\0';
					gotc = true;
				}
			}
		}
	}
	if (!gotc)
		c_key[0] = '\0';

	if (!u_key[0] && !i_key[0] && !c_key[0])
		return OVENT_OK;

	hour = TV_TO_HOUR(&(ovents.createdate));
	min = TV_TO_MIN(&(ovents.createdate));

	K_WLOCK(ovents_free);
	if (u_key[0] && strcmp(u_key, ANON_USER) != 0) {
		o_item = find_ovents(u_key, hour, NULL);
		if (o_item) {
			DATA_OVENTS(d_ovents, o_item);
			d_ovents->count[IDMIN(id, min)]++;
		} else {
			o_item = k_unlink_head(ovents_free);
			DATA_OVENTS(d_ovents, o_item);
			bzero(d_ovents, sizeof(*d_ovents));
			STRNCPY(d_ovents->key, u_key);
			d_ovents->hour = hour;
			d_ovents->count[IDMIN(id, min)]++;
			copy_tv(&(d_ovents->createdate), &(ovents.createdate));
			STRNCPY(d_ovents->createby, ovents.createby);
			STRNCPY(d_ovents->createinet, ovents.createinet);
			copy_tv(&(d_ovents->expirydate), &default_expiry);
			k_add_head(ovents_store, o_item);
			add_to_ktree(ovents_root, o_item);
		}
	}

	if (i_key[0]) {
		o_item = find_ovents(i_key, hour, NULL);
		if (o_item) {
			DATA_OVENTS(d_ovents, o_item);
			d_ovents->count[IDMIN(id, min)]++;
		} else {
			o_item = k_unlink_head(ovents_free);
			DATA_OVENTS(d_ovents, o_item);
			bzero(d_ovents, sizeof(*d_ovents));
			STRNCPY(d_ovents->key, i_key);
			d_ovents->hour = hour;
			d_ovents->count[IDMIN(id, min)]++;
			copy_tv(&(d_ovents->createdate), &(ovents.createdate));
			STRNCPY(d_ovents->createby, ovents.createby);
			STRNCPY(d_ovents->createinet, ovents.createinet);
			copy_tv(&(d_ovents->expirydate), &default_expiry);
			k_add_head(ovents_store, o_item);
			add_to_ktree(ovents_root, o_item);
		}
	}

	if (c_key[0]) {
		o_item = find_ovents(c_key, hour, NULL);
		if (o_item) {
			DATA_OVENTS(d_ovents, o_item);
			d_ovents->count[IDMIN(id, min)]++;
		} else {
			o_item = k_unlink_head(ovents_free);
			DATA_OVENTS(d_ovents, o_item);
			bzero(d_ovents, sizeof(*d_ovents));
			STRNCPY(d_ovents->key, c_key);
			d_ovents->hour = hour;
			d_ovents->count[IDMIN(id, min)]++;
			copy_tv(&(d_ovents->createdate), &(ovents.createdate));
			STRNCPY(d_ovents->createby, ovents.createby);
			STRNCPY(d_ovents->createinet, ovents.createinet);
			copy_tv(&(d_ovents->expirydate), &default_expiry);
			k_add_head(ovents_store, o_item);
			add_to_ktree(ovents_root, o_item);
		}
	}
	K_WUNLOCK(ovents_free);

	return check_ovents(id, u_key, i_key, c_key, &(ovents.createdate));
}

void ips_add(char *group, char *ip, char *eventname, bool is_event, char *des,
		bool log, bool cclass, int life, bool locked)
{
	K_ITEM *i_item, *i2_item;
	IPS *ips, *ips2;
	char *dot;
	tv_t now;
	bool ok;

	if (is_event) {
		if (!is_elimitname(eventname, true)) {
			LOGERR("%s() invalid Event name '%s' - ignored",
				__func__, eventname);
			return;
		}
	} else {
		if (!is_olimitname(eventname, true)) {
			LOGERR("%s() invalid Ovent name '%s' - ignored",
				__func__, eventname);
			return;
		}
	}

	setnow(&now);
	if (!locked)
		K_WLOCK(ips_free);
	i_item = k_unlink_head(ips_free);
	DATA_IPS(ips, i_item);
	STRNCPY(ips->group, group);
	STRNCPY(ips->ip, ip);
	STRNCPY(ips->eventname, eventname);
	ips->is_event = is_event;
	if (!des)
		ips->description = NULL;
	else {
		ips->description = strdup(des);
		if (!ips->description)
			quithere(1, "strdup OOM");
		LIST_MEM_ADD(ips_free, ips->description);
	}
	ips->log = log;
	ips->lifetime = life;
	HISTORYDATEDEFAULT(ips, &now);
	add_to_ktree(ips_root, i_item);
	k_add_head(ips_store, i_item);
	if (cclass) {
		i2_item = k_unlink_head(ips_free);
		DATA_IPS(ips2, i2_item);
		memcpy(ips2, ips, sizeof(*ips2));
		ok = false;
		dot = strchr(ips->ip, '.');
		if (dot) {
			dot = strchr(dot+1, '.');
			if (dot) {
				dot = strchr(dot+1, '.');
				if (dot) {
					*(dot+1) = '\0';
					ok = true;
				}
			}
		}
		if (ok) {
			if (!des)
				ips2->description = NULL;
			else {
				ips2->description = strdup(des);
				LIST_MEM_ADD(ips_free, ips2->description);
			}
			add_to_ktree(ips_root, i2_item);
			k_add_head(ips_store, i2_item);
		} else
			k_add_head(ips_free, i2_item);
	}
	if (!locked)
		K_WUNLOCK(ips_free);
}

// TODO: discard them from RAM
bool auths_add(PGconn *conn, INTRANSIENT *in_poolinstance,
		INTRANSIENT *in_username, INTRANSIENT *in_workername,
		char *clientid, char *enonce1, char *useragent, char *preauth,
		char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root,
		bool addressuser, USERS **users, WORKERS **workers,
		int *event, bool reload_data)
{
	K_TREE_CTX ctx[1];
	K_ITEM *a_item, *u_item, *w_item;
	char cd_buf[DATE_BUFSIZ];
	AUTHS *row;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(auths_free);
	a_item = k_unlink_head(auths_free);
	K_WUNLOCK(auths_free);

	DATA_AUTHS(row, a_item);
	bzero(row, sizeof(*row));

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item) {
		if (addressuser) {
			u_item = users_add(conn, in_username, EMPTY, EMPTY,
					   NULL, USER_ADDRESS, by, code, inet,
					   cd, trf_root);
		} else {
			LOGDEBUG("%s(): unknown user '%s'",
				 __func__,
				 st = safe_text_nonull(in_username->str));
			FREENULL(st);
			if (!reload_data)
				*event = events_add(EVENTID_INVAUTH, trf_root);
		}
		if (!u_item)
			goto unitem;
	}
	DATA_USERS(*users, u_item);

	// Any status content means disallow mining
	if ((*users)->status[0])
		goto unitem;

	row->in_poolinstance = in_poolinstance->str;
	row->userid = (*users)->userid;
	// since update=false, a dup will be ok and do nothing when igndup=true
	w_item = new_worker(conn, false, row->userid, in_workername->str,
			    DIFFICULTYDEFAULT_DEF_STR,
			    IDLENOTIFICATIONENABLED_DEF,
			    IDLENOTIFICATIONTIME_DEF_STR,
			    by, code, inet, cd, trf_root);
	if (!w_item)
		goto unitem;

	DATA_WORKERS(*workers, w_item);
	row->in_workername = in_workername->str;
	TXT_TO_INT("clientid", clientid, row->clientid);
	STRNCPY(row->enonce1, enonce1);
	STRNCPY(row->useragent, useragent);
	STRNCPY(row->preauth, preauth);

	HISTORYDATEINIT(row, cd, by, code, inet);
	HISTORYDATETRANSFER(trf_root, row);

	K_WLOCK(auths_free);
	if (find_in_ktree(auths_root, a_item, ctx)) {
		k_add_head(auths_free, a_item);
		K_WUNLOCK(auths_free);

		// Shouldn't actually be possible unless twice in the logs
		tv_to_buf(cd, cd_buf, sizeof(cd_buf));
		LOGERR("%s(): Duplicate auths ignored %s/%s/%s",
			__func__, in_poolinstance->str,
			st = safe_text_nonull(in_workername->str), cd_buf);
		FREENULL(st);

		/* Let them mine, that's what matters :)
		 *  though this would normally only be during a reload */
		return true;
	}
	K_WUNLOCK(auths_free);

	// Update even if DB fails
	workerstatus_update(row, NULL, NULL);

	row->authid = 1;

	ok = true;
unitem:
	K_WLOCK(auths_free);
#if 1
	/* To save ram for now, don't store them,
	 * we don't actually use them anywhere yet */
	k_add_head(auths_free, a_item);
#else
	if (!ok)
		k_add_head(auths_free, a_item);
	else {
		add_to_ktree(auths_root, a_item);
		k_add_head(auths_store, a_item);
	}
#endif
	K_WUNLOCK(auths_free);

	return ok;
}

bool poolstats_add(PGconn *conn, bool store, INTRANSIENT *in_poolinstance,
			char *elapsed, char *users, char *workers,
			char *hashrate, char *hashrate5m,
			char *hashrate1hr, char *hashrate24hr,
			char *by, char *code, char *inet, tv_t *cd,
			bool igndup, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	K_TREE_CTX ctx[1];
	K_ITEM *p_item;
	POOLSTATS *row;
	char *ins;
	char *params[8 + SIMPLEDATECOUNT];
	int n, par = 0;
	bool ok = false;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(poolstats_free);
	p_item = k_unlink_head(poolstats_free);
	K_WUNLOCK(poolstats_free);

	DATA_POOLSTATS(row, p_item);
	bzero(row, sizeof(*row));

	row->stored = false;

	row->in_poolinstance = in_poolinstance->str;
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	TXT_TO_INT("users", users, row->users);
	TXT_TO_INT("workers", workers, row->workers);
	TXT_TO_DOUBLE("hashrate", hashrate, row->hashrate);
	TXT_TO_DOUBLE("hashrate5m", hashrate5m, row->hashrate5m);
	TXT_TO_DOUBLE("hashrate1hr", hashrate1hr, row->hashrate1hr);
	TXT_TO_DOUBLE("hashrate24hr", hashrate24hr, row->hashrate24hr);

	SIMPLEDATEINIT(row, cd, by, code, inet);
	SIMPLEDATETRANSFER(trf_root, row);

	K_WLOCK(poolstats_free);
	if (igndup && find_in_ktree(poolstats_root, p_item, ctx)) {
		k_add_head(poolstats_free, p_item);
		K_WUNLOCK(poolstats_free);
		return true;
	}
	K_WUNLOCK(poolstats_free);

	if (store) {
		par = 0;
		params[par++] = str_to_buf(row->in_poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(row->elapsed, NULL, 0);
		params[par++] = int_to_buf(row->users, NULL, 0);
		params[par++] = int_to_buf(row->workers, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate5m, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate1hr, NULL, 0);
		params[par++] = bigint_to_buf(row->hashrate24hr, NULL, 0);
		SIMPLEDATEPARAMS(params, par, row);
		PARCHK(par, params);

		ins = "insert into poolstats "
			"(poolinstance,elapsed,users,workers,hashrate,"
			"hashrate5m,hashrate1hr,hashrate24hr"
			SIMPLEDATECONTROL ") values (" PQPARAM12 ")";

		if (CKPQConn(&conn))
			conned = true;
		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			bool show_msg = true;
			char *code;
			if (igndup) {
				code = PQresultErrorField(res, PG_DIAG_SQLSTATE);
				if (code && strcmp(code, SQL_UNIQUE_VIOLATION) == 0)
					show_msg = false;
			}
			if (show_msg)
				PGLOGERR("Insert", rescode, conn);
			goto unparam;
		}

		row->stored = true;
	}

	ok = true;
unparam:
	if (store) {
		CKPQClear(res);
		CKPQDisco(&conn, conned);
		for (n = 0; n < par; n++)
			free(params[n]);
	}

	K_WLOCK(poolstats_free);
	if (!ok)
		k_add_head(poolstats_free, p_item);
	else {
		add_to_ktree(poolstats_root, p_item);
		k_add_head(poolstats_store, p_item);
	}
	K_WUNLOCK(poolstats_free);

	return ok;
}

// TODO: data selection - only require ?
bool poolstats_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	struct tm tm;
	time_t now_t;
	char tzinfo[16], stamp[128];
	POOLSTATS *row;
	char *field = NULL;
	char *sel = NULL;
	size_t len, off;
	int fields = 8;
	long minoff, hroff;
	char tzch;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	// Temoprarily ... load last 24hrs worth
	now_t = time(NULL);
	now_t -= 24 * 60 * 60;
	localtime_r(&now_t, &tm);
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
			"'%d-%02d-%02d %02d:%02d:%02d%s'",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			tzinfo);

	int poolinstance_num, elapsed_num, users_num, workers_num, hashrate_num;
	int hashrate5m_num, hashrate1hr_num, hashrate24hr_num;
	SIMPLEDATE_num;

	APPEND_REALLOC_INIT(sel, off, len);
	APPEND_REALLOC(sel, off, len,
			"select "
			"poolinstance,elapsed,users,workers,hashrate,"
			"hashrate5m,hashrate1hr,hashrate24hr"
			SIMPLEDATECONTROL
			" from poolstats where "CDDB">");
	APPEND_REALLOC(sel, off, len, stamp);

	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		ok = false;
		goto clean;
	}

	n = PQnfields(res);
	if (n != (fields + SIMPLEDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + SIMPLEDATECOUNT, n);
		CKPQClear(res);
		ok = false;
		goto clean;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	poolinstance_num = elapsed_num = users_num = workers_num =
	hashrate_num = hashrate5m_num = hashrate1hr_num =
	hashrate24hr_num = CKPQFUNDEF;
	SIMPLEDATE_init;
	K_WLOCK(poolstats_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(poolstats_free);
		DATA_POOLSTATS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		row->stored = true;

		CKPQ_VAL_FLD_num(res, i, poolinstance, field, ok);
		if (!ok)
			break;
		if (sys_poolinstance && strcmp(field, sys_poolinstance)) {
			k_add_head(poolstats_free, item);
			POOLINSTANCE_DBLOAD_SET(poolstats, field);
			continue;
		}
		row->in_poolinstance = intransient_str("poolinstance", field);

		CKPQ_VAL_FLD_num(res, i, elapsed, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("elapsed", field, row->elapsed);

		CKPQ_VAL_FLD_num(res, i, users, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("users", field, row->users);

		CKPQ_VAL_FLD_num(res, i, workers, field, ok);
		if (!ok)
			break;
		TXT_TO_INT("workers", field, row->workers);

		CKPQ_VAL_FLD_num(res, i, hashrate, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate", field, row->hashrate);

		CKPQ_VAL_FLD_num(res, i, hashrate5m, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate5m", field, row->hashrate5m);

		CKPQ_VAL_FLD_num(res, i, hashrate1hr, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate1hr", field, row->hashrate1hr);

		CKPQ_VAL_FLD_num(res, i, hashrate24hr, field, ok);
		if (!ok)
			break;
		TXT_TO_DOUBLE("hashrate24hr", field, row->hashrate24hr);

		SIMPLEDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(poolstats_root, item);
		k_add_head(poolstats_store, item);

		if (tv_newer(&(dbstatus.newest_createdate_poolstats), &(row->createdate)))
			copy_tv(&(dbstatus.newest_createdate_poolstats), &(row->createdate));

		tick();
	}
	if (!ok)
		k_add_head(poolstats_free, item);

	K_WUNLOCK(poolstats_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s poolstats records",
			   __func__, pcombuf);
	}
clean:
	free(sel);
	POOLINSTANCE_DBLOAD_MSG(poolstats);
	return ok;
}

// To RAM
bool userstats_add(INTRANSIENT *in_poolinstance, char *elapsed, char *username,
		   INTRANSIENT *in_workername, char *hashrate, char *hashrate5m,
		   char *hashrate1hr, char *hashrate24hr, bool idle, bool eos,
		   char *by, char *code, char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *us_item, *u_item, *us_match, *us_next;
	USERSTATS *row, *match, *next;
	USERS *users;
	K_TREE_CTX ctx[1];
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(userstats_free);
	us_item = k_unlink_head(userstats_free);
	K_WUNLOCK(userstats_free);

	DATA_USERSTATS(row, us_item);
	bzero(row, sizeof(*row));

	row->in_poolinstance = in_poolinstance->str;
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		LOGERR("%s(): unknown user '%s'",
			__func__,
			st = safe_text_nonull(username));
		FREENULL(st);
		return false;
	}
	DATA_USERS(users, u_item);
	row->userid = users->userid;
	row->in_workername = in_workername->str;
	TXT_TO_DOUBLE("hashrate", hashrate, row->hashrate);
	TXT_TO_DOUBLE("hashrate5m", hashrate5m, row->hashrate5m);
	TXT_TO_DOUBLE("hashrate1hr", hashrate1hr, row->hashrate1hr);
	TXT_TO_DOUBLE("hashrate24hr", hashrate24hr, row->hashrate24hr);
	row->idle = idle;
	row->instances = NO_INSTANCE_DATA;
	row->summarylevel[0] = SUMMARY_NONE;
	row->summarylevel[1] = '\0';
	row->summarycount = 1;
	SIMPLEDATEINIT(row, cd, by, code, inet);
	SIMPLEDATETRANSFER(trf_root, row);
	copy_tv(&(row->statsdate), &(row->createdate));

	workerstatus_update(NULL, NULL, row);

	/* group at: userid,workername */
	K_WLOCK(userstats_free);
	us_match = STORE_WHEAD(userstats_eos_store);
	while (us_match && cmp_userstats(us_item, us_match) != 0.0)
		us_match = us_match->next;

	if (us_match) {
		DATA_USERSTATS(match, us_match);
		match->hashrate += row->hashrate;
		match->hashrate5m += row->hashrate5m;
		match->hashrate1hr += row->hashrate1hr;
		match->hashrate24hr += row->hashrate24hr;
		// Minimum elapsed of the data set
		if (match->elapsed > row->elapsed)
			match->elapsed = row->elapsed;
		// Unused
		k_add_head(userstats_free, us_item);
	} else {
		// New user+worker
		k_add_head(userstats_eos_store, us_item);
	}
	K_WUNLOCK(userstats_free);

	if (eos) {
		K_WLOCK(userstats_free);
		us_next = STORE_WHEAD(userstats_eos_store);
		while (us_next) {
			us_item = find_in_ktree(userstats_root, us_next, ctx);
			if (!us_item) {
				// New user+worker - store it in RAM
				us_match = us_next;
				us_next = us_match->next;
				k_unlink_item(userstats_eos_store, us_match);
				add_to_ktree(userstats_root, us_match);
				k_add_head(userstats_store, us_match);
			} else {
				DATA_USERSTATS(next, us_next);
				// Old user+worker - update RAM if us_item is newer
				DATA_USERSTATS(row, us_item);
				if (tv_newer(&(next->createdate), &(row->createdate))) {
					// the tree index data is the same
					memcpy(next, row, sizeof(*row));
				}
				us_next = us_next->next;
			}
		}
		// Discard them
		if (userstats_eos_store->count > 0)
			k_list_transfer_to_head(userstats_eos_store, userstats_free);
		K_WUNLOCK(userstats_free);
	}

	return true;
}

// To RAM
bool workerstats_add(INTRANSIENT *in_poolinstance, char *elapsed, char *username,
			INTRANSIENT *in_workername, char *hashrate,
			char *hashrate5m, char *hashrate1hr, char *hashrate24hr,
			bool idle, char *instances, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *us_item, *u_item, *us_match;
	USERSTATS *row, *match;
	USERS *users;
	K_TREE_CTX ctx[1];

	LOGDEBUG("%s(): add", __func__);

	K_WLOCK(userstats_free);
	us_item = k_unlink_head(userstats_free);
	K_WUNLOCK(userstats_free);

	DATA_USERSTATS(row, us_item);
	bzero(row, sizeof(*row));

	row->in_poolinstance = in_poolinstance->str;
	TXT_TO_BIGINT("elapsed", elapsed, row->elapsed);
	K_RLOCK(users_free);
	u_item = find_users(username);
	K_RUNLOCK(users_free);
	if (!u_item) {
		char *usr = NULL, *wrk = NULL;
		LOGERR("%s(): unknown user '%s' (worker=%s)",
			__func__,
			usr = safe_text_nonull(username),
			wrk = safe_text_nonull(in_workername->str));
		FREENULL(usr);
		FREENULL(wrk);
		return false;
	}
	DATA_USERS(users, u_item);
	row->userid = users->userid;
	row->in_workername = in_workername->str;
	TXT_TO_DOUBLE("hashrate", hashrate, row->hashrate);
	TXT_TO_DOUBLE("hashrate5m", hashrate5m, row->hashrate5m);
	TXT_TO_DOUBLE("hashrate1hr", hashrate1hr, row->hashrate1hr);
	TXT_TO_DOUBLE("hashrate24hr", hashrate24hr, row->hashrate24hr);
	row->idle = idle;
	if (instances)
		TXT_TO_INT("instances", instances, row->instances);
	else
		row->instances = NO_INSTANCE_DATA;
	row->summarylevel[0] = SUMMARY_NONE;
	row->summarylevel[1] = '\0';
	row->summarycount = 1;
	SIMPLEDATEINIT(row, cd, by, code, inet);
	SIMPLEDATETRANSFER(trf_root, row);
	copy_tv(&(row->statsdate), &(row->createdate));

	workerstatus_update(NULL, NULL, row);

	K_WLOCK(userstats_free);
	us_match = find_in_ktree(userstats_root, us_item, ctx);
	if (!us_match) {
		// New user+worker - store it in RAM
		add_to_ktree(userstats_root, us_item);
		k_add_head(userstats_store, us_item);
	} else {
		DATA_USERSTATS(match, us_match);
		// Old user+worker - update RAM if us_item is newer
		if (tv_newer(&(match->createdate), &(row->createdate))) {
			// the tree index data is the same
			memcpy(match, row, sizeof(*row));
		}
		k_add_head(userstats_free, us_item);
	}
	K_WUNLOCK(userstats_free);

	return true;
}

bool markersummary_add(PGconn *conn, K_ITEM *ms_item, char *by, char *code,
			char *inet, tv_t *cd, K_TREE *trf_root)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	MARKERSUMMARY *row;
	char *params[20 + MODIFYDATECOUNT];
	int n, par = 0;
	char *ins;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	DATA_MARKERSUMMARY(row, ms_item);

	MODIFYDATEINTRANS(row, cd, by, code, inet);
	MODIFYDATETRANSFERIN(trf_root, row);

	par = 0;
	params[par++] = bigint_to_buf(row->markerid, NULL, 0);
	params[par++] = bigint_to_buf(row->userid, NULL, 0);
	params[par++] = str_to_buf(row->in_workername, NULL, 0);
	params[par++] = double_to_buf(row->diffacc, NULL, 0);
	params[par++] = double_to_buf(row->diffsta, NULL, 0);
	params[par++] = double_to_buf(row->diffdup, NULL, 0);
	params[par++] = double_to_buf(row->diffhi, NULL, 0);
	params[par++] = double_to_buf(row->diffrej, NULL, 0);
	params[par++] = double_to_buf(row->shareacc, NULL, 0);
	params[par++] = double_to_buf(row->sharesta, NULL, 0);
	params[par++] = double_to_buf(row->sharedup, NULL, 0);
	params[par++] = double_to_buf(row->sharehi, NULL, 0);
	params[par++] = double_to_buf(row->sharerej, NULL, 0);
	params[par++] = bigint_to_buf(row->sharecount, NULL, 0);
	params[par++] = bigint_to_buf(row->errorcount, NULL, 0);
	params[par++] = tv_to_buf(&(row->firstshare), NULL, 0);
	params[par++] = tv_to_buf(&(row->lastshare), NULL, 0);
	params[par++] = tv_to_buf(&(row->firstshareacc), NULL, 0);
	params[par++] = tv_to_buf(&(row->lastshareacc), NULL, 0);
	params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
	MODIFYDATEPARAMSIN(params, par, row);
	PARCHK(par, params);

	ins = "insert into markersummary "
		"(markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,firstshareacc,"
		"lastshareacc,lastdiffacc"
		MODIFYDATECONTROL ") values (" PQPARAM28 ")";

	LOGDEBUG("%s() adding ms %"PRId64"/%"PRId64"/%s/%.0f",
		 __func__, row->markerid, row->userid,
		 st = safe_text_nonull(row->in_workername),
		 row->diffacc);
	FREENULL(st);

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		goto unparam;
	}

	ok = true;
unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	// caller must do tree/list/store changes

	return ok;
}

bool markersummary_fill(PGconn *conn)
{
	char tickbuf[256], pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item = NULL, *p_item, *wm_item = NULL;
	K_TREE_CTX ctx[1];
	char cd_buf[DATE_BUFSIZ];
	char *cd = NULL, *what = NULL;
	int n, t, i, p_n;
	MARKERSUMMARY *row, *p_row;
	WORKMARKERS *workmarkers;
	char *params[1];
	char *field = NULL;
	char *sel;
	int fields = 20, par = 0;
	int64_t ms = 0, amt = 0;
	bool ok = false;
	tv_t old;

	LOGDEBUG("%s(): select", __func__);

	if (mark_start < 0)
		mark_start = 0;
	else {
		amt = ms = mark_start;
		switch (mark_start_type) {
			case 'D': // mark_start days
				setnow(&old);
				old.tv_sec -= 60 * 60 * 24 * ms;
				K_RLOCK(workmarkers_free);
				wm_item = last_in_ktree(workmarkers_root, ctx);
				while (wm_item) {
					// Newest processed workmarker <= old
					DATA_WORKMARKERS(workmarkers, wm_item);
					if (CURRENT(&(workmarkers->expirydate)) &&
					    WMPROCESSED(workmarkers->status) &&
					    !tv_newer(&old, &(workmarkers->createdate)))
						break;
					wm_item = prev_in_ktree(ctx);
				}
				if (!wm_item)
					mark_start = 0;
				else {
					mark_start = workmarkers->markerid;
					tv_to_buf(&(workmarkers->createdate),
						  cd_buf, sizeof(cd_buf));
					cd = cd_buf;
					what = "days";
				}
				K_RUNLOCK(workmarkers_free);
				break;
			case 'S': // mark_start shifts (workmarkers)
				K_RLOCK(workmarkers_free);
				wm_item = last_in_ktree(workmarkers_root, ctx);
				while (wm_item) {
					DATA_WORKMARKERS(workmarkers, wm_item);
					if (CURRENT(&(workmarkers->expirydate)) &&
					    WMPROCESSED(workmarkers->status)) {
						ms--;
						if (ms <= 0)
							break;
					}
					wm_item = prev_in_ktree(ctx);
				}
				if (!wm_item)
					mark_start = 0;
				else {
					mark_start = workmarkers->markerid;
					tv_to_buf(&(workmarkers->createdate),
						  cd_buf, sizeof(cd_buf));
					cd = cd_buf;
					what = "shifts";
				}
				K_RUNLOCK(workmarkers_free);
				break;
			case 'M': // markerid = mark_start
				break;
			default:
				/* Not possible unless ckdb.c is different
				 *  in which case it will just use mark_start */
				break;
		}
	}

	int markerid_num, userid_num, workername_num, diffacc_num, diffsta_num;
	int diffdup_num, diffhi_num, diffrej_num, shareacc_num, sharesta_num;
	int sharedup_num, sharehi_num, sharerej_num, sharecount_num;
	int errorcount_num, firstshare_num, lastshare_num, firstshareacc_num;
	int lastshareacc_num, lastdiffacc_num;
	MODIFYDATE_num;

	// TODO: limit how far back
	sel = "declare ws cursor for select "
		"markerid,userid,workername,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,firstshareacc,"
		"lastshareacc,lastdiffacc"
		MODIFYDATECONTROL
		" from markersummary where markerid>=$1";

	par = 0;
	params[par++] = bigint_to_buf(mark_start, NULL, 0);
	PARCHK(par, params);

	LOGWARNING("%s(): loading from markerid>=%s", __func__, params[0]);
	if (cd) {
		LOGWARNING(" ... %s = %s >= %"PRId64" %s",
			   params[0], cd, amt, what);
	}

	STRNCPY(tickbuf, TICK_PREFIX"ms 0");
	cr_msg(false, tickbuf);

	if (!CKPQBegin(conn))
		return false;

	if (exclusive_db) {
		res = CKPQExec(conn, "Lock table markersummary in access exclusive mode", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Lock", rescode, conn);
			goto flail;
		}
	}

	res = CKPQExecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Declare", rescode, conn);
		goto flail;
	}

	LOGDEBUG("%s(): fetching ...", __func__);

	res = CKPQExec(conn, "fetch 1 in ws", CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Fetch first", rescode, conn);
		CKPQClear(res);
		goto flail;
	}

	n = PQnfields(res);
	if (n != (fields + MODIFYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + MODIFYDATECOUNT, n);
		CKPQClear(res);
		goto flail;
	}

	n = 0;
	ok = true;
	markerid_num = userid_num = workername_num = diffacc_num = diffsta_num =
	diffdup_num = diffhi_num = diffrej_num = shareacc_num = sharesta_num =
	sharedup_num = sharehi_num = sharerej_num = sharecount_num =
	errorcount_num = firstshare_num = lastshare_num = firstshareacc_num =
	lastshareacc_num = lastdiffacc_num = CKPQFUNDEF;
	MODIFYDATE_init;
	K_WLOCK(markersummary_free);
	while ((t = PQntuples(res)) > 0) {
		// Avoid locking them too many times
		K_RLOCK(workmarkers_free);
		K_WLOCK(userinfo_free);
		for (i = 0; i < t; i++) {
			item = k_unlink_head(markersummary_free);
			DATA_MARKERSUMMARY(row, item);
			bzero(row, sizeof(*row));

			if (everyone_die) {
				ok = false;
				break;
			}

			CKPQ_VAL_FLD_num(res, i, markerid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("markerid", field, row->markerid);

			CKPQ_VAL_FLD_num(res, i, userid, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("userid", field, row->userid);

			CKPQ_VAL_FLD_num(res, i, workername, field, ok);
			if (!ok)
				break;
			row->in_workername = intransient_str("workername", field);

			CKPQ_VAL_FLD_num(res, i, diffacc, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffacc", field, row->diffacc);

			CKPQ_VAL_FLD_num(res, i, diffsta, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffsta", field, row->diffsta);

			CKPQ_VAL_FLD_num(res, i, diffdup, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffdup", field, row->diffdup);

			CKPQ_VAL_FLD_num(res, i, diffhi, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffhi", field, row->diffhi);

			CKPQ_VAL_FLD_num(res, i, diffrej, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("diffrej", field, row->diffrej);

			CKPQ_VAL_FLD_num(res, i, shareacc, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("shareacc", field, row->shareacc);

			CKPQ_VAL_FLD_num(res, i, sharesta, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("sharesta", field, row->sharesta);

			CKPQ_VAL_FLD_num(res, i, sharedup, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("sharedup", field, row->sharedup);

			CKPQ_VAL_FLD_num(res, i, sharehi, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("sharehi", field, row->sharehi);

			CKPQ_VAL_FLD_num(res, i, sharerej, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("sharerej", field, row->sharerej);

			CKPQ_VAL_FLD_num(res, i, sharecount, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("sharecount", field, row->sharecount);

			CKPQ_VAL_FLD_num(res, i, errorcount, field, ok);
			if (!ok)
				break;
			TXT_TO_BIGINT("errorcount", field, row->errorcount);

			CKPQ_VAL_FLD_num(res, i, firstshare, field, ok);
			if (!ok)
				break;
			TXT_TO_TVDB("firstshare", field, row->firstshare);

			CKPQ_VAL_FLD_num(res, i, lastshare, field, ok);
			if (!ok)
				break;
			TXT_TO_TVDB("lastshare", field, row->lastshare);

			CKPQ_VAL_FLD_num(res, i, firstshareacc, field, ok);
			if (!ok)
				break;
			TXT_TO_TVDB("firstshareacc", field, row->firstshareacc);

			CKPQ_VAL_FLD_num(res, i, lastshareacc, field, ok);
			if (!ok)
				break;
			TXT_TO_TVDB("lastshareacc", field, row->lastshareacc);

			CKPQ_VAL_FLD_num(res, i, lastdiffacc, field, ok);
			if (!ok)
				break;
			TXT_TO_DOUBLE("lastdiffacc", field, row->lastdiffacc);

			MODIFYDATEIN(res, i, row, ok);
			if (!ok)
				break;

			/* Save having to do this everywhere in the code for old data
			 * It's not always accurate, but soon after when it's not,
			 *  and also what was used before the 2 fields were added */
			if (row->diffacc > 0) {
				if (row->firstshareacc.tv_sec == 0L)
					copy_tv(&(row->firstshareacc), &(row->firstshare));
				if (row->lastshareacc.tv_sec == 0L)
					copy_tv(&(row->lastshareacc), &(row->lastshare));
			}

			add_to_ktree(markersummary_root, item);
			add_to_ktree(markersummary_userid_root, item);
			k_add_head(markersummary_store, item);

			p_item = find_markersummary_p(row->markerid);
			if (!p_item) {
				/* N.B. this could be false due to the markerid
				 *  having the wrong status TODO: deal with that? */
				p_item = k_unlink_head(markersummary_free);
				DATA_MARKERSUMMARY(p_row, p_item);
				bzero(p_row, sizeof(*p_row));
				p_row->markerid = row->markerid;
				POOL_MS(p_row);
				add_to_ktree(markersummary_pool_root, p_item);
				k_add_head(markersummary_pool_store, p_item);
			} else {
				DATA_MARKERSUMMARY(p_row, p_item);
			}

			markersummary_to_pool(p_row, row);

			userinfo_update(NULL, NULL, row, false);

			if (n == 0 || ((n+1) % FETCHTICK) == 0) {
				pcom(n+1, pcombuf, sizeof(pcombuf));
				snprintf(tickbuf, sizeof(tickbuf),
					 TICK_PREFIX"ms %s", pcombuf);
				cr_msg(false, tickbuf);
			}
			tick();
			n++;
		}
		K_WUNLOCK(userinfo_free);
		K_RUNLOCK(workmarkers_free);
		CKPQClear(res);
		res = CKPQExec(conn, "fetch "CKPQFETCHSTR" in ws", CKPQ_READ);
		rescode = CKPQResultStatus(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Fetch next", rescode, conn);
			ok = false;
			break;
		}
		markerid_num = userid_num = workername_num = diffacc_num =
		diffsta_num = diffdup_num = diffhi_num = diffrej_num =
		shareacc_num = sharesta_num = sharedup_num = sharehi_num =
		sharerej_num = sharecount_num = errorcount_num =
		firstshare_num = lastshare_num = firstshareacc_num =
		lastshareacc_num = lastdiffacc_num = CKPQFUNDEF;
		MODIFYDATE_init;
	}
	if (!ok) {
		free_markersummary_data(item);
		k_add_head(markersummary_free, item);
	}

	p_n = markersummary_pool_store->count;

	K_WUNLOCK(markersummary_free);
	CKPQClear(res);
flail:

	CKPQCommit(conn);
	for (i = 0; i < par; i++)
		free(params[i]);
	par = 0;

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): fetched %s markersummary records",
			   __func__, pcombuf);
		pcom(p_n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): created %s markersummary pool records",
			   __func__, pcombuf);
	}

	return ok;
}

bool keysummary_add(PGconn *conn, K_ITEM *ks_item, char *by, char *code,
		    char *inet, tv_t *cd)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res;
	KEYSUMMARY *row;
	char *params[20 + SIMPLEDATECOUNT];
	int n, par = 0;
	char *ins;
	bool ok = false;
	char *st = NULL;

	LOGDEBUG("%s(): add", __func__);

	DATA_KEYSUMMARY(row, ks_item);

	SIMPLEDATEINTRANS(row, cd, by, code, inet);

	par = 0;
	params[par++] = bigint_to_buf(row->markerid, NULL, 0);
	params[par++] = str_to_buf(row->keytype, NULL, 0);
	params[par++] = str_to_buf(row->key, NULL, 0);
	params[par++] = double_to_buf(row->diffacc, NULL, 0);
	params[par++] = double_to_buf(row->diffsta, NULL, 0);
	params[par++] = double_to_buf(row->diffdup, NULL, 0);
	params[par++] = double_to_buf(row->diffhi, NULL, 0);
	params[par++] = double_to_buf(row->diffrej, NULL, 0);
	params[par++] = double_to_buf(row->shareacc, NULL, 0);
	params[par++] = double_to_buf(row->sharesta, NULL, 0);
	params[par++] = double_to_buf(row->sharedup, NULL, 0);
	params[par++] = double_to_buf(row->sharehi, NULL, 0);
	params[par++] = double_to_buf(row->sharerej, NULL, 0);
	params[par++] = bigint_to_buf(row->sharecount, NULL, 0);
	params[par++] = bigint_to_buf(row->errorcount, NULL, 0);
	params[par++] = tv_to_buf(&(row->firstshare), NULL, 0);
	params[par++] = tv_to_buf(&(row->lastshare), NULL, 0);
	params[par++] = tv_to_buf(&(row->firstshareacc), NULL, 0);
	params[par++] = tv_to_buf(&(row->lastshareacc), NULL, 0);
	params[par++] = double_to_buf(row->lastdiffacc, NULL, 0);
	SIMPLEDATEPARAMSIN(params, par, row);
	PARCHK(par, params);

	ins = "insert into keysummary "
		"(markerid,keytype,key,diffacc,diffsta,diffdup,diffhi,"
		"diffrej,shareacc,sharesta,sharedup,sharehi,sharerej,"
		"sharecount,errorcount,firstshare,lastshare,firstshareacc,"
		"lastshareacc,lastdiffacc"
		SIMPLEDATECONTROL ") values (" PQPARAM24 ")";

	LOGDEBUG("%s() adding ks %"PRId64"/%s/%s/%.0f",
		 __func__, row->markerid, row->keytype,
		 st = safe_text_nonull(row->key),
		 row->diffacc);
	FREENULL(st);

	if (CKPQConn(&conn))
		conned = true;
	res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
	rescode = CKPQResultStatus(res);
	CKPQClear(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Insert", rescode, conn);
		/* Don't fail on a duplicate during key_update
		 * TODO: should only be on a duplicate ... */
		if (key_update)
			ok = true;
		goto unparam;
	}

	ok = true;
unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	// caller must do tree/list/store changes

	return ok;
}

/* Already means there is a transaction already in progress
 *  so don't begin or commit/rollback
 * Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * Add requires all db fields except markerid, however if markerid
 *  is non-zero, it will be used instead of getting a new one
 *  i.e. this effectively means updating a workmarker
 * !Add requires markerid or workinfoidend, only
 *  workinfoidend is used if markerid is zero
 * N.B. if you expire a workmarker without creating a new one,
 *  it's markerid is effectively cancelled, since creating a
 *  new matching workmarker later, will get a new markerid,
 *  since we only check for a CURRENT workmarkers
 * N.B. also, this returns success if !add and there is no matching
 *  old workmarkers */
bool _workmarkers_process(PGconn *conn, bool already, bool add,
			  int64_t markerid, char *poolinstance,
			  int64_t workinfoidend, int64_t workinfoidstart,
			  char *description, char *status, char *by, char *code,
			  char *inet, tv_t *cd, K_TREE *trf_root,
			  WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *wm_item = NULL, *old_wm_item = NULL, *w_item;
	WORKMARKERS *row, *oldworkmarkers = NULL;
	char *upd, *ins;
	char *params[6 + HISTORYDATECOUNT];
	bool ok = false, begun = false;
	int n, par = 0;

	LOGDEBUG("%s(): add %c already %c", __func__,
		 add ? 'Y' : 'N', already ? 'Y' : 'N');

	if (markerid == 0) {
		K_RLOCK(workmarkers_free);
		old_wm_item = find_workmarkers(workinfoidend, true, '\0', NULL);
		K_RUNLOCK(workmarkers_free);
	} else {
		K_RLOCK(workmarkers_free);
		old_wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
	}
	if (old_wm_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_WORKMARKERS(oldworkmarkers, old_wm_item);
		if (CKPQConn(&conn))
			conned = true;
		if (!already) {
			begun = CKPQBegin(conn);
			if (!begun)
				goto unparam;
		}

		upd = "update workmarkers set "EDDB"=$1 where markerid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(oldworkmarkers->markerid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		if (poolinstance == NULL || description == NULL ||
		    status == NULL) {
			LOGEMERG("%s(): NULL field(s) passed:%s%s%s"
				 WHERE_FFL, __func__,
				 poolinstance ? "" : " poolinstance",
				 description ? "" : " description",
				 status ? "" : " status",
				 WHERE_FFL_PASS);
			goto rollback;
		}
		w_item = find_workinfo(workinfoidstart, NULL);
		if (!w_item)
			goto rollback;
		w_item = find_workinfo(workinfoidend, NULL);
		if (!w_item)
			goto rollback;

		K_WLOCK(workmarkers_free);
		wm_item = k_unlink_head(workmarkers_free);
		K_WUNLOCK(workmarkers_free);
		DATA_WORKMARKERS(row, wm_item);
		bzero(row, sizeof(*row));

		if (CKPQConn(&conn))
			conned = true;
		if (!already && !begun) {
			begun = CKPQBegin(conn);
			if (!begun)
				goto unparam;
		}

		if (old_wm_item)
			row->markerid = oldworkmarkers->markerid;
		else {
			if (markerid != 0)
				row->markerid = markerid;
			else {
				row->markerid = nextid(conn, "markerid", 1,
							cd, by, code, inet);
				if (row->markerid == 0)
					goto rollback;
			}
		}

		row->in_poolinstance = intransient_str("poolinstance", poolinstance);
		row->workinfoidend = workinfoidend;
		row->workinfoidstart = workinfoidstart;
		DUP_POINTER(workmarkers_free, row->description, description);
		STRNCPY(row->status, status);
		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		ins = "insert into workmarkers "
			"(markerid,poolinstance,workinfoidend,workinfoidstart,"
			"description,status"
			HISTORYDATECONTROL ") values (" PQPARAM11 ")";
		par = 0;
		params[par++] = bigint_to_buf(row->markerid, NULL, 0);
		params[par++] = str_to_buf(row->in_poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidend, NULL, 0);
		params[par++] = bigint_to_buf(row->workinfoidstart, NULL, 0);
		params[par++] = str_to_buf(row->description, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto rollback;
		}
		row->pps_value = workinfo_pps(w_item, workinfoidend);
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	if (!ok) {
		if (wm_item) {
			K_WLOCK(workmarkers_free);
			free_workmarkers_data(wm_item);
			k_add_head(workmarkers_free, wm_item);
			K_WUNLOCK(workmarkers_free);
		}
	} else {
		if (wm_item)
			shift_rewards(wm_item);
		K_WLOCK(workmarkers_free);
		if (old_wm_item) {
			remove_from_ktree(workmarkers_root, old_wm_item);
			remove_from_ktree(workmarkers_workinfoid_root,
					  old_wm_item);
			copy_tv(&(oldworkmarkers->expirydate), cd);
			add_to_ktree(workmarkers_root, old_wm_item);
			add_to_ktree(workmarkers_workinfoid_root, old_wm_item);
		}
		if (wm_item) {
			add_to_ktree(workmarkers_root, wm_item);
			add_to_ktree(workmarkers_workinfoid_root, wm_item);
			k_add_head(workmarkers_store, wm_item);
		}
		K_WUNLOCK(workmarkers_free);
	}

	return ok;
}

bool workmarkers_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item, *wi_item;
	WORKINFO *workinfo;
	char *params[1];
	int n, i, par = 0;
	WORKMARKERS *row;
	char *field = NULL;
	char *sel;
	int fields = 6;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int markerid_num, poolinstance_num, workinfoidend_num;
	int workinfoidstart_num, description_num, status_num;
	HISTORYDATE_num;

	// Allow limiting the load for key_update
	if (key_update && dbload_workinfoid_start != -1) {
		sel = "select "
			"markerid,poolinstance,workinfoidend,workinfoidstart,"
			"description,status"
			HISTORYDATECONTROL
			" from workmarkers where workinfoidstart>=$1";
		par = 0;
		params[par++] = bigint_to_buf(dbload_workinfoid_start, NULL, 0);
		PARCHK(par, params);
		res = CKPQExecParams(conn, sel, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_READ);
	} else {
		sel = "select "
			"markerid,poolinstance,workinfoidend,workinfoidstart,"
			"description,status"
			HISTORYDATECONTROL
			" from workmarkers";
		res = CKPQExec(conn, sel, CKPQ_READ);
	}
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	markerid_num = poolinstance_num = workinfoidend_num =
	workinfoidstart_num = description_num = status_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(workmarkers_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(workmarkers_free);
		DATA_WORKMARKERS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, poolinstance, field, ok);
		if (!ok)
			break;
		if (sys_poolinstance && strcmp(field, sys_poolinstance)) {
			k_add_head(workmarkers_free, item);
			POOLINSTANCE_DBLOAD_SET(workmarkers, field);
			continue;
		}
		row->in_poolinstance = intransient_str("poolinstance", field);

		CKPQ_VAL_FLD_num(res, i, markerid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("markerid", field, row->markerid);

		CKPQ_VAL_FLD_num(res, i, workinfoidend, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidend", field, row->workinfoidend);

		CKPQ_VAL_FLD_num(res, i, workinfoidstart, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoidstart", field, row->workinfoidstart);

		CKPQ_VAL_FLD_num(res, i, description, field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("description", field, row->description);
		LIST_MEM_ADD(workmarkers_free, row->description);

		CKPQ_VAL_FLD_num(res, i, status, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(workmarkers_root, item);
		add_to_ktree(workmarkers_workinfoid_root, item);
		k_add_head(workmarkers_store, item);

		wi_item = find_workinfo(row->workinfoidend, NULL);
		if (!wi_item) {
			LOGERR("%s(): ERROR workmarkerid %"PRId64
				" wid end %"PRId64" doesn't exist! "
				"PPS value will be zero",
				__func__, row->markerid,
				row->workinfoidend);
		}
		row->pps_value = workinfo_pps(wi_item, row->workinfoidend);

		if (CURRENT(&(row->expirydate)) &&
		    !WMPROCESSED(row->status)) {
			LOGWARNING("%s(): WARNING workmarkerid %"PRId64" (%s)"
				   " wid end %"PRId64" isn't processed! (%s) "
				   "You need to correct it after the startup "
				   "completes, with a marks action: processed"
				   " or cancel",
				   __func__, row->markerid, row->description,
				   row->workinfoidend, row->status);
		}

		/* Ignore any workmarker that isn't processed, so that the
		 *  necessary data to process it can be reloaded, if the
		 *  workmarker is after the last processed shift
		 * Any CURRENT non-processed workmarkers will give a console
		 *  warning (above) */
		if (CURRENT(&(row->expirydate)) &&
		    WMPROCESSED(row->status) &&
		    dbstatus.newest_workmarker_workinfoid < row->workinfoidend) {
			dbstatus.newest_workmarker_workinfoid = row->workinfoidend;
			if (!wi_item) {
				LOGEMERG("%s(): FAILURE workmarkerid %"PRId64
					 " wid end %"PRId64" doesn't exist! "
					 "You should abort ckdb and fix it, "
					 "since the reload may skip some data",
					 __func__, row->markerid,
					 row->workinfoidend);
			} else {
				DATA_WORKINFO(workinfo, wi_item);
				copy_tv(&(dbstatus.newest_createdate_workmarker_workinfo),
					&(workinfo->createdate));
			}
		}

		tick();
	}
	if (!ok) {
		free_workmarkers_data(item);
		k_add_head(workmarkers_free, item);
	}

	K_WUNLOCK(workmarkers_free);
	CKPQClear(res);
	for (i = 0; i < par; i++)
		free(params[i]);
	par = 0;

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s workmarkers records",
			   __func__, pcombuf);
	}

	POOLINSTANCE_DBLOAD_MSG(workmarkers);
	return ok;
}

/* Add means create a new one and expire the old one if it exists,
 *  otherwise we only expire the old one if it exists
 * Add requires all db fields
 * !Add only requires the (poolinstance and) workinfoid db fields */
bool _marks_process(PGconn *conn, bool add, char *poolinstance,
		    int64_t workinfoid, char *description, char *extra,
		    char *marktype, char *status, char *by, char *code,
		    char *inet, tv_t *cd, K_TREE *trf_root, WHERE_FFL_ARGS)
{
	ExecStatusType rescode;
	bool conned = false;
	PGresult *res = NULL;
	K_ITEM *m_item = NULL, *old_m_item = NULL, *w_item;
	MARKS *row, *oldmarks = NULL;
	char *upd, *ins;
	char *params[6 + HISTORYDATECOUNT];
	bool ok = false, begun = false;
	int n, par = 0;

	LOGDEBUG("%s(): add %c", __func__, add ? 'Y' : 'N');

	K_RLOCK(marks_free);
	old_m_item = find_marks(workinfoid);
	K_RUNLOCK(marks_free);
	if (old_m_item) {
		LOGDEBUG("%s(): updating old", __func__);

		DATA_MARKS(oldmarks, old_m_item);
		if (CKPQConn(&conn))
			conned = true;
		begun = CKPQBegin(conn);
		if (!begun)
			goto unparam;

		upd = "update marks set "EDDB"=$1 where workinfoid=$2"
			" and "EDDB"=$3";
		par = 0;
		params[par++] = tv_to_buf(cd, NULL, 0);
		params[par++] = bigint_to_buf(workinfoid, NULL, 0);
		params[par++] = tv_to_buf((tv_t *)&default_expiry, NULL, 0);
		PARCHKVAL(par, 3, params);

		res = CKPQExecParams(conn, upd, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Update", rescode, conn);
			goto rollback;
		}

		for (n = 0; n < par; n++)
			free(params[n]);
		par = 0;
	}

	if (add) {
		LOGDEBUG("%s(): adding new", __func__);

		if (poolinstance == NULL || description == NULL ||
		    extra == NULL || marktype == NULL || status == NULL) {
			LOGEMERG("%s(): NULL field(s) passed:%s%s%s%s%s"
				 WHERE_FFL, __func__,
				 poolinstance ? "" : " poolinstance",
				 description ? "" : " description",
				 extra ? "" : " extra",
				 marktype ? "" : " marktype",
				 status ? "" : " status",
				 WHERE_FFL_PASS);
			goto rollback;
		}
		w_item = find_workinfo(workinfoid, NULL);
		if (!w_item)
			goto rollback;
		K_WLOCK(marks_free);
		m_item = k_unlink_head(marks_free);
		K_WUNLOCK(marks_free);
		DATA_MARKS(row, m_item);
		bzero(row, sizeof(*row));
		row->in_poolinstance = intransient_str("poolinstance", poolinstance);
		row->workinfoid = workinfoid;
		DUP_POINTER(marks_free, row->description, description);
		DUP_POINTER(marks_free, row->extra, extra);
		STRNCPY(row->marktype, marktype);
		STRNCPY(row->status, status);
		HISTORYDATEINIT(row, cd, by, code, inet);
		HISTORYDATETRANSFER(trf_root, row);

		ins = "insert into marks "
			"(poolinstance,workinfoid,description,extra,marktype,"
			"status"
			HISTORYDATECONTROL ") values (" PQPARAM11 ")";
		par = 0;
		params[par++] = str_to_buf(row->in_poolinstance, NULL, 0);
		params[par++] = bigint_to_buf(workinfoid, NULL, 0);
		params[par++] = str_to_buf(row->description, NULL, 0);
		params[par++] = str_to_buf(row->extra, NULL, 0);
		params[par++] = str_to_buf(row->marktype, NULL, 0);
		params[par++] = str_to_buf(row->status, NULL, 0);
		HISTORYDATEPARAMS(params, par, row);
		PARCHK(par, params);

		if (CKPQConn(&conn))
			conned = true;
		if (!begun) {
			begun = CKPQBegin(conn);
			if (!begun)
				goto unparam;
		}

		res = CKPQExecParams(conn, ins, par, NULL, (const char **)params, NULL, NULL, 0, CKPQ_WRITE);
		rescode = CKPQResultStatus(res);
		CKPQClear(res);
		if (!PGOK(rescode)) {
			PGLOGERR("Insert", rescode, conn);
			goto rollback;
		}
	}

	ok = true;
rollback:
	if (begun)
		CKPQEnd(conn, ok);

unparam:
	CKPQDisco(&conn, conned);
	for (n = 0; n < par; n++)
		free(params[n]);

	K_WLOCK(marks_free);
	if (!ok) {
		if (m_item) {
			free_marks_data(m_item);
			k_add_head(marks_free, m_item);
		}
	} else {
		if (old_m_item) {
			remove_from_ktree(marks_root, old_m_item);
			copy_tv(&(oldmarks->expirydate), cd);
			add_to_ktree(marks_root, old_m_item);
		}
		if (m_item) {
			add_to_ktree(marks_root, m_item);
			k_add_head(marks_store, m_item);
		}
	}
	K_WUNLOCK(marks_free);

	return ok;
}

bool marks_fill(PGconn *conn)
{
	char pcombuf[64];
	ExecStatusType rescode;
	PGresult *res;
	K_ITEM *item;
	int n, i;
	MARKS *row;
	char *field = NULL;
	char *sel;
	int fields = 6;
	bool ok;

	LOGDEBUG("%s(): select", __func__);

	int poolinstance_num, workinfoid_num, description_num, extra_num;
	int marktype_num, status_num;
	HISTORYDATE_num;

	// TODO: limit how far back
	sel = "select "
		"poolinstance,workinfoid,description,extra,marktype,status"
		HISTORYDATECONTROL
		" from marks";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGERR("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != (fields + HISTORYDATECOUNT)) {
		LOGERR("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields + HISTORYDATECOUNT, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	LOGDEBUG("%s(): tree build count %d", __func__, n);
	ok = true;
	poolinstance_num = workinfoid_num = description_num = extra_num =
	marktype_num = status_num = CKPQFUNDEF;
	HISTORYDATE_init;
	K_WLOCK(marks_free);
	for (i = 0; i < n; i++) {
		item = k_unlink_head(marks_free);
		DATA_MARKS(row, item);
		bzero(row, sizeof(*row));

		if (everyone_die) {
			ok = false;
			break;
		}

		CKPQ_VAL_FLD_num(res, i, poolinstance, field, ok);
		if (!ok)
			break;
		if (sys_poolinstance && strcmp(field, sys_poolinstance)) {
			k_add_head(marks_free, item);
			POOLINSTANCE_DBLOAD_SET(marks, field);
			continue;
		}
		row->in_poolinstance = intransient_str("poolinstance", field);

		CKPQ_VAL_FLD_num(res, i, workinfoid, field, ok);
		if (!ok)
			break;
		TXT_TO_BIGINT("workinfoid", field, row->workinfoid);

		CKPQ_VAL_FLD_num(res, i, description, field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("description", field, row->description);
		LIST_MEM_ADD(marks_free, row->description);

		CKPQ_VAL_FLD_num(res, i, extra, field, ok);
		if (!ok)
			break;
		TXT_TO_PTR("extra", field, row->extra);
		LIST_MEM_ADD(marks_free, row->extra);

		CKPQ_VAL_FLD_num(res, i, marktype, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("marktype", field, row->marktype);

		CKPQ_VAL_FLD_num(res, i, status, field, ok);
		if (!ok)
			break;
		TXT_TO_STR("status", field, row->status);

		HISTORYDATEFLDS(res, i, row, ok);
		if (!ok)
			break;

		add_to_ktree(marks_root, item);
		k_add_head(marks_store, item);

		tick();
	}
	if (!ok) {
		free_marks_data(item);
		k_add_head(marks_free, item);
	}

	K_WUNLOCK(marks_free);
	CKPQClear(res);

	if (ok) {
		LOGDEBUG("%s(): built", __func__);
		pcom(n, pcombuf, sizeof(pcombuf));
		LOGWARNING("%s(): loaded %s marks records",
			   __func__, pcombuf);
	}

	POOLINSTANCE_DBLOAD_MSG(marks);
	return ok;
}

bool check_db_version(PGconn *conn)
{
	ExecStatusType rescode;
	PGresult *res;
	char *field = NULL;
	char *sel;
	char *pgv;
	int fields = 3;
	bool ok;
	int n, f;

	LOGDEBUG("%s(): select", __func__);

	sel = "select version() as pgv,* from version;";
	res = CKPQExec(conn, sel, CKPQ_READ);
	rescode = CKPQResultStatus(res);
	if (!PGOK(rescode)) {
		PGLOGEMERG("Select", rescode, conn);
		CKPQClear(res);
		return false;
	}

	n = PQnfields(res);
	if (n != fields) {
		LOGEMERG("%s(): Invalid field count - should be %d, but is %d",
			__func__, fields, n);
		CKPQClear(res);
		return false;
	}

	n = PQntuples(res);
	if (n != 1) {
		LOGEMERG("%s(): Invalid record count - should be %d, but is %d",
			__func__, 1, n);
		CKPQClear(res);
		return false;
	}

	ok = true;
	f = CKPQFUNDEF;
	CKPQ_VAL_FLD(res, 0, f, "vlock", field, ok);
	if (!ok) {
		LOGEMERG("%s(): Missing field vlock", __func__);
		CKPQClear(res);
		return false;
	}

	if (strcmp(field, DB_VLOCK)) {
		LOGEMERG("%s(): incorrect vlock '%s' - should be '%s'",
			__func__, field, DB_VLOCK);
		CKPQClear(res);
		return false;
	}

	ok = true;
	f = CKPQFUNDEF;
	CKPQ_VAL_FLD(res, 0, f, "version", field, ok);
	if (!ok) {
		LOGEMERG("%s(): Missing field version", __func__);
		CKPQClear(res);
		return false;
	}

	if (strcmp(field, DB_VERSION)) {
		LOGEMERG("%s(): incorrect version '%s' - should be '%s'",
			__func__, field, DB_VERSION);
		CKPQClear(res);
		return false;
	}

	ok = true;
	f = CKPQFUNDEF;
	CKPQ_VAL_FLD(res, 0, f, "pgv", field, ok);
	if (ok)
		pgv = strdup(field);
	else
		pgv = strdup("Failed to get postgresql version information");

	CKPQClear(res);

	LOGWARNING("%s(): DB version (%s) correct (CKDB V%s)",
		   __func__, DB_VERSION, CKDB_VERSION);
	LOGWARNING("%s(): %s", __func__, pgv);

	free(pgv);

	return true;
}
