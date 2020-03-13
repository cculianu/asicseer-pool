/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 2014-2016 Andrew Smith
 * Copyright 2014 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "asicseer-db.h"

#define BTCKEY ((const char *)"result")

#define GETBLOCKHASHCMD "getblockhash"
#define GETBLOCKHASH "{\"method\":\"" GETBLOCKHASHCMD "\",\"params\":[%d],\"id\":1}"
#define GETBLOCKHASHKEY NULL

#define GETBLOCKCMD "getblock"
#define GETBLOCK "{\"method\":\"" GETBLOCKCMD "\",\"params\":[\"%s\"],\"id\":1}"
#define GETBLOCKCONFKEY ((const char *)"confirmations")

#define VALIDADDRCMD "validateaddress"
#define VALIDADDR "{\"method\":\"" VALIDADDRCMD "\",\"params\":[\"%s\"],\"id\":1}"
#define VALIDADDRKEY ((const char *)"isvalid")

static char *btc_data(char *json, size_t *len)
{
	size_t off;
	char tmp[1024];
	char *buf;

	APPEND_REALLOC_INIT(buf, off, *len);
	APPEND_REALLOC(buf, off, *len, "POST / HTTP/1.1\n");
	ck_wlock(&btc_lock);
	snprintf(tmp, sizeof(tmp), "Authorization: Basic %s\n", btc_auth);
	APPEND_REALLOC(buf, off, *len, tmp);
	snprintf(tmp, sizeof(tmp), "Host: %s/\n", btc_server);
	ck_wunlock(&btc_lock);
	APPEND_REALLOC(buf, off, *len, tmp);
	APPEND_REALLOC(buf, off, *len, "Content-Type: application/json\n");
	snprintf(tmp, sizeof(tmp), "Content-Length: %d\n\n", (int)strlen(json));
	APPEND_REALLOC(buf, off, *len, tmp);
	APPEND_REALLOC(buf, off, *len, json);

	return buf;
}

#define SOCK_READ 8192

static int read_socket(int fd, char **buf, int timeout)
{
	char tmp[SOCK_READ+1];
	int ret, off, len;
	tv_t tv_timeout;
	fd_set readfs;

	len = SOCK_READ;
	*buf = malloc(len+1);
	if (!(*buf))
		quithere(1, "malloc (%d) OOM", len+1);
	off = 0;

	while (42) {
		tv_timeout.tv_sec = timeout;
		tv_timeout.tv_usec = 0;
		FD_ZERO(&readfs);
		FD_SET(fd, &readfs);
		ret = select(fd + 1, &readfs, NULL, NULL, &tv_timeout);
		if (ret == 0)
			break;

		if (ret < 0) {
			LOGERR("%s() btc socket select error %d:%s",
				__func__, errno, strerror(errno));
			break;
		}

		ret = recv(fd, tmp, SOCK_READ, 0);
		if (ret == 0)
			break;
		if (ret < 0) {
			LOGERR("%s() btc socket recv error %d:%s",
				__func__, errno, strerror(errno));
			break;
		}

		if ((off + ret) > len) {
			len += SOCK_READ;
			*buf = realloc(*buf, len + 1);
			if (!(*buf))
				quithere(1, "realloc (%d) OOM", len);
		}

		memcpy(*buf + off, tmp, ret);
		off += ret;
	}

	if (close(fd)) {
                LOGERR("%s() btc socket close error %d:%s",
			__func__, errno, strerror(errno));
	}

	return off;
}

#define btc_io(_cmd, _json) _btc_io(_cmd, _json, WHERE_FFL_HERE)

static char *_btc_io(__maybe_unused const char *cmd, char *json, WHERE_FFL_ARGS)
{
	char *ip = NULL, *port = NULL;
	char *data, *ans, *res, *ptr;
	int fd, ret, red;
	size_t len;

	data = btc_data(json, &len);
	if (!extract_sockaddr(btc_server, &ip, &port)) {
		LOGERR("%s() invalid btc server '%s'",
		        __func__, btc_server);
		return NULL;
	}
	fd = connect_socket(ip, port);
	if (fd < 0) {
		LOGERR("%s() failed to connect to btc server %s",
		        __func__, btc_server);
		return NULL;
	}
	ret = write_socket(fd, data, len);
	if (ret != (int)len) {
		LOGERR("%s() failed to write to btc server %s",
		        __func__, btc_server);
		return NULL;
	}
	red = read_socket(fd, &ans, btc_timeout);
	ans[red] = '\0';
	if (strncasecmp(ans, "HTTP/1.1 200 OK", 15)) {
		char *text = safe_text(ans);
		LOGERR("%s() btc server response not ok: %s",
		       __func__, text);
		free(text);
		free(ans);
		res = strdup(EMPTY);
	} else {
		ptr = strstr(ans, "\n{");
		if (ptr)
			res = strdup(ptr+1);
		else
			res = strdup(EMPTY);
		free(ans);
	}
	return res;
}

static json_t *single_decode(char *ans, const char *cmd, const char *key)
{
	json_t *json_data, *btc_ob, *json_ob = NULL;
	json_error_t err_val;

	if (ans && *ans) {
		json_data = json_loads(ans, JSON_DISABLE_EOF_CHECK, &err_val);
		if (!json_data) {
			char *text = safe_text(ans);
			LOGERR("%s() Json %s decode error "
				"json_err=(%d:%d:%d)%s:%s ans='%s'",
				__func__, cmd,
				err_val.line, err_val.column,
				err_val.position, err_val.source,
				err_val.text, text);
			free(text);
		} else {
			btc_ob = json_object_get(json_data, BTCKEY);
			if (!btc_ob) {
				char *text = safe_text(ans);
				LOGERR("%s() Json %s reply missing main key %s "
					"ans='%s'",
					__func__, cmd, key, text);
				free(text);
			} else {
				if (key == NULL)
					json_ob = btc_ob;
				else {
					json_ob = json_object_get(btc_ob, key);
					if (!json_ob) {
						char *text = safe_text(ans);
						LOGERR("%s() Json %s reply missing "
							"sub-key %s ans='%s'",
							__func__, cmd, key, text);
						free(text);
					}
				}
			}
		}
	}
	return json_ob;
}

static char *single_decode_str(char *ans, const char *cmd, const char *key)
{
	const char *json_str;
	char *str = NULL;
	json_t *json_ob;

	json_ob = single_decode(ans, cmd, key);
	if (json_ob) {
		if (!json_is_string(json_ob)) {
			char *text = safe_text(ans);
			if (!key)
				key = BTCKEY;
			LOGERR("%s() Json %s key %s "
				"not a string ans='%s'",
				__func__, cmd, key, text);
			free(text);
		} else {
			json_str = json_string_value(json_ob);
			if (json_str)
				str = strdup(json_str);
		}
	}
	return str;
}

static int64_t single_decode_int(char *ans, const char *cmd, const char *key)
{
	json_t *json_ob;
	int64_t val = 0;

	json_ob = single_decode(ans, cmd, key);
	if (json_ob) {
		if (!json_is_integer(json_ob)) {
			char *text = safe_text(ans);
			if (!key)
				key = BTCKEY;
			LOGERR("%s() Json %s key %s "
				"not an int ans='%s'",
				__func__, cmd, key, text);
			free(text);
		} else
			val = (int64_t)json_integer_value(json_ob);
	}
	return val;
}

static bool single_decode_bool(char *ans, const char *cmd, const char *key)
{
	json_t *json_ob;
	int json_typ;
	bool val = false;

	json_ob = single_decode(ans, cmd, key);
	if (json_ob) {
		json_typ = json_typeof(json_ob);
		if (json_typ != JSON_TRUE && json_typ != JSON_FALSE) {
			char *text = safe_text(ans);
			if (!key)
				key = BTCKEY;
			LOGERR("%s() Json %s key %s "
				"not a bool ans='%s'",
				__func__, cmd, key, text);
			free(text);
		} else {
			if (json_typ == JSON_TRUE)
				val = true;
		}
	}
	return val;
}

static char *btc_blockhash(int32_t height)
{
	char buf[1024];
	char *ans;
	char *hash;

	snprintf(buf, sizeof(buf), GETBLOCKHASH, height);
	ans = btc_io(GETBLOCKHASHCMD, buf);
	hash = single_decode_str(ans, GETBLOCKHASHCMD, GETBLOCKHASHKEY);
	free(ans);
	return hash;
}

static int32_t btc_confirms(char *hash)
{
	char buf[1024];
	char *ans;
	int32_t conf;

	snprintf(buf, sizeof(buf), GETBLOCK, hash);
	ans = btc_io(GETBLOCKCMD, buf);
	conf = (int32_t)single_decode_int(ans, GETBLOCKCMD, GETBLOCKCONFKEY);
	free(ans);
	return conf;
}

bool btc_valid_address(char *addr)
{
	char buf[1024];
	char *ans;
	bool valid;

	snprintf(buf, sizeof(buf), VALIDADDR, addr);
	ans = btc_io(VALIDADDRCMD, buf);
	valid = single_decode_bool(ans, VALIDADDRCMD, VALIDADDRKEY);
	free(ans);
	return valid;
}

// Check orphan, returns true only if all OK and not an orphan
bool btc_orphancheck(BLOCKS *blocks)
{
	char hash[TXT_BIG+1];
	char *blockhash;
	size_t len;
	tv_t now;
	bool ok;

	LOGDEBUG("%s() checking %d %s",
		 __func__, blocks->height, blocks->blockhash);

	if (blocks->ignore)
		return false;

	len = strlen(blocks->blockhash);
	if (len != SHA256SIZHEX) {
		LOGERR("%s() invalid blockhash size %d (%d) for block %d",
			__func__, (int)len, SHA256SIZHEX, blocks->height);

		/* So we don't keep repeating the message
		 * This should never happen */
		blocks->ignore = true;

		return false;
	}

	dbhash2btchash(blocks->blockhash, hash, sizeof(hash));

	blockhash = btc_blockhash(blocks->height);
	// Something's amiss - let it try again later
	if (!blockhash)
		return false;

	if (strlen(blockhash) != SHA256SIZHEX) {
		free(blockhash);
		return false;
	}

	if (strcmp(blockhash, hash) != 0) {
		LOGERR("%s() flagging block %d as %s pool=%s btc=%s",
			__func__, blocks->height,
			blocks_confirmed(BLOCKS_ORPHAN_STR),
			hash, blockhash);

		setnow(&now);

		ok = blocks_add(NULL, blocks->height,
				      blocks->blockhash,
				      BLOCKS_ORPHAN_STR, EMPTY,
				      EMPTY, EMPTY, NULL, EMPTY,
				      EMPTY, EMPTY, EMPTY, EMPTY,
				      by_default, (char *)__func__, inet_default,
				      &now, false, id_default, NULL);

		if (!ok)
			blocks->ignore = true;

		free(blockhash);
		return false;
	}

	free(blockhash);
	return true;
}

// Check to update confirm count
void btc_blockstatus(BLOCKS *blocks)
{
	char hash[TXT_BIG+1];
	char *blockhash;
	int32_t confirms;
	size_t len;
	tv_t now;
	bool ok;

	LOGDEBUG("%s() checking %d %s",
		 __func__, blocks->height, blocks->blockhash);

	// Caller must check this to avoid resending it every time
	if (blocks->ignore) {
		LOGERR("%s() ignored block %d passed",
			__func__, blocks->height);
		return;
	}

	len = strlen(blocks->blockhash);
	if (len != SHA256SIZHEX) {
		LOGERR("%s() invalid blockhash size %d (%d) for block %d",
			__func__, (int)len, SHA256SIZHEX, blocks->height);

		/* So we don't keep repeating the message
		 * This should never happen */
		blocks->ignore = true;

		return;
	}

	dbhash2btchash(blocks->blockhash, hash, sizeof(hash));

	blockhash = btc_blockhash(blocks->height);
	// Something's amiss - let it try again later
	if (!blockhash)
		return;

	if (strlen(blockhash) != SHA256SIZHEX) {
		free(blockhash);
		return;
	}

	confirms = btc_confirms(hash);
	if (confirms >= BLOCKS_42_VALUE) {
		LOGERR("%s() flagging block %d as %s confirms=%d(%d)",
			__func__, blocks->height,
			blocks_confirmed(BLOCKS_42_STR),
			confirms, BLOCKS_42_VALUE);

		setnow(&now);

		ok = blocks_add(NULL, blocks->height,
				      blocks->blockhash,
				      BLOCKS_42_STR, EMPTY,
				      EMPTY, EMPTY, NULL, EMPTY,
				      EMPTY, EMPTY, EMPTY, EMPTY,
				      by_default, (char *)__func__, inet_default,
				      &now, false, id_default, NULL);

		if (!ok)
			blocks->ignore = true;
	}
	free(blockhash);
}
