/*
 * Copyright 2014-2017 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <string.h>

#include "ckpool.h"
#include "libckpool.h"
#include "bitcoin.h"
#include "stratifier.h"

static const char *b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static char* understood_rules[] = {"segwit"};

static bool check_required_rule(const char* rule)
{
	unsigned int i;

	for (i = 0; i < sizeof(understood_rules) / sizeof(understood_rules[0]); i++) {
		if (safecmp(understood_rules[i], rule) == 0)
			return true;
	}
	return false;
}

/* Take a bitcoin address and do some sanity checks on it, then send it to
 * bitcoind to see if it's a valid address */
bool validate_address(connsock_t *cs, const char *address)
{
	json_t *val, *res_val, *valid_val;
	char rpc_req[128];
	bool ret = false;
	int len, i, j;

	if (unlikely(!address)) {
		LOGWARNING("Null address passed to validate_address");
		return ret;
	}
	len = strlen(address);
	if (len < 27 || len > 36) {
		LOGWARNING("Invalid address length %d passed to validate_address", len);
		return ret;
	}
	for (i = 0; i < len; i++) {
		char c = address[i];
		bool found = false;

		for (j = 0; j < 58; j++) {
			if (c == b58chars[j]) {
				found = true;
				break;
			}
		}
		if (!found) {
			LOGNOTICE("Invalid char %.1s passed to validate_address", &c);
			return ret;
		}
	}

	snprintf(rpc_req, 128, "{\"method\": \"validateaddress\", \"params\": [\"%s\"]}\n", address);
	val = json_rpc_call(cs, rpc_req);
	if (!val) {
		LOGERR("%s:%s Failed to get valid json response to validate_address", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGERR("Failed to get result json response to validate_address");
		goto out;
	}
	valid_val = json_object_get(res_val, "isvalid");
	if (!valid_val) {
		LOGERR("Failed to get isvalid json response to validate_address");
		goto out;
	}
	if (!json_is_true(valid_val))
		LOGDEBUG("Bitcoin address %s is NOT valid", address);
	else {
		LOGDEBUG("Bitcoin address %s IS valid", address);
		ret = true;
	}
out:
	if (val)
		json_decref(val);
	return ret;
}

static const char *gbt_req = "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": [\"coinbasetxn\", \"workid\", \"coinbase/append\"], \"rules\" : [\"segwit\"]}]}\n";

/* Request getblocktemplate from bitcoind already connected with a connsock_t
 * and then summarise the information to the most efficient set of data
 * required to assemble a mining template, storing it in a gbtbase_t structure */
bool gen_gbtbase(connsock_t *cs, gbtbase_t *gbt)
{
	json_t *rules_array, *coinbase_aux, *res_val, *val;
	const char *previousblockhash;
	char hash_swap[32], tmp[32];
	uint64_t coinbasevalue;
	const char *target;
	const char *flags;
	const char *bits;
	const char *rule;
	int version;
	int curtime;
	int height;
	int i;
	bool ret = false;

	val = json_rpc_call(cs, gbt_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getblocktemplate", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblocktemplate");
		goto out;
	}

	rules_array = json_object_get(res_val, "rules");
	if (rules_array) {
		int rule_count =  json_array_size(rules_array);

		for (i = 0; i < rule_count; i++) {
			rule = json_string_value(json_array_get(rules_array, i));
			if (rule && *rule++ == '!' && !check_required_rule(rule)) {
				LOGERR("Required rule not understood: %s", rule);
				goto out;
			}
		}
	}

	previousblockhash = json_string_value(json_object_get(res_val, "previousblockhash"));
	target = json_string_value(json_object_get(res_val, "target"));
	version = json_integer_value(json_object_get(res_val, "version"));
	curtime = json_integer_value(json_object_get(res_val, "curtime"));
	bits = json_string_value(json_object_get(res_val, "bits"));
	height = json_integer_value(json_object_get(res_val, "height"));
	coinbasevalue = json_integer_value(json_object_get(res_val, "coinbasevalue"));
	coinbase_aux = json_object_get(res_val, "coinbaseaux");
	flags = json_string_value(json_object_get(coinbase_aux, "flags"));

	if (unlikely(!previousblockhash || !target || !version || !curtime || !bits || !coinbase_aux || !flags)) {
		LOGERR("JSON failed to decode GBT %s %s %d %d %s %s", previousblockhash, target, version, curtime, bits, flags);
		goto out;
	}

	/* Store getblocktemplate for remainder of json components as is */
	json_incref(res_val);
	json_object_del(val, "result");
	gbt->json = res_val;

	hex2bin(hash_swap, previousblockhash, 32);
	swap_256(tmp, hash_swap);
	__bin2hex(gbt->prevhash, tmp, 32);

	strncpy(gbt->target, target, 65);

	hex2bin(hash_swap, target, 32);
	bswap_256(tmp, hash_swap);
	gbt->diff = diff_from_target((uchar *)tmp);
	json_object_set_new_nocheck(gbt->json, "diff", json_real(gbt->diff));

	gbt->version = version;

	gbt->curtime = curtime;

	snprintf(gbt->ntime, 9, "%08x", curtime);
	json_object_set_new_nocheck(gbt->json, "ntime", json_string_nocheck(gbt->ntime));
	sscanf(gbt->ntime, "%x", &gbt->ntime32);

	snprintf(gbt->bbversion, 9, "%08x", version);
	json_object_set_new_nocheck(gbt->json, "bbversion", json_string_nocheck(gbt->bbversion));

	snprintf(gbt->nbit, 9, "%s", bits);
	json_object_set_new_nocheck(gbt->json, "nbit", json_string_nocheck(gbt->nbit));

	gbt->coinbasevalue = coinbasevalue;

	gbt->height = height;

	gbt->flags = strdup(flags);

	ret = true;
out:
	return ret;
}

void clear_gbtbase(gbtbase_t *gbt)
{
	free(gbt->flags);
	if (gbt->json)
		json_decref(gbt->json);
	memset(gbt, 0, sizeof(gbtbase_t));
}

static const char *blockcount_req = "{\"method\": \"getblockcount\"}\n";

/* Request getblockcount from bitcoind, returning the count or -1 if the call
 * fails. */
int get_blockcount(connsock_t *cs)
{
	json_t *val, *res_val;
	int ret = -1;

	val = json_rpc_call(cs, blockcount_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getblockcount", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockcount");
		goto out;
	}
	ret = json_integer_value(res_val);
out:
	json_decref(val);
	return ret;
}

/* Request getblockhash from bitcoind for height, writing the value into *hash
 * which should be at least 65 bytes long since the hash is 64 chars. */
bool get_blockhash(connsock_t *cs, int height, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	char rpc_req[128];
	bool ret = false;

	sprintf(rpc_req, "{\"method\": \"getblockhash\", \"params\": [%d]}\n", height);
	val = json_rpc_call(cs, rpc_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getblockhash", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

static const char *bestblockhash_req = "{\"method\": \"getbestblockhash\"}\n";

/* Request getbestblockhash from bitcoind. bitcoind 0.9+ only */
bool get_bestblockhash(connsock_t *cs, char *hash)
{
	json_t *val, *res_val;
	const char *res_ret;
	bool ret = false;

	val = json_rpc_call(cs, bestblockhash_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to getbestblockhash", cs->url, cs->port);
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to getbestblockhash");
		goto out;
	}
	res_ret = json_string_value(res_val);
	if (!res_ret || !strlen(res_ret)) {
		LOGWARNING("Got null string in result to getbestblockhash");
		goto out;
	}
	strncpy(hash, res_ret, 65);
	ret = true;
out:
	json_decref(val);
	return ret;
}

bool submit_block(connsock_t *cs, const char *params)
{
	json_t *val, *res_val;
	int len, retries = 0;
	const char *res_ret;
	bool ret = false;
	char *rpc_req;

	len = strlen(params) + 64;
retry:
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"submitblock\", \"params\": [\"%s\"]}\n", params);
	val = json_rpc_call(cs, rpc_req);
	dealloc(rpc_req);
	if (!val) {
		LOGWARNING("%s:%s Failed to get valid json response to submitblock", cs->url, cs->port);
		if (++retries < 5)
			goto retry;
		return ret;
	}
	res_val = json_object_get(val, "result");
	if (!res_val) {
		LOGWARNING("Failed to get result in json response to submitblock");
		if (++retries < 5) {
			json_decref(val);
			goto retry;
		}
		goto out;
	}
	if (!json_is_null(res_val)) {
		res_ret = json_string_value(res_val);
		if (res_ret && strlen(res_ret)) {
			LOGWARNING("SUBMIT BLOCK RETURNED: %s", res_ret);
			/* Consider duplicate response as an accepted block */
			if (safecmp(res_ret, "duplicate"))
				goto out;
		} else {
			LOGWARNING("SUBMIT BLOCK GOT NO RESPONSE!");
			goto out;
		}
	}
	LOGWARNING("BLOCK ACCEPTED!");
	ret = true;
out:
	json_decref(val);
	return ret;
}

void precious_block(connsock_t *cs, const char *params)
{
	char *rpc_req;
	int len;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to submit_txn due to connsock dead");
		return;
	}

	len = strlen(params) + 64;
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"preciousblock\", \"params\": [\"%s\"]}\n", params);
	json_rpc_msg(cs, rpc_req);
	dealloc(rpc_req);
}

void submit_txn(connsock_t *cs, const char *params)
{
	char *rpc_req;
	int len;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to submit_txn due to connsock dead");
		return;
	}

	len = strlen(params) + 64;
	rpc_req = ckalloc(len);
	sprintf(rpc_req, "{\"method\": \"sendrawtransaction\", \"params\": [\"%s\"]}\n", params);
	json_rpc_msg(cs, rpc_req);
	dealloc(rpc_req);
}

char *get_txn(connsock_t *cs, const char *hash)
{
	char *rpc_req, *ret = NULL;
	json_t *val, *res_val;

	if (unlikely(!cs->alive)) {
		LOGDEBUG("Failed to get_txn due to connsock dead");
		goto out;
	}

	ASPRINTF(&rpc_req, "{\"method\": \"getrawtransaction\", \"params\": [\"%s\"]}\n", hash);
	val = json_rpc_response(cs, rpc_req);
	dealloc(rpc_req);
	if (!val) {
		LOGDEBUG("%s:%s Failed to get valid json response to get_txn", cs->url, cs->port);
		goto out;
	}
	res_val = json_object_get(val, "result");
	if (res_val && !json_is_null(res_val) && json_is_string(res_val)) {
		ret = strdup(json_string_value(res_val));
		LOGDEBUG("get_txn for hash %s got data %s", hash, ret);
	} else
		LOGDEBUG("get_txn did not retrieve data for hash %s", hash);
	json_decref(val);
out:
	return ret;
}
