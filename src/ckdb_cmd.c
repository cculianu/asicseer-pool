/*
 * Copyright 1995-2016 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "ckdb.h"

/*
 * Allow overriding the username however the username must still be present
 * This should ONLY be used for web reporting cmds i.e. read only
 * Current PHP allows this for a hard coded user
 */
static INTRANSIENT *adminuser(K_TREE *trf_root, char *reply, size_t siz)
{
	INTRANSIENT *in_username, *in_admin;
	char reply2[1024] = "";

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				 (char *)userpatt, reply, siz);
	if (!in_username)
		return NULL;

	in_admin = optional_in(trf_root, "admin", MIN_USERNAME,
				(char *)userpatt, reply2, sizeof(reply2));
	if (in_admin)
		return in_admin;

	return in_username;
}

static char *cmd_adduser(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			 char *code, char *inet, __maybe_unused tv_t *notcd,
			 K_TREE *trf_root, __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_emailaddress, *i_passwordhash, *u_item = NULL;
	INTRANSIENT *in_username;
	int event = EVENT_OK;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				(char *)userpatt, reply, siz);
	if (!in_username)
		return strdup(reply);

	/* If a username added from the web site looks like an address
	 *  then disallow it - a false positive is not an issue
	 * Allowing it will create a security issue - someone could create
	 *  an account with someone else's, as yet unused, payout address
	 *  and redirect the payout to another payout address.
	 *  ... and the person who owns the payout address can't check that
	 *  in advance, they'll just find out with their first payout not
	 *  arriving at their payout address */
	if (!like_address(in_username->str)) {
		i_emailaddress = require_name(trf_root, "emailaddress", 7,
					      (char *)mailpatt, reply, siz);
		if (!i_emailaddress)
			return strdup(reply);

		i_passwordhash = require_name(trf_root, "passwordhash", 64,
					      (char *)hashpatt, reply, siz);
		if (!i_passwordhash)
			return strdup(reply);

		event = events_add(EVENTID_CREACC, trf_root);
		if (event == EVENT_OK) {
			u_item = users_add(conn, in_username,
						 transfer_data(i_emailaddress),
						 transfer_data(i_passwordhash),
						 NULL, 0, by, code, inet, now,
						 trf_root);
		}
	}

	if (!u_item) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return reply_event(event, "failed.DBE");
	}
	LOGDEBUG("%s.ok.added %s", id, in_username->str);
	snprintf(reply, siz, "ok.added %s", in_username->str);
	return strdup(reply);
}

static char *cmd_newpass(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *cd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_username, *i_oldhash, *i_newhash, *i_2fa, *u_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	bool ok = true;
	char *oldhash;
	int32_t value;
	USERS *users;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", MIN_USERNAME,
				  (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_oldhash = optional_name(trf_root, "oldhash", 64, (char *)hashpatt,
				  reply, siz);
	if (i_oldhash)
		oldhash = transfer_data(i_oldhash);
	else {
		// fail if the oldhash is invalid
		if (*reply)
			ok = false;
		oldhash = EMPTY;
	}

	i_2fa = require_name(trf_root, "2fa", 1, (char *)intpatt, reply, siz);
	if (!i_2fa) {
		event = events_add(EVENTID_INV2FA, trf_root);
		return reply_event(event, reply);
	}

	if (ok) {
		i_newhash = require_name(trf_root, "newhash",
					 64, (char *)hashpatt,
					 reply, siz);
		if (!i_newhash)
			return strdup(reply);

		K_RLOCK(users_free);
		u_item = find_users(transfer_data(i_username));
		K_RUNLOCK(users_free);

		if (u_item) {
			DATA_USERS(users, u_item);
			if (USER_TOTP_ENA(users)) {
				value = (int32_t)atoi(transfer_data(i_2fa));
				ok = check_2fa(users, value);
				if (!ok)
					event = events_add(EVENTID_WRONG2FA, trf_root);
			}
			if (ok) {
				ok = users_update(NULL,
						  u_item,
						  oldhash,
						  transfer_data(i_newhash),
						  NULL,
						  by, code, inet, now,
						  trf_root,
						  NULL, &event);
			}
		} else
			ok = false;
	}

	if (!ok) {
		LOGERR("%s.failed.%s", id, transfer_data(i_username));
		return reply_event(event, "failed.");
	}
	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return strdup("ok.");
}

static char *cmd_chkpass(__maybe_unused PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_username, *i_passwordhash, *i_2fa, *u_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	USERS *users;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", MIN_USERNAME,
				  (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	i_passwordhash = require_name(trf_root, "passwordhash", 64, (char *)hashpatt, reply, siz);
	if (!i_passwordhash)
		return strdup(reply);

	i_2fa = require_name(trf_root, "2fa", 1, (char *)intpatt, reply, siz);
	if (!i_2fa) {
		event = events_add(EVENTID_INV2FA, trf_root);
		return reply_event(event, reply);
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		event = events_add(EVENTID_INVUSER, trf_root);
		ok = false;
	} else {
		DATA_USERS(users, u_item);
		ok = check_hash(users, transfer_data(i_passwordhash));
		if (!ok)
			event = events_add(EVENTID_PASSFAIL, trf_root);
		if (ok && USER_TOTP_ENA(users)) {
			uint32_t value = (int32_t)atoi(transfer_data(i_2fa));
			ok = check_2fa(users, value);
			if (!ok)
				event = events_add(EVENTID_WRONG2FA, trf_root);
		}
	}

	if (!ok) {
		LOGERR("%s.failed.%s", id, transfer_data(i_username));
		return reply_event(event, "failed.");
	}
	LOGDEBUG("%s.ok.%s", id, transfer_data(i_username));
	return strdup("ok.");
}

static char *cmd_2fa(__maybe_unused PGconn *conn, char *cmd, char *id,
		     tv_t *now, char *by, char *code, char *inet,
		     __maybe_unused tv_t *notcd, K_TREE *trf_root,
		     __maybe_unused bool reload_data)
{
	K_ITEM *i_username, *i_action, *i_entropy, *i_value, *u_item, *u_new;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	size_t len, off;
	char tmp[1024];
	int32_t entropy, value;
	USERS *users;
	char *action, *buf = NULL, *st = NULL;
	char *sfa_status = EMPTY, *sfa_error = EMPTY, *sfa_msg = EMPTY;
	bool ok = false, key = false;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = require_name(trf_root, "username", MIN_USERNAME,
				  (char *)userpatt, reply, siz);
	if (!i_username)
		return strdup(reply);

	// Field always expected, blank means to report the status
	i_action = require_name(trf_root, "action", 0, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	/* Field always expected with a value,
	 * but the value is only used when generating a Secret Key */
	i_entropy = require_name(trf_root, "entropy", 1, (char *)intpatt,
				 reply, siz);
	if (!i_entropy)
		return strdup(reply);

	// Field always expected, use 0 if not required
	i_value = require_name(trf_root, "value", 1, (char *)intpatt,
				reply, siz);
	if (!i_value) {
		event = events_add(EVENTID_INV2FA, trf_root);
		return reply_event(event, reply);
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (u_item) {
		DATA_USERS(users, u_item);

		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");

		switch (users->databits & (USER_TOTPAUTH | USER_TEST2FA)) {
			case 0:
				break;
			case USER_TOTPAUTH:
				sfa_status = "ok";
				break;
			case (USER_TOTPAUTH | USER_TEST2FA):
				sfa_status = "test";
				key = true;
				break;
			default:
				// USER_TEST2FA only <- currently invalid
				LOGERR("%s() users databits invalid for "
					"'%s/%"PRId64,
					__func__,
					st = safe_text_nonull(users->in_username),
					users->databits);
				FREENULL(st);
				goto dame;
		}

		if (!*action) {
			ok = true;
		} else if (strcmp(action, "setup") == 0) {
			// Can't setup if anything is already present -> new
			if (users->databits & (USER_TOTPAUTH | USER_TEST2FA))
				goto dame;
			entropy = (int32_t)atoi(transfer_data(i_entropy));
			u_new = gen_2fa_key(u_item, entropy, by, code, inet,
					    now, trf_root);
			if (u_new) {
				ok = true;
				sfa_status = "test";
				key = true;
				u_item = u_new;
				DATA_USERS(users, u_item);
			}
		} else if (strcmp(action, "test") == 0) {
			// Can't test if it's not ready to test
			if ((users->databits & (USER_TOTPAUTH | USER_TEST2FA))
			    != (USER_TOTPAUTH | USER_TEST2FA))
				goto dame;
			value = (int32_t)atoi(transfer_data(i_value));
			ok = tst_2fa(u_item, value, by, code, inet, now,
				     trf_root);
			if (!ok)
				sfa_error = "Invalid code";
			else {
				key = false;
				sfa_status = "ok";
				sfa_msg = "2FA Enabled";
			}
			// Report sfa_error to web
			ok = true;
		} else if (strcmp(action, "untest") == 0) {
			// Can't untest if it's not ready to test
			if ((users->databits & (USER_TOTPAUTH | USER_TEST2FA))
			    != (USER_TOTPAUTH | USER_TEST2FA))
				goto dame;
			// since it's currently test, the value isn't required
			u_new = remove_2fa(u_item, 0, by, code, inet, now,
					   trf_root, false);
			if (u_new) {
				ok = true;
				sfa_status = EMPTY;
				key = false;
				sfa_msg = "2FA Cancelled";
			}
		} else if (strcmp(action, "new") == 0) {
			// Can't new if 2FA isn't already present -> setup
			if ((users->databits & USER_TOTPAUTH) == 0)
				goto dame;
			value = (int32_t)atoi(transfer_data(i_value));
			if (!check_2fa(users, value)) {
				event = events_add(EVENTID_WRONG2FA, trf_root);
				sfa_error = "Invalid code";
				// Report sfa_error to web
				ok = true;
			} else {
				entropy = (int32_t)atoi(transfer_data(i_entropy));
				u_new = gen_2fa_key(u_item, entropy, by, code,
						    inet, now, trf_root);
				if (u_new) {
					ok = true;
					sfa_status = "test";
					key = true;
					u_item = u_new;
					DATA_USERS(users, u_item);
				}
			}
		} else if (strcmp(action, "remove") == 0) {
			// Can't remove if 2FA isn't already present
			if (!(users->databits & (USER_TOTPAUTH | USER_TEST2FA)))
				goto dame;
			// remove requires value
			value = (int32_t)atoi(transfer_data(i_value));
			if (!check_2fa(users, value)) {
				event = events_add(EVENTID_WRONG2FA, trf_root);
				sfa_error = "Invalid code";
				// Report sfa_error to web
				ok = true;
			} else {
				/* already tested 2fa so don't retest, also,
				 *  a retest will fail using the same value */
				u_new = remove_2fa(u_item, value, by, code,
						   inet, now, trf_root, false);
				if (u_new) {
					ok = true;
					sfa_status = EMPTY;
					key = false;
					sfa_msg = "2FA Removed";
				}
			}
		}
		if (key) {
			char *keystr, *issuer = "KanoCKDB";
			char cd_buf[DATE_BUFSIZ];
			unsigned char *bin;
			OPTIONCONTROL *oc;
			K_ITEM *oc_item;
			size_t binlen;
			bin = users_userdata_get_bin(users,
						     USER_TOTPAUTH_NAME,
						     USER_TOTPAUTH,
						     &binlen);
			if (binlen != TOTPAUTH_KEYSIZE) {
				LOGERR("%s() invalid key for '%s/%s "
					"len(%d) != %d",
					__func__,
					st = safe_text_nonull(users->in_username),
					USER_TOTPAUTH_NAME, (int)binlen,
					TOTPAUTH_KEYSIZE);
				FREENULL(st);
			}
			if (bin && binlen == TOTPAUTH_KEYSIZE) {
				keystr = tob32(users, bin, binlen,
						USER_TOTPAUTH_NAME,
						TOTPAUTH_DSP_KEYSIZE);
				snprintf(tmp, sizeof(tmp), "2fa_key=%s%c",
					 keystr, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				FREENULL(keystr);

				oc_item = find_optioncontrol(TOTPAUTH_ISSUER,
							     now,
							     OPTIONCONTROL_HEIGHT);
				if (oc_item) {
					DATA_OPTIONCONTROL(oc, oc_item);
					issuer = oc->optionvalue;
				} else {
					tv_to_buf(now, cd_buf, sizeof(cd_buf));
					LOGEMERG("%s(): missing optioncontrol "
						 "%s (%s/%d)",
						 __func__, TOTPAUTH_ISSUER,
						 cd_buf, OPTIONCONTROL_HEIGHT);
				}

				// TODO: add issuer to optioncontrol
				snprintf(tmp, sizeof(tmp),
					 "2fa_auth=%s%c2fa_hash=%s%c"
					 "2fa_time=%d%c2fa_issuer=%s%c",
					 TOTPAUTH_AUTH, FLDSEP,
					 TOTPAUTH_HASH, FLDSEP,
					 TOTPAUTH_TIME, FLDSEP,
					 issuer, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}
			FREENULL(bin);
		}
	}

	if (!ok) {
dame:
		// Only db/php/code errors should get here
		LOGERR("%s.failed.%s-%s", id, transfer_data(i_username), action);
		FREENULL(buf);
		return reply_event(event, "failed.");
	}

	snprintf(tmp, sizeof(tmp), "2fa_status=%s%c2fa_error=%s%c2fa_msg=%s",
				   sfa_status, FLDSEP, sfa_error, FLDSEP,
				   sfa_msg);
	APPEND_REALLOC(buf, off, len, tmp);
	LOGDEBUG("%s.%s-%s.%s", id, transfer_data(i_username), action, buf);
	return reply_event_free(event, buf);
}

static char *cmd_userset(PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	INTRANSIENT *in_username;
	K_ITEM *i_passwordhash, *i_2fa, *i_rows, *i_address;
	K_ITEM *i_ratio, *i_payname, *i_email, *u_item, *pa_item, *old_pa_item;
	K_ITEM *ua_item = NULL;
	USERATTS *useratts = NULL;
	char *email, *address, *payname;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	char tmp[1024];
	PAYMENTADDRESSES *row, *pa;
	K_STORE *pa_store = NULL;
	K_TREE_CTX ctx[1];
	USERS *users;
	char *reason = NULL;
	char *answer = NULL;
	char *ret = NULL;
	size_t len, off;
	int32_t ratio;
	int rows, i, limit;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				 (char *)userpatt, reply, siz);
	if (!in_username) {
		// For web this message is detailed enough
		reason = "System error";
		goto struckout;
	}

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);

	if (!u_item) {
		event = events_add(EVENTID_UNKATTS, trf_root);
		reason = "Unknown user";
		goto struckout;
	} else {
		DATA_USERS(users, u_item);
		i_passwordhash = optional_name(trf_root, "passwordhash",
						64, (char *)hashpatt,
						reply, siz);
		if (*reply) {
			reason = "Invalid data";
			goto struckout;
		}

		K_RLOCK(useratts_free);
		ua_item = find_useratts(users->userid, USER_MULTI_PAYOUT);
		K_RUNLOCK(useratts_free);
		if (!ua_item)
			limit = 1;
		else {
			DATA_USERATTS(useratts, ua_item);
			if (useratts->attnum > 0)
				limit = (int)(useratts->attnum);
			else
				limit = USER_ADDR_LIMIT;
		}

		if (!i_passwordhash) {
			APPEND_REALLOC_INIT(answer, off, len);
			snprintf(tmp, sizeof(tmp), "email=%s%c",
				 users->emailaddress, FLDSEP);
			APPEND_REALLOC(answer, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "limit=%d%c", limit, FLDSEP);
			APPEND_REALLOC(answer, off, len, tmp);

			K_RLOCK(paymentaddresses_free);
			pa_item = find_paymentaddresses(users->userid, ctx);
			rows = 0;
			if (pa_item) {
				DATA_PAYMENTADDRESSES(row, pa_item);
				while (pa_item && CURRENT(&(row->expirydate)) &&
				       row->userid == users->userid) {
					snprintf(tmp, sizeof(tmp), "addr:%d=%s%c",
						 rows, row->in_payaddress, FLDSEP);
					APPEND_REALLOC(answer, off, len, tmp);
					snprintf(tmp, sizeof(tmp), "ratio:%d=%d%c",
						 rows, row->payratio, FLDSEP);
					APPEND_REALLOC(answer, off, len, tmp);
					snprintf(tmp, sizeof(tmp), "payname:%d=%s%c",
						 rows, row->payname, FLDSEP);
					APPEND_REALLOC(answer, off, len, tmp);
					rows++;

					pa_item = prev_in_ktree(ctx);
					DATA_PAYMENTADDRESSES_NULL(row, pa_item);
				}
			}
			K_RUNLOCK(paymentaddresses_free);

			snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				 rows, FLDSEP,
				 "addr,ratio,payname", FLDSEP);
			APPEND_REALLOC(answer, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s",
				 "PaymentAddresses", FLDSEP, "");
			APPEND_REALLOC(answer, off, len, tmp);
		} else {
			i_2fa = require_name(trf_root, "2fa", 1, (char *)intpatt,
					      reply, siz);
			if (!i_2fa) {
				event = events_add(EVENTID_INV2FA, trf_root);
				reason = "Invalid data";
				goto struckout;
			}

			if (!check_hash(users, transfer_data(i_passwordhash))) {
				event = events_add(EVENTID_PASSFAIL, trf_root);
				reason = "Incorrect password";
				goto struckout;
			}

			if (USER_TOTP_ENA(users)) {
				uint32_t value = (int32_t)atoi(transfer_data(i_2fa));
				if (!check_2fa(users, value)) {
					event = events_add(EVENTID_WRONG2FA, trf_root);
					reason = "Invalid data";
					goto struckout;
				}
			}

			i_email = optional_name(trf_root, "email",
						1, (char *)mailpatt,
						reply, siz);
			if (i_email)
				email = transfer_data(i_email);
			else {
				if (*reply) {
					reason = "Invalid email";
					goto struckout;
				}
				email = NULL;
			}

			// address rows
			i_rows = optional_name(trf_root, "rows",
					       1, (char *)intpatt,
					       reply, siz);
			if (!i_rows && *reply) {
				// Exists, but invalid
				reason = "System error";
				goto struckout;
			}
			if (i_rows) {
				rows = atoi(transfer_data(i_rows));
				if (rows < 0)  {
					reason = "System error";
					goto struckout;
				}
				if (rows > 0) {
					pa_store = k_new_store(paymentaddresses_free);
					K_WLOCK(paymentaddresses_free);
					// discard any extras above the limit
					for (i = 0; i < rows && pa_store->count < limit; i++) {
						snprintf(tmp, sizeof(tmp), "ratio:%d", i);
						i_ratio = optional_name(trf_root, tmp,
									1, (char *)intpatt,
									reply, siz);
						if (*reply) {
							K_WUNLOCK(paymentaddresses_free);
							reason = "Invalid ratio";
							goto struckout;
						}
						if (i_ratio)
							ratio = atoi(transfer_data(i_ratio));
						else
							ratio = PAYRATIODEF;

						/* 0 = expire/remove the address
						 * intpatt means it will be >= 0 */
						if (ratio == 0)
							continue;

						// This name won't be intransient
						snprintf(tmp, sizeof(tmp), "address:%d", i);
						i_address = require_name(trf_root, tmp,
									 ADDR_MIN_LEN,
									 (char *)addrpatt,
									 reply, siz);
						if (!i_address) {
							K_WUNLOCK(paymentaddresses_free);
							event = events_add(EVENTID_INCBTC,
									   trf_root);
							reason = "Invalid address";
							goto struckout;
						}
						address = transfer_data(i_address);
						pa_item = STORE_HEAD_NOLOCK(pa_store);
						while (pa_item) {
							DATA_PAYMENTADDRESSES(row, pa_item);
							if (strcmp(row->in_payaddress, address) == 0) {
								K_WUNLOCK(paymentaddresses_free);
								reason = "Duplicate address";
								goto struckout;
							}
							pa_item = pa_item->next;
						}
						snprintf(tmp, sizeof(tmp), "payname:%d", i);
						i_payname = optional_name(trf_root, tmp,
									  0, NULL,
									  reply, siz);
						if (i_payname)
							payname = transfer_data(i_payname);
						else
							payname = EMPTY;
						pa_item = k_unlink_head(paymentaddresses_free);
						DATA_PAYMENTADDRESSES(row, pa_item);
						bzero(row, sizeof(*row));
						row->in_payaddress = intransient_str("payaddress", address);
						row->payratio = ratio;
						STRNCPY(row->payname, payname);
						k_add_head(pa_store, pa_item);
					}
					K_WUNLOCK(paymentaddresses_free);
				}
			}
			/* If all addresses have a ratio of zero
			 * pa_store->count will be 0 */
			if ((email == NULL || *email == '\0') &&
			    (pa_store == NULL || pa_store->count == 0)) {
				reason = "Missing/Invalid value";
				goto struckout;
			}

			if (pa_store && pa_store->count > 0) {
				pa_item = STORE_HEAD_NOLOCK(pa_store);
				while (pa_item) {
					DATA_PAYMENTADDRESSES(row, pa_item);
					// Only EVER validate addresses once ... for now
					K_RLOCK(paymentaddresses_free);
					old_pa_item = find_any_payaddress(row->in_payaddress);
					K_RUNLOCK(paymentaddresses_free);
					if (old_pa_item) {
						/* This test effectively means that
						 * two users can never add the same
						 * payout address */
						DATA_PAYMENTADDRESSES(pa, old_pa_item);
						if (pa->userid != users->userid) {
							event = events_add(EVENTID_BTCUSED,
									   trf_root);
							reason = "Unavailable BTC address";
							goto struckout;
						}
					} else if (!btc_valid_address(row->in_payaddress)) {
						event = events_add(EVENTID_INVBTC,
								   trf_root);
						reason = "Invalid BTC address";
						goto struckout;
					}
					pa_item = pa_item->next;
				}
			}

			if (email && *email) {
				ok = users_update(conn, u_item,
							NULL, NULL,
							email,
							by, code, inet, now,
							trf_root,
							NULL, &event);
				if (!ok) {
					reason = "email error";
					goto struckout;
				}
			}

			if (pa_store && pa_store->count > 0) {
				ok = paymentaddresses_set(conn, users->userid,
								pa_store, by,
								code, inet, now,
								trf_root);
				if (!ok) {
					reason = "address error";
					goto struckout;
				}
			}
			answer = strdup("updated");
		}
	}

struckout:
	if (pa_store) {
		if (pa_store->count) {
			K_WLOCK(paymentaddresses_free);
			k_list_transfer_to_head(pa_store, paymentaddresses_free);
			K_WUNLOCK(paymentaddresses_free);
		}
		k_free_store(pa_store);
		pa_store = NULL;
	}
	if (reason) {
		char *user, *st = NULL;
		snprintf(reply, siz, "ERR.%s", reason);
		if (in_username)
			user = st = safe_text(in_username->str);
		else
			user = EMPTY;
		LOGERR("%s.%s.%s (%s)", cmd, id, reply, user);
		FREENULL(st);
		return reply_event(event, reply);
	}
	APPEND_REALLOC_INIT(ret, off, len);
	APPEND_REALLOC(ret, off, len, "ok.");
	APPEND_REALLOC(ret, off, len, answer);
	free(answer);
	LOGDEBUG("%s.%s", id, ret);
	return reply_event_free(event, ret);
}

static char *cmd_workerset(PGconn *conn, char *cmd, char *id, tv_t *now,
			   char *by, char *code, char *inet, tv_t *cd,
			   K_TREE *trf_root, __maybe_unused bool reload_data)
{
	K_ITEM *i_username, *i_workername, *i_diffdef, *i_oldworkers;
	K_ITEM *u_item, *ua_item, *w_item;
	HEARTBEATQUEUE *heartbeatqueue;
	K_ITEM *hq_item;
	char workername_buf[32]; // 'workername:' + digits
	char diffdef_buf[32]; // 'difficultydefault:' + digits
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	USERATTS *useratts;
	WORKERS *workers;
	USERS *users;
	int ovent = OVENT_OK, done;
	int32_t difficultydefault;
	char *reason = NULL;
	char *answer = NULL;
	int workernum;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	ovent = ovents_add(OVENTID_WORKERS, trf_root);
	if (ovent != OVENT_OK) {
		snprintf(reply, siz, "ERR");
		return reply_ovent(ovent, reply);
	}

	i_username = require_name(trf_root, "username", MIN_USERNAME,
				  (char *)userpatt, reply, siz);
	if (!i_username) {
		// For web this message is detailed enough
		reason = "System error";
		goto struckout;
	}

	K_RLOCK(users_free);
	u_item = find_users(transfer_data(i_username));
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto struckout;
	} else {
		DATA_USERS(users, u_item);

		// Default answer if no problems
		answer = strdup("updated");

		i_oldworkers = optional_name(trf_root, "oldworkers",
					     1, NULL, reply, siz);
		if (i_oldworkers) {
			bool update = false;
			int64_t new_ow = atol(transfer_data(i_oldworkers));

			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, USER_OLD_WORKERS);
			K_RUNLOCK(useratts_free);
			if (!ua_item) {
				if (new_ow != USER_OLD_WORKERS_DEFAULT)
					update = true;
			} else {
				DATA_USERATTS(useratts, ua_item);
				if (new_ow != useratts->attnum)
					update = true;
			}
			if (update) {
				ua_item = useratts_add(conn, users->in_username,
							USER_OLD_WORKERS, EMPTY,
							EMPTY, EMPTY,
							transfer_data(i_oldworkers),
							EMPTY, EMPTY, EMPTY,
							by, code, inet, cd,
							trf_root, false);
				if (!ua_item)
					reason = "Invalid";
			}
			goto kazuki;
		}

		done = 0;
		// Loop through the list of workers and do any changes
		for (workernum = 0; workernum < 9999; workernum++) {
			snprintf(workername_buf, sizeof(workername_buf),
				 "workername:%d", workernum);

			i_workername = optional_name(trf_root, workername_buf,
							1, NULL, reply, siz);
			if (!i_workername)
				break;

			// More than 1?
			if (done++ == 1) {
				ovent = ovents_add(OVENTID_MULTIADDR, trf_root);
				if (ovent != OVENT_OK) {
					if (answer)
						free(answer);
					snprintf(reply, siz, "ERR");
					return reply_ovent(ovent, reply);
				}
			}

			w_item = find_workers(false, users->userid,
					      transfer_data(i_workername));
			// Abort if any dont exist
			if (!w_item) {
				reason = "Unknown worker";
				break;
			}

			DATA_WORKERS(workers, w_item);

			snprintf(diffdef_buf, sizeof(diffdef_buf),
				 "difficultydefault:%d", workernum);

			i_diffdef = optional_name(trf_root, diffdef_buf,
						    1, (char *)intpatt,
						    reply, siz);

			// Abort if any are invalid
			if (*reply) {
				reason = "Invalid diff";
				break;
			}

			if (!i_diffdef)
				continue;

			difficultydefault = atoi(transfer_data(i_diffdef));
			if (difficultydefault != 0) {
				if (difficultydefault < DIFFICULTYDEFAULT_MIN)
					difficultydefault = DIFFICULTYDEFAULT_MIN;
				if (difficultydefault > DIFFICULTYDEFAULT_MAX)
					difficultydefault = DIFFICULTYDEFAULT_MAX;
			}

			if (workers->difficultydefault != difficultydefault) {
				/* This uses a seperate txn per update
				    thus will update all up to a failure
				   Since the web then re-gets the values,
				    it will show what was updated */
				workers->difficultydefault = difficultydefault;
				ok = workers_update(conn, w_item, NULL, NULL,
							  NULL, by, code, inet,
							  now, trf_root, false);
				if (!ok) {
					reason = "DB error";
					break;
				}

				/* workerset is not from a log file,
				   so always queue it */
				K_WLOCK(heartbeatqueue_free);
				hq_item = k_unlink_head(heartbeatqueue_free);
				K_WUNLOCK(heartbeatqueue_free);

				DATA_HEARTBEATQUEUE(heartbeatqueue, hq_item);
				heartbeatqueue->in_workername = workers->in_workername;
				heartbeatqueue->difficultydefault = workers->difficultydefault;
				copy_tv(&(heartbeatqueue->createdate), now);

				K_WLOCK(heartbeatqueue_free);
				k_add_tail(heartbeatqueue_store, hq_item);
				K_WUNLOCK(heartbeatqueue_free);
			}
		}
		// Only 1?
		if (done == 1) {
			ovent = ovents_add(OVENTID_ONEADDR, trf_root);
			if (ovent != OVENT_OK) {
				if (answer)
					free(answer);
				snprintf(reply, siz, "ERR");
				return reply_ovent(ovent, reply);
			}
		}
	}

kazuki:
struckout:
	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

static char *cmd_poolstats_do(PGconn *conn, char *cmd, char *id, char *by,
			      char *code, char *inet, tv_t *cd, bool igndup,
			      K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_TREE_CTX ctx[1];
	bool store;

	// log to logfile

	K_ITEM *i_elapsed, *i_users, *i_workers;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	INTRANSIENT *in_poolinstance;
	K_ITEM look, *ps;
	POOLSTATS row, *poolstats;
	bool ok = false;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_poolinstance = require_in(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!in_poolinstance)
		return strdup(reply);

	if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
		POOLINSTANCE_DATA_SET(poolstats, in_poolinstance->str);
		return strdup(FAILED_PI);
	}

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		i_elapsed = &poolstats_elapsed;

	i_users = require_name(trf_root, "users", 1, NULL, reply, siz);
	if (!i_users)
		return strdup(reply);

	i_workers = require_name(trf_root, "workers", 1, NULL, reply, siz);
	if (!i_workers)
		return strdup(reply);

	i_hashrate = require_name(trf_root, "hashrate", 1, NULL, reply, siz);
	if (!i_hashrate)
		return strdup(reply);

	i_hashrate5m = require_name(trf_root, "hashrate5m", 1, NULL, reply, siz);
	if (!i_hashrate5m)
		return strdup(reply);

	i_hashrate1hr = require_name(trf_root, "hashrate1hr", 1, NULL, reply, siz);
	if (!i_hashrate1hr)
		return strdup(reply);

	i_hashrate24hr = require_name(trf_root, "hashrate24hr", 1, NULL, reply, siz);
	if (!i_hashrate24hr)
		return strdup(reply);

	row.in_poolinstance = in_poolinstance->str;
	row.createdate.tv_sec = date_eot.tv_sec;
	row.createdate.tv_usec = date_eot.tv_usec;
	INIT_POOLSTATS(&look);
	look.data = (void *)(&row);
	K_RLOCK(poolstats_free);
	ps = find_before_in_ktree(poolstats_root, &look, ctx);
	K_RUNLOCK(poolstats_free);
	if (!ps)
		store = true;
	else {
		DATA_POOLSTATS(poolstats, ps);
		// Find last stored matching the poolinstance and less than STATS_PER old
		while (ps && !poolstats->stored &&
		       INTREQ(row.in_poolinstance, poolstats->in_poolinstance) &&
		       tvdiff(cd, &(poolstats->createdate)) < STATS_PER) {
				ps = prev_in_ktree(ctx);
				DATA_POOLSTATS_NULL(poolstats, ps);
		}

		if (!ps || !poolstats->stored ||
		    !INTREQ(row.in_poolinstance, poolstats->in_poolinstance) ||
		    tvdiff(cd, &(poolstats->createdate)) >= STATS_PER)
			store = true;
		else
			store = false;
	}

	ok = poolstats_add(conn, store, in_poolinstance,
					transfer_data(i_elapsed),
					transfer_data(i_users),
					transfer_data(i_workers),
					transfer_data(i_hashrate),
					transfer_data(i_hashrate5m),
					transfer_data(i_hashrate1hr),
					transfer_data(i_hashrate24hr),
					by, code, inet, cd, igndup, trf_root);

	if (!ok) {
		if (!igndup)
			LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	LOGDEBUG("%s.ok.", id);
	snprintf(reply, siz, "ok.");
	return strdup(reply);
}

static char *cmd_poolstats(PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *notnow, char *by,
			   char *code, char *inet, tv_t *cd,
			   K_TREE *trf_root, __maybe_unused bool reload_data)
{
	bool igndup = false;

	/* confirm_summaries() doesn't call this
	 * We don't care about dups during reload since poolstats_fill()
	 * doesn't load all the data */
	if (reloading)
		igndup = true;

	return cmd_poolstats_do(conn, cmd, id, by, code, inet, cd, igndup, trf_root);
}

static char *cmd_userstats(__maybe_unused PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *notnow, char *by, char *code,
			   char *inet, tv_t *cd, K_TREE *trf_root,
			   __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);

	// log to logfile

	K_ITEM *i_elapsed, *i_username;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	INTRANSIENT *in_poolinstance;
	K_ITEM *i_eos, *i_idle;
	INTRANSIENT *in_workername;
	bool ok = false, idle, eos;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_poolinstance = require_in(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!in_poolinstance)
		return strdup(reply);

	if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
		POOLINSTANCE_DATA_SET(userstats, in_poolinstance->str);
		return strdup(FAILED_PI);
	}

	i_elapsed = optional_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		i_elapsed = &userstats_elapsed;

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	in_workername = optional_in(trf_root, "workername", 1, NULL, reply, siz);
	if (!in_workername)
		in_workername = userstats_workername;

	i_hashrate = require_name(trf_root, "hashrate", 1, NULL, reply, siz);
	if (!i_hashrate)
		return strdup(reply);

	i_hashrate5m = require_name(trf_root, "hashrate5m", 1, NULL, reply, siz);
	if (!i_hashrate5m)
		return strdup(reply);

	i_hashrate1hr = require_name(trf_root, "hashrate1hr", 1, NULL, reply, siz);
	if (!i_hashrate1hr)
		return strdup(reply);

	i_hashrate24hr = require_name(trf_root, "hashrate24hr", 1, NULL, reply, siz);
	if (!i_hashrate24hr)
		return strdup(reply);

	i_idle = optional_name(trf_root, "idle", 1, NULL, reply, siz);
	if (!i_idle)
		i_idle = &userstats_idle;

	idle = (strcasecmp(transfer_data(i_idle), TRUE_STR) == 0);

	i_eos = optional_name(trf_root, "eos", 1, NULL, reply, siz);
	if (!i_eos)
		i_eos = &userstats_eos;

	eos = (strcasecmp(transfer_data(i_eos), TRUE_STR) == 0);

	ok = userstats_add(in_poolinstance,
			   transfer_data(i_elapsed),
			   transfer_data(i_username),
			   in_workername,
			   transfer_data(i_hashrate),
			   transfer_data(i_hashrate5m),
			   transfer_data(i_hashrate1hr),
			   transfer_data(i_hashrate24hr),
			   idle, eos, by, code, inet, cd, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DATA", __func__, id);
		return strdup("failed.DATA");
	}
	LOGDEBUG("%s.ok.", id);
	snprintf(reply, siz, "ok.");
	return strdup(reply);
}

static char *cmd_workerstats(__maybe_unused PGconn *conn, char *cmd, char *id,
			     __maybe_unused tv_t *notnow, char *by, char *code,
			     char *inet, tv_t *cd, K_TREE *trf_root,
			     __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);

	// log to logfile

	K_ITEM *i_elapsed, *i_username;
	K_ITEM *i_hashrate, *i_hashrate5m, *i_hashrate1hr, *i_hashrate24hr;
	INTRANSIENT *in_poolinstance;
	K_ITEM *i_idle, *i_instances;
	INTRANSIENT *in_workername;
	bool ok = false, idle;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_poolinstance = require_in(trf_root, "poolinstance", 1, NULL, reply, siz);
	if (!in_poolinstance)
		return strdup(reply);

	if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
		POOLINSTANCE_DATA_SET(workerstats, in_poolinstance->str);
		return strdup(FAILED_PI);
	}

	i_elapsed = require_name(trf_root, "elapsed", 1, NULL, reply, siz);
	if (!i_elapsed)
		return strdup(reply);

	i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
	if (!i_username)
		return strdup(reply);

	in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
	if (!in_workername)
		return strdup(reply);

	i_hashrate = require_name(trf_root, "hashrate", 1, NULL, reply, siz);
	if (!i_hashrate)
		return strdup(reply);

	i_hashrate5m = require_name(trf_root, "hashrate5m", 1, NULL, reply, siz);
	if (!i_hashrate5m)
		return strdup(reply);

	i_hashrate1hr = require_name(trf_root, "hashrate1hr", 1, NULL, reply, siz);
	if (!i_hashrate1hr)
		return strdup(reply);

	i_hashrate24hr = require_name(trf_root, "hashrate24hr", 1, NULL, reply, siz);
	if (!i_hashrate24hr)
		return strdup(reply);

	i_idle = require_name(trf_root, "idle", 1, NULL, reply, siz);
	if (!i_idle)
		return strdup(reply);

	idle = (strcasecmp(transfer_data(i_idle), TRUE_STR) == 0);

	i_instances = optional_name(trf_root, "instances", 1, NULL, reply, siz);

	ok = workerstats_add(in_poolinstance,
			     transfer_data(i_elapsed),
			     transfer_data(i_username),
			     in_workername,
			     transfer_data(i_hashrate),
			     transfer_data(i_hashrate5m),
			     transfer_data(i_hashrate1hr),
			     transfer_data(i_hashrate24hr), idle,
			     i_instances ? transfer_data(i_instances) : NULL,
			     by, code, inet, cd, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DATA", __func__, id);
		return strdup("failed.DATA");
	}
	LOGDEBUG("%s.ok.", id);
	snprintf(reply, siz, "ok.");
	return strdup(reply);
}

static char *cmd_blocklist(__maybe_unused PGconn *conn, char *cmd, char *id,
			   tv_t *now, __maybe_unused char *by,
			   __maybe_unused char *code, __maybe_unused char *inet,
			   __maybe_unused tv_t *notcd,
			   __maybe_unused K_TREE *trf_root,
			   __maybe_unused bool reload_data)
{
	int ovent = OVENT_OK;
	K_TREE_CTX ctx[1];
	K_ITEM *b_item;
	BLOCKS *blocks;
	char reply[1024] = "";
	char tmp[1024];
	char *buf, *desc, desc_buf[64];
	size_t len, off;
	tv_t stats_tv = {0,0}, stats_tv2 = {0,0};
	int rows, srows, tot, seq;
	int64_t maxrows;
	bool has_stats;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	ovent = ovents_add(OVENTID_BLOCKS, trf_root);
	if (ovent != OVENT_OK) {
		snprintf(reply, sizeof(reply), "ERR");
		return reply_ovent(ovent, reply);
	}

	maxrows = sys_setting(BLOCKS_SETTING_NAME, BLOCKS_DEFAULT, now);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

redo:
	has_stats = check_update_blocks_stats(&stats_tv);

	srows = rows = 0;
	K_RLOCK(blocks_free);
	b_item = first_in_ktree(blocks_root, ctx);
	tot = 0;
	while (b_item) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate))) {
			if (blocks->confirmed[0] != BLOCKS_ORPHAN &&
			    blocks->confirmed[0] != BLOCKS_REJECT)
				tot++;
		}
		b_item = next_in_ktree(ctx);
	}
	seq = tot;
	b_item = last_in_ktree(blocks_root, ctx);
	while (b_item && rows < (int)maxrows) {
		DATA_BLOCKS(blocks, b_item);
		if (CURRENT(&(blocks->expirydate))) {
			if (blocks->confirmed[0] == BLOCKS_ORPHAN ||
			    blocks->confirmed[0] == BLOCKS_REJECT) {
				snprintf(tmp, sizeof(tmp),
					 "seq:%d=%c%c",
					 rows,
					 blocks->confirmed[0] == BLOCKS_ORPHAN ?
						'o' : 'r',
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp),
					 "seq:%d=%d%c",
					 rows, seq--, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}
			int_to_buf(blocks->height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			dbhash2btchash(blocks->blockhash, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "blockhash:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(blocks->nonce, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "nonce:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(blocks->reward, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "reward:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(blocks->in_workername, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "workername:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			// When block was found
			snprintf(tmp, sizeof(tmp),
				 "first"CDTRF":%d=%ld%c", rows,
				 blocks->blockcreatedate.tv_sec, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			// Last time block was updated
			snprintf(tmp, sizeof(tmp),
				 CDTRF":%d=%ld%c", rows,
				 blocks->createdate.tv_sec, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			// When previous valid block was found
			snprintf(tmp, sizeof(tmp),
				 "prev"CDTRF":%d=%ld%c", rows,
				 blocks->prevcreatedate.tv_sec, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "confirmed:%d=%s%cstatus:%d=%s%c", rows,
				 blocks->confirmed, FLDSEP, rows,
				 blocks_confirmed(blocks->confirmed), FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "info:%d=%s%c", rows,
				 blocks->info, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp),
				 "statsconf:%d=%s%c", rows,
				 blocks->statsconfirmed, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->diffacc, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "diffacc:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->diffinv, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "diffinv:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->shareacc, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shareacc:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(blocks->shareinv, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shareinv:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(blocks->elapsed, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "elapsed:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			if (has_stats) {
				snprintf(tmp, sizeof(tmp),
					 "netdiff:%d=%.8f%cdiffratio:%d=%.8f%c"
					 "cdf:%d=%.8f%cluck:%d=%.8f%c"
					 "luckhistory:%d=%.8f%c",
					 rows, blocks->netdiff, FLDSEP,
					 rows, blocks->blockdiffratio, FLDSEP,
					 rows, blocks->blockcdf, FLDSEP,
					 rows, blocks->blockluck, FLDSEP,
					 rows, blocks->luckhistory, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			} else {
				snprintf(tmp, sizeof(tmp),
					 "netdiff:%d=?%cdiffratio:%d=?%c"
					 "cdf:%d=?%cluck:%d=?%c"
					 "luckhistory:%d=?%c",
					 rows, FLDSEP, rows, FLDSEP,
					 rows, FLDSEP, rows, FLDSEP,
					 rows, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}

			rows++;
		}
		b_item = prev_in_ktree(ctx);
	}
	if (has_stats) {
		seq = tot;
		b_item = last_in_ktree(blocks_root, ctx);
		while (b_item) {
			DATA_BLOCKS(blocks, b_item);
			if (CURRENT(&(blocks->expirydate)) &&
			    blocks->confirmed[0] != BLOCKS_ORPHAN &&
			    blocks->confirmed[0] != BLOCKS_REJECT) {
				desc = NULL;
				if (seq == 1) {
					snprintf(desc_buf, sizeof(desc_buf),
						 "All - Last %d", tot);
					desc = desc_buf;
				} else if (seq == tot - 4) {
					desc = "Last 5";
				} else if (seq == tot - 9) {
					desc = "Last 10";
				} else if (seq == tot - 24) {
					desc = "Last 25";
				} else if (seq == tot - 49) {
					desc = "Last 50";
				} else if (seq == tot - 99) {
					desc = "Last 100";
				} else if (seq == tot - 249) {
					desc = "Last 250";
				} else if (seq == tot - 499) {
					desc = "Last 500";
				} else if (seq == tot - 999) {
					desc = "Last 1000";
				}
				if (desc) {
					snprintf(tmp, sizeof(tmp),
						 "s_seq:%d=%d%c"
						 "s_desc:%d=%s%c"
						 "s_height:%d=%d%c"
						 "s_"CDTRF":%d=%ld%c"
						 "s_prev"CDTRF":%d=%ld%c"
						 "s_diffratio:%d=%.8f%c"
						 "s_diffmean:%d=%.8f%c"
						 "s_cdferl:%d=%.8f%c"
						 "s_luck:%d=%.8f%c"
						 "s_txmean:%d=%.8f%c",
						 srows, seq, FLDSEP,
						 srows, desc, FLDSEP,
						 srows, (int)(blocks->height), FLDSEP,
						 srows, blocks->blockcreatedate.tv_sec, FLDSEP,
						 srows, blocks->prevcreatedate.tv_sec, FLDSEP,
						 srows, blocks->diffratio, FLDSEP,
						 srows, blocks->diffmean, FLDSEP,
						 srows, blocks->cdferl, FLDSEP,
						 srows, blocks->luck, FLDSEP,
						 srows, blocks->txmean, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					srows++;
				}
				seq--;
			}
			b_item = prev_in_ktree(ctx);
		}
		copy_tv(&stats_tv2, &blocks_stats_time);
	}
	K_RUNLOCK(blocks_free);

	// Only check for a redo if we used the stats values
	if (has_stats) {
		/* If the stats changed then redo with the new corrected values
		 * This isn't likely at all, but it guarantees the blocks
		 *  page shows correct information since any code that wants
		 *  to modify the blocks table must have it under write lock
		 *  then flag the stats as needing to be recalculated */
		if (!tv_equal(&stats_tv, &stats_tv2)) {
			APPEND_REALLOC_RESET(buf, off);
			goto redo;
		}
	}

	snprintf(tmp, sizeof(tmp),
		 "s_rows=%d%cs_flds=%s%c",
		 srows, FLDSEP,
		 "s_seq,s_desc,s_height,s_"CDTRF",s_prev"CDTRF",s_diffratio,"
		 "s_diffmean,s_cdferl,s_luck,s_txmean",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp),
		 "historysize=%d%crows=%d%cflds=%s%c",
		 LUCKNUM, FLDSEP, rows, FLDSEP,
		 "seq,height,blockhash,nonce,reward,workername,first"CDTRF","
		 CDTRF",prev"CDTRF",confirmed,status,info,statsconf,diffacc,"
		 "diffinv,shareacc,shareinv,elapsed,netdiff,diffratio,cdf,luck,"
		 "luckhistory",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Blocks,BlockStats", FLDSEP, ",s");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%d_blocks", id, rows);
	return buf;
}

static char *cmd_blockstatus(PGconn *conn, char *cmd, char *id, tv_t *now,
			     char *by, char *code, char *inet,
			     __maybe_unused tv_t *cd, K_TREE *trf_root,
			     __maybe_unused bool reload_data)
{
	K_ITEM *i_height, *i_blockhash, *i_action, *i_info;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *b_item;
	BLOCKS *blocks;
	int32_t height;
	char *action, *info, *tmp;
	bool ok = false;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);

	TXT_TO_INT("height", transfer_data(i_height), height);

	i_blockhash = require_name(trf_root, "blockhash", 1, NULL, reply, siz);
	if (!i_blockhash)
		return strdup(reply);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);

	action = transfer_data(i_action);

	K_RLOCK(blocks_free);
	b_item = find_blocks(height, transfer_data(i_blockhash), NULL);
	K_RUNLOCK(blocks_free);

	if (!b_item) {
		snprintf(reply, siz, "ERR.unknown block");
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	DATA_BLOCKS(blocks, b_item);

	// Default to previous value
	info = blocks->info;

	if (strcasecmp(action, "orphan") == 0) {
		switch (blocks->confirmed[0]) {
			case BLOCKS_NEW:
			case BLOCKS_CONFIRM:
				ok = blocks_add(conn, height,
						      blocks->blockhash,
						      BLOCKS_ORPHAN_STR, info,
						      EMPTY, EMPTY, NULL, EMPTY,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      by, code, inet, now, false, id,
						      trf_root);
				if (!ok) {
					snprintf(reply, siz,
						 "DBE.action '%s'",
						 action);
					LOGERR("%s.%s", id, reply);
					return strdup(reply);
				}
				// TODO: reset the share counter?
				break;
			default:
				snprintf(reply, siz,
					 "ERR.invalid action '%.*s%s' for block state '%s'",
					 CMD_SIZ, action,
					 (strlen(action) > CMD_SIZ) ? "..." : "",
					 blocks_confirmed(blocks->confirmed));
				LOGERR("%s.%s", id, reply);
				return strdup(reply);
		}
	} else if (strcasecmp(action, "reject") == 0) {
		i_info = require_name(trf_root, "info", 0, (char *)strpatt,
				      reply, siz);
		if (!i_info)
			return strdup(reply);
		tmp = transfer_data(i_info);
		/* Override if not empty
		 * Thus you can't blank it out if current has a value */
		if (tmp && *tmp)
			info = tmp;

		switch (blocks->confirmed[0]) {
			case BLOCKS_NEW:
			case BLOCKS_CONFIRM:
			case BLOCKS_ORPHAN:
			case BLOCKS_REJECT:
				ok = blocks_add(conn, height,
						      blocks->blockhash,
						      BLOCKS_REJECT_STR, info,
						      EMPTY, EMPTY, NULL, EMPTY,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      by, code, inet, now, false, id,
						      trf_root);
				if (!ok) {
					snprintf(reply, siz,
						 "DBE.action '%s'",
						 action);
					LOGERR("%s.%s", id, reply);
					return strdup(reply);
				}
				// TODO: reset the share counter?
				break;
			default:
				snprintf(reply, siz,
					 "ERR.invalid action '%.*s%s' for block state '%s'",
					 CMD_SIZ, action,
					 (strlen(action) > CMD_SIZ) ? "..." : "",
					 blocks_confirmed(blocks->confirmed));
				LOGERR("%s.%s", id, reply);
				return strdup(reply);
		}
	} else if (strcasecmp(action, "confirm") == 0) {
		// Confirm a new block that wasn't confirmed due to some bug
		switch (blocks->confirmed[0]) {
			case BLOCKS_NEW:
				ok = blocks_add(conn, height,
						      blocks->blockhash,
						      BLOCKS_CONFIRM_STR, info,
						      EMPTY, EMPTY, NULL, EMPTY,
						      EMPTY, EMPTY, EMPTY, EMPTY,
						      by, code, inet, now, false, id,
						      trf_root);
				if (!ok) {
					snprintf(reply, siz,
						 "DBE.action '%s'",
						 action);
					LOGERR("%s.%s", id, reply);
					return strdup(reply);
				}
				// TODO: reset the share counter?
				break;
			default:
				snprintf(reply, siz,
					 "ERR.invalid action '%.*s%s' for block state '%s'",
					 CMD_SIZ, action,
					 (strlen(action) > CMD_SIZ) ? "..." : "",
					 blocks_confirmed(blocks->confirmed));
				LOGERR("%s.%s", id, reply);
				return strdup(reply);
		}
	} else {
		snprintf(reply, siz, "ERR.unknown action '%s'",
			 transfer_data(i_action));
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	snprintf(reply, siz, "ok.%s %d", transfer_data(i_action), height);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_newid(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			char *code, char *inet, __maybe_unused tv_t *cd,
			K_TREE *trf_root, __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_idname, *i_idvalue;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_idname = require_name(trf_root, "idname", 3, (char *)idpatt, reply, siz);
	if (!i_idname)
		return strdup(reply);

	i_idvalue = require_name(trf_root, "idvalue", 1, (char *)intpatt, reply, siz);
	if (!i_idvalue)
		return strdup(reply);

	ok = idcontrol_add(conn, transfer_data(i_idname),
				 transfer_data(i_idvalue),
				 by, code, inet, now, trf_root);

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	snprintf(reply, siz, "ok.added %s %s",
				transfer_data(i_idname),
				transfer_data(i_idvalue));
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_payments(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	K_ITEM *u_item, *p_item, *p2_item, *po_item;
	INTRANSIENT *in_username;
	K_TREE_CTX ctx[1];
	K_STORE *pay_store;
	PAYMENTS *payments, *last_payments = NULL;
	PAYOUTS *payouts;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	int rows;
	bool pok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = adminuser(trf_root, reply, siz);
	if (!in_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	pay_store = k_new_store(payments_free);
	K_WLOCK(payments_free);
	p_item = find_first_payments(users->userid, ctx);
	DATA_PAYMENTS_NULL(payments, p_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (p_item && payments->userid == users->userid) {
		if (CURRENT(&(payments->expirydate))) {
			if (!last_payments ||
			    payments->payoutid != last_payments->payoutid) {
				p2_item = k_unlink_head(payments_free);
				DATA_PAYMENTS_NULL(last_payments, p2_item);
				memcpy(last_payments, payments,
					sizeof(*last_payments));
				k_add_tail(pay_store, p2_item);
			} else {
				/* This is OK since it's a local store and
				 *  we don't use INTREQ() on it */
				last_payments->in_payaddress = "*Multiple";
				last_payments->amount += payments->amount;
			}
		}
		p_item = next_in_ktree(ctx);
		DATA_PAYMENTS_NULL(payments, p_item);
	}
	K_WUNLOCK(payments_free);

	p_item = STORE_HEAD_NOLOCK(pay_store);
	while (p_item) {
		DATA_PAYMENTS(payments, p_item);
		pok = false;
		K_RLOCK(payouts_free);
		po_item = find_payoutid(payments->payoutid);
		DATA_PAYOUTS_NULL(payouts, po_item);
		if (p_item && PAYGENERATED(payouts->status))
			pok = true;
		K_RUNLOCK(payouts_free);
		if (pok) {
			bigint_to_buf(payouts->payoutid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "payoutid:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			int_to_buf(payouts->height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(payments->in_payaddress, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "payaddress:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(payments->amount, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "amount:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			tv_to_buf(&(payments->paydate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "paydate:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;
		}
		p_item = p_item->next;
	}
	K_WLOCK(payments_free);
	k_list_transfer_to_head(pay_store, payments_free);
	K_WUNLOCK(payments_free);

	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payoutid,height,payaddress,amount,paydate", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Payments", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, in_username->str);
	return buf;
}

static char *cmd_percent(char *cmd, char *id, tv_t *now, USERS *users)
{
	K_ITEM w_look, *w_item, us_look, *us_item, *ws_item;
	K_TREE_CTX w_ctx[1], pay_ctx[1];
	WORKERS lookworkers, *workers;
	WORKERSTATUS *workerstatus;
	USERSTATS *userstats;
	char tmp[1024];
	char *buf;
	size_t len, off;
	int rows;

	double t_hashrate5m = 0, t_hashrate1hr = 0;
	double t_hashrate24hr = 0;
	double t_diffacc = 0, t_diffinv = 0;
	double t_diffsta = 0, t_diffdup = 0;
	double t_diffhi = 0, t_diffrej = 0;
	double t_shareacc = 0, t_shareinv = 0;
	double t_sharesta = 0, t_sharedup = 0;
	double t_sharehi = 0, t_sharerej = 0;

	K_ITEM *pa_item;
	PAYMENTADDRESSES *pa;
	int64_t paytotal;
	double ratio;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "blockreward=%"PRId64"%c",
				   pool.reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	INIT_WORKERS(&w_look);
	INIT_USERSTATS(&us_look);

	// Add up all user's worker stats to be divided into payout percentages
	lookworkers.userid = users->userid;
	lookworkers.in_workername = EMPTY;
	DATE_ZERO(&(lookworkers.expirydate));
	w_look.data = (void *)(&lookworkers);
	K_RLOCK(workers_free);
	w_item = find_after_in_ktree(workers_root, &w_look, w_ctx);
	K_RUNLOCK(workers_free);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			K_RLOCK(workerstatus_free);
			ws_item = find_workerstatus(true, users->userid,
						    workers->in_workername);
			if (ws_item) {
				DATA_WORKERSTATUS(workerstatus, ws_item);
				t_diffacc += workerstatus->block_diffacc;
				t_diffinv += workerstatus->block_diffinv;
				t_diffsta += workerstatus->block_diffsta;
				t_diffdup += workerstatus->block_diffdup;
				t_diffhi  += workerstatus->block_diffhi;
				t_diffrej += workerstatus->block_diffrej;
				t_shareacc += workerstatus->block_shareacc;
				t_shareinv += workerstatus->block_shareinv;
				t_sharesta += workerstatus->block_sharesta;
				t_sharedup += workerstatus->block_sharedup;
				t_sharehi += workerstatus->block_sharehi;
				t_sharerej += workerstatus->block_sharerej;
			}
			K_RUNLOCK(workerstatus_free);

			/* TODO: workers_root userid+worker is ordered
			 *  so no 'find' should be needed -
			 *  just cmp to last 'unused us_item' userid+worker
			 *  then step it forward to be the next ready 'unused' */
			K_RLOCK(userstats_free);
			us_item = find_userstats(users->userid, workers->in_workername);
			if (us_item) {
				DATA_USERSTATS(userstats, us_item);
				if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
					t_hashrate5m += userstats->hashrate5m;
					t_hashrate1hr += userstats->hashrate1hr;
					t_hashrate24hr += userstats->hashrate24hr;
				}
			}
			K_RUNLOCK(userstats_free);
		}
		K_RLOCK(workers_free);
		w_item = next_in_ktree(w_ctx);
		K_RUNLOCK(workers_free);
		DATA_WORKERS_NULL(workers, w_item);
	}

	// Calculate total payratio
	paytotal = 0;
	K_RLOCK(paymentaddresses_free);
	pa_item = find_paymentaddresses(users->userid, pay_ctx);
	DATA_PAYMENTADDRESSES(pa, pa_item);
	while (pa_item && CURRENT(&(pa->expirydate)) &&
	       pa->userid == users->userid) {
		paytotal += pa->payratio;
		pa_item = prev_in_ktree(pay_ctx);
		DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	}
	if (paytotal == 0)
		paytotal = 1;

	// Divide totals into payout percentages
	rows = 0;
	pa_item = find_paymentaddresses(users->userid, pay_ctx);
	DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	while (pa_item && CURRENT(&(pa->expirydate)) &&
	       pa->userid == users->userid) {
		ratio = (double)(pa->payratio) / (double)paytotal;

		snprintf(tmp, sizeof(tmp), "payaddress:%d=%s%c",
					   rows, pa->in_payaddress, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "payratio:%d=%"PRId32"%c",
					   rows, pa->payratio, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "paypercent:%d=%.6f%c",
					   rows, ratio * 100.0, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "payname:%d=%s%c",
					   rows, pa->payname, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate5m:%d=%.1f%c", rows,
					   (double)t_hashrate5m * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate1hr:%d=%.1f%c", rows,
					   (double)t_hashrate1hr * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_hashrate24hr:%d=%.1f%c", rows,
					   (double)t_hashrate24hr * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffacc:%d=%.1f%c", rows,
					   (double)t_diffacc * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffinv:%d=%.1f%c", rows,
					   (double)t_diffinv * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffsta:%d=%.1f%c", rows,
					   (double)t_diffsta * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffdup:%d=%.1f%c", rows,
					   (double)t_diffdup * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffhi:%d=%.1f%c", rows,
					   (double)t_diffhi * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_diffrej:%d=%.1f%c", rows,
					   (double)t_diffrej * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_shareacc:%d=%.1f%c", rows,
					   (double)t_shareacc * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_shareinv:%d=%.1f%c", rows,
					   (double)t_shareinv * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharesta:%d=%.1f%c", rows,
					   (double)t_sharesta * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharedup:%d=%.1f%c", rows,
					   (double)t_sharedup * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharehi:%d=%.1f%c", rows,
					   (double)t_sharehi * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "p_sharerej:%d=%.1f%c", rows,
					   (double)t_sharerej * ratio,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		rows++;

		pa_item = prev_in_ktree(pay_ctx);
		DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
	}
	K_RUNLOCK(paymentaddresses_free);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payaddress,payratio,paypercent,payname,"
		 "p_hashrate5m,p_hashrate1hr,p_hashrate24hr,"
		 "p_diffacc,p_diffinv,"
		 "p_diffsta,p_diffdup,p_diffhi,p_diffrej,"
		 "p_shareacc,p_shareinv,"
		 "p_sharesta,p_sharedup,p_sharehi,p_sharerej",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Percents", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, users->in_username);
	return buf;
}

static char *cmd_workers(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_stats, *i_percent, w_look, *u_item, *w_item;
	K_ITEM *ua_item, *us_item, *ws_item;
	INTRANSIENT *in_username;
	K_TREE_CTX w_ctx[1];
	WORKERS lookworkers, *workers;
	WORKERSTATUS *workerstatus;
	USERSTATS *userstats;
	USERATTS *useratts;
	USERS *users;
	int ovent = OVENT_OK;
	char reply[1024] = "";
	char tmp[1024];
	int64_t oldworkers = USER_OLD_WORKERS_DEFAULT;
	size_t siz = sizeof(reply);
	tv_t last_share;
	char *buf;
	size_t len, off;
	bool stats, percent;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	ovent = ovents_add(OVENTID_WORKERS, trf_root);
	if (ovent != OVENT_OK) {
		snprintf(reply, siz, "ERR");
		return reply_ovent(ovent, reply);
	}

	in_username = adminuser(trf_root, reply, siz);
	if (!in_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	i_stats = optional_name(trf_root, "stats", 1, NULL, reply, siz);
	if (!i_stats)
		stats = false;
	else
		stats = (strcasecmp(transfer_data(i_stats), TRUE_STR) == 0);

	percent = false;
	K_RLOCK(useratts_free);
	ua_item = find_useratts(users->userid, USER_MULTI_PAYOUT);
	K_RUNLOCK(useratts_free);
	if (ua_item) {
		i_percent = optional_name(trf_root, "percent", 1, NULL, reply, siz);
		if (i_percent)
			percent = (strcasecmp(transfer_data(i_stats), TRUE_STR) == 0);
	}

	if (percent)
		return cmd_percent(cmd, id, now, users);

	K_RLOCK(useratts_free);
	ua_item = find_useratts(users->userid, USER_OLD_WORKERS);
	K_RUNLOCK(useratts_free);
	if (ua_item) {
		DATA_USERATTS(useratts, ua_item);
		oldworkers = useratts->attnum;
	}

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "blockreward=%"PRId64"%c",
				   pool.reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "oldworkers=%"PRId64"%c",
				   oldworkers, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	if (oldworkers > 0)
		oldworkers *= 24L * 60L * 60L;
	else
		oldworkers = now->tv_sec + 1;

	INIT_WORKERS(&w_look);

	lookworkers.userid = users->userid;
	lookworkers.in_workername = EMPTY;
	DATE_ZERO(&(lookworkers.expirydate));
	w_look.data = (void *)(&lookworkers);
	K_RLOCK(workers_free);
	w_item = find_after_in_ktree(workers_root, &w_look, w_ctx);
	K_RUNLOCK(workers_free);
	DATA_WORKERS_NULL(workers, w_item);
	rows = 0;
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			K_RLOCK(workerstatus_free);
			ws_item = find_workerstatus(true, users->userid,
						    workers->in_workername);
			if (ws_item) {
				DATA_WORKERSTATUS(workerstatus, ws_item);
				// good or bad - either means active
				copy_tv(&last_share, &(workerstatus->last_share));
			} else
				DATE_ZERO(&last_share);
			K_RUNLOCK(workerstatus_free);

			if (tvdiff(now, &last_share) < oldworkers) {
				str_to_buf(workers->in_workername, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "workername:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				int_to_buf(workers->difficultydefault, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "difficultydefault:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				str_to_buf(workers->idlenotificationenabled, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "idlenotificationenabled:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				int_to_buf(workers->idlenotificationtime, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "idlenotificationtime:%d=%s%c", rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				if (stats) {
					double w_hashrate5m, w_hashrate1hr;
					double w_hashrate24hr;
					int64_t w_elapsed;
					tv_t w_lastshare;
					tv_t w_lastshareacc;
					double w_lastdiffacc, w_diffacc;
					double w_diffinv;
					double w_diffsta, w_diffdup;
					double w_diffhi, w_diffrej;
					double w_shareacc, w_shareinv;
					double w_sharesta, w_sharedup;
					double w_sharehi, w_sharerej;
					double w_active_diffacc;
					tv_t w_active_start;
					int w_instances;

					w_hashrate5m = w_hashrate1hr =
					w_hashrate24hr = 0.0;
					w_elapsed = -1;
					w_instances = NO_INSTANCE_DATA;

					if (!ws_item) {
						w_lastshare.tv_sec =
						w_lastshareacc.tv_sec = 0L;
						w_lastdiffacc = w_diffacc =
						w_diffinv = w_diffsta =
						w_diffdup = w_diffhi =
						w_diffrej = w_shareacc =
						w_shareinv = w_sharesta =
						w_sharedup = w_sharehi =
						w_sharerej = w_active_diffacc = 0;
						w_active_start.tv_sec = 0L;
					} else {
						DATA_WORKERSTATUS(workerstatus, ws_item);
						// It's bad to read possibly changing data
						K_RLOCK(workerstatus_free);
						w_lastshare.tv_sec = workerstatus->last_share.tv_sec;
						w_lastshareacc.tv_sec = workerstatus->last_share_acc.tv_sec;
						w_lastdiffacc = workerstatus->last_diff_acc;
						w_diffacc = workerstatus->block_diffacc;
						w_diffinv = workerstatus->block_diffinv;
						w_diffsta = workerstatus->block_diffsta;
						w_diffdup = workerstatus->block_diffdup;
						w_diffhi  = workerstatus->block_diffhi;
						w_diffrej = workerstatus->block_diffrej;
						w_shareacc = workerstatus->block_shareacc;
						w_shareinv = workerstatus->block_shareinv;
						w_sharesta = workerstatus->block_sharesta;
						w_sharedup = workerstatus->block_sharedup;
						w_sharehi = workerstatus->block_sharehi;
						w_sharerej = workerstatus->block_sharerej;
						w_active_diffacc = workerstatus->active_diffacc;
						w_active_start.tv_sec = workerstatus->active_start.tv_sec;
						K_RUNLOCK(workerstatus_free);
					}

					/* TODO: workers_root userid+worker is ordered
					 *  so no 'find' should be needed -
					 *  just cmp to last 'unused us_item' userid+worker
					 *  then step it forward to be the next ready 'unused' */
					K_RLOCK(userstats_free);
					us_item = find_userstats(users->userid, workers->in_workername);
					if (us_item) {
						DATA_USERSTATS(userstats, us_item);
						if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
							w_hashrate5m += userstats->hashrate5m;
							w_hashrate1hr += userstats->hashrate1hr;
							w_hashrate24hr += userstats->hashrate24hr;
							if (w_elapsed == -1 || w_elapsed > userstats->elapsed)
								w_elapsed = userstats->elapsed;
							if (userstats->instances != NO_INSTANCE_DATA) {
								if (w_instances == NO_INSTANCE_DATA)
									w_instances = 0;
								w_instances += userstats->instances;
							}
						}
					}
					K_RUNLOCK(userstats_free);

					double_to_buf(w_hashrate5m, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_hashrate1hr, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_hashrate24hr, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_hashrate24hr:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					bigint_to_buf(w_elapsed, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_elapsed:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					int_to_buf((int)(w_lastshare.tv_sec), reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_lastshare:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					int_to_buf((int)(w_lastshareacc.tv_sec), reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_lastshareacc:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_lastdiffacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_lastdiff:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffacc:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffinv, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffinv:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffsta, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffsta:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffdup, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffdup:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffhi, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffhi:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_diffrej, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_diffrej:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_shareacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_shareacc:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_shareinv, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_shareinv:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_sharesta, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_sharesta:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_sharedup, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_sharedup:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_sharehi, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_sharehi:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_sharerej, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_sharerej:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(w_active_diffacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_active_diffacc:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					int_to_buf((int)(w_active_start.tv_sec), reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_active_start:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					int_to_buf(w_instances, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "w_instances:%d=%s%c", rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
				}
				rows++;
			}
		}
		K_RLOCK(workers_free);
		w_item = next_in_ktree(w_ctx);
		K_RUNLOCK(workers_free);
		DATA_WORKERS_NULL(workers, w_item);
	}
	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%s%c",
		 rows, FLDSEP,
		 "workername,difficultydefault,idlenotificationenabled,"
		 "idlenotificationtime",
		 stats ? ",w_hashrate5m,w_hashrate1hr,w_hashrate24hr,"
		 "w_elapsed,w_lastshare,w_lastshareacc,"
		 "w_lastdiff,w_diffacc,w_diffinv,"
		 "w_diffsta,w_diffdup,w_diffhi,w_diffrej,"
		 "w_shareacc,w_shareinv,"
		 "w_sharesta,w_sharedup,w_sharehi,w_sharerej,"
		 "w_active_diffacc,w_active_start,w_instances" : "",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Workers", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, in_username->str);
	return buf;
}

static char *cmd_allusers(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	K_STORE *usu_store = k_new_store(userstats_free);
	K_ITEM *us_item, *usu_item, *u_item;
	K_TREE_CTX us_ctx[1];
	USERSTATS *userstats, *userstats_u = NULL;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	char *buf;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	/* Sum up all recent userstats without workername
	 * i.e. userstasts per username */
	K_WLOCK(userstats_free);
	us_item = first_in_ktree(userstats_root, us_ctx);
	while (us_item) {
		DATA_USERSTATS(userstats, us_item);
		if (tvdiff(now, &(userstats->statsdate)) < ALLUSERS_LIMIT_S) {
			if (!userstats_u || userstats->userid != userstats_u->userid) {
				usu_item = k_unlink_head(userstats_free);
				DATA_USERSTATS(userstats_u, usu_item);

				userstats_u->userid = userstats->userid;
				/* Remember the first workername for if we ever
				 *  get the missing user LOGERR message below */
				userstats_u->in_workername = userstats->in_workername;
				userstats_u->hashrate5m = userstats->hashrate5m;
				userstats_u->hashrate1hr = userstats->hashrate1hr;
				userstats_u->instances = userstats->instances;

				k_add_head(usu_store, usu_item);
			} else {
				userstats_u->hashrate5m += userstats->hashrate5m;
				userstats_u->hashrate1hr += userstats->hashrate1hr;
				if (userstats->instances != NO_INSTANCE_DATA) {
					if ( userstats_u->instances == NO_INSTANCE_DATA)
						userstats_u->instances = 0;
					userstats_u->instances += userstats->instances;
				}
			}
		}
		us_item = next_in_ktree(us_ctx);
	}
	K_WUNLOCK(userstats_free);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	usu_item = STORE_HEAD_NOLOCK(usu_store);
	while (usu_item) {
		DATA_USERSTATS(userstats_u, usu_item);
		K_RLOCK(users_free);
		u_item = find_userid(userstats_u->userid);
		K_RUNLOCK(users_free);
		if (!u_item) {
			LOGERR("%s() userstats, but not users, "
			       "ignored %"PRId64"/%s",
			       __func__, userstats_u->userid,
			       userstats_u->in_workername);
		} else {
			DATA_USERS(users, u_item);
			str_to_buf(users->in_username, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "username:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			bigint_to_buf(users->userid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "userid:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(userstats_u->hashrate5m, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate5m:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			double_to_buf(userstats_u->hashrate1hr, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_hashrate1hr:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			int_to_buf(userstats_u->instances, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "u_instances:%d=%s%c", rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;
		}
		usu_item = usu_item->next;
	}

	K_WLOCK(userstats_free);
	k_list_transfer_to_head(usu_store, userstats_free);
	K_WUNLOCK(userstats_free);
	k_free_store(usu_store);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "username,userid,u_hashrate5m,u_hashrate1hr,u_instances",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Users", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.allusers", id);
	return buf;
}

static char *cmd_sharelog(PGconn *conn, char *cmd, char *id,
				__maybe_unused tv_t *notnow, char *by,
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root,
				__maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int64_t workinfoid;

	// log to logfile with processing success/failure code

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (strcasecmp(cmd, STR_WORKINFO) == 0) {
		K_ITEM *i_workinfoid, *i_transactiontree, *i_merklehash;
		K_ITEM *i_coinbase1, *i_coinbase2, *i_ntime, *i_reward;
		INTRANSIENT *in_poolinstance, *in_prevhash, *in_version, *in_bits;
		bool igndup = false;
		char *txn_tree;

		// nothing needed by key_update is triggered by the workinfo data
		if (key_update)
			goto wiconf;

		in_poolinstance = require_in(trf_root, "poolinstance", 1, NULL, reply, siz);
		if (!in_poolinstance)
			return strdup(reply);

		if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)){
			POOLINSTANCE_DATA_SET(workinfo, in_poolinstance->str);
			return strdup(FAILED_PI);
		}

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

		if (reloading && !confirm_sharesummary) {
			if (workinfoid <= dbstatus.newest_workinfoid)
				igndup = true;
		}

		if (confirm_sharesummary) {
			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto wiconf;
		}

		i_transactiontree = require_name(trf_root, "transactiontree", 0, NULL, reply, siz);
		if (!i_transactiontree)
			return strdup(reply);
		if (txn_tree_store)
			txn_tree = transfer_data(i_transactiontree);
		else
			txn_tree = EMPTY;

		i_merklehash = require_name(trf_root, "merklehash", 0, NULL, reply, siz);
		if (!i_merklehash)
			return strdup(reply);

		in_prevhash = require_in(trf_root, "prevhash", 1, NULL, reply, siz);
		if (!in_prevhash)
			return strdup(reply);

		i_coinbase1 = require_name(trf_root, "coinbase1", 1, NULL, reply, siz);
		if (!i_coinbase1)
			return strdup(reply);

		i_coinbase2 = require_name(trf_root, "coinbase2", 1, NULL, reply, siz);
		if (!i_coinbase2)
			return strdup(reply);

		in_version = require_in(trf_root, "version", 1, NULL, reply, siz);
		if (!in_version)
			return strdup(reply);

		in_bits = require_in(trf_root, "bits", 1, NULL, reply, siz);
		if (!in_bits)
			return strdup(reply);

		i_ntime = require_name(trf_root, "ntime", 1, NULL, reply, siz);
		if (!i_ntime)
			return strdup(reply);

		i_reward = require_name(trf_root, "reward", 1, NULL, reply, siz);
		if (!i_reward)
			return strdup(reply);

		workinfoid = workinfo_add(conn, transfer_data(i_workinfoid),
						in_poolinstance,
						txn_tree,
						transfer_data(i_merklehash),
						in_prevhash,
						transfer_data(i_coinbase1),
						transfer_data(i_coinbase2),
						in_version,
						in_bits,
						transfer_data(i_ntime),
						transfer_data(i_reward),
						by, code, inet, cd, igndup, trf_root);

		if (workinfoid == -1) {
			LOGERR("%s(%s) %s.failed.DBE", __func__, cmd, id);
			return strdup("failed.DBE");
		} else {
			// Only flag a successful workinfo
			ck_wlock(&last_lock);
			setnow(&last_workinfo);
			ck_wunlock(&last_lock);
		}
		LOGDEBUG("%s.ok.added %"PRId64, id, workinfoid);
wiconf:
		snprintf(reply, siz, "ok.%"PRId64, workinfoid);
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_SHARES) == 0) {
		K_ITEM *i_workinfoid, *i_username, *i_clientid, *i_errn;
		K_ITEM *i_enonce1, *i_nonce2, *i_nonce, *i_diff, *i_sdiff;
		K_ITEM *i_secondaryuserid, *i_ntime, *i_address, *i_agent;
		INTRANSIENT *in_workername;
		char *address, *agent;
		bool ok;

		i_nonce = require_name(trf_root, "nonce", 1, NULL, reply, siz);
		if (!i_nonce)
			return strdup(reply);

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

		if (reloading && !key_update && !confirm_sharesummary) {
			/* ISDR (Ignored shares during reload)
			 * This will discard any shares older than the newest
			 *  workinfoidend of any workmarker - including ready
			 *  but not processed workmarkers
			 * This means that if a workmarker needs re-processing
			 *  and all of it's shares need to be redone, that will
			 *  require a seperate procedure to the reload
			 *  This would be the (as yet non-existant)
			 *   confirm_markersummary which will replace the
			 *   now unusable confirm_sharesummary code
			 * However, if the workmarker simply just needs to be
			 *  flagged as processed, this avoids the problem of
			 *  duplicating shares before flagging it
			 */
			if (workinfoid <= dbstatus.newest_workmarker_workinfoid)
				return NULL;
		}

		if (key_update) {
			if (workinfoid < key_wi_stt || workinfoid > key_wi_fin)
				goto sconf;
		}

		if (confirm_sharesummary) {
			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto sconf;
		}

		i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
		if (!i_username)
			return strdup(reply);

		in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
		if (!in_workername)
			return strdup(reply);

		i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
		if (!i_clientid)
			return strdup(reply);

		i_errn = require_name(trf_root, "errn", 1, NULL, reply, siz);
		if (!i_errn)
			return strdup(reply);

		i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
		if (!i_enonce1)
			return strdup(reply);

		i_nonce2 = require_name(trf_root, "nonce2", 1, NULL, reply, siz);
		if (!i_nonce2)
			return strdup(reply);

		i_diff = require_name(trf_root, "diff", 1, NULL, reply, siz);
		if (!i_diff)
			return strdup(reply);

		i_sdiff = require_name(trf_root, "sdiff", 1, NULL, reply, siz);
		if (!i_sdiff)
			return strdup(reply);

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid",
						  1, NULL, reply, siz);
		if (!i_secondaryuserid)
			i_secondaryuserid = &shares_secondaryuserid;

		i_ntime = require_name(trf_root, "ntime", 1, NULL, reply, siz);
		if (!i_ntime)
			return strdup(reply);

		i_address = optional_name(trf_root, "address", 0, NULL, reply, siz);
		if (i_address)
			address = transfer_data(i_address);
		else
			address = EMPTY;

		i_agent = optional_name(trf_root, "agent", 0, NULL, reply, siz);
		if (i_agent)
			agent = transfer_data(i_agent);
		else
			agent = EMPTY;

		ok = shares_add(conn, transfer_data(i_workinfoid),
				      transfer_data(i_username),
				      in_workername,
				      transfer_data(i_clientid),
				      transfer_data(i_errn),
				      transfer_data(i_enonce1),
				      transfer_data(i_nonce2),
				      transfer_data(i_nonce),
				      transfer_data(i_diff),
				      transfer_data(i_sdiff),
				      transfer_data(i_secondaryuserid),
				      transfer_data(i_ntime), address, agent,
				      by, code, inet, cd, trf_root);

		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		} else {
			// Only flag a successful share
			int32_t errn;
			TXT_TO_INT("errn", transfer_data(i_errn), errn);
			ck_wlock(&last_lock);
			setnow(&last_share);
			if (errn == SE_NONE)
				copy_tv(&last_share_acc, &last_share);
			else
				copy_tv(&last_share_inv, &last_share);
			ck_wunlock(&last_lock);
		}
		LOGDEBUG("%s.ok.added %s", id, transfer_data(i_nonce));
sconf:
		snprintf(reply, siz, "ok.added %s", transfer_data(i_nonce));
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_SHAREERRORS) == 0) {
		K_ITEM *i_workinfoid, *i_username, *i_clientid, *i_errn;
		K_ITEM *i_error, *i_secondaryuserid;
		INTRANSIENT *in_workername;
		bool ok;

		// not summarised in keysummaries
		if (key_update)
			goto wiconf;

		i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
		if (!i_username)
			return strdup(reply);

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

		if (reloading && !confirm_sharesummary) {
			// See comment 'ISDR' above for shares
			if (workinfoid <= dbstatus.newest_workmarker_workinfoid)
				return NULL;
		}
		if (confirm_sharesummary) {
			TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto seconf;
		}

		in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
		if (!in_workername)
			return strdup(reply);

		i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
		if (!i_clientid)
			return strdup(reply);

		i_errn = require_name(trf_root, "errn", 1, NULL, reply, siz);
		if (!i_errn)
			return strdup(reply);

		i_error = require_name(trf_root, "error", 1, NULL, reply, siz);
		if (!i_error)
			return strdup(reply);

		i_secondaryuserid = optional_name(trf_root, "secondaryuserid",
						  1, NULL, reply, siz);
		if (!i_secondaryuserid)
			i_secondaryuserid = &shareerrors_secondaryuserid;

		ok = shareerrors_add(conn, transfer_data(i_workinfoid),
					   transfer_data(i_username),
					   in_workername,
					   transfer_data(i_clientid),
					   transfer_data(i_errn),
					   transfer_data(i_error),
					   transfer_data(i_secondaryuserid),
					   by, code, inet, cd, trf_root);
		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		}
		LOGDEBUG("%s.ok.added %s", id, transfer_data(i_username));
seconf:
		snprintf(reply, siz, "ok.added %s", transfer_data(i_username));
		return strdup(reply);
	} else if (strcasecmp(cmd, STR_AGEWORKINFO) == 0) {
		K_ITEM *i_workinfoid;
		INTRANSIENT *in_poolinstance;
		int64_t ss_count, s_count, s_diff;
		tv_t ss_first, ss_last;
		bool ok;

		in_poolinstance = require_in(trf_root, "poolinstance", 1, NULL, reply, siz);
		if (!in_poolinstance)
			return strdup(reply);

		if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
			POOLINSTANCE_DATA_SET(ageworkinfo, in_poolinstance->str);
			return strdup(FAILED_PI);
		}

		i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);

		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);

		if (reloading && !key_update && !confirm_sharesummary) {
			// This excludes any already summarised
			if (workinfoid <= dbstatus.newest_workmarker_workinfoid)
				return NULL;
		}

		if (key_update) {
			if (workinfoid < key_wi_stt || workinfoid > key_wi_fin)
				goto awconf;
		}

		if (confirm_sharesummary) {
			if (workinfoid < confirm_first_workinfoid ||
			    workinfoid > confirm_last_workinfoid)
				goto awconf;
		}

		ok = workinfo_age(workinfoid, in_poolinstance, cd, &ss_first,
				  &ss_last, &ss_count, &s_count, &s_diff);
		if (!ok) {
			LOGERR("%s(%s) %s.failed.DATA", __func__, cmd, id);
			return strdup("failed.DATA");
		} else {
			/* Don't slow down the reload - do them later,
			 *  unless it's a long reload since:
			 *   Any pool restarts in the reload data will cause
			 *    unaged workinfos and thus would stop marker() */
			if (!reloading || key_update || reloaded_N_files) {
				// Aging is a queued item thus the reply is ignored
				auto_age_older(workinfoid, in_poolinstance, cd);
			}
		}
		LOGDEBUG("%s.ok.aged %"PRId64, id, workinfoid);
awconf:
		snprintf(reply, siz, "ok.%"PRId64, workinfoid);
		return strdup(reply);
	}

	LOGERR("%s.bad.cmd %s", id, cmd);
	return strdup("bad.cmd");
}

// TODO: the confirm update: identify block changes from workinfo height?
static char *cmd_blocks_do(PGconn *conn, char *cmd, int32_t height, char *id,
			   char *by, char *code, char *inet, tv_t *cd,
			   bool igndup, K_TREE *trf_root)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_blockhash, *i_confirmed, *i_workinfoid, *i_username;
	K_ITEM *i_clientid, *i_enonce1, *i_nonce2, *i_nonce, *i_reward;
	INTRANSIENT *in_workername;
	TRANSFER *transfer;
	char *msg;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_blockhash = require_name(trf_root, "blockhash", 1, NULL, reply, siz);
	if (!i_blockhash)
		return strdup(reply);

	i_confirmed = require_name(trf_root, "confirmed", 1, NULL, reply, siz);
	if (!i_confirmed)
		return strdup(reply);

	DATA_TRANSFER(transfer, i_confirmed);
	transfer->mvalue[0] = tolower(transfer->mvalue[0]);
	switch(transfer->mvalue[0]) {
		case BLOCKS_NEW:
			i_workinfoid = require_name(trf_root, "workinfoid", 1, NULL, reply, siz);
			if (!i_workinfoid)
				return strdup(reply);

			i_username = require_name(trf_root, "username", 1, NULL, reply, siz);
			if (!i_username)
				return strdup(reply);

			in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
			if (!in_workername)
				return strdup(reply);

			i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
			if (!i_clientid)
				return strdup(reply);

			i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
			if (!i_enonce1)
				return strdup(reply);

			i_nonce2 = require_name(trf_root, "nonce2", 1, NULL, reply, siz);
			if (!i_nonce2)
				return strdup(reply);

			i_nonce = require_name(trf_root, "nonce", 1, NULL, reply, siz);
			if (!i_nonce)
				return strdup(reply);

			i_reward = require_name(trf_root, "reward", 1, NULL, reply, siz);
			if (!i_reward)
				return strdup(reply);

			msg = "added";
			ok = blocks_add(conn, height,
					      transfer_data(i_blockhash),
					      transfer_data(i_confirmed),
					      EMPTY,
					      transfer_data(i_workinfoid),
					      transfer_data(i_username),
					      in_workername,
					      transfer_data(i_clientid),
					      transfer_data(i_enonce1),
					      transfer_data(i_nonce2),
					      transfer_data(i_nonce),
					      transfer_data(i_reward),
					      by, code, inet, cd, igndup, id,
					      trf_root);
			break;
		case BLOCKS_CONFIRM:
			msg = "confirmed";
			ok = blocks_add(conn, height,
					      transfer_data(i_blockhash),
					      transfer_data(i_confirmed),
					      EMPTY,
					      EMPTY, EMPTY, NULL, EMPTY,
					      EMPTY, EMPTY, EMPTY, EMPTY,
					      by, code, inet, cd, igndup, id,
					      trf_root);
			break;
		default:
			LOGERR("%s(): %s.failed.invalid confirm='%s'",
			       __func__, id, transfer_data(i_confirmed));
			return strdup("failed.DATA");
	}

	if (!ok) {
		/* Ignore during startup,
		 * another error should have shown if it matters */
		if (startup_complete)
			LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}

	LOGDEBUG("%s.ok.blocks %s", id, msg);
	snprintf(reply, siz, "ok.%s", msg);
	return strdup(reply);
}

static char *cmd_blocks(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *notnow, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root, __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	bool igndup = false;
	K_ITEM *i_height;
	int32_t height;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);

	TXT_TO_INT("height", transfer_data(i_height), height);

	// confirm_summaries() doesn't call this
	if (reloading) {
		// Since they're blocks, just try them all
		if (height <= dbstatus.newest_height_blocks)
			igndup = true;
	}

	return cmd_blocks_do(conn, cmd, height, id, by, code, inet, cd, igndup,
				trf_root);
}

static char *cmd_auth_do(PGconn *conn, char *cmd, char *id, char *by,
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root, bool reload_data)
{
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	K_ITEM *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth, *u_item, *oc_item, *w_item;
	INTRANSIENT *in_poolinstance, *in_username, *in_workername;
	USERS *users = NULL;
	WORKERS *workers = NULL;
	OPTIONCONTROL *optioncontrol;
	size_t len, off;
	char *buf;
	bool ok = true, first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_poolinstance = optional_in(trf_root, "poolinstance", 1, NULL,
					reply, siz);
	if (!in_poolinstance) {
		if (sys_poolinstance) {
			in_poolinstance = get_intransient("poolinstance",
							  (char *)sys_poolinstance);
		} else
			in_poolinstance = in_empty;
	} else {
		if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
			POOLINSTANCE_DATA_SET(auth, in_poolinstance->str);
			return strdup(FAILED_PI);
		}
	}

	in_username = require_in(trf_root, "username", 1, NULL, reply, siz);
	if (!in_username)
		return strdup(reply);

	in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
	if (!in_workername)
		return strdup(reply);

	i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
	if (!i_clientid)
		return strdup(reply);

	i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
	if (!i_enonce1)
		return strdup(reply);

	i_useragent = require_name(trf_root, "useragent", 0, NULL, reply, siz);
	if (!i_useragent)
		return strdup(reply);

	i_preauth = optional_name(trf_root, "preauth", 1, NULL, reply, siz);
	if (!i_preauth)
		i_preauth = &auth_preauth;

	oc_item = find_optioncontrol(OPTIONCONTROL_AUTOADDUSER, cd, pool.height);
	if (oc_item) {
		K_RLOCK(users_free);
		u_item = find_users(in_username->str);
		K_RUNLOCK(users_free);
		if (!u_item) {
			if (!reload_data)
				event = events_add(EVENTID_AUTOACC, trf_root);
			if (event == EVENT_OK) {
				DATA_OPTIONCONTROL(optioncontrol, oc_item);
				u_item = users_add(conn, in_username, EMPTY,
						   optioncontrol->optionvalue,
						   NULL, 0, by, code, inet, cd,
						   trf_root);
			} else
				ok = false;
		}
	}

	if (ok) {
		ok = auths_add(conn, in_poolinstance,
				     in_username, in_workername,
				     transfer_data(i_clientid),
				     transfer_data(i_enonce1),
				     transfer_data(i_useragent),
				     transfer_data(i_preauth),
				     by, code, inet, cd, trf_root, false,
				     &users, &workers, &event, reload_data);
	}

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return reply_event(event, "failed.DBE");
	}

	// Only flag a successful auth
	ck_wlock(&last_lock);
	setnow(&last_auth);
	ck_wunlock(&last_lock);

	if (switch_state < SWITCH_STATE_AUTHWORKERS) {
		snprintf(reply, siz,
			 "ok.authorise={\"secondaryuserid\":\"%s\","
			 "\"difficultydefault\":%d}",
			 users->secondaryuserid, workers->difficultydefault);
		LOGDEBUG("%s.%s", id, reply);
		return strdup(reply);
	}

	APPEND_REALLOC_INIT(buf, off, len);
	snprintf(reply, siz,
		 "ok.authorise={\"secondaryuserid\":\"%s\","
		 "\"workers\":[",
		 users->secondaryuserid);
	APPEND_REALLOC(buf, off, len, reply);
	first = true;
	K_RLOCK(workers_free);
	w_item = first_workers(users->userid, ctx);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			snprintf(reply, siz,
				 "%s{\"workername\":\"%s\","
				 "\"difficultydefault\":%"PRId32"}",
				 first ? EMPTY : ",",
				 workers->in_workername,
				 workers->difficultydefault);
			APPEND_REALLOC(buf, off, len, reply);
			first = false;
		}
		w_item = next_in_ktree(ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}
	K_RUNLOCK(workers_free);
	APPEND_REALLOC(buf, off, len, "]}");

	LOGDEBUG("%s.%s", id, buf);
	return buf;
}

static char *cmd_auth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root, bool reload_data)
{
	return cmd_auth_do(conn, cmd, id, by, code, inet, cd, trf_root,
				reload_data);
}

static char *cmd_addrauth_do(PGconn *conn, char *cmd, char *id, char *by,
				char *code, char *inet, tv_t *cd,
				K_TREE *trf_root, bool reload_data)
{
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	K_ITEM *i_clientid;
	K_ITEM *i_enonce1, *i_useragent, *i_preauth, *w_item;
	INTRANSIENT *in_poolinstance, *in_username, *in_workername;
	USERS *users = NULL;
	WORKERS *workers = NULL;
	size_t len, off;
	char *buf;
	bool ok, first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_poolinstance = optional_in(trf_root, "poolinstance", 1, NULL,
					reply, siz);
	if (!in_poolinstance) {
		if (sys_poolinstance) {
			in_poolinstance = get_intransient("poolinstance",
							  (char *)sys_poolinstance);
		} else
			in_poolinstance = in_empty;
	} else {
		if (sys_poolinstance && strcmp(sys_poolinstance, in_poolinstance->str)) {
			POOLINSTANCE_DATA_SET(addrauth, in_poolinstance->str);
			return strdup(FAILED_PI);
		}
	}

	in_username = require_in(trf_root, "username", 1, NULL, reply, siz);
	if (!in_username)
		return strdup(reply);

	in_workername = require_in(trf_root, "workername", 1, NULL, reply, siz);
	if (!in_workername)
		return strdup(reply);

	i_clientid = require_name(trf_root, "clientid", 1, NULL, reply, siz);
	if (!i_clientid)
		return strdup(reply);

	i_enonce1 = require_name(trf_root, "enonce1", 1, NULL, reply, siz);
	if (!i_enonce1)
		return strdup(reply);

	i_useragent = require_name(trf_root, "useragent", 0, NULL, reply, siz);
	if (!i_useragent)
		return strdup(reply);

	i_preauth = require_name(trf_root, "preauth", 1, NULL, reply, siz);
	if (!i_preauth)
		return strdup(reply);

	ok = auths_add(conn, in_poolinstance, in_username, in_workername,
			     transfer_data(i_clientid),
			     transfer_data(i_enonce1),
			     transfer_data(i_useragent),
			     transfer_data(i_preauth),
			     by, code, inet, cd, trf_root, true,
			     &users, &workers, &event, reload_data);

	if (!ok) {
		LOGDEBUG("%s() %s.failed.DBE", __func__, id);
		return reply_event(event, "failed.DBE");
	}

	// Only flag a successful auth
	ck_wlock(&last_lock);
	setnow(&last_auth);
	ck_wunlock(&last_lock);

	if (switch_state < SWITCH_STATE_AUTHWORKERS) {
		snprintf(reply, siz,
			 "ok.addrauth={\"secondaryuserid\":\"%s\","
			 "\"difficultydefault\":%d}",
			 users->secondaryuserid, workers->difficultydefault);
		LOGDEBUG("%s.%s", id, reply);
		return strdup(reply);
	}

	APPEND_REALLOC_INIT(buf, off, len);
	snprintf(reply, siz,
		 "ok.addrauth={\"secondaryuserid\":\"%s\","
		 "\"workers\":[",
		 users->secondaryuserid);
	APPEND_REALLOC(buf, off, len, reply);
	first = true;
	K_RLOCK(workers_free);
	w_item = first_workers(users->userid, ctx);
	DATA_WORKERS_NULL(workers, w_item);
	while (w_item && workers->userid == users->userid) {
		if (CURRENT(&(workers->expirydate))) {
			snprintf(reply, siz,
				 "%s{\"workername\":\"%s\","
				 "\"difficultydefault\":%"PRId32"}",
				 first ? EMPTY : ",",
				 workers->in_workername,
				 workers->difficultydefault);
			APPEND_REALLOC(buf, off, len, reply);
			first = false;
		}
		w_item = next_in_ktree(ctx);
		DATA_WORKERS_NULL(workers, w_item);
	}
	K_RUNLOCK(workers_free);
	APPEND_REALLOC(buf, off, len, "]}");

	LOGDEBUG("%s.%s", id, buf);
	return buf;
}

static char *cmd_addrauth(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root, bool reload_data)
{
	return cmd_addrauth_do(conn, cmd, id, by, code, inet, cd, trf_root,
				reload_data);
}

static char *cmd_heartbeat(__maybe_unused PGconn *conn, char *cmd, char *id,
			   __maybe_unused tv_t *now, __maybe_unused char *by,
			   __maybe_unused char *code, __maybe_unused char *inet,
			   __maybe_unused tv_t *cd,
			   __maybe_unused K_TREE *trf_root,
			   __maybe_unused bool reload_data)
{
	HEARTBEATQUEUE *heartbeatqueue;
	K_STORE *hq_store;
	K_ITEM *hq_item;
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	size_t len, off;
	bool first;

	// Wait until startup is complete, we get a heartbeat every second
	if (!startup_complete)
		goto pulse;

	ck_wlock(&last_lock);
	setnow(&last_heartbeat);
	ck_wunlock(&last_lock);

	K_WLOCK(heartbeatqueue_free);
	if (heartbeatqueue_store->count == 0) {
		K_WUNLOCK(heartbeatqueue_free);
		goto pulse;
	}

	hq_store = k_new_store_locked(heartbeatqueue_free);
	k_list_transfer_to_head(heartbeatqueue_store, hq_store);
	K_WUNLOCK(heartbeatqueue_free);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.heartbeat={\"diffchange\":[");
	hq_item = STORE_TAIL_NOLOCK(hq_store);
	first = true;
	while (hq_item) {
		DATA_HEARTBEATQUEUE(heartbeatqueue, hq_item);
		tvs_to_buf(&last_bc, reply, siz);
		snprintf(tmp, sizeof(tmp),
			 "%s{\"workername\":\"%s\","
			 "\"difficultydefault\":%d,"
			 "\""CDTRF"\":\"%ld,%ld\"}",
			 first ? "" : ",",
			 heartbeatqueue->in_workername,
			 heartbeatqueue->difficultydefault,
			 heartbeatqueue->createdate.tv_sec,
			 heartbeatqueue->createdate.tv_usec);
		APPEND_REALLOC(buf, off, len, tmp);
		hq_item = hq_item->prev;
		first = false;
	}
	APPEND_REALLOC(buf, off, len, "]}");

	K_WLOCK(heartbeatqueue_free);
	k_list_transfer_to_head(hq_store, heartbeatqueue_free);
	K_WUNLOCK(heartbeatqueue_free);
	hq_store = k_free_store(hq_store);

	LOGDEBUG("%s.%s.%s", cmd, id, buf);
	return buf;
pulse:
	snprintf(reply, siz, "ok.pulse");
	LOGDEBUG("%s.%s.%s", cmd, id, reply);
	return strdup(reply);
}

static char *cmd_homepage(__maybe_unused PGconn *conn, char *cmd, char *id,
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	K_ITEM *i_username, *u_item, *b_item, *p_item, *us_item, look;
	K_ITEM *ua_item, *pa_item;
	int ovent = OVENT_OK;
	double u_hashrate5m, u_hashrate1hr;
	char reply[1024], tmp[1024], *buf;
	size_t siz = sizeof(reply);
	USERSTATS lookuserstats, *userstats;
	POOLSTATS *poolstats;
	BLOCKS *blocks;
	USERS *users;
	int64_t u_elapsed;
	int u_instances;
	K_TREE_CTX ctx[1];
	size_t len, off;
	bool has_uhr;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	ovent = ovents_add(OVENTID_HOMEPAGE, trf_root);
	if (ovent != OVENT_OK) {
		snprintf(reply, siz, "ERR");
		return reply_ovent(ovent, reply);
	}

	i_username = optional_name(trf_root, "username", 1, NULL, reply, siz);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

	// N.B. cmd_homepage isn't called until startup_complete
	ftv_to_buf(now, reply, siz);
	snprintf(tmp, sizeof(tmp), "now=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ck_rlock(&last_lock);
	ftv_to_buf(&last_heartbeat, reply, siz);
	snprintf(tmp, sizeof(tmp), "lasthb=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_workinfo, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastwi=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_share, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastsh=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_share_acc, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastshacc=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_share_inv, reply, siz);
	snprintf(tmp, sizeof(tmp), "lastshinv=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	ftv_to_buf(&last_auth, reply, siz);
	ck_runlock(&last_lock);
	snprintf(tmp, sizeof(tmp), "lastau=%s%c", reply, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	if (last_bc.tv_sec) {
		tvs_to_buf(&last_bc, reply, siz);
		snprintf(tmp, sizeof(tmp), "lastbc=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		K_RLOCK(workinfo_free);
		if (workinfo_current) {
			WORKINFO *wic;
			DATA_WORKINFO(wic, workinfo_current);
			snprintf(tmp, sizeof(tmp), "lastheight=%d%c",
						   wic->height-1, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		} else {
			snprintf(tmp, sizeof(tmp), "lastheight=?%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		K_RUNLOCK(workinfo_free);
	} else {
		snprintf(tmp, sizeof(tmp), "lastbc=?%clastheight=?%c",
					   FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	if (current_ndiff) {
		snprintf(tmp, sizeof(tmp), "currndiff=%.1f%c", current_ndiff, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "currndiff=?%c", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	// TODO: handle orphans
	K_RLOCK(blocks_free);
	b_item = last_in_ktree(blocks_root, ctx);
	K_RUNLOCK(blocks_free);
	if (b_item) {
		DATA_BLOCKS(blocks, b_item);
		tvs_to_buf(&(blocks->createdate), reply, siz);
		snprintf(tmp, sizeof(tmp), "lastblock=%s%cconfirmed=%s%c",
					   reply, FLDSEP,
					   blocks->confirmed, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "lastblockheight=%d%c",
					   blocks->height, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "lastblock=?%cconfirmed=?%c"
					   "lastblockheight=?%c",
					   FLDSEP, FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}


	snprintf(tmp, sizeof(tmp), "blockacc=%.1f%c",
				   pool.diffacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockerr=%.1f%c",
				   pool.diffinv, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockshareacc=%.1f%c",
				   pool.shareacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "blockshareinv=%.1f%c",
				   pool.shareinv, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	// TODO: DB only has one poolinstance with -i
	K_RLOCK(poolstats_free);
	p_item = last_in_ktree(poolstats_root, ctx);
	K_RUNLOCK(poolstats_free);
	if (p_item) {
		DATA_POOLSTATS(poolstats, p_item);
		int_to_buf(poolstats->users, reply, siz);
		snprintf(tmp, sizeof(tmp), "users=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		int_to_buf(poolstats->workers, reply, siz);
		snprintf(tmp, sizeof(tmp), "workers=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate5m, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate1hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(poolstats->hashrate24hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_hashrate24hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(poolstats->elapsed, reply, siz);
		snprintf(tmp, sizeof(tmp), "p_elapsed=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		tvs_to_buf(&(poolstats->createdate), reply, siz);
		snprintf(tmp, sizeof(tmp), "p_statsdate=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "ckdb_elapsed=%d%c",
			 (int)(now->tv_sec - ckdb_start.tv_sec), FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp), "users=?%cworkers=?%cp_hashrate=?%c"
					   "p_hashrate5m=?%cp_hashrate1hr=?%c"
					   "p_hashrate24hr=?%cp_elapsed=?%c"
					   "p_statsdate=?%cckdb_elapsed=?%c",
					   FLDSEP, FLDSEP, FLDSEP, FLDSEP,
					   FLDSEP, FLDSEP, FLDSEP, FLDSEP,
					   FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	// Don't bother with locking - it's just an FYI web stat
	int psync = pool_workqueue_store->count;
	int csync = cmd_workqueue_store->count;
	int bsync = btc_workqueue_store->count;
	int qsync = breakqueue_free->total - breakqueue_free->count;
	snprintf(tmp, sizeof(tmp), "psync=%d%c", psync, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "csync=%d%c", csync, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "bsync=%d%c", bsync, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "qsync=%d%c", qsync, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	// qsync isn't part of 'sync'
	snprintf(tmp, sizeof(tmp), "sync=%d%c", psync + csync + bsync, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	u_item = NULL;
	if (i_username) {
		K_RLOCK(users_free);
		u_item = find_users(transfer_data(i_username));
		K_RUNLOCK(users_free);
	}

	// User info to add to or affect the web site display
	if (u_item) {
		DATA_USERS(users, u_item);
		K_RLOCK(useratts_free);
		ua_item = find_useratts(users->userid, USER_MULTI_PAYOUT);
		K_RUNLOCK(useratts_free);
		if (ua_item) {
			snprintf(tmp, sizeof(tmp),
				 "u_multiaddr=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		if (!(*(users->emailaddress))) {
			snprintf(tmp, sizeof(tmp),
				 "u_noemail=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
		K_RLOCK(paymentaddresses_free);
		pa_item = find_paymentaddresses(users->userid, ctx);
		K_RUNLOCK(paymentaddresses_free);
		if (!pa_item) {
			snprintf(tmp, sizeof(tmp),
				 "u_nopayaddr=1%c", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	has_uhr = false;
	if (p_item && u_item) {
		u_hashrate5m = u_hashrate1hr = 0.0;
		u_elapsed = -1;
		u_instances = NO_INSTANCE_DATA;
		/* find last matching userid record - before userid+1
		 * Use 'before' in case there is (unexpectedly) a userstats
		 *  with an empty workername */
		lookuserstats.userid = users->userid+1;
		lookuserstats.in_workername = EMPTY;
		INIT_USERSTATS(&look);
		look.data = (void *)(&lookuserstats);
		K_RLOCK(userstats_free);
		us_item = find_before_in_ktree(userstats_root, &look, ctx);
		DATA_USERSTATS_NULL(userstats, us_item);
		while (us_item && userstats->userid == users->userid) {
			if (tvdiff(now, &(userstats->statsdate)) < USERSTATS_PER_S) {
				u_hashrate5m += userstats->hashrate5m;
				u_hashrate1hr += userstats->hashrate1hr;
				if (u_elapsed == -1 || u_elapsed > userstats->elapsed)
					u_elapsed = userstats->elapsed;
				if (userstats->instances != NO_INSTANCE_DATA) {
					if (u_instances == NO_INSTANCE_DATA)
						u_instances = 0;
					u_instances += userstats->instances;
				}
				has_uhr = true;
			}
			us_item = prev_in_ktree(ctx);
			DATA_USERSTATS_NULL(userstats, us_item);
		}
		K_RUNLOCK(userstats_free);
	}

	if (has_uhr) {
		double_to_buf(u_hashrate5m, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_hashrate5m=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(u_hashrate1hr, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_hashrate1hr=%s%c", reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		bigint_to_buf(u_elapsed, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_elapsed=%s", reply);
		APPEND_REALLOC(buf, off, len, tmp);

		int_to_buf(u_instances, reply, siz);
		snprintf(tmp, sizeof(tmp), "u_instances=%s", reply);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(tmp, sizeof(tmp),
			 "u_hashrate5m=?%cu_hashrate1hr=?%cu_elapsed=?%cu_instances=?",
			 FLDSEP, FLDSEP, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	LOGDEBUG("%s.ok.home,user=%s", id,
		 i_username ? transfer_data(i_username): "N");
	return buf;
}

/* Return the list of useratts for the given username=value
 * Format is attlist=attname.element,attname.element,...
 * Replies will be attname.element=value
 * The 2 date fields, date and date2, have a secondary element name
 *  dateexp and date2exp
 *  This will return Y or N depending upon if the date has expired as:
 *   attname.dateexp=N (or Y) and attname.date2exp=N (or Y)
 *  Expired means the date is <= now
 */
static char *cmd_getatts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_attlist, *u_item, *ua_item;
	INTRANSIENT *in_username;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	int event = EVENT_OK;
	char tmp[1024];
	USERATTS *useratts;
	USERS *users;
	char *reason = NULL;
	char *answer = NULL;
	char *attlist = NULL, *ptr, *comma, *dot;
	size_t len, off;
	bool first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				 (char *)userpatt, reply, siz);
	if (!in_username) {
		// Shouldn't happen except with a code problem no event required
		reason = "Missing username";
		goto nuts;
	}

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);

	if (!u_item) {
		// page_api.php without a valid username
		event = events_add(EVENTID_UNKATTS, trf_root);
		reason = "Unknown user";
		goto nuts;
	} else {
		DATA_USERS(users, u_item);
		i_attlist = require_name(trf_root, "attlist", 1, NULL, reply, siz);
		if (!i_attlist) {
			reason = "Missing attlist";
			goto nuts;
		}

		APPEND_REALLOC_INIT(answer, off, len);
		attlist = ptr = strdup(transfer_data(i_attlist));
		first = true;
		while (ptr && *ptr) {
			comma = strchr(ptr, ',');
			if (comma)
				*(comma++) = '\0';
			dot = strchr(ptr, '.');
			if (!dot) {
				reason = "Missing element";
				goto nuts;
			}
			*(dot++) = '\0';
			if (strcmp(ptr, APIKEY) == 0) {
				// API request count
				event = ovents_add(OVENTID_API, trf_root);
				if (event != OVENT_OK) {
					if (attlist)
						free(attlist);
					if (answer)
						free(answer);
					snprintf(reply, siz, "ERR");
					return reply_ovent(event, reply);
				}
			}
			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, ptr);
			K_RUNLOCK(useratts_free);
			/* web code must check the existance of the attname
			 * in the reply since it will be missing if it doesn't
			 * exist in the DB */
			if (ua_item) {
				char num_buf[BIGINT_BUFSIZ];
				char ctv_buf[CDATE_BUFSIZ];
				char *ans;
				DATA_USERATTS(useratts, ua_item);
				if (strcmp(dot, "str") == 0) {
					ans = useratts->attstr;
				} else if (strcmp(dot, "str2") == 0) {
					ans = useratts->attstr2;
				} else if (strcmp(dot, "num") == 0) {
					bigint_to_buf(useratts->attnum,
						      num_buf,
						      sizeof(num_buf));
					ans = num_buf;
				} else if (strcmp(dot, "num2") == 0) {
					bigint_to_buf(useratts->attnum2,
						      num_buf,
						      sizeof(num_buf));
					ans = num_buf;
				} else if (strcmp(dot, "date") == 0) {
					ctv_to_buf(&(useratts->attdate),
						   ctv_buf,
						   sizeof(num_buf));
					ans = ctv_buf;
				} else if (strcmp(dot, "dateexp") == 0) {
					// Y/N if date is <= now (expired)
					if (tv_newer(&(useratts->attdate), now))
						ans = TRUE_STR;
					else
						ans = FALSE_STR;
				} else if (strcmp(dot, "date2") == 0) {
					ctv_to_buf(&(useratts->attdate2),
						   ctv_buf,
						   sizeof(num_buf));
					ans = ctv_buf;
				} else if (strcmp(dot, "date2exp") == 0) {
					// Y/N if date2 is <= now (expired)
					if (tv_newer(&(useratts->attdate2), now))
						ans = TRUE_STR;
					else
						ans = FALSE_STR;
				} else {
					reason = "Unknown element";
					goto nuts;
				}
				snprintf(tmp, sizeof(tmp), "%s%s.%s=%s",
					 first ? EMPTY : FLDSEPSTR,
					 ptr, dot, ans);
				APPEND_REALLOC(answer, off, len, tmp);
				first = false;
			}
			ptr = comma;
		}
	}
nuts:
	if (attlist)
		free(attlist);

	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return reply_event(event, reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

static void att_to_date(tv_t *date, char *data, tv_t *now)
{
	int add;

	if (strncasecmp(data, "now+", 4) == 0) {
		add = atoi(data+4);
		copy_tv(date, now);
		date->tv_sec += add;
	} else if (strcasecmp(data, "now") == 0) {
		copy_tv(date, now);
	} else {
		txt_to_ctv("date", data, date, sizeof(*date));
	}
}

/* Store useratts in the DB for the given username=value
 * Format is 1 or more: ua_attname.element=value
 *  i.e. each starts with the constant "ua_"
 * attname cannot contain Tab . or =
 * element is per the coded list below, which also cannot contain Tab . or =
 * Any matching useratts attnames found currently in the DB are expired
 * Transfer will sort them so that any of the same attname
 *  will be next to each other
 *  thus will combine multiple elements for the same attname
 *  into one single useratts record (as is mandatory)
 * The 2 date fields date and date2 require either epoch values sec,usec
 *  (usec is optional and defaults to 0) or one of: now or now+NNN
 *  now is the current epoch value and now+NNN is the epoch + NNN seconds
 *  See att_to_date() above
 *  */
static char *cmd_setatts(PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	bool conned = false;
	K_ITEM *t_item, *u_item, *ua_item = NULL;
	INTRANSIENT *in_username;
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	TRANSFER *transfer;
	USERATTS *useratts = NULL;
	USERS *users;
	char attname[sizeof(useratts->attname)*2];
	char *reason = NULL;
	char *dot, *data;
	bool begun = false;
	int set = 0, db = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				 (char *)userpatt, reply, siz);
	if (!in_username) {
		reason = "Missing user";
		goto bats;
	}

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto bats;
	} else {
		DATA_USERS(users, u_item);
		t_item = first_in_ktree_nolock(trf_root, ctx);
		while (t_item) {
			DATA_TRANSFER(transfer, t_item);
			if (strncmp(transfer->name, "ua_", 3) == 0) {
				data = transfer_data(t_item);
				STRNCPY(attname, transfer->name + 3);
				dot = strchr(attname, '.');
				if (!dot) {
					reason = "Missing element";
					goto bats;
				}
				*(dot++) = '\0';
				// If we already had a different one, save it to the DB
				if (ua_item && strcmp(useratts->attname, attname) != 0) {
					if (CKPQConn(&conn))
						conned = true;
					if (!begun) {
						begun = CKPQBegin(conn);
						if (!begun) {
							reason = "DBERR";
							goto bats;
						}
					}
					if (useratts_item_add(conn, ua_item, now, begun)) {
						ua_item = NULL;
						db++;
					} else {
						reason = "DBERR";
						goto rollback;
					}
				}
				if (!ua_item) {
					K_WLOCK(useratts_free);
					ua_item = k_unlink_head(useratts_free);
					K_WUNLOCK(useratts_free);
					DATA_USERATTS(useratts, ua_item);
					bzero(useratts, sizeof(*useratts));
					useratts->userid = users->userid;
					STRNCPY(useratts->attname, attname);
					HISTORYDATEINIT(useratts, now, by, code, inet);
					HISTORYDATETRANSFER(trf_root, useratts);
				}
				// List of valid element names for storage
				if (strcmp(dot, "str") == 0) {
					STRNCPY(useratts->attstr, data);
					set++;
				} else if (strcmp(dot, "str2") == 0) {
					STRNCPY(useratts->attstr2, data);
					set++;
				} else if (strcmp(dot, "num") == 0) {
					TXT_TO_BIGINT("num", data, useratts->attnum);
					set++;
				} else if (strcmp(dot, "num2") == 0) {
					TXT_TO_BIGINT("num2", data, useratts->attnum2);
					set++;
				} else if (strcmp(dot, "date") == 0) {
					att_to_date(&(useratts->attdate), data, now);
					set++;
				} else if (strcmp(dot, "date2") == 0) {
					att_to_date(&(useratts->attdate2), data, now);
					set++;
				} else {
					reason = "Unknown element";
					goto bats;
				}
			}
			t_item = next_in_ktree(ctx);
		}
		if (ua_item) {
			if (CKPQConn(&conn))
				conned = true;
			if (!begun) {
				begun = CKPQBegin(conn);
				if (!begun) {
					reason = "DBERR";
					goto bats;
				}
			}
			if (!useratts_item_add(conn, ua_item, now, begun)) {
				reason = "DBERR";
				goto rollback;
			}
			db++;
		}
	}
rollback:

	CKPQEnd(conn, (reason == NULL));

bats:
	CKPQDisco(&conn, conned);
	if (reason) {
		if (ua_item) {
			K_WLOCK(useratts_free);
			k_add_head(useratts_free, ua_item);
			K_WUNLOCK(useratts_free);
		}
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.set %d,%d", db, set);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

/* Expire the list of useratts for the given username=value
 * Format is attlist=attname,attname,...
 * Each matching DB attname record will have it's expirydate set to now
 *  thus an attempt to access it with getatts will not find it and
 *  return nothing for that attname
 */
static char *cmd_expatts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_attlist, *u_item, *ua_item;
	INTRANSIENT *in_username;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	USERATTS *useratts;
	USERS *users;
	char *reason = NULL;
	char *attlist, *ptr, *comma;
	int db = 0, mis = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = require_in(trf_root, "username", MIN_USERNAME,
				 (char *)userpatt, reply, siz);
	if (!in_username) {
		reason = "Missing username";
		goto rats;
	}

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);

	if (!u_item) {
		reason = "Unknown user";
		goto rats;
	} else {
		DATA_USERS(users, u_item);
		i_attlist = require_name(trf_root, "attlist", 1, NULL, reply, siz);
		if (!i_attlist) {
			reason = "Missing attlist";
			goto rats;
		}

		attlist = ptr = strdup(transfer_data(i_attlist));
		while (ptr && *ptr) {
			comma = strchr(ptr, ',');
			if (comma)
				*(comma++) = '\0';
			K_RLOCK(useratts_free);
			ua_item = find_useratts(users->userid, ptr);
			K_RUNLOCK(useratts_free);
			if (!ua_item)
				mis++;
			else {
				DATA_USERATTS(useratts, ua_item);
				HISTORYDATEINIT(useratts, now, by, code, inet);
				HISTORYDATETRANSFER(trf_root, useratts);
				/* Since we are expiring records, don't bother
				 *  with combining them all into a single
				 *  transaction and don't abort on error
				 * Thus if an error is returned, retry would be
				 *  necessary, but some may also have been
				 *  expired successfully */
				if (!useratts_item_expire(conn, ua_item, now))
					reason = "DBERR";
				else
					db++;
			}
			ptr = comma;
		}
		free(attlist);
	}
rats:
	if (reason) {
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.exp %d,%d", db, mis);
	LOGDEBUG("%s.%s.%s", cmd, id, reply);
	return strdup(reply);
}

/* Return the list of optioncontrols
 * Format is optlist=optionname,optionname,optionname,...
 * Replies will be optionname=value
 * Any optionnames not in the DB or not yet active will be missing
 */
static char *cmd_getopts(__maybe_unused PGconn *conn, char *cmd, char *id,
			 tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_optlist, *oc_item;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024];
	OPTIONCONTROL *optioncontrol;
	char *reason = NULL;
	char *answer = NULL;
	char *optlist = NULL, *ptr, *comma;
	size_t len, off;
	bool first;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_optlist = require_name(trf_root, "optlist", 1, NULL, reply, siz);
	if (!i_optlist) {
		reason = "Missing optlist";
		goto ruts;
	}

	APPEND_REALLOC_INIT(answer, off, len);
	optlist = ptr = strdup(transfer_data(i_optlist));
	first = true;
	while (ptr && *ptr) {
		comma = strchr(ptr, ',');
		if (comma)
			*(comma++) = '\0';
		oc_item = find_optioncontrol(ptr, now, pool.height);
		/* web code must check the existance of the optionname
		 * in the reply since it will be missing if it doesn't
		 * exist in the DB */
		if (oc_item) {
			DATA_OPTIONCONTROL(optioncontrol, oc_item);
			snprintf(tmp, sizeof(tmp), "%s%s=%s",
				 first ? EMPTY : FLDSEPSTR,
				 optioncontrol->optionname,
				 optioncontrol->optionvalue);
			APPEND_REALLOC(answer, off, len, tmp);
			first = false;
		}
		ptr = comma;
	}
ruts:
	if (optlist)
		free(optlist);

	if (reason) {
		if (answer)
			free(answer);
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.%s", answer);
	LOGDEBUG("%s.%s", id, answer);
	free(answer);
	return strdup(reply);
}

// This is the same as att_set_date() for now
#define opt_set_date(_date, _data, _now) att_set_date(_date, _data, _now)

/* Store optioncontrols in the DB
 * Format is 1 or more: oc_optionname.fld=value
 *  i.e. each starts with the constant "oc_"
 * optionname cannot contain Tab . or =
 * fld is one of the 3: value, date, height
 * value must exist
 * None, one or both of date and height can exist
 * If a matching optioncontrol (same name, date and height) exists,
 *  it will have it's expiry date set to now and be replaced with the new value
 * The date field requires either an epoch sec,usec
 *  (usec is optional and defaults to 0) or one of: now or now+NNN
 *  now is the current epoch value and now+NNN is the epoch + NNN seconds
 *  See opt_set_date() above */
static char *cmd_setopts(PGconn *conn, char *cmd, char *id,
			 tv_t *now, char *by, char *code, char *inet,
			 __maybe_unused tv_t *notcd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	bool conned = false;
	K_ITEM *t_item, *oc_item = NULL, *ok = NULL;
	K_TREE_CTX ctx[1];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	TRANSFER *transfer;
	OPTIONCONTROL *optioncontrol;
	char optionname[sizeof(optioncontrol->optionname)*2];
	char *reason = NULL;
	char *dot, *data;
	bool begun = false, gotvalue = false;
	int db = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	t_item = first_in_ktree_nolock(trf_root, ctx);
	while (t_item) {
		DATA_TRANSFER(transfer, t_item);
		if (strncmp(transfer->name, "oc_", 3) == 0) {
			data = transfer_data(t_item);
			STRNCPY(optionname, transfer->name + 3);
			dot = strchr(optionname, '.');
			if (!dot) {
				reason = "Missing field";
				goto rollback;
			}
			*(dot++) = '\0';
			// If we already had a different one, save it to the DB
			if (oc_item && strcmp(optioncontrol->optionname, optionname) != 0) {
				if (!gotvalue) {
					reason = "Missing value";
					goto rollback;
				}
				if (CKPQConn(&conn))
					conned = true;
				if (!begun) {
					begun = CKPQBegin(conn);
					if (!begun) {
						reason = "DBERR";
						goto rollback;
					}
				}
				ok = optioncontrol_item_add(conn, oc_item, now, begun);
				oc_item = NULL;
				if (ok)
					db++;
				else {
					reason = "DBERR";
					goto rollback;
				}
			}
			if (!oc_item) {
				K_WLOCK(optioncontrol_free);
				oc_item = k_unlink_head(optioncontrol_free);
				K_WUNLOCK(optioncontrol_free);
				DATA_OPTIONCONTROL(optioncontrol, oc_item);
				bzero(optioncontrol, sizeof(*optioncontrol));
				STRNCPY(optioncontrol->optionname, optionname);
				optioncontrol->activationheight = OPTIONCONTROL_HEIGHT;
				HISTORYDATEINIT(optioncontrol, now, by, code, inet);
				HISTORYDATETRANSFER(trf_root, optioncontrol);
				gotvalue = false;
			}
			if (strcmp(dot, "value") == 0) {
				DUP_POINTER(optioncontrol_free,
					    optioncontrol->optionvalue, data);
				gotvalue = true;
			} else if (strcmp(dot, "date") == 0) {
				att_to_date(&(optioncontrol->activationdate), data, now);
			} else if (strcmp(dot, "height") == 0) {
				TXT_TO_INT("height", data, optioncontrol->activationheight);
			} else {
				reason = "Unknown field";
				goto rollback;
			}
		}
		t_item = next_in_ktree(ctx);
	}
	if (oc_item) {
		if (!gotvalue) {
			reason = "Missing value";
			goto rollback;
		}
		if (CKPQConn(&conn))
			conned = true;
		if (!begun) {
			begun = CKPQBegin(conn);
			if (!begun) {
				reason = "DBERR";
				goto rollback;
			}
		}
		ok = optioncontrol_item_add(conn, oc_item, now, begun);
		oc_item = NULL;
		if (ok)
			db++;
		else {
			reason = "DBERR";
			goto rollback;
		}
	}
rollback:
	if (begun)
		CKPQEnd(conn, (reason == NULL));

	CKPQDisco(&conn, conned);
	if (reason) {
		snprintf(reply, siz, "ERR.%s", reason);
		LOGERR("%s.%s.%s", cmd, id, reply);
		return strdup(reply);
	}
	snprintf(reply, siz, "ok.set %d", db);
	LOGDEBUG("%s.%s", id, reply);
	return strdup(reply);
}

/* Kept for reference/comparison to cmd_pplns2()
 * This will get different results due to the fact that it uses the current
 *  contents of the payoutaddresses table
 * However, the only differences should be the addresses,
 *  and the breakdown for percent address users,
 *  the totals per user and per payout should still be the same */
static char *cmd_pplns(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	char reply[1024], tmp[1024], *buf;
	char *block_extra, *share_status = EMPTY, *marks_status = EMPTY;
	size_t siz = sizeof(reply);
	K_ITEM *i_height, *i_difftimes, *i_diffadd, *i_allowaged;
	K_ITEM b_look, ss_look, *b_item, *w_item, *ss_item;
	K_ITEM wm_look, *wm_item, ms_look, *ms_item;
	K_ITEM *mu_item, *wb_item, *u_item;
	SHARESUMMARY looksharesummary, *sharesummary;
	WORKMARKERS lookworkmarkers, *workmarkers;
	MARKERSUMMARY lookmarkersummary, *markersummary;
	MININGPAYOUTS *miningpayouts;
	WORKINFO *workinfo;
	TRANSFER *transfer;
	BLOCKS lookblocks, *blocks;
	K_TREE *mu_root;
	K_STORE *mu_store;
	USERS *users;
	int32_t height;
	int64_t block_workinfoid, end_workinfoid;
	int64_t begin_workinfoid;
	int64_t total_share_count, acc_share_count;
	int64_t ss_count, wm_count, ms_count;
	char tv_buf[DATE_BUFSIZ];
	tv_t cd, begin_tv, block_tv, end_tv;
	K_TREE_CTX ctx[1], wm_ctx[1], ms_ctx[1], pay_ctx[1];
	double ndiff, total_diff, elapsed;
	double diff_times = 1.0;
	double diff_add = 0.0;
	double diff_want;
	bool allow_aged = false;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (sharesummary_marks_limit)
		marks_status = "ckdb -w load value means pplns may be incorrect";

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);
	TXT_TO_INT("height", transfer_data(i_height), height);

	i_difftimes = optional_name(trf_root, "diff_times", 1, NULL, reply, siz);
	if (i_difftimes)
		TXT_TO_DOUBLE("diff_times", transfer_data(i_difftimes), diff_times);

	i_diffadd = optional_name(trf_root, "diff_add", 1, NULL, reply, siz);
	if (i_diffadd)
		TXT_TO_DOUBLE("diff_add", transfer_data(i_diffadd), diff_add);

	i_allowaged = optional_name(trf_root, "allow_aged", 1, NULL, reply, siz);
	if (i_allowaged) {
		DATA_TRANSFER(transfer, i_allowaged);
		if (toupper(transfer->mvalue[0]) == TRUE_STR[0])
			allow_aged = true;
	}

	LOGDEBUG("%s(): height %"PRId32, __func__, height);

	DATE_ZERO(&block_tv);
	DATE_ZERO(&cd);
	lookblocks.height = height + 1;
	lookblocks.blockhash[0] = '\0';
	INIT_BLOCKS(&b_look);
	b_look.data = (void *)(&lookblocks);
	K_RLOCK(blocks_free);
	b_item = find_before_in_ktree(blocks_root, &b_look, ctx);
	if (!b_item) {
		K_RUNLOCK(blocks_free);
		snprintf(reply, siz, "ERR.no block height %d", height);
		return strdup(reply);
	}
	DATA_BLOCKS_NULL(blocks, b_item);
	while (b_item && blocks->height == height) {
		if (blocks->confirmed[0] == BLOCKS_NEW) {
			copy_tv(&block_tv, &(blocks->createdate));
			copy_tv(&end_tv, &(blocks->createdate));
		}
		// Allow any state, but report it
		if (CURRENT(&(blocks->expirydate)))
			break;
		b_item = prev_in_ktree(ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
	}
	K_RUNLOCK(blocks_free);
	if (!b_item || blocks->height != height) {
		snprintf(reply, siz, "ERR.no CURRENT block %d", height);
		return strdup(reply);
	}
	if (block_tv.tv_sec == 0) {
		snprintf(reply, siz, "ERR.block %d missing '%s' record",
				     height,
				     blocks_confirmed(BLOCKS_NEW_STR));
		return strdup(reply);
	}
	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->in_workername, blocks->confirmed, blocks->reward);
	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
			block_extra = "Can't be paid out yet";
			break;
		case BLOCKS_ORPHAN:
		case BLOCKS_REJECT:
			block_extra = "Can't be paid out";
			break;
		default:
			block_extra = EMPTY;
			break;
	}
	block_workinfoid = blocks->workinfoid;
	w_item = find_workinfo(block_workinfoid, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing workinfo %"PRId64, block_workinfoid);
		return strdup(reply);
	}
	DATA_WORKINFO(workinfo, w_item);

	ndiff = workinfo->diff_target;
	diff_want = ndiff * diff_times + diff_add;
	if (diff_want < 1.0) {
		snprintf(reply, siz,
			 "ERR.invalid diff_want result %f",
			 diff_want);
		return strdup(reply);
	}

	LOGDEBUG("%s(): ndiff %.0f", __func__, ndiff);
	begin_workinfoid = end_workinfoid = 0;
	total_share_count = acc_share_count = 0;
	total_diff = 0;
	ss_count = wm_count = ms_count = 0;

	mu_store = k_new_store(miningpayouts_free);
	mu_root = new_ktree_auto("OldMPU", cmp_mu, miningpayouts_free);

	looksharesummary.workinfoid = block_workinfoid;
	looksharesummary.userid = MAXID;
	looksharesummary.in_workername = EMPTY;
	INIT_SHARESUMMARY(&ss_look);
	ss_look.data = (void *)(&looksharesummary);
	K_WLOCK(miningpayouts_free);
	K_RLOCK(sharesummary_free);
	K_RLOCK(workmarkers_free);
	K_RLOCK(markersummary_free);
	ss_item = find_before_in_ktree(sharesummary_workinfoid_root,
					&ss_look, ctx);
	DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	if (ss_item)
		end_workinfoid = sharesummary->workinfoid;
	/* add up all sharesummaries until >= diff_want
	 * also record the latest lastshareacc - that will be the end pplns time
	 *  which will be >= block_tv */
	while (total_diff < diff_want && ss_item) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				share_status = "Not ready1";
		}

		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += (int64_t)(sharesummary->diffacc);
		begin_workinfoid = sharesummary->workinfoid;
		if (tv_newer(&end_tv, &(sharesummary->lastshareacc)))
			copy_tv(&end_tv, &(sharesummary->lastshareacc));
		upd_add_mu(mu_root, mu_store, sharesummary->userid,
			   (int64_t)(sharesummary->diffacc));
		ss_item = prev_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}

	// include all the rest of the sharesummaries with begin_workinfoid
	while (ss_item && sharesummary->workinfoid == begin_workinfoid) {
		switch (sharesummary->complete[0]) {
			case SUMMARY_CONFIRM:
				break;
			case SUMMARY_COMPLETE:
				if (allow_aged)
					break;
			default:
				if (share_status == EMPTY)
					share_status = "Not ready2";
				else
					share_status = "Not ready1+2";
		}
		ss_count++;
		total_share_count += sharesummary->sharecount;
		acc_share_count += sharesummary->shareacc;
		total_diff += (int64_t)(sharesummary->diffacc);
		upd_add_mu(mu_root, mu_store, sharesummary->userid,
			   (int64_t)(sharesummary->diffacc));
		ss_item = prev_in_ktree(ctx);
		DATA_SHARESUMMARY_NULL(sharesummary, ss_item);
	}
	LOGDEBUG("%s(): ss %"PRId64" total %.0f want %.0f",
		 __func__, ss_count, total_diff, diff_want);
	/* If we haven't met or exceeded the required N,
	 * move on to the markersummaries */
	if (total_diff < diff_want) {
		lookworkmarkers.expirydate.tv_sec = default_expiry.tv_sec;
		lookworkmarkers.expirydate.tv_usec = default_expiry.tv_usec;
		if (begin_workinfoid != 0)
			lookworkmarkers.workinfoidend = begin_workinfoid;
		else
			lookworkmarkers.workinfoidend = block_workinfoid + 1;
		INIT_WORKMARKERS(&wm_look);
		wm_look.data = (void *)(&lookworkmarkers);
		wm_item = find_before_in_ktree(workmarkers_workinfoid_root,
						&wm_look, wm_ctx);
		DATA_WORKMARKERS_NULL(workmarkers, wm_item);
		LOGDEBUG("%s(): workmarkers < %"PRId64, __func__, lookworkmarkers.workinfoidend);
		while (total_diff < diff_want && wm_item && CURRENT(&(workmarkers->expirydate))) {
			if (WMPROCESSED(workmarkers->status)) {
				wm_count++;
				lookmarkersummary.markerid = workmarkers->markerid;
				lookmarkersummary.userid = MAXID;
				lookmarkersummary.in_workername = EMPTY;
				INIT_MARKERSUMMARY(&ms_look);
				ms_look.data = (void *)(&lookmarkersummary);
				ms_item = find_before_in_ktree(markersummary_root,
								&ms_look, ms_ctx);
				DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				// add the whole markerid
				while (ms_item && markersummary->markerid == workmarkers->markerid) {
					if (end_workinfoid == 0)
						end_workinfoid = workmarkers->workinfoidend;
					ms_count++;
					total_share_count += markersummary->sharecount;
					acc_share_count += markersummary->shareacc;
					total_diff += (int64_t)(markersummary->diffacc);
					begin_workinfoid = workmarkers->workinfoidstart;
					if (tv_newer(&end_tv, &(markersummary->lastshareacc)))
						copy_tv(&end_tv, &(markersummary->lastshareacc));
					upd_add_mu(mu_root, mu_store, markersummary->userid,
						   (int64_t)(markersummary->diffacc));
					ms_item = prev_in_ktree(ms_ctx);
					DATA_MARKERSUMMARY_NULL(markersummary, ms_item);
				}
			}
			wm_item = prev_in_ktree(wm_ctx);
			DATA_WORKMARKERS_NULL(workmarkers, wm_item);
		}
		LOGDEBUG("%s(): wm %"PRId64" ms %"PRId64" total %.0f want %.0f",
			 __func__, wm_count, ms_count, total_diff, diff_want);
	}
	K_RUNLOCK(markersummary_free);
	K_RUNLOCK(workmarkers_free);
	K_RUNLOCK(sharesummary_free);
	K_WUNLOCK(miningpayouts_free);

	LOGDEBUG("%s(): total %.0f want %.0f", __func__, total_diff, diff_want);
	if (total_diff == 0.0) {
		snprintf(reply, siz,
			 "ERR.total share diff 0 before workinfo %"PRId64,
			 block_workinfoid);
		goto shazbot;
	}

	wb_item = find_workinfo(begin_workinfoid, NULL);
	if (!wb_item) {
		snprintf(reply, siz, "ERR.missing begin workinfo record! %"PRId64, block_workinfoid);
		goto shazbot;
	}
	DATA_WORKINFO(workinfo, wb_item);

	copy_tv(&begin_tv, &(workinfo->createdate));
	/* Elapsed is from the start of the first workinfoid used,
	 *  to the time of the last share counted -
	 *  which can be after the block, but must have the same workinfoid as
	 *  the block, if it is after the block
	 * All shares accepted in all workinfoids after the block's workinfoid
	 *  will not be creditied to this block no matter what the height
	 *  of their workinfoid is - but will be candidates for the next block */
	elapsed = tvdiff(&end_tv, &begin_tv);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "block=%d%c", height, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_hash=%s%c", blocks->blockhash, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_reward=%"PRId64"%c", blocks->reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_status=%s%c",
				   blocks_confirmed(blocks->confirmed), FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_extra=%s%c", block_extra, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "share_status=%s%c", share_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "marks_status=%s%c", marks_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "workername=%s%c", blocks->in_workername, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "nonce=%s%c", blocks->nonce, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_workinfoid=%"PRId64"%c", begin_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_workinfoid=%"PRId64"%c", block_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_workinfoid=%"PRId64"%c", end_workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diffacc_total=%.0f%c", total_diff, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "pplns_elapsed=%f%c", elapsed, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	rows = 0;
	mu_item = first_in_ktree(mu_root, ctx);
	while (mu_item) {
		DATA_MININGPAYOUTS(miningpayouts, mu_item);

		K_RLOCK(users_free);
		u_item = find_userid(miningpayouts->userid);
		K_RUNLOCK(users_free);
		if (!u_item) {
			snprintf(reply, siz,
				 "ERR.unknown userid %"PRId64,
				 miningpayouts->userid);
			goto shazbot;
		}

		DATA_USERS(users, u_item);

		K_ITEM *pa_item;
		PAYMENTADDRESSES *pa;
		int64_t paytotal;
		double amount;
		int count;

		K_RLOCK(paymentaddresses_free);
		pa_item = find_paymentaddresses(miningpayouts->userid, pay_ctx);
		if (pa_item) {
			paytotal = 0;
			DATA_PAYMENTADDRESSES(pa, pa_item);
			while (pa_item && CURRENT(&(pa->expirydate)) &&
			       pa->userid == miningpayouts->userid) {
				paytotal += pa->payratio;
				pa_item = prev_in_ktree(pay_ctx);
				DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			}
			count = 0;
			pa_item = find_paymentaddresses(miningpayouts->userid, pay_ctx);
			DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			while (pa_item && CURRENT(&(pa->expirydate)) &&
			       pa->userid == miningpayouts->userid) {
				amount = (double)(miningpayouts->amount) *
					 (double)pa->payratio / (double)paytotal;

				snprintf(tmp, sizeof(tmp),
					 "user:%d=%s.%d%cpayaddress:%d=%s%c",
					 rows, users->in_username, ++count,
					 FLDSEP, rows, pa->in_payaddress, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "diffacc_user:%d=%.1f%c",
					 rows, amount, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				rows++;

				pa_item = prev_in_ktree(pay_ctx);
				DATA_PAYMENTADDRESSES_NULL(pa, pa_item);
			}
			K_RUNLOCK(paymentaddresses_free);
		} else {
			K_RUNLOCK(paymentaddresses_free);
			snprintf(tmp, sizeof(tmp),
				 "user:%d=%s.0%cpayaddress:%d=%s%c",
				 rows, users->in_username, FLDSEP,
				 rows, "none", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp),
				 "diffacc_user:%d=%"PRId64"%c",
				 rows,
				 miningpayouts->amount,
				 FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			rows++;
		}
		mu_item = next_in_ktree(ctx);
	}
	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "user,diffacc_user,payaddress", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
				   "Users", FLDSEP, "", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	tv_to_buf(&begin_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "begin_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_epoch=%ld%c", begin_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&block_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "block_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_epoch=%ld%c", block_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&end_tv, tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "end_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_epoch=%ld%c", end_tv.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "block_ndiff=%f%c", ndiff, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_times=%f%c", diff_times, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_add=%f%c", diff_add, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_want=%f%c", diff_want, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "acc_share_count=%"PRId64"%c",
				   acc_share_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "total_share_count=%"PRId64"%c",
				   total_share_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "ss_count=%"PRId64"%c", ss_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "wm_count=%"PRId64"%c", wm_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "ms_count=%"PRId64"%c", ms_count, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	// So web can always verify it received all data
	APPEND_REALLOC(buf, off, len, "pplns_last=1");

	free_ktree(mu_root, NULL);
	K_WLOCK(miningpayouts_free);
	k_list_transfer_to_head(mu_store, miningpayouts_free);
	K_WUNLOCK(miningpayouts_free);
	mu_store = k_free_store(mu_store);

	LOGDEBUG("%s.ok.pplns.%s", id, buf);
	return buf;

shazbot:

	free_ktree(mu_root, NULL);
	K_WLOCK(miningpayouts_free);
	k_list_transfer_to_head(mu_store, miningpayouts_free);
	K_WUNLOCK(miningpayouts_free);
	mu_store = k_free_store(mu_store);

	return strdup(reply);
}

// Generated from the payouts, miningpayouts and payments data
static char *cmd_pplns2(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	char reply[1024], tmp[1024], *buf;
	char *block_extra, *marks_status = EMPTY;
	size_t siz = sizeof(reply);
	K_ITEM *i_height;
	K_ITEM b_look, *b_item, *p_item, *mp_item, *pay_item, *u_item, *ua_item;
	K_ITEM *w_item;
	MININGPAYOUTS *miningpayouts;
	PAYMENTS *payments;
	PAYOUTS *payouts;
	BLOCKS lookblocks, *blocks;
	WORKINFO *bworkinfo, *workinfo;
	USERS *users;
	int32_t height;
	K_TREE_CTX b_ctx[1], mp_ctx[1], pay_ctx[1];
	char tv_buf[DATE_BUFSIZ];
	size_t len, off;
	int rows;
	bool pok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	if (sharesummary_marks_limit)
		marks_status = "ckdb -w load value means pplns may be incorrect";

	i_height = require_name(trf_root, "height", 1, NULL, reply, siz);
	if (!i_height)
		return strdup(reply);
	TXT_TO_INT("height", transfer_data(i_height), height);

	LOGDEBUG("%s(): height %"PRId32, __func__, height);

	lookblocks.height = height;
	lookblocks.blockhash[0] = '\0';
	INIT_BLOCKS(&b_look);
	b_look.data = (void *)(&lookblocks);
	K_RLOCK(blocks_free);
	b_item = find_after_in_ktree(blocks_root, &b_look, b_ctx);
	K_RUNLOCK(blocks_free);
	if (!b_item) {
		snprintf(reply, siz, "ERR.no block height >= %"PRId32, height);
		return strdup(reply);
	}
	DATA_BLOCKS(blocks, b_item);
	if (!b_item || blocks->height != height) {
		snprintf(reply, siz, "ERR.no block height %"PRId32, height);
		return strdup(reply);
	}
	if (blocks->blockcreatedate.tv_sec == 0) {
		snprintf(reply, siz, "ERR.block %"PRId32" has 0 blockcreatedate",
				     height);
		return strdup(reply);
	}
	if (!CURRENT(&(blocks->expirydate))) {
		snprintf(reply, siz, "ERR.no CURRENT block %d"PRId32, height);
		return strdup(reply);
	}
	LOGDEBUG("%s(): block %"PRId32"/%"PRId64"/%s/%s/%"PRId64,
		 __func__, blocks->height, blocks->workinfoid,
		 blocks->in_workername, blocks->confirmed, blocks->reward);
	switch (blocks->confirmed[0]) {
		case BLOCKS_NEW:
			block_extra = "Can't be paid out yet";
			break;
		case BLOCKS_ORPHAN:
		case BLOCKS_REJECT:
			block_extra = "Can't be paid out";
			break;
		default:
			block_extra = EMPTY;
			break;
	}

	w_item = find_workinfo(blocks->workinfoid, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing block workinfo record!"
			 " %"PRId64,
			 blocks->workinfoid);
		return strdup(reply);
	}
	DATA_WORKINFO(bworkinfo, w_item);

	pok = false;
	K_RLOCK(payouts_free);
	p_item = find_payouts(height, blocks->blockhash);
	DATA_PAYOUTS_NULL(payouts, p_item);
	if (p_item && PAYGENERATED(payouts->status))
		pok = true;
	K_RUNLOCK(payouts_free);
	if (!p_item) {
		snprintf(reply, siz, "ERR.no payout for %"PRId32"/%s",
			 height, blocks->blockhash);
		return strdup(reply);
	}
	if (!pok) {
		snprintf(reply, siz, "ERR.payout %"PRId64" status=%s "
			 "for %"PRId32"/%s",
			 payouts->payoutid, payouts->status, height,
			 blocks->blockhash);
		return strdup(reply);
	}

	LOGDEBUG("%s(): total %.1f want %.1f",
		 __func__, payouts->diffused, payouts->diffwanted);

	w_item = find_workinfo(payouts->workinfoidstart, NULL);
	if (!w_item) {
		snprintf(reply, siz, "ERR.missing begin workinfo record!"
			 " %"PRId64,
			 payouts->workinfoidstart);
		return strdup(reply);
	}
	DATA_WORKINFO(workinfo, w_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	snprintf(tmp, sizeof(tmp), "block=%d%c", height, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_hash=%s%c", blocks->blockhash, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_reward=%"PRId64"%c", blocks->reward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "miner_reward=%"PRId64"%c", payouts->minerreward, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_status=%s%c",
				   blocks_confirmed(blocks->confirmed), FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_extra=%s%c", block_extra, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "marks_status=%s%c", marks_status, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "workername=%s%c", blocks->in_workername, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "nonce=%s%c", blocks->nonce, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_workinfoid=%"PRId64"%c", payouts->workinfoidstart, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_workinfoid=%"PRId64"%c", blocks->workinfoid, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_workinfoid=%"PRId64"%c", payouts->workinfoidend, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diffacc_total=%.1f%c", payouts->diffused, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "pplns_elapsed=%"PRId64"%c", payouts->elapsed, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	rows = 0;
	K_RLOCK(miningpayouts_free);
	mp_item = first_miningpayouts(payouts->payoutid, mp_ctx);
	K_RUNLOCK(miningpayouts_free);
	DATA_MININGPAYOUTS_NULL(miningpayouts, mp_item);
	while (mp_item && miningpayouts->payoutid == payouts->payoutid) {
		if (CURRENT(&(miningpayouts->expirydate))) {
			int out = 0;
			K_RLOCK(users_free);
			u_item = find_userid(miningpayouts->userid);
			K_RUNLOCK(users_free);
			if (!u_item) {
				snprintf(reply, siz,
					 "ERR.unknown userid %"PRId64,
					 miningpayouts->userid);
				goto shazbot;
			}
			DATA_USERS(users, u_item);
			K_RLOCK(useratts_free);
			ua_item = find_useratts(miningpayouts->userid, HOLD_PAYOUTS);
			K_RUNLOCK(useratts_free);

			K_RLOCK(payments_free);
			pay_item = find_first_paypayid(miningpayouts->userid,
							payouts->payoutid,
							pay_ctx);
			DATA_PAYMENTS_NULL(payments, pay_item);
			while (pay_item &&
			       payments->userid == miningpayouts->userid &&
			       payments->payoutid == payouts->payoutid) {
				if (CURRENT(&(payments->expirydate))) {
					snprintf(tmp, sizeof(tmp),
						 "user:%d=%s%c"
						 "payaddress:%d=%s%c"
						 "amount:%d=%"PRId64"%c"
						 "diffacc:%d=%.1f%c",
						 rows, payments->in_subname,
						 FLDSEP, rows,
						 ua_item ? HOLD_ADDRESS :
						  payments->in_payaddress,
						 FLDSEP, rows, payments->amount,
						 FLDSEP, rows,
						 payments->diffacc, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					rows++;
					out++;
				}
				pay_item = next_in_ktree(pay_ctx);
				DATA_PAYMENTS_NULL(payments, pay_item);
			}
			K_RUNLOCK(payments_free);
			if (out == 0) {
				snprintf(tmp, sizeof(tmp),
					 "user:%d=%s.0%c"
					 "payaddress:%d=%s%c"
					 "amount:%d=%"PRId64"%c"
					 "diffacc:%d=%.1f%c",
					 rows, users->in_username, FLDSEP,
					 rows, NONE_ADDRESS, FLDSEP,
					 rows, miningpayouts->amount, FLDSEP,
					 rows, miningpayouts->diffacc, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				rows++;
			}
		}
		K_RLOCK(miningpayouts_free);
		mp_item = next_in_ktree(mp_ctx);
		K_RUNLOCK(miningpayouts_free);
		DATA_MININGPAYOUTS_NULL(miningpayouts, mp_item);
	}

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "user,payaddress,amount,diffacc", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
				   "Users", FLDSEP, "", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	tv_to_buf(&(workinfo->createdate), tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "begin_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "begin_epoch=%ld%c",
				   workinfo->createdate.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&(blocks->blockcreatedate), tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "block_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_epoch=%ld%c",
				   blocks->blockcreatedate.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	tv_to_buf(&(payouts->lastshareacc), tv_buf, sizeof(tv_buf));
	snprintf(tmp, sizeof(tmp), "end_stamp=%s%c", tv_buf, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "end_epoch=%ld%c",
				   payouts->lastshareacc.tv_sec, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%s%c", payouts->stats, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "block_ndiff=%f%c",
				   bworkinfo->diff_target, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "diff_want=%.1f%c",
				   payouts->diffwanted, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "acc_share_count=%.0f%c",
				   payouts->shareacc, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	// So web can always verify it received all data
	APPEND_REALLOC(buf, off, len, "pplns_last=1");

	LOGDEBUG("%s.ok.pplns.%s", id, buf);
	return buf;

shazbot:
	return strdup(reply);
}

static char *cmd_payouts(PGconn *conn, char *cmd, char *id, tv_t *now,
			 char *by, char *code, char *inet,
			 __maybe_unused tv_t *cd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char msg[1024] = "";
	K_ITEM *i_action, *i_payoutid, *i_height, *i_blockhash, *i_addrdate;
	K_ITEM *p_item, *p2_item, *old_p2_item;
	PAYOUTS *payouts, *payouts2, *old_payouts2;
	char *action;
	int64_t payoutid = -1;
	int32_t height = 0;
	char blockhash[TXT_BIG+1];
	tv_t addrdate;
	bool ok = true;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "generated") == 0) {
		/* Change the status of a processing payout to generated
		 * Require payoutid
		 * Use this if the payout process completed but the end txn,
		 *  that only updates the payout to generated, failed */
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		K_WLOCK(payouts_free);
		p_item = find_payoutid(payoutid);
		if (!p_item) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "no payout with id %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts, p_item);
		if (!PAYPROCESSING(payouts->status)) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "status !processing (%s) for payout %"PRId64,
				 payouts->status, payoutid);
			return strdup(reply);
		}
		p2_item = k_unlink_head(payouts_free);
		K_WUNLOCK(payouts_free);

		/* There is a risk of the p_item changing while it's unlocked,
		 *  but since this is a manual interface it's not really likely
		 *  and there'll be an error if something goes wrong
		 * It reports the old and new status */
		DATA_PAYOUTS(payouts2, p2_item);
		bzero(payouts2, sizeof(*payouts2));
		payouts2->payoutid = payouts->payoutid;
		payouts2->height = payouts->height;
		STRNCPY(payouts2->blockhash, payouts->blockhash);
		payouts2->minerreward = payouts->minerreward;
		payouts2->workinfoidstart = payouts->workinfoidstart;
		payouts2->workinfoidend = payouts->workinfoidend;
		payouts2->elapsed = payouts->elapsed;
		STRNCPY(payouts2->status, PAYOUTS_GENERATED_STR);
		payouts2->diffwanted = payouts->diffwanted;
		payouts2->diffused = payouts->diffused;
		payouts2->shareacc = payouts->shareacc;
		copy_tv(&(payouts2->lastshareacc), &(payouts->lastshareacc));
		DUP_POINTER(payouts_free, payouts2->stats, payouts->stats);

		ok = payouts_add(conn, true, p2_item, &old_p2_item,
				 by, code, inet, now, NULL, false);
		if (!ok) {
			snprintf(reply, siz, "failed payout %"PRId64, payoutid);
			return strdup(reply);
		}
		// Original wasn't generated, so reward it
		reward_shifts(payouts2, 1);
		DATA_PAYOUTS(payouts2, p2_item);
		DATA_PAYOUTS(old_payouts2, old_p2_item);
		snprintf(msg, sizeof(msg),
			 "payout %"PRId64" changed from '%s' to '%s' for "
			 "%"PRId32"/%s",
			 payoutid, old_payouts2->status, payouts2->status,
			 payouts2->height, payouts2->blockhash);
	} else if (strcasecmp(action, "orphan") == 0 ||
	           strcasecmp(action, "reject") == 0) {
		/* Change the status of a generated payout to orphaned
		 *  or rejected
		 * Require payoutid
		 * Use this if the orphan or reject process didn't
		 *  automatically update a generated payout
		 * TODO: get orphaned and rejected blocks to automatically do this */
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		K_WLOCK(payouts_free);
		p_item = find_payoutid(payoutid);
		if (!p_item) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "no payout with id %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts, p_item);
		if (!PAYGENERATED(payouts->status)) {
			K_WUNLOCK(payouts_free);
			snprintf(reply, siz,
				 "status !generated (%s) for payout %"PRId64,
				 payouts->status, payoutid);
			return strdup(reply);
		}
		p2_item = k_unlink_head(payouts_free);
		K_WUNLOCK(payouts_free);

		/* There is a risk of the p_item changing while it's unlocked,
		 *  but since this is a manual interface it's not really likely
		 *  and there'll be an error if something goes wrong
		 * It reports the old and new status */
		DATA_PAYOUTS(payouts2, p2_item);
		bzero(payouts2, sizeof(*payouts2));
		payouts2->payoutid = payouts->payoutid;
		payouts2->height = payouts->height;
		STRNCPY(payouts2->blockhash, payouts->blockhash);
		payouts2->minerreward = payouts->minerreward;
		payouts2->workinfoidstart = payouts->workinfoidstart;
		payouts2->workinfoidend = payouts->workinfoidend;
		payouts2->elapsed = payouts->elapsed;
		if (strcasecmp(action, "orphan") == 0)
			STRNCPY(payouts2->status, PAYOUTS_ORPHAN_STR);
		else
			STRNCPY(payouts2->status, PAYOUTS_REJECT_STR);
		payouts2->diffwanted = payouts->diffwanted;
		payouts2->diffused = payouts->diffused;
		payouts2->shareacc = payouts->shareacc;
		copy_tv(&(payouts2->lastshareacc), &(payouts->lastshareacc));
		DUP_POINTER(payouts_free, payouts2->stats, payouts->stats);

		ok = payouts_add(conn, true, p2_item, &old_p2_item,
				 by, code, inet, now, NULL, false);
		if (!ok) {
			snprintf(reply, siz, "failed payout %"PRId64, payoutid);
			return strdup(reply);
		}
		// Original was generated, so undo the reward
		reward_shifts(payouts2, -1);
		DATA_PAYOUTS(payouts2, p2_item);
		DATA_PAYOUTS(old_payouts2, old_p2_item);
		snprintf(msg, sizeof(msg),
			 "payout %"PRId64" changed from '%s' to '%s' for "
			 "%"PRId32"/%s",
			 payoutid, old_payouts2->status, payouts2->status,
			 payouts2->height, payouts2->blockhash);
	} else if (strcasecmp(action, "expire") == 0) {
		/* Expire the payout - effectively deletes it
		 * Require payoutid
		 * TODO: If any payments are paid then don't allow it */
		i_payoutid = require_name(trf_root, "payoutid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_payoutid)
			return strdup(reply);
		TXT_TO_BIGINT("payoutid", transfer_data(i_payoutid), payoutid);

		// payouts_full_expire updates the shift rewards
		p_item = payouts_full_expire(conn, payoutid, now, true);
		if (!p_item) {
			snprintf(reply, siz, "failed payout %"PRId64, payoutid);
			return strdup(reply);
		}
		DATA_PAYOUTS(payouts, p_item);
		snprintf(msg, sizeof(msg),
			 "payout %"PRId64" block %"PRId32" reward %"PRId64
			 " status '%s'",
			 payouts->payoutid, payouts->height,
			 payouts->minerreward, payouts->status);
	} else if (strcasecmp(action, "process") == 0) {
		/* Generate a payout
		 * Require height, blockhash and addrdate
		 *  addrdate is an epoch integer
		 *   and 0 means uses the default = block NEW createdate
		 *   this is the date to use to determine payoutaddresses
		 * Check the console for processing messages */
		i_height = require_name(trf_root, "height", 6,
					(char *)intpatt, reply, siz);
		if (!i_height)
			return strdup(reply);
		TXT_TO_INT("height", transfer_data(i_height), height);

		i_blockhash = require_name(trf_root, "blockhash", 64,
					   (char *)hashpatt, reply, siz);
		if (!i_blockhash)
			return strdup(reply);
		TXT_TO_STR("blockhash", transfer_data(i_blockhash), blockhash);

		i_addrdate = require_name(trf_root, "addrdate", 1,
					 (char *)intpatt, reply, siz);
		if (!i_addrdate)
			return strdup(reply);
		TXT_TO_CTV("addrdate", transfer_data(i_addrdate), addrdate);

		// process_pplns updates the shift rewards
		if (addrdate.tv_sec == 0)
			ok = process_pplns(height, blockhash, NULL);
		else
			ok = process_pplns(height, blockhash, &addrdate);

	} else if (strcasecmp(action, "genon") == 0) {
		/* Turn on auto payout generation
		 *  and report the before/after status
		 * No parameters */
		bool old = genpayout_auto;
		genpayout_auto = true;
		snprintf(msg, sizeof(msg), "payout generation state was %s,"
					   " now %s",
					   old ? "On" : "Off",
					   genpayout_auto ? "On" : "Off");
		ok = true;
	} else if (strcasecmp(action, "genoff") == 0) {
		/* Turn off auto payout generation
		 *  and report the before/after status
		 * No parameters */
		bool old = genpayout_auto;
		genpayout_auto = false;
		snprintf(msg, sizeof(msg), "payout generation state was %s,"
					   " now %s",
					   old ? "On" : "Off",
					   genpayout_auto ? "On" : "Off");
		ok = true;
	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	snprintf(reply, siz, "%s.%s%s%s",
			     ok ? "ok" : "ERR",
			     action,
			     msg[0] ? " " : EMPTY,
			     msg[0] ? msg : EMPTY);
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

static char *cmd_mpayouts(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	K_ITEM *u_item, *mp_item, *po_item;
	INTRANSIENT *in_username;
	K_TREE_CTX ctx[1];
	MININGPAYOUTS *mp;
	PAYOUTS *payouts;
	USERS *users;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = adminuser(trf_root, reply, siz);
	if (!in_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	K_RLOCK(payouts_free);
	po_item = last_in_ktree(payouts_root, ctx);
	DATA_PAYOUTS_NULL(payouts, po_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (po_item) {
		if (CURRENT(&(payouts->expirydate)) &&
		    PAYGENERATED(payouts->status)) {
			K_RLOCK(miningpayouts_free);
			mp_item = find_miningpayouts(payouts->payoutid,
						     users->userid);
			if (mp_item) {
				DATA_MININGPAYOUTS(mp, mp_item);

				bigint_to_buf(payouts->payoutid, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "payoutid:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				int_to_buf(payouts->height, reply,
					   sizeof(reply));
				snprintf(tmp, sizeof(tmp), "height:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				snprintf(tmp, sizeof(tmp),
					 "block"CDTRF":%d=%ld%c", rows,
					 payouts->blockcreatedate.tv_sec, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(payouts->elapsed, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "elapsed:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(mp->amount, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "amount:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(mp->diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "diffacc:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				bigint_to_buf(payouts->minerreward, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "minerreward:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(payouts->diffused, reply,
					      sizeof(reply));
				snprintf(tmp, sizeof(tmp), "diffused:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				str_to_buf(payouts->status, reply,
					   sizeof(reply));
				snprintf(tmp, sizeof(tmp), "status:%d=%s%c",
							   rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				rows++;
			}
			K_RUNLOCK(miningpayouts_free);
		}
		po_item = prev_in_ktree(ctx);
		DATA_PAYOUTS_NULL(payouts, po_item);
	}
	K_RUNLOCK(payouts_free);

	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "payoutid,height,block"CDTRF",elapsed,amount,diffacc,minerreward,diffused,status",
		 FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "MiningPayouts", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, in_username->str);
	return buf;
}

typedef struct worker_match {
	char *worker;
	bool match;
	size_t len;
	bool used;
	bool everused;
} WM;

static char *worker_offset(char *workername)
{
	char *c1, *c2;

	/* Find the start of the workername including the SEP */
	c1 = strchr(workername, WORKSEP1);
	c2 = strchr(workername, WORKSEP2);
	if (c1 || c2) {
		if (!c1 || (c1 && c2 && (c2 < c1)))
			c1 = c2;
	}
	// No workername after the username
	if (!c1)
		c1 = WORKERS_EMPTY;

	return c1;
}

/* Some arbitrarily large limit, increase it if needed
    (doesn't need to be very large) */
#define SELECT_LIMIT 63

/* select is a string of workernames separated by WORKERS_SEL_SEP
 * Setup the wm array of workers with select broken up
 * The wm array is terminated by workers = NULL
 *  and will have 0 elements if select is NULL/empty
 * The count of the first occurrence of WORKERS_ALL is returned,
 *  or -1 if WORKERS_ALL isn't found */
static int select_list(WM *wm, char *select)
{
	int count, all_count = -1;
	size_t len, offset;
	char *end;

	if (select == NULL || *select == '\0')
		return all_count;

	len = strlen(select);
	count = 0;
	offset = 0;
	while (offset < len) {
		if (select[offset] == WORKERS_SEL_SEP)
			offset++;
		else {
			wm[count].worker = select + offset;
			wm[count+1].worker = NULL;
			end = strchr(wm[count].worker, WORKERS_SEL_SEP);
			if (end != NULL) {
				offset = 1 + end - select;
				*end = '\0';
			}

			if (all_count == -1 &&
			    strcasecmp(wm[count].worker, WORKERS_ALL) == 0) {
				all_count = count;
			}

			if (end == NULL || ++count > SELECT_LIMIT)
				break;
		}
	}
	return all_count;
}

static char *cmd_shifts(__maybe_unused PGconn *conn, char *cmd, char *id,
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	INTRANSIENT *in_username;
	K_ITEM *i_select;
	K_ITEM *u_item, *p_item, *m_item, ms_look, *wm_item, *ms_item, *wi_item;
	K_TREE_CTX wm_ctx[1], ms_ctx[1];
	WORKMARKERS *wm;
	WORKINFO *wi;
	MARKERSUMMARY markersummary, *ms, ms_add[SELECT_LIMIT+1];
	PAYOUTS *payouts;
	USERS *users;
	MARKS *marks = NULL;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *select = NULL;
	WM workm[SELECT_LIMIT+1];
	char *buf = NULL, *work, *st = NULL;
	size_t len, off;
	tv_t marker_end = { 0L, 0L };
	int rows, want, i, where_all;
	int64_t maxrows;
	double wm_count, d;
	int64_t last_payout_start = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = adminuser(trf_root, reply, siz);
	if (!in_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	maxrows = user_sys_setting(users->userid, SHIFTS_SETTING_NAME,
				   SHIFTS_DEFAULT, now);

	K_RLOCK(payouts_free);
	p_item = find_last_payouts();
	K_RUNLOCK(payouts_free);
	if (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		wm_count = payout_stats(payouts, "wm_count");
		wm_count *= 1.42;
		if (maxrows < wm_count)
			maxrows = wm_count;
		last_payout_start = payouts->workinfoidstart;
	}

	i_select = optional_name(trf_root, "select", 1, NULL, reply, siz);
	if (i_select)
		select = strdup(transfer_data(i_select));

	APPEND_REALLOC_INIT(buf, off, len);
	snprintf(tmp, sizeof(tmp), " select='%s'",
		 select ? st = safe_text_nonull(select) : "null");
	FREENULL(st);
	APPEND_REALLOC(buf, off, len, tmp);

	bzero(workm, sizeof(workm));
	where_all = select_list(&(workm[0]), select);
	// Nothing selected = all
	if (workm[0].worker == NULL) {
		where_all = 0;
		workm[0].worker = WORKERS_ALL;
		APPEND_REALLOC(buf, off, len, " no workers");
	} else {
		for (i = 0; workm[i].worker; i++) {
			// N.B. len is only used if match is true
			len = workm[i].len = strlen(workm[i].worker);
			// If at least 3 characters and last is '*'
			if (len > 2 && workm[i].worker[len-1] == '*') {
				workm[i].worker[len-1] = '\0';
				workm[i].match = true;
				workm[i].len--;
			}
			snprintf(tmp, sizeof(tmp), " workm[%d]=%s,%s,%d",
						   i, st = safe_text_nonull(workm[i].worker),
						   workm[i].match ? "Y" : "N",
						   (int)(workm[i].len));
			FREENULL(st);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	if (where_all >= 0)
		workm[where_all].used = true;

	snprintf(tmp, sizeof(tmp), " where_all=%d", where_all);
	APPEND_REALLOC(buf, off, len, tmp);
	LOGDEBUG("%s() user=%"PRId64"/%s' %s",
		 __func__, users->userid, users->in_username, buf+1);
	FREENULL(buf);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	INIT_MARKERSUMMARY(&ms_look);
	ms_look.data = (void *)(&markersummary);
	rows = 0;
	K_RLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, wm_ctx);
	DATA_WORKMARKERS_NULL(wm, wm_item);
	/* TODO: allow to see details of a single payoutid
	 *	 if it has multiple items (percent payout user) */
	while (rows < (maxrows - 1) && wm_item) {
		if (CURRENT(&(wm->expirydate)) && WMPROCESSED(wm->status)) {
			K_RUNLOCK(workmarkers_free);

			K_RLOCK(marks_free);
			m_item = find_marks(wm->workinfoidend);
			K_RUNLOCK(marks_free);
			DATA_MARKS_NULL(marks, m_item);
			if (m_item == NULL) {
				// Log it but keep going
				LOGERR("%s() missing mark for markerid "
					"%"PRId64"/%s widend %"PRId64,
					__func__, wm->markerid,
					wm->description,
					wm->workinfoidend);
			}

			// Zero everything for this shift
			bzero(ms_add, sizeof(ms_add));
			for (i = 0; workm[i].worker; i++) {
				if (i != where_all)
					workm[i].used = false;
			}

			markersummary.markerid = wm->markerid;
			markersummary.userid = users->userid;
			markersummary.in_workername = EMPTY;
			K_RLOCK(markersummary_free);
			ms_item = find_after_in_ktree(markersummary_root,
							&ms_look, ms_ctx);
			DATA_MARKERSUMMARY_NULL(ms, ms_item);
			while (ms_item && ms->markerid == wm->markerid &&
			       ms->userid == users->userid) {
				work = worker_offset(ms->in_workername);
				for (want = 0; workm[want].worker; want++) {
					if ((want == where_all) ||
					    (workm[want].match && strncmp(work, workm[want].worker, workm[want].len) == 0) ||
					    (!(workm[want].match) && strcmp(workm[want].worker, work) == 0)) {
						workm[want].used = true;
						workm[want].everused = true;
						ms_add[want].diffacc += ms->diffacc;
						ms_add[want].diffsta += ms->diffsta;
						ms_add[want].diffdup += ms->diffdup;
						ms_add[want].diffhi += ms->diffhi;
						ms_add[want].diffrej += ms->diffrej;
						ms_add[want].shareacc += ms->shareacc;
						ms_add[want].sharesta += ms->sharesta;
						ms_add[want].sharedup += ms->sharedup;
						ms_add[want].sharehi += ms->sharehi;
						ms_add[want].sharerej += ms->sharerej;
					}
				}
				ms_item = next_in_ktree(ms_ctx);
				DATA_MARKERSUMMARY_NULL(ms, ms_item);
			}
			K_RUNLOCK(markersummary_free);

			for (i = 0; i <= SELECT_LIMIT; i++) {
				if (workm[i].used) {
					double_to_buf(ms_add[i].diffacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_diffacc:%d=%s%c",
								   i, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					d = ms_add[i].diffsta + ms_add[i].diffdup +
					    ms_add[i].diffhi + ms_add[i].diffrej;
					double_to_buf(d, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_diffinv:%d=%s%c",
								   i, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					double_to_buf(ms_add[i].shareacc, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_shareacc:%d=%s%c",
								   i, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);

					d = ms_add[i].sharesta + ms_add[i].sharedup +
					    ms_add[i].sharehi + ms_add[i].sharerej;
					double_to_buf(d, reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp), "%d_shareinv:%d=%s%c",
								   i, rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
				}
			}

			if (marker_end.tv_sec == 0L) {
				wi_item = next_workinfo(wm->workinfoidend, NULL);
				if (!wi_item) {
					/* There's no workinfo after this shift
					 * Unexpected ... estimate last wid+30s */
					wi_item = find_workinfo(wm->workinfoidend, NULL);
					if (!wi_item) {
						// Nothing is currently locked
						LOGERR("%s() workmarker %"PRId64"/%s."
							" missing widend %"PRId64,
							__func__, wm->markerid,
							wm->description,
							wm->workinfoidend);
						snprintf(reply, siz, "data error 1");
						free(buf);
						return(strdup(reply));
					}
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
					marker_end.tv_sec += 30;
				} else {
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
				}
			}

			wi_item = find_workinfo(wm->workinfoidstart, NULL);
			if (!wi_item) {
				// Nothing is currently locked
				LOGERR("%s() workmarker %"PRId64"/%s. missing "
					"widstart %"PRId64,
					__func__, wm->markerid, wm->description,
					wm->workinfoidstart);
				snprintf(reply, siz, "data error 2");
				free(buf);
				return(strdup(reply));
			}
			DATA_WORKINFO(wi, wi_item);

			bigint_to_buf(wm->markerid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "markerid:%d=%s%c",
					   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(wm->description, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shift:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "endmarkextra:%d=%s%c",
						   rows,
						   m_item ? marks->extra : EMPTY,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&(wi->createdate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "start:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&marker_end, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "end:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "rewards:%d=%d%c",
						   rows, wm->rewards, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			// Use %.15e -> 16 non-leading-zero decimal places
			snprintf(tmp, sizeof(tmp), "ppsvalue:%d=%.15f%c",
						   rows, wm->pps_value, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			// Use %.15e -> 16 non-leading-zero decimal places
			snprintf(tmp, sizeof(tmp), "ppsrewarded:%d=%.15e%c",
						   rows, wm->rewarded, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "lastpayoutstart:%d=%s%c",
						   rows,
						   (wm->workinfoidstart ==
						    last_payout_start) ?
						    "Y" : EMPTY,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;

			// Setup for next shift
			copy_tv(&marker_end, &(wi->createdate));

			K_RLOCK(workmarkers_free);
		}
		wm_item = prev_in_ktree(wm_ctx);
		DATA_WORKMARKERS_NULL(wm, wm_item);
	}
	K_RUNLOCK(workmarkers_free);

	for (i = 0; workm[i].worker; i++) {
		if (workm[i].everused) {
			snprintf(tmp, sizeof(tmp),
				 "%d_worker=%s%s%c",
				 i, workm[i].worker,
				 workm[i].match ? "*" : EMPTY,
				 FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp),
				 "%d_flds=%s%c", i,
				 "diffacc,diffinv,shareacc,shareinv", FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	// Missing if all isn't selected
	if (where_all >= 0) {
		snprintf(tmp, sizeof(tmp), "prefix_all=%d_%c",
					   where_all, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
	}

	/* rows is an upper limit of rows in each worker
	 * 'all' starts at 0 and finishes at rows-1
	 * other workers start >= 0 and finish <= rows-1 */
	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				   rows, FLDSEP,
				   "markerid,shift,start,end,rewards,"
				   "ppsvalue,ppsrewarded,lastpayoutstart",
				   FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s", "Shifts");
	APPEND_REALLOC(buf, off, len, tmp);
	for (i = 0; workm[i].worker; i++) {
		if (workm[i].everused) {
			snprintf(tmp, sizeof(tmp), ",Worker_%d", i);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	snprintf(tmp, sizeof(tmp), "%carp=", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	for (i = 0; workm[i].worker; i++) {
		if (workm[i].everused) {
			snprintf(tmp, sizeof(tmp), ",%d_", i);
			APPEND_REALLOC(buf, off, len, tmp);
		}
	}

	LOGDEBUG("%s.ok.%s", id, in_username->str);
	return(buf);
}

static char *cmd_dsp(__maybe_unused PGconn *conn, __maybe_unused char *cmd,
		     char *id, __maybe_unused tv_t *now,
		     __maybe_unused char *by, __maybe_unused char *code,
		     __maybe_unused char *inet, __maybe_unused tv_t *notcd,
		     __maybe_unused K_TREE *trf_root,
		     __maybe_unused bool reload_data)
{
	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

#if 1
	LOGDEBUG("%s.disabled.dsp", id);
	return strdup("disabled.dsp");
#else
	// WARNING: This is a gaping security hole - only use in development
	K_ITEM *i_file, *i_name, *i_type;
	char reply[1024] = "", *fil, *name, *typ;
	size_t siz = sizeof(reply);
	K_STORE *store = NULL;
	K_TREE *tree = NULL;
	bool unknown_typ = true, unknown_name = true, msg = false;

	i_file = require_name(trf_root, "file", 1, NULL, reply, siz);
	if (!i_file)
		return strdup(reply);

	i_name = require_name(trf_root, "name", 1, NULL, reply, siz);
	if (!i_name)
		return strdup(reply);

	i_type = optional_name(trf_root, "type", 1, NULL, reply, siz);
	if (*reply)
		return strdup(reply);

	fil = transfer_data(i_file);
	name = transfer_data(i_name);
	if (i_type)
		typ = transfer_data(i_type);
	else
		typ = "tree";

	if (strcasecmp(typ, "tree") == 0) {
		unknown_typ = false;

		if (strcasecmp(name, "blocks") == 0)
			tree = blocks_root;

		if (strcasecmp(name, "transfer") == 0)
			tree = trf_root;

		if (strcasecmp(name, "paymentaddresses") == 0)
			tree = paymentaddresses_root;

		if (strcasecmp(name, "paymentaddresses_create") == 0)
			tree = paymentaddresses_create_root;

		if (strcasecmp(name, "sharesummary") == 0)
			tree = sharesummary_root;

		if (strcasecmp(name, "userstats") == 0)
			tree = userstats_root;

		if (strcasecmp(name, "markersummary") == 0)
			tree = markersummary_root;

		if (strcasecmp(name, "workmarkers") == 0)
			tree = workmarkers_root;

		if (strcasecmp(name, "idcontrol") == 0)
			tree = idcontrol_root;

		if (tree) {
			unknown_name = false;
			if (tree->master->dsp_func)
				dsp_ktree(tree, fil, NULL);
			else {
				snprintf(reply, siz,
					 "%s %s has no dsp_func",
					 typ, name);
				msg = true;
			}
		}
	} else if (strcasecmp(typ, "store") == 0) {
		unknown_typ = false;

		if (strcasecmp(name, "blocks") == 0)
			store = blocks_store;

		if (strcasecmp(name, "markersummary") == 0)
			store = markersummary_store;

		if (strcasecmp(name, "msgline") == 0)
			store = msgline_store;

		if (store) {
			unknown_name = false;
			if (store->master->dsp_func)
				dsp_kstore(store, fil, NULL);
			else {
				snprintf(reply, siz,
					 "%s %s has no dsp_func",
					 typ, name);
				msg = true;
			}
		}
	}

	if (unknown_typ) {
		snprintf(reply, siz, "unknown typ '%s'", typ);
	} else if (unknown_name) {
		snprintf(reply, siz, "unknown name '%s' for '%s'", name, typ);
	} else {
		if (!msg)
			snprintf(reply, siz, "ok.dsp.file='%s'", fil);
	}
	LOGDEBUG("%s.%s'", id, reply);
	return strdup(reply);
#endif
}

static char *cmd_stats(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd,
			__maybe_unused K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	char tmp[1024], *buf;
	const char *name;
	size_t len, off;
	int64_t ram, ram2, tot = 0;
	K_LIST *klist;
	K_LISTS *klists;
	int rows = 0;
	bool istree;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

	/* All but temporary lists are in klist_all
	 * All trees are there also since all trees have a node klist */
	ck_wlock(&lock_check_lock);
	klists = all_klists;
	while (klists) {
		klist = klists->klist;

		ram = sizeof(*klist);
		if (klist->name == tree_node_list_name) {
			ram += sizeof(K_TREE);
			istree = true;
			name = klist->name2;
		} else {
			istree = false;
			name = klist->name;
		}
		if (klist->lock)
			ram += sizeof(*(klist->lock));
		// List of item lists
		ram += klist->item_mem_count * sizeof(*(klist->item_memory));
		// items
		ram += klist->total * sizeof(K_ITEM);
		// List of data lists
		ram += klist->data_mem_count * sizeof(*(klist->data_memory));
		// data
		ram += klist->total * klist->siz;

		// stores
		ram += klist->stores * sizeof(K_STORE);

		ram2 = klist->ram;

		snprintf(tmp, sizeof(tmp),
			 "name:%d=%s%s%s%cinitial:%d=%d%callocated:%d=%d%c"
			 "instore:%d=%d%cram:%d=%"PRId64"%c"
			 "ram2:%d=%"PRId64"%ccull:%d=%d%ccull_limit:%d=%d%c",
			 rows, name, istree ? " (tree)" : "",
			 klist->is_lock_only ? " (lock)" : "", FLDSEP,
			 rows, klist->allocate, FLDSEP,
			 rows, klist->total, FLDSEP,
			 rows, klist->total - klist->count, FLDSEP,
			 rows, ram, FLDSEP,
			 rows, ram2, FLDSEP,
			 rows, klist->cull_count, FLDSEP,
			 rows, klist->cull_limit, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		tot += ram + ram2;
		rows++;

		klists = klists->next;
	}
	ck_wunlock(&lock_check_lock);

	snprintf(tmp, sizeof(tmp), "totalram=%"PRId64"%c", tot, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "name,initial,allocated,instore,ram,cull,cull_limit", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s", "Stats", FLDSEP, "");
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s...", id, cmd);
	return buf;
}

// TODO: add to heartbeat to disable the miner if active and status != ""
static char *cmd_userstatus(PGconn *conn, char *cmd, char *id, tv_t *now, char *by,
			    char *code, char *inet, __maybe_unused tv_t *cd,
			    K_TREE *trf_root, __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	K_ITEM *i_username, *i_userid, *i_status, *u_item;
	int64_t userid;
	char *status;
	USERS *users;
	bool ok;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_username = optional_name(trf_root, "username", MIN_USERNAME,
				   (char *)userpatt, reply, siz);
	i_userid = optional_name(trf_root, "userid", 1, (char *)intpatt, reply, siz);
	// Either username or userid
	if (!i_username && !i_userid) {
		snprintf(reply, siz, "failed.invalid/missing userinfo");
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	// A zero length status re-enables it
	i_status = require_name(trf_root, "status", 0, NULL, reply, siz);
	if (!i_status)
		return strdup(reply);
	status = transfer_data(i_status);

	K_RLOCK(users_free);
	if (i_username)
		u_item = find_users(transfer_data(i_username));
	else {
		TXT_TO_BIGINT("userid", transfer_data(i_userid), userid);
		u_item = find_userid(userid);
	}
	K_RUNLOCK(users_free);

	if (!u_item)
		ok = false;
	else {
		ok = users_update(conn, u_item,
					NULL, NULL,
					NULL,
					by, code, inet, now,
					trf_root,
					status, NULL);
	}

	if (!ok) {
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	DATA_USERS(users, u_item);
	snprintf(reply, siz, "ok.updated %"PRId64" %s status %s",
			     users->userid,
			     users->in_username,
			     status[0] ? "disabled" : "enabled");
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

/* Socket interface to the functions that will be used later to automatically
 * create marks, workmarkers and process the workmarkers and sharesummaries
 * to generate markersummaries */
static char *cmd_marks(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, char *by,
			char *code, char *inet, tv_t *cd,
			K_TREE *trf_root, __maybe_unused bool reload_data)
{
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024] = "";
	char msg[1024] = "";
	K_ITEM *i_action, *i_workinfoid, *i_marktype, *i_description;
	K_ITEM *i_height, *i_status, *i_extra, *m_item, *b_item, *w_item;
	K_ITEM *wm_item, *wm_item_prev, *i_markerid;
	WORKINFO *workinfo = NULL;
	WORKMARKERS *workmarkers;
	K_TREE_CTX ctx[1];
	BLOCKS *blocks;
	MARKS *marks;
	char *action;
	int64_t workinfoid = -1, markerid = -1;
	char *marktype;
	int32_t height = 0;
	char description[TXT_BIG+1] = { '\0' };
	char extra[TXT_BIG+1] = { '\0' };
	char status[TXT_FLAG+1] = { MARK_READY, '\0' };
	bool ok = false, pps;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "add") == 0) {
		/* Add a mark, -m/genon will automatically do this
		 * Require marktype
		 * Require workinfoid for all but 'b'
		 * If marktype is 'b' or 'p' then require height/block (number)
		 * If marktype is 'o' or 'f' then require description
		 * Status optional - default READY */
		i_marktype = require_name(trf_root, "marktype",
					  1, NULL,
					  reply, siz);
		if (!i_marktype)
			return strdup(reply);
		marktype = transfer_data(i_marktype);

		if (marktype[0] != MARKTYPE_BLOCK) {
			i_workinfoid = require_name(trf_root, "workinfoid",
						    1, (char *)intpatt,
						    reply, siz);
			if (!i_workinfoid)
				return strdup(reply);
			TXT_TO_BIGINT("workinfoid",
				      transfer_data(i_workinfoid),
				      workinfoid);
		}

		switch (marktype[0]) {
			case MARKTYPE_BLOCK:
			case MARKTYPE_PPLNS:
				i_height = require_name(trf_root,
							"height",
							1, (char *)intpatt,
							reply, siz);
				if (!i_height)
					return strdup(reply);
				TXT_TO_INT("height", transfer_data(i_height),
					   height);
				K_RLOCK(blocks_free);
				b_item = find_prev_blocks(height+1, NULL);
				K_RUNLOCK(blocks_free);
				if (b_item) {
					DATA_BLOCKS(blocks, b_item);
					if (blocks->height != height)
						b_item = NULL;
				}
				if (!b_item) {
					snprintf(reply, siz,
						 "no blocks with height %"PRId32, height);
					return strdup(reply);
				}
				if (marktype[0] == MARKTYPE_BLOCK)
					workinfoid = blocks->workinfoid;

				if (!marks_description(description, sizeof(description),
							marktype, height, NULL, NULL))
					goto dame;
				break;
			case MARKTYPE_SHIFT_BEGIN:
			case MARKTYPE_SHIFT_END:
				snprintf(reply, siz,
					 "marktype %s not yet handled",
					 marks_marktype(marktype));
				return strdup(reply);
			case MARKTYPE_OTHER_BEGIN:
			case MARKTYPE_OTHER_FINISH:
				i_description = require_name(trf_root,
							     "description",
							     1, NULL,
							     reply, siz);
				if (!i_description)
					return strdup(reply);
				if (!marks_description(description, sizeof(description),
							marktype, height, NULL,
							transfer_data(i_description)))
					goto dame;
				break;
			default:
				snprintf(reply, siz,
					 "unknown marktype '%s'", marktype);
				return strdup(reply);
		}
		i_status = optional_name(trf_root, "status", 1, NULL, reply, siz);
		if (i_status) {
			STRNCPY(status, transfer_data(i_status));
			switch(status[0]) {
				case MARK_READY:
				case MARK_USED:
				case '\0':
					break;
				default:
					snprintf(reply, siz,
						 "unknown mark status '%s'", status);
					return strdup(reply);
			}
		}
		if (workinfoid == -1) {
			snprintf(reply, siz, "workinfoid not found");
			return strdup(reply);
		}
		w_item = find_workinfo(workinfoid, NULL);
		if (!w_item) {
			snprintf(reply, siz, "invalid workinfoid %"PRId64,
				 workinfoid);
			return strdup(reply);
		}
		DATA_WORKINFO(workinfo, w_item);
		ok = marks_process(conn, true, workinfo->in_poolinstance,
				   workinfoid, description, extra, marktype,
				   status, by, code, inet, cd, trf_root);
	} else if (strcasecmp(action, "expire") == 0) {
		/* Expire the mark - effectively deletes it
		 * Require workinfoid */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		ok = marks_process(conn, false, EMPTY, workinfoid, NULL,
				   NULL, NULL, NULL, by, code, inet, cd,
				   trf_root);
	} else if (strcasecmp(action, "status") == 0) {
		/* Change the status on a mark
		 * Require workinfoid and status
		 * N.B. you can cause generate errors if you change the status of a USED marks */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		DATA_MARKS(marks, m_item);
		i_status = require_name(trf_root, "status", 0, NULL, reply, siz);
		if (!i_status)
			return strdup(reply);
		STRNCPY(status, transfer_data(i_status));
		switch(status[0]) {
			case MARK_READY:
			case MARK_USED:
			case '\0':
				break;
			default:
				snprintf(reply, siz,
					 "unknown mark status '%s'", status);
				return strdup(reply);
		}
		// Unchanged
		if (strcmp(status, marks->status) == 0) {
			action = "status-unchanged";
			ok = true;
		} else {
			ok = marks_process(conn, true, marks->in_poolinstance,
					   workinfoid, marks->description,
					   marks->extra, marks->marktype,
					   status, by, code, inet, cd,
					   trf_root);
		}
	} else if (strcasecmp(action, "extra") == 0) {
		/* Change the 'extra' description
		 * Require workinfoid and extra
		 * If a mark is actually multiple marks with the same
		 *  workinfoid, then we can record the extra info here
		 * This would be true of each block, once shifts are
		 *  implemented, since the current shift ends when a
		 *  block is found
		 * This could also be true, very rarely, if the beginning
		 *  of a pplns payout range matched any other mark,
		 *  since the beginning can be any workinfoid */
		i_workinfoid = require_name(trf_root, "workinfoid", 1, (char *)intpatt, reply, siz);
		if (!i_workinfoid)
			return strdup(reply);
		TXT_TO_BIGINT("workinfoid", transfer_data(i_workinfoid), workinfoid);
		K_RLOCK(marks_free);
		m_item = find_marks(workinfoid);
		K_RUNLOCK(marks_free);
		if (!m_item) {
			snprintf(reply, siz,
				 "unknown current mark with workinfoid %"PRId64, workinfoid);
			return strdup(reply);
		}
		DATA_MARKS(marks, m_item);
		i_extra = require_name(trf_root, "extra", 0, NULL, reply, siz);
		if (!i_extra)
			return strdup(reply);
		STRNCPY(extra, transfer_data(i_extra));
		// Unchanged
		if (strcmp(extra, marks->extra) == 0) {
			action = "extra-unchanged";
			ok = true;
		} else {
			ok = marks_process(conn, true, marks->in_poolinstance,
					   workinfoid, marks->description,
					   extra, marks->marktype,
					   status, by, code, inet, cd,
					   trf_root);
		}
	} else if (strcasecmp(action, "generate") == 0) {
		/* Generate workmarkers, -m/genon will automatically do this
		 * No parameters */
		tmp[0] = '\0';
		ok = workmarkers_generate(conn, tmp, sizeof(tmp),
					  by, code, inet, cd, trf_root, true);
		if (!ok) {
			snprintf(reply, siz, "%s error: %s", action, tmp);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
		if (*tmp) {
			snprintf(reply, siz, "%s: %s", action, tmp);
			LOGWARNING("%s.%s", id, reply);
		}
	} else if (strcasecmp(action, "expunge") == 0) {
		/* Expire all generated workmarkers that aren't PROCESSED
		 * No parameters
		 * This exists so we can fix all workmarkers that haven't
		 *  been PROCESSED yet,
		 *  if there was a problem with the marks
		 * Simply expunge all the workmarkers, correct the marks,
		 *  then generate the workmarkers again
		 * WARNING - using psql to do the worksummary generation
		 *  will not update the workmarkers status inside ckdb
		 *  so this will expunge those worksummary records also
		 *  You'll need to restart ckdb after using psql */
		int count = 0;
		ok = true;
		wm_item_prev = NULL;
		K_RLOCK(workmarkers_free);
		wm_item = last_in_ktree(workmarkers_root, ctx);
		K_RUNLOCK(workmarkers_free);
		while (wm_item) {
			K_RLOCK(workmarkers_free);
			wm_item_prev = prev_in_ktree(ctx);
			K_RUNLOCK(workmarkers_free);
			DATA_WORKMARKERS(workmarkers, wm_item);
			if (CURRENT(&(workmarkers->expirydate)) &&
			    !WMPROCESSED(workmarkers->status)) {
				ok = workmarkers_process(conn, false, false,
							 workmarkers->markerid,
							 NULL, 0, 0, NULL, NULL, by,
							 code, inet, cd, trf_root);
				if (!ok)
					break;
				count++;
			}
			wm_item = wm_item_prev;
		}
		if (ok) {
			if (count == 0) {
				snprintf(msg, sizeof(msg),
					 "no unprocessed current workmarkers");
			} else {
				snprintf(msg, sizeof(msg),
					 "%d workmarkers expunged", count);
			}
		}
	} else if (strcasecmp(action, "sum") == 0) {
		/* For the last available workmarker,
		 *  summarise it's sharesummaries into markersummaries
		 *  -m/genon will automatically do this
		 * No parameters */
		ok = make_markersummaries(true, by, code, inet, cd, trf_root);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else if (strcasecmp(action, "ready") == 0) {
		/* Mark a processed workmarker as ready
		 *  for fixing problems with markersummaries
		 * Requires markerid */
		i_markerid = require_name(trf_root, "markerid", 1, (char *)intpatt, reply, siz);
		if (!i_markerid)
			return strdup(reply);
		TXT_TO_BIGINT("markerid", transfer_data(i_markerid), markerid);
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
		if (!wm_item) {
			snprintf(reply, siz,
				 "unknown workmarkers with markerid %"PRId64, markerid);
			return strdup(reply);
		}
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (!WMPROCESSED(workmarkers->status)) {
			snprintf(reply, siz,
				 "markerid isn't processed %"PRId64, markerid);
			return strdup(reply);
		}
		ok = workmarkers_process(NULL, false, true, markerid,
					 workmarkers->in_poolinstance,
					 workmarkers->workinfoidend,
					 workmarkers->workinfoidstart,
					 workmarkers->description,
					 MARKER_READY_STR,
					 by, code, inet, cd, trf_root);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else if (strcasecmp(action, "processed") == 0) {
		/* Mark a workmarker as processed
		 * Requires markerid */
		i_markerid = require_name(trf_root, "markerid", 1, (char *)intpatt, reply, siz);
		if (!i_markerid)
			return strdup(reply);
		TXT_TO_BIGINT("markerid", transfer_data(i_markerid), markerid);
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
		if (!wm_item) {
			snprintf(reply, siz,
				 "unknown workmarkers with markerid %"PRId64, markerid);
			return strdup(reply);
		}
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (WMPROCESSED(workmarkers->status)) {
			snprintf(reply, siz,
				 "already processed markerid %"PRId64, markerid);
			return strdup(reply);
		}
		ok = workmarkers_process(NULL, false, true, markerid,
					 workmarkers->in_poolinstance,
					 workmarkers->workinfoidend,
					 workmarkers->workinfoidstart,
					 workmarkers->description,
					 MARKER_PROCESSED_STR,
					 by, code, inet, cd, trf_root);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else if (strcasecmp(action, "cancel") == 0) {
		/* Cancel(delete) all the markersummaries in a workmarker
		 * This can only be done if the workmarker isn't processed
		 * It reports on the console, summary information of the
		 *  markersummaries that were deleted
		 *
		 * WARNING ... if you do this after the workmarker has been
		 *  processed, after switching it to ready, there will no
		 *  longer be any matching shares or sharesummaries in ram
		 *  to regenerate the markersummaries, so you'd need to restart
		 *  ckdb to reload the shares to regenerate the markersummaries
		 *  HOWEVER, ckdb wont reload the shares if there is a later
		 *  workmarker that is already processed
		 *
		 * To reprocess an already processed workmarker, you'd have
		 *  to firstly turn off auto processing with genoff, then
		 *  change the required workmarker, and all after it, to
		 *  ready, then cancel them all, then finally restart ckdb
		 *  which will reload all the necessary shares and regenerate
		 *  the markersummaries
		 *  Of course if you don't have ALL the necessary shares in
		 *   the CCLs then you'd lose data doing this
		 *
		 * K/SS_to_K/MS will complain if any markersummaries already exist
		 *  when processing a workmarker
		 * Normally you would use 'processed' if the markersummaries
		 *  are OK, and just the workmarker failed to be updated to
		 *  processed status
		 * However, if there is actually something wrong with the
		 *  shift data (markersummaries) you can delete them and they
		 *  will be regenerated
		 *  This will usually only work as expected if the last
		 *   workmarker isn't marked as processed, but somehow there
		 *   are markersummaries for it in the DB, thus the reload
		 *   will reload all the shares for the workmarker then it
		 *   will print a warning every 13s on the console saying
		 *   that it can't process the workmarker
		 *   In this case you would cancel the workmarker then ckdb
		 *    will regenerate it from the shares/sharesummaries in ram
		 *
		 * Requires markerid */
		i_markerid = require_name(trf_root, "markerid", 1, (char *)intpatt, reply, siz);
		if (!i_markerid)
			return strdup(reply);
		TXT_TO_BIGINT("markerid", transfer_data(i_markerid), markerid);
		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkerid(markerid, true, '\0');
		K_RUNLOCK(workmarkers_free);
		if (!wm_item) {
			snprintf(reply, siz,
				 "unknown workmarkers with markerid %"PRId64, markerid);
			return strdup(reply);
		}
		DATA_WORKMARKERS(workmarkers, wm_item);
		if (WMPROCESSED(workmarkers->status)) {
			snprintf(reply, siz,
				 "can't cancel a processed markerid %"PRId64,
				 markerid);
			return strdup(reply);
		}

		ok = delete_markersummaries(NULL, workmarkers);
		if (!ok) {
			snprintf(reply, siz, "%s failed", action);
			LOGERR("%s.%s", id, reply);
			return strdup(reply);
		}
	} else if (strcasecmp(action, "genon") == 0) {
		/* Turn on auto marker generation and processing
		 *  and report the before/after status
		 * No parameters */
		bool old = markersummary_auto;
		markersummary_auto = true;
		snprintf(msg, sizeof(msg), "mark generation state was %s,"
					   " now %s",
					   old ? "On" : "Off",
					   markersummary_auto ? "On" : "Off");
		ok = true;
	} else if (strcasecmp(action, "genoff") == 0) {
		/* Turn off auto marker generation and processing
		 *  and report the before/after status
		 * No parameters */
		bool old = markersummary_auto;
		markersummary_auto = false;
		snprintf(msg, sizeof(msg), "mark generation state was %s,"
					   " now %s",
					   old ? "On" : "Off",
					   markersummary_auto ? "On" : "Off");
		ok = true;
	} else if (strcasecmp(action, "pps") == 0) {
		/* Recalculate a shift's rewards/rewarded
		 * Require markerid */
		i_markerid = require_name(trf_root, "markerid", 1,
					  (char *)intpatt, reply, siz);
		if (!i_markerid)
			return strdup(reply);
		TXT_TO_BIGINT("markerid", transfer_data(i_markerid), markerid);

		K_RLOCK(workmarkers_free);
		wm_item = find_workmarkerid(markerid, false, MARKER_PROCESSED);
		K_RUNLOCK(workmarkers_free);
		if (!wm_item) {
			snprintf(reply, siz, "no markerid %"PRId64, markerid);
			return strdup(reply);
		}
		DATA_WORKMARKERS(workmarkers, wm_item);
		pps = shift_rewards(wm_item);
		if (pps) {
			snprintf(msg, sizeof(msg),
				 "shift '%s' markerid %"PRId64" rewards %d "
				 "rewarded %.3e pps %.3e",
				 workmarkers->description,
				 workmarkers->markerid, workmarkers->rewards,
				 workmarkers->rewarded, workmarkers->pps_value);
		} else {
			snprintf(msg, sizeof(msg),
				 "shift '%s' markerid %"PRId64" no rewards yet"
				 " pps %.3e",
				 workmarkers->description,
				 workmarkers->markerid, workmarkers->pps_value);
		}
		ok = true;
	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s.%s", id, reply);
		return strdup(reply);
	}

	if (!ok) {
dame:
		LOGERR("%s() %s.failed.DBE", __func__, id);
		return strdup("failed.DBE");
	}
	if (msg[0])
		snprintf(reply, siz, "ok.%s %s", action, msg);
	else
		snprintf(reply, siz, "ok.%s", action);
	LOGWARNING("%s.%s", id, reply);
	return strdup(reply);
}

// Layout the reply like cmd_shifts so the php/js code is similar
static char *cmd_pshift(__maybe_unused PGconn *conn, char *cmd, char *id,
			  tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd, K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	INTRANSIENT *in_username;
	K_ITEM *u_item, *p_item, *m_item, *wm_item, *ms_item, *wi_item;
	K_TREE_CTX wm_ctx[1];
	WORKMARKERS *wm;
	WORKINFO *wi;
	MARKERSUMMARY *ms;
	PAYOUTS *payouts;
	USERS *users;
	MARKS *marks = NULL;
	char reply[1024] = "";
	char tmp[1024];
	size_t siz = sizeof(reply);
	char *buf;
	size_t len, off;
	tv_t marker_end = { 0L, 0L };
	int rows;
	int64_t maxrows;
	double wm_count, d;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	in_username = adminuser(trf_root, reply, siz);
	if (!in_username)
		return strdup(reply);

	K_RLOCK(users_free);
	u_item = find_users(in_username->str);
	K_RUNLOCK(users_free);
	if (!u_item)
		return strdup("bad");
	DATA_USERS(users, u_item);

	maxrows = user_sys_setting(users->userid, SHIFTS_SETTING_NAME,
				   SHIFTS_DEFAULT, now);

	K_RLOCK(payouts_free);
	p_item = find_last_payouts();
	K_RUNLOCK(payouts_free);
	if (p_item) {
		DATA_PAYOUTS(payouts, p_item);
		wm_count = payout_stats(payouts, "wm_count");
		wm_count *= 1.42;
		if (maxrows < wm_count)
			maxrows = wm_count;
	}

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");
	rows = 0;
	K_RLOCK(workmarkers_free);
	wm_item = last_in_ktree(workmarkers_workinfoid_root, wm_ctx);
	DATA_WORKMARKERS_NULL(wm, wm_item);
	while (rows < (maxrows - 1) && wm_item) {
		if (CURRENT(&(wm->expirydate)) && WMPROCESSED(wm->status)) {
			K_RUNLOCK(workmarkers_free);

			K_RLOCK(marks_free);
			m_item = find_marks(wm->workinfoidend);
			K_RUNLOCK(marks_free);
			DATA_MARKS_NULL(marks, m_item);
			if (m_item == NULL) {
				// Log it but keep going
				LOGERR("%s() missing mark for markerid "
					"%"PRId64"/%s widend %"PRId64,
					__func__, wm->markerid,
					wm->description,
					wm->workinfoidend);
			}

			K_RLOCK(markersummary_free);
			K_RLOCK(workmarkers_free);
			ms_item = find_markersummary_p(wm->markerid);
			K_RUNLOCK(workmarkers_free);
			K_RUNLOCK(markersummary_free);
			if (ms_item) {
				DATA_MARKERSUMMARY(ms, ms_item);
				double_to_buf(ms->diffacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffacc:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				d = ms->diffsta + ms->diffdup + ms->diffhi +
				    ms->diffrej;
				double_to_buf(d, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_diffinv:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				double_to_buf(ms->shareacc, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_shareacc:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				d = ms->sharesta + ms->sharedup + ms->sharehi +
				    ms->sharerej;
				double_to_buf(d, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp), "%d_shareinv:%d=%s%c",
							   0, rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
			}

			if (marker_end.tv_sec == 0L) {
				wi_item = next_workinfo(wm->workinfoidend, NULL);
				if (!wi_item) {
					/* There's no workinfo after this shift
					 * Unexpected ... estimate last wid+30s */
					wi_item = find_workinfo(wm->workinfoidend, NULL);
					if (!wi_item) {
						// Nothing is currently locked
						LOGERR("%s() workmarker %"PRId64"/%s."
							" missing widend %"PRId64,
							__func__, wm->markerid,
							wm->description,
							wm->workinfoidend);
						snprintf(reply, siz, "data error 1");
						free(buf);
						return(strdup(reply));
					}
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
					marker_end.tv_sec += 30;
				} else {
					DATA_WORKINFO(wi, wi_item);
					copy_tv(&marker_end, &(wi->createdate));
				}
			}

			wi_item = find_workinfo(wm->workinfoidstart, NULL);
			if (!wi_item) {
				// Nothing is currently locked
				LOGERR("%s() workmarker %"PRId64"/%s. missing "
					"widstart %"PRId64,
					__func__, wm->markerid, wm->description,
					wm->workinfoidstart);
				snprintf(reply, siz, "data error 2");
				free(buf);
				return(strdup(reply));
			}
			DATA_WORKINFO(wi, wi_item);

			bigint_to_buf(wm->markerid, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "markerid:%d=%s%c",
					   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			str_to_buf(wm->description, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "shift:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			snprintf(tmp, sizeof(tmp), "endmarkextra:%d=%s%c",
						   rows,
						   m_item ? marks->extra : EMPTY,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&(wi->createdate), reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "start:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			ftv_to_buf(&marker_end, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "end:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

			rows++;

			// Setup for next shift
			copy_tv(&marker_end, &(wi->createdate));

			K_RLOCK(workmarkers_free);
		}
		wm_item = prev_in_ktree(wm_ctx);
		DATA_WORKMARKERS_NULL(wm, wm_item);
	}
	K_RUNLOCK(workmarkers_free);

	snprintf(tmp, sizeof(tmp), "%d_pool=%s%c", 0, "all", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%d_flds=%s%c",
		 0, "diffacc,diffinv,shareacc,shareinv", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "prefix_all=%d_%c", 0, FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "rows=%d%cflds=%s%c",
				   rows, FLDSEP,
				   "markerid,shift,start,end", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "arn=%s", "Pool Shifts");
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), ",Pool_%d", 0);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), "%carp=", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);
	snprintf(tmp, sizeof(tmp), ",%d_", 0);
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%s", id, in_username->str);
	return(buf);
}

// Show a status report on the console
static char *cmd_shsta(__maybe_unused PGconn *conn, char *cmd, char *id,
			tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd,
			__maybe_unused K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	char buf[256];

	status_report(now, true);

	snprintf(buf, sizeof(buf), "ok.%s", cmd);
	LOGDEBUG("%s.%s", id, buf);
	return strdup(buf);
}

static char *cmd_userinfo(__maybe_unused PGconn *conn, char *cmd, char *id,
			  __maybe_unused tv_t *now, __maybe_unused char *by,
			  __maybe_unused char *code, __maybe_unused char *inet,
			  __maybe_unused tv_t *notcd,
			  __maybe_unused K_TREE *trf_root,
			  __maybe_unused bool reload_data)
{
	K_ITEM *ui_item;
	USERINFO *userinfo;
	char reply[1024] = "";
	char tmp[1024];
	size_t len, off;
	double d;
	char *buf;
	int rows;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

	rows = 0;
	K_RLOCK(userinfo_free);
	ui_item = STORE_RHEAD(userinfo_store);
	while (ui_item) {
		DATA_USERINFO(userinfo, ui_item);

		str_to_buf(userinfo->in_username, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "username:%d=%s%c",
			 rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "blocks:%d=%d%c", rows,
			 userinfo->blocks -
			 (userinfo->orphans + userinfo->rejects),
			 FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "orphans:%d=%d%c", rows,
			 userinfo->orphans, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(userinfo->diffacc, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "diffacc:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		d = userinfo->diffsta + userinfo->diffdup + userinfo->diffhi +
		    userinfo->diffrej;
		double_to_buf(d, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "diffinv:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		double_to_buf(userinfo->shareacc, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "shareacc:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		d = userinfo->sharesta + userinfo->sharedup + userinfo->sharehi +
		    userinfo->sharerej;
		double_to_buf(d, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "shareinv:%d=%s%c", rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "lastblock=%ld%c",
					   userinfo->last_block.tv_sec, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		rows++;
		ui_item = ui_item->next;
	}
	K_RUNLOCK(userinfo_free);

	snprintf(tmp, sizeof(tmp),
		 "rows=%d%cflds=%s%c",
		 rows, FLDSEP,
		 "username,blocks,orphans,diffacc,diffinv,shareacc,shareinv,"
		 "lastblock", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	snprintf(tmp, sizeof(tmp), "arn=%s%carp=", "UserInfo", FLDSEP);
	APPEND_REALLOC(buf, off, len, tmp);

	LOGDEBUG("%s.ok.%d_rows", id, rows);
	return buf;
}

/* Set/show the BTC server settings
 * You must supply the btcserver to change anything
 * The format for userpass is username:password
 * If you don't supply the btcserver it will simply report the current server
 * If you supply btcserver but not the userpass it will use the current userpass
 * The reply will ONLY contain the URL, not the user/pass */
static char *cmd_btcset(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *notcd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	K_ITEM *i_btcserver, *i_userpass;
	char *btcserver = NULL, *userpass = NULL, *tmp;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char buf[256];

	i_btcserver = optional_name(trf_root, "btcserver", 1, NULL, reply, siz);
	if (i_btcserver) {
		btcserver = strdup(transfer_data(i_btcserver));
		i_userpass = optional_name(trf_root, "userpass", 0, NULL, reply, siz);
		if (i_userpass)
			userpass = transfer_data(i_userpass);

		ck_wlock(&btc_lock);
		btc_server = btcserver;
		btcserver = NULL;
		if (userpass) {
			if (btc_auth) {
				tmp = btc_auth;
				while (*tmp)
					*(tmp++) = '\0';
			}
			FREENULL(btc_auth);
			btc_auth = http_base64(userpass);
		}
		ck_wunlock(&btc_lock);

		if (userpass) {
			tmp = userpass;
			while (*tmp)
				*(tmp++) = '\0';
		}
	}

	FREENULL(btcserver);

	ck_wlock(&btc_lock);
	snprintf(buf, sizeof(buf), "ok.btcserver=%s", btc_server);
	ck_wunlock(&btc_lock);
	LOGDEBUG("%s.%s.%s", id, cmd, buf);
	return strdup(buf);
}

/* Query CKDB for certain information
 * See each string compare below of 'request' for the list of queries
 * For non-error conditions, rows=0 means there were no matching results
 *  for the request, and rows=n is placed last in the reply */
static char *cmd_query(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *cd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	K_TREE_CTX ctx[1];
	char cd_buf[DATE_BUFSIZ];
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024] = "";
	char msg[1024] = "";
	char *buf = NULL;
	size_t len, off;
	K_ITEM *i_request;
	char *request;
	bool ok = false;
	int rows = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_request = require_name(trf_root, "request", 1, NULL, reply, siz);
	if (!i_request)
		return strdup(reply);
	request = transfer_data(i_request);

	APPEND_REALLOC_INIT(buf, off, len);
	APPEND_REALLOC(buf, off, len, "ok.");

	if (strcasecmp(request, "block") == 0) {
		/* return DB information for the blocks with height=value
		 * if expired= is present, it will also return expired records */
		K_ITEM *i_height, *i_expired, *b_item;
		bool expired = false;
		BLOCKS *blocks;
		int32_t height;

		i_height = require_name(trf_root, "height",
					1, (char *)intpatt,
					reply, siz);
		if (!i_height)
			goto badreply;
		TXT_TO_INT("height", transfer_data(i_height), height);

		i_expired = optional_name(trf_root, "expired",
					  0, NULL, reply, siz);
		if (i_expired)
			expired = true;

		int_to_buf(height, reply, sizeof(reply));
		snprintf(msg, sizeof(msg), "height=%s", reply);

		K_RLOCK(blocks_free);
		b_item = find_prev_blocks(height, ctx);
		DATA_BLOCKS_NULL(blocks, b_item);
		while (b_item && blocks->height <= height) {
			if ((expired || CURRENT(&(blocks->expirydate))) &&
			    blocks->height == height) {
				int_to_buf(blocks->height, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "height:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "blockhash:%d=%s%c",
					 rows, blocks->blockhash, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "confirmed:%d=%s%c",
					 rows, blocks->confirmed, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(blocks->expirydate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 EDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(blocks->createdate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 CDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(blocks->blockcreatedate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 "block"CDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(blocks->workinfoid, reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "workinfoid:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				rows++;
			}
			b_item = next_in_ktree(ctx);
			DATA_BLOCKS_NULL(blocks, b_item);
		}
		K_RUNLOCK(blocks_free);

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "height,blockhash,confirmed,"EDDB"_str,"
			 CDDB"_str,block"CDDB"_str,workinfoid", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "Blocks", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "workinfo") == 0) {
		/* return DB information for the workinfo with wid=value
		 * if expired= is present, it will also return expired records
		 *  though ckdb doesn't expire workinfo records - only external
		 *  pgsql scripts would do that to the DB, then ckdb would
		 *  load them the next time it (re)starts */
		K_ITEM *i_wid, *i_expired, *wi_item, *wm_item;
		bool expired = false;
		WORKINFO *workinfo;
		WORKMARKERS *wm;
		int64_t wid;

		i_wid = require_name(trf_root, "wid",
					1, (char *)intpatt,
					reply, siz);
		if (!i_wid)
			goto badreply;
		TXT_TO_BIGINT("wid", transfer_data(i_wid), wid);

		i_expired = optional_name(trf_root, "expired",
					  0, NULL, reply, siz);
		if (i_expired)
			expired = true;

		bigint_to_buf(wid, reply, sizeof(reply));
		snprintf(msg, sizeof(msg), "wid=%s", reply);

		/* We look for the 'next' (or last) workinfo then go backwards
		 *  to ensure we find all expired records in case they
		 *  were requested */
		K_RLOCK(workinfo_free);
		wi_item = next_workinfo(wid, ctx);
		if (!wi_item)
			wi_item = last_in_ktree(workinfo_root, ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		while (wi_item && workinfo->workinfoid >= wid) {
			if ((expired || CURRENT(&(workinfo->expirydate))) &&
			    workinfo->workinfoid == wid) {
				bigint_to_buf(workinfo->workinfoid,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "workinfoid:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				int_to_buf(workinfo->height,
					   reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "height:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "prevhash:%d=%s%c",
					 rows, workinfo->in_prevhash, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(workinfo->expirydate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 EDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(workinfo->createdate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 CDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "ndiff:%d=%.1f%c", rows,
					 workinfo->diff_target,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "ppsvalue:%d=%.15f%c", rows,
					 workinfo_pps(wi_item,
						      workinfo->workinfoid),
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				K_RLOCK(workmarkers_free);
				wm_item = find_workmarkers(wid, false,
							   MARKER_PROCESSED,
							   NULL);
				K_RUNLOCK(workmarkers_free);
				if (!wm_item) {
					snprintf(tmp, sizeof(tmp),
						 "markerid:%d=%c", rows, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					snprintf(tmp, sizeof(tmp),
						 "shift:%d=%c", rows, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					snprintf(tmp, sizeof(tmp),
						 "shiftend:%d=%c", rows, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					snprintf(tmp, sizeof(tmp),
						 "shiftstart:%d=%c", rows, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
				} else {
					DATA_WORKMARKERS(wm, wm_item);
					bigint_to_buf(wm->markerid,
						      reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp),
						 "markerid:%d=%s%c",
						 rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					snprintf(tmp, sizeof(tmp),
						 "shift:%d=%s%c",
						 rows, wm->description, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					bigint_to_buf(wm->workinfoidend,
						      reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp),
						 "shiftend:%d=%s%c",
						 rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
					bigint_to_buf(wm->workinfoidstart,
						      reply, sizeof(reply));
					snprintf(tmp, sizeof(tmp),
						 "shiftstart:%d=%s%c",
						 rows, reply, FLDSEP);
					APPEND_REALLOC(buf, off, len, tmp);
				}
				rows++;
			}
			wi_item = prev_in_ktree(ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		K_RUNLOCK(workinfo_free);

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "workinfoid,height,prevhash,"EDDB"_str,"CDDB"_str,"
			 "ndiff,ppsvalue,markerid,shift,shiftend,shiftstart",
			 FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "Workinfo", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "range") == 0) {
		/* Return the workinfoid range that has block height=height
		 * WARNING! This will traverse workinfo from the end back to
		 *  the given height, and thus since workinfo is the 2nd
		 *  largest tree, it may access swapped data if you request
		 *  older data */
		K_ITEM *i_height, *wi_item;
		WORKINFO *workinfo;
		int32_t height, this_height;
		int64_t idend, idstt;

		i_height = require_name(trf_root, "height",
					1, (char *)intpatt,
					reply, siz);
		if (!i_height)
			goto badreply;
		TXT_TO_INT("height", transfer_data(i_height), height);

		int_to_buf(height, reply, sizeof(reply));
		snprintf(msg, sizeof(msg), "height=%s", reply);

		idend = idstt = 0L;
		/* Start from the last workinfo and continue until we get
		 * below block 'height' */
		K_RLOCK(workinfo_free);
		wi_item = last_in_ktree(workinfo_root, ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		while (wi_item) {
			this_height = workinfo->height;
			if (this_height < height)
				break;
			if (CURRENT(&(workinfo->expirydate)) &&
			    this_height == height) {
				if (idend == 0L)
					idend = workinfo->workinfoid;
				idstt = workinfo->workinfoid;
			}
			wi_item = prev_in_ktree(ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		K_RUNLOCK(workinfo_free);

		int_to_buf(height, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "height:%d=%s%c",
					   rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		bigint_to_buf(idend, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "workinfoidend:%d=%s%c",
					   rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		bigint_to_buf(idstt, reply, sizeof(reply));
		snprintf(tmp, sizeof(tmp), "workinfoidstart:%d=%s%c",
					   rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		rows++;

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "height,workinfoidend,workinfoidstart", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "WorkinfoRange", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "diff") == 0) {
		/* return the details of the next diff change after
		 *  block height=height
		 * WARNING! This will traverse workinfo from the end back to
		 *  the given height, and thus since workinfo is the 2nd
		 *  largest tree, it may access swapped data if you request
		 *  older data */
		K_ITEM *i_height, *wi_item;
		WORKINFO *workinfo = NULL;
		int32_t height, this_height;
		char bits[TXT_SML+1];
		bool got = false;

		i_height = require_name(trf_root, "height",
					1, (char *)intpatt,
					reply, siz);
		if (!i_height)
			goto badreply;
		TXT_TO_INT("height", transfer_data(i_height), height);

		int_to_buf(height, reply, sizeof(reply));
		snprintf(msg, sizeof(msg), "height=%s", reply);

		snprintf(tmp, sizeof(tmp), "height0:%d=%s%c",
					   rows, reply, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		/* Start from the last workinfo and continue until we get
		 * below block 'height' */
		K_RLOCK(workinfo_free);
		wi_item = last_in_ktree(workinfo_root, ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		while (wi_item) {
			if (CURRENT(&(workinfo->expirydate))) {
				this_height = workinfo->height;
				if (this_height < height)
					break;
			}
			wi_item = prev_in_ktree(ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		// If we fell off the front use the first one
		if (!wi_item)
			wi_item = first_in_ktree(workinfo_root, ctx);
		DATA_WORKINFO_NULL(workinfo, wi_item);
		while (wi_item) {
			if (CURRENT(&(workinfo->expirydate))) {
				this_height = workinfo->height;
				if (this_height >= height)
					break;
			}
			wi_item = next_in_ktree(ctx);
			DATA_WORKINFO_NULL(workinfo, wi_item);
		}
		if (wi_item) {
			DATA_WORKINFO(workinfo, wi_item);
			this_height = workinfo->height;
			if (this_height == height) {
				// We have our starting point
				STRNCPY(bits, workinfo->in_bits);
				got = true;

				bigint_to_buf(workinfo->workinfoid,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "workinfoid0:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "ndiff0:%d=%.1f%c", rows,
					 workinfo->diff_target,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				while (wi_item) {
					if (CURRENT(&(workinfo->expirydate))) {
						if (strcmp(bits, workinfo->in_bits) != 0)
							break;
					}
					wi_item = next_in_ktree(ctx);
					DATA_WORKINFO_NULL(workinfo, wi_item);
				}
			} else
				wi_item = NULL;
		}
		K_RUNLOCK(workinfo_free);

		if (!got) {
			snprintf(tmp, sizeof(tmp), "workinfoid0:%d=%c",
						   rows, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "ndiff0:%d=%c",
						   rows, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}

		if (!wi_item) {
			snprintf(tmp, sizeof(tmp), "height:%d=%c",
						   rows, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "workinfoid:%d=%c",
						   rows, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "ndiff:%d=%c",
						   rows, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		} else {
			this_height = workinfo->height;
			int_to_buf(this_height, reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "height:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			bigint_to_buf(workinfo->workinfoid,
				      reply, sizeof(reply));
			snprintf(tmp, sizeof(tmp), "workinfoid:%d=%s%c",
						   rows, reply, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "ndiff:%d=%.1f%c",
						   rows,
						   workinfo->diff_target,
						   FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
		}

		rows++;

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "height0,workinfoid0,ndiff0,height,workinfo,ndiff",
			 FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "WorkinfoRange", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "payout") == 0) {
		/* return the details of the payouts for block height=height
		 * if expired= is present, also return expired records */
		K_ITEM *i_height, *i_expired, *p_item;
		PAYOUTS *payouts = NULL;
		bool expired = false;
		int32_t height;
		char *stats = NULL, *ptr;

		i_height = require_name(trf_root, "height",
					1, (char *)intpatt,
					reply, siz);
		if (!i_height)
			goto badreply;
		TXT_TO_INT("height", transfer_data(i_height), height);

		int_to_buf(height, reply, sizeof(reply));
		snprintf(msg, sizeof(msg), "height=%s", reply);

		i_expired = optional_name(trf_root, "expired",
					  0, NULL, reply, siz);
		if (i_expired)
			expired = true;

		K_RLOCK(payouts_free);
		p_item = first_payouts(height, ctx);
		DATA_PAYOUTS_NULL(payouts, p_item);
		while (p_item && payouts->height == height) {
			if (expired || CURRENT(&(payouts->expirydate))) {
				int_to_buf(payouts->height,
					   reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "height:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(payouts->payoutid,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "payoutid:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(payouts->minerreward,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "minerreward:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(payouts->workinfoidstart,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "workinfoidstart:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(payouts->workinfoidend,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "workinfoidend:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				bigint_to_buf(payouts->elapsed,
					      reply, sizeof(reply));
				snprintf(tmp, sizeof(tmp),
					 "elapsed:%d=%s%c",
					 rows, reply, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "status:%d=%s%c",
					 rows, payouts->status, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "diffwanted:%d=%f%c",
					 rows, payouts->diffwanted, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "diffused:%d=%f%c",
					 rows, payouts->diffused, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				ptr = stats = strdup(payouts->stats);
				if (!stats) {
					quithere(1, "strdup (%"PRId64") OOM",
						    payouts->payoutid);
				}
				while (*ptr) {
					if (*ptr == FLDSEP)
						*ptr = ' ';
					ptr++;
				}
				snprintf(tmp, sizeof(tmp),
					 "stats:%d=%s%c",
					 rows, stats, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				FREENULL(stats);
				tv_to_buf(&(payouts->expirydate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 EDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				tv_to_buf(&(payouts->createdate), cd_buf,
					  sizeof(cd_buf));
				snprintf(tmp, sizeof(tmp),
					 CDDB"_str:%d=%s%c",
					 rows, cd_buf, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				rows++;
			}
			p_item = next_in_ktree(ctx);
			DATA_PAYOUTS_NULL(payouts, p_item);
		}
		K_RUNLOCK(payouts_free);

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "height,payoutid,minerreward,workinfoidstart,"
			 "workinfoidend,elapsed,status,diffwanted,diffused,"
			 "stats,"EDDB"_str,"CDDB"_str",
			 FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "Payouts", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "shareinfo") == 0) {
		/* return share information for the workinfo with wid>=value
		 * if wid=0 then find the oldest workinfo that has shares */
		K_ITEM *i_wid, s_look, *s_item;
		SHARES lookshares, *shares;
		int64_t selwid, wid, s_count = 0, s_diff = 0, s_sdiff = 0;
		bool found;

		i_wid = require_name(trf_root, "wid",
					1, (char *)intpatt,
					reply, siz);
		if (!i_wid)
			goto badreply;
		TXT_TO_BIGINT("wid", transfer_data(i_wid), selwid);

		INIT_SHARES(&s_look);
		lookshares.workinfoid = selwid;
		lookshares.userid = -1;
		lookshares.in_workername = EMPTY;
		DATE_ZERO(&(lookshares.createdate));
		s_look.data = (void *)(&lookshares);
		found = false;
		K_RLOCK(shares_free);
		s_item = find_after_in_ktree(shares_root, &s_look, ctx);
		if (s_item) {
			found = true;
			DATA_SHARES(shares, s_item);
			wid = shares->workinfoid;
			while (s_item) {
				DATA_SHARES(shares, s_item);
				if (shares->workinfoid != wid)
					break;
				s_count++;
				s_diff += shares->diff;
				if (s_sdiff < shares->sdiff)
					s_sdiff = shares->sdiff;
				s_item = next_in_ktree(ctx);
			}
		}
		K_RUNLOCK(shares_free);

		if (found) {
			snprintf(tmp, sizeof(tmp), "selwid=%"PRId64"%c",
				 selwid, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "wid=%"PRId64"%c",
				 wid, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "shares=%"PRId64"%c",
				 s_count, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "diff=%"PRId64"%c",
				 s_diff, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "maxsdiff=%"PRId64"%c",
				 s_sdiff, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			rows++;
		}

		ok = true;
	} else if (strcasecmp(request, "nameram") == 0) {
		NAMERAM *nameram = NULL;
		K_ITEM *n_item;

		K_RLOCK(nameram_free);
		n_item = STORE_RHEAD(nameram_store);
		while (n_item) {
			DATA_NAMERAM(nameram, n_item);
			snprintf(tmp, sizeof(tmp), "rem:%d=%d%c",
				 rows, (int)sizeof(nameram->rem), FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "left:%d=%d%c",
				 rows, (int)(nameram->left), FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			n_item = n_item->next;
			rows++;
		}
		K_RUNLOCK(nameram_free);
		snprintf(tmp, sizeof(tmp), "flds=%s%c", "rem,left", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "NameRAM", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "ioqueue") == 0) {
		K_RLOCK(ioqueue_free);
		snprintf(tmp, sizeof(tmp), "console=%d%c",
			 console_ioqueue_store->count, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "file=%d%c",
			 ioqueue_store->count, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		K_RUNLOCK(ioqueue_free);
		rows++;

		ok = true;
	} else if (strcasecmp(request, "esm") == 0) {
		K_ITEM *esm_item;
		ESM *esm = NULL;

		K_RLOCK(esm_free);
		esm_item = first_in_ktree(esm_root, ctx);
		while (esm_item) {
			DATA_ESM(esm, esm_item);
			snprintf(tmp, sizeof(tmp), "workinfoid:%d=%"PRId64"%c",
				 rows, esm->workinfoid, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "queued:%d=%d%c",
				 rows, esm->queued, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "procured:%d=%d%c",
				 rows, esm->procured, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "discarded:%d=%d%c",
				 rows, esm->discarded, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "errqueued:%d=%d%c",
				 rows, esm->errqueued, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "errprocured:%d=%d%c",
				 rows, esm->errprocured, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			snprintf(tmp, sizeof(tmp), "errdiscarded:%d=%d%c",
				 rows, esm->errdiscarded, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			tv_to_buf(&(esm->createdate), cd_buf, sizeof(cd_buf));
			snprintf(tmp, sizeof(tmp), CDDB"_str:%d=%s%c",
				 rows, cd_buf, FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);
			esm_item = next_in_ktree(ctx);
			rows++;
		}
		K_RUNLOCK(esm_free);
		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "workinfoid,queued,procured,discarded,errqueued,"
			 "errprocured,errdiscarded,"CDDB"_str", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 "ESM", FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
	} else if (strcasecmp(request, "pg") == 0) {
		K_RLOCK(pgdb_free);
		snprintf(tmp, sizeof(tmp), "connections=%d%c",
			 pgdb_count, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		K_RUNLOCK(pgdb_free);
		rows++;

		ok = true;
#if 0
	} else if (strcasecmp(request, "transfer") == 0) {
		/* Code for debugging the transfer stores
		 *  limit is set to avoid a very large reply,
		 *  since transfer can be millions of items during a reload */
		TRANSFER *trf = NULL;
		K_STORE *trf_store;
		K_ITEM *trf_item, *i_limit;
		int stores = 0, limit = 20, tot_stores = 0;
		bool exceeded = false;

		i_limit = optional_name(trf_root, "limit",
					1, (char *)intpatt,
					reply, siz);
		if (*reply) {
			LOGERR("%s() %s.%s", __func__, id, reply);
			goto badreply;
		}
		if (i_limit)
			limit = atoi(transfer_data(i_limit));

		snprintf(tmp, sizeof(tmp), "limit=%d%c", limit, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		K_RLOCK(transfer_free);
		trf_store = transfer_free->next_store;
		while (!exceeded && trf_store) {
			trf_item = trf_store->head;
			while (trf_item) {
				if (rows >= limit) {
					exceeded = true;
					break;
				}
				DATA_TRANSFER(trf, trf_item);
				snprintf(tmp, sizeof(tmp), "store:%d=%d%c",
					 rows, stores, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "storename:%d=%s%c",
					 rows, trf_store->name, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "name:%d=%s%c",
					 rows, trf->name, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "mvalue:%d=%s%c",
					 rows, trf->mvalue, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp),
					 "malloc:%d=%"PRIu64"%c",
					 rows, trf->msiz, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "intrans:%d=%c%c",
					 rows, trf->intransient ? 'Y' : 'N',
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);

				trf_item = trf_item->next;
				rows++;
			}
			trf_store = trf_store->next_store;
			stores++;
		}
		tot_stores = stores;
		if (exceeded) {
			while (trf_store) {
				trf_store = trf_store->next_store;
				tot_stores++;
			}
		}
		K_RUNLOCK(transfer_free);

		snprintf(tmp, sizeof(tmp), "rowstores=%d%c",
			 stores, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "totstores=%d%c",
			 tot_stores, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "limitexceeded=%c%c",
			 exceeded ? 'Y' : 'N', FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		snprintf(tmp, sizeof(tmp), "flds=%s%c",
			 "store,storename,name,mvalue,malloc,intrans", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		snprintf(tmp, sizeof(tmp), "arn=%s%carp=%s%c",
			 transfer_free->name, FLDSEP, "", FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);

		ok = true;
#endif
	} else {
		snprintf(reply, siz, "unknown request '%s'", request);
		LOGERR("%s() %s.%s", __func__, id, reply);
		goto badreply;
	}

	if (!ok) {
		snprintf(reply, siz, "failed.%s%s%s",
					request,
					msg[0] ? " " : "",
					msg[0] ? msg : "");
		LOGERR("%s() %s.%s", __func__, id, reply);
		goto badreply;
	}

	snprintf(tmp, sizeof(tmp), "rows=%d", rows);
	APPEND_REALLOC(buf, off, len, tmp);
	LOGWARNING("%s() %s.%s%s%s", __func__, id, request,
				     msg[0] ? " " : "",
				     msg[0] ? msg : "");
	return buf;

badreply:
	free(buf);
	return strdup(reply);
}

// Query and disable internal lock detection code
static char *cmd_locks(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *cd,
			__maybe_unused K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	bool code_locks = false, code_deadlocks = false;
	bool was_locks = false, was_deadlocks = false;
	bool new_locks = false, new_deadlocks = false;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
#if LOCK_CHECK
	K_ITEM *i_locks, *i_deadlocks;
	char *deadlocks;
#endif

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

#if LOCK_CHECK
	code_locks = true;
	was_locks = new_locks = check_locks;

	code_deadlocks = true;
	was_deadlocks = new_locks = check_deadlocks;
#endif

	/* options are
	 *  locks <- disable lock checking if it's enabled (value ignored)
	 *  deadlocks=Y/N <- enable/disable deadlock prediction
	 *  	any word with any case starting with 'Y' means enable it
	 *  	anything else means disable it
	 *  	When you enable it, it won't re-enable it for threads that
	 *  	 have failed a deadlock prediction test
	 * It will report the status of both */

#if LOCK_CHECK
	i_locks = optional_name(trf_root, "locks", 0, NULL, reply, siz);
	if (i_locks)
		new_locks = check_locks = false;

	i_deadlocks = optional_name(trf_root, "deadlocks", 0, NULL, reply, siz);
	if (i_deadlocks) {
		deadlocks = transfer_data(i_deadlocks);
		if (toupper(*deadlocks) == TRUE_CHR)
			check_deadlocks = true;
		else
			check_deadlocks = false;
		new_deadlocks = check_deadlocks;
	}
#endif

	snprintf(reply, siz,
		 "code_locks=%s%cwas_locks=%s%cnew_locks=%s%c"
		 "code_deadlocks=%s%cwas_deadlocks=%s%cnew_deadlocks=%s",
		 TFSTR(code_locks), FLDSEP, TFSTR(was_locks), FLDSEP,
		 TFSTR(new_locks), FLDSEP, TFSTR(code_deadlocks), FLDSEP,
		 TFSTR(was_deadlocks), FLDSEP, TFSTR(new_deadlocks));
	LOGWARNING("%s() %s.%s", __func__, id, reply);
	return strdup(reply);
}

static void event_tree(K_TREE *the_tree, char *list, char *reply, size_t siz,
			char **buf, size_t *off, size_t *len, int *rows)
{
	K_TREE_CTX ctx[1];
	K_ITEM *e_item;
	EVENTS *e;

	LOGDEBUG(">%s() tree='%s' list='%s'", __func__, the_tree->name, list);
	e_item = first_in_ktree(the_tree, ctx);
	while (e_item) {
		DATA_EVENTS(e, e_item);
		if (CURRENT(&(e->expirydate))) {
			snprintf(reply, siz, "list:%d=%s%c",
				 *rows, list, FLDSEP);
			APPEND_REALLOC(*buf, *off, *len, reply);
			snprintf(reply, siz, "id:%d=%d%c",
				 *rows, e->id, FLDSEP);
			APPEND_REALLOC(*buf, *off, *len, reply);
			snprintf(reply, siz, "idname:%d=%s%c",
				 *rows, e_limits[e->id].name, FLDSEP);
			APPEND_REALLOC(*buf, *off, *len, reply);
			snprintf(reply, siz, "user:%d=%s%c",
				 *rows, e->createby, FLDSEP);
			APPEND_REALLOC(*buf, *off, *len, reply);

			if (the_tree == events_ipc_root) {
				snprintf(reply, siz, "ipc:%d=%s%c",
					 *rows, e->ipc, FLDSEP);
				APPEND_REALLOC(*buf, *off, *len, reply);
			} else {
				snprintf(reply, siz, "ip:%d=%s%c",
					 *rows, e->createinet, FLDSEP);
				APPEND_REALLOC(*buf, *off, *len, reply);
			}

			if (the_tree == events_hash_root) {
				snprintf(reply, siz, "hash:%d=%.8s%c",
					 *rows, e->hash, FLDSEP);
				APPEND_REALLOC(*buf, *off, *len, reply);
			}

			snprintf(reply, siz, CDTRF":%d=%ld%c",
				 *rows, e->createdate.tv_sec, FLDSEP);
			APPEND_REALLOC(*buf, *off, *len, reply);

			(*rows)++;
		}
		e_item = next_in_ktree(ctx);
	}
}

// Events status/settings
static char *cmd_events(__maybe_unused PGconn *conn, char *cmd, char *id,
			tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *cd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	K_ITEM *i_action, *i_cmd, *i_list, *i_ip, *i_eventname, *i_lifetime;
	K_ITEM *i_des, *i_item, *next_item, *o_item;
	K_TREE_CTX ctx[1];
	OVENTS *ovents;
	IPS *ips;
	char *action, *alert_cmd, *list, *ip, *eventname, *des;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char tmp[1024] = "";
	char *buf = NULL;
	size_t len, off;
	int i, rows, oldlife, lifetime, vid, min;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "cmd") == 0) {
		/* Change ckdb_alert_cmd to 'cmd'
		 * blank to disable it */
		i_cmd = require_name(trf_root, "cmd", 0, NULL, reply, siz);
		if (!i_cmd)
			return strdup(reply);
		alert_cmd = transfer_data(i_cmd);
		if (strlen(alert_cmd) > MAX_ALERT_CMD)
			return strdup("Invalid cmd length - limit " STRINT(MAX_ALERT_CMD));
		K_WLOCK(event_limits_free);
		FREENULL(ckdb_alert_cmd);
		if (*alert_cmd)
			ckdb_alert_cmd = strdup(alert_cmd);
		K_WUNLOCK(event_limits_free);
		APPEND_REALLOC_INIT(buf, off, len);
		if (*alert_cmd)
			APPEND_REALLOC(buf, off, len, "ok.cmd set");
		else
			APPEND_REALLOC(buf, off, len, "ok.cmd disabled");
	} else if (strcasecmp(action, "settings") == 0) {
		// Return all current event settings
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		K_RLOCK(event_limits_free);
		i = -1;
		while (e_limits[++i].name) {
			snprintf(tmp, sizeof(tmp), "%s_enabled=%c%c",
				 e_limits[i].name,
				 e_limits[i].enabled ? TRUE_CHR : FALSE_CHR,
				 FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

#define EVENTFLD(_fld) do { \
		snprintf(tmp, sizeof(tmp), "%s_" #_fld "=%d%c", \
			 e_limits[i].name, e_limits[i]._fld, FLDSEP); \
		APPEND_REALLOC(buf, off, len, tmp); \
	} while (0)

			EVENTFLD(user_low_time);
			EVENTFLD(user_low_time_limit);
			EVENTFLD(user_hi_time);
			EVENTFLD(user_hi_time_limit);
			EVENTFLD(ip_low_time);
			EVENTFLD(ip_low_time_limit);
			EVENTFLD(ip_hi_time);
			EVENTFLD(ip_hi_time_limit);
			EVENTFLD(lifetime);
		}
		snprintf(tmp, sizeof(tmp), "event_limits_hash_lifetime=%d%c",
			 event_limits_hash_lifetime, FLDSEP);
		APPEND_REALLOC(buf, off, len, tmp);
		i = -1;
		while (o_limits[++i].name) {
			snprintf(tmp, sizeof(tmp), "%s_enabled=%c%c",
				 o_limits[i].name,
				 o_limits[i].enabled ? TRUE_CHR : FALSE_CHR,
				 FLDSEP);
			APPEND_REALLOC(buf, off, len, tmp);

#define OVENTFLD(_fld) do { \
		snprintf(tmp, sizeof(tmp), "%s_" #_fld "=%d%c", \
			 o_limits[i].name, o_limits[i]._fld, FLDSEP); \
		APPEND_REALLOC(buf, off, len, tmp); \
	} while (0)

			OVENTFLD(user_low_time);
			OVENTFLD(user_low_time_limit);
			OVENTFLD(user_hi_time);
			OVENTFLD(user_hi_time_limit);
			OVENTFLD(ip_low_time);
			OVENTFLD(ip_low_time_limit);
			OVENTFLD(ip_hi_time);
			OVENTFLD(ip_hi_time_limit);
			OVENTFLD(lifetime);
		}
		snprintf(tmp, sizeof(tmp), "ovent_limits_ipc_factor=%f",
			 ovent_limits_ipc_factor);
		APPEND_REALLOC(buf, off, len, tmp);
		K_RUNLOCK(event_limits_free);
	} else if (strcasecmp(action, "events") == 0) {
		/* List the event tree contents
		 * List is 'all' or one of: hash, user, ip or ipc <- tree names
		 * Output can be large - check web Admin->ckp for tree sizes */
		bool all, one = false;
		i_list = require_name(trf_root, "list", 1, NULL, reply, siz);
		if (!i_list)
			return strdup(reply);
		list = transfer_data(i_list);
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		rows = 0;
		all = (strcmp(list, "all") == 0);
		K_RLOCK(events_free);
		if (all || strcmp(list, "user") == 0) {
			one = true;
			event_tree(events_user_root, "user", reply, siz, &buf,
				   &off, &len, &rows);
		}
		if (all || strcmp(list, "ip") == 0) {
			one = true;
			event_tree(events_ip_root, "ip", reply, siz, &buf,
				   &off, &len, &rows);
		}
		if (all || strcmp(list, "ipc") == 0) {
			one = true;
			event_tree(events_ipc_root, "ipc", reply, siz, &buf,
				   &off, &len, &rows);
		}
		if (all || strcmp(list, "hash") == 0) {
			one = true;
			event_tree(events_hash_root, "hash", reply, siz, &buf,
				   &off, &len, &rows);
		}
		K_RUNLOCK(events_free);
		if (!one) {
			free(buf);
			snprintf(reply, siz, "unknown stats list '%s'", list);
			LOGERR("%s() %s.%s", __func__, id, reply);
			return strdup(reply);
		}
		snprintf(tmp, sizeof(tmp), "rows=%d", rows);
		APPEND_REALLOC(buf, off, len, tmp);
	} else if (strcasecmp(action, "ips") == 0) {
		// List the ips tree contents
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		rows = 0;
		K_RLOCK(ips_free);
		i_item = first_in_ktree(ips_root, ctx);
		while (i_item) {
			DATA_IPS(ips, i_item);
			if (CURRENT(&(ips->expirydate))) {
				snprintf(tmp, sizeof(tmp), "group:%d=%s%c",
					 rows, ips->group, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "ip:%d=%s%c",
					 rows, ips->ip, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "eventname:%d=%s%c",
					 rows, ips->eventname, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "is_event:%d=%c%c",
					 rows,
					 ips->is_event ?  TRUE_CHR : FALSE_CHR,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "lifetime:%d=%d%c",
					 rows, ips->lifetime, FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "log:%d=%c%c",
					 rows, ips->log ? TRUE_CHR : FALSE_CHR,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(tmp, sizeof(tmp), "description:%d=%s%c",
					 rows, ips->description ? : EMPTY,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, tmp);
				snprintf(reply, siz, CDTRF":%d=%ld%c",
					 rows++, ips->createdate.tv_sec,
					 FLDSEP);
				APPEND_REALLOC(buf, off, len, reply);
			}
			i_item = next_in_ktree(ctx);
		}
		K_RUNLOCK(ips_free);
		snprintf(tmp, sizeof(tmp), "rows=%d", rows);
		APPEND_REALLOC(buf, off, len, tmp);
	} else if (strcasecmp(action, "ban") == 0) {
		/* Ban the ip with optional eventname and lifetime
		 * N.B. this doesn't survive a CKDB restart
		 *	use just cmd_setopts for permanent bans */
		bool found = false;
		oldlife = 0;
		i_ip = require_name(trf_root, "ip", 1, NULL, reply, siz);
		if (!i_ip)
			return strdup(reply);
		ip = transfer_data(i_ip);
		i_eventname = optional_name(trf_root, "eventname", 1, NULL, reply, siz);
		if (i_eventname)
			eventname = transfer_data(i_eventname);
		else {
			if (*reply)
				return strdup(reply);
			eventname = EVENTNAME_ALL;
		}
		i_lifetime = optional_name(trf_root, "lifetime", 1,
					   (char *)intpatt, reply, siz);
		if (i_lifetime)
			lifetime = atoi(transfer_data(i_lifetime));
		else {
			if (*reply)
				return strdup(reply);
			// default to almost 42 years :)
			lifetime = 60*60*24*365*42;
		}
		i_des = optional_name(trf_root, "des", 1, NULL, reply, siz);
		if (i_des)
			des = transfer_data(i_des);
		else {
			if (*reply)
				return strdup(reply);
			des = NULL;
		}
		K_WLOCK(ips_free);
		i_item = find_ips(IPS_GROUP_BAN, ip, eventname, NULL);
		if (i_item) {
			DATA_IPS(ips, i_item);
			found = true;
			oldlife = ips->lifetime;
			ips->lifetime = lifetime;
			// Don't change it if it's not supplied
			if (des) {
				LIST_MEM_SUB(ips_free, ips->description);
				FREENULL(ips->description);
				ips->description = strdup(des);
				LIST_MEM_ADD(ips_free, ips->description);
			}
		} else {
			ips_add(IPS_GROUP_BAN, ip, eventname,
				is_elimitname(eventname, true), des, true,
				false, lifetime, true);
		}
		K_WUNLOCK(ips_free);
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		if (found) {
			snprintf(tmp, sizeof(tmp), "already %s/%s %d->%d",
				 ip, eventname, oldlife, lifetime);
		} else {
			snprintf(tmp, sizeof(tmp), "ban %s/%s %d",
				 ip, eventname, lifetime);
		}
		APPEND_REALLOC(buf, off, len, tmp);
	} else if (strcasecmp(action, "unban") == 0) {
		/* Unban the ip+eventname - sets lifetime to 1 meaning
		 *  it expires 1 second after it was created
		 *  so next access will remove the ban and succeed
		 * N.B. if it was a permanent 'cmd_setopts' ban, the unban
		 *	won't survive a CKDB restart.
		 *	You need to BOTH use this AND remove the optioncontrol
		 *	record from the database to permanently remove a ban
		 *	(since there's no cmd_expopts ... yet) */
		bool found = false;
		i_ip = require_name(trf_root, "ip", 1, NULL, reply, siz);
		if (!i_ip)
			return strdup(reply);
		ip = transfer_data(i_ip);
		i_eventname = require_name(trf_root, "eventname", 1, NULL, reply, siz);
		if (!i_eventname)
			return strdup(reply);
		eventname = transfer_data(i_eventname);
		K_WLOCK(ips_free);
		i_item = find_ips(IPS_GROUP_BAN, ip, eventname, NULL);
		if (i_item) {
			found = true;
			DATA_IPS(ips, i_item);
			ips->lifetime = 1;
		}
		K_WUNLOCK(ips_free);
		APPEND_REALLOC_INIT(buf, off, len);
		if (found) {
			APPEND_REALLOC(buf, off, len, "ok.");
			APPEND_REALLOC(buf, off, len, ip);
			APPEND_REALLOC(buf, off, len, "/");
			APPEND_REALLOC(buf, off, len, eventname);
			APPEND_REALLOC(buf, off, len, " unbanned");
		} else {
			APPEND_REALLOC(buf, off, len,
					"ERR.unknown BAN ip+eventname");
		}
	} else if (strcasecmp(action, "ok") == 0) {
		/* OK the ip+eventname with optional lifetime
		 * N.B. this doesn't survive a CKDB restart
		 *	use just cmd_setopts for permanent OKs */
		bool found = false;
		oldlife = 0;
		i_ip = require_name(trf_root, "ip", 1, NULL, reply, siz);
		if (!i_ip)
			return strdup(reply);
		ip = transfer_data(i_ip);
		i_eventname = require_name(trf_root, "eventname", 1, NULL, reply, siz);
		if (!i_eventname)
			return strdup(reply);
		eventname = transfer_data(i_eventname);
		i_lifetime = optional_name(trf_root, "lifetime", 1,
					   (char *)intpatt, reply, siz);
		if (i_lifetime)
			lifetime = atoi(transfer_data(i_lifetime));
		else {
			if (*reply)
				return strdup(reply);
			// Forever
			lifetime = 0;
		}
		i_des = optional_name(trf_root, "des", 1, NULL, reply, siz);
		if (i_des)
			des = transfer_data(i_des);
		else {
			if (*reply)
				return strdup(reply);
			des = NULL;
		}
		K_WLOCK(ips_free);
		i_item = find_ips(IPS_GROUP_OK, ip, eventname, NULL);
		if (i_item) {
			DATA_IPS(ips, i_item);
			found = true;
			oldlife = ips->lifetime;
			ips->lifetime = lifetime;
			// Don't change it if it's not supplied
			if (des) {
				LIST_MEM_SUB(ips_free, ips->description);
				FREENULL(ips->description);
				ips->description = strdup(des);
				LIST_MEM_ADD(ips_free, ips->description);
			}
		} else {
			ips_add(IPS_GROUP_OK, ip, eventname,
				is_elimitname(eventname, true), des, true,
				false, lifetime, true);
		}
		K_WUNLOCK(ips_free);
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		if (found) {
			snprintf(tmp, sizeof(tmp), "already %s/%s %d->%d",
				 ip, eventname, oldlife, lifetime);
		} else {
			snprintf(tmp, sizeof(tmp), "ok %s/%s %d",
				 ip, eventname, lifetime);
		}
		APPEND_REALLOC(buf, off, len, tmp);
	} else if (strcasecmp(action, "unok") == 0) {
		/* UnOK the ip+eventname - sets lifetime to 1 meaning
		 *  it expires 1 second after it was created
		 *  so next access will remove the OK and succeed
		 * N.B. if it was a permanent 'cmd_setopts' OK, the unOK
		 *	won't survive a CKDB restart.
		 *	You need to BOTH use this AND remove the optioncontrol
		 *	record from the database to permanently remove an OK
		 *	(since there's no cmd_expopts ... yet) */
		bool found = false;
		i_ip = require_name(trf_root, "ip", 1, NULL, reply, siz);
		if (!i_ip)
			return strdup(reply);
		ip = transfer_data(i_ip);
		i_eventname = require_name(trf_root, "eventname", 1, NULL, reply, siz);
		if (!i_eventname)
			return strdup(reply);
		eventname = transfer_data(i_eventname);
		K_WLOCK(ips_free);
		i_item = find_ips(IPS_GROUP_OK, ip, eventname, NULL);
		if (i_item) {
			found = true;
			DATA_IPS(ips, i_item);
			ips->lifetime = 1;
		}
		K_WUNLOCK(ips_free);
		APPEND_REALLOC_INIT(buf, off, len);
		if (found) {
			APPEND_REALLOC(buf, off, len, "ok.");
			APPEND_REALLOC(buf, off, len, ip);
			APPEND_REALLOC(buf, off, len, "/");
			APPEND_REALLOC(buf, off, len, eventname);
			APPEND_REALLOC(buf, off, len, " unOKed");
		} else {
			APPEND_REALLOC(buf, off, len,
					"ERR.unknown OK ip+eventname");
		}
	} else if (strcasecmp(action, "expire") == 0) {
		/* Expire all ips that are too old
		 *  and remove all non-current */
		bool expire;
		rows = 0;
		K_WLOCK(ips_free);
		i_item = first_in_ktree(ips_root, ctx);
		while (i_item) {
			DATA_IPS(ips, i_item);
			expire = false;
			if (!CURRENT(&(ips->expirydate)))
				expire = true;
			else if (ips->lifetime != 0 &&
				 (int)tvdiff(now, &(ips->createdate)) > ips->lifetime) {
					expire = true;
				}
			if (expire) {
				rows++;
				next_item = next_in_ktree(ctx);
				remove_from_ktree(ips_root, i_item);
				k_unlink_item(ips_store, i_item);
				if (ips->description) {
					LIST_MEM_SUB(ips_free, ips->description);
					FREENULL(ips->description);
				}
				k_add_head(ips_free, i_item);
				i_item = next_item;
				continue;
			}
			i_item = next_in_ktree(ctx);
		}
		K_WUNLOCK(ips_free);
		APPEND_REALLOC_INIT(buf, off, len);
		snprintf(tmp, sizeof(tmp), "ok.expired %d", rows);
		APPEND_REALLOC(buf, off, len, tmp);
	} else if (strcasecmp(action, "ovents") == 0) {
		/* List the ovent tree contents
		 * Output can be large - check web Admin->ckp for tree sizes */
		bool got;
		APPEND_REALLOC_INIT(buf, off, len);
		APPEND_REALLOC(buf, off, len, "ok.");
		rows = 0;
		K_RLOCK(ovents_free);
		o_item = first_in_ktree(ovents_root, ctx);
		while (o_item) {
			DATA_OVENTS(ovents, o_item);
			for (vid = 0; o_limits[vid].name; vid++) {
				got = false;
				for (min = 0; min < 60; min++) {
					if (ovents->count[IDMIN(vid, min)]) {
						if (!got) {
							snprintf(reply, siz, "key:%d=%s%c",
								 rows, ovents->key, FLDSEP);
							APPEND_REALLOC(buf, off, len, reply);
							snprintf(reply, siz, "id:%d=%d%c",
								 rows, vid, FLDSEP);
							APPEND_REALLOC(buf, off, len, reply);
							snprintf(reply, siz, "idname:%d=%s%c",
								 rows, o_limits[vid].name, FLDSEP);
							APPEND_REALLOC(buf, off, len, reply);
							snprintf(reply, siz, "hour:%d=%d%c",
								 rows, ovents->hour, FLDSEP);
							APPEND_REALLOC(buf, off, len, reply);
							got = true;
						}
						snprintf(reply, siz, "min%02d:%d=%d%c",
							 min, rows, ovents->count[IDMIN(vid, min)],
							 FLDSEP);
						APPEND_REALLOC(buf, off, len, reply);
					}
				}
				if (got)
					rows++;
			}
			o_item = next_in_ktree(ctx);
		}
		K_RUNLOCK(ovents_free);
		snprintf(tmp, sizeof(tmp), "rows=%d", rows);
		APPEND_REALLOC(buf, off, len, tmp);
	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s() %s.%s", __func__, id, reply);
		return strdup(reply);
	}

	return buf;
}

// High Share actions
static char *cmd_high(PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *cd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	bool conned = false;
	K_TREE_CTX ctx[1];
	K_ITEM *i_action, *s_item = NULL;
	char *action;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char *buf = NULL;
	int count = 0;
	bool ok, did;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_action = require_name(trf_root, "action", 1, NULL, reply, siz);
	if (!i_action)
		return strdup(reply);
	action = transfer_data(i_action);

	if (strcasecmp(action, "store") == 0) {
		/* Store the shares_hi_root list in the db now,
		 * rather than wait for a shift process to do it */
		if (CKPQConn(&conn))
			conned = true;
		count = 0;
		do {
			did = false;
			K_WLOCK(shares_free);
			s_item = first_in_ktree(shares_hi_root, ctx);
			K_WUNLOCK(shares_free);
			if (s_item) {
				did = true;
				ok = shares_db(conn, s_item);
				if (!ok)
					break;
				count++;
			}
		} while (did);
		CKPQDisco(&conn, conned);
		if (count) {
			LOGWARNING("%s() Stored: %d high shares",
				   __func__, count);
		} else
			LOGWARNING("%s() No high shares to store", __func__);

		if (ok)
			snprintf(reply, siz, "ok.stored %d", count);
		else
			snprintf(reply, siz, "DBERR.stored %d", count);
		return strdup(reply);
	} else {
		snprintf(reply, siz, "unknown action '%s'", action);
		LOGERR("%s() %s.%s", __func__, id, reply);
		return strdup(reply);
	}

	return buf;
}

// Running thread adjustments
static char *cmd_threads(__maybe_unused PGconn *conn, char *cmd, char *id,
			 __maybe_unused tv_t *now, __maybe_unused char *by,
			 __maybe_unused char *code, __maybe_unused char *inet,
			 __maybe_unused tv_t *cd, K_TREE *trf_root,
			 __maybe_unused bool reload_data)
{
	K_ITEM *i_name, *i_delta;
	char *name, *delta;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char *buf = NULL;
	int delta_value = 0;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_name = require_name(trf_root, "name", 1, NULL, reply, siz);
	if (!i_name)
		return strdup(reply);
	name = transfer_data(i_name);
	i_delta = require_name(trf_root, "delta", 2, NULL, reply, siz);
	if (!i_delta)
		return strdup(reply);
	delta = transfer_data(i_delta);
	if (*delta != '+' && *delta != '-') {
		snprintf(reply, siz, "invalid delta '%s'", delta);
		LOGERR("%s() %s.%s", __func__, id, reply);
		return strdup(reply);
	}
	delta_value = atoi(delta+1);
	if (delta_value < 1 || delta_value >= THREAD_LIMIT) {
		snprintf(reply, siz, "invalid delta range '%s'", delta);
		LOGERR("%s() %s.%s", __func__, id, reply);
		return strdup(reply);
	}
	if (*delta == '-')
		delta_value = -delta_value;

	if (strcasecmp(name, "pr") == 0 ||
	    strcasecmp(name, "process_reload") == 0) {
		K_WLOCK(breakqueue_free);
		// Just overwrite whatever's there
		reload_queue_threads_delta = delta_value;
		K_WUNLOCK(breakqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else if (strcasecmp(name, "pq") == 0 ||
		   strcasecmp(name, "pqproc") == 0) {
		K_WLOCK(workqueue_free);
		// Just overwrite whatever's there
		proc_queue_threads_delta = delta_value;
		K_WUNLOCK(workqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else if (strcasecmp(name, "rb") == 0 ||
		   strcasecmp(name, "reload_breaker") == 0) {
		K_WLOCK(breakqueue_free);
		// Just overwrite whatever's there
		reload_breakdown_threads_delta = delta_value;
		K_WUNLOCK(breakqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else if (strcasecmp(name, "cb") == 0 ||
		   strcasecmp(name, "cmd_breaker") == 0) {
		K_WLOCK(breakqueue_free);
		// Just overwrite whatever's there
		cmd_breakdown_threads_delta = delta_value;
		K_WUNLOCK(breakqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else if (strcasecmp(name, "cl") == 0 ||
		   strcasecmp(name, "cmd_listener") == 0) {
		K_WLOCK(workqueue_free);
		// Just overwrite whatever's there
		cmd_listener_threads_delta = delta_value;
		K_WUNLOCK(workqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else if (strcasecmp(name, "bl") == 0 ||
		   strcasecmp(name, "btc_listener") == 0) {
		K_WLOCK(workqueue_free);
		// Just overwrite whatever's there
		btc_listener_threads_delta = delta_value;
		K_WUNLOCK(workqueue_free);
		snprintf(reply, siz, "ok.delta %d request sent", delta_value);
		return strdup(reply);
	} else {
		snprintf(reply, siz, "unknown name '%s'", name);
		LOGERR("%s() %s.%s", __func__, id, reply);
		return strdup(reply);
	}

	return buf;
}

static char *cmd_pause(__maybe_unused PGconn *conn, char *cmd, char *id,
			__maybe_unused tv_t *now, __maybe_unused char *by,
			__maybe_unused char *code, __maybe_unused char *inet,
			__maybe_unused tv_t *cd, K_TREE *trf_root,
			__maybe_unused bool reload_data)
{
	K_ITEM *i_name;
	char reply[1024] = "";
	size_t siz = sizeof(reply);
	char *name;

	LOGDEBUG("%s(): cmd '%s'", __func__, cmd);

	i_name = require_name(trf_root, "name", 1, NULL, reply, siz);
	if (!i_name)
		return strdup(reply);
	name = transfer_data(i_name);

	/* Pause the breaker threads to help culling to take place for some
	 *  tables that can be culled but 'never' empty due to threads always
	 *  creating new data before the old data has finished being processed
	 * N.B. this should only be needed on a sizeable pool, once after
	 *  the reload completes ... and even 499ms would be a long time to
	 *  pause in the case of a sizeable pool ... DANGER, WILL ROBINSON! */
	if (strcasecmp(name, "breaker") == 0) {
		K_ITEM *i_ms;
		int ms = 100;

		i_ms = optional_name(trf_root, "ms", 1, NULL, reply, siz);
		if (*reply)
			return strdup(reply);
		if (i_ms) {
			ms = atoi(transfer_data(i_ms));
			// 4999 is too long, don't do it!
			if (ms < 10 || ms > 4999) {
				snprintf(reply, siz,
					 "%s ms %d outside range 10-4999",
					 name, ms);
				goto out;
			}
		}

		if (!reload_queue_complete && !key_update) {
			snprintf(reply, siz,
				 "no point pausing %s before reload completes",
				 name);
			goto out;
		}

		/* Use an absolute start time to try to get all threads asleep
		 *  at the same time */
		K_WLOCK(breakqueue_free);
		cksleep_prepare_r(&breaker_sleep_stt);
		breaker_sleep_ms = ms;
		K_WUNLOCK(breakqueue_free);
		snprintf(reply, siz, "ok.%s %s%dms pause sent", name,
					ms > 499 ? "ALERT!!! " : EMPTY, ms);
	} else
		snprintf(reply, siz, "unknown name '%s'", name);

out:
	LOGWARNING("%s() %s.%s", __func__, id, reply);
	return strdup(reply);
}

/* The socket command format is as follows:
 *  Basic structure:
 *    cmd.ID.fld1=value1 FLDSEP fld2=value2 FLDSEP fld3=...
 *   cmd is the cmd_str from the table below
 *   ID is a string of anything but '.' - preferably just digits and/or letters
 *   FLDSEP is a single character macro - defined in the code near the top
 *    no spaces around FLDSEP - they are added above for readability
 *     i.e. it's really: cmd.ID.fld1=value1FLDSEPfld2...
 *   fldN names cannot contain '=' or FLDSEP
 *   valueN values cannot contain FLDSEP except for the json field (see below)
 *
 *  The reply will be ID.timestamp.status.information...
 *  Status 'ok' means it succeeded
 *  Some cmds you can optionally send as just 'cmd' if 'noid' below is true
 *   then the reply will be .timestamp.status.information
 *   i.e. a zero length 'ID' at the start of the reply
 *
 *  Data from ckpool starts with a fld1: json={...} of field data
 *  This is assumed to be the only field data sent and any other fields after
 *   it will cause a json error
 *  Any fields before it will circumvent the json interpretation of {...} and
 *   the full json in {...} will be stored as text in TRANSFER under the name
 *   'json' - which will (usually) mean the command will fail if it requires
 *   actual field data
 *
 *  Examples of the commands not from ckpool with an example reply
 *  STAMP is the unix timestamp in seconds
 *   With no ID:
 *	ping
 *	.STAMP.ok.pong
 *
 *	terminate
 *	.STAMP.ok.exiting
 *
 *   With an ID
 *   In each case the ID in these examples, also returned, is 'ID' which can
 *   of course be most any string, as stated above
 *   For commands with multiple fld=value the space between them must be typed
 *   as a TAB
 *	ping.ID
 *	ID.STAMP.ok.pong
 *
 *	newid.ID.idname=fooid idvalue=1234
 *	ID.STAMP.ok.added fooid 1234
 *
 *  loglevel is a special case to make it quick and easy to use:
 *	loglevel.ID
 *  sets the loglevel to atoi(ID)
 *  Without an ID, it just reports the current value
 *
 *  createdate = true
 *   means that the data sent must contain a fld or json fld called createdate
 *
 * The reply format for authorise, addrauth and heartbeat includes json:
 *   ID.STAMP.ok.cmd={json}
 *  where cmd is auth, addrauth, or heartbeat
 * For the heartbeat pulse reply it has no '={}'
 */

//	  cmd_val	cmd_str		noid	createdate func		seq		access
struct CMDS ckdb_cmds[] = {
	{ CMD_TERMINATE, "terminate",	true,	false,	NULL,		SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_PING,	"ping",		true,	false,	NULL,		SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_VERSION,	"version",	true,	false,	NULL,		SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_LOGLEVEL,	"loglevel",	true,	false,	NULL,		SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_FLUSH,	"flush",	true,	false,	NULL,		SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_WORKINFO,	STR_WORKINFO,	false,	true,	cmd_sharelog,	SEQ_WORKINFO,	ACCESS_POOL },
	{ CMD_SHARES,	STR_SHARES,	false,	true,	cmd_sharelog,	SEQ_SHARES,	ACCESS_POOL },
	{ CMD_SHAREERRORS,STR_SHAREERRORS,false,true,	cmd_sharelog,	SEQ_SHAREERRORS,ACCESS_POOL },
	{ CMD_AGEWORKINFO,STR_AGEWORKINFO,false,true,	cmd_sharelog,	SEQ_AGEWORKINFO,ACCESS_POOL },
	{ CMD_AUTH,	"authorise",	false,	true,	cmd_auth,	SEQ_AUTH,	ACCESS_POOL },
	{ CMD_ADDRAUTH,	"addrauth",	false,	true,	cmd_addrauth,	SEQ_ADDRAUTH,	ACCESS_POOL },
	{ CMD_HEARTBEAT,"heartbeat",	false,	true,	cmd_heartbeat,	SEQ_HEARTBEAT,	ACCESS_POOL },
	{ CMD_ADDUSER,	"adduser",	false,	false,	cmd_adduser,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_NEWPASS,	"newpass",	false,	false,	cmd_newpass,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_CHKPASS,	"chkpass",	false,	false,	cmd_chkpass,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_2FA,	"2fa",		false,	false,	cmd_2fa,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_USERSET,	"usersettings",	false,	false,	cmd_userset,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_WORKERSET,"workerset",	false,	false,	cmd_workerset,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_POOLSTAT,	"poolstats",	false,	true,	cmd_poolstats,	SEQ_POOLSTATS,	ACCESS_POOL },
	{ CMD_USERSTAT,	"userstats",	false,	true,	cmd_userstats,	SEQ_NONE,	ACCESS_POOL },
	{ CMD_WORKERSTAT,"workerstats",	false,	true,	cmd_workerstats,SEQ_WORKERSTAT, ACCESS_POOL },
	{ CMD_BLOCK,	"block",	false,	true,	cmd_blocks,	SEQ_BLOCK,	ACCESS_POOL },
	{ CMD_BLOCKLIST,"blocklist",	false,	false,	cmd_blocklist,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_BLOCKSTATUS,"blockstatus",false,	false,	cmd_blockstatus,SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_NEWID,	"newid",	false,	false,	cmd_newid,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_PAYMENTS,	"payments",	false,	false,	cmd_payments,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_WORKERS,	"workers",	false,	false,	cmd_workers,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_ALLUSERS,	"allusers",	false,	false,	cmd_allusers,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_HOMEPAGE,	"homepage",	false,	false,	cmd_homepage,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_GETATTS,	"getatts",	false,	false,	cmd_getatts,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_SETATTS,	"setatts",	false,	false,	cmd_setatts,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_EXPATTS,	"expatts",	false,	false,	cmd_expatts,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_GETOPTS,	"getopts",	false,	false,	cmd_getopts,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_SETOPTS,	"setopts",	false,	false,	cmd_setopts,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_DSP,	"dsp",		false,	false,	cmd_dsp,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_STATS,	"stats",	true,	false,	cmd_stats,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_PPLNS,	"pplns",	false,	false,	cmd_pplns,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_PPLNS2,	"pplns2",	false,	false,	cmd_pplns2,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_PAYOUTS,	"payouts",	false,	false,	cmd_payouts,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_MPAYOUTS,	"mpayouts",	false,	false,	cmd_mpayouts,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_SHIFTS,	"shifts",	false,	false,	cmd_shifts,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_USERSTATUS,"userstatus",	false,	false,	cmd_userstatus,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_MARKS,	"marks",	false,	false,	cmd_marks,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_PSHIFT,	"pshift",	false,	false,	cmd_pshift,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_SHSTA,	"shsta",	true,	false,	cmd_shsta,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_USERINFO,	"userinfo",	false,	false,	cmd_userinfo,	SEQ_NONE,	ACCESS_WEB },
	{ CMD_BTCSET,	"btcset",	false,	false,	cmd_btcset,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_QUERY,	"query",	false,	false,	cmd_query,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_LOCKS,	"locks",	false,	false,	cmd_locks,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_EVENTS,	"events",	false,	false,	cmd_events,	SEQ_NONE,	ACCESS_SYSTEM | ACCESS_WEB },
	{ CMD_HIGH,	"high",		false,	false,	cmd_high,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_THREADS,	"threads",	false,	false,	cmd_threads,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_PAUSE,	"pause",	false,	false,	cmd_pause,	SEQ_NONE,	ACCESS_SYSTEM },
	{ CMD_END,	NULL,		false,	false,	NULL,		SEQ_NONE,	0 }
};
