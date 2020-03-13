/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 2015-2016 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <openssl/x509.h>
#include <openssl/hmac.h>
#include "asicseer-db.h"

#if (SHA256SIZBIN != SHA256_DIGEST_LENGTH)
#error "SHA256SIZBIN must = OpenSSL SHA256_DIGEST_LENGTH"
#endif

static char b32code[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', '2', '3', '4', '5', '6', '7'
};

#define ASSERT32(condition) __maybe_unused static char b32code_length_must_be_32[(condition)?1:-1]
ASSERT32(sizeof(b32code) == 32);

// bin is bigendian, return buf is bigendian
char *_tob32(USERS *users, unsigned char *bin, size_t len, char *name,
	     size_t olen, WHERE_FFL_ARGS)
{
	size_t osiz = (len * 8 + 4) / 5;
	char *buf, *ptr, *st = NULL;
	int i, j, bits, ch;

	if (osiz != olen) {
		LOGEMERG("%s() of '%s' data for '%s' invalid olen=%d != osiz=%d"
			 WHERE_FFL,
			 __func__, name, st = safe_text_nonull(users->in_username),
			 (int)olen, (int)osiz, WHERE_FFL_PASS);
		FREENULL(st);
		olen = osiz;
	}

	buf = malloc(olen+1);
	ptr = buf + olen;
	*ptr = '\0';
	i = 0;
	while (--ptr >= buf) {
		j = i / 8;
		bits = (31 << (i % 8));
		ch = (bin[len-j-1] & bits) >> (i % 8);
		if (bits > 255)
			ch |= (bin[len-j-2] & (bits >> 8)) << (8 - (i % 8));
		// Shouldn't ever happen
		if (ch < 0 || ch > 31) {
			char *binstr = bin2hex(bin, len);
			LOGEMERG("%s() failure of '%s' data for '%s' invalid "
				 "ch=%d, i=%d j=%d bits=%d bin=0x%s len=%d "
				 "olen=%d" WHERE_FFL,
				 __func__, name,
				 st = safe_text_nonull(users->in_username),
				 ch, i, j, bits, binstr, (int)len, (int)olen,
				 WHERE_FFL_PASS);
			FREENULL(st);
			FREENULL(binstr);
			ch = 0;
		}
		*ptr = b32code[ch];
		i += 5;
	}
	return buf;
}

bool gen_data(__maybe_unused USERS *users, unsigned char *buf, size_t len,
	      int32_t entropy)
{
	unsigned char *ptr;
	ssize_t ret, want, got;
	int i;

	int fil = open("/dev/random", O_RDONLY);
	if (fil == -1)
		return false;

	want = (ssize_t)len;
	got = 0;
	while (got < want) {
		ret = read(fil, buf+got, want-got);
		if (ret < 0) {
			close(fil);
			return false;
		}
		got += ret;
	}
	close(fil);

	ptr = (unsigned char *)&entropy;
	for (i = 0; i < (int)sizeof(entropy) && (i + sizeof(entropy)) < len; i++)
		buf[i+sizeof(entropy)] ^= *(ptr + i);

	return true;
}

K_ITEM *gen_2fa_key(K_ITEM *old_u_item, int32_t entropy, char *by, char *code,
		    char *inet, tv_t *cd,  K_TREE *trf_root)
{
	unsigned char key[TOTPAUTH_KEYSIZE];
	K_ITEM *u_item = NULL;
	USERS *old_users, *users;
	bool ok;

	DATA_USERS(old_users, old_u_item);
	ok = gen_data(old_users, key, sizeof(key), entropy);
	if (ok) {
		K_WLOCK(users_free);
		u_item = k_unlink_head(users_free);
		K_WUNLOCK(users_free);
		DATA_USERS(users, u_item);
		copy_users(users, old_users);
		users_userdata_add_bin(users, USER_TOTPAUTH_NAME,
					USER_TOTPAUTH, key, sizeof(key));
		users_userdata_add_txt(users, USER_TEST2FA_NAME,
					USER_TEST2FA, "Y");
		ok = users_replace(NULL, u_item, old_u_item, by, code, inet, cd,
				   trf_root);
		if (!ok) {
			// u_item was cleaned up in user_replace()
			u_item = NULL;
		}
	}
	return u_item;
}

bool check_2fa(USERS *users, int32_t value)
{
	char *st = NULL, *tmp1 = NULL, *tmp2 = NULL, *tmp3 = NULL;
	unsigned char tim[sizeof(int64_t)], *bin, *hash;
	unsigned int reslen;
	size_t binlen;
	HMAC_CTX *ctx = NULL;
	int64_t now;
	int32_t otp;
	int i, offset;

	now = (int64_t)time(NULL) / TOTPAUTH_TIME;
	bin = users_userdata_get_bin(users, USER_TOTPAUTH_NAME,
				     USER_TOTPAUTH, &binlen);
	if (binlen != TOTPAUTH_KEYSIZE) {
		LOGERR("%s() invalid key for '%s/%s "
			"len(%d) != %d",
			__func__,
			st = safe_text_nonull(users->in_username),
			USER_TOTPAUTH_NAME, (int)binlen,
			TOTPAUTH_KEYSIZE);
		FREENULL(st);
		return false;
	}
	for (i = 0; i < (int)sizeof(int64_t); i++)
		tim[i] = (now >> 8 * ((sizeof(int64_t) - 1) - i)) & 0xff;

	LOGDEBUG("%s() '%s/%s tim=%"PRId64"=%s key=%s=%s", __func__,
		 st = safe_text_nonull(users->in_username),
		 USER_TOTPAUTH_NAME, now,
		 tmp1 = (char *)bin2hex(&tim, sizeof(tim)),
		 tmp2 = (char *)bin2hex(bin, TOTPAUTH_KEYSIZE),
		 tmp3 = tob32(users, bin, binlen,USER_TOTPAUTH_NAME, TOTPAUTH_DSP_KEYSIZE));
	FREENULL(tmp3);
	FREENULL(tmp2);
	FREENULL(tmp1);
	FREENULL(st);

	hash = malloc(SHA256_DIGEST_LENGTH);
	if (!hash)
		quithere(1, "malloc OOM");

	ctx = HMAC_CTX_new();
	if (!ctx)
		quithere(1, "HMAC_CTX_new returned NULL");
	HMAC_Init_ex(ctx, bin, binlen, EVP_sha256(), NULL);
	HMAC_Update(ctx, (unsigned char *)&tim, sizeof(tim));
	HMAC_Final(ctx, hash, &reslen);
	HMAC_CTX_free(ctx);
	ctx = NULL;

	LOGDEBUG("%s() '%s/%s hash=%s", __func__,
		 st = safe_text_nonull(users->in_username),
		 USER_TOTPAUTH_NAME,
		 tmp1 = (char *)bin2hex(hash, SHA256_DIGEST_LENGTH));
	FREENULL(tmp1);
	FREENULL(st);

	offset = hash[reslen-1] & 0xf;

	otp = ((hash[offset] & 0x7f) << 24) | ((hash[offset+1] & 0xff) << 16) |
	      ((hash[offset+2] & 0xff) << 8) | (hash[offset+3] & 0xff);

	otp %= 1000000;

	LOGDEBUG("%s() '%s/%s offset=%d otp=%"PRId32" value=%"PRId32
		 " lastvalue=%"PRId32,
		 __func__, st = safe_text_nonull(users->in_username),
		 USER_TOTPAUTH_NAME, offset, otp, value, users->lastvalue);
	FREENULL(st);
	FREENULL(hash);

	/* Disallow 0 since that's the default value
	 * If it is 0, that means wait another TOTPAUTH_TIME and try again
	 *  0 is only one in a million tests for all users
	 * For security reasons, we can't allow using the same value twice,
	 *  N.B. a ckdb restart will forget lastvalue, but a restart should
	 *       take long enough to resolve that issue */
	if (otp == value && otp != 0 && otp != users->lastvalue) {
		users->lastvalue = otp;
		return true;
	} else
		return false;
}

bool tst_2fa(K_ITEM *old_u_item, int32_t value, char *by, char *code,
	     char *inet, tv_t *cd, K_TREE *trf_root)
{
	K_ITEM *u_item;
	USERS *old_users, *users;
	bool ok;

	DATA_USERS(old_users, old_u_item);
	ok = check_2fa(old_users, value);
	if (ok) {
		K_WLOCK(users_free);
		u_item = k_unlink_head(users_free);
		K_WUNLOCK(users_free);
		DATA_USERS(users, u_item);
		copy_users(users, old_users);
		users_userdata_del(users, USER_TEST2FA_NAME, USER_TEST2FA);
		ok = users_replace(NULL, u_item, old_u_item, by, code, inet, cd,
				   trf_root);
		// if !ok : u_item was cleaned up in user_replace()
	}
	return ok;
}

K_ITEM *remove_2fa(K_ITEM *old_u_item, int32_t value, char *by, char *code,
		   char *inet, tv_t *cd,  K_TREE *trf_root, bool check)
{
	K_ITEM *u_item = NULL;
	USERS *old_users, *users;
	bool ok = true, did = false;

	DATA_USERS(old_users, old_u_item);
	/* N.B. check_2fa will fail if it is called a second time
	 * with the same value */
	if (check)
		ok = check_2fa(old_users, value);
	if (ok) {
		K_WLOCK(users_free);
		u_item = k_unlink_head(users_free);
		K_WUNLOCK(users_free);
		DATA_USERS(users, u_item);
		copy_users(users, old_users);
		if (users->databits & USER_TEST2FA) {
			users_userdata_del(users, USER_TEST2FA_NAME, USER_TEST2FA);
			did = true;
		}
		if (users->databits & USER_TOTPAUTH) {
			users_userdata_del(users, USER_TOTPAUTH_NAME, USER_TOTPAUTH);
			did = true;
		}
		if (did) {
			ok = users_replace(NULL, u_item, old_u_item, by, code, inet, cd,
					   trf_root);
			if (!ok) {
				// u_item was cleaned up in user_replace()
				u_item = NULL;
			}
		} else {
			K_WLOCK(users_free);
			free_users_data(u_item);
			k_add_head(users_free, u_item);
			K_WUNLOCK(users_free);
			u_item = NULL;
		}
	}
	return u_item;
}
