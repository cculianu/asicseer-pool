/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICseer https://asicseer.com
 * Copyright 2018 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

#include "libasicseerpool.h"

bool json_get_int(int *store, const json_t *val, const char *res)
{
	json_t *entry = json_object_get(val, res);
	bool ret = false;

	if (!entry) {
		printf("\nJson did not find entry %s", res);
		goto out;
	}
	if (!json_is_integer(entry)) {
		printf("\nJson entry %s is not an integer", res);
		goto out;
	}
	*store = json_integer_value(entry);
	ret = true;
out:
	return ret;
}

int main()
{
	char *dnam, *s, *username, *buf, *fname;
	int ret, users = 0, workers = 0;
	struct dirent *dir;
	struct stat fdbuf;
	json_t *val;
	FILE *fp, *sfp;
	DIR *d;
	int fd;

	ASPRINTF(&dnam, "logs/users");
	d = opendir(dnam);
	if (!d) {
		printf("\nNo user directory found");
		exit(1);
	}

	while ((dir = readdir(d)) != NULL) {
		json_t *worker_array, *arr_val;
		int lastshare;
		size_t index;

		username = basename(dir->d_name);
		if (!strcmp(username, "/") || !strcmp(username, ".") || !strcmp(username, ".."))
			continue;

		users++;
		ASPRINTF(&s, "%s/%s", dnam, username);
		fp = fopen(s, "re");
		if (unlikely(!fp)) {
			/* Permission problems should be the only reason this happens */
			printf("\nFailed to load user %s logfile to read", username);
			continue;
		}
		fd = fileno(fp);
		if (unlikely(fstat(fd, &fdbuf))) {
			printf("\nFailed to fstat user %s logfile", username);
			fclose(fp);
			continue;
		}
		/* We don't know how big the logfile will be so allocate
		 * according to file size */
		buf = ckzalloc(fdbuf.st_size + 1);
		ret = fread(buf, 1, fdbuf.st_size, fp);
		fclose(fp);
		if (ret < 1) {
			printf("\nFailed to read user %s logfile", username);
			dealloc(buf);
			continue;
		}
		val = json_loads(buf, 0, NULL);
		if (!val) {
			printf("\nFailed to json decode user %s logfile: %s", username, buf);
			dealloc(buf);
			continue;
		}
		dealloc(buf);

		json_get_int(&lastshare, val, "lastshare");

		worker_array = json_object_get(val, "worker");
		json_array_foreach(worker_array, index, arr_val) {
			const char *workername = json_string_value(json_object_get(arr_val, "workername"));
			int wlastshare;

			if (unlikely(!workername || !strlen(workername)) ||
			    !strstr(workername, username)) {
				printf("\nInvalid workername in read_userstats %s", workername);
				continue;
			}

			workers++;
			json_get_int(&wlastshare, arr_val, "lastshare");
			if (wlastshare > lastshare - 86400)
				printf("\nCurrent worker %s", workername);
			else {
				printf("\nDeleting Old worker %s", workername);
				json_array_remove(worker_array, index--);
			}
		}
		dealloc(s);
		s = json_dumps(val, JSON_NO_UTF8 | JSON_PRESERVE_ORDER | JSON_REAL_PRECISION(16) | JSON_COMPACT);
		ASPRINTF(&fname, "logs/usersummaries/%s", username);
		sfp = fopen(fname, "we");
		if (!sfp) {
			printf("\nFailed to fopen %s\n", fname);
			exit(1);
		}
		dealloc(fname);
		fprintf(sfp, "%s", s);
		dealloc(s);
		fclose(sfp);
		json_decref(val);
	}
	closedir(d);

	if (likely(users))
		printf("\nLoaded %d users and %d workers", users, workers);
	return 0;
}
