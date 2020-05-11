/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICshack LLC https://asicshack.com
 * Copyright (c) 2009-2016 Petri Lehtinen <petri@digip.org>
 * Copyright (c) 2015,2017 Con Kolivas <kernel@kolivas.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "jansson_private.h"
#include "strbuffer.h"

#define STRBUFFER_MIN_SIZE  4096
#define STRBUFFER_FACTOR    2
#define STRBUFFER_SIZE_MAX  ((size_t)-1L)

int strbuffer_init(strbuffer_t *strbuff)
{
    strbuff->size = STRBUFFER_MIN_SIZE;
    strbuff->length = 0;

    strbuff->value = jsonp_malloc(strbuff->size);
    if(!strbuff->value)
        return -1;

    /* initialize to empty */
    strbuff->value[0] = '\0';
    return 0;
}

void strbuffer_close(strbuffer_t *strbuff)
{
    if(strbuff->value)
        jsonp_free(strbuff->value);

    strbuff->size = 0;
    strbuff->length = 0;
    strbuff->value = NULL;
}

void strbuffer_clear(strbuffer_t *strbuff)
{
    strbuff->length = 0;
    strbuff->value[0] = '\0';
}

const char *strbuffer_value(const strbuffer_t *strbuff)
{
    return strbuff->value;
}

char *strbuffer_steal_value(strbuffer_t *strbuff)
{
    char *result = strbuff->value;
    strbuff->value = NULL;
    return result;
}

int strbuffer_append_byte(strbuffer_t *strbuff, char byte)
{
    return strbuffer_append_bytes(strbuff, &byte, 1);
}

int strbuffer_append_bytes(strbuffer_t *strbuff, const char *data, size_t size)
{
    /* Leave room for EOL and NULL bytes */
    if(size + 2 > strbuff->size - strbuff->length)
    {
        useconds_t backoff = 1U;
        size_t new_size;
        char *new_value;

        /* avoid integer overflow */
        if (strbuff->size > STRBUFFER_SIZE_MAX / STRBUFFER_FACTOR
            || size > STRBUFFER_SIZE_MAX - 1
            || strbuff->length > STRBUFFER_SIZE_MAX - 1 - size)
            return -1;

        new_size = max(strbuff->size * STRBUFFER_FACTOR,
                       strbuff->length + size + 1);

	while (42) {
		new_value = realloc(strbuff->value, new_size);
		if (new_value)
			break;
		usleep(backoff * 1000U);
		backoff <<= 1;
	}

        strbuff->value = new_value;
        strbuff->size = new_size;
    }

    memcpy(strbuff->value + strbuff->length, data, size);
    strbuff->length += size;
    strbuff->value[strbuff->length] = '\0';

    return 0;
}

char strbuffer_pop(strbuffer_t *strbuff)
{
    if(strbuff->length > 0) {
        char c = strbuff->value[--strbuff->length];
        strbuff->value[strbuff->length] = '\0';
        return c;
    }
    else
        return '\0';
}
