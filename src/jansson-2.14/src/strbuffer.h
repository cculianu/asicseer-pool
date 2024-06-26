/*
 * Copyright (c) 2009-2016 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STRBUFFER_H
#define STRBUFFER_H

#include "jansson.h"
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    union {
        char    *value;
        uint8_t *uvalue;
        void    *data;
    };
    size_t length; /* bytes used */
    size_t size;   /* bytes allocated */
} strbuffer_t;

int strbuffer_init(strbuffer_t *strbuff) JANSSON_ATTRS((warn_unused_result));
void strbuffer_close(strbuffer_t *strbuff);

void strbuffer_clear(strbuffer_t *strbuff);

const char *strbuffer_value(const strbuffer_t *strbuff);

/* Steal the value and close the strbuffer */
char *strbuffer_steal_value(strbuffer_t *strbuff);

int strbuffer_append_char(strbuffer_t *strbuff, char ch);
int strbuffer_append_byte(strbuffer_t *strbuff, uint8_t byte);
int strbuffer_append_bytes(strbuffer_t *strbuff, const void *data, size_t size);

char strbuffer_pop(strbuffer_t *strbuff);

#endif
