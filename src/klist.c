/*
 * Copyright (c) 2020 Calin Culianu <calin.culianu@gmail.com>
 * Copyright (c) 2020 ASICshack LLC https://asicshack.com
 * Copyright 2013-2014 Andrew Smith - BlackArrow Ltd
 * Copyright 2015-2016 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "klist.h"

const char *tree_node_list_name = "TreeNodes";

#if LOCK_CHECK
bool disable_checks = false;
bool check_locks = true;
const char *thread_noname = "UNSET";
int next_thread_id = 0;
__thread int my_thread_id = -1;
__thread char *my_thread_name = NULL;
__thread bool my_check_locks = true;

bool auto_check_deadlocks = true;
// Must be false to start with
bool check_deadlocks = false;
__thread int my_locks[MAX_LOCKDEPTH];
__thread const char *my_locks_n[MAX_LOCKDEPTH];
__thread const char *my_locks_fl[MAX_LOCKDEPTH];
__thread const char *my_locks_f[MAX_LOCKDEPTH];
__thread int my_locks_l[MAX_LOCKDEPTH];
__thread int my_lock_level = 0;
__thread bool my_check_deadlocks = true;
#endif
// Required for cmd_stats
bool lock_check_init = false;
cklock_t lock_check_lock;
K_LISTS *all_klists;

#define _CHKLIST(_list, _name) do {\
        if (!_list) { \
            quithere(1, "%s() can't process a NULL " _name \
                    KLIST_FFL, \
                    __func__, KLIST_FFL_PASS); \
        } \
    } while (0);

#define CHKLIST(__list) _CHKLIST(__list, "list")

#define CHKLS(__list) _CHKLIST(__list, "list/store")

#define _CHKITEM(_item, _list, _name) do {\
        if (!_item) { \
            quithere(1, "%s() can't process a NULL %s " _name \
                    KLIST_FFL, \
                    __func__, _list->name, \
                    KLIST_FFL_PASS); \
        } \
    } while (0);

#define CHKITEM(__item, __list) _CHKITEM(__item, __list, "item")

void _dsp_kstore(K_STORE *store, char *filename, char *msg, KLIST_FFL_ARGS)
{
    K_ITEM *item;
    FILE *stream;
    struct tm tm;
    time_t now_t;
    char stamp[128];

    if (!(store->master->dsp_func)) {
        quithere(1, "List %s has no dsp_func" KLIST_FFL,
                store->master->name, KLIST_FFL_PASS);
    }

    now_t = time(NULL);
    localtime_r(&now_t, &tm);
    snprintf(stamp, sizeof(stamp),
            "[%d-%02d-%02d %02d:%02d:%02d]",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);

    stream = fopen(filename, "ae");
    if (!stream)
    {
        fprintf(stderr, "%s %s() failed to open '%s' (%d) %s",
                stamp, __func__, filename, errno, strerror(errno));
        return;
    }

    if (msg)
        fprintf(stream, "%s %s\n", stamp, msg);
    else
        fprintf(stream, "%s Dump of store '%s':\n", stamp, store->master->name);

    if (store->count > 0)
    {
        K_RLOCK(store->master);

        item = store->head;
        while (item)
        {
            store->master->dsp_func(item, stream);
            item = item->next;
        }
        K_RUNLOCK(store->master);

        fprintf(stream, "End\n\n");
    }
    else
        fprintf(stream, "Empty kstore\n\n");

    fclose(stream);
}

static void k_alloc_items(K_LIST *list, KLIST_FFL_ARGS)
{
    K_ITEM *item;
    void *data;
    int allocate, i;

    CHKLIST(list);

    if (list->is_store) {
        quithere(1, "List %s store can't %s()" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    if (list->limit > 0 && list->total >= list->limit)
        return;

    allocate = list->allocate;
    if (list->limit > 0 && (list->total + allocate) > list->limit)
        allocate = list->limit - list->total;

    list->item_mem_count++;
    if (!(list->item_memory = realloc(list->item_memory,
                      list->item_mem_count * sizeof(*(list->item_memory))))) {
        quithere(1, "List %s item_memory failed to realloc count=%d",
                list->name, list->item_mem_count);
    }
    item = calloc(allocate, sizeof(*item));
    if (!item) {
        quithere(1, "List %s failed to calloc %d new items - total was %d, limit was %d",
                list->name, allocate, list->total, list->limit);
    }
    list->item_memory[list->item_mem_count - 1] = (void *)item;

    item[0].name = list->name;
    item[0].prev = NULL;
    item[0].next = &(item[1]);
    for (i = 1; i < allocate-1; i++) {
        item[i].name = list->name;
        item[i].prev = &item[i-1];
        item[i].next = &item[i+1];
    }
    item[allocate-1].name = list->name;
    item[allocate-1].prev = &(item[allocate-2]);
    item[allocate-1].next = NULL;

    list->head = item;
    if (list->do_tail)
        list->tail = &(item[allocate-1]);

    list->data_mem_count++;
    if (!(list->data_memory = realloc(list->data_memory,
                      list->data_mem_count * sizeof(*(list->data_memory))))) {
        quithere(1, "List %s data_memory failed to realloc count=%d",
                list->name, list->data_mem_count);
    }
    data = calloc(allocate, list->siz);
    if (!data) {
        quithere(1, "List %s failed to calloc %d new data - total was %d, limit was %d",
                list->name, allocate, list->total, list->limit);
    }
    list->data_memory[list->data_mem_count - 1] = data;

    item = list->head;
    while (item) {
        item->data = data;
        data += list->siz;
        item = item->next;
    }

    list->total += allocate;
    list->count = allocate;
    list->count_up = allocate;
}

K_STORE *_k_new_store(K_LIST *list, bool gotlock, KLIST_FFL_ARGS)
{
    K_STORE *store;

    CHKLIST(list);

    store = calloc(1, sizeof(*store));
    if (!store)
        quithere(1, "Failed to calloc store for %s", list->name);

    store->master = list;
    store->is_store = true;
    store->lock = NULL;
    store->name = list->name;
    store->do_tail = list->do_tail;
    store->prev_store = NULL;
    // Only tracked for lists with a lock
    if (store->master->lock == NULL) {
        store->next_store = NULL;
        store->master->stores++;
    } else {
        if (!gotlock)
            K_WLOCK(list);
        // In the master list, next is the head
        if (list->next_store)
            list->next_store->prev_store = store;
        store->next_store = list->next_store;
        list->next_store = store;
        list->stores++;
        if (!gotlock)
            K_WUNLOCK(list);
    }

    return store;
}

K_LIST *_k_new_list(const char *name, size_t siz, int allocate, int limit,
            bool do_tail, bool lock_only, bool without_lock,
            bool local_list, const char *name2, int cull_limit,
            KLIST_FFL_ARGS)
{
    K_LIST *list;

    if (allocate < 1)
        quithere(1, "Invalid new list %s with allocate %d must be > 0", name, allocate);

    if (limit < 0)
        quithere(1, "Invalid new list %s with limit %d must be >= 0", name, limit);

    /* after culling, the first block of items are again allocated,
     * so there's no point culling a single block of items */
    if (cull_limit > 0 && cull_limit <= allocate)
        quithere(1, "Invalid new list %s with cull_limit %d must be > allocate (%d)", name, cull_limit, allocate);

    list = calloc(1, sizeof(*list));
    if (!list)
        quithere(1, "Failed to calloc list %s", name);

    list->master = list;
    list->is_store = false;
    list->is_lock_only = lock_only;
    list->local_list = local_list;

    if (without_lock)
        list->lock = NULL;
    else {
        list->lock = calloc(1, sizeof(*(list->lock)));
        if (!(list->lock))
            quithere(1, "Failed to calloc lock for list %s", name);

        cklock_init(list->lock);
    }

    list->name = name;
    list->name2 = name2;
    list->siz = siz;
    list->allocate = allocate;
    list->limit = limit;
    list->do_tail = do_tail;
    list->cull_limit = cull_limit;
    list->next_store = list->prev_store = NULL;

    if (!(list->is_lock_only))
        k_alloc_items(list, KLIST_FFL_PASS);

    /* Don't want to keep track of short lived (tree) lists
     * since they wont use locking anyway */
    if (!list->local_list) {
        K_LISTS *klists;

        // not locked :P
        if (!lock_check_init) {
            quitfrom(1, file, func, line,
                 "in %s(), lock_check_lock has not been initialised!",
                 __func__);
        }

        klists = calloc(1, sizeof(*klists));
        if (!klists)
            quithere(1, "Failed to calloc klists %s", name);

        klists->klist = list;
        ck_wlock(&lock_check_lock);
        klists->next = all_klists;
        all_klists = klists;
        ck_wunlock(&lock_check_lock);
    }

    return list;
}

/*
 * Unlink and return the head of the list
 * If the list is empty:
 * 1) If it's a store - return NULL
 * 2) alloc a new list and return the head -
 *	which is NULL if the list limit has been reached
 */
K_ITEM *_k_unlink_head(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    K_ITEM *item;

    CHKLS(list);
    _LIST_WRITE(list, chklock, file, func, line);

    if (!(list->head) && !(list->is_store))
        k_alloc_items(list, KLIST_FFL_PASS);

    if (!(list->head))
        return NULL;

    item = list->head;
    list->head = item->next;
    if (list->head)
        list->head->prev = NULL;
    else {
        if (list->do_tail)
            list->tail = NULL;
    }

    item->prev = item->next = NULL;

    list->count--;

    return item;
}

// Zeros the head returned
K_ITEM *_k_unlink_head_zero(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    K_ITEM *item;

    CHKLS(list);
    _LIST_WRITE(list, chklock, file, func, line);

    item = _k_unlink_head(list, false, KLIST_FFL_PASS);

    if (item)
        memset(item->data, 0, list->siz);

    return item;
}

// Returns NULL if empty
K_ITEM *_k_unlink_tail(K_LIST *list, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    K_ITEM *item;

    CHKLS(list);
    _LIST_WRITE(list, chklock, file, func, line);

    if (!(list->do_tail)) {
        quithere(1, "List %s can't %s() - do_tail is false" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    if (!(list->tail))
        return NULL;

    item = list->tail;
    list->tail = item->prev;
    if (list->tail)
        list->tail->next = NULL;
    else
        list->head = NULL;

    item->prev = item->next = NULL;

    list->count--;

    return item;
}

#define CHKCULL(_list) \
    do { \
        if (!((_list)->is_store) && !((_list)->is_lock_only) && \
            (_list)->cull_limit > 0 && \
            (_list)->count == (_list)->total && \
            (_list)->total >= (_list)->cull_limit) { \
            k_cull_list(_list, file, func, line); \
        } \
    } while(0);

static void k_cull_list(K_LIST *list, KLIST_FFL_ARGS)
{
    int i;

    CHKLIST(list);
    _LIST_WRITE(list, true, file, func, line);

    if (list->is_store) {
        quithere(1, "List %s can't %s() a store" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    if (list->is_lock_only) {
        quithere(1, "List %s can't %s() a lock_only" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    if (list->count != list->total) {
        quithere(1, "List %s can't %s() a list in use" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    for (i = 0; i < list->item_mem_count; i++)
        free(list->item_memory[i]);
    free(list->item_memory);
    list->item_memory = NULL;
    list->item_mem_count = 0;

    for (i = 0; i < list->data_mem_count; i++)
        free(list->data_memory[i]);
    free(list->data_memory);
    list->data_memory = NULL;
    list->data_mem_count = 0;

    list->total = list->count = list->count_up = 0;
    list->head = list->tail = NULL;

    list->cull_count++;

    k_alloc_items(list, KLIST_FFL_PASS);
}

void _k_add_head(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    CHKLS(list);
    CHKITEM(item, list);
    _LIST_WRITE(list, chklock, file, func, line);

    if (item->name != list->name) {
        quithere(1, "List %s can't %s() a %s item" KLIST_FFL,
                list->name, __func__, item->name, KLIST_FFL_PASS);
    }

    if (item->prev || item->next) {
        quithere(1, "%s() added item %s still linked" KLIST_FFL,
                __func__, item->name, KLIST_FFL_PASS);
    }

    item->prev = NULL;
    item->next = list->head;
    if (list->head)
        list->head->prev = item;

    list->head = item;

    if (list->do_tail) {
        if (!(list->tail))
            list->tail = item;
    }

    list->count++;
    list->count_up++;

    CHKCULL(list);
}

/* slows it down (of course) - only for debugging
void _k_free_head(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    CHKLS(list);
    CHKITEM(item, list);
    _LIST_WRITE(list, chklock, file, func, line);

    memset(item->data, 0xff, list->siz);
    _k_add_head(list, item, KLIST_FFL_PASS);
}
*/

void _k_add_tail(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    CHKLS(list);
    CHKITEM(item, list);
    _LIST_WRITE(list, chklock, file, func, line);

    if (item->name != list->name) {
        quithere(1, "List %s can't %s() a %s item" KLIST_FFL,
                list->name, __func__, item->name, KLIST_FFL_PASS);
    }

    if (!(list->do_tail)) {
        quithere(1, "List %s can't %s() - do_tail is false" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    if (item->prev || item->next) {
        quithere(1, "%s() added item %s still linked" KLIST_FFL,
                __func__, item->name, KLIST_FFL_PASS);
    }

    item->prev = list->tail;
    item->next = NULL;
    if (list->tail)
        list->tail->next = item;

    list->tail = item;

    if (!(list->head))
        list->head = item;

    list->count++;
    list->count_up++;

    CHKCULL(list);
}

// Insert item into the list next after 'after'
void _k_insert_after(K_LIST *list, K_ITEM *item, K_ITEM *after, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    CHKLS(list);
    CHKITEM(item, list);
    _CHKITEM(item, after, "after");
    _LIST_WRITE(list, chklock, file, func, line);

    if (item->name != list->name) {
        quithere(1, "List %s can't %s() a %s item" KLIST_FFL,
                list->name, __func__, item->name, KLIST_FFL_PASS);
    }

    if (after->name != list->name) {
        quithere(1, "List %s can't %s() a %s after" KLIST_FFL,
                list->name, __func__, item->name, KLIST_FFL_PASS);
    }

    if (item->prev || item->next) {
        quithere(1, "%s() added item %s still linked" KLIST_FFL,
                __func__, item->name, KLIST_FFL_PASS);
    }

    item->prev = after;
    item->next = after->next;
    if (item->next)
        item->next->prev = item;
    after->next = item;

    if (list->do_tail) {
        if (list->tail == after)
            list->tail = item;
    }

    list->count++;
    list->count_up++;

    // no point checking cull since this wouldn't be an _free list
}

void _k_unlink_item(K_LIST *list, K_ITEM *item, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    CHKLS(list);
    CHKITEM(item, list);
    _LIST_WRITE(list, chklock, file, func, line);

    if (item->name != list->name) {
        quithere(1, "List %s can't %s() a %s item" KLIST_FFL,
                list->name, __func__, item->name, KLIST_FFL_PASS);
    }

    if (item->prev)
        item->prev->next = item->next;

    if (item->next)
        item->next->prev = item->prev;

    if (list->head == item)
        list->head = item->next;

    if (list->do_tail) {
        if (list->tail == item)
            list->tail = item->prev;
    }

    item->prev = item->next = NULL;

    list->count--;
}

void _k_list_transfer_to_head(K_LIST *from, K_LIST *to, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    _CHKLIST(from, "from list/store");
    _CHKLIST(to, "to list/store");

    if (from->name != to->name) {
        quithere(1, "List %s can't %s() to a %s list" KLIST_FFL,
                from->name, __func__, to->name, KLIST_FFL_PASS);
    }

    // from and to are the same lock
    _LIST_WRITE(to, chklock, file, func, line);

    if (!(from->do_tail)) {
        quithere(1, "List %s can't %s() - do_tail is false" KLIST_FFL,
                from->name, __func__, KLIST_FFL_PASS);
    }

    if (!(from->head))
        return;

    if (to->head)
        to->head->prev = from->tail;
    else
        to->tail = from->tail;

    from->tail->next = to->head;
    to->head = from->head;

    from->head = from->tail = NULL;
    to->count += from->count;
    from->count = 0;
    to->count_up += from->count_up;
    from->count_up = 0;

    CHKCULL(to);
}

void _k_list_transfer_to_tail(K_LIST *from, K_LIST *to, LOCK_MAYBE bool chklock, KLIST_FFL_ARGS)
{
    _CHKLIST(from, "from list/store");
    _CHKLIST(to, "to list/store");

    if (from->name != to->name) {
        quithere(1, "List %s can't %s() to a %s list" KLIST_FFL,
                from->name, __func__, to->name, KLIST_FFL_PASS);
    }

    // from and to are the same lock
    _LIST_WRITE(to, chklock, file, func, line);

    if (!(from->do_tail)) {
        quithere(1, "List %s can't %s() - do_tail is false" KLIST_FFL,
                from->name, __func__, KLIST_FFL_PASS);
    }

    if (!(from->head))
        return;

    if (to->tail)
        to->tail->next = from->head;
    else
        to->head = from->head;

    from->head->prev = to->tail;
    to->tail = from->tail;

    from->head = from->tail = NULL;
    to->count += from->count;
    from->count = 0;
    to->count_up += from->count_up;
    from->count_up = 0;

    CHKCULL(to);
}

K_LIST *_k_free_list(K_LIST *list, KLIST_FFL_ARGS)
{
    int i;

    CHKLIST(list);

    if (list->is_store) {
        quithere(1, "List %s can't %s() a store" KLIST_FFL,
                list->name, __func__, KLIST_FFL_PASS);
    }

    for (i = 0; i < list->item_mem_count; i++)
        free(list->item_memory[i]);
    free(list->item_memory);

    for (i = 0; i < list->data_mem_count; i++)
        free(list->data_memory[i]);
    free(list->data_memory);

    if (list->lock) {
        cklock_destroy(list->lock);

        free(list->lock);
    }

    // local_list lists are not stored in all_klists
    if (!list->local_list) {
        K_LISTS *klists, *klists_prev = NULL;

        // not locked :P
        if (!lock_check_init) {
            quitfrom(1, file, func, line,
                 "in %s(), lock_check_lock has not been initialised!",
                 __func__);
        }

        ck_wlock(&lock_check_lock);
        klists = all_klists;
        while (klists && klists->klist != list) {
            klists_prev = klists;
            klists = klists->next;
        }
        if (!klists) {
            quitfrom(1, file, func, line,
                 "in %s(), list %s not in klists",
                 __func__, list->name);
        } else {
            if (klists_prev)
                klists_prev->next = klists->next;
            else
                all_klists = klists->next;
            free(klists);
        }
        ck_wunlock(&lock_check_lock);
    }

    free(list);

    return NULL;
}

K_STORE *_k_free_store(K_STORE *store, KLIST_FFL_ARGS)
{
    _CHKLIST(store, "store");

    if (!(store->is_store)) {
        quithere(1, "Store %s can't %s() the list" KLIST_FFL,
                store->name, __func__, KLIST_FFL_PASS);
    }

    if (store->master->lock == NULL)
        store->master->stores--;
    else {
        K_WLOCK(store->master);
        // unlink store from the list
        if (store->prev_store)
            store->prev_store->next_store = store->next_store;
        if (store->next_store)
            store->next_store->prev_store = store->prev_store;
        // correct the head if we are the head
        if (store->master->next_store == store)
            store->master->next_store = store->next_store;
        store->master->stores--;
        K_WUNLOCK(store->master);
    }

    free(store);

    return NULL;
}
