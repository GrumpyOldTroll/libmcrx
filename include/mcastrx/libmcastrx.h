/*
 * libmcastrx - multicast receiving library
 *
 * Copyright (C) 2019 by Akamai Technologies
 *    Jake Holland <jakeholland.net@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mcastrx_ctx
 *
 * library user context - reads the config and system
 * environment, user variables, allows custom logging
 */
struct mcastrx_ctx;
struct mcastrx_ctx *mcastrx_ref(struct mcastrx_ctx *ctx);
struct mcastrx_ctx *mcastrx_unref(struct mcastrx_ctx *ctx);
int mcastrx_new(struct mcastrx_ctx **ctx);
void mcastrx_set_log_fn(struct mcastrx_ctx *ctx,
                  void (*log_fn)(struct mcastrx_ctx *ctx,
                                 int priority, const char *file, int line, const char *fn,
                                 const char *format, va_list args));
int mcastrx_get_log_priority(struct mcastrx_ctx *ctx);
void mcastrx_set_log_priority(struct mcastrx_ctx *ctx, int priority);
void *mcastrx_get_userdata(struct mcastrx_ctx *ctx);
void mcastrx_set_userdata(struct mcastrx_ctx *ctx, void *userdata);

/*
 * mcastrx_list
 *
 * access to mcastrx generated lists
 */
struct mcastrx_list_entry;
struct mcastrx_list_entry *mcastrx_list_entry_get_next(struct mcastrx_list_entry *list_entry);
const char *mcastrx_list_entry_get_name(struct mcastrx_list_entry *list_entry);
const char *mcastrx_list_entry_get_value(struct mcastrx_list_entry *list_entry);
#define mcastrx_list_entry_foreach(list_entry, first_entry) \
        for (list_entry = first_entry; \
             list_entry != NULL; \
             list_entry = mcastrx_list_entry_get_next(list_entry))

/*
 * mcastrx_thing
 *
 * access to things of mcastrx
 */
struct mcastrx_thing;
struct mcastrx_thing *mcastrx_thing_ref(struct mcastrx_thing *thing);
struct mcastrx_thing *mcastrx_thing_unref(struct mcastrx_thing *thing);
struct mcastrx_ctx *mcastrx_thing_get_ctx(struct mcastrx_thing *thing);
int mcastrx_thing_new_from_string(struct mcastrx_ctx *ctx, const char *string, struct mcastrx_thing **thing);
struct mcastrx_list_entry *mcastrx_thing_get_some_list_entry(struct mcastrx_thing *thing);

#ifdef __cplusplus
} /* extern "C" */
#endif
