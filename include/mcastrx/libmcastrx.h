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

#ifndef GUARD_LIBMCASTRX_H
#define GUARD_LIBMCASTRX_H

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
                        void (*log_fn)(struct mcastrx_ctx *ctx, int priority,
                                       const char *file, int line,
                                       const char *fn, const char *format,
                                       va_list args));
int mcastrx_get_log_priority(struct mcastrx_ctx *ctx);
void mcastrx_set_log_priority(struct mcastrx_ctx *ctx, int priority);
void *mcastrx_get_userdata(struct mcastrx_ctx *ctx);
void mcastrx_set_userdata(struct mcastrx_ctx *ctx, void *userdata);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // GUARD_LIBMCASTRX_H
