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

#include <stdbool.h>
#include <syslog.h>

#include <mcastrx/libmcastrx.h>

#define UNUSED(x) ((void)x)

static inline void __attribute__((always_inline, format(printf, 2, 3)))
mcastrx_log_null(struct mcastrx_ctx *ctx, const char *format, ...)
{
     UNUSED(ctx);
     UNUSED(format);
}

#define mcastrx_log_cond(ctx, prio, ...) \
  do { \
    if (mcastrx_get_log_priority(ctx) >= prio) \
      mcastrx_log(ctx, prio, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
  } while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define dbg(ctx, ...) mcastrx_log_cond(ctx, LOG_DEBUG, __VA_ARGS__)
#  else
#    define dbg(ctx, ...) mcastrx_log_null(ctx, __VA_ARGS__)
#  endif
#  define info(ctx, ...) mcastrx_log_cond(ctx, LOG_INFO, __VA_ARGS__)
#  define err(ctx, ...) mcastrx_log_cond(ctx, LOG_ERR, __VA_ARGS__)
#else
#  define dbg(ctx, ...) mcastrx_log_null(ctx, __VA_ARGS__)
#  define info(ctx, ...) mcastrx_log_null(ctx, __VA_ARGS__)
#  define err(ctx, ...) mcastrx_log_null(ctx, __VA_ARGS__)
#endif

#define MCASTRX_EXPORT __attribute__ ((visibility("default")))

void mcastrx_log(struct mcastrx_ctx *ctx,
           int priority, const char *file, int line, const char *fn,
           const char *format, ...)
           __attribute__((format(printf, 6, 7)));
