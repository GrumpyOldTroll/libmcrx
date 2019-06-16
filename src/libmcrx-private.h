/*
 * libmcrx - multicast receiving library
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

#ifndef GUARD_LIBMCRX_PRIVATE_H_
#define GUARD_LIBMCRX_PRIVATE_H_

#include <stdbool.h>
#include <syslog.h>

#include <mcrx/libmcrx.h>

#define UNUSED(x) ((void)x)

static inline void __attribute__((always_inline, format(printf, 2, 3)))
mcrx_log_null(struct mcrx_ctx *ctx, const char *format, ...) {
  UNUSED(ctx);
  UNUSED(format);
}

#define mcrx_log_cond(ctx, prio, ...)                                     \
  do {                                                                       \
    if (mcrx_ctx_get_log_priority(ctx) >= prio)                               \
      mcrx_log(ctx, prio, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); \
  } while (0)

#ifdef ENABLE_LOGGING
#ifdef ENABLE_DEBUG
#define dbg(ctx, ...) mcrx_log_cond(ctx, LOG_DEBUG, __VA_ARGS__)
#else
#define dbg(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#endif
#define info(ctx, ...) mcrx_log_cond(ctx, LOG_INFO, __VA_ARGS__)
#define warn(ctx, ...) mcrx_log_cond(ctx, LOG_WARNING, __VA_ARGS__)
#define err(ctx, ...) mcrx_log_cond(ctx, LOG_ERR, __VA_ARGS__)
#else
#define dbg(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define info(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define warn(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define err(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#endif

#define MCRX_EXPORT __attribute__((visibility("default")))

void mcrx_log(struct mcrx_ctx *ctx, int priority, const char *file,
                 int line, const char *fn, const char *format, ...)
    __attribute__((format(printf, 6, 7)));

#endif  // GUARD_LIBMCRX_PRIVATE_H_
