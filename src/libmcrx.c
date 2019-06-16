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

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mcrx/libmcrx.h>
#include "./libmcrx-private.h"

/**
 * SECTION:libmcrx
 * @short_description: libmcrx context
 *
 * The context contains the default values for the library user,
 * and is passed to all library operations.
 */

/**
 * mcrx_ctx:
 *
 * Opaque object representing the library context.
 */
struct mcrx_ctx {
  int refcount;
  void (*log_fn)(struct mcrx_ctx *ctx, int priority, const char *file,
                 int line, const char *fn, const char *format, va_list args);
  intptr_t userdata;
  int log_priority;
};

void mcrx_log(
    struct mcrx_ctx *ctx,
    int priority,
    const char *file,
    int line,
    const char *fn,
    const char *format,
    ...) {
  va_list args;

  va_start(args, format);
  ctx->log_fn(ctx, priority, file, line, fn, format, args);
  va_end(args);
}

static void log_stderr(
    struct mcrx_ctx *ctx,
    int priority,
    const char *file,
    int line,
    const char *fn,
    const char *format,
    va_list args) {
  UNUSED(ctx);
  UNUSED(priority);
  UNUSED(file);
  UNUSED(line);

  fprintf(stderr, "libmcrx: %s: ", fn);
  vfprintf(stderr, format, args);
}

/**
 * mcrx_ctx_get_userdata:
 * @ctx: mcrx library context
 *
 * Retrieve stored data pointer from library context. This might be useful
 * to access from callbacks like a custom logging function.
 *
 * Returns: stored userdata
 **/
MCRX_EXPORT intptr_t mcrx_ctx_get_userdata(
    struct mcrx_ctx *ctx) {
  if (ctx == NULL) {
    return 0;
  }

  return ctx->userdata;
}

/**
 * mcrx_ctx_set_userdata:
 * @ctx: mcrx library context
 * @userdata: data pointer
 *
 * Store custom @userdata in the library context.
 **/
MCRX_EXPORT void mcrx_ctx_set_userdata(
    struct mcrx_ctx *ctx,
    intptr_t userdata) {
  if (ctx == NULL) {
    return;
  }

  ctx->userdata = userdata;
}

static int log_priority(
    const char *priority) {
  char *endptr;
  int prio;

  prio = strtol(priority, &endptr, 10);

  if (endptr[0] == '\0' || isspace(endptr[0])) {
    return prio;
  }

  if (strncmp(priority, "err", 3) == 0) {
    return LOG_ERR;
  }

  if (strncmp(priority, "info", 4) == 0) {
    return LOG_INFO;
  }

  if (strncmp(priority, "debug", 5) == 0) {
    return LOG_DEBUG;
  }

  return 0;
}

/**
 * mcrx_ctx_new:
 *
 * Create mcrx library context. This reads the mcrx configuration
 * and fills in the default values.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the mcrx library context.
 *
 * Returns: a new mcrx library context
 **/
MCRX_EXPORT int mcrx_ctx_new(
    struct mcrx_ctx **ctx) {
  const char *env;
  struct mcrx_ctx *c;

  c = calloc(1, sizeof(struct mcrx_ctx));
  if (!c) {
    return -ENOMEM;
  }

  c->refcount = 1;
  c->log_fn = log_stderr;
  c->log_priority = LOG_ERR;

  /* environment overwrites config */
  env = getenv("MCRX_LOG");
  if (env != NULL) {
    mcrx_ctx_set_log_priority(c, log_priority(env));
  }

  info(c, "version %s context %p created\n", VERSION, (void *)c);
  dbg(c, "log_priority=%d\n", c->log_priority);
  *ctx = c;
  return 0;
}

/**
 * mcrx_ctx_ref:
 * @ctx: mcrx library context
 *
 * Take a reference of the mcrx library context.
 *
 * Returns: the passed mcrx library context
 **/
MCRX_EXPORT struct mcrx_ctx *mcrx_ctx_ref(
    struct mcrx_ctx *ctx) {
  if (ctx == NULL) {
    return NULL;
  }

  ctx->refcount++;
  return ctx;
}

/**
 * mcrx_ctx_unref:
 * @ctx: mcrx library context
 *
 * Drop a reference of the mcrx library context. If the refcount
 * reaches zero, the resources of the context will be released.
 *
 **/
MCRX_EXPORT struct mcrx_ctx *mcrx_ctx_unref(
    struct mcrx_ctx *ctx) {
  if (ctx == NULL) {
    return NULL;
  }

  ctx->refcount--;
  if (ctx->refcount > 0) {
    return ctx;
  }

  info(ctx, "context %p released\n", (void *)ctx);
  free(ctx);
  return NULL;
}

/**
 * mcrx_ctx_set_log_fn:
 * @ctx: mcrx library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the user's logging functionality.
 *
 **/
MCRX_EXPORT void mcrx_ctx_set_log_fn(
    struct mcrx_ctx *ctx,
    void (*log_fn)(
      struct mcrx_ctx *ctx,
      int priority,
      const char *file,
      int line,
      const char *fn,
      const char *format,
      va_list args)) {
  ctx->log_fn = log_fn;
  info(ctx, "custom logging function %p registered\n", (void *)&log_fn);
}

/**
 * mcrx_ctx_get_log_priority:
 * @ctx: mcrx library context
 *
 * Returns: the current logging priority
 **/
MCRX_EXPORT int mcrx_ctx_get_log_priority(
    struct mcrx_ctx *ctx) {
  return ctx->log_priority;
}

/**
 * mcrx_ctx_set_log_priority:
 * @ctx: mcrx library context
 * @priority: the new logging priority
 *
 * Set the current logging priority. The value controls which messages
 * are logged.
 **/
MCRX_EXPORT void mcrx_ctx_set_log_priority(
    struct mcrx_ctx *ctx,
    int priority) {
  ctx->log_priority = priority;
}

