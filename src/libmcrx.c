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
#include <inttypes.h>

#include <mcrx/libmcrx.h>
#include "./libmcrx-private.h"

/**
 * SECTION:libmcrx
 * @short_description: libmcrx context
 *
 * The context contains the default values for the library user,
 * and is passed to all library operations.
 */

/*
 * mcrx_log:
 *
 * This gets called underneath the "dbg", "info", "warn", and "err"
 * printf-like macros (as: info(ctx, "something %s", str); )
 */
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

  if (strncmp(priority, "warn", 4) == 0) {
    return LOG_WARNING;
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
 * @ctxp: pointer to be filled with the new mcrx library context
 *
 * Create mcrx library context. This reads the mcrx configuration
 * and fills in the default values.
 *
 * The initial refcount is 1, and needs to be decremented to
 * release the resources of the mcrx library context.
 *
 * Returns: An error code.
 **/
MCRX_EXPORT int mcrx_ctx_new(
    struct mcrx_ctx **ctxp) {
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
    int prio = log_priority(env);
    if (prio == 0) {
      err(c, "env MCRX_LOG=%s unconverted (try debug, info, warn, err)\n",
          env);
    }
    mcrx_ctx_set_log_priority(c, prio);
  }
  LIST_INIT(&c->subs_head);

  info(c, "version %s context %p created\n", VERSION, (void *)c);
  dbg(c, "log_priority=%d\n", c->log_priority);
  *ctxp = c;
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
    warn(ctx, "context %p increment attempted\n", (void *)ctx);
    return NULL;
  }

  dbg(ctx, "context %p incremented\n", (void *)ctx);
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
 * Returns: the passed mcrx library context, or NULL if released.
 **/
MCRX_EXPORT struct mcrx_ctx *mcrx_ctx_unref(
    struct mcrx_ctx *ctx) {
  if (ctx == NULL) {
    warn(ctx, "context %p decrement attempted\n", (void *)ctx);
    return NULL;
  }

  ctx->refcount--;
  if (ctx->refcount > 0) {
    dbg(ctx, "context %p decremented\n", (void *)ctx);
    return ctx;
  }

  int nsubs = 0;
  while (!LIST_EMPTY(&ctx->subs_head)) {
    struct mcrx_subscription *sub;
    sub = LIST_FIRST(&ctx->subs_head);
    warn(ctx, "subscription %p still alive when deleting context %p\n",
        (void*)sub, (void*)ctx);
    sub->ctx = NULL;
    LIST_REMOVE(sub, sub_entries);
    nsubs += 1;
  }
  if (nsubs != 0) {
    err(ctx, "%d subscriptions still alive when deleting context %p\n",
        nsubs, (void*)ctx);
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
  info(ctx,
      "custom logging function %016"PRIxPTR
      " registered (replaced %016"PRIxPTR")\n",
      (uintptr_t)log_fn, (uintptr_t)ctx->log_fn);

  // PRIxPTR from <inttypes.h> should compile everywhere, but this probably works
  // too: . --jake 2019-06-17
      //"custom logging function %016llx registered (replaced %016llx)\n",
      //(unsigned long long)log_fn, (unsigned long long)ctx->log_fn);

  ctx->log_fn = log_fn;
}

/**
 * mcrx_ctx_get_log_priority:
 * @ctx: mcrx library context
 *
 * Returns: the current logging priority
 **/
MCRX_EXPORT int mcrx_ctx_get_log_priority(
    struct mcrx_ctx *ctx) {
  if (ctx == NULL) {
    return LOG_DEBUG;
  }
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
  if (ctx == NULL) {
    return;
  }
  ctx->log_priority = priority;
}

/**
 * mcrx_subscription_ref:
 * @sub: mcrx subscription handle
 *
 * Take a reference of the mcrx subscription handle.
 *
 * Returns: the passed mcrx subscription handle.
 **/
MCRX_EXPORT struct mcrx_subscription* mcrx_subscription_ref(
    struct mcrx_subscription* sub) {
  if (sub == NULL) {
    warn(mcrx_subscription_get_ctx(sub),
         "subscription %p increment attempted\n", (void *)sub);
    return NULL;
  }

  dbg(mcrx_subscription_get_ctx(sub),
      "subscription %p incremented\n", (void *)sub);
  sub->refcount++;
  return sub;
}

/**
 * mcrx_subscription_unref:
 * @sub: mcrx subscription handle
 *
 * Drop a reference of the mcrx subscription handle. If the refcount
 * reaches zero, the resources of the handle will be released.
 *
 * Returns: the passed mcrx subscription handle (or null if released)
 **/
MCRX_EXPORT struct mcrx_subscription* mcrx_subscription_unref(
    struct mcrx_subscription* sub) {
  if (sub == NULL) {
    warn(mcrx_subscription_get_ctx(sub),
        "subscription %p decrement attempted\n", (void *)sub);
    return NULL;
  }

  sub->refcount--;
  if (sub->refcount > 0) {
    dbg(mcrx_subscription_get_ctx(sub),
        "subscription %p decremented\n", (void *)sub);
    return sub;
  }

  int npkts = 0;
  while (!TAILQ_EMPTY(&sub->pkts_head)) {
    struct mcrx_packet *pkt;
    pkt = TAILQ_FIRST(&sub->pkts_head);
    warn(mcrx_subscription_get_ctx(sub),
        "packet %p still alive when deleting subscription %p\n",
        (void*)pkt, (void*)sub);
    pkt->sub = NULL;
    TAILQ_REMOVE(&sub->pkts_head, pkt, pkt_entries);
    npkts += 1;
  }
  if (npkts != 0) {
    err(mcrx_subscription_get_ctx(sub),
        "%d packets still alive when deleting subscription %p\n",
        npkts, (void*)sub);
  }

  // TBD: jake 2019-06-16: is this safe if it's removed already? how to check?
  LIST_REMOVE(sub, sub_entries);
  if (sub->ctx == NULL) {
    warn(mcrx_subscription_get_ctx(sub),
        "subscription %p ctx NULL when released\n", (void *)sub);
  }
  info(mcrx_subscription_get_ctx(sub),
      "subscription %p released\n", (void *)sub);

  free(sub);
  return NULL;
}

/**
 * mcrx_subscription_get_userdata:
 * @sub: mcrx subscription handle
 *
 * Retrieve stored data pointer from subscription handle. This might be useful
 * to access from callbacks like a custom logging function.
 *
 * Returns: stored userdata
 **/
MCRX_EXPORT intptr_t mcrx_subscription_get_userdata(
    struct mcrx_subscription *sub) {
  if (sub == NULL) {
    return 0;
  }

  return sub->userdata;
}

/**
 * mcrx_subscription_set_userdata:
 * @sub: mcrx subscription handle
 * @userdata: data pointer
 *
 * Store custom @userdata in the subscription handle.
 **/
MCRX_EXPORT void mcrx_subscription_set_userdata(
    struct mcrx_subscription *sub,
    intptr_t userdata) {
  if (sub == NULL) {
    return;
  }

  sub->userdata = userdata;
}

/**
 * mcrx_subscription_get_ctx:
 * @sub: mcrx subscription handle
 *
 * Retrieve the mcrx library context for the subscription handle.
 * Note: this DOES NOT increase the ctx ref count, so increase it
 * with mcrx_ctx_ref if you are possibly holding it beyond the
 * subscription lifetime.
 *
 * Returns: mcrx library context that owns the subscription
 **/
MCRX_EXPORT struct mcrx_ctx* mcrx_subscription_get_ctx(
    struct mcrx_subscription* sub) {
  if (sub == NULL) {
    return NULL;
  }

  return sub->ctx;
}

/**
 * mcrx_subscription_new:
 * @ctx: mcrx library context
 * @config: subscription config
 * @subp: pointer to be filled with the new subscription handle
 *
 * Create a new subscription handle from the config parameters.
 *
 * Returns: error code
 **/
MCRX_EXPORT int mcrx_subscription_new(
    struct mcrx_ctx* ctx,
    const struct mcrx_subscription_config* config,
    struct mcrx_subscription** subp) {
  if (ctx == NULL || config == NULL || subp == NULL) {
    err(ctx, "invalid input: ctx=%p, config=%p, subp=%p\n",
        (void*)ctx, (void*)config, (void*)subp);
    return -EINVAL;
  }

  if (config->magic != MCRX_SUBSCRIPTION_MAGIC) {
    warn(ctx, "config should be initialized with MCRX_SUBSCRIPTION_INIT\n");
  }
  struct mcrx_subscription* sub;
  sub = calloc(1, sizeof(struct mcrx_subscription));
  if (!sub) {
    return -ENOMEM;
  }

  sub->ctx = ctx;
  sub->refcount = 1;
  memcpy(&sub->input, config, sizeof(*config));

  TAILQ_INIT(&sub->pkts_head);
  LIST_INSERT_HEAD(&ctx->subs_head, sub, sub_entries);
  info(ctx, "subscription %p created\n", (void *)sub);
  *subp = sub;
  return 0;
}

/**
 * mcrx_packet_ref:
 * @pkt: mcrx packet handle
 *
 * Take a reference of the mcrx packet handle.
 *
 * Returns: the passed mcrx packet handle.
 **/
MCRX_EXPORT struct mcrx_packet* mcrx_packet_ref(
    struct mcrx_packet* pkt) {
  if (pkt == NULL) {
    warn(mcrx_subscription_get_ctx(mcrx_packet_get_subscription(pkt)),
         "packet %p increment attempted\n", (void *)pkt);
    return NULL;
  }

  dbg(mcrx_subscription_get_ctx(mcrx_packet_get_subscription(pkt)),
      "packet %p incremented\n", (void *)pkt);
  pkt->refcount++;
  return pkt;
}

/**
 * mcrx_packet_unref:
 * @pkt: mcrx packet handle
 *
 * Drop a reference of the mcrx packet handle. If the refcount
 * reaches zero, the resources of the handle will be released.
 *
 * Returns: the passed mcrx packet handle (or null if released)
 **/
MCRX_EXPORT struct mcrx_packet* mcrx_packet_unref(
    struct mcrx_packet* pkt) {
  if (pkt == NULL) {
    warn(mcrx_subscription_get_ctx(mcrx_packet_get_subscription(pkt)),
        "packet %p decrement attempted\n", (void *)pkt);
    return NULL;
  }

  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);

  pkt->refcount--;
  if (pkt->refcount > 0) {
    dbg(mcrx_subscription_get_ctx(sub),
        "packet %p decremented\n", (void *)pkt);
    return pkt;
  }

  if (sub == NULL) {
    warn(mcrx_subscription_get_ctx(sub),
        "packet %p sub NULL when released\n", (void *)pkt);
  } else {
    TAILQ_REMOVE(&sub->pkts_head, pkt, pkt_entries);
  }

  dbg(mcrx_subscription_get_ctx(mcrx_packet_get_subscription(pkt)),
      "packet %p released\n", (void *)pkt);
  free(pkt);
  return NULL;
}

/**
 * mcrx_packet_get_userdata:
 * @pkt: mcrx packet handle
 *
 * Retrieve stored data pointer from packet handle. This might be useful
 * to access from callbacks like a custom logging function.
 *
 * Returns: stored userdata
 **/
MCRX_EXPORT intptr_t mcrx_packet_get_userdata(
    struct mcrx_packet* pkt) {
  if (pkt == NULL) {
    return 0;
  }

  return pkt->userdata;
}

/**
 * mcrx_packet_set_userdata:
 * @pkt: mcrx packet handle
 * @userdata: data pointer
 *
 * Store custom @userdata in the packet handle.
 **/
MCRX_EXPORT void mcrx_packet_set_userdata(
    struct mcrx_packet* pkt,
    intptr_t userdata) {
  if (pkt == NULL) {
    return;
  }

  pkt->userdata = userdata;
}

/**
 * mcrx_packet_get_subscription:
 * @pkt: mcrx packet handle
 *
 * Retrieve the mcrx subscription handle for the packet handle.
 * Note: this DOES NOT increase the subscription ref count, so increase it
 * with mcrx_subscription_ref if you are possibly holding it beyond the
 * packet lifetime.
 *
 * Returns: mcrx subscription handle that owns the packet
 **/
MCRX_EXPORT struct mcrx_subscription* mcrx_packet_get_subscription(
    struct mcrx_packet* pkt) {
  if (pkt == NULL) {
    return NULL;
  }

  return pkt->sub;
}

/**
 * mcrx_packet_get_contents:
 * @pkt: mcrx packet handle
 * @datap: pointer to be filled with a pointer to the packet data
 *
 * Retrieve the packet payload contents and length.
 *
 * Returns: the length of the data.
 **/
MCRX_EXPORT uint16_t mcrx_packet_get_contents(
    struct mcrx_packet* pkt,
    uint8_t** datap) {
  if (pkt == NULL) {
    if (datap != NULL) {
      *datap = NULL;
    }
    return 0;
  }

  if (datap != NULL) {
    *datap = &pkt->data[0];
  }
  return pkt->size;
}

