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
    enum mcrx_log_priority priority,
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

static void log_string_cb(
    struct mcrx_ctx *ctx,
    int priority,
    const char *file,
    int line,
    const char *fn,
    const char *format,
    va_list args) {

  if (!ctx) {
    fprintf(stderr, "%s: %d (%s) error: log_string_cb null ctx\n",
        file, line, fn);
    return;
  }
  if (!ctx->string_log_fn) {
    fprintf(stderr, "%s: %d (%s) error: log_string_cb called unattached\n",
        file, line, fn);
    log_stderr(ctx, priority, file, line, fn, format, args);
    return;
  }
  char buf[1024];
  int buflen = sizeof(buf);
  int len = vsnprintf(buf, buflen, format, args);
  if (len < buflen && len >= 0) {
    buf[len] = 0;
  } else {
    buf[sizeof(buf)-1] = 0;
    len = sizeof(buf);
  }
  ctx->string_log_fn(ctx, priority, file, line, fn, buf);
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
  if (!ctx) {
    info(ctx, "mcrx_ctx_set_log_fn called with no ctx\n");
    return;
  }

  void (*old_log_fn)(
      struct mcrx_ctx *ctx,
      int priority,
      const char *file,
      int line,
      const char *fn,
      const char *format,
      va_list args);
  old_log_fn = ctx->log_fn;

  if (log_fn == NULL) {
    ctx->log_fn = log_stderr;
    ctx->string_log_fn = NULL;
  } else {
    ctx->log_fn = log_fn;
    ctx->string_log_fn = NULL;
  }

  // PRIxPTR from <inttypes.h> should compile everywhere, but this
  // probably works too, if it has trouble: --jake 2019-06-17
  // "custom logging function %016llx registered (replaced %016llx)\n",
  // (unsigned long long)log_fn, (unsigned long long)ctx->log_fn);
  info(ctx,
      "custom logging function %016"PRIxPTR
      " registered (replaced %016"PRIxPTR")\n",
      (uintptr_t)log_fn, (uintptr_t)old_log_fn);
}

MCRX_EXPORT void mcrx_ctx_set_log_string_fn(
    struct mcrx_ctx *ctx,
    void (*string_log_fn)(
      struct mcrx_ctx *ctx,
      int priority,
      const char *file,
      int line,
      const char *fn,
      const char *str)) {
  if (!ctx) {
    info(ctx, "mcrx_ctx_set_log_string_fn called with no ctx\n");
    return;
  }

  void (*old_string_log_fn)(struct mcrx_ctx *ctx, int priority,
    const char *file, int line, const char *fn,
    const char *str);
  old_string_log_fn = ctx->string_log_fn;
  if (string_log_fn == NULL) {
    ctx->log_fn = log_stderr;
    ctx->string_log_fn = NULL;
  } else {
    ctx->log_fn = log_string_cb;
    ctx->string_log_fn = string_log_fn;
  }
  info(ctx,
      "custom logging function %016"PRIxPTR
      " registered (replaced %016"PRIxPTR")\n",
      (uintptr_t)string_log_fn, (uintptr_t)old_string_log_fn);
}

MCRX_EXPORT void mcrx_ctx_log_msg(
    struct mcrx_ctx *ctx,
    enum mcrx_log_priority prio,
    const char* file,
    int line,
    const char* fn,
    const char* msg) {
  if (!ctx) {
    err(ctx, "no ctx for log_msg(%d,%s:%d/%s): %s", (int)prio,
        file, line, fn, msg);
    return;
  }
  if (!ctx->log_fn) {
    err(ctx, "no log_fn for log_msg(%d,%s:%d/%s): %s", (int)prio,
        file, line, fn, msg);
    return;
  }
  switch (prio) {
    case MCRX_LOGLEVEL_DEBUG:
    case MCRX_LOGLEVEL_INFO:
    case MCRX_LOGLEVEL_WARNING:
    case MCRX_LOGLEVEL_ERROR:
      mcrx_log(ctx, prio, file, line, fn, "%s", msg);
      break;
    default:
      err(ctx, "bad priority for log_msg(%d,%s:%d/%s): %s", (int)prio,
          file, line, fn, msg);
      break;
  }
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

MCRX_EXPORT enum mcrx_error_code mcrx_ctx_set_receive_socket_handlers(
    struct mcrx_ctx *ctx,
    int (*add_socket_cb)(
        struct mcrx_ctx*,
        intptr_t handle,
        int fd,
        int (*do_receive)(intptr_t handle, int fd)),
    int (*remove_socket_cb)(
        struct mcrx_ctx*,
        int fd)) {
  if (ctx == NULL) {
    return MCRX_ERR_NULLARG;
  }

  if (ctx->sock_handler_state == MCRX_SOCKHANDLER_BUILTIN) {
    return MCRX_ERR_INCONSISTENT_HANDLER;
  }

  if (ctx->sock_handler_state == MCRX_SOCKHANDLER_EXTERNAL) {
    if (add_socket_cb == NULL && remove_socket_cb == NULL) {
      if (ctx->live_subs == 0) {
        ctx->add_socket_cb = mcrx_prv_add_socket_cb;
        ctx->remove_socket_cb = mcrx_prv_remove_socket_cb;
        ctx->sock_handler_state = MCRX_SOCKHANDLER_UNCOMMITTED;
        return MCRX_ERR_OK;
      }
      return MCRX_ERR_INCONSISTENT_HANDLER;
    }
    ctx->add_socket_cb = add_socket_cb;
    ctx->remove_socket_cb = remove_socket_cb;
    return MCRX_ERR_OK;
  }

  if (ctx->sock_handler_state == MCRX_SOCKHANDLER_UNCOMMITTED) {
    if (ctx->live_subs != 0) {
      err(ctx,
          "internal error: ctx %p uncommitted sockhandler with live subs\n",
          (void*)ctx);
      return MCRX_ERR_INTERNAL_ERROR;
    }
    if (!add_socket_cb || !remove_socket_cb) {
      err(ctx,
          "ctx %p ignoring null socket handler registration\n", (void*)ctx);
      return MCRX_ERR_NULLARG;
    }
    ctx->add_socket_cb = add_socket_cb;
    ctx->remove_socket_cb = remove_socket_cb;
    ctx->sock_handler_state = MCRX_SOCKHANDLER_EXTERNAL;
    return MCRX_ERR_OK;
  }

  err(ctx, "internal error: ctx %p sockhandler unknown state\n", (void*)ctx);
  return MCRX_ERR_INTERNAL_ERROR;
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
MCRX_EXPORT enum mcrx_error_code mcrx_ctx_new(
    struct mcrx_ctx **ctxp) {
  const char *env;
  struct mcrx_ctx *c;

  c = calloc(1, sizeof(struct mcrx_ctx));
  if (!c) {
    return MCRX_ERR_NOMEM;
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
  c->timeout_ms = 1000 + random() % 1000;
  c->add_socket_cb = mcrx_prv_add_socket_cb;
  c->remove_socket_cb = mcrx_prv_remove_socket_cb;
  c->sock_handler_state = MCRX_SOCKHANDLER_UNCOMMITTED;
  c->wait_fd = -1;

  // info(c, "version %s context %p created\n", VERSION, (void *)c);
  dbg(c, "log_priority=%d\n", c->log_priority);
  *ctxp = c;
  return MCRX_ERR_OK;
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
    if (sub->joined) {
      mcrx_subscription_leave(sub);
    }
    sub->ctx = NULL;
    LIST_REMOVE(sub, sub_entries);
    nsubs += 1;
  }
  if (nsubs != 0) {
    err(ctx, "%d subscriptions still alive when deleting context %p\n",
        nsubs, (void*)ctx);
  }

  if (ctx->wait_fd != -1) {
    err(ctx, "wait_fd still alive when deleting context %p\n", (void*)ctx);
    close(ctx->wait_fd);
    ctx->wait_fd = -1;
  }

  info(ctx, "context %p released\n", (void *)ctx);
  free(ctx);
  return NULL;
}

/**
 * mcrx_ctx_get_log_priority:
 * @ctx: mcrx library context
 *
 * Returns: the current logging priority
 **/
MCRX_EXPORT enum mcrx_log_priority mcrx_ctx_get_log_priority(
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
    enum mcrx_log_priority priority) {
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
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  if (sub == NULL) {
    warn(ctx, "subscription %p increment attempted\n", (void *)sub);
    return NULL;
  }

  dbg(ctx, "subscription %p incremented\n", (void *)sub);
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
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  if (sub == NULL) {
    warn(ctx, "null subscription %p unref attempted\n", (void *)sub);
    return NULL;
  }
  if (ctx == NULL) {
    warn(ctx, "detached subscription %p ctx NULL on unref\n", (void *)sub);
  }

  sub->refcount--;
  if (sub->refcount > 0) {
    dbg(ctx, "subscription %p decremented\n", (void *)sub);
    return sub;
  }

  int npkts = 0;
  while (!TAILQ_EMPTY(&sub->pkts_head)) {
    struct mcrx_packet *pkt;
    pkt = TAILQ_FIRST(&sub->pkts_head);
    pkt->sub = NULL;
    TAILQ_REMOVE(&sub->pkts_head, pkt, pkt_entries);
    npkts += 1;
  }
  if (npkts != 0) {
    warn(ctx, "%d packets still alive when deleting subscription %p\n",
        npkts, (void*)sub);
  }

  if (ctx) {
    LIST_REMOVE(sub, sub_entries);
  }
  info(ctx, "subscription %p released\n", (void *)sub);

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

static int default_receive_cb(
    struct mcrx_packet* pkt) {
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  int len = mcrx_packet_get_contents(pkt, NULL);
  warn(ctx, "sub %p no receive callback set for pkt %p len %d\n", (void*)sub,
      (void*)pkt, len);
  return MCRX_RECEIVE_CONTINUE;
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
MCRX_EXPORT enum mcrx_error_code mcrx_subscription_new(
    struct mcrx_ctx* ctx,
    const struct mcrx_subscription_config* config,
    struct mcrx_subscription** subp) {
  if (ctx == NULL || config == NULL || subp == NULL) {
    err(ctx, "invalid input: ctx=%p, config=%p, subp=%p\n",
        (void*)ctx, (void*)config, (void*)subp);
    return MCRX_ERR_NULLARG;
  }

  if (config->magic != MCRX_SUBSCRIPTION_CONFIG_INIT_MAGIC) {
    warn(ctx, "config should be initialized with MCRX_SUBSCRIPTION_INIT\n");
  }
  struct mcrx_subscription* sub;
  sub = calloc(1, sizeof(struct mcrx_subscription));
  if (!sub) {
    return MCRX_ERR_NOMEM;
  }

  sub->ctx = ctx;
  sub->refcount = 1;
  sub->receive_cb = default_receive_cb;
  sub->sock_fd = -1;

  // default assume 1500 ethernet, minus:
  // ip  (20 v4 or 40 v6, according to amt)
  // udp (8)
  // amt (2)
  // ip  (20 v4 or 40 v6, according to sub)
  // udp (8)
  // 118 v6 sub or 98 v4 sub
  sub->max_payload_size = 1382;
  memcpy(&sub->input, config, sizeof(*config));

  TAILQ_INIT(&sub->pkts_head);
  LIST_INSERT_HEAD(&ctx->subs_head, sub, sub_entries);
  info(ctx, "subscription %p created\n", (void *)sub);
  *subp = sub;
  return MCRX_ERR_OK;
}

void mcrx_subscription_set_max_payload(
    struct mcrx_subscription* sub,
    uint16_t payload_size) {
  sub->max_payload_size = payload_size;
}

/**
 * mcrx_subscription_set_receive_cb:
 * @sub: mcrx subscription handle
 * @receive_cb: receiver callback function
 *
 * Join the (S,G) and pass to user packets received on the given port.
 * receive_cb should return an enum mcrx_receive_cb_continuation value.
 *
 * Returns: 0 on success -1 and set errno on failure
 **/
MCRX_EXPORT void mcrx_subscription_set_receive_cb(
    struct mcrx_subscription* sub,
    int (*receive_cb)(
      struct mcrx_packet* packet)) {
  if (!receive_cb) {
    sub->receive_cb = default_receive_cb;
  } else {
    sub->receive_cb = receive_cb;
  }
}

/**
 * mcrx_subscription_join:
 * @sub: mcrx subscription handle
 * @receive_cb: receiver callback function
 *
 * Join the (S,G) and pass to user packets received on the given port.
 *
 * Returns: error code
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_subscription_join(
    struct mcrx_subscription* sub) {
  enum mcrx_error_code err = mcrx_subscription_native_join(sub);
  if (err == MCRX_ERR_OK) {
    struct mcrx_ctx* ctx = (struct mcrx_ctx*)mcrx_subscription_get_ctx(sub);
    if (ctx) {
      ctx->live_subs++;
    }
  }
  return err;
}

/**
 * mcrx_subscription_leave:
 * @sub: mcrx subscription handle
 *
 * Stop receiving and leave the subscription's (S,G).
 *
 * Returns: error code
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_subscription_leave(
    struct mcrx_subscription* sub) {
  enum mcrx_error_code err = mcrx_subscription_native_leave(sub);
  if (err == MCRX_ERR_OK) {
    struct mcrx_ctx* ctx = (struct mcrx_ctx*)mcrx_subscription_get_ctx(sub);
    if (ctx) {
      ctx->live_subs--;
    }
  }
  return err;
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
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  if (pkt == NULL) {
    warn(ctx, "packet %p increment attempted\n", (void *)pkt);
    return NULL;
  }

  dbg(ctx, "packet %p incremented\n", (void *)pkt);
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
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  if (pkt == NULL) {
    warn(ctx, "packet %p decrement attempted\n", (void *)pkt);
    return NULL;
  }

  pkt->refcount--;
  if (pkt->refcount > 0) {
    dbg(ctx, "packet %p decremented\n", (void *)pkt);
    return pkt;
  }

  if (sub == NULL) {
    warn(ctx, "packet %p sub NULL when released\n", (void *)pkt);
  } else {
    TAILQ_REMOVE(&sub->pkts_head, pkt, pkt_entries);
  }

  dbg(ctx, "packet %p released\n", (void *)pkt);
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

