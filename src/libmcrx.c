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
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

/**
 * mcrx_ctx_set_log_string_fn:
 * @ctx: mcrx library context
 * @string_log_fn: function to be called for logging messages
 *
 * This can be used instead of mcrx_ctx_set_log_fn to
 * register a callback that takes a fully-formed string instead
 * of a va_list.  It is not possible to use both log_fn and
 * log_string_fn, use of either will override the other.
 *
 **/
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

/**
 * mcrx_cts_log_msg:
 * @ctx: mcrx library context
 * @prio: log level
 * @file: filename to report (usually __FILE__)
 * @line: line number to report (usually __LINE__)
 * @fn: function to report (usually __function__)
 * @msg: message to log
 *
 * This feeds a message into the logging system, as if the
 * libmcrx library generated an error or warning message.
 */
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

/**
 * mcrx_set_recive_socket_handlers:
 * @ctx: mcrx library context
 * @add_socket_cb: callback when a socket is added
 * @remove_socket_cb: callback when a socket is removed
 *
 * This can be used to integrate with event loops that do not
 * play will with making a blocking call in a dedicated thread to
 * receive the libmcrx packets.  This will expose the sockets to
 * the calling program, so they can be used in select/epoll/kevent/etc.
 * for receive events.  After a receive event on the libmcrx sockets
 * reported by these callbacks, the do_receive function pointer
 * provided by the add_socket_cb should be invoked with the handle
 * parameter provided by the add_socket_cb and the fd.
 *
 * Applications that use this function cannot use
 * mcrx_ctx_receive_packets with the same ctx, and instead must process
 * socket receive events for this ctx with the given do_receive
 * functions (which are non-blocking, and invoke the subscription
 * packet receive callbacks).
 */
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

  if (ctx->mnat_map != NULL) {
    mcrx_mnatmap_unref(ctx->mnat_map);
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

/**
 * mcrx_subscription_override_ifname:
 * @sub: mcrx subscription handle
 * @ifname: name of interface on which to join
 *
 * Ordinarily, the subscription will join on the interface with the
 * route toward the source IP, but this can be used to override the
 * interface with a user-provided name.  The provided ifname must
 * remain a valid pointer until the subscription is released or until
 * overridden with a different ifname, and must be a 0-terminated string.
 * This takes effect on the join, so leave/override/join can change
 * interfaces.
 **/
MCRX_EXPORT void mcrx_subscription_override_ifname(
    struct mcrx_subscription* sub,
    const char* ifname) {
  if (sub == NULL) {
    return;
  }

  sub->override_ifname = ifname;
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
  sub->state = MCRX_SUBSCRIPTION_STATE_UNJOINED;

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

MCRX_EXPORT void mcrx_subscription_set_state_change_cb(
    struct mcrx_subscription* sub,
    int (*state_change_cb)(
        struct mcrx_subscription* sub, enum mcrx_subscription_state state, enum mcrx_error_code result)) {
  sub->state_change_cb = state_change_cb;
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
  if (sub && sub->ctx && sub->ctx->mnat_map) {
    sub->mnat_entry = mcrx_mnatmap_find_or_alloc_entry_from_subscription(sub, sub->ctx->mnat_map);
    if (sub->mnat_entry == NULL || mcrx_mnatmap_entry_unresolved(sub->mnat_entry)) {
      // if we can not find a mnap entry or the entry is unresolved for local address
      info(sub->ctx, "can not find resolved mnat entry for subscription %p\n", (void *)sub);
      sub->state = MCRX_SUBSCRIPTION_STATE_PENDING;
      if (sub->state_change_cb) {
        sub->state_change_cb(sub, sub->state, MCRX_ERR_OK);
      }
      return MCRX_ERR_OK;
    }
  }
  enum mcrx_error_code err = mcrx_subscription_native_join(sub);
  if (err == MCRX_ERR_OK) {
    struct mcrx_ctx* ctx = (struct mcrx_ctx*)mcrx_subscription_get_ctx(sub);
    if (ctx) {
      ctx->live_subs++;
    }
    sub->state = MCRX_SUBSCRIPTION_STATE_JOINED;
    if (sub->state_change_cb) {
      sub->state_change_cb(sub, sub->state, MCRX_ERR_OK);
    }
  } else {
    sub->state = MCRX_SUBSCRIPTION_STATE_UNJOINED;
    if (sub->state_change_cb) {
      sub->state_change_cb(sub, sub->state, err);
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
  if (sub->state == MCRX_SUBSCRIPTION_STATE_UNJOINED) {
    return MCRX_ERR_ALREADY_NOTJOINED;
  }
  if (sub->state == MCRX_SUBSCRIPTION_STATE_PENDING) {
    sub->mnat_entry = NULL;
    sub->state = MCRX_SUBSCRIPTION_STATE_UNJOINED;
    if (sub->state_change_cb) {
      sub->state_change_cb(sub, sub->state, MCRX_ERR_OK);
    }
    return MCRX_ERR_OK;
  }
  sub->mnat_entry = NULL;
  enum mcrx_error_code err = mcrx_subscription_native_leave(sub);
  if (err == MCRX_ERR_OK) {
    struct mcrx_ctx* ctx = (struct mcrx_ctx*)mcrx_subscription_get_ctx(sub);
    if (ctx) {
      ctx->live_subs--;
    }
    sub->state = MCRX_SUBSCRIPTION_STATE_UNJOINED;
    if (sub->state_change_cb) {
      sub->state_change_cb(sub, sub->state, MCRX_ERR_OK);
    }
  } else {
    sub->state = MCRX_SUBSCRIPTION_STATE_UNJOINED;
    if (sub->state_change_cb) {
      sub->state_change_cb(sub, sub->state, err);
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

/**
 * mcrx_packet_get_remote_port:
 * @pkt: mcrx packet handle
 *
 * Retrieve the source port.
 *
 * Returns: the source port of the packet in host byte order.
 **/
MCRX_EXPORT uint16_t mcrx_packet_get_remote_port(
    struct mcrx_packet* pkt) {
  if (pkt == NULL) {
    return 0;
  }

  return pkt->remote_port;
}

/**
 * mcrx_strerror:
 * @err: enum mcrx_error_code
 *
 * Similar to strerror(2). For some cases from system call failures,
 * errno will also be set and can additionally be used in strerror/perror
 * for more information about the problem encountered.
 */
MCRX_EXPORT const char*
mcrx_strerror(enum mcrx_error_code err) {
  switch (err) {
    case MCRX_ERR_OK:
      return "mcrx: no error";
    case MCRX_ERR_TIMEDOUT:
      return "mcrx: timed out";
    case MCRX_ERR_NOMEM:
      return "mcrx: out of memory";
    case MCRX_ERR_NULLARG:
      return "mcrx: null argument passed";
    case MCRX_ERR_NOSPACE:
      return "mcrx: insufficient buffer space for ntop";
    case MCRX_ERR_UNKNOWN_FAMILY:
      return "mcrx: unknown address family";
    case MCRX_ERR_UNSUPPORTED:
      return "mcrx: unsupported operation";
    case MCRX_ERR_ALREADY_JOINED:
      return "mcrx: already joined";
    case MCRX_ERR_ALREADY_NOTJOINED:
      return "mcrx: already not joined";
    case MCRX_ERR_INTERNAL_ERROR:
      return "mcrx: internal library error";
    case MCRX_ERR_MNAT_ENTRY_NOT_FOUND:
      return "mcrx: mnat entry not found";
    case MCRX_ERR_CALLBACK_FAILED:
      return "mcrx: callback failed";
    case MCRX_ERR_NOTHING_JOINED:
      return "mcrx: nothing joined";
    case MCRX_ERR_INCONSISTENT_HANDLER:
      return "mcrx: socket handlers not consistent with packet receive path";
    case MCRX_ERR_SYSCALL_BIND:
      return "mcrx: system error during bind()";
    case MCRX_ERR_SYSCALL_CLOSE:
      return "mcrx: system error during close()";
    case MCRX_ERR_SYSCALL_CONNECT:
      return "mcrx: system error during connect()";
    case MCRX_ERR_SYSCALL_FCNTL:
      return "mcrx: system error during fcntl()";
    case MCRX_ERR_SYSCALL_GETSOCKNAME:
      return "mcrx: system error during getsockname()";
    case MCRX_ERR_SYSCALL_GETIFADDRS:
      return "mcrx: system error during getifaddrs()";
    case MCRX_ERR_SYSCALL_NTOP:
      return "mcrx: system error during ntop()";
    case MCRX_ERR_SYSCALL_RECVMSG:
      return "mcrx: system error during recvmsg()";
    case MCRX_ERR_SYSCALL_SOCKET:
      return "mcrx: system error during socket()";
    case MCRX_ERR_SYSCALL_SETSOCKOPT:
      return "mcrx: system error during setsockopt()";
    case MCRX_ERR_SYSCALL_SETSOURCEFILTER:
      return "mcrx: system error during setsourcefilter()";
    case MCRX_ERR_SYSCALL_EPOLLCREATE:
      return "mcrx: system error during epollcreate()";
    case MCRX_ERR_SYSCALL_EPOLLADD:
      return "mcrx: system error during epolladd()";
    case MCRX_ERR_SYSCALL_EPOLLDEL:
      return "mcrx: system error during epolldel()";
    case MCRX_ERR_SYSCALL_EPOLLWAIT:
      return "mcrx: system error during epollwait()";
    case MCRX_ERR_SYSCALL_KEVENT:
      return "mcrx: system error during kevent()";
    case MCRX_ERR_SYSCALL_KQUEUE:
      return "mcrx: system error during kqueue()";
  }
  return "mcrx_strerror: unknown error code";
}

/**
 * mcrx_is_system_error:
 * @err: enum mcrx_error_code
 *
 * returns 1 if calling strerror(errno) can be expected to give
 * additional useful information about the underlying system problem
 * encountered when mcrx produced this error code, or 0 otherwise.
 */
MCRX_EXPORT int
mcrx_is_system_error(enum mcrx_error_code err) {
  return err >= MCRX_ERR_SYSCALL_BIND;
}

/**
 * mcrx_mnatmap_new:
 * @mnatmapp: pointer to be filled with the new mnat context
 *
 * Create a new mnat context.
 *
 * Returns: error code
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_mnatmap_new(
    struct mcrx_mnatmap **mnatmapp) {
  if (mnatmapp == NULL) {
    return MCRX_ERR_NULLARG;
  }

  struct mcrx_mnatmap *mnat_ctx;
  mnat_ctx = calloc(1, sizeof(struct mcrx_mnatmap));
  if (!mnat_ctx) {
    return MCRX_ERR_NOMEM;
  }

  mnat_ctx->refcount = 1;
  LIST_INIT(&mnat_ctx->mnats_head);

  *mnatmapp = mnat_ctx;
  return MCRX_ERR_OK;
}

/**
 * mcrx_mnatmap_apply:
 * Apply the mnat context to mcrx context
 *
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_mnatmap_apply(struct mcrx_ctx *ctx,
    struct mcrx_mnatmap *mnatmap) {
  if (ctx == NULL) {
    return MCRX_ERR_NULLARG;
  }
  if (mnatmap != NULL) {
    struct mcrx_mnatmap *clone_context;
    enum mcrx_error_code ret = mcrx_mnatmap_clone(mnatmap, &clone_context);
    if (ret != MCRX_ERR_OK) {
      return ret;
    }
    struct mcrx_mnatmap *original_mnat_map = ctx->mnat_map;
    ctx->mnat_map = clone_context;
    struct mcrx_subscription *sub;
    LIST_FOREACH(sub, &ctx->subs_head, sub_entries) {
      if (sub->state == MCRX_SUBSCRIPTION_STATE_PENDING) {
        mcrx_subscription_join(sub);
      } else if (sub->state == MCRX_SUBSCRIPTION_STATE_JOINED && original_mnat_map == NULL) {
        // previous subscription joined without MNAT
        mcrx_subscription_join(sub);
      } else if (sub->state == MCRX_SUBSCRIPTION_STATE_JOINED) {
        struct mcrx_mnat_entry *entry = NULL;
        struct mcrx_source_group_addrs global_address;
        memset(&global_address, 0, sizeof(global_address));
        global_address.addr_type = sub->input.addr_type;
        memcpy(&global_address.addrs, &sub->input.addrs,
            sizeof(global_address.addrs));
        entry = mcrx_mnatmap_find_entry(ctx->mnat_map, &global_address);
        if (!mcrx_mnatmap_entry_local_equal(entry, sub->mnat_entry)) {
          if (sub->mnat_entry == NULL && entry != NULL && mcrx_mnatmap_address_equal(&entry->global_addrs, &entry->local_addrs)) {
            sub->mnat_entry = entry;
          } else {
            mcrx_subscription_leave(sub);
            mcrx_subscription_join(sub);
          }
        } else {
          sub->mnat_entry = entry;
        }
      } else {
        sub->mnat_entry = NULL;
      }
    }
    if (original_mnat_map != NULL) {
      mcrx_mnatmap_unref(original_mnat_map);
    }
  } else {
    if (ctx->mnat_map != NULL) {
      struct mcrx_mnatmap *original_mnat_map = ctx->mnat_map;
      ctx->mnat_map = NULL;
      struct mcrx_subscription *sub;
      LIST_FOREACH(sub, &ctx->subs_head, sub_entries)
      {
        if (sub->state == MCRX_SUBSCRIPTION_STATE_JOINED) {
          mcrx_subscription_leave(sub);
          mcrx_subscription_join(sub);
        } else if (sub->state == MCRX_SUBSCRIPTION_STATE_PENDING) {
          mcrx_subscription_join(sub);
        }
      }
      mcrx_mnatmap_unref(original_mnat_map);
    }
  }

  info(ctx, "mnat context %p apply\n", (void* )mnatmap);

  return MCRX_ERR_OK;
}

/**
 * mcrx_mnatmap_get_mapping:
 *
 * Retrieve the mcrx mnat local addresses based on global source and group addresses.
 *
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_mnatmap_get_mapping(
    struct mcrx_mnatmap *mnatmap, const struct mcrx_source_group_addrs *global_address,
    struct mcrx_source_group_addrs *local_address) {
  if (global_address == NULL || local_address == NULL) {
      return MCRX_ERR_NULLARG;
  }
  struct mcrx_mnat_entry *entry = mcrx_mnatmap_find_entry(mnatmap, global_address);
  if (entry == NULL) {
    return MCRX_ERR_MNAT_ENTRY_NOT_FOUND;
  }
  if (entry->local_addrs.addr_type == MCRX_ADDR_TYPE_V4) {
    local_address->addr_type = entry->local_addrs.addr_type;
    memcpy(&local_address->addrs.v4.source, &entry->local_addrs.addrs.v4.source, sizeof(struct in_addr));
    memcpy(&local_address->addrs.v4.group, &entry->local_addrs.addrs.v4.group, sizeof(struct in_addr));
  } else if (entry->local_addrs.addr_type == MCRX_ADDR_TYPE_V6) {
    local_address->addr_type = entry->local_addrs.addr_type;
    memcpy(&local_address->addrs.v6.source, &entry->local_addrs.addrs.v6.source,
        sizeof(struct in6_addr));
    memcpy(&local_address->addrs.v6.group, &entry->local_addrs.addrs.v6.group,
        sizeof(struct in6_addr));
  } else if (entry->local_addrs.addr_type == MCRX_ADDR_TYPE_UNKNOWN) {
    memset(local_address, 0, sizeof(struct mcrx_source_group_addrs));
    local_address->addr_type = entry->local_addrs.addr_type;
  } else {
    memset(local_address, 0, sizeof(struct mcrx_source_group_addrs));
    local_address->addr_type = entry->local_addrs.addr_type;
    return MCRX_ERR_INTERNAL_ERROR;
  }
  return MCRX_ERR_OK;
}

/**
 * mcrx_mnatmap_find_entry:
 *
 * Retrieve the mcrx mnat entry based on global source and group addresses.
 *
 **/
struct mcrx_mnat_entry* mcrx_mnatmap_find_entry(
    struct mcrx_mnatmap *mnatmap, const struct mcrx_source_group_addrs *global_address) {
  struct mcrx_mnat_entry *entry = NULL;
  if (global_address == NULL) {
    return entry;
  }
  LIST_FOREACH(entry, &mnatmap->mnats_head, mnat_entries) {
    if (entry->global_addrs.addr_type == MCRX_ADDR_TYPE_V4 && global_address->addr_type == MCRX_ADDR_TYPE_V4 &&
        memcmp(&entry->global_addrs.addrs.v4.source, &global_address->addrs.v4.source, sizeof(struct in_addr)) == 0 &&
        memcmp(&entry->global_addrs.addrs.v4.group, &global_address->addrs.v4.group, sizeof(struct in_addr)) == 0) {
        return entry;
    }
    if (entry->global_addrs.addr_type == MCRX_ADDR_TYPE_V6
        && global_address->addr_type == MCRX_ADDR_TYPE_V6
        && memcmp(&entry->global_addrs.addrs.v6.source,
            &global_address->addrs.v6.source, sizeof(struct in6_addr)) == 0
        && memcmp(&entry->global_addrs.addrs.v6.group,
            &global_address->addrs.v6.group, sizeof(struct in6_addr)) == 0) {
      return entry;
    }
  }
  return entry;
}

/**
 * mcrx_mnatmap_add_or_update_mapping:
 *
 * Add the mcrx mnat entry.
 * Note: local_address can be NULL for unresolved MNAT entry
 *
 **/
enum mcrx_error_code mcrx_mnatmap_add_or_update_mapping(
    struct mcrx_mnatmap *mnatmap, const struct mcrx_source_group_addrs *global_address,
    const struct mcrx_source_group_addrs *local_address) {
  bool add_entry = false;
  if (global_address == NULL) {
    return MCRX_ERR_NULLARG;
  }
  struct mcrx_mnat_entry *entry = mcrx_mnatmap_find_entry(mnatmap,
      global_address);
  if (entry == NULL) {
    entry = calloc(1, sizeof(struct mcrx_mnat_entry));
    if (!entry) {
      return MCRX_ERR_NOMEM;
    }
    add_entry = true;
    if (global_address->addr_type == MCRX_ADDR_TYPE_V4) {
      entry->global_addrs.addr_type = global_address->addr_type;
      memcpy(&entry->global_addrs.addrs.v4.source, &global_address->addrs.v4.source,
          sizeof(struct in_addr));
      memcpy(&entry->global_addrs.addrs.v4.group, &global_address->addrs.v4.group,
          sizeof(struct in_addr));
    } else if (global_address->addr_type == MCRX_ADDR_TYPE_V6) {
      entry->global_addrs.addr_type = global_address->addr_type;
      memcpy(&entry->global_addrs.addrs.v6.source, &global_address->addrs.v6.source,
          sizeof(struct in6_addr));
      memcpy(&entry->global_addrs.addrs.v6.group, &global_address->addrs.v6.group,
          sizeof(struct in6_addr));
    } else {
      free(entry);
      return MCRX_ERR_UNKNOWN_FAMILY;
    }
  }
  if (local_address == NULL || local_address->addr_type == MCRX_ADDR_TYPE_UNKNOWN) {
    // unresolved local address
    memset(&entry->local_addrs, 0, sizeof(entry->local_addrs));
    entry->local_addrs.addr_type = MCRX_ADDR_TYPE_UNKNOWN;
  } else if (local_address->addr_type == MCRX_ADDR_TYPE_V4) {
    entry->local_addrs.addr_type = local_address->addr_type;
    memcpy(&entry->local_addrs.addrs.v4.source, &local_address->addrs.v4.source,
        sizeof(struct in_addr));
    memcpy(&entry->local_addrs.addrs.v4.group, &local_address->addrs.v4.group,
        sizeof(struct in_addr));
  } else if (local_address->addr_type == MCRX_ADDR_TYPE_V6) {
    entry->local_addrs.addr_type = local_address->addr_type;
    memcpy(&entry->local_addrs.addrs.v6.source, &local_address->addrs.v6.source,
        sizeof(struct in6_addr));
    memcpy(&entry->local_addrs.addrs.v6.group, &local_address->addrs.v6.group,
        sizeof(struct in6_addr));
  } else {
    if (add_entry) {
      free(entry);
    }
    return MCRX_ERR_UNKNOWN_FAMILY;
  }

  if (add_entry) {
    LIST_INSERT_HEAD(&mnatmap->mnats_head, entry, mnat_entries);
  }

  return MCRX_ERR_OK;
}

/**
 * mcrx_mnatmap_remove_mapping:
 *
 * Remove the mcrx mnat mapping.
 *
 **/
MCRX_EXPORT enum mcrx_error_code mcrx_mnatmap_remove_mapping(
    struct mcrx_mnatmap *mnatmap, const struct mcrx_source_group_addrs *global_address) {
  if (global_address == NULL) {
    return MCRX_ERR_NULLARG;
  }

  struct mcrx_mnat_entry *entry = mcrx_mnatmap_find_entry(mnatmap,
      global_address);
  if (entry == NULL) {
    return MCRX_ERR_OK;
  }

  LIST_REMOVE(entry, mnat_entries);
  free(entry);

  return MCRX_ERR_OK;
}

/**
 * mcrx_mnatmap_ref:
 *
 **/
MCRX_EXPORT struct mcrx_mnatmap* mcrx_mnatmap_ref(
    struct mcrx_mnatmap *mnatmap) {
  mnatmap->refcount++;
  return mnatmap;
}

MCRX_EXPORT struct mcrx_mnatmap* mcrx_mnatmap_unref(
    struct mcrx_mnatmap *mnatmap) {
  mnatmap->refcount--;
  if (mnatmap->refcount > 0) {
    return mnatmap;
  }

  while (!LIST_EMPTY(&mnatmap->mnats_head)) {
    struct mcrx_mnat_entry *entry = LIST_FIRST(&mnatmap->mnats_head);
    LIST_REMOVE(entry, mnat_entries);
    free(entry);
  }

  free(mnatmap);
  return NULL;
}

/**
 * mcrx_mnatmap_find_or_alloc_entry_from_subscription:
 *
 * Retrieve the mcrx mnat entry based on subscription, will create unresolved entry if there is no matching entry
 * for the subscription while the mnat is configured
 *
 **/
struct mcrx_mnat_entry* mcrx_mnatmap_find_or_alloc_entry_from_subscription(
    struct mcrx_subscription *sub, struct mcrx_mnatmap *mnatmap) {
  if (sub == NULL || mnatmap == NULL) {
    return NULL;
  }
  struct mcrx_mnat_entry *entry = NULL;
  struct mcrx_source_group_addrs global_address;
  memset(&global_address, 0, sizeof(global_address));
  global_address.addr_type = sub->input.addr_type;
  memcpy(&global_address.addrs, &sub->input.addrs,
      sizeof(global_address.addrs));
  entry = mcrx_mnatmap_find_entry(mnatmap, &global_address);
  if (entry == NULL) {
    // mnat is active and we can not find entry, alloc a unresolved entry
    enum mcrx_error_code ret = mcrx_mnatmap_add_or_update_mapping(mnatmap, &global_address, NULL);
    if (ret != MCRX_ERR_OK) {
      return NULL;
    } else {
      return mcrx_mnatmap_find_entry(mnatmap, &global_address);
    }
  } else {
    return entry;
  }
}


MCRX_EXPORT enum mcrx_error_code mcrx_mnatmap_clone(struct mcrx_mnatmap *mnatmap_src,
    struct mcrx_mnatmap **mnatmapp_dest) {
  if (mnatmap_src == NULL || mnatmapp_dest == NULL) {
    return MCRX_ERR_NULLARG;
  }
  enum mcrx_error_code ret = mcrx_mnatmap_new(mnatmapp_dest);
  if (ret != MCRX_ERR_OK) {
    return ret;
  }
  struct mcrx_mnat_entry *entry = NULL;
  LIST_FOREACH(entry, &mnatmap_src->mnats_head, mnat_entries) {
    struct mcrx_mnat_entry *entry_dest = calloc(1, sizeof(struct mcrx_mnat_entry));
    if (!entry_dest) {
      mcrx_mnatmap_unref(*mnatmapp_dest);
      *mnatmapp_dest = NULL;
      return MCRX_ERR_NOMEM;
    }
    memcpy((void *)entry_dest, (void *)entry, sizeof(entry));
    LIST_INSERT_HEAD(&(*mnatmapp_dest)->mnats_head, entry_dest, mnat_entries);
  }

  return MCRX_ERR_OK;
}

bool mcrx_mnatmap_entry_unresolved(struct mcrx_mnat_entry* entry) {
  if (entry == NULL) {
    return true;
  }
  // check to see whether the local address is resolved
  if (entry->local_addrs.addr_type == MCRX_ADDR_TYPE_UNKNOWN) {
    return true;
  }

  return false;
}

bool mcrx_mnatmap_entry_local_equal(struct mcrx_mnat_entry* entry_src,
    struct mcrx_mnat_entry* entry_dest) {
  if (entry_src == NULL || entry_dest == NULL) {
    return false;
  }
  return mcrx_mnatmap_address_equal(&entry_src->local_addrs, &entry_dest->local_addrs);
}

bool mcrx_mnatmap_entry_global_equal(struct mcrx_mnat_entry* entry_src,
    struct mcrx_mnat_entry* entry_dest) {
  if (entry_src == NULL || entry_dest == NULL) {
    return false;
  }
  return mcrx_mnatmap_address_equal(&entry_src->global_addrs, &entry_dest->global_addrs);
}

bool mcrx_mnatmap_address_equal(struct mcrx_source_group_addrs * addr1,
    struct mcrx_source_group_addrs *addr2) {
  if (addr1 == NULL || addr2 == NULL) {
      return false;
    }
  if (addr1->addr_type == MCRX_ADDR_TYPE_V4 && addr2->addr_type == MCRX_ADDR_TYPE_V4 &&
      memcmp(&addr1->addrs.v4.source, &addr2->addrs.v4.source, sizeof(struct in_addr)) == 0 &&
      memcmp(&addr1->addrs.v4.group, &addr2->addrs.v4.group, sizeof(struct in_addr)) == 0) {
    return true;
  }
  if (addr1->addr_type == MCRX_ADDR_TYPE_V6 && addr2->addr_type == MCRX_ADDR_TYPE_V6 &&
      memcmp(&addr1->addrs.v6.source, &addr2->addrs.v6.source, sizeof(struct in6_addr)) == 0 &&
      memcmp(&addr1->addrs.v6.group, &addr2->addrs.v6.group, sizeof(struct in6_addr)) == 0) {
    return true;
  }
  return false;
}


MCRX_EXPORT enum mcrx_error_code mcrx_source_group_addrs_config_pton(
    struct mcrx_source_group_addrs *addrs,
    const char* source,
    const char* group) {
  int ret;
  ret = inet_pton(AF_INET, source, &addrs->addrs.v4);
  if (ret > 0) {
    ret = inet_pton(AF_INET, group, &addrs->addrs.v4.group);
    if (ret > 0) {
      addrs->addr_type = MCRX_ADDR_TYPE_V4;
      return MCRX_ERR_OK;
    }
  }

  ret = inet_pton(AF_INET6, source, &addrs->addrs.v6.source);
  if (ret > 0) {
    ret = inet_pton(AF_INET6, group, &addrs->addrs.v6.group);
    if (ret > 0) {
      addrs->addr_type = MCRX_ADDR_TYPE_V6;
      return MCRX_ERR_OK;
    }
  }

  addrs->addr_type = MCRX_ADDR_TYPE_UNKNOWN;
  return MCRX_ERR_UNKNOWN_FAMILY;
}


