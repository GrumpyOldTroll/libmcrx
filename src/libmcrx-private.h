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
#include <sys/queue.h>

#include <mcrx/libmcrx.h>

#ifdef __APPLE__
#define MCRX_PRV_USE_KEVENT 1
#define MCRX_PRV_USE_EPOLL 0
#endif

#ifdef __linux__
#define MCRX_PRV_USE_KEVENT 0
#define MCRX_PRV_USE_EPOLL 1
#endif

#define UNUSED(x) ((void)x)

static inline void __attribute__((always_inline, format(printf, 2, 3)))
mcrx_log_null(struct mcrx_ctx *ctx, const char *format, ...) {
  UNUSED(ctx);
  UNUSED(format);
}

#ifdef LIBMCRX_STATIC
#define MCRX_EXPORT
#else
// for chromium's static build usage (with checking of exported symbols)
// this caused an error, but it's needed for the dynamic library usage
// in https://github.com/fg-inet/python-asyncio-taps. --jake 2020-10
#define MCRX_EXPORT __attribute__((visibility("default")))
#endif

#define mcrx_log_cond(ctx, prio, file, line, func, ...)                   \
  do {                                                                    \
    int INSIDE_DEF_lpr;                                                   \
    if (!(ctx)) {                                                         \
      INSIDE_DEF_lpr = MCRX_LOGLEVEL_WARNING;                             \
    } else {                                                              \
      INSIDE_DEF_lpr = mcrx_ctx_get_log_priority(ctx);                    \
    }                                                                     \
    if (INSIDE_DEF_lpr >= (prio)) {                                       \
      mcrx_log(ctx, prio, file, line, func, __VA_ARGS__);                 \
    }                                                                     \
  } while (0)

#ifdef DISABLE_DEBUG
#undef DISABLE_DEBUG
#endif

#ifndef DISABLE_LOGGING
#ifndef DISABLE_DEBUG
#define dbg_passthru(ctx, file, line, func, ...) mcrx_log_cond(ctx, \
    MCRX_LOGLEVEL_DEBUG, file, line, func, __VA_ARGS__)
#define dbg(ctx, ...) dbg_passthru(ctx, __FILE__, __LINE__, __func__, \
    __VA_ARGS__)
#else
#define dbg(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#endif
#define info_passthru(ctx, file, line, func, ...) mcrx_log_cond(ctx, \
    MCRX_LOGLEVEL_INFO, file, line, func, __VA_ARGS__)
#define warn_passthru(ctx, file, line, func, ...) mcrx_log_cond(ctx, \
    MCRX_LOGLEVEL_WARNING, file, line, func, __VA_ARGS__)
#define err_passthru(ctx, file, line, func, ...) mcrx_log_cond(ctx, \
    MCRX_LOGLEVEL_ERROR, file, line, func, __VA_ARGS__)

#define info(ctx, ...) info_passthru(ctx, __FILE__, __LINE__, __func__, \
    __VA_ARGS__)
#define warn(ctx, ...) warn_passthru(ctx, __FILE__, __LINE__, __func__, \
    __VA_ARGS__)
#define err(ctx, ...) err_passthru(ctx, __FILE__, __LINE__, __func__, \
    __VA_ARGS__)
#else
#define dbg(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define info(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define warn(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define err(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)

#define dbg_passthru(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define info_passthru(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define warn_passthru(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#define err_passthru(ctx, ...) mcrx_log_null(ctx, __VA_ARGS__)
#endif

void mcrx_log(struct mcrx_ctx *ctx, enum mcrx_log_priority priority,
    const char *file, int line, const char *fn, const char *format, ...)
    __attribute__((format(printf, 6, 7)));

/**
 * mcrx_packet:
 *
 * Opaque object representing a received packet.
 */
struct mcrx_packet {
  struct mcrx_subscription *sub;
  int refcount;
  intptr_t userdata;
  TAILQ_ENTRY(mcrx_packet) pkt_entries;
  uint16_t remote_port;
  uint16_t size;
  uint8_t data[];
};

/**
 * mcrx_subscription:
 *
 * Opaque object representing a subscription to an (S,G):port.
 */
struct mcrx_subscription {
  struct mcrx_ctx *ctx;
  int refcount;
  intptr_t userdata;
  uint16_t max_payload_size;
  LIST_ENTRY(mcrx_subscription) sub_entries;
  TAILQ_HEAD(tailhead, mcrx_packet) pkts_head;
  struct mcrx_subscription_config input;
  int sock_fd;
  int (*receive_cb)(struct mcrx_packet* packet);
  int joined;
  const char* override_ifname;
  struct mcrx_mnat_entry *mnat_entry;
  enum mcrx_subscription_state state;
  int (*state_change_cb)(struct mcrx_subscription *sub, enum mcrx_subscription_state state, enum mcrx_error_code result);
};

enum mcrx_socket_handling_state {
  MCRX_SOCKHANDLER_UNCOMMITTED,
  MCRX_SOCKHANDLER_BUILTIN,
  MCRX_SOCKHANDLER_EXTERNAL
};

/**
 * mcrx_mnat_entry:
 *
 * Opaque object representing a mnat entry.
 */
struct mcrx_mnat_entry {
  LIST_ENTRY(mcrx_mnat_entry) mnat_entries;
  struct mcrx_source_group_addrs local_addrs;
  struct mcrx_source_group_addrs global_addrs;
};

/**
 * mcrx_mnat_map:
 *
 * Opaque object representing a mnat context.
 */
struct mcrx_mnatmap {
  int refcount;
  LIST_HEAD(mnat_listhead, mcrx_mnat_entry) mnats_head;
};

/**
 * mcrx_ctx:
 *
 * Opaque object representing the library context.
 */
struct mcrx_ctx {
  int refcount;
  void (*log_fn)(struct mcrx_ctx *ctx, int priority,
      const char *file, int line, const char *fn,
      const char *format, va_list args);
  void (*string_log_fn)(struct mcrx_ctx *ctx, int priority,
      const char *file, int line, const char *fn,
      const char *str);
  intptr_t userdata;
  enum mcrx_log_priority log_priority;
  LIST_HEAD(listhead, mcrx_subscription) subs_head;
  struct mcrx_mnatmap *mnat_map;
  int timeout_ms;
  int wait_fd;
  sigset_t wait_sigmask;
  intptr_t added_handle;
  intptr_t removed_handle;
  int (*add_socket_cb)(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*do_receive)(intptr_t handle, int fd));

  int (*remove_socket_cb)(
    struct mcrx_ctx* ctx,
    int fd);

  u_int live_subs;
  enum mcrx_socket_handling_state sock_handler_state;

#if MCRX_PRV_USE_KEVENT
  struct kevent* events;
  u_int nevents;
  struct kevent* triggered;
  u_int ntriggered;
  u_int nadded;
#endif
#if MCRX_PRV_USE_EPOLL
  struct epoll_event *events;
  u_int nevents;
  struct epoll_event* triggered;
  u_int ntriggered;
#endif
};

enum mcrx_error_code mcrx_subscription_native_join(
    struct mcrx_subscription* sub);
enum mcrx_error_code mcrx_subscription_native_leave(
    struct mcrx_subscription* sub);

int mcrx_prv_add_socket_cb(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*do_receive)(intptr_t handle, int fd));

int mcrx_prv_remove_socket_cb(
    struct mcrx_ctx* ctx,
    int fd);

void wrap_strerr(
    int err_no,
    char* buf,
    int len);

struct mcrx_mnat_entry* mcrx_mnatmap_find_entry(struct mcrx_mnatmap *mnatmap,
    const struct mcrx_source_group_addrs *global_address);
struct mcrx_mnat_entry* mcrx_mnatmap_find_or_alloc_entry_from_subscription(
    struct mcrx_subscription *sub, struct mcrx_mnatmap *mnatmap);
enum mcrx_error_code mcrx_mnatmap_clone(struct mcrx_mnatmap *mnatmap_src,
    struct mcrx_mnatmap **mnatmapp_dest);
bool mcrx_mnatmap_entry_unresolved(struct mcrx_mnat_entry* entry);
bool mcrx_mnatmap_entry_local_equal(struct mcrx_mnat_entry* entry_src, struct mcrx_mnat_entry* entry_dest);
bool mcrx_mnatmap_entry_global_equal(struct mcrx_mnat_entry* entry_src, struct mcrx_mnat_entry* entry_dest);
bool mcrx_mnatmap_address_equal(struct mcrx_source_group_addrs * addr1, struct mcrx_source_group_addrs *addr2);

enum mcrx_error_code handle_close_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func);
#define handle_close_error(ctx) handle_close_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

#endif  // GUARD_LIBMCRX_PRIVATE_H_
