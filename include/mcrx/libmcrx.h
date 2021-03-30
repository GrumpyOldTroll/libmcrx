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

#ifndef GUARD_LIBMCRX_H
#define GUARD_LIBMCRX_H

#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <mcrx/errors.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * mcrx_ctx:
 *
 * library user context - reads the config and system
 * environment, user variables, allows custom logging
 */
struct mcrx_ctx;

/**
 * mcrx_subscription:
 *
 * subscription handle - joins a (S,G) and passes received
 * packets to library user.
 */
struct mcrx_subscription;


/**
 * mcrx_mnat_entry:
 *
 * mnat entry.
 */
struct mcrx_mnat_entry;

/**
 * mcrx_mnat_ctx:
 *
 * mnat context handle.
 */
struct mcrx_mnat_ctx;

/**
 * mcrx_packet:
 *
 * packet handle - provides data and packet lengths to
 * library user.
 */
struct mcrx_packet;

struct mcrx_ctx *mcrx_ctx_ref(
    struct mcrx_ctx *ctx);
struct mcrx_ctx *mcrx_ctx_unref(
    struct mcrx_ctx *ctx);
intptr_t mcrx_ctx_get_userdata(
    struct mcrx_ctx *ctx);
void mcrx_ctx_set_userdata(
    struct mcrx_ctx *ctx,
    intptr_t userdata);

enum mcrx_error_code mcrx_ctx_new(
    struct mcrx_ctx **ctxp);


void mcrx_ctx_set_log_fn(
    struct mcrx_ctx *ctx,
    void (*log_fn)(
      struct mcrx_ctx *ctx,
      int priority,  // a value from mcrx_log_priority
      const char *file,
      int line,
      const char *fn,
      const char *format,
      va_list args));
void mcrx_ctx_set_log_string_fn(
    struct mcrx_ctx *ctx,
    void (*log_fn)(
      struct mcrx_ctx *ctx,
      int priority,  // a value from mcrx_log_priority
      const char *file,
      int line,
      const char *fn,
      const char *str));
// log priority values match those in <sys/syslog.h>
// but only these values are supported.
enum mcrx_log_priority {
  MCRX_LOGLEVEL_ERROR = 3,    // MCRX_LOG=err
  MCRX_LOGLEVEL_WARNING = 4,  // MCRX_LOG=warn
  MCRX_LOGLEVEL_INFO = 6,     // MCRX_LOG=info
  MCRX_LOGLEVEL_DEBUG = 7,    // MCRX_LOG=dbg
};
// log priority: LOG_ERR, LOG_WARNING, LOG_INFO, or LOG_DEBUG (syslog.h)
enum mcrx_log_priority mcrx_ctx_get_log_priority(
    struct mcrx_ctx *ctx);
void mcrx_ctx_set_log_priority(
    struct mcrx_ctx *ctx,
    enum mcrx_log_priority priority);

/**
 * mcrx_ctx_log_msg:
 *
 * writes a message into the same log stream as mcrx internal logging.
 */
void mcrx_ctx_log_msg(
    struct mcrx_ctx *ctx,
    enum mcrx_log_priority prio,
    const char *file,
    int line,
    const char *fn,
    const char* msg);


// Default value is 1000+random()%1000
// like epoll, 0 means don't block, -1 means infinity
void mcrx_ctx_set_wait_ms(
    struct mcrx_ctx *ctx,
    int timeout_ms);

enum mcrx_error_code mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx);

enum mcrx_error_code mcrx_ctx_set_receive_socket_handlers(
    struct mcrx_ctx *ctx,
    int (*add_socket_cb)(
        struct mcrx_ctx* ctx,
        intptr_t handle,
        int fd,
        int (*do_receive)(intptr_t handle, int fd)),
    int (*remove_socket_cb)(
        struct mcrx_ctx* ctx,
        int fd));


/**
 * mcrx_subscription_addrs_v4:
 *
 * on platforms with struct in_addr, a memcpy from one of those into
 * these objects is ok.  This is declared weird for easier cross-platform.
 *
 * struct in_addr usually there if you include <netinet/in.h>
 * and can be filled from string with inet_ntop(AF_INET)
 */
struct mcrx_subscription_addrs_v4 {
  struct in_addr source;
  struct in_addr group;
};

/**
 * mcrx_subscription_addrs_v6:
 *
 * on platforms with struct in6_addr, a memcpy from one of those into
 * these objects is ok.  This is declared weird for easier cross-platform.
 *
 * struct in_addr usually there if you include <netinet/in.h>
 * and can be filled from string with inet_ntop(AF_INET6)
 */
struct mcrx_subscription_addrs_v6 {
  struct in6_addr source;
  struct in6_addr group;
};

enum MCRX_ADDR_TYPE {
  MCRX_ADDR_TYPE_UNKNOWN,
  MCRX_ADDR_TYPE_V4,
  MCRX_ADDR_TYPE_V6
};

/**
 * mcrx_subscription_config:
 *
 * config for the subscription object.  Provides the (S,G) either as
 * a pair of v4 addresses, a pair of v6 addresses, or a pair of DNS
 * names (which may be address strings, but will error if they don't
 * match type after resolution).  Also requires UDP port.  Initialize
 * with MCRX_SUBSCRIPTION_INIT, then overwrite fields as needed.
 */
struct mcrx_subscription_config {
  int magic;
  uint16_t packet_size;
  uint16_t port;  // in host byte order (.port=255 to get wire=0x00ff)
  enum MCRX_ADDR_TYPE addr_type;
  union {
    struct mcrx_subscription_addrs_v4 v4;
    struct mcrx_subscription_addrs_v6 v6;
  } addrs;
};
#define MCRX_SUBSCRIPTION_CONFIG_INIT_MAGIC 0x42
// default values
#define MCRX_SUBSCRIPTION_CONFIG_INIT { \
  .magic = MCRX_SUBSCRIPTION_CONFIG_INIT_MAGIC, \
  .packet_size = 1452 \
}

enum mcrx_error_code mcrx_subscription_config_pton(
    struct mcrx_subscription_config* config,
    const char* source,
    const char* group);

struct mcrx_subscription* mcrx_subscription_ref(
    struct mcrx_subscription* sub);
struct mcrx_subscription* mcrx_subscription_unref(
    struct mcrx_subscription* sub);
intptr_t mcrx_subscription_get_userdata(
    struct mcrx_subscription *sub);
void mcrx_subscription_set_userdata(
    struct mcrx_subscription *sub,
    intptr_t userdata);
struct mcrx_ctx* mcrx_subscription_get_ctx(
    struct mcrx_subscription* sub);
void mcrx_subscription_override_ifname(
    struct mcrx_subscription* sub,
    const char* ifname);

enum mcrx_error_code mcrx_subscription_new(
    struct mcrx_ctx* ctx,
    const struct mcrx_subscription_config* config,
    struct mcrx_subscription** subp);


enum mcrx_error_code mcrx_mnat_ctx_new(struct mcrx_mnat_ctx **mnatctxp);
struct mcrx_mnat_ctx* mcrx_mnat_ctx_ref(struct mcrx_mnat_ctx *mnatctx);
struct mcrx_mnat_ctx* mcrx_mnat_ctx_unref(struct mcrx_mnat_ctx *mnatctx);
enum mcrx_error_code mcrx_mnat_ctx_add_entry(struct mcrx_mnat_ctx *mnatctx,
    const char *global_source, const char *global_group,
    const char *local_source, const char *local_group);
enum mcrx_error_code mcrx_mnat_ctx_update_entry(struct mcrx_mnat_ctx *mnatctx,
    const char *global_source, const char *global_group,
    const char *local_source, const char *local_group);
enum mcrx_error_code mcrx_mnat_ctx_remove_entry(struct mcrx_mnat_ctx *mnatctx,
    const char *global_source, const char *global_group);
struct mcrx_mnat_entry* mcrx_mnat_ctx_find_entry(struct mcrx_mnat_ctx *mnatctx,
    const char *global_source, const char *global_group);
enum mcrx_error_code mcrx_mnat_ctx_apply(struct mcrx_ctx *ctx,
    struct mcrx_mnat_ctx *mnatctxp);
struct mcrx_mnat_entry* mcrx_mnat_ctx_find_entry_from_subscription(
    struct mcrx_subscription *sub, struct mcrx_mnat_ctx *mnatctx);
enum mcrx_error_code mcrx_mnat_ctx_clone(struct mcrx_mnat_ctx *mnatctx_src,
    struct mcrx_mnat_ctx **mnatctxp_dest);
bool mcrx_mnat_ctx_entry_unresolved(struct mcrx_mnat_entry* entry);
bool mcrx_mnat_ctx_entry_local_equal(struct mcrx_mnat_entry* entry_src, struct mcrx_mnat_entry* entry_dest);
bool mcrx_mnat_ctx_entry_global_equal(struct mcrx_mnat_entry* entry_src, struct mcrx_mnat_entry* entry_dest);
/*
 * at entry to receive_cb, mcrx_packet_get_userdata returns the
 * same as mcrx_subscription_get_userdata for the sub.
 */
enum mcrx_receive_cb_continuation {
  MCRX_RECEIVE_CONTINUE = 0,
  MCRX_RECEIVE_STOP_FD,
  MCRX_RECEIVE_STOP_CTX
};
void mcrx_subscription_set_receive_cb(
    struct mcrx_subscription* sub,
    int (*receive_cb)(
      struct mcrx_packet* packet));

void mcrx_subscription_set_max_payload(
    struct mcrx_subscription* sub,
    uint16_t payload_size);
enum mcrx_error_code mcrx_subscription_join(
    struct mcrx_subscription* sub);
enum mcrx_error_code mcrx_subscription_leave(
    struct mcrx_subscription* sub);

struct mcrx_packet* mcrx_packet_ref(
    struct mcrx_packet* pkt);
struct mcrx_packet* mcrx_packet_unref(
    struct mcrx_packet* pkt);
intptr_t mcrx_packet_get_userdata(
    struct mcrx_packet* pkt);
void mcrx_packet_set_userdata(
    struct mcrx_packet* pkt,
    intptr_t userdata);
struct mcrx_subscription* mcrx_packet_get_subscription(
    struct mcrx_packet* pkt);

// returns length of data
uint16_t mcrx_packet_get_contents(
    struct mcrx_packet* pkt,
    uint8_t** data);
// remote port of received packet (host byte order)
uint16_t mcrx_packet_get_remote_port(
    struct mcrx_packet* pkt);

#define MCRX_SUB_STRLEN (INET6_ADDRSTRLEN+2+INET6_ADDRSTRLEN+1+6)
/**
 * mcrx_subscription_ntop:
 * @sub: subscription
 * @buf: buffer to write desc into
 * @len: len of buffer (use MCRX_SUB_STRLEN to guarantee size)
 *
 * Write "src->grp(port)" to buf, return nonzero and set errno on error.
 *
 * Returns: 0 on success, nonzero on error.
 */
enum mcrx_error_code mcrx_subscription_ntop(
    struct mcrx_subscription* sub,
    char* buf,
    int buflen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // GUARD_LIBMCRX_H
