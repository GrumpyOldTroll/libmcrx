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
#include <syslog.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mcrx_ctx
 *
 * library user context - reads the config and system
 * environment, user variables, allows custom logging
 */
struct mcrx_ctx;

/*
 * mcrx_subscription
 *
 * subscription handle - joins a (S,G) and passes received
 * packets to library user.
 */
struct mcrx_subscription;

/*
 * mcrx_packet
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

int mcrx_ctx_new(
    struct mcrx_ctx **ctxp);
void mcrx_ctx_set_log_fn(
    struct mcrx_ctx *ctx,
    void (*log_fn)(
      struct mcrx_ctx *ctx,
      int priority,
      const char *file,
      int line,
      const char *fn,
      const char *format,
      va_list args));
// log priority: LOG_ERR, LOG_WARNING, LOG_INFO, or LOG_DEBUG (syslog.h)
int mcrx_ctx_get_log_priority(
    struct mcrx_ctx *ctx);
void mcrx_ctx_set_log_priority(
    struct mcrx_ctx *ctx,
    int priority);
int mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx,
    int timeout_ms);

/*
 * mcrx_subscription
 *
 * a subscription handle.  joins and leaves groups, tracks statistics,
 * fires callbacks as packets are received.
 */
struct mcrx_subscription_addrs_dns {
  const char* source;
  const char* group;
};

/*
 * mcrx_subscription_addrs_v4
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

/*
 * mcrx_subscription_addrs_v6
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

/*
 * mcrx_subscription_config
 *
 * config for the subscription object.  Provides the (S,G) either as
 * a pair of v4 addresses, a pair of v6 addresses, or a pair of DNS
 * names (which may be address strings, but will error if they don't
 * match type after resolution).  Also requires UDP port.  Initialize
 * with MCRX_SUBSCRIPTION_INIT, then overwrite fields as needed.
 */
struct mcrx_subscription_config {
  int magic;
  enum MCRX_ADDR_TYPE addr_type;
  union {
    struct mcrx_subscription_addrs_v4 v4;
    struct mcrx_subscription_addrs_v6 v6;
  } addrs;
  uint16_t port;  // in host byte order (.port=255 to get wire=0x00ff)
  uint16_t packet_size;
};
#define MCRX_SUBSCRIPTION_MAGIC 0x42
// default values
#define MCRX_SUBSCRIPTION_INIT { \
  .magic = MCRX_SUBSCRIPTION_MAGIC, \
  .packet_size = 1452 \
}

int mcrx_subscription_config_pton(
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

int mcrx_subscription_new(
    struct mcrx_ctx* ctx,
    const struct mcrx_subscription_config* config,
    struct mcrx_subscription** subp);

int mcrx_subscription_join(
    struct mcrx_subscription* sub,
    void (*receive_cb)(
      struct mcrx_packet* packet));
int mcrx_subscription_leave(
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

#define MCRX_SUB_STRLEN (INET6_ADDRSTRLEN+2+INET6_ADDRSTRLEN+1+6)
/**
 * mcrx_sub_ntop:
 * @sub: subscription
 * @buf: buffer to write desc into
 * @len: len of buffer (use MCRX_SUB_STRLEN to guarantee size)
 *
 * Write "src->grp(port)" to buf, return nonzero and set errno on error.
 *
 * Returns: 0 on success, nonzero on error.
 */
int mcrx_subscription_ntop(
    struct mcrx_subscription* sub,
    char* buf,
    int buflen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // GUARD_LIBMCRX_H
