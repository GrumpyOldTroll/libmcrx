/*
 * libmrx - multicast receiving library
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
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mrx_ctx
 *
 * library user context - reads the config and system
 * environment, user variables, allows custom logging
 */
struct mrx_ctx;
struct mrx_subscription;
struct mrx_packet;

struct mrx_ctx *mrx_ctx_ref(
    struct mrx_ctx *ctx);
struct mrx_ctx *mrx_ctx_unref(
    struct mrx_ctx *ctx);
intptr_t mrx_ctx_get_userdata(
    struct mrx_ctx *ctx);
void mrx_ctx_set_userdata(
    struct mrx_ctx *ctx,
    intptr_t userdata);

int mrx_ctx_new(
    struct mrx_ctx **ctx);
void mrx_ctx_set_log_fn(
    struct mrx_ctx *ctx,
    void (*log_fn)(
      struct mrx_ctx *ctx,
      int priority,
      const char *file,
      int line,
      const char *fn,
      const char *format,
      va_list args));
int mrx_ctx_get_log_priority(
    struct mrx_ctx *ctx);
void mrx_ctx_set_log_priority(
    struct mrx_ctx *ctx,
    int priority);
int mrx_ctx_receive_packets(
    struct mrx_ctx *ctx,
    int timeout_ms);

/*
 * mrx_subscription
 *
 * a subscription handle.  joins and leaves groups, tracks statistics,
 * fires callbacks as packets are received.
 */
struct mrx_subscription_addrs_dns {
  const char* source;
  const char* group;
};

/*
 * mrx_subscription_addrs_v4
 *
 * on platforms with struct in_addr, a memcpy from one of those into
 * these objects is ok.  This is declared weird for easier cross-platform.
 *
 * struct in_addr usually there if you include <netinet/in.h>
 * and can be filled from string with inet_ntop(AF_INET)
 */
struct mrx_subscription_addrs_v4 {
  struct in_addr source;
  struct in_addr group;
};

/*
 * mrx_subscription_addrs_v6
 *
 * on platforms with struct in6_addr, a memcpy from one of those into
 * these objects is ok.  This is declared weird for easier cross-platform.
 *
 * struct in_addr usually there if you include <netinet/in.h>
 * and can be filled from string with inet_ntop(AF_INET6)
 */
struct mrx_subscription_addrs_v6 {
  struct in6_addr source;
  struct in6_addr group;
};

enum MRX_ADDR_TYPE {
  MRX_ADDR_TYPE_DNS,
  MRX_ADDR_TYPE_V4,
  MRX_ADDR_TYPE_V6
};

struct mrx_subscription_config {
  int magic;
  enum MRX_ADDR_TYPE addr_type;
  union {
    struct mrx_subscription_addrs_dns dns;
    struct mrx_subscription_addrs_v4 v4;
    struct mrx_subscription_addrs_v6 v6;
  } addrs;
  uint16_t port;  // in host byte order (.port = 1024 to get wire=0x0400)
  uint16_t packet_size;
};
#define MRX_SUBSCRIPTION_MAGIC 0x42
#define MRX_SUBSCRIPTION_INIT { \
  .magic = MRX_SUBSCRIPTION_MAGIC, \
  .packet_size = 1452 \
}

struct mrx_subscription* mrx_subscription_ref(
    struct mrx_subscription* sub);
struct mrx_subscription* mrx_subscription_unref(
    struct mrx_subscription* sub);
intptr_t mrx_subscription_get_userdata(
    struct mrx_subscription *sub);
void mrx_subscription_set_userdata(
    struct mrx_subscription *sub,
    intptr_t userdata);
struct mrx_ctx* mrx_subscription_get_ctx(
    struct mrx_subscription* sub);

int mrx_subscription_new(
    struct mrx_ctx* ctx,
    const struct mrx_subscription_config* config,
    struct mrx_subscription** sub);

int mrx_subscription_join(
    struct mrx_subscription* sub,
    void (*receive_cb)(
      struct mrx_packet* packet));
int mrx_subscription_leave(
    struct mrx_subscription* sub);

struct mrx_packet* mrx_packet_ref(
    struct mrx_packet* pkt);
struct mrx_packet* mrx_packet_unref(
    struct mrx_packet* pkt);
intptr_t mrx_packet_get_userdata(
    struct mrx_packet* pkt);
void mrx_packet_set_userdata(
    struct mrx_packet* pkt,
    intptr_t userdata);
struct mrx_subscription* mrx_packet_get_subscription(
    struct mrx_packet* pkt);

// returns length of data
uint16_t mrx_packet_get_contents(
    struct mrx_packet* pkt,
    uint8_t** data);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // GUARD_LIBMCASTRX_H
