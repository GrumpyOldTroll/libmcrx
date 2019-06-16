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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <mcastrx/libmcastrx.h>

static int npackets = 0;
static void receive_cb(struct mrx_packet* pkt) {
  unsigned int length = mrx_packet_get_contents(pkt, 0);
  printf("got packet, length=%u\n", length);
  npackets += 1;
  if (npackets > 5) {
    mrx_subscription_leave(mrx_packet_get_subscription(pkt));
  }
  mrx_packet_unref(pkt);
}

int
main(int argc, char *argv[])
{
  (void)(argc);
  (void)(argv);

  struct mrx_ctx *ctx;
  struct mrx_subscription *sub = NULL;
  int err;

  err = mrx_ctx_new(&ctx);
  if (err < 0) {
    fprintf(stderr, "ctx_new failed\n");
    return EXIT_FAILURE;
  }

  printf("version %s\n", VERSION);

  struct mrx_subscription_config cfg = MRX_SUBSCRIPTION_INIT;
  cfg.addr_type = MRX_ADDR_TYPE_DNS;
  cfg.addrs.dns.source = "23.212.185.1";
  cfg.addrs.dns.group = "232.10.10.1";
  cfg.port = 5001;

  err = mrx_subscription_new(ctx, &cfg, &sub);
  if (err < 0) {
    fprintf(stderr, "new subscription failed\n");
    mrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  err = mrx_subscription_join(sub, receive_cb);
  if (err < 0) {
    fprintf(stderr, "subscription join failed\n");
    mrx_subscription_unref(sub);
    mrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  err = mrx_ctx_receive_packets(ctx, -1);
  if (err < 0) {
    fprintf(stderr, "subscription receive failed\n");
    mrx_subscription_unref(sub);
    mrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  mrx_subscription_unref(sub);
  mrx_ctx_unref(ctx);
  return EXIT_SUCCESS;
}
