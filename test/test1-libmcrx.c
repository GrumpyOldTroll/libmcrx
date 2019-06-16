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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <mcrx/libmcrx.h>

struct sub_info {
  int npackets;
};

static void receive_cb(struct mcrx_packet* pkt) {
  unsigned int length = mcrx_packet_get_contents(pkt, 0);
  printf("got packet, length=%u\n", length);
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct sub_info* info = (struct sub_info*)mcrx_subscription_get_userdata(sub);
  info->npackets += 1;
  mcrx_packet_unref(pkt);

  if (info->npackets > 5) {
    mcrx_subscription_leave(mcrx_packet_get_subscription(pkt));
  }
}

int
main(int argc, char *argv[])
{
  (void)(argc);
  (void)(argv);

  struct mcrx_ctx *ctx;
  struct mcrx_subscription *sub = NULL;
  int err;
  struct sub_info info = { .npackets=0 };

  err = mcrx_ctx_new(&ctx);
  if (err < 0) {
    fprintf(stderr, "ctx_new failed\n");
    return EXIT_FAILURE;
  }

  struct mcrx_subscription_config cfg = MCRX_SUBSCRIPTION_INIT;
  cfg.addr_type = MCRX_ADDR_TYPE_DNS;
  cfg.addrs.dns.source = "23.212.185.1";
  cfg.addrs.dns.group = "232.10.10.1";
  cfg.port = 5001;

  err = mcrx_subscription_new(ctx, &cfg, &sub);
  if (err < 0) {
    fprintf(stderr, "new subscription failed\n");
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  mcrx_subscription_set_userdata(sub, (intptr_t)&info);

  err = mcrx_subscription_join(sub, receive_cb);
  if (err < 0) {
    fprintf(stderr, "subscription join failed\n");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  err = mcrx_ctx_receive_packets(ctx, -1);
  if (err < 0) {
    fprintf(stderr, "subscription receive failed\n");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  // check I get warnings when not finishing this.
  // mcrx_subscription_unref(sub);
  mcrx_ctx_unref(ctx);
  return EXIT_SUCCESS;
}
