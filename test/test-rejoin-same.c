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
  int got_5;
};

static int receive_cb(struct mcrx_packet* pkt) {
  unsigned int length = mcrx_packet_get_contents(pkt, 0);
  printf("got packet, length=%u\n", length);
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct sub_info* info = (struct sub_info*)mcrx_subscription_get_userdata(sub);
  info->npackets += 1;
  mcrx_packet_unref(pkt);
  pkt = NULL;

  if (info->npackets > 5) {
    printf("unsubscribing\n");
    mcrx_subscription_leave(sub);
    info->got_5 = 1;
  }
  if (info->npackets > 100) {
    fprintf(stderr, "did not stop at 5 packets\n");
    exit(1);
    return MCRX_RECEIVE_STOP_CTX;
  }
  return MCRX_RECEIVE_CONTINUE;
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
  mcrx_ctx_set_log_priority(ctx, MCRX_LOGLEVEL_INFO);

  struct mcrx_subscription_config cfg = MCRX_SUBSCRIPTION_CONFIG_INIT;
  err = mcrx_subscription_config_pton(&cfg, "23.212.185.5", "232.1.1.1");
  if (err != 0) {
    fprintf(stderr, "subscription_config_pton failed\n");
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  cfg.port = 5001;

  err = mcrx_subscription_new(ctx, &cfg, &sub);
  if (err != 0) {
    fprintf(stderr, "new subscription failed\n");
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  mcrx_subscription_set_userdata(sub, (intptr_t)&info);
  mcrx_subscription_set_receive_cb(sub, receive_cb);
  mcrx_ctx_set_wait_ms(ctx, 5000);

  err = mcrx_subscription_join(sub);
  if (err != 0) {
    fprintf(stderr, "subscription join failed\n");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  do {
    err = mcrx_ctx_receive_packets(ctx);
  } while (!err || err == MCRX_ERR_TIMEDOUT);

  if (err != MCRX_ERR_NOTHING_JOINED) {
    fprintf(stderr, "subscription receive failed: %s\n", strerror(err));
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  info.npackets = 0;
  info.got_5 = 0;
  sleep(5);
  err = mcrx_subscription_join(sub);
  if (err != 0) {
    fprintf(stderr, "subscription join failed\n");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  do {
    err = mcrx_ctx_receive_packets(ctx);
  } while (!err || err == MCRX_ERR_TIMEDOUT);

  mcrx_subscription_unref(sub);
  mcrx_ctx_unref(ctx);
  if (info.got_5) {
    return EXIT_SUCCESS;
  } else {
    return EXIT_FAILURE;
  }
}
