#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <signal.h>

#include <mcrx/libmcrx.h>

static volatile int stopping = 0;
static void
stopping_sighandler(int sig, siginfo_t *si, void *unused) {
  (void)sig;
  (void)si;
  (void)unused;
  printf("mcrx-check: stopping from signal\n");
  stopping = 1;
}

struct sub_info {
  int target_packets;
  unsigned int got_packets;
  unsigned long long got_bytes;
  time_t start_time;
  double target_duration;
};
static unsigned int dummy_data_check = 0;

static int receive_cb(struct mcrx_packet* pkt) {
  uint8_t* data = 0;
  unsigned int length = mcrx_packet_get_contents(pkt, &data);
  struct mcrx_subscription* sub = mcrx_packet_get_subscription(pkt);
  struct sub_info* info = (struct sub_info*)mcrx_subscription_get_userdata(sub);
  int done = 0;
  info->got_packets += 1;
  info->got_bytes += length;
  if (info->target_packets > 0 && info->got_packets >= (unsigned int)info->target_packets) {
    done = 1;
  }
  if (info->target_duration) {
    time_t now = time(0);
    double since = difftime(now, info->start_time);
    if (since >= info->target_duration) {
      done = 1;
    }
  }
  if (stopping) {
    done=1;
  }
  // a bounds-check so valgrind will complain if it's bad:
  if (length > 0 && data) {
    dummy_data_check += data[0];
    dummy_data_check += data[length-1];
  }
  mcrx_packet_unref(pkt);
  pkt = NULL;

  if (done) {
    mcrx_subscription_leave(sub);
    return MCRX_RECEIVE_STOP_FD;
  }
  return MCRX_RECEIVE_CONTINUE;
}

int
main(int argc, char *argv[]) {
  int ch, rc = 0;

  struct option long_options[] = {
    { "source", required_argument, 0, 's' },
    { "group", required_argument, 0, 'g' },
    { "port", required_argument, 0, 'p' },
    { "interface", required_argument, 0, 'i' },
    { "count", required_argument, 0, 'c' },
    { "duration", required_argument, 0, 'd' },
    { "verbose", no_argument, 0, 'v' },
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
  };
  const char* source = 0;
  const char* group = 0;
  const char* port_str = 0;
  const char* count_str = 0;
  const char* duration_str = 0;
  int verbose = 0;
  int fail = 0;
  int port=0, count=5;
  double target_duration=5.;
  const char* override_ifname = NULL;

  while ((ch =
      getopt_long(argc, argv, "s:g:p:c:d:i:vh", long_options, NULL)) != EOF) {
    switch (ch) {
        case 's': {
          source = optarg;
          break;
        }
        case 'g': {
          group = optarg;
          break;
        }
        case 'p': {
          port_str = optarg;
          break;
        }
        case 'i': {
          override_ifname = optarg;
          break;
        }
        case 'c': {
          count_str = optarg;
          break;
        }
        case 'd': {
          duration_str = optarg;
          break;
        }
        case 'v': {
          verbose += 1;
          break;
        }
        case 'h': {
          printf("usage: %s -s <source> -g <group> -p <port> [-c <packet count>] [-d <seconds>] [-i ifname] [-v]\n"
             "  -s, --source:    source IP of (S,G)\n"
             "  -g, --group:     group IP of (S,G)\n"
             "  -p, --port:      UDP port to listen on\n"
             "  -c, --count:     <count> packets to stop+succeed (0 for infinite, def=5)\n"
             "  -d, --duration:  stop after <duration> seconds (0 for infinite, def=5)\n"
             "  -i, --interface: override the normal interface (toward the source) with this interface name\n"
             "  -v, --verbose:  increase verbosity (show libmcrx function calls)\n"
             "  -h, --help:     show this usage message\n",
              argv[0]);
          return 0;
        }
    }
  }

  if (!port_str) {
    fprintf(stderr, "port (-p/--port <num>) is required\n");
    fail = 1;
  } else {
    rc = sscanf(port_str, "%d", &port);
    if (rc != 1) {
      fprintf(stderr, "failed to read port from %s\n", port_str);
      fail = 1;
    } else {
      if (port < 1 || port > 0xffff) {
        fprintf(stderr, "port %d not a valid port (1-%d)\n", port, 0xffff);
        fail = 1;
      }
    }
  }

  count = 5;
  if (count_str) {
    rc = sscanf(count_str, "%d", &count);
    if (rc != 1) {
      fprintf(stderr, "failed to read count from %s\n", count_str);
      fail = 1;
    }
  }

  target_duration = 5.;
  if (duration_str) {
    rc = sscanf(duration_str, "%lf", &target_duration);
    if (rc != 1) {
      fprintf(stderr, "failed to read duration from %s\n", duration_str);
      fail = 1;
    }
  }

  struct mcrx_ctx *ctx;
  struct mcrx_subscription *sub = NULL;
  int err;
  struct sub_info info = {
    .target_packets=count,
    .got_packets=0,
    .start_time=time(0),
    .target_duration=target_duration
  };

  struct mcrx_subscription_config cfg = MCRX_SUBSCRIPTION_CONFIG_INIT;
  err = mcrx_subscription_config_pton(&cfg, source, group);
  if (err != 0) {
    fprintf(stderr, "subscription_config_pton failed: %s\n", mcrx_strerror(err));
    fail = 1;
  }

  if (fail) {
    return EXIT_FAILURE;
  }

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = stopping_sighandler;
  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    perror("sigaction(SIGTERM) failed");
    return EXIT_FAILURE;
  }
  if (sigaction(SIGHUP, &sa, NULL) == -1) {
    perror("sigaction(SIGHUP) failed");
    return EXIT_FAILURE;
  }
  if (sigaction(SIGINT, &sa, NULL) == -1) {
    perror("sigaction(SIGINT) failed");
    return EXIT_FAILURE;
  }
  if (sigaction(SIGQUIT, &sa, NULL) == -1) {
    perror("sigaction(SIGQUIT) failed");
    return EXIT_FAILURE;
  }

  err = mcrx_ctx_new(&ctx);
  if (err != 0) {
    fprintf(stderr, "ctx_new failed: %s %s\n", mcrx_strerror(err), mcrx_is_system_error(err)?strerror(errno):"");
    return EXIT_FAILURE;
  }
  int level = MCRX_LOGLEVEL_WARNING;
  if (verbose > 1) {
    level = MCRX_LOGLEVEL_DEBUG;
  } else if (verbose > 0) {
    level = MCRX_LOGLEVEL_INFO;
  }
  mcrx_ctx_set_log_priority(ctx, level);

  cfg.port = port;

  err = mcrx_subscription_new(ctx, &cfg, &sub);
  if (err != 0) {
    fprintf(stderr, "new subscription failed: %s %s\n", mcrx_strerror(err), mcrx_is_system_error(err)?strerror(errno):"");
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  if (override_ifname) {
    mcrx_subscription_override_ifname(sub, override_ifname);
  }

  int timeout_milliseconds=500;
  /*
  if (target_duration >= 0) {
    timeout_milliseconds = (int)(target_duration*1000 + 0.5);
  }
  */
  mcrx_subscription_set_userdata(sub, (intptr_t)&info);
  mcrx_subscription_set_receive_cb(sub, receive_cb);
  mcrx_ctx_set_wait_ms(ctx, timeout_milliseconds);

  err = mcrx_subscription_join(sub);
  if (err != 0) {
    fprintf(stderr, "subscription join failed: %s %s\n", mcrx_strerror(err), mcrx_is_system_error(err)?strerror(errno):"");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  int msg_period = 1;
  time_t last_msg_time = time(0);
  time_t now;
  do {
    err = mcrx_ctx_receive_packets(ctx);
    now = time(0);
    if (target_duration) {
      double dur = difftime(now, info.start_time);
      if (dur > target_duration) {
        break;
      }
    }
    if (stopping) {
      int leave_err = mcrx_subscription_leave(sub);
      if (leave_err != 0) {
        fprintf(stderr, "subscription leave failed: %s %s\n", mcrx_strerror(leave_err), mcrx_is_system_error(leave_err)?strerror(errno):"");
      }
      break;
    }
    double msg_gap = difftime(now, last_msg_time);
    if (msg_gap > msg_period) {
      double total_dur = difftime(now, info.start_time);
      struct tm *loc_time;
      last_msg_time = now;
      char tbuf[80];
      loc_time = localtime(&now);
      strftime(tbuf,sizeof(tbuf),"%m-%d %H:%M:%S", loc_time);
      printf("%s: joined to %s->%s:%d for %gs, %u pkts received\n",
          tbuf, source, group, (int)port, total_dur, info.got_packets);
    }
  } while (!err || err == MCRX_ERR_TIMEDOUT);

  if (err && err != MCRX_ERR_NOTHING_JOINED && err != MCRX_ERR_TIMEDOUT) {
    fprintf(stderr, "subscription receive failed: %s %s\n", mcrx_strerror(err), mcrx_is_system_error(err)?strerror(errno):"");
    mcrx_subscription_unref(sub);
    mcrx_ctx_unref(ctx);
    return EXIT_FAILURE;
  }

  mcrx_subscription_unref(sub);
  mcrx_ctx_unref(ctx);
  now = time(0);
  double dur = difftime(now, info.start_time);
  if (info.target_packets && info.got_packets >= (unsigned int)info.target_packets) {
    printf("passed (%u/%d packets in %lgs)\n", info.got_packets, count, dur);
    return EXIT_SUCCESS;
  } else {
    printf("failed (%u/%d packets in %lgs)\n", info.got_packets, count, dur);
    return EXIT_FAILURE;
  }
}

