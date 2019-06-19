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
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>

#include <mcrx/libmcrx.h>
#include "./libmcrx-private.h"

/*
 * platform macros:
 * https://stackoverflow.com/questions/142508/how-do-i-check-os-with-a-preprocessor-directive
 * https://sourceforge.net/p/predef/wiki/OperatingSystems/
 */

static void wrap_strerr(int eno, char* buf, int len) {
#ifdef __linux__
  const char* ret = strerror_r(eno, buf, len);
  if (ret != buf) {
    strncpy(buf, ret, len);
  }
#elif defined(__APPLE__)
  int rc = strerror_r(eno, buf, len);
  if (rc != 0) {
    snprintf(buf, len, "strerror_r error on (%d)", eno);
    buf[len-1] = 0;
  }
#else
  // strerror_r is kind of a debacle, and wouldn't switch to
  // the XSI version with a -D_BSD_SOURCE as advertised:
  // http://man7.org/linux/man-pages/man3/strerror_r.3.html
  // http://man7.org/linux/man-pages/man7/feature_test_macros.7.html
  // --jake 2019-06-17
  UNUSED(eno);
  UNUSED(buf);
  UNUSED(len);
  suffering_and_woe;
#endif
}

/**
 * mcrx_ctx_receive_packets
 * @ctx: mcrx library context
 * @timeout_mx: timeout in milliseconds.
 *
 * receive_cb calls happen only from inside this function.  Provide
 * timeout_ms = -1 to timeout never, or timeout_ms=0 to return
 * immediately even if there were no packets.
 *
 * Returns: error code on problem, EAGAIN if timeout reached
 */
MCRX_EXPORT int mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx,
    int timeout_ms) {
  UNUSED(ctx);
  UNUSED(timeout_ms);
  usleep(10000000);
  return -ENOTSUP;
}

int mcrx_subscription_ntop(
    struct mcrx_subscription* sub,
    char* buf,
    int buflen) {
  int af;
  const void *src, *grp;
  char src_buf[INET6_ADDRSTRLEN];
  char grp_buf[INET6_ADDRSTRLEN];
  switch (sub->input.addr_type) {
    case MCRX_ADDR_TYPE_V4:
      af = AF_INET;
      src = &sub->input.addrs.v4.source;
      grp = &sub->input.addrs.v4.group;
      break;
    case MCRX_ADDR_TYPE_V6:
      af = AF_INET6;
      src = &sub->input.addrs.v6.source;
      grp = &sub->input.addrs.v6.group;
      break;
    default:
      errno = EINVAL;
      return -1;
  }
  const char* src_str = inet_ntop(af, src, src_buf, sizeof(src_buf));
  if (src_str == NULL) {
    return -1;
  }
  const char* grp_str = inet_ntop(af, grp, grp_buf, sizeof(grp_buf));
  if (grp_str == NULL) {
    return -1;
  }
  int wrotelen = snprintf(buf, buflen, "%s->%s(%u)",
      src_str, grp_str, sub->input.port);
  if (wrotelen >= buflen) {
    errno = ENOSPC;
    return -1;
  }
  return 0;
}

// int
// route_main(int argc, char **argv);

static int sockaddr_ntop(
    struct mcrx_ctx* ctx,
    const struct sockaddr* sa,
    char* sbuf,
    int buflen) {
  const void* addr;
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sp = (const struct sockaddr_in*)sa;
      addr = &sp->sin_addr;
      const char* ret = inet_ntop(sa->sa_family, addr, sbuf, buflen);
      if (ret == NULL) {
        char ebuf[1024];
        wrap_strerr(errno, ebuf, sizeof(ebuf));
        err(ctx, "failed inet_ntop: %s\n", ebuf);
        return -1;
      }
      return 0;
    }
    case AF_INET6: {
      const struct sockaddr_in6* sp = (const struct sockaddr_in6*)sa;
      addr = &sp->sin6_addr;
      const char* ret = inet_ntop(sa->sa_family, addr, sbuf, buflen);
      if (ret == NULL) {
        char ebuf[1024];
        wrap_strerr(errno, ebuf, sizeof(ebuf));
        err(ctx, "failed inet_ntop: %s\n", ebuf);
        return -1;
      }
      return 0;
    }
    default:
      dbg(ctx, "unknown address family %d (not %d or %d)\n",
          sa->sa_family, AF_INET, AF_INET6);
      errno = EINVAL;
      return -1;
  }
}

static int mcrx_find_interface(
    struct mcrx_subscription* sub,
    int* if_indexp,
    void* if_addr) {
  /*
   * It's unreasonably difficult to extract the correct interface
   * addr or interface index (one of which is needed, depending
   * on whether we're using IP_ADD_SOURCE_MEMBERSHIP or a different
   * api for joining.
   *
   * getsockopt(SIOCGIFINDEX) and SIOCGIFADDR on a udp socket
   * after connect are adequate for linux, but for mac those are
   * unavailable, so instead we getsockname and walk the ifaddrs
   * looking for a match.  Either way, we pick the interface that
   * would be used if opening a socket to the source, as a first
   * pass.
   *
   * really could use an api that gives me the list of viable
   * interface indexes and/or addresses...
   * -jake 2019-06-18
   */
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  // int x = SIOCGIFINDEX;
  // printf("%d\n", x);

#if 0
  // if (RTA_DST == 0) if getaddr(RTAX_DST), nrflags |= F_ISHOST
  // RTM_RESOLVE messages give "Invalid argument" errno on mac.
  // RTM_GET messages give "Invalid argument" errno on mac.
  *if_indexp = 3;
  inet_pton(AF_INET, "192.168.56.1", if_addr);

  int addr_len;
  struct {
    struct rt_msghdr rt_msg;
    struct sockaddr_storage dst_addr;
  } rt_msg_buf;
  memset(&rt_msg_buf, 0, sizeof(rt_msg_buf));
  void* dst_addrp = &rt_msg_buf.dst_addr;
  int family = AF_UNSPEC;
  switch (sub->input.addr_type) {
    case MCRX_ADDR_TYPE_V4:
      family = AF_INET;
      ((struct sockaddr_in*) dst_addrp)->sin_family = AF_INET;
      ((struct sockaddr_in*) dst_addrp)->sin_addr =
       sub->input.addrs.v4.source;
      addr_len = sizeof(struct sockaddr_in);
      break;
    case MCRX_ADDR_TYPE_V6:
      family = AF_INET6;
      ((struct sockaddr_in6*) dst_addrp)->sin6_family = AF_INET6;
      ((struct sockaddr_in6*) dst_addrp)->sin6_addr =
       sub->input.addrs.v6.source;
      addr_len = sizeof(struct sockaddr_in6);
      break;
    default:
      err(ctx, "sub %p internal error: unknown type\n", (void*)sub);
      return -EINVAL;
  }

  int nlfd = socket(AF_ROUTE, SOCK_RAW, family);
  if (nlfd < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p failed to open netlink socket: %s\n", (void*)sub, buf);
    return -EINVAL;
  }
  int seq = 1;
  int pid = getpid();
  struct rt_msghdr *rt_msg = &rt_msg_buf.rt_msg;
  rt_msg->rtm_msglen = sizeof(*rt_msg) + addr_len;
  rt_msg->rtm_version = RTM_VERSION;
  rt_msg->rtm_addrs = RTA_DST | RTA_IFP;
  rt_msg->rtm_flags = RTF_HOST | RTF_UP;
  rt_msg->rtm_type = RTM_GET;
  rt_msg->rtm_seq = seq;
  rt_msg->rtm_pid = pid;

  int rc;
  rc = write(nlfd, &rt_msg, rt_msg->rtm_msglen);
  if (rc != rt_msg->rtm_msglen) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p write=%d (not %d) for rt_msg to netlink socket: %s\n",
        (void*)sub, rc, rt_msg->rtm_msglen, buf);
    close(nlfd);
    return -EINVAL;
  }

  int msg_idx = 0;
  do {
    msg_idx += 1;
    rc = read(nlfd, &rt_msg_buf, sizeof(rt_msg_buf));
    if (rc < (int)sizeof(struct rt_msghdr)) {
      char buf[1024];
      wrap_strerr(errno, buf, sizeof(buf));
      err(ctx, "sub %p read=%d (header %d) for addr to netlink socket: %s\n",
          (void*)sub, rc, (int)sizeof(struct rt_msghdr), buf);
      close(nlfd);
      return -EINVAL;
    }
    if (rc < rt_msg->rtm_msglen) {
      char buf[1024];
      wrap_strerr(errno, buf, sizeof(buf));
      err(ctx, "sub %p read=%d (len %d) for addr to netlink socket: %s\n",
          (void*)sub, rc, (int)sizeof(struct rt_msghdr), buf);
      close(nlfd);
      return -EINVAL;
    }
    int skip = 0;
    if (rt_msg->rtm_type != RTM_GET) {
      info(ctx, "%d: skipping non-resolve\n", msg_idx);
      skip = 1;
    }
    if (rt_msg->rtm_seq != seq) {
      info(ctx, "%d: skipping seq\n", msg_idx);
      skip = 1;
    }
    if (rt_msg->rtm_pid != pid) {
      info(ctx, "%d: skipping pid\n", msg_idx);
      skip = 1;
    }
    if (!skip) {
      break;
    }
  } while (1);

  struct sockaddr* sa = (struct sockaddr*)dst_addrp;
  info(ctx, "family: %d (v4=%d, v6=%d)\n", sa->sa_family, AF_INET, AF_INET6);
#endif

#if 0
  // tried copying the freebsd /sbin/route/route.c and making it compile,
  // but it also failed with: "Address family not supported by protocol family"
  // in netlink write.
  const char* rargv[4] = {"blah", "get", "192.168.56.2", 0};
  int rargc = sizeof(rargv) / sizeof(rargv[0]) - 1;
  route_main(rargc, rargv);
#endif

  int family = AF_UNSPEC;
  struct sockaddr_storage ss;
  struct sockaddr* sp = (struct sockaddr*)&ss;
  void* addr_p;
  int sa_len = 0;
  int addr_offset = 0;
  int addr_len = 0;
  switch (sub->input.addr_type) {
    case MCRX_ADDR_TYPE_V4: {
      family = AF_INET;
      struct sockaddr_in* sp4 = (struct sockaddr_in*)sp;
      sp4->sin_family = AF_INET;
      sp4->sin_addr = sub->input.addrs.v4.source;
      sp4->sin_port = htons(5001);
      sa_len = sizeof(struct sockaddr_in);
      // ((struct sockaddr_in*)sp)->sin_len = sa_len;
      addr_p = &sp4->sin_addr;
      addr_offset = (((uint8_t*)addr_p)-((uint8_t*)sp));
      addr_len = sizeof(sp4->sin_addr);
      break;
    }
    case MCRX_ADDR_TYPE_V6: {
      family = AF_INET6;
      struct sockaddr_in6* sp6 = (struct sockaddr_in6*)sp;
      sp6->sin6_family = AF_INET6;
      sp6->sin6_addr = sub->input.addrs.v6.source;
      sp6->sin6_port = htons(5001);
      sa_len = sizeof(struct sockaddr_in6);
      // ((struct sockaddr_in6*)sp)->sin6_len = sa_len;
      addr_p = &sp6->sin6_addr;
      addr_offset = (((uint8_t*)addr_p)-((uint8_t*)sp));
      addr_len = sizeof(sp6->sin6_addr);
      break;
    }
    default:
      err(ctx, "sub %p internal error: unknown type\n", (void*)sub);
      return -EINVAL;
  }

  // extract the local interface by connecting a udp socket to the
  // source and checking its local address.
  int check_sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (check_sock <= 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p socket failed: %s\n",
        (void*)sub, buf);
    return -EINVAL;
  }

  int rc;
  rc = connect(check_sock, sp, sa_len);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p connect failed(%d): %s\n",
        (void*)sub, rc, buf);
    close(check_sock);
    return -EINVAL;
  }

  socklen_t got_len = sizeof(ss);
  rc = getsockname(check_sock, sp, &got_len);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p getsockname failed: %s\n",
        (void*)sub, buf);
    close(check_sock);
    return -EINVAL;
  }

  if (got_len != (socklen_t)sa_len) {
    err(ctx, "sub %p getsockname addrlen got %d not %d\n",
        (void*)sub, got_len, sa_len);
    close(check_sock);
    return -EINVAL;
  }
  close(check_sock);

  // now sp is the local address for a socket that could send to
  // the source, so use that to find the interface index (and for
  // ipv6, a link-local address, since the MLD packets MUST be from a
  // link-local address, failing this the message is silently ignored
  // by a linux next-hop, as required at the top of:
  // https://tools.ietf.org/html/rfc3810#section-5

  char addr_buf[INET6_ADDRSTRLEN];
  const char* loc_addr_str = inet_ntop(family, addr_p, addr_buf,
      sizeof(addr_buf));
  if (!loc_addr_str) {
    err(ctx, "sub %p inet_ntop failed\n",
        (void*)sub);
    return -EINVAL;
  }

  info(ctx, "got local sockaddr: %s\n", loc_addr_str);

  struct ifaddrs* all_addrs = 0;
  rc = getifaddrs(&all_addrs);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p getifaddrs failed: %s\n",
        (void*)sub, buf);
    return -EINVAL;
  }

  struct ifaddrs* cur_ifa;
  struct ifaddrs* match_ifa = NULL;
  for (cur_ifa = all_addrs; cur_ifa; cur_ifa = cur_ifa->ifa_next) {
    if (cur_ifa->ifa_addr) {
      if (cur_ifa->ifa_addr->sa_family == family) {
        void* check_addr = (void*)(((uint8_t*)cur_ifa->ifa_addr)+addr_offset);
        rc = memcmp(addr_p, check_addr, addr_len);
        if (rc == 0) {
          info(ctx, "found matching interface: %s(base)\n", cur_ifa->ifa_name);
          unsigned int idx = if_nametoindex(cur_ifa->ifa_name);
          if (idx == 0) {
            err(ctx, "failed if_nametoindex(%s)\n", cur_ifa->ifa_name);
          } else {
            if (match_ifa) {
              warn(ctx, "found alternate matching interface(%s replaces %s)\n",
                  match_ifa->ifa_name, cur_ifa->ifa_name);
            }
            match_ifa = cur_ifa;
            if (if_indexp) {
              *if_indexp = idx;
            }
          }
        }
      }
    }

    char ifa_buf[INET6_ADDRSTRLEN];
    const char* ifa_s = "null_addr";
    if (cur_ifa->ifa_addr) {
      rc = sockaddr_ntop(ctx, cur_ifa->ifa_addr, ifa_buf, sizeof(ifa_buf));
      ifa_s = &ifa_buf[0];
      if (rc != 0) {
        snprintf(ifa_buf, sizeof(ifa_buf),
            "failed_sockntop(af=%d, vs. %d/%d)\n",
            cur_ifa->ifa_addr->sa_family, AF_INET, AF_INET6);
      }
    }
    dbg(ctx, "   ifa %s: %s\n",
        cur_ifa->ifa_name, ifa_s);
  }
  int found = 0;
  if (match_ifa) {
    if (!if_addr) {
      found = 1;
    } else {
      switch (family) {
        case AF_INET: {
          void* check_addr =
            (void*)(((uint8_t*)match_ifa->ifa_addr)+addr_offset);
          memcpy(if_addr, check_addr, addr_len);
          found = 1;
          break;
        }
        case AF_INET6: {
          // V6 has to use a link-local address; find one on the same interface
          for (cur_ifa = all_addrs; cur_ifa; cur_ifa = cur_ifa->ifa_next) {
            if (strcmp(cur_ifa->ifa_name, match_ifa->ifa_name) != 0) {
              continue;
            }
            if (cur_ifa->ifa_addr && cur_ifa->ifa_addr->sa_family != family) {
              continue;
            }
            struct sockaddr_in6* sa6 =
              ((struct sockaddr_in6*)cur_ifa->ifa_addr);
            if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
              memcpy(if_addr, &sa6->sin6_addr, addr_len);
              found = 1;
              break;
            }
          }
          break;
        }
      }
    }
  }
  freeifaddrs(all_addrs);

  if (!found) {
    err(ctx, "failed to find suitable local address\n");
    return 1;
  } else {
    char addr_sbuf[INET6_ADDRSTRLEN];
    char sub_sbuf[MCRX_SUB_STRLEN];
    const char* addr_str = "(unrequested_addr)";
    int idx = -1;
    if (if_addr) {
      addr_str = inet_ntop(family, if_addr, addr_sbuf, sizeof(addr_sbuf));
      if (!addr_str) {
        err(ctx, "internal error sub %p: inet_ntop failed with found addr\n",
            (void*)sub);
      }
    }
    if (if_indexp) {
      idx = *if_indexp;
    }
    if (mcrx_subscription_ntop(sub, sub_sbuf, sizeof(sub_sbuf)) != 0) {
      err(ctx, "internal error sub %p: subscription_ntop failed\n",
          (void*)sub);
      strncpy(&sub_sbuf[0], "(failed sub_ntop)\n", sizeof(sub_sbuf));
    }
    info(ctx, "sub %p if_addr=%s, if_idx=%d for %s\n", (void*)sub, addr_str,
        idx, sub_sbuf);
  }

  return 0;
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
MCRX_EXPORT int mcrx_subscription_join(
    struct mcrx_subscription* sub,
    void (*receive_cb)(
      struct mcrx_packet* packet)) {
  struct mcrx_ctx* ctx = mcrx_subscription_get_ctx(sub);
  if (sub == NULL || ctx == NULL) {
    err(ctx, "NULL sub(%p) or ctx(%p)\n", (void*)sub, (void*)ctx);
    return -EINVAL;
  }

  char desc[MCRX_SUB_STRLEN];
  if (mcrx_subscription_ntop(sub, desc, sizeof(desc)) != 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p wrap_strerr failed: %s\n", (void*)sub, buf);
    return -EINVAL;
  }

  int family;
  if (sub->input.addr_type != MCRX_ADDR_TYPE_V4 &&
      sub->input.addr_type != MCRX_ADDR_TYPE_V6) {
      err(ctx, "sub %p (%s) address type not set\n", (void*)sub, desc);
      return -EINVAL;
  } else if (sub->input.addr_type == MCRX_ADDR_TYPE_V4) {
    family = AF_INET;
  } else {
    family = AF_INET6;
  }

  int rc;
  int sock_fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (sock_fd < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p (%s) socket failed: %s\n", (void*)sub, buf, desc);
    return -EBADF;
  }

  int val;
  int len;
  val = true;
  len = sizeof(val);
  rc = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &val, len);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p (%s) setsockopt(REUSEADDR) failed: %s\n", (void*)sub,
        desc, buf);
    close(sock_fd);
    return -EBADF;
  }

  /*
   * All the multicast join functions need to specify an interface
   * (most by index, some by address).
   */
  union {
    struct in6_addr i6;
    struct in_addr i4;
  } if_addr;
  void* if_addrp;
  int if_idx;
  switch (sub->input.addr_type) {
    case MCRX_ADDR_TYPE_V4:
      if_addrp = &if_addr.i4;
      break;
    case MCRX_ADDR_TYPE_V6:
      if_addrp = &if_addr.i4;
      break;
    default:
      err(ctx, "sub %p (%s) internal error: unknown type picking interface\n",
          (void*)sub, desc);
      close(sock_fd);
      return -EBADF;
  }

  rc = mcrx_find_interface(sub, &if_idx, if_addrp);
  if (rc != 0) {
    err(ctx, "sub %p (%s) could not find interface\n", (void*)sub, desc);
    close(sock_fd);
    return -EBADF;
  }

  /*
   * choices for group management:
   *
   * 1.
   * IP_ADD_MEMBERSHIP/IP_DROP_MEMBERSHIP
   * IP_ADD_SOURCE_MEMBERSHIP/IP_DROP_SOURCE_MEMBERSHIP
   * IPV6_ADD_MEMBERSHIP/IPV6_DROP_MEMBERSHIP
   * - incredibly, there's no IPV6_ADD_SOURCE_MEMBERSHIP in linux
   * - mac has no IPV6_ADD_anything
   *
   * 2.
   * MCAST_JOIN_GROUP/MCAST_LEAVE_GROUP
   * MCAST_JOIN_SOURCE_GROUP/MCAST_LEAVE_SOURCE_GROUP
   * - compiles, but not functional on mac
   *
   * 3.
   * MCAST_MSFILTER
   * - ok except for being needlessly complicated.  supports ipv4 and v6
   * - IP_MSFILTER is similar but IP4-only, where MCAST_MSFILTER is either
   * - mac has IP_MSFILTER but not MCAST_MSFILTER
   * - freebsd has IPV6_MSFILTER
   *
   * 4. setsourcefilter  (https://tools.ietf.org/html/rfc3678#section-5.2.1)
   * - there in mac, bsd, and linux? (in linux, not in kernel's netinet/in.h,
   *   but it's there in userspace, presumably using MCAST_MSFILTER underneath)
   * - however, everything I try on mac or linux always gives "Invalid argument".
   *   Not sure if the socket or the interface index or the filter or one of the
   *   sockbufs is the issue.  TBD: maybe debug this in-kernel to find out?
   *   --jake 2019-06-17
   */

  switch (sub->input.addr_type) {
    case MCRX_ADDR_TYPE_V4: {
      struct sockaddr_storage sinss_source = {0};
      struct sockaddr_in *sin4_source = (struct sockaddr_in*)&sinss_source;

      struct sockaddr_in sin4_group = {0};
      sin4_group.sin_port = htons(sub->input.port);
      sin4_group.sin_family = AF_INET;
      sin4_group.sin_addr = sub->input.addrs.v4.group;

      sin4_source->sin_family = AF_INET;
      sin4_source->sin_addr = sub->input.addrs.v4.source;
#if BSD
      sin4_group.sin_len = sizeof(struct sockaddr_in);
      sin4_source->sin_len = sizeof(struct sockaddr_in);
#endif

      rc = bind(sock_fd, (struct sockaddr*)(&sin4_group),
          sizeof(struct sockaddr_in));
      if (rc < 0) {
        char buf[1024];
        wrap_strerr(errno, buf, sizeof(buf));
        err(ctx, "sub %p (%s) bind failed: %s\n", (void*)sub, desc, buf);
        close(sock_fd);
        return -EBADF;
      }

#if 0
      rc = setsourcefilter(sock_fd, if_idx, (struct sockaddr*)&sin4_group,
          sizeof(struct sockaddr_in), MCAST_INCLUDE, 1, &sinss_source);
      if (rc < 0) {
        char buf[1024];
        wrap_strerr(errno, buf, sizeof(buf));
        err(ctx, "sub %p (%s) setsourcefilter failed: %s\n", (void*)sub,
            desc, buf);
        close(sock_fd);
        return -EBADF;
      }
#elif defined(__APPLE__)
      struct ip_mreq_source mreq;
      memset(&mreq, 0, sizeof(mreq));
      mreq.imr_multiaddr = sub->input.addrs.v4.group;
      mreq.imr_sourceaddr = sub->input.addrs.v4.source;
      mreq.imr_interface = *((struct in_addr*)if_addrp);
      rc = setsockopt(sock_fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
          &mreq, sizeof(mreq));
      if (rc < 0) {
        char buf[1024];
        wrap_strerr(errno, buf, sizeof(buf));
        err(ctx,
            "sub %p (%s) setsockopt(IP_ADD_SOURCE_MEMBERSHIP) failed: %s\n",
            (void*)sub,
            desc, buf);
        close(sock_fd);
        return -EBADF;
      }
#else
      woe_and_sorrow_joining_undefined;
#endif
      break;
    }
    case MCRX_ADDR_TYPE_V6: {
      struct sockaddr_storage sinss_source = {0};
      struct sockaddr_in6 *sin6_source = (struct sockaddr_in6*)&sinss_source;
      struct sockaddr_in6 sin6_group = {0};
      sin6_group.sin6_port = htons(sub->input.port);
      sin6_group.sin6_family = AF_INET6;
      sin6_group.sin6_addr = sub->input.addrs.v6.group;

      sin6_source->sin6_family = AF_INET6;
      sin6_source->sin6_addr = sub->input.addrs.v6.source;
#if BSD
      sin6_group.sin6_len = sizeof(struct sockaddr_in6);
      sin6_source->sin6_len = sizeof(struct sockaddr_in6);
#endif
      rc = bind(sock_fd, (struct sockaddr*)(&sin6_group),
          sizeof(struct sockaddr_in6));
      if (rc < 0) {
        char buf[1024];
        wrap_strerr(errno, buf, sizeof(buf));
        err(ctx, "sub %p (%s) bind failed: %s\n", (void*)sub, desc, buf);
        close(sock_fd);
        return -EBADF;
      }

      rc = setsourcefilter(sock_fd, if_idx, (struct sockaddr*)&sin6_group,
          sizeof(struct sockaddr_in6), MCAST_INCLUDE, 1, &sinss_source);
      if (rc < 0) {
        char buf[1024];
        wrap_strerr(errno, buf, sizeof(buf));
        err(ctx, "sub %p (%s) setsourcefilter failed: %s\n", (void*)sub,
            desc, buf);
        close(sock_fd);
        return -EBADF;
      }
      break;
    }
    default:
      err(ctx, "sub %p (%s) internal error, invalid addr_type\n", (void*)sub,
          desc);
      close(sock_fd);
      return -EINVAL;
  }
/*
  char bound_ifname[IFNAMSZ];
  socklen_t bound_ifname_len = sizeof(bound_ifname);
  rc = getsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, &bound_ifname[0],
      &bound_ifname_len);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p getsockopt(BINDTODEVICE) failed: %s\n", (void*)sub, buf);
    close(sock_fd);
    return -EBADF;
  }
  info(ctx, "sub %p socket bound to %s\n", bound_ifname);
  */

  val = fcntl(sock_fd, F_GETFL, 0);
  if (val < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p (%s) fcntl(F_GETFL) failed: %s\n", (void*)sub, desc, buf);
    close(sock_fd);
    return -EBADF;
  }

  rc = fcntl(sock_fd, F_SETFL, val | O_NONBLOCK);
  if (rc < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "sub %p (%s) fcntl(F_GETFL) failed: %s\n", (void*)sub, desc, buf);
    close(sock_fd);
    return -EBADF;
  }

  sub->receive_cb = receive_cb;

  return 0;
}

/**
 * mcrx_subscription_leave:
 * @sub: mcrx subscription handle
 *
 * Stop receiving and leave the subscription's (S,G).
 *
 * Returns: error code
 **/
MCRX_EXPORT int mcrx_subscription_leave(
    struct mcrx_subscription* sub) {
  UNUSED(sub);
  return -ENOTSUP;
}

/**
 * mcrx_subscription_config_ntop:
 * @config: a subscription config object
 * @source: a string with an IPv4 or IPv6 address
 * @group: a string with an IPv4 or IPv6 address
 *
 * Fill config addresses and addr_type, ensure the address families match.
 *
 * Returns: 0 on success, -1 on error.
 **/
MCRX_EXPORT int mcrx_subscription_config_pton(
    struct mcrx_subscription_config* config,
    const char* source,
    const char* group) {
  int ret;
  ret = inet_pton(AF_INET, source, &config->addrs.v4.source);
  if (ret > 0) {
    ret = inet_pton(AF_INET, group, &config->addrs.v4.group);
    if (ret > 0) {
      config->addr_type = MCRX_ADDR_TYPE_V4;
      return 0;
    }
  }

  ret = inet_pton(AF_INET6, source, &config->addrs.v6.source);
  if (ret > 0) {
    ret = inet_pton(AF_INET6, group, &config->addrs.v6.group);
    if (ret > 0) {
      config->addr_type = MCRX_ADDR_TYPE_V6;
      return 0;
    }
  }

  config->addr_type = MCRX_ADDR_TYPE_UNKNOWN;
  return -1;
}
