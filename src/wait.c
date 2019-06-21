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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <mcrx/libmcrx.h>
#include "./libmcrx-private.h"

#if MCRX_PRV_USE_KEVENT
#include <sys/event.h>

struct mcrx_fd_handle {
  int magic;
  struct mcrx_ctx* ctx;
  intptr_t handle;
  int fd;
  int (*handle_cb)(intptr_t handle, int fd);
};
#define MCRX_FD_HANDLE_MAGIC 0x74

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
    struct mcrx_ctx *ctx) {
  if (ctx->nevents == 0) {
    if (ctx->triggered != NULL) {
      free(ctx->triggered);
      ctx->triggered = NULL;
      ctx->ntriggered = 0;
      if (ctx->wait_fd) {
        close(ctx->wait_fd);
        ctx->wait_fd = 0;
      }
    } else {
      warn(ctx, "waiting again for packets with no listeners\n");
      if (ctx->timeout_ms > 0) {
        usleep(1000*ctx->timeout_ms);
      } else {
        // much friendlier to other threads when there's a bug...
        usleep(1000);
      }
    }
    return EAGAIN;
  }
  if (ctx->wait_fd == 0) {
    int fd = kqueue();
    if (fd <= 0) {
      char buf[1024];
      wrap_strerr(errno, buf, sizeof(buf));
      err(ctx, "failed kqueue: %s\n", buf);
      return errno;
    }
    ctx->wait_fd = fd;
  }
  if (ctx->nevents != ctx->ntriggered) {
    if (ctx->triggered == NULL) {
      ctx->triggered = (struct kevent*)calloc(ctx->nevents,
          sizeof(struct kevent));
      if (!ctx->triggered) {
        errno = ENOMEM;
        err(ctx, "failed to alloc %d events\n", ctx->nevents);
        return ENOMEM;
      }
      ctx->ntriggered = ctx->nevents;
    } else {
      struct kevent* new_triggers = (struct kevent*)realloc(ctx->triggered,
          sizeof(struct kevent)*ctx->nevents);
      if (!new_triggers) {
        warn(ctx, "failed to realloc %d events from %d\n", ctx->nevents,
            ctx->ntriggered);
      } else {
        ctx->ntriggered = ctx->nevents;
        ctx->triggered = new_triggers;
      }
    }
  }

  struct timespec tm;
  struct timespec* ptm;
  if (ctx->timeout_ms < 0) {
    ptm = NULL;
  } else {
    tm.tv_sec = ctx->timeout_ms / 1000;
    tm.tv_nsec = (ctx->timeout_ms % 1000) * 1000000;
    ptm = &tm;
  }
  int nevents = kevent(ctx->wait_fd, ctx->events, ctx->nevents,
      ctx->triggered, ctx->ntriggered, ptm);
  dbg(ctx, "%d events from %u changes, %u trigger space\n",
      nevents, ctx->nevents, ctx->ntriggered);

  if (nevents < 0) {
    char buf[1024];
    wrap_strerr(errno, buf, sizeof(buf));
    err(ctx, "failed kevent: %s\n", buf);
    return errno;
  }

  u_int idx;
  if (ctx->nadded != 0) {
    u_int tot_events = ctx->nevents;
    for (idx = 0; idx < tot_events; idx++) {
      struct kevent* evt = &ctx->events[idx];
      if (evt->flags & EV_ADD) {
        evt->flags = EV_ENABLE;
      }
    }
    ctx->nadded = 0;
  }

  if (nevents == 0) {
    info(ctx, "no events fired, timed out %d\n", ctx->timeout_ms);
    return ETIMEDOUT;
  }

  // keep ctx alive regardless of what happens during callbacks.
  mcrx_ctx_ref(ctx);
  for (idx = 0; idx < (u_int)nevents; ++idx) {
    struct kevent* evt = &ctx->triggered[idx];
    struct mcrx_fd_handle* handle = (struct mcrx_fd_handle*)evt->udata;
    if (!handle) {
      err(ctx, "event with no handle (%u)\n", (unsigned int)evt->ident);
      continue;
    }
    if (handle->magic != MCRX_FD_HANDLE_MAGIC) {
      err(ctx, "event with improper handle (%u)\n", (unsigned int)evt->ident);
      continue;
    }
    int fd = evt->ident;
    if (handle->fd != fd) {
      err(ctx, "event handle fd mismatch (%d != %d)\n", handle->fd, fd);
      continue;
    }
    if (handle->ctx != ctx) {
      err(ctx, "event handle ctx mismatch (%p != %p)\n", (void*)handle->ctx,
          (void*)ctx);
      continue;
    }
    dbg(ctx, "fired event, fd=%d, flags=%x, fflags=%x\n", fd, evt->flags,
        evt->fflags);
    handle->handle_cb(handle->handle, fd);
  }
  mcrx_ctx_unref(ctx);
  return 0;
}

int mcrx_prv_add_socket_cb(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*handle_cb)(intptr_t handle, int fd)) {
  u_int idx;
  struct kevent* evt;
  if (!ctx) {
    errno = EINVAL;
    err(ctx, "add_socket_cb with no ctx\n");
    return -1;
  }
  if (!handle_cb) {
    errno = EINVAL;
    err(ctx, "add_socket_cb with no callback\n");
    return -1;
  }
  if (fd <= 0) {
    errno = EINVAL;
    err(ctx, "add_socket_cb with bad fd (%d)\n", fd);
    return -1;
  }
  struct mcrx_fd_handle* new_cb = (struct mcrx_fd_handle*)calloc(1,
      sizeof(struct mcrx_fd_handle));
  if (new_cb == NULL) {
    errno = ENOMEM;
    err(ctx, "failed to alloc fd handle, oom\n");
    return -1;
  }
  new_cb->magic = MCRX_FD_HANDLE_MAGIC;
  new_cb->ctx = ctx;
  new_cb->fd = fd;
  new_cb->handle = handle;
  new_cb->handle_cb = handle_cb;

  for (idx = 0; idx < ctx->nevents; idx++) {
    evt = &ctx->events[idx];
    if (evt->filter == EVFILT_READ && evt->ident == (uintptr_t)fd) {
      struct mcrx_fd_handle *old_cb = (struct mcrx_fd_handle*)evt->udata;
      warn(ctx, "fd=%d  already in event list flags=%x->%x handle=%p->%p\n",
          fd, evt->flags, (EV_ADD|EV_ENABLE), (void*)old_cb->handle,
          (void*)new_cb->handle);
      evt->udata = new_cb;
      if (!(evt->flags & EV_ADD)) {
        ctx->nadded += 1;
      }
      evt->flags = EV_ADD | EV_ENABLE;
      free(old_cb);
      return 0;
    }
  }
  if (ctx->events == NULL) {
    info(ctx, "allocd read event for %d\n", fd);
    ctx->events = calloc(1, sizeof(struct kevent));
    if (!ctx->events) {
      err(ctx, "failed to alloc 1-entry event list, oom\n");
      errno = ENOMEM;
      free(new_cb);
      return -1;
    }
    dbg(ctx, "allocd 1-entry event list\n");
    evt = &ctx->events[0];
  } else {
    struct kevent* new_evt = (struct kevent*)realloc(ctx->events,
        (ctx->nevents+1)*sizeof(struct kevent));
    if (!new_evt) {
      err(ctx, "failed to realloc %u-entry event list, oom\n",
          ctx->nevents + 1);
      errno = ENOMEM;
      free(new_cb);
      return -1;
    }
    dbg(ctx, "reallocd %u-entry eventl list\n", ctx->nevents + 1);
    ctx->events = new_evt;
    evt = &ctx->events[ctx->nevents];
  }
  ctx->nevents += 1;
  ctx->nadded += 1;
  EV_SET(evt, fd, EVFILT_READ, EV_ADD, 0, 0, (void*)new_cb);
  return 0;
}

int mcrx_prv_remove_socket_cb(
    struct mcrx_ctx* ctx,
    int fd) {
  if (!ctx) {
    errno = EINVAL;
    err(ctx, "remove_socket_cb with no ctx\n");
    return -1;
  }
  if (fd <= 0) {
    errno = EINVAL;
    err(ctx, "remove_socket_cb with bad fd (%d)\n", fd);
    return -1;
  }

  u_int idx;
  for (idx = 0; idx < ctx->nevents; idx++) {
    struct kevent* evt;
    evt = &ctx->events[idx];
    if (evt->filter == EVFILT_READ && evt->ident == (uintptr_t)fd) {
      if (ctx->nevents < 1) {
        err(ctx, "internal error: nevents under 1 when removing a match\n");
        errno = EINVAL;
        return -1;
      }
      struct mcrx_fd_handle *old_cb = (struct mcrx_fd_handle*)evt->udata;
      if (!old_cb) {
        err(ctx, "internal error: no udata set on event for %d\n", fd);
        errno = EINVAL;
        return -1;
      }
      if (old_cb->ctx != ctx) {
        err(ctx, "internal error: wrong ctx on %d\n", fd);
      }
      if (old_cb->fd != fd) {
        err(ctx, "internal error: wrong ctx on %d\n", fd);
      }
      evt->udata = 0;
      if (evt->flags & EV_ADD) {
        if (ctx->nadded < 1) {
          err(ctx,
              "internal error: number added under 1 when removing an add %d\n",
              fd);
        } else {
          ctx->nadded -= 1;
        }
      }
      ctx->nevents -= 1;
      // as long as the fd is closed, which we do after this call, the
      // event is removed from the kernel list.
      if (ctx->nevents == 0) {
        free(ctx->events);
        ctx->events = 0;
        close(ctx->wait_fd);
        ctx->wait_fd = 0;
      } else {
        ctx->events = (struct kevent*)realloc(ctx->events,
            sizeof(struct kevent)*ctx->nevents);
      }

      free(old_cb);
      return 0;
    }
  }

  return 0;
}

#endif  // MCRX_PRV_USE_KEVENT

#if MCRX_PRV_USE_EPOLL
#include <sys/epoll.h>

MCRX_EXPORT int mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx) {
  if (ctx->wait_fd == 0) {
    int fd = epoll_create1(EPOLL_CLOEXEC);
    if (fd <= 0) {
      char buf[1024];
      wrap_strerr(errno, buf, sizeof(buf));
      err(ctx, "failed epoll_create1: %s\n", buf);
      return -1;
    }
    ctx->wait_fd = fd;
  }
  if (ctx->wait_sigmask) {
    //  epoll_pwait(ctx->wait_fd, ctx->
  } else {
    //  epoll_wait(ctx->wait_fd,
  }
}

int mcrx_prv_add_socket_cb(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*handle_cb)(intptr_t handle, int fd)) {
  if (ctx->wait_fd == 0) {
    return ENOTSUP;
  }

  return ENOTSUP;
}

int mcrx_prv_remove_socket_cb(
    struct mcrx_ctx* ctx,
    int fd) {
  if (ctx->wait_fd == 0) {
    return ENOTSUP;
  }

  return ENOTSUP;
}

#endif  // MCRX_PRV_USE_EPOLL
