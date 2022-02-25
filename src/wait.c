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
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>

#include <mcrx/libmcrx.h>
#include "./libmcrx-private.h"

struct mcrx_fd_handle {
  int magic;
  struct mcrx_ctx* ctx;
  intptr_t handle;
  int fd;
  int (*handle_cb)(intptr_t handle, int fd);
};
#define MCRX_FD_HANDLE_MAGIC 0x74

#if MCRX_PRV_USE_KEVENT
#include <sys/event.h>

// I isolated the handling of various system calls in case I
// need to refine the error handling better.  At this point,
// the only goal is to have enough breadcrumbs to debug it if
// these errors get hit, but it's possible more refined error
// reporting would become worthwhile.
static enum mcrx_error_code handle_kevent_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "kevent error: %s\n", buf);
  return MCRX_ERR_SYSCALL_KEVENT;
}
#define handle_kevent_error(ctx) handle_kevent_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

static enum mcrx_error_code handle_kqueue_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "kqueue error: %s\n", buf);
  return MCRX_ERR_SYSCALL_KQUEUE;
}
#define handle_kqueue_error(ctx) handle_kqueue_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

/**
 * mcrx_ctx_receive_packets
 * @ctx: mcrx library context
 * @timeout_mx: timeout in milliseconds.
 *
 * receive_cb calls happen only from inside this function.  Provide
 * timeout_ms = -1 to timeout never, or timeout_ms=0 to return
 * immediately even if there were no packets.
 *
 * Applications that use this function cannot use
 * mcrx_ctx_set_receive_socket_handlers.
 *
 * Returns: error code on problem, EAGAIN if timeout reached
 */
MCRX_EXPORT enum mcrx_error_code mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx) {
  if (ctx->nevents == 0) {
    if (ctx->triggered != NULL) {
      free(ctx->triggered);
      ctx->triggered = NULL;
      ctx->ntriggered = 0;
      if (ctx->wait_fd != -1) {
        if (close(ctx->wait_fd)) {
          handle_close_error(ctx);
        }
        ctx->wait_fd = -1;
      }
      return MCRX_ERR_NOTHING_JOINED;
    } else {
      warn(ctx, "waiting again for packets with no listeners\n");
      if (ctx->timeout_ms > 0) {
        usleep(1000*ctx->timeout_ms);
      } else {
        // much friendlier to other threads when there's a bug...
        usleep(1000);
      }
    }
    return MCRX_ERR_NOTHING_JOINED;
  }
  if (ctx->wait_fd == -1) {
    int fd = kqueue();
    if (fd < 0) {
      return handle_kqueue_error(ctx);
    }
    dbg(ctx, "created kqueue fd=%d\n", fd);
    ctx->wait_fd = fd;
  }
  if (ctx->nevents != ctx->ntriggered) {
    if (ctx->triggered == NULL) {
      ctx->triggered = (struct kevent*)calloc(ctx->nevents,
          sizeof(struct kevent));
      if (!ctx->triggered) {
        err(ctx, "failed to alloc %d events\n", ctx->nevents);
        return MCRX_ERR_NOMEM;
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
  dbg(ctx, "waiting, trigger space=%u event space=%u\n",
      ctx->ntriggered, ctx->nevents);
  int nevents = kevent(ctx->wait_fd, ctx->events, ctx->nevents,
      ctx->triggered, ctx->ntriggered, ptm);
  dbg(ctx, "%d events from %u changes, %u trigger space\n",
      nevents, ctx->nevents, ctx->ntriggered);

  if (nevents < 0) {
    if (errno == EINTR) {
      // treat interrupts like a timeout (and don't report error)
      return MCRX_ERR_TIMEDOUT;
    }

    err(ctx, "ctx %p failed kevent(%d)\n", (void*)ctx, ctx->wait_fd);
    return handle_kevent_error(ctx);
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
    dbg(ctx, "no events fired--timed out? %d\n", ctx->timeout_ms);
    return MCRX_ERR_TIMEDOUT;
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
    int rc = handle->handle_cb(handle->handle, fd);
    if (rc != MCRX_RECEIVE_CONTINUE) {
      if (rc == MCRX_RECEIVE_STOP_CTX) {
        break;
      }
    }
  }
  mcrx_ctx_unref(ctx);
  return MCRX_ERR_OK;
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
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (!handle_cb) {
    errno = EINVAL;
    err(ctx, "add_socket_cb with no callback\n");
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (fd < 0) {
    errno = EINVAL;
    err(ctx, "add_socket_cb with bad fd (%d)\n", fd);
    return MCRX_ERR_INTERNAL_ERROR;
  }
  struct mcrx_fd_handle* new_cb = (struct mcrx_fd_handle*)calloc(1,
      sizeof(struct mcrx_fd_handle));
  if (new_cb == NULL) {
    errno = ENOMEM;
    err(ctx, "failed to alloc fd handle, oom\n");
    return MCRX_ERR_NOMEM;
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
      return MCRX_ERR_OK;
    }
  }
  if (ctx->events == NULL) {
    info(ctx, "allocd read event for %d\n", fd);
    ctx->events = calloc(1, sizeof(struct kevent));
    if (!ctx->events) {
      err(ctx, "failed to alloc 1-entry event list, oom\n");
      errno = ENOMEM;
      free(new_cb);
      return MCRX_ERR_NOMEM;
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
      return MCRX_ERR_NOMEM;
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
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (fd < 0) {
    errno = EINVAL;
    err(ctx, "remove_socket_cb with bad fd (%d)\n", fd);
    return MCRX_ERR_INTERNAL_ERROR;
  }

  u_int idx;
  for (idx = 0; idx < ctx->nevents; idx++) {
    struct kevent* evt;
    evt = &ctx->events[idx];
    if (evt->filter == EVFILT_READ && evt->ident == (uintptr_t)fd) {
      struct mcrx_fd_handle *old_cb = (struct mcrx_fd_handle*)evt->udata;
      if (!old_cb) {
        err(ctx, "internal error: no udata set on event for %d\n", fd);
        errno = EINVAL;
        return MCRX_ERR_INTERNAL_ERROR;
      }
      if (old_cb->ctx != ctx) {
        err(ctx, "ctx %p internal error: wrong ctx(%p) on %d\n", (void*)ctx,
            (void*)old_cb->ctx, fd);
      }
      if (old_cb->fd != fd) {
        err(ctx, "internal error: wrong fd (%d) on %d\n", fd, old_cb->fd);
      }
      dbg(ctx, "removing fd %d from wait events\n", fd);
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
        if (close(ctx->wait_fd)) {
          handle_close_error(ctx);
        }
        ctx->wait_fd = -1;
      } else {
        ctx->events = (struct kevent*)realloc(ctx->events,
            sizeof(struct kevent)*ctx->nevents);
      }

      free(old_cb);
      return 0;
    }
  }

  err(ctx, "internal error: did not find fd to remove\n");
  errno = EBADF;
  return MCRX_ERR_INTERNAL_ERROR;
}

#endif  // MCRX_PRV_USE_KEVENT

#if MCRX_PRV_USE_EPOLL
#include <sys/epoll.h>

// I isolated the handling of various system calls in case I
// need to refine the error handling better.  At this point,
// the only goal is to have enough breadcrumbs to debug it if
// these errors get hit, but it's possible more refined error
// reporting would become worthwhile.
static enum mcrx_error_code handle_epollcreate_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "epoll_create1 error: %s\n", buf);
  return MCRX_ERR_SYSCALL_EPOLLCREATE;
}
#define handle_epollcreate_error(ctx) handle_epollcreate_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

static enum mcrx_error_code handle_epolladd_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "epoll_ctl(ADD) error: %s\n", buf);
  return MCRX_ERR_SYSCALL_EPOLLADD;
}
#define handle_epolladd_error(ctx) handle_epolladd_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

static enum mcrx_error_code handle_epolldel_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "epoll_ctl(DEL) error: %s\n", buf);
  return MCRX_ERR_SYSCALL_EPOLLDEL;
}
#define handle_epolldel_error(ctx) handle_epolldel_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

static enum mcrx_error_code handle_epollwait_error_impl(
    struct mcrx_ctx* ctx,
    const char* file,
    int line,
    const char* func) {
  char buf[1024];
  wrap_strerr(errno, buf, sizeof(buf));
  err_passthru(ctx, file, line, func,
      "epoll_wait() error: %s\n", buf);
  return MCRX_ERR_SYSCALL_EPOLLWAIT;
}
#define handle_epollwait_error(ctx) handle_epollwait_error_impl(\
    (ctx), __FILE__, __LINE__, __func__)

MCRX_EXPORT enum mcrx_error_code mcrx_ctx_receive_packets(
    struct mcrx_ctx *ctx) {
  if (ctx->nevents == 0) {
    if (ctx->triggered != NULL) {
      free(ctx->triggered);
      ctx->triggered = NULL;
      ctx->ntriggered = 0;
      if (ctx->wait_fd != -1) {
        if (close(ctx->wait_fd)) {
          handle_close_error(ctx);
        }
        ctx->wait_fd = -1;
      }
      return MCRX_ERR_NOTHING_JOINED;
    } else {
      warn(ctx, "waiting again for packets with no listeners\n");
      if (ctx->timeout_ms > 0) {
        usleep(1000*ctx->timeout_ms);
      } else {
        // if caller improperly spins on this call, it's much friendlier
        // to other threads to inject a 1ms sleep. --jake 2019-06-28
        usleep(1000);
      }
    }
    return MCRX_ERR_NOTHING_JOINED;
  }
  if (ctx->wait_fd == -1) {
    err(ctx, "no wait_fd ctx %p on entry to receive_packets\n", (void*)ctx);
    // shouldn't ever get here.  should make this fatal, or keep going?
    // --jake 2019-06-21
    int fd = epoll_create1(EPOLL_CLOEXEC);
    if (fd < 0) {
      return handle_epollcreate_error(ctx);
    }
    u_int idx;
    for (idx = 0; idx < ctx->nevents; idx++) {
      struct epoll_event* evt = &ctx->events[idx];
      struct mcrx_fd_handle* cur_cb = (struct mcrx_fd_handle*)evt->data.ptr;
      int rc = epoll_ctl(ctx->wait_fd, EPOLL_CTL_ADD, cur_cb->fd, evt);
      if (rc < 0) {
        enum mcrx_error_code ret = handle_epolladd_error(ctx);
        int prev_errno = errno;
        if (close(fd)) {
          handle_close_error(ctx);
        }
        errno = prev_errno;
        return ret;
      }
    }
    ctx->wait_fd = fd;
  }
  if (ctx->nevents != ctx->ntriggered) {
    if (ctx->triggered == NULL) {
      ctx->triggered = (struct epoll_event*)calloc(ctx->nevents,
          sizeof(struct epoll_event));
      if (!ctx->triggered) {
        err(ctx, "failed to alloc %d events\n", ctx->nevents);
        return MCRX_ERR_NOMEM;
      }
      ctx->ntriggered = ctx->nevents;
    } else {
      struct epoll_event* new_triggers = (struct epoll_event*)
        realloc(ctx->triggered, sizeof(struct epoll_event)*ctx->nevents);
      if (!new_triggers) {
        warn(ctx, "failed to realloc %d events from %d\n", ctx->nevents,
            ctx->ntriggered);
      } else {
        ctx->ntriggered = ctx->nevents;
        ctx->triggered = new_triggers;
      }
    }
  }

  int nevents = epoll_wait(ctx->wait_fd, ctx->triggered, ctx->ntriggered,
      ctx->timeout_ms);
  dbg(ctx, "%d events from %u changes, %u trigger space\n",
      nevents, ctx->nevents, ctx->ntriggered);

  if (nevents < 0) {
    if (errno == EINTR) {
      // treat interrupts like a timeout (and don't report error)
      return MCRX_ERR_TIMEDOUT;
    }
    return handle_epollwait_error(ctx);
  }

  if (nevents == 0) {
    dbg(ctx, "no events fired--timed out, hopefully %d\n", ctx->timeout_ms);
    return MCRX_ERR_TIMEDOUT;
  }

  // keep ctx alive regardless of what happens during callbacks.
  mcrx_ctx_ref(ctx);
  u_int idx;
  for (idx = 0; idx < (u_int)nevents; ++idx) {
    struct epoll_event* evt = &ctx->triggered[idx];
    struct mcrx_fd_handle* handle = (struct mcrx_fd_handle*)evt->data.ptr;
    if (!handle) {
      err(ctx, "event with no handle (%u)\n", (unsigned int)idx);
      continue;
    }
    if (handle->magic != MCRX_FD_HANDLE_MAGIC) {
      err(ctx, "event with improper handle (%u)\n", (unsigned int)idx);
      continue;
    }
    if (handle->ctx != ctx) {
      err(ctx, "event handle ctx mismatch (%p != %p)\n", (void*)handle->ctx,
          (void*)ctx);
      continue;
    }
    dbg(ctx, "receive_cb handle=%"PRIxPTR"x fd=%d cb=%p\n",
        handle->handle, handle->fd, (void*)handle);
    int rc = handle->handle_cb(handle->handle, handle->fd);
    if (rc != MCRX_RECEIVE_CONTINUE) {
      if (rc == MCRX_RECEIVE_STOP_CTX) {
        break;
      }
    }
  }
  mcrx_ctx_unref(ctx);

  return MCRX_ERR_OK;
}

int mcrx_prv_add_socket_cb(
    struct mcrx_ctx* ctx,
    intptr_t handle,
    int fd,
    int (*handle_cb)(intptr_t handle, int fd)) {
  if (!ctx) {
    err(ctx, "add_socket_cb with no ctx\n");
    errno = EINVAL;
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (!handle_cb) {
    err(ctx, "add_socket_cb with no callback\n");
    errno = EINVAL;
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (fd < 0) {
    err(ctx, "add_socket_cb with bad fd (%d)\n", fd);
    errno = EINVAL;
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (ctx->wait_fd == -1) {
    int wait_fd = epoll_create1(EPOLL_CLOEXEC);
    if (wait_fd < 0) {
      handle_epollcreate_error(ctx);
      errno = EINVAL;
      return MCRX_ERR_INTERNAL_ERROR;
    }
    ctx->wait_fd = wait_fd;
  }

  struct mcrx_fd_handle* new_cb = (struct mcrx_fd_handle*)calloc(1,
      sizeof(struct mcrx_fd_handle));
  if (new_cb == NULL) {
    errno = ENOMEM;
    err(ctx, "failed to alloc fd handle, oom\n");
    return MCRX_ERR_NOMEM;
  }
  new_cb->magic = MCRX_FD_HANDLE_MAGIC;
  new_cb->ctx = ctx;
  new_cb->fd = fd;
  new_cb->handle = handle;
  new_cb->handle_cb = handle_cb;
  dbg(ctx, "add_socket_cb handle=%"PRIxPTR"x fd=%d cb=%p\n",
      handle, fd, (void*)new_cb);

  if (ctx->events == NULL) {
    if (ctx->nevents != 0) {
      warn(ctx, "internal error: inconsistent nevents=%d with null events (fixed to 0)\n", ctx->nevents);
      ctx->nevents=0;
    }
    ctx->events = (struct epoll_event*)calloc(1,
        sizeof(struct epoll_event));
    if (!ctx->events) {
      errno = ENOMEM;
      err(ctx, "failed to alloc space for new fd handle, oom\n");
      free(new_cb);
      return MCRX_ERR_NOMEM;
    }
  } else {
    struct epoll_event *new_holders = (struct epoll_event*)realloc(
        ctx->events, sizeof(struct epoll_event)*(ctx->nevents+1));
    if (!new_holders) {
      errno = ENOMEM;
      err(ctx, "failed to realloc space for new fd handle, oom\n");
      free(new_cb);
      return MCRX_ERR_NOMEM;
    }
    ctx->events = new_holders;
  }
  memset(&ctx->events[ctx->nevents], 0, sizeof(struct epoll_event));
  ctx->events[ctx->nevents].data.ptr = new_cb;
  ctx->events[ctx->nevents].events = EPOLLIN;

  int rc = epoll_ctl(ctx->wait_fd, EPOLL_CTL_ADD, fd,
      &ctx->events[ctx->nevents]);
  if (rc < 0) {
    enum mcrx_error_code ret = handle_epolladd_error(ctx);
    free(new_cb);
    return ret;
  }
  ctx->nevents += 1;

  return 0;
}

int mcrx_prv_remove_socket_cb(
    struct mcrx_ctx* ctx,
    int fd) {
  if (!ctx) {
    errno = EINVAL;
    err(ctx, "remove_socket_cb with no ctx\n");
    return MCRX_ERR_INTERNAL_ERROR;
  }
  if (fd < 0) {
    errno = EINVAL;
    err(ctx, "remove_socket_cb with bad fd (%d)\n", fd);
    return MCRX_ERR_INTERNAL_ERROR;
  }

  u_int idx;
  for (idx = 0; idx < ctx->nevents; idx++) {
    struct epoll_event* evt;
    evt = &ctx->events[idx];
    struct mcrx_fd_handle* cur_cb = (struct mcrx_fd_handle*)evt->data.ptr;
    if (cur_cb->fd != fd) {
      continue;
    }
    if (cur_cb->ctx != ctx) {
      err(ctx, "internal error: wrong ctx on %d\n", fd);
    }
    dbg(ctx, "remove_socket_cb handle=%"PRIxPTR"x fd=%d cb=%p\n",
        cur_cb->handle, fd, (void*)cur_cb);
    ctx->nevents -= 1;
    if (ctx->wait_fd != -1) {
      int rc = epoll_ctl(ctx->wait_fd, EPOLL_CTL_DEL, fd, evt);
      if (rc < 0) {
        handle_epolldel_error(ctx);
      }
    }
    if (idx < ctx->nevents) {
      memmove(&ctx->events[idx], &ctx->events[idx+1],
          (ctx->nevents-idx)*sizeof(struct epoll_event));
    }
    if (ctx->nevents == 0) {
      free(ctx->events);
      ctx->events = 0;
      if (close(ctx->wait_fd)) {
        handle_close_error(ctx);
      }
      ctx->wait_fd = -1;
    } else {
      ctx->events = (struct epoll_event*)realloc(ctx->events,
          sizeof(struct epoll_event)*ctx->nevents);
    }

    free(cur_cb);
    return 0;
  }

  err(ctx, "internal error: did not find fd to remove\n");
  errno = EBADF;
  return MCRX_ERR_INTERNAL_ERROR;
}

#endif  // MCRX_PRV_USE_EPOLL
