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

#ifndef GUARD_LIBMCRX_ERRORS_H
#define GUARD_LIBMCRX_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

enum mcrx_error_code {
  MCRX_ERR_OK = 0,
  MCRX_ERR_TIMEDOUT,  // only from receive_packets, if timeout hit.
  MCRX_ERR_NOMEM,
  MCRX_ERR_NULLARG,
  MCRX_ERR_NOSPACE,
  MCRX_ERR_UNKNOWN_FAMILY,
  MCRX_ERR_UNSUPPORTED,
  MCRX_ERR_ALREADY_JOINED,
  MCRX_ERR_ALREADY_NOTJOINED,
  MCRX_ERR_INTERNAL_ERROR,
  MCRX_ERR_CALLBACK_FAILED,
  MCRX_ERR_NOTHING_JOINED,
  MCRX_ERR_INCONSISTENT_HANDLER,
  MNAT_ENTRY_NOT_FOUND,

  // errors from system calls within the library.  errno
  // remains as set by the underlying system.
  // for stability under change, these come from a different space.
  MCRX_ERR_SYSCALL_BIND = 9001,
  MCRX_ERR_SYSCALL_CLOSE,
  MCRX_ERR_SYSCALL_CONNECT,
  MCRX_ERR_SYSCALL_FCNTL,
  MCRX_ERR_SYSCALL_GETSOCKNAME,
  MCRX_ERR_SYSCALL_GETIFADDRS,
  MCRX_ERR_SYSCALL_NTOP,
  MCRX_ERR_SYSCALL_RECVMSG,
  MCRX_ERR_SYSCALL_SOCKET,
  MCRX_ERR_SYSCALL_SETSOCKOPT,
  MCRX_ERR_SYSCALL_SETSOURCEFILTER,
  MCRX_ERR_SYSCALL_EPOLLCREATE,
  MCRX_ERR_SYSCALL_EPOLLADD,
  MCRX_ERR_SYSCALL_EPOLLDEL,
  MCRX_ERR_SYSCALL_EPOLLWAIT,
  MCRX_ERR_SYSCALL_KEVENT,
  MCRX_ERR_SYSCALL_KQUEUE,
};

// this will give error information about the error code above
// if mcrx_is_system_error(err) is true, there may be additional
// information available by calling strerror(errno)
const char* mcrx_strerror(enum mcrx_error_code err);

// this is zero when no errno can be expected, or 1 when errno
// can be used to strerror(errno) to see the underlying system
// problem encountered.
int mcrx_is_system_error(enum mcrx_error_code err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // GUARD_LIBMCRX_ERRORS_H
