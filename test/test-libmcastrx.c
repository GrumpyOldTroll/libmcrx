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

int
main(int argc, char *argv[])
{
     struct mcastrx_ctx *ctx;
     struct mcastrx_thing *thing = NULL;
     int err;

     err = mcastrx_new(&ctx);
     if (err < 0) {
          return EXIT_FAILURE;
     }

     printf("version %s\n", VERSION);

     err = mcastrx_thing_new_from_string(ctx, "foo", &thing);
     if (err >= 0) {
          mcastrx_thing_unref(thing);
     }

     mcastrx_unref(ctx);
     return EXIT_SUCCESS;
}
