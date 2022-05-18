# Intro

libmcrx is a low-level library for receiving multicast UDP traffic.

[![Build](https://github.com/GrumpyOldTroll/libmcrx/actions/workflows/main.yml/badge.svg)](https://github.com/GrumpyOldTroll/libmcrx/actions/workflows/main.yml)
[![Clang Static Analysis](https://github.com/GrumpyOldTroll/libmcrx/actions/workflows/clang-analyzer.yml/badge.svg)](https://github.com/GrumpyOldTroll/libmcrx/actions/workflows/clang-analyzer.yml)

## Motivation

The code for receiving multicast traffic is different on different platforms, and has some quirks and complexities.
This library is intended to ease adoption of multicast-based protocols by simplifying the programming task of receiving multicast packets at the client side.
Its API uses C linkage in an attempt to maximize the portability for implementing simple wrappers in other languages.

The library also is intended to serve as an extension point to integrate with some standards and standard-tracked work in progress in the IETF, ideally including:

 - [AMBI](https://datatracker.ietf.org/doc/draft-ietf-mboned-ambi/): an asymmetric cryptographic authentication scheme for multicast traffic
   - this provides loss statistics as well as authenticated payloads
 - [CBACC](https://datatracker.ietf.org/doc/draft-ietf-mboned-cbacc/): bandwith limitation enforcement.
 - [AMT](https://www.rfc-editor.org/rfc/rfc7450.html): unicast tunneling
   - with [DRIAD](https://www.rfc-editor.org/rfc/rfc8777.html), a tunnel discovery mechanism that ensures use of native multicast is favored where possible

# Building

## Linux

### Prerequisites

For normal linux builds of the library, this project uses autoconf and automake, following the [libabc](http://0pointer.de/blog/projects/libabc.html) template.

#### APT-based (Debian, Ubuntu)

~~~
apt-get install \
  autoconf \
  libtool-bin \
  make \
  build-essential
~~~

#### MacOS with brew

Using [brew](https://brew.sh/):

~~~
brew install \
  autoconf \
  automake \
  make \
  libtool
~~~

TBD: more platforms

### Build

~~~
./autogen.sh
./configure
make
~~~

As usual with autotools, `./configure --help` provides a bunch of options, and more in-depth [explanations](https://www.gnu.org/prep/standards/html_node/Configuration.html#Configuration) give more [useful details](https://www.gnu.org/prep/standards/html_node/Directory-Variables.html).

For example, with something like `--prefix=${HOME}/local-install` a `make install` will not need sudo, and will put the library and header files under ${HOME}/local-install.

### Test

Note that to test this library, you'll need reachability to an active sender of multicast traffic.  See the [how-to](HOWTO.md) for some approaches.

NB: the current tests use a hardcoded (S,G), and probably should be changed to use a config file instead.  As-is you'll basically need to be using the multicast-ingest-platform or to be in a multicast-capable network that performs ingest using DRIAD for it to pass, assuming the sender it uses is running.

~~~
make check
~~~

### Install

Autoconf by default should build a configure and Makefiles that will put the headers and libraries into the default location for user libraries for the system.

~~~
sudo make install
~~~

# Using the library

This library is structured as a few types of objects in a hierarchy, wrapping as much socket-receiving complexity as we could arrange.

The relevant objects are:

 - **ctx**: a context.  All the function calls are associated with exactly one context (or with an object below that's associated with exactly one context).  Multiple contexts may exist, and objects associated with different contexts do not directly interact (they can be processed by separate threads without any synchronization between contexts, for example).
 - **sub**: a subscription.  Each subscription is associated immutably with an (S,G) or (\*,G) and a UDP port number.  A callback function is set for the subscription and provides received packets.
 - **pkt**: a packet.  Each packet provides the payload of a UDP packet received on the wire and associated with a particular subscription.

Each of these objects is created with a "_new" function, and is destroyed with a "_unref" function.  (An internal refcount may be increased with a "_ref" function, which will keep the object alive through one extra "_unref".)

Each object also can hold an arbitrary "user data" pointer, set and retrieved with a set_userdata and get_userdata function.  That pointer is opaque to the library, and provided as a convenience for the calling system.

Basic usage looks like this:

~~~c
#include <mcrx/libmcrx.h>

static int receive_cb(struct mcrx_packet* packet);

int receive_thread() {
  struct mcrx_ctx* ctx = NULL;
  mcrx_ctx_new(&ctx);

  struct mcrx_subscription_config conf = MCRX_SUBSCRIPTION_CONFIG_INIT;
  mcrx_subscription_config_pton(&conf, "23.212.185.4", "232.1.1.1");
  conf.port = 5001;

  struct mcrx_subscription *sub;
  mcrx_subscription_new(ctx, &conf, &sub);
  mcrx_subscription_set_receive_cb(sub, receive_cb);

  mcrx_subscription_join(sub);

  while (1) {
    mcrx_ctx_receive_packets(ctx);
  }
}

static int receive_cb(struct mcrx_packet* packet) {
  // do something with packet
  // operations like creating, joining, and leaving subscriptions are
  // safe here.
  mcrx_packet_unref(packet);
  return MCRX_RECEIVE_CONTINUE;
}
~~~

For a more detailed example including appropriate error handling, please see [mcrx-check](test/mcrx-check.c).

## Thread Safety

There is no thread safety handling inside the library.
It's the caller's responsibility to ensure that no calls to any functions using the same ctx or the objects generated from the same ctx (including packets and subscriptions) have function calls that overlap in time between different threads.

## Alternative Event Handlers

For an example integrating with an external event handler instead of using the blocking mcrx_ctx_receive_packets call, see the libmcrx integration with [python-asyncio-taps](https://github.com/fg-inet/python-asyncio-taps).

That project uses python's [asyncio](https://docs.python.org/3/library/asyncio.html) as the event handling library, and exports sockets to be added to the list of sockets to monitor for read readiness via mcrx_ctx_set_receive_socket_handlers, rather than using the blocking mcrx_ctx_receive_packets call.

In that scenario, the calling system is responsible for making a timely call to the do_receive function for all the sockets that have been given to the calling system with the add_socket_cb callback and that have not yet been removed with the remove_socket_cb callback.
