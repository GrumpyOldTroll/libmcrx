#!/usr/bin/env python3

# libmcrx - multicast receiving library
# driad.py
#
# Copyright (C) 2019 by Akamai Technologies
#    Jake Holland <jakeholland.net@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import sys
import random
import ipaddress
import subprocess
import argparse

'''
Attempts lookup of an AMT relay that can forward multicast traffic
from <source_ip> via DRIAD (draft-ietf-mboned-driad-amt-discovery).
This does not perform the DNS-SD lookup to find a local relay, only
the remote lookup of a relay known to the source using DNS RRType
260.

requires 'dig' in path.

Outputs an IP address of an AMT relay, if successful.
'''

def main(args_in):
    parser = argparse.ArgumentParser(
            description='''
Use DNS RRType 260 to look up an AMT relay known to a multicast
sender, identified by the sending IP address of a (S,G).  See
draft-ietf-mboned-driad-amt-discovery for details.''')

    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('SourceIP', help='source ip of a multicast source')
    parser.add_argument('-r', '--resolver', help='use a specific DNS resolver')
    args = parser.parse_args(args_in[1:])
    source_ip_str = args.SourceIP
    source_ip = ipaddress.ip_address(source_ip_str)
    rev_ip_name = source_ip.reverse_pointer
    # note: on mac, this does not work without encoding the ip as ascii
    if args.resolver is None:
        initial_cmd = ['dig', '+short',  '-t',  'TYPE260', rev_ip_name.encode('ascii')]
    else:
        resolver = "@"+args.resolver
        initial_cmd = ['dig', '+short',  '-t',  'TYPE260', resolver, rev_ip_name.encode('ascii')]

    if args.verbose:
        print('running "%s"' % ' '.join([str(x) for x in initial_cmd]),
                file=sys.stderr)

    initial_dig_output = \
            subprocess.check_output(initial_cmd).decode('ascii').strip()

    prec = 256
    rand = 0
    loc = None
    typ = None
    npossibilities = 0
    for line in initial_dig_output.split('\n'):
        if args.verbose:
            print('parsing line: %s' % line, file=sys.stderr)
        if not line.startswith('\\#'):
            if args.verbose:
                print('  skipping (does not start \\#)...', file=sys.stderr)
            continue
        vals = line.rstrip().split(maxsplit=2)
        if len(vals) != 3:
            if args.verbose:
                print('  skipping (does not have \\# <len> <vals>)...',
                        file=sys.stderr)
            continue
        npossibilities += 1
        val = vals[2]
        cur_precedence = int(val[0:2],16)
        cur_typ = int(val[2:4],16)&0x7f
        if args.verbose:
            print('  parsed precedence=%d, type=%d' % (cur_precedence, cur_typ),
                    file=sys.stderr);

        if cur_precedence < prec or \
                (cur_precedence == prec and rand > random.random()):
            rand = random.random()
            loc = val[4:]
            prec = cur_precedence
            typ = cur_typ
            if args.verbose:
                print('  tentatively accepted val: %s' % loc,
                        file=sys.stderr);

    if not loc:
        print('no results from DRIAD lookup: "%s"' %
                ' '.join([str(x) for x in initial_cmd]), file=sys.stderr)
        return -1

    if typ == 1:
        ans = '%d.%d.%d.%d' % (
                int(loc[0:2],16),
                int(loc[2:4],16),
                int(loc[4:6],16),
                int(loc[6:8],16))
    elif typ == 2:
        ans = ipaddress.ip_address(':'.join(
            [loc[i:i+4] for i in range(0,32,4)])).compressed
    elif typ == 3:
        ix = 0
        names = []
        while ix < len(loc):
            ln = int(loc[ix:ix+2],16)
            if ln == 0:
                break
            #print('ln:%d' % ln)
            ix += 2
            name=''.join([chr(int(loc[jx:jx+2],16))
                for jx in range(ix, ix+2*ln, 2)])
            #print('name:%s' % name)
            names.append(name)
            ix += 2*ln
        dn = '.'.join(names)
        if args.resolver is None:
            secondary_dig_cmd = ['dig', '+short', dn.encode('ascii')]
        else:
            resolver = "@"+args.resolver
            secondary_dig_cmd = ['dig', '+short', resolver, dn.encode('ascii')]
        if args.verbose:
            print('running "%s"' % ' '.join([str(x) for x in secondary_dig_cmd]),
                file=sys.stderr)
        out  = subprocess.check_output(secondary_dig_cmd).decode('ascii').strip()
        if not out:
            print('dig +short %s failed: %s' % (dn,out), file=sys.stderr)
            return -1
        ans = out
    else:
        print('failed TYPE260 parse:%s' % (loc), file=sys.stderr)
        return -1

    print(ans)
    return 0

if __name__=="__main__":
    ret = main(sys.argv)
    exit(ret)
