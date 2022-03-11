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
import re
from itertools import groupby

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
RFC 8777 for details.''')

    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('SourceIP', help='source ip of a multicast sender')
    parser.add_argument('-r', '--resolver', help='use a specific DNS resolver')
    parser.add_argument('-a', '--all', action='store_true', default=False, help='show all addresses (ordered by precedence/random when equal, "#" prefixed for less-preferred)')
    parser.add_argument('-f', '--family', choices=('any', '4', '6'), default='4', help='address family to accept (default=4 for ossified usage compatibility, sorry)')

    args = parser.parse_args(args_in[1:])
    no4, no6 = False, False
    if args.family == '4':
        no6 = True
    elif args.family == '6':
        no4 = True

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

    amt_line_re = re.compile(r'^\s*(?:\\#\s+(?P<generic_len>[0-9]+)\s+(?P<generic_data>(?:[0-9a-fA-F]|\s)+)|(?P<precedence>[0-9]+)\s+(?P<dbit>0|1)\s+(?P<type>[0-3])\s+(?P<relay>\S+)\s*)$')

    possibilities = []
    for line in initial_dig_output.split('\n'):
        if args.verbose:
            print('parsing line: %s' % line, file=sys.stderr)
        m = amt_line_re.match(line)
        if not m:
            if args.verbose:
                print(f'  skipping line "{line}" (does not match AMTRELAY)...', file=sys.stderr)
            continue
        prec_str = m.group('precedence')
        if prec_str:
            cur_precedence = int(prec_str)
        else:
            val = m.group('generic_data')
            if val:
                cur_precedence = int(val[0:2],16)
            else:
                if args.verbose:
                    print(f'  internal error: matched regex without precedence, skipping', file=sys.stderr)
                continue
        possibilities.append((cur_precedence, m))

    prec_group = ''
    found = 0
    possibilities.sort()
    for prec, equal_group in groupby(possibilities, lambda x: x[0]):
        equal_list = list(equal_group)
        if len(equal_list) > 1:
            random.shuffle(equal_list)

        group_found = 0
        for prec, m in equal_list:
            typ_str, relay = m.group('type'), m.group('relay')
            if typ_str:
                typ = int(typ_str)
            else:
                val = m.group('generic_data')
                typ = int(val[2:4],16)&0x7f
                loc = val[4:]

                if typ == 1:
                    relay = '%d.%d.%d.%d' % (
                            int(loc[0:2],16),
                            int(loc[2:4],16),
                            int(loc[4:6],16),
                            int(loc[6:8],16))
                    if no4:
                        if args.verbose:
                            print('  excluding %s from family=6' % relay, file=sys.stderr)
                        continue
                elif typ == 2:
                    relay = ipaddress.ip_address(':'.join(
                        [loc[i:i+4] for i in range(0,32,4)])).compressed
                    if no6:
                        if args.verbose:
                            print('  excluding %s from family=4' % relay, file=sys.stderr)
                        continue
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
                    relay = '.'.join(names)

                else:
                    print('failed TYPE260 generic parse:%s' % (val), file=sys.stderr)
                    continue

            if typ == 3:
                if args.resolver is None:
                    secondary_dig_cmd = ['dig', '+short', relay.encode('ascii'), 'AAAA', relay.encode('ascii'), 'A']
                else:
                    resolver = "@"+args.resolver
                    secondary_dig_cmd = ['dig', '+short', resolver, relay.encode('ascii'), 'AAAA', relay.encode('ascii'), 'A']
                if args.verbose:
                    print('  running "%s"' % ' '.join([str(x) for x in secondary_dig_cmd]),
                        file=sys.stderr)
                out  = subprocess.check_output(secondary_dig_cmd).decode('ascii').strip()
                if not out:
                    print('  rejecting: %s failed: %s' % (' '.join([str(x) for x in secondary_dig_cmd]), out), file=sys.stderr)
                    continue
                addrs = []
                for line in out.split('\n'):
                    try:
                        addr = ipaddress.ip_address(line.strip())
                    except:
                        continue
                    if no4 and addr.version == 4:
                        if args.verbose:
                            print('  excluding %s via %s from family=6' % (addr, relay), file=sys.stderr)
                        continue
                    elif no6 and addr.version == 6:
                        if args.verbose:
                            print('  excluding %s via %s from family=4' % (addr, relay), file=sys.stderr)
                        continue
                    addrs.append(line.strip())
                if len(addrs) == 0:
                    if args.verbose:
                        print('  rejecting: %s no usable addresses found in output: %s' % (' '.join([str(x) for x in secondary_dig_cmd]), out), file=sys.stderr)
                    continue

                if len(addrs) > 1:
                    random.shuffle(addrs)
                for relay in addrs:
                    print(prec_group + str(relay))
                    if not args.all:
                        return 0
                    found += 1
                    group_found += 1
            else:
                print(prec_group + str(relay))
                if not args.all:
                    return 0
                found += 1
                group_found += 1

        if group_found != 0:
            prec_group += '#'

    if found == 0:
        print('no results from DRIAD lookup: "%s"' %
                ' '.join([str(x) for x in initial_cmd]), file=sys.stderr)
        return -1

    return 0

if __name__=="__main__":
    ret = main(sys.argv)
    exit(ret)
