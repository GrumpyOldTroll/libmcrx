#!/usr/bin/env python3

import sys
import socket
import argparse
import time
from ipaddress import ip_address
from math import ceil

def main(args_in):
    parser = argparse.ArgumentParser(
            description='''Send test multicast UDP packets.''')

    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-s', '--source', type=ip_address)
    parser.add_argument('-g', '--group', type=ip_address, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-f', '--source-port', type=int)
    parser.add_argument('-t', '--ttl', type=int, default=64)
    parser.add_argument('--interface', type=str)
    parser.add_argument('-i', '--interval', type=int, help='inter-packet gap in milliseconds', default=10)
    parser.add_argument('-d', '--duration', type=int, help='how long to run, in seconds (actually maps to count based on interval) (0=infinity)')
    parser.add_argument('-c', '--count', type=int, help='how many packets to send (0=infinity), ignored if duration set', default=10)
    parser.add_argument('-z', '--size', type=int, help='payload size', default=1000)

    args = parser.parse_args(args_in[1:])

    if args.source:
        if args.group.version != args.source.version:
            raise ValueError(f'ip version mismatch between source={args.source}, group={args.group}')

    if not args.group.is_multicast:
        raise ValueError(f'destination address {args.group} should be a multicast group')

    if args.group.version == 4:
        family = socket.AF_INET
        so_ip = socket.IPPROTO_IP
        ttl_type = socket.IP_MULTICAST_TTL
        mult_loop = socket.IP_MULTICAST_LOOP
    else:
        family = socket.AF_INET6
        so_ip = socket.IPPROTO_IPV6
        ttl_type = socket.IPV6_MULTICAST_HOPS
        mult_loop = socket.IPV6_MULTICAST_LOOP

    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(so_ip, ttl_type, args.ttl)
    sock.setsockopt(so_ip, mult_loop, 1)

    if args.interface:
        sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                args.interface.encode(),
            )

    if args.source or args.source_port:
        source = args.source
        if not source:
            source = ''
        source_port = args.source_port
        if source_port is None:
            source_port = 0
        sock.bind((str(source), source_port))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    dest = str(args.group)
    dest_port = args.port
    gap = args.interval/1000

    count = args.count
    if args.duration is not None:
        count = ceil(args.duration * 1000 / args.interval)

    data = ''.join([f'{i:04x}' for i in range((args.size-1)//4 + 1)])[:args.size].encode()

    if count:
        for i in range(count):
            sock.sendto(data, (dest, dest_port))
            time.sleep(gap)
    else:
        while True:
            sock.sendto(data, (dest, dest_port))
            time.sleep(gap)

    return 0

if __name__=="__main__":
    ret = main(sys.argv)
    exit(ret)

