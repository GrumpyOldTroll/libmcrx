#!/usr/bin/env python3
import sys
import random
import ipaddress
import subprocess

'''parses output from:
    dig +short -t TYPE260 <source_ip>

Attempts lookup of an AMT relay that can forward multicast traffic
from <source_ip> via DRIAD (draft-ietf-mboned-driad-amt-discovery).

Outputs an IP address of an AMT relay, if successful.
'''

def main(args):
    prec = 256
    rand = 0
    loc = None
    typ = None
    for line in sys.stdin:
        if not line.startswith('\\#'):
            continue
        vals = line.rstrip().split(maxsplit=2)
        if len(vals) != 3:
            continue
        val = vals[2]
        cur_precedence = int(val[0:2],16)
        cur_typ = int(val[2:4],16)&0x7f
        #print('val:%s'%val)
        if cur_precedence < prec or \
                (cur_precedence == prec and rand > random.random()):
            rand = random.random()
            loc = val[4:]
            prec = cur_precedence
            typ = cur_typ

    if loc:
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
            out  = subprocess.check_output(
                    ['dig','+short'.encode('ascii'),dn.encode('ascii')])
            out = out.decode('ascii').strip()
            if out:
                ans = out
            else:
                ans='dig +short %s failed: %s' % (dn,out)
        else:
            ans = 'failed TYPE260 parse:%s' % (loc)

        print(ans)
    else:
        print('no results in input')

    return 0

if __name__=="__main__":
    ret = main(sys.argv)
    exit(ret)
