#!/usr/bin/env python3

import shodan
import sys
import argparse
import netaddr


KEY = ''
api = shodan.Shodan(KEY)


def lookup_ip(ip):
    print(ip)
    print('=' * len(ip))

    try:
        host = api.host(ip)
        print('Operating System: {0}'.format(host.get('os', '')))
        print('Hostnames: {0}'.format(', '.join(host.get('hostnames', []))))
        print('Ports: {0}'.format(', '.join([str(p) for p in host['ports']])))
        print('Vulns: {0}'.format(', '.join(host.get('vulns', []))))
        print()

    except shodan.APIError as e:
        print('API Error: {0}\n'.format(e))


if __name__ == '__main__':
    #Parse command line arguments using argparse
    desc = """
This script will query the Shodan API and return a list of open ports on the
specified IP addresses. The IP address(es) to check can be given as a single
IP, a range of IPs, or in CIDR notation.
"""
    parser = argparse.ArgumentParser(description=desc)
    ipgroup = parser.add_mutually_exclusive_group(required=True)
    ipgroup.add_argument('-i', action='store', default=None,
                         metavar="IP",
                         help='A single IP address. ex: 192.168.1.1')
    ipgroup.add_argument('-r', action='store', default=None,
                         metavar="IP", nargs=2,
                         help='A start and end IP address. ex: 192.168.1.1 192.168.1.10')
    ipgroup.add_argument('-c', action='store', default=None,
                         metavar="CIDR",
                         help='A range of IPs in CIDR notation. ex: 192.168.1.0/24')

    args = parser.parse_args()

    network = None
    try:
        if args.i is not None:
            lookup_ip(args.i)

        elif args.r is not None:
            start, end = args.r
            range = netaddr.IPRange(start, end)

            ips = []
            for c in range.cidrs():
                ips.extend(c)
            
            for ip in sorted(set(ips)):
                lookup_ip(str(ip))

        else:
            for ip in netaddr.IPNetwork(args.c):
                lookup_ip(str(ip))

    except netaddr.AddrFormatError as e:
        print('Address Error: {0}.\n'.format(str(e)))
        parser.print_help()
        sys.exit(1)

