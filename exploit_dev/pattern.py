#!/usr/bin/env python2
# Taken from: https://github.com/blackr8t/pwn-tools/blob/master/pattern.py
# Modified by Und3rf10w
import sys
import argparse
from string import uppercase, lowercase, digits

MAX_PATTERN_LENGTH = 20280

def pattern_gen(length):
    """
    Generate a pattern of a given length up to a maximum
    of 20280 - after this the pattern would repeat
    """
    if length >= MAX_PATTERN_LENGTH:
        print 'ERROR: Pattern length exceeds maximum of %d' % MAX_PATTERN_LENGTH
        sys.exit(1)

    pattern = ''
    for upper in uppercase:
        for lower in lowercase:
            for digit in digits:
                if len(pattern) < length:
                    pattern += upper+lower+digit
                else:
                    out = pattern[:length]
                    print out
                    return

def pattern_search(search_pattern):
    """
    Search for search_pattern in pattern. Convert from hex if given as such.
    """
    needle = search_pattern
    if len(needle) == 10 or len(needle) == 8:
        try:
            # (EIP = 0x41326641) Value can be given as either 0x41326641 or 41326641
            if needle.startswith('0x'):
                # Strip off '0x', convert to ASCII and reverse
                needle = needle[2:].decode('hex')
                needle = needle[::-1]
            else:
                needle = needle.decode('hex')
                needle = needle[::-1]
        except TypeError as e:
            print 'Unable to convert hex input:', e
            sys.exit(1)

    haystack = ''
    for upper in uppercase:
        for lower in lowercase:
            for digit in digits:
                haystack += upper+lower+digit
                found_at = haystack.find(needle)
                if found_at > -1:
                    print('Pattern %s first occurrence at position %d in pattern.' %
                          (search_pattern, found_at))
                    return

    print ('Couldn\'t find %s (%s) anywhere in the pattern.' %
           (search_pattern, needle))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog=str(sys.argv[0]), usage='%(prog)s [options]', description='Pattern Generator and Searcher')

    parser.add_argument('-s', help='Search for given pattern or address (0x41326641 || 41326641 || A2fA', dest='search_pattern', required=False)
    parser.add_argument('-g', help='Generate pattern of length', dest='length', required=False)

    args = parser.parse_args()
    try:
        if args.search_pattern and args.length:
            print "ERROR: both -g and -s given"
        elif args.search_pattern:
            pattern_search(args.search_pattern)
        else:
            pattern_gen(int(args.length))
    except:
        parser.print_help()
        sys.exit(0)