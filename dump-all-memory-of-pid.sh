#!/bin/bash

# usage: ./dump-all-memory-of-pid.sh [pid]

# The output is printed to files with the names: pid-startaddress-stopaddress.dump

# Dependencies: gdb

grep rw-p /proc/$1/maps | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' | while read start stop; do gdb --batch --pid $1 -ex "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; done
