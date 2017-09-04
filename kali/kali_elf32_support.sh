#!/bin/sh
# How to execute elf32 bit programs on x64

dpkg --add-architecture i386
apt-get update
apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386