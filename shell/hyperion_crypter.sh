#!/bin/sh
# Install Hyperion - A runtime PE-Crypter in kali
# https://github.com/nullsecuritynet/tools/tree/master/binary/hyperion
# https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-1.2.zip
# cd /opt
# wget https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-1.2.zip
# unzip Hyperion-1.2.zip
# cd Hyperion-1.2
# i686-w64-mingw32-g++ Src/Crypter/*.cpp -o hyperion.exe
# cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libgcc_s_sjlj-1.dll .
# cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libstdc++-6.dll .
# wine hyperion.exe ../shell.exe ../shell_hype.exe

# Usage: hyperion.exe <options> <infile> <outfile>

wine /opt/Hyperion-1.2/hyperion.exe $1 hype-$1