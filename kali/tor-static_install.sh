#!/bin/sh
sudo apt-get install -y libssl-dev libevent-dev zlib1g-dev automake

cd /opt
wget https://www.openssl.org/source/openssl-1.0.2k.tar.gz
tar xzf openssl-1.0.2k.tar.gz && cd openssl-1.0.2k
./config --prefix=/usr/local/openssl-1.0.2k --openssldir=/usr/local/openssl-1.0.2k && make install

cd /opt
wget https://dist.torproject.org/tor-0.3.0.7.tar.gz
tar xzf tor-0.3.0.7.tar.gz
cd tor-0.3.0.7
./configure --enable-static-tor --with-libevent-dir=/usr/lib/x86_64-linux-gnu/ --with-openssl-dir=/usr/local/openssl-1.0.2k  --with-zlib-dir=/usr/lib/x86_64-linux-gnu/
make -j2

# ldd src/or/tor
# not a dynamic executable

wget -O /etc/torrc https://raw.githubusercontent.com/jivoi/ansible-pentest-with-tor/master/roles/pentest/templates/torrc.j2
cp src/or/tor /usr/local/bin
mkdir -p /var/log/tor/
/usr/local/bin/tor -f /etc/torrc

# May 25 20:15:47.816 [notice] Tor 0.3.0.7 running on Linux with Libevent 2.0.21-stable, OpenSSL 1.0.2k and Zlib 1.2.8.
# May 25 20:15:47.817 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
# May 25 20:15:47.817 [notice] Read configuration file "/etc/torrc".
# May 25 20:15:47.823 [notice] Opening Socks listener on 127.0.0.1:9050


# ldd src/or/tor
#         linux-vdso.so.1 (0x00007ffc5f3dc000)
#         libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f17058ed000)
#         libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f17055e9000)
#         libevent-2.0.so.5 => /usr/lib/x86_64-linux-gnu/libevent-2.0.so.5 (0x00007f17053a1000)
#         libssl.so.1.1 => /usr/lib/x86_64-linux-gnu/libssl.so.1.1 (0x00007f1705135000)
#         libcrypto.so.1.1 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f1704ca2000)
#         libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f1704a83000)
#         libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f170487f000)
#         libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f17044e1000)
#         /lib64/ld-linux-x86-64.so.2 (0x0000559562b9e000)

# gcc -O2 -static -Wall -fno-strict-aliasing -L/usr/lib/x86_64-linux-gnu/ -o tor tor_main.o ./libtor.a ../common/libor.a ../common/libor-crypto.a ../common/libcurve25519_donna.a ../common/libor-event.a /usr/lib/x86_64-linux-gnu/libz.a -lm /usr/lib/x86_64-linux-gnu/libevent.a -lrt /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a -lpthread -ldl