#!/bin/bash
# let-in
# User-initiated reverse support shell via OpenSSL from a host user behind a firewall to the guest.

# Usage

# Both parties run:

# source <(curl -s https://gist.githubusercontent.com/cyrus-and/713391cbc342f069c149/raw/let-in.sh)
# Guest runs:

# let-me-in
# Host runs:

# let-you-in $guest_address
# Dependencies

# sudo apt-get install socat  # Linux (Debian-based)
# brew install socat          # Mac OS X (Homebrew)
# sudo ports install socat    # Mac OS X (MacPorts)
# Gotchas

# Guest's terminal is freezed until a client connects.

# source <(curl -s https://gist.githubusercontent.com/cyrus-and/713391cbc342f069c149/raw/let-in.sh)

function let-me-in() {
    local port="${1:-2222}"
    local host="${2:-0.0.0.0}"
    local cert="$(tempfile -p cert)"
    local dhparam="$HOME/.dhparam"
    echo "[+] Preparing the certificate..."
    openssl req -x509 -new -nodes -subj '/' -keyout "$cert" -out "$cert"
    ! [ -r "$dhparam" ] && openssl dhparam -out "$dhparam" 1024
    echo "[+] Listening on $host:$port..."
    socat "-,raw,echo=0" "openssl-listen:$port,bind=$host,reuseaddr,cert=$cert,dhparam=$dhparam,verify=0"
    echo "[+] Cleaning up..."
    rm -f "$cert"
}

function let-you-in() {
    if [ $# != 1 -a $# != 2 ]; then
        echo 'Usage: <host> [<port>]' >&2
        return 1
    fi
    local host="${1}"
    local port="${2:-2222}"
    echo "[+] Connecting to $host:$port. Press Ctrl+C to exit..."
    socat "openssl-connect:$host:$port,verify=0" "exec:$SHELL,pty,stderr,setsid"
}

echo '
1. Guest runs:

    let-me-in [<port> [<host>]]

2. Host runs:

    let-you-in <host> [<port>]
'
