#!/bin/bash
# source <(curl -s https://gist.githubusercontent.com/cyrus-and/713391cbc342f069c149/raw/unsafe-let-in.sh)

function let-me-in() {
    local port="${1:-2222}"
    local host="${2:-0.0.0.0}"
    echo "[+] Listening on $host:$port..."
    socat "-,raw,echo=0" "tcp-listen:$port,bind=$host,reuseaddr"
}

function let-you-in() {
    if [ $# != 1 -a $# != 2 ]; then
        echo 'Usage: <host> [<port>]' >&2
        return 1
    fi
    local host="${1}"
    local port="${2:-2222}"
    echo "[+] Connecting to $host:$port. Press Ctrl+C to exit..."
    socat "tcp-connect:$host:$port" "exec:$SHELL,pty,stderr,setsid"
}

echo '
1. Guest runs:

    let-me-in [<port> [<host>]]
    
2. Host runs:

    let-you-in <host> [<port>]
'
