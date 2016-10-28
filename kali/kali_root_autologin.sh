#!/bin/sh
# Auto login – GNOME gmd3
cp /etc/gdm3/daemon.conf /etc/gdm3/daemon.conf.bak

cat > /etc/gdm3/daemon.conf <<'_EOF'
# GDM configuration storage - modified by kali-root-login
#
# See /usr/share/gdm/gdm.schemas for a list of available options.

[daemon]
# Enabling automatic login
AutomaticLoginEnable = true
AutomaticLogin = root

# Enabling timed login
# TimedLoginEnable = true
# TimedLogin = user1
# TimedLoginDelay = 10

# Reserving more VTs for test consoles (default is 7)
# FirstVT = 9

[security]
AllowRoot = true

[xdmcp]

[greeter]
# Only include selected logins in the greeter
# IncludeAll = false
# Include = user1,user2

[chooser]

[debug]
# More verbose logs
# Additionally lets the X server dump core if it crashes
# Enable = true
_EOF
