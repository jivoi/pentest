#!/bin/bash
apt-get update
apt-get -y upgrade
apt-get install -y wine winbind

dpkg --add-architecture i386
apt-get install -y wine32
apt-get install -y mingw-w64

# Need X Server session
winecfg