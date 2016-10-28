#!/bin/bash
# the user account is offsec
# rerun this script allow changing password for pure-ftpd test
apt-get install -y pure-ftpd
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
/etc/init.d/pure-ftpd restart
