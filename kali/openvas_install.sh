apt-get update && apt-get dist-upgrade -y
apt-get install -y openvas
openvas-setup
cd /lib/systemd/system
sed -e 's/127.0.0.1/0.0.0.0/g' greenbone-security-assistant.service openvas-manager.service openvas-scanner.service -i
systemctl daemon-reload
openvas-start
# User created with password '3fd51f33-d9a8-4d50-8984-74fc8a872basda'
https://192.168.56.1:9392