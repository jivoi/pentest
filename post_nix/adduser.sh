useradd -m test1
passwd test1
usermod -a -G root test1
# ---
useradd test1; echo test1 | passwd --stdin test1 && usermod -a -G root test1
# ---
echo "useradd -m -p test1 test1 -g root -d /home/test1" >> create_user.sh
# ---
echo "offsec\noffsec" | passwd test1