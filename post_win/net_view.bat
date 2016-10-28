echo List domain association
net view /domain
echo List all users in domain
net user /domain
echo List all groups
net group /domain
echo List all users in domaingroup
net group /domain "administrators"
echo List all local admins
net localgroup /domain "administrators"
echo List all local accounts with SID
wmic useraccount
echo List all information about domain user including group membership
net user /domain "admin"
echo List all domain controllers on domain
nltest /dclist:(domain)


