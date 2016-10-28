if (@ARGV < 2)
	{
	    print "Usage: ./msf_enum_smb.pl target > smb_enum.rc\n";
	} else {
$source=$ARGV[0];
$target=$ARGV[1];
$user="";
$pass="";
@exploits =("use auxiliary/scanner/smb/pipe_auditor","use auxiliary/scanner/smb/pipe_dcerpc_auditor","use auxiliary/scanner/smb/smb2","use auxiliary/scanner/smb/smb_enumshares","use auxiliary/scanner/smb/smb_enumusers","use auxiliary/scanner/smb/smb_lookupsid","use auxiliary/scanner/smb/smb_version");

foreach $exploit(@exploits) {
print "\n";
print $exploit."\n";
print "set RHOSTS ".$target."\n";
print "set SMBUser ".$user."\n";
print "set SMBPass ".$user."\n";
print "set THREADS 11"."\n";
print "run"."\n";
}
	}
