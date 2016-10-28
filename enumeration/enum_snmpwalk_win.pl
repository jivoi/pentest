@IP=('127.0.0.1');

$source=$ARGV[0];
$IP=$ARGV[1];

$command = '';
sub records{
my @mx = ($command);
foreach $param(@_) {
push @mx, $param;
}
system(@mx);
}

@snmp=('public','private','manager');
$command = 'snmpwalk';
foreach $IP(@IP){

foreach $snmp(@snmp){
print "SNMP - ".$snmp;
records("-c",$snmp,"-v1",$IP);
print "Windows Users";
records("-c",$snmp,"-v1",$IP,"1.3.6.1.4.1.77.1.2.25");
print "Running processes";
records("-c",$snmp,"-v1",$IP,"1.3.6.1.2.1.25.4.2.1.2");
print "Open Ports";
records("-c",$snmp,"-v1",$IP,"1.3.6.1.2.1.6.13.1.3");
print "Installed Software";
records("-c",$snmp,"-v1",$IP,"1.3.6.1.2.1.25.6.3.1.2");
}

}


# #!/usr/bin/env python
# import sys
# import os

# if len(sys.argv) != 2:
#     print "null_snmpwalk <address>"
#     sys.exit(0)

# address = sys.argv[1].strip()
# # Enum users
# os.system('snmpwalk -c public -v1 ' + str(address) + ' 1.3.6.1.4.1.77.1.2.25')
# #Enum running processes
# os.system('snmpwalk -c public -v1 ' + str(address) + ' 1.3.6.1.2.1.25.4.2.1.2')
# #enum open tcp ports
# os.system('snmpwalk -c public -v1 ' + str(address) + ' 1.3.6.1.2.1.6.13.1.3')
# #enum installed software
# os.system('snmpwalk -c public -v1 ' + str(address) + ' 1.3.6.1.2.1.25.6.3.1.2')