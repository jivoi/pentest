<?php
ini_set('zlib.output_compression', false);// Turn off PHP output compression
while (@ob_end_flush());//Flush (send) the output buffer and turn off output buffering
ini_set('implicit_flush', true);// Implicitly flush the buffer(s)
ob_implicit_flush(true);// Implicitly flush the buffer(s)
set_time_limit(0);//Set this so PHP doesn't timeout during a long stream 
header("Cache-Control: no-cache"); //set http headers to prevent caching
header("Pragma: no-cache");//set http headers to prevent caching
function scan_target(){
	// Get the client ip address and ports
	$ipaddress = $_SERVER['REMOTE_ADDR'];
	if (filter_var($ipaddress, FILTER_VALIDATE_IP) === false) {echo "<pre>Target is not a valid IP</pre>";exit(0);}
	$target = escapeshellarg(preg_replace('/[^0-9.\']/', '', $ipaddress));
	$ports = escapeshellarg(preg_replace('/[^0-9,\-\']/', '', htmlspecialchars($_GET["ports"])));
	
	//checks if ports is set to 0 and then forces to top 100 ports
	if ( $ports == "'0'") {$cmd = escapeshellcmd("nmap -T4 --stats-every 5 -r -n -Pn --top-ports 100 $target");
	} else {$cmd = escapeshellcmd("nmap -T4 --stats-every 5 -r -n -Pn -p$ports $target");}
	
	echo '<pre>';
	$a = popen($cmd, 'r'); 
	while($b = fgets($a, 4096)) { 
		echo $b;
		flush(); 
	} 
	pclose($a); 
	echo '</pre>';
}
?>
<html><head><title>Port Scan Me</title></head><body>
<form action="" method="get">Custom Ports: (e.g. 53,80,137-139,443,445) <input type="text" name="ports"><input type="submit"></form>
<form action="" method="get">Default Ports: <select name="ports">
	<option value="0">Top 100</option>
	<option value="21">FTP 21</option>
	<option value="22">SSH 22</option>
	<option value="23">Telnet 23</option>
	<option value="53">DNS 53</option>
	<option value="80">HTTP 80</option>
	<option value="139">NetBIOS 139</option>
	<option value="443">HTTPS 443</option>
	<option value="445">SMB 445</option>
	<option value="1433">MSSQL 1433</option>
	<option value="3306">MySQL 3306</option>
	<option value="3389">RDP 3389</option>
	<option value="5632">PCAnywhere 5632</option>
	<option value="5900">VNC 5900</option>
</select><input type="submit"></form>	
<?php
if(isset($_GET["ports"])){
	scan_target();
}
?>
</body></html>
