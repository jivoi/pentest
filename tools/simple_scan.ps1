# .SYNOPSIS
# This script scans a remote host to check what ports are open.
# .DESCRIPTION
# This script scans a remote host to check what ports are open.
# .PARAMETER Target
# Remote host to scan
# .PARAMETER SPort
# Port to start scan with.
# .PARAMETER EPort
# Port to end scan with.
# .EXAMPLE
# Scan remote host to check what ports are open.
# simple_scan.ps1 1 1024 192.168.56.1
# .NOTES
# Please let me know what you think or if it isn't working.

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [int] $SPort,
    [Parameter(Mandatory=$True,Position=2)]
    [int] $EPort,
    [Parameter(Mandatory=$True,Position=3)]
    [System.Net.IPAddress] $TargetIP,
    [Switch] $ShowClosed = $false
)

$range = $SPort..$EPort

foreach ($port in $range){
    $TCPConn = New-Object System.Net.Sockets.TcpClient;
    Try
    {
        $TCPConn.Connect($TargetIP, $port);
        Write-Host "Port $port is Open";
    }
    Catch [System.Net.Sockets.SocketException]
    {
        Write-Host "Port $port is Closed";
    }
    Finally
    {
        $TCPConn.Dispose();
    }
 }