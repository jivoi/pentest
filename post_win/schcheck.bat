@echo off
REM - Lists all schededuled tasks. Runs list of executables against icacls and checks if any allow Everyone RW permissions.
REM - Note: At present the script only ECHO's tasks.
for /f  "tokens=3* delims=: " %%m in ('schtasks /query /v /fo LIST ^| find "Task To Run:"') do (
	for /f "tokens=1* delims=?" %%x in ('echo(%%~n^| findstr /L /V /I /C:"COM handler" /C:"multiple" /C:"%SystemRoot%" /C:"shutdown"') do (
	ECHO %%~x REM  > results.txt
	)
 )
