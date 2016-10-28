# Licence
# =======
# 
# windows-privesc-check - Security Auditing Tool For Windows
# Copyright (C) 2010  pentestmonkey@pentestmonkey.net
#                     http://pentestmonkey.net/windows-privesc-check
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability for
# damage caused by this tool.  If these terms are not acceptable to you, then you  
# may not use this tool.
#
# In all other respects the GPL version 2 applies.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# TODO List
# =========
#
# TODO review "read" perms.  should probably ignore these.
# TODO explaination of what various permissions mean
# TODO Audit: Process listing, full paths and perms of all processes
# TODO dlls used by programs (for all checks)
# TODO find web roots and check for write access
# TODO support remote server (remote file, reg keys, unc paths for file, remote resolving of sids)
# TODO task scheduler
# TODO alert if lanman hashes are being stored (for post-exploitation)
# TODO alert if named local/domain service accounts are being used (for post-exploitation)
# TODO Alert if really important patches are missing.  These are metasploitable:
#  MS10_015 977165 Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (kitrap0d - meterpreter "getsystem")
#  MS03_049 828749 Microsoft Workstation Service NetAddAlternateComputerName Overflow (netapi)     
#  MS04_007 828028 Microsoft ASN.1 Library Bitstring Heap Overflow (killbill)      
#  MS04_011 835732 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow (lsass)    
#  MS04_031 841533 Microsoft NetDDE Service Overflow (netdde)
#  MS05_039 899588 Microsoft Plug and Play Service Overflow (pnp)
#  MS06_025 911280 Microsoft RRAS Service RASMAN Registry Overflow (rasmans_reg)
#  MS06_025 911280 Microsoft RRAS Service Overflow (rras)
#  MS06_040 921883 Microsoft Server Service NetpwPathCanonicalize Overflow (netapi)
#  MS06_066 923980 Microsoft Services MS06-066 nwapi32.dll (nwapi)
#  MS06_066 923980 Microsoft Services MS06-066 nwwks.dll (nwwks)
#  MS06_070 924270 Microsoft Workstation Service NetpManageIPCConnect Overflow (wkssvc)
#  MS07_029 935966 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB) (msdns_zonename)
#  MS08_067 958644 Microsoft Server Service Relative Path Stack Corruption (netapi)
#  MS09_050 975517 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference (smb2_negotiate_func_index)
#  MS03_026 823980 Microsoft RPC DCOM Interface Overflow
#  MS05_017 892944 Microsoft Message Queueing Service Path Overflow
#  MS07_065 937894 Microsoft Message Queueing Service DNS Name Path Overflow
# TODO registry key checks for windows services
# TODO per-user checks including perms on home dirs and startup folders + default user and all users
# TODO need to be able to order issues more logically.  Maybe group by section?

# Building an Executable
# ======================
#
# This script should be converted to an exe before it is used for
# auditing - otherwise you'd have to install loads of dependencies
# on the target system.
#
# Download pyinstaller: http://www.pyinstaller.org/changeset/latest/trunk?old_path=%2F&format=zip
# Read the docs: http://www.pyinstaller.org/export/latest/tags/1.4/doc/Manual.html?format=raw
#
# Unzip to c:\pyinstaller (say)
# cd c:\pyinstaller
# python Configure.py
# python Makespec.py --onefile c:\somepath\wpc.py
# python Build.py wpc\wpc.spec
# wpc\dist\wpc.exe
#
# Alternative to pyinstaller is cxfreeze.  This doesn't always work, though:
# \Python26\Scripts\cxfreeze wpc.py --target-dir dist
# zip -r wpc.zip dist
# 
# You then need to copy wpc.zip to the target and unzip it.  The exe therein
# should then run because all the dependencies are in the current (dist) directory.

# 64-bit vs 32-bit
# ================
#
# If we run a 32-bit version of this script on a 64-bit box we have (at least) the 
# following problems:
# * Registry:  We CAN'T see the whole 64-bit registry.  This seems insurmountable.
# * Files:     It's harder to see in system32.  This can be worked round.

# What types of object have permissions?
# ======================================
#
# Files, directories and registry keys are the obvious candidates.  There are several others too...
#
# This provides a good summary: http://msdn.microsoft.com/en-us/library/aa379557%28v=VS.85%29.aspx
#
# Files or directories on an NTFS file system	GetNamedSecurityInfo, SetNamedSecurityInfo, GetSecurityInfo, SetSecurityInfo
# Named pipes
# Anonymous pipes
# Processes
# Threads
# File-mapping objects	
# Access tokens	
# Window-management objects (window stations and desktops)
# Registry keys	
# Windows services
# Local or remote printers	
# Network shares	
# Interprocess synchronization objects 
# Directory service objects	
#
# This provides a good description of how Access Tokens interact with the Security Descriptors on Securable Objects: http://msdn.microsoft.com/en-us/library/aa374876%28v=VS.85%29.aspx
#
# http://msdn.microsoft.com/en-us/library/aa379593(VS.85).aspx
#  win32security.SE_UNKNOWN_OBJECT_TYPE - n/a
#  win32security.SE_FILE_OBJECT - poc working
#  win32security.SE_SERVICE - poc working
#  win32security.SE_PRINTER - TODO Indicates a printer. A printer object can be a local printer, such as PrinterName, or a remote printer, such as 
#                      \\ComputerName\PrinterName.
#  win32security.SE_REGISTRY_KEY - TODO
#     Indicates a registry key. A registry key object can be in the local registry, such as CLASSES_ROOT\SomePath or in a remote registry, 
#     such as \\ComputerName\CLASSES_ROOT\SomePath.
#     The names of registry keys must use the following literal strings to identify the predefined registry keys: 
#     "CLASSES_ROOT", "CURRENT_USER", "MACHINE", and "USERS".
#     perms: http://msdn.microsoft.com/en-us/library/ms724878(VS.85).aspx
#  win32security.SE_LMSHARE - TODO Indicates a network share. A share object can be local, such as ShareName, or remote, such as \\ComputerName\ShareName.
#  win32security.SE_KERNEL_OBJECT - TODO
#        Indicates a local  kernel object.
#        The GetSecurityInfo and SetSecurityInfo functions support all types of kernel objects. 
#        The GetNamedSecurityInfo and SetNamedSecurityInfo functions work only with the following kernel objects: 
#        semaphore, event, mutex, waitable timer, and file mapping.
#  win32security.SE_WINDOW_OBJECT - TODO Indicates a window station or desktop object on the local computer. 
#                    You cannot use GetNamedSecurityInfo and SetNamedSecurityInfo with these objects because the names of window stations or desktops are not unique.
#  win32security.SE_DS_OBJECT - TODO - Active Directory object
#                 Indicates a directory service object or a property set or property of a directory service object. 
#                 The name string for a directory service object must be in  X.500 form, for example:
#                 CN=SomeObject,OU=ou2,OU=ou1,DC=DomainName,DC=CompanyName,DC=com,O=internet
#					perm list: http://msdn.microsoft.com/en-us/library/aa772285(VS.85).aspx
#  win32security.SE_DS_OBJECT_ALL - TODO 
#             Indicates a directory service object and all of its property sets and properties. 
#  win32security.SE_PROVIDER_DEFINED_OBJECT - TODO Indicates a provider-defined object. 
#  win32security.SE_WMIGUID_OBJECT - TODO Indicates a WMI object.
#  win32security.SE_REGISTRY_WOW64_32KEY - TODO Indicates an object for a registry entry under WOW64. 

# What sort of privileges can be granted on Windows?
# ==================================================
#
# These are bit like Capabilities on Linux.
# http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
# http://msdn.microsoft.com/en-us/library/bb545671(VS.85).aspx
#
# These privs sound like they might allow the holder to gain admin rights:
#
# SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege") Required to assign the primary token of a process. User Right: Replace a process-level token.
# SE_BACKUP_NAME TEXT("SeBackupPrivilege") Required to perform backup operations. This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. This privilege is required by the RegSaveKey and RegSaveKeyExfunctions. The following access rights are granted if this privilege is held: READ_CONTROL ACCESS_SYSTEM_SECURITY FILE_GENERIC_READ FILE_TRAVERSE User Right: Back up files and directories.
# SE_CREATE_PAGEFILE_NAME TEXT("SeCreatePagefilePrivilege") Required to create a paging file. User Right: Create a pagefile.
# SE_CREATE_TOKEN_NAME TEXT("SeCreateTokenPrivilege") Required to create a primary token. User Right: Create a token object.
# SE_DEBUG_NAME TEXT("SeDebugPrivilege") Required to debug and adjust the memory of a process owned by another account. User Right: Debug programs.
# SE_ENABLE_DELEGATION_NAME TEXT("SeEnableDelegationPrivilege") Required to mark user and computer accounts as trusted for delegation. User Right: Enable computer and user accounts to be trusted for delegation.
# SE_LOAD_DRIVER_NAME TEXT("SeLoadDriverPrivilege") Required to load or unload a device driver. User Right: Load and unload device drivers.
# SE_MACHINE_ACCOUNT_NAME TEXT("SeMachineAccountPrivilege") Required to create a computer account. User Right: Add workstations to domain.
# SE_MANAGE_VOLUME_NAME TEXT("SeManageVolumePrivilege") Required to enable volume management privileges. User Right: Manage the files on a volume.
# SE_RELABEL_NAME TEXT("SeRelabelPrivilege") Required to modify the mandatory integrity level of an object. User Right: Modify an object label.
# SE_RESTORE_NAME TEXT("SeRestorePrivilege") Required to perform restore operations. This privilege causes the system to grant all write access control to any file, regardless of the ACL specified for the file. Any access request other than write is still evaluated with the ACL. Additionally, this privilege enables you to set any valid user or group SID as the owner of a file. This privilege is required by the RegLoadKey function. The following access rights are granted if this privilege is held: WRITE_DAC WRITE_OWNER ACCESS_SYSTEM_SECURITY FILE_GENERIC_WRITE FILE_ADD_FILE FILE_ADD_SUBDIRECTORY DELETE User Right: Restore files and directories.
# SE_SHUTDOWN_NAME TEXT("SeShutdownPrivilege") Required to shut down a local system. User Right: Shut down the system.
# SE_SYNC_AGENT_NAME TEXT("SeSyncAgentPrivilege") Required for a domain controller to use the LDAP directory synchronization services. This privilege enables the holder to read all objects and properties in the directory, regardless of the protection on the objects and properties. By default, it is assigned to the Administrator and LocalSystem accounts on domain controllers. User Right: Synchronize directory service data.
# SE_TAKE_OWNERSHIP_NAME TEXT("SeTakeOwnershipPrivilege") Required to take ownership of an object without being granted discretionary access. This privilege allows the owner value to be set only to those values that the holder may legitimately assign as the owner of an object. User Right: Take ownership of files or other objects.
# SE_TCB_NAME TEXT("SeTcbPrivilege") This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems are granted this privilege. User Right: Act as part of the operating system.
# SE_TRUSTED_CREDMAN_ACCESS_NAME TEXT("SeTrustedCredManAccessPrivilege") Required to access Credential Manager as a trusted caller. User Right: Access Credential Manager as a trusted caller.
#
# These sound like they could be troublesome in the wrong hands:
#
# SE_SECURITY_NAME TEXT("SeSecurityPrivilege") Required to perform a number of security-related functions, such as controlling and viewing audit messages. This privilege identifies its holder as a security operator. User Right: Manage auditing and security log.
# SE_REMOTE_SHUTDOWN_NAME TEXT("SeRemoteShutdownPrivilege") Required to shut down a system using a network request. User Right: Force shutdown from a remote system.
# SE_PROF_SINGLE_PROCESS_NAME TEXT("SeProfileSingleProcessPrivilege") Required to gather profiling information for a single process. User Right: Profile single process.
# SE_AUDIT_NAME TEXT("SeAuditPrivilege") Required to generate audit-log entries. Give this privilege to secure servers.User Right: Generate security audits.
# SE_INC_BASE_PRIORITY_NAME TEXT("SeIncreaseBasePriorityPrivilege") Required to increase the base priority of a process. User Right: Increase scheduling priority.
# SE_INC_WORKING_SET_NAME TEXT("SeIncreaseWorkingSetPrivilege") Required to allocate more memory for applications that run in the context of users. User Right: Increase a process working set.
# SE_INCREASE_QUOTA_NAME TEXT("SeIncreaseQuotaPrivilege") Required to increase the quota assigned to a process. User Right: Adjust memory quotas for a process.
# SE_LOCK_MEMORY_NAME TEXT("SeLockMemoryPrivilege") Required to lock physical pages in memory. User Right: Lock pages in memory.
# SE_SYSTEM_ENVIRONMENT_NAME TEXT("SeSystemEnvironmentPrivilege") Required to modify the nonvolatile RAM of systems that use this type of memory to store configuration information. User Right: Modify firmware environment values.
#
# These sound less interesting:
#
# SE_CHANGE_NOTIFY_NAME TEXT("SeChangeNotifyPrivilege") Required to receive notifications of changes to files or directories. This privilege also causes the system to skip all traversal access checks. It is enabled by default for all users. User Right: Bypass traverse checking.
# SE_CREATE_GLOBAL_NAME TEXT("SeCreateGlobalPrivilege") Required to create named file mapping objects in the global namespace during Terminal Services sessions. This privilege is enabled by default for administrators, services, and the local system account.User Right: Create global objects. Windows XP/2000:  This privilege is not supported. Note that this value is supported starting with Windows Server 2003, Windows XP with SP2, and Windows 2000 with SP4.
# SE_CREATE_PERMANENT_NAME TEXT("SeCreatePermanentPrivilege") Required to create a permanent object. User Right: Create permanent shared objects.
# SE_CREATE_SYMBOLIC_LINK_NAME TEXT("SeCreateSymbolicLinkPrivilege") Required to create a symbolic link. User Right: Create symbolic links.
# SE_IMPERSONATE_NAME TEXT("SeImpersonatePrivilege") Required to impersonate. User Right: Impersonate a client after authentication.    Windows XP/2000:  This privilege is not supported. Note that this value is supported starting with Windows Server 2003, Windows XP with SP2, and Windows 2000 with SP4.
# SE_SYSTEM_PROFILE_NAME TEXT("SeSystemProfilePrivilege") Required to gather profiling information for the entire system. User Right: Profile system performance.
# SE_SYSTEMTIME_NAME TEXT("SeSystemtimePrivilege") Required to modify the system time. User Right: Change the system time.
# SE_TIME_ZONE_NAME TEXT("SeTimeZonePrivilege") Required to adjust the time zone associated with the computer's internal clock. User Right: Change the time zone.
# SE_UNDOCK_NAME TEXT("SeUndockPrivilege") Required to undock a laptop. User Right: Remove computer from docking station.
# SE_UNSOLICITED_INPUT_NAME TEXT("SeUnsolicitedInputPrivilege") Required to read unsolicited input from a terminal device. User Right: Not applicable.

# These are from ntsecapi.h:
#
# SE_BATCH_LOGON_NAME TEXT("SeBatchLogonRight") Required for an account to log on using the batch logon type.
# SE_DENY_BATCH_LOGON_NAME TEXT("SeDenyBatchLogonRight") Explicitly denies an account the right to log on using the batch logon type.
# SE_DENY_INTERACTIVE_LOGON_NAME TEXT("SeDenyInteractiveLogonRight") Explicitly denies an account the right to log on using the interactive logon type.
# SE_DENY_NETWORK_LOGON_NAME TEXT("SeDenyNetworkLogonRight") Explicitly denies an account the right to log on using the network logon type.
# SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME TEXT("SeDenyRemoteInteractiveLogonRight") Explicitly denies an account the right to log on remotely using the interactive logon type.
# SE_DENY_SERVICE_LOGON_NAME TEXT("SeDenyServiceLogonRight") Explicitly denies an account the right to log on using the service logon type.
# SE_INTERACTIVE_LOGON_NAME TEXT("SeInteractiveLogonRight") Required for an account to log on using the interactive logon type.
# SE_NETWORK_LOGON_NAME TEXT("SeNetworkLogonRight") Required for an account to log on using the network logon type.
# SE_REMOTE_INTERACTIVE_LOGON_NAME TEXT("SeRemoteInteractiveLogonRight") Required for an account to log on remotely using the interactive logon type.
# SE_SERVICE_LOGON_NAME TEXT("SeServiceLogonRight") Required for an account to log on using the service logon type.

#import pythoncom, sys, os, time, win32api
#from win32com.taskscheduler import taskscheduler
import glob
import datetime
import socket
import os, sys
import win32process
import re
import win32security, ntsecuritycon, win32api, win32con, win32file
import win32service
import pywintypes # doesn't play well with molebox pro - why did we need this anyway?
import win32net
import ctypes
import getopt
import _winreg
import win32netcon
from subprocess import Popen, PIPE, STDOUT
# from winapi import *
from ntsecuritycon import TokenSessionId, TokenSandBoxInert, TokenType, TokenImpersonationLevel, TokenVirtualizationEnabled, TokenVirtualizationAllowed, TokenHasRestrictions, TokenElevationType, TokenUIAccess, TokenUser, TokenOwner, TokenGroups, TokenRestrictedSids, TokenPrivileges, TokenPrimaryGroup, TokenSource, TokenDefaultDacl, TokenStatistics, TokenOrigin, TokenLinkedToken, TokenLogonSid, TokenElevation, TokenIntegrityLevel, TokenMandatoryPolicy, SE_ASSIGNPRIMARYTOKEN_NAME, SE_BACKUP_NAME, SE_CREATE_PAGEFILE_NAME, SE_CREATE_TOKEN_NAME, SE_DEBUG_NAME, SE_LOAD_DRIVER_NAME, SE_MACHINE_ACCOUNT_NAME, SE_RESTORE_NAME, SE_SHUTDOWN_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME
# Need: SE_ENABLE_DELEGATION_NAME, SE_MANAGE_VOLUME_NAME, SE_RELABEL_NAME, SE_SYNC_AGENT_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME
k32 = ctypes.windll.kernel32
wow64 = ctypes.c_long( 0 )
on64bitwindows = 1
remote_server = None
remote_username = None
remote_password = None
remote_domain = None
local_ips = socket.gethostbyname_ex(socket.gethostname())[2] # have to do this before Wow64DisableWow64FsRedirection

version = "1.0"
svnversion="$Revision$" # Don't change this line.  Auto-updated.
svnnum=re.sub('[^0-9]', '', svnversion)
if svnnum:
	version = version + "svn" + svnnum

all_checks       = 0
registry_checks  = 0
path_checks      = 0
service_checks   = 0
service_audit    = 0
drive_checks     = 0
eventlog_checks  = 0
progfiles_checks = 0
process_checks   = 0
share_checks     = 0
passpol_audit    = 0
user_group_audit = 0
logged_in_audit  = 0
process_audit    = 0
admin_users_audit= 0
host_info_audit  = 0
ignore_trusted   = 0
owner_info       = 0
weak_perms_only  = 0
host_info_audit     = 0
patch_checks     = 0
verbose          = 0
report_file_name = None

kb_nos = {
        '977165': 'MS10_015 Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (kitrap0d - meterpreter "getsystem")',
        '828749': 'MS03_049 Microsoft Workstation Service NetAddAlternateComputerName Overflow (netapi)     ',
        '828028': 'MS04_007 Microsoft ASN.1 Library Bitstring Heap Overflow (killbill)      ',
        '835732': 'MS04_011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow (lsass)    ',
        '841533': 'MS04_031 Microsoft NetDDE Service Overflow (netdde)',
        '899588': 'MS05_039 Microsoft Plug and Play Service Overflow (pnp)',
        '911280': 'MS06_025 Microsoft RRAS Service RASMAN Registry Overflow (rasmans_reg)',
        '911280': 'MS06_025 Microsoft RRAS Service Overflow (rras)',
        '921883': 'MS06_040 Microsoft Server Service NetpwPathCanonicalize Overflow (netapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwapi32.dll (nwapi)',
        '923980': 'MS06_066 Microsoft Services MS06-066 nwwks.dll (nwwks)',
        '924270': 'MS06_070 Microsoft Workstation Service NetpManageIPCConnect Overflow (wkssvc)',
        '935966': 'MS07_029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB) (msdns_zonename)',
        '958644': 'MS08_067 Microsoft Server Service Relative Path Stack Corruption (netapi)',
        '975517': 'MS09_050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference (smb2_negotiate_func_index)',
        '823980': 'MS03_026 Microsoft RPC DCOM Interface Overflow',
        '892944': 'MS05_017 Microsoft Message Queueing Service Path Overflow',
        '937894': 'MS07_065 Microsoft Message Queueing Service DNS Name Path Overflow'
}

reg_paths = (
	'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services',
	'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
	'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
	'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
	'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
	'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
	'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
	'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
	'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce',
	'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices',
	'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
	'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices',
	'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
	'HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows',
)

# We don't care if some users / groups hold dangerous permission because they're trusted
# These have fully qualified names:
trusted_principles_fq = (
	"BUILTIN\\Administrators",
	"NT SERVICE\\TrustedInstaller",
	"NT AUTHORITY\\SYSTEM"
)

# We may temporarily regard a user as trusted (e.g. if we're looking for writable
# files in a user's path, we do not care that he can write to his own path)
tmp_trusted_principles_fq = (
)

eventlog_key_hklm = 'SYSTEM\CurrentControlSet\Services\Eventlog'

# We don't care if members of these groups hold dangerous permission because they're trusted
# These have names without a domain:
trusted_principles = (
	"Administrators",
	"Domain Admins",
	"Enterprise Admins",
)

# Windows privileges from 
windows_privileges = (
        "SeAssignPrimaryTokenPrivilege",
        "SeBackupPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreateTokenPrivilege",
        "SeDebugPrivilege",
        "SeEnableDelegationPrivilege",
        "SeLoadDriverPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeRelabelPrivilege",
        "SeRestorePrivilege",
        "SeShutdownPrivilege",
        "SeSyncAgentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege",
        "SeSecurityPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeAuditPrivilege",
        "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeLockMemoryPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePermanentPrivilege",
        "SeCreateSymbolicLinkPrivilege",
        "SeImpersonatePrivilege",
        "SeSystemProfilePrivilege",
        "SeSystemtimePrivilege",
        "SeTimeZonePrivilege",
        "SeUndockPrivilege",
        "SeUnsolicitedInputPrivilege",
        "SeBatchLogonRight",
        "SeDenyBatchLogonRight",
        "SeDenyInteractiveLogonRight",
        "SeDenyNetworkLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
        "SeDenyServiceLogonRight",
        "SeInteractiveLogonRight",
        "SeNetworkLogonRight",
        "SeRemoteInteractiveLogonRight",
        "SeServiceLogonRight"
)

share_types = (
	"STYPE_IPC",
	"STYPE_DISKTREE",
	"STYPE_PRINTQ",
	"STYPE_DEVICE",
)
	
sv_types = (
        "SV_TYPE_WORKSTATION",
        "SV_TYPE_SERVER",
        "SV_TYPE_SQLSERVER",
        "SV_TYPE_DOMAIN_CTRL",
        "SV_TYPE_DOMAIN_BAKCTRL",
        "SV_TYPE_TIME_SOURCE",
        "SV_TYPE_AFP",
        "SV_TYPE_NOVELL",
        "SV_TYPE_DOMAIN_MEMBER",
        "SV_TYPE_PRINTQ_SERVER",
        "SV_TYPE_DIALIN_SERVER",
        "SV_TYPE_XENIX_SERVER",
        "SV_TYPE_NT",
        "SV_TYPE_WFW",
        "SV_TYPE_SERVER_MFPN",
        "SV_TYPE_SERVER_NT",
        "SV_TYPE_POTENTIAL_BROWSER",
        "SV_TYPE_BACKUP_BROWSER",
        "SV_TYPE_MASTER_BROWSER",
        "SV_TYPE_DOMAIN_MASTER",
        "SV_TYPE_SERVER_OSF",
        "SV_TYPE_SERVER_VMS",
        "SV_TYPE_WINDOWS",
        "SV_TYPE_DFS",
        "SV_TYPE_CLUSTER_NT",
        "SV_TYPE_TERMINALSERVER", # missing from win32netcon.py
        #"SV_TYPE_CLUSTER_VS_NT", # missing from win32netcon.py
        "SV_TYPE_DCE",
        "SV_TYPE_ALTERNATE_XPORT",
        "SV_TYPE_LOCAL_LIST_ONLY",
        "SV_TYPE_DOMAIN_ENUM"
)

win32netcon.SV_TYPE_TERMINALSERVER = 0x2000000 

dangerous_perms_write = {
	# http://www.tek-tips.com/faqs.cfm?fid
	'share': {
		ntsecuritycon: (
			"FILE_READ_DATA", #
			"FILE_WRITE_DATA",
			"FILE_APPEND_DATA",
			"FILE_READ_EA", #
			"FILE_WRITE_EA",
			"FILE_EXECUTE", #
			"FILE_READ_ATTRIBUTES", #
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			"READ_CONTROL", #
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE", #
		)
	},
	'file': {
		ntsecuritycon: (
			#"FILE_READ_DATA",
			"FILE_WRITE_DATA",
			"FILE_APPEND_DATA",
			#"FILE_READ_EA",
			"FILE_WRITE_EA",
			#"FILE_EXECUTE",
			#"FILE_READ_ATTRIBUTES",
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			#"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			#"SYNCHRONIZE",
		)
	},
	# http://msdn.microsoft.com/en-us/library/ms724878(VS.85).aspx
	# KEY_ALL_ACCESS: STANDARD_RIGHTS_REQUIRED KEY_QUERY_VALUE KEY_SET_VALUE KEY_CREATE_SUB_KEY KEY_ENUMERATE_SUB_KEYS KEY_NOTIFY KEY_CREATE_LINK
	# KEY_CREATE_LINK (0x0020) Reserved for system use.
	# KEY_CREATE_SUB_KEY (0x0004)	Required to create a subkey of a registry key.
	# KEY_ENUMERATE_SUB_KEYS (0x0008)	Required to enumerate the subkeys of a registry key.
	# KEY_EXECUTE (0x20019)	Equivalent to KEY_READ.
	# KEY_NOTIFY (0x0010)	Required to request change notifications for a registry key or for subkeys of a registry key.
	# KEY_QUERY_VALUE (0x0001)	Required to query the values of a registry key.
	# KEY_READ (0x20019)	Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
	# KEY_SET_VALUE (0x0002)	Required to create, delete, or set a registry value.
	# KEY_WOW64_32KEY (0x0200)	Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. For more information, see Accessing an Alternate Registry View.	This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
	# Windows 2000:  This flag is not supported.
	# KEY_WOW64_64KEY (0x0100)	Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. For more information, see Accessing an Alternate Registry View.
	# This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
	# Windows 2000:  This flag is not supported.
	# KEY_WRITE (0x20006)	Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
	# "STANDARD_RIGHTS_REQUIRED",
	# "STANDARD_RIGHTS_WRITE",
	# "STANDARD_RIGHTS_READ",
	# "DELETE",
	# "READ_CONTROL",
	# "WRITE_DAC",
	#"WRITE_OWNER",
	'reg': {		
		_winreg: (
			#"KEY_ALL_ACCESS", # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
			#"KEY_QUERY_VALUE", # GUI "Query Value"
			"KEY_SET_VALUE", # GUI "Set Value".  Required to create, delete, or set a registry value.
			"KEY_CREATE_LINK", # GUI "Create Link".  Reserved for system use.
			"KEY_CREATE_SUB_KEY", # GUI "Create subkey"
			# "KEY_ENUMERATE_SUB_KEYS", # GUI "Create subkeys"
			# "KEY_NOTIFY", # GUI "Notify"
			#"KEY_EXECUTE", # same as KEY_READ
			#"KEY_READ",
			#"KEY_WOW64_32KEY",
			#"KEY_WOW64_64KEY",
			# "KEY_WRITE", # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
		),
		ntsecuritycon: (
			"DELETE", # GUI "Delete"
			# "READ_CONTROL", # GUI "Read Control" - read security descriptor
			"WRITE_DAC", # GUI "Write DAC"
			"WRITE_OWNER", # GUI "Write Owner"
			#"STANDARD_RIGHTS_REQUIRED",
			#"STANDARD_RIGHTS_WRITE",
			#"STANDARD_RIGHTS_READ",
		)
	},
	'directory': {
		ntsecuritycon: (
			#"FILE_LIST_DIRECTORY",
			"FILE_ADD_FILE",
			"FILE_ADD_SUBDIRECTORY",
			#"FILE_READ_EA",
			"FILE_WRITE_EA",
			#"FILE_TRAVERSE",
			"FILE_DELETE_CHILD",
			#"FILE_READ_ATTRIBUTES",
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			#"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			#"SYNCHRONIZE",
		)
	},
	'service_manager': {
		# For service manager
		# http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
		# SC_MANAGER_ALL_ACCESS (0xF003F)	Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
		# SC_MANAGER_CREATE_SERVICE (0x0002)	Required to call the CreateService function to create a service object and add it to the database.
		# SC_MANAGER_CONNECT (0x0001)	Required to connect to the service control manager.
		# SC_MANAGER_ENUMERATE_SERVICE (0x0004)	Required to call the EnumServicesStatusEx function to list the services that are in the database.
		# SC_MANAGER_LOCK (0x0008)	Required to call the LockServiceDatabase function to acquire a lock on the database.
		# SC_MANAGER_MODIFY_BOOT_CONFIG (0x0020)	Required to call the NotifyBootConfigStatus function.
		# SC_MANAGER_QUERY_LOCK_STATUS (0x0010)Required to call the  QueryServiceLockStatus function to retrieve the lock status information for the database.
		win32service: (
			"SC_MANAGER_ALL_ACCESS",
			"SC_MANAGER_CREATE_SERVICE",
			"SC_MANAGER_CONNECT",
			"SC_MANAGER_ENUMERATE_SERVICE",
			"SC_MANAGER_LOCK",
			"SC_MANAGER_MODIFY_BOOT_CONFIG",
			"SC_MANAGER_QUERY_LOCK_STATUS",
		)
	},
	'service': {
		# For services:
		# http://msdn.microsoft.com/en-us/library/ms685981(VS.85).aspx
		# SERVICE_ALL_ACCESS (0xF01FF)	Includes STANDARD_RIGHTS_REQUIRED in addition to all access rights in this table.
		# SERVICE_CHANGE_CONFIG (0x0002)	Required to call the ChangeServiceConfig or ChangeServiceConfig2 function to change the service configuration. Because 	this grants the caller the right to change the executable file that the system runs, it should be granted only to administrators.
		# SERVICE_ENUMERATE_DEPENDENTS (0x0008)	Required to call the EnumDependentServices function to enumerate all the services dependent on the service.
		# SERVICE_INTERROGATE (0x0080)	Required to call the ControlService function to ask the service to report its status immediately.
		# SERVICE_PAUSE_CONTINUE (0x0040)	Required to call the ControlService function to pause or continue the service.
		# SERVICE_QUERY_CONFIG (0x0001)	Required to call the QueryServiceConfig and QueryServiceConfig2 functions to query the service configuration.
		# SERVICE_QUERY_STATUS (0x0004)	Required to call the QueryServiceStatusEx function to ask the service control manager about the status of the service.
		# SERVICE_START (0x0010)	Required to call the StartService function to start the service.
		# SERVICE_STOP (0x0020)	Required to call the ControlService function to stop the service.
		# SERVICE_USER_DEFINED_CONTROL(0x0100)	Required to call the ControlService function to specify a user-defined control code.
		win32service: (
			# "SERVICE_INTERROGATE",
			# "SERVICE_QUERY_STATUS",
			# "SERVICE_ENUMERATE_DEPENDENTS",
			"SERVICE_ALL_ACCESS",
			"SERVICE_CHANGE_CONFIG",
			"SERVICE_PAUSE_CONTINUE",
			# "SERVICE_QUERY_CONFIG",
			"SERVICE_START",
			"SERVICE_STOP",
			# "SERVICE_USER_DEFINED_CONTROL", # TODO this is granted most of the time.  Double check that's not a bad thing.
		)
	},
}

all_perms = {
	'share': {
		ntsecuritycon: (
			"FILE_READ_DATA", #
			"FILE_WRITE_DATA",
			"FILE_APPEND_DATA",
			"FILE_READ_EA", #
			"FILE_WRITE_EA",
			"FILE_EXECUTE", #
			"FILE_READ_ATTRIBUTES", #
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			"READ_CONTROL", #
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE", #
		)
	},
	'file': {
		ntsecuritycon: (
			"FILE_READ_DATA",
			"FILE_WRITE_DATA",
			"FILE_APPEND_DATA",
			"FILE_READ_EA",
			"FILE_WRITE_EA",
			"FILE_EXECUTE",
			"FILE_READ_ATTRIBUTES",
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE",
		)
	},
	'reg': {		
		_winreg: (
			"KEY_ALL_ACCESS",
			"KEY_CREATE_LINK",
			"KEY_CREATE_SUB_KEY",
			"KEY_ENUMERATE_SUB_KEYS",
			"KEY_EXECUTE",
			"KEY_NOTIFY",
			"KEY_QUERY_VALUE",
			"KEY_READ",
			"KEY_SET_VALUE",
			"KEY_WOW64_32KEY",
			"KEY_WOW64_64KEY",
			"KEY_WRITE",
		),
		ntsecuritycon: (
			"DELETE",
			"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			"STANDARD_RIGHTS_REQUIRED",
			"STANDARD_RIGHTS_WRITE",
			"STANDARD_RIGHTS_READ",
			"SYNCHRONIZE",
		)
	},
	'directory': {
		ntsecuritycon: (
			"FILE_LIST_DIRECTORY",
			"FILE_ADD_FILE",
			"FILE_ADD_SUBDIRECTORY",
			"FILE_READ_EA",
			"FILE_WRITE_EA",
			"FILE_TRAVERSE",
			"FILE_DELETE_CHILD",
			"FILE_READ_ATTRIBUTES",
			"FILE_WRITE_ATTRIBUTES",
			"DELETE",
			"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE",
		)
	},
	'service_manager': {
		win32service: (
			"SC_MANAGER_ALL_ACCESS",
			"SC_MANAGER_CREATE_SERVICE",
			"SC_MANAGER_CONNECT",
			"SC_MANAGER_ENUMERATE_SERVICE",
			"SC_MANAGER_LOCK",
			"SC_MANAGER_MODIFY_BOOT_CONFIG",
			"SC_MANAGER_QUERY_LOCK_STATUS",
		)
	},
	'service': {
		win32service: (
			"SERVICE_INTERROGATE",
			"SERVICE_QUERY_STATUS",
			"SERVICE_ENUMERATE_DEPENDENTS",
			"SERVICE_ALL_ACCESS",
			"SERVICE_CHANGE_CONFIG",
			"SERVICE_PAUSE_CONTINUE",
			"SERVICE_QUERY_CONFIG",
			"SERVICE_START",
			"SERVICE_STOP",
			"SERVICE_USER_DEFINED_CONTROL", # TODO this is granted most of the time.  Double check that's not a bad thing.
		)
	},
	'process': {
		win32con: (
			"PROCESS_TERMINATE",
			"PROCESS_CREATE_THREAD",
			"PROCESS_VM_OPERATION",
			"PROCESS_VM_READ",
			"PROCESS_VM_WRITE",
			"PROCESS_DUP_HANDLE",
			"PROCESS_CREATE_PROCESS",
			"PROCESS_SET_QUOTA",
			"PROCESS_SET_INFORMATION",
			"PROCESS_QUERY_INFORMATION",
			"PROCESS_ALL_ACCESS"
		),
		ntsecuritycon: (
			"DELETE",
			"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE",
			"STANDARD_RIGHTS_REQUIRED",
			"STANDARD_RIGHTS_READ",
			"STANDARD_RIGHTS_WRITE",
			"STANDARD_RIGHTS_EXECUTE",
			"STANDARD_RIGHTS_ALL",
			"SPECIFIC_RIGHTS_ALL",
			"ACCESS_SYSTEM_SECURITY",
			"MAXIMUM_ALLOWED",
			"GENERIC_READ",
			"GENERIC_WRITE",
			"GENERIC_EXECUTE",
			"GENERIC_ALL"
		)
	},
	'thread': {
		win32con: (
			"THREAD_TERMINATE",
			"THREAD_SUSPEND_RESUME",
			"THREAD_GET_CONTEXT",
			"THREAD_SET_CONTEXT",
			"THREAD_SET_INFORMATION",
			"THREAD_QUERY_INFORMATION",
			"THREAD_SET_THREAD_TOKEN",
			"THREAD_IMPERSONATE",
			"THREAD_DIRECT_IMPERSONATION",
			"THREAD_ALL_ACCESS",
			"THREAD_QUERY_LIMITED_INFORMATION",
			"THREAD_SET_LIMITED_INFORMATION"
		),
		ntsecuritycon: (
			"DELETE",
			"READ_CONTROL",
			"WRITE_DAC",
			"WRITE_OWNER",
			"SYNCHRONIZE",
		)
	},
}

# Used to store a data structure representing the issues we've found
# We use this to generate the report
issues = {}

issue_template = {
    'WPC001': {
       'title': "Insecure Permissions on Program Files",
       'description': '''Some of the programs in %ProgramFiles% and/or %ProgramFiles(x86)% could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below can be modified by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below can be changed by non-administrative users:",
          },
       }
    },
	
    'WPC002': {
       'title': "Insecure Permissions on Files and Directories in Path (OBSELETE ISSUE)",
       'description': '''Some of the programs and directories in the %PATH% variable could be changed by non-administrative users.

This could allow certain users on the system to place malicious code into certain key directories, or to replace programs with malicious ones.  A malicious local user could use this technique to hijack the privileges of other local users, running commands with their privileges.
''',
       'recommendation': '''Programs run by multiple users should only be changable only by administrative users.  The directories containing these programs should only be changable only by administrators too.  Revoke write privileges for non-administrative users from the above programs and directories.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          },
          'writable_dirs': {
             'section': "description",
             'preamble': "The directories below are in the path of the user used to carry out this audit.  Each one can be changed by non-administrative users:",
          }
       }
    },
	
    'WPC003': {
       'title': "Insecure Permissions In Windows Registry",
       'description': '''Some registry keys that hold the names of programs run by other users were checked and found to have insecure permissions.  It would be possible for non-administrative users to modify the registry to cause a different programs to be run.  This weakness could be abused by low-privileged users to run commands of their choosing with higher privileges.''',
       'recommendation': '''Modify the permissions on the above registry keys to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },
	
    'WPC004': {
       'title': "Insecure Permissions On Windows Service Executables",
       'description': '''Some of the programs that are run when Windows Services start were found to have weak file permissions.  It is possible for non-administrative local users to replace some of the Windows Service executables with malicious programs.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_progs': {
             'section': "description",
             'preamble': "The programs below could be changed by non-administrative users:",
          },
       }
    },
	
    'WPC005': {
       'title': "Insecure Permissions On Windows Service Registry Keys (NOT IMPLEMENTED YET)",
       'description': '''Some registry keys that hold the names of programs that are run when Windows Services start were found to have weak file permissions.  They could be changed by non-administrative users to cause malicious programs to be run instead of the intended Windows Service Executable.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_reg_paths': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },

	'WPC007': {
       'title': "Insecure Permissions On Event Log File",
       'description': '''Some of the Event Log files could be changed by non-administrative users.  This may allow attackers to cover their tracks.''',
       'recommendation': '''Modify the permissions on the above files to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_file': {
             'section': "description",
             'preamble': "The files below could be changed by non-administrative users:",
          },
       }
    },

    'WPC008': {
       'title': "Insecure Permissions On Event Log DLL",
       'description': '''Some DLL files used by Event Viewer to display logs could be changed by non-administrative users.  It may be possible to replace these with a view to having code run when an administrative user next views log files.''',
       'recommendation': '''Modify the permissions on the above DLLs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_dll': {
             'section': "description",
             'preamble': "The DLL files below could be changed by non-administrative users:",
          },
       }
    },

    'WPC009': {
       'title': "Insecure Permissions On Event Log Registry Key (NOT IMPLMENTED YET)",
       'description': '''Some registry keys that hold the names of DLLs used by Event Viewer and the location of Log Files are writable by non-administrative users.  It may be possible to maliciouly alter the registry to change the location of log files or run malicious code.''',
       'recommendation': '''Modify the permissions on the above programs to allow only administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_eventlog_key': {
             'section': "description",
             'preamble': "The registry keys below could be changed by non-administrative users:",
          },
       }
    },

    'WPC010': {
       'title': "Insecure Permissions On Drive Root",
       'description': '''Some of the local drive roots allow non-administrative users to create files and folders.  This could allow malicious files to be placed in on the server in the hope that they'll allow a local user to escalate privileges (e.g. create program.exe which might get accidentally launched by another user).''',
       'recommendation': '''Modify the permissions on the drive roots to only allow administrators write access.  Revoke write access from low-privileged users.''',
       'supporting_data': {
          'writable_drive_root': {
             'section': "description",
             'preamble': "The following drives allow non-administrative users to write to their root directory:",
          },
       }
    },

    'WPC011': {
       'title': "Insecure (Non-NTFS) File System Used",
       'description': '''Some local drives use Non-NTFS file systems.  These drive therefore don't allow secure file permissions to be used.  Any local user can change any data on these drives.''',
       'recommendation': '''Use NTFS filesystems instead of FAT.  Ensure that strong file permissions are set - NTFS file permissions are insecure by default after FAT file systems are converted.''',
       'supporting_data': {
          'fat_fs_drives': {
             'section': "description",
             'preamble': "The following drives use Non-NTFS file systems:",
          },
       }
    },

    'WPC012': {
       'title': "Insecure Permissions On Windows Services",
       'description': '''Some of the Windows Services installed have weak permissions.  This could allow non-administrators to manipulate services to their own advantage.  The impact depends on the permissions granted, but can include starting services, stopping service or even reconfiguring them to run a different program.  This can lead to denial of service or even privilege escalation if the service is running as a user with more privilege than a malicious local user.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_service_perms': {
             'section': "description",
             'preamble': "Some Windows Services can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC013': {
       'title': "Insecure Permissions On Files / Directories In System PATH",
       'description': '''Some programs/directories in the system path have weak permissions.  TODO which user are affected by this issue?''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exe': {
             'section': "description",
             'preamble': "The following programs/DLLs in the system PATH can be manipulated by non-administrator users:",
          },
          'weak_perms_dir': {
             'section': "description",
             'preamble': "The following directories in the system PATH can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC014': {
       'title': "Insecure Permissions On Files / Directories In Current User's PATH",
       'description': '''Some programs/directories in the path of the user used to perform this audit have weak permissions.  TODO which user was used to perform this audit?''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exe': {
             'section': "description",
             'preamble': "The following programs/DLLs in current user's PATH can be manipulated by non-administrator users:",
          },
          'weak_perms_dir': {
             'section': "description",
             'preamble': "The following directories in the current user's PATH can be manipulated by non-administrator users:",
          },
       }
    },
	
    'WPC015': {
       'title': "Insecure Permissions On Files / Directories In Users' PATHs (NEED TO CHECK THIS WORKS)",
       'description': '''Some programs/directories in the paths of users on this system have weak permissions.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exe': {
             'section': "description",
             'preamble': "The following programs/DLLs in users' PATHs can be manipulated by non-administrator users:",
          },
          'weak_perms_dir': {
             'section': "description",
             'preamble': "The following directories in users' PATHs can be manipulated by non-administrator users:",
          },
       }
    },
    'WPC016': {
       'title': "Insecure Permissions On Running Programs",
       'description': '''Some programs running at the time of the audit have weak file permissions.  The corresponding programs could be altered by non-administrator users.''',
       'recommendation': '''Review the permissions that have been granted to non-administrative users and revoke access where possible.''',
       'supporting_data': {
          'weak_perms_exes': {
             'section': "description",
             'preamble': "The following programs were running at the time of the audit, but could be changed on-disk by non-administrator users:",
          },
          'weak_perms_dlls': {
             'section': "description",
             'preamble': "The following DLLs are used by program which were running at the time of the audit.  These DLLs can be changed on-disk by non-administrator users:",
          },
       }
    },
    'WPC017': {
       'title': "Shares Accessible By Non-Admin Users",
       'description': '''The share-level permissions on some Windows file shares allows access by non-administrative users.  This can often be desirable, in which case this issue can be ignored.  However, sometimes it can allow data to be stolen or programs to be malciously modified.  NB: Setting strong NTFS permissions can sometimes mean that data which seems to be exposed on a share actually isn't accessible.''',
       'recommendation': '''Review the share-level permissions that have been granted to non-administrative users and revoke access where possible.  Share-level permissions can be viewed in Windows Explorer: Right-click folder | Sharing and Security | "Sharing" tab | "Permissions" button (for XP - other OSs may vary slightly).''',
       'supporting_data': {
          'non_admin_shares': {
             'section': "description",
             'preamble': "The following shares are accessible by non-administrative users:",
          },
       }
    },
}

issue_template_html = '''
<h3>REPLACE_TITLE</h3>

<table>
<tr>
<td>
<b>Description</b>
</td>
<td>
REPLACE_DESCRIPTION
REPLACE_DESCRIPTION_DATA
</td>
</tr>

<tr>
<td>
<b>Recommendation</b>
</td>
<td>
REPLACE_RECOMMENDATION
REPLACE_RECOMMENDATION_DATA
</td>
</tr>
</table>
'''

issue_list_html ='''
REPLACE_PREAMBLE
<ul>
REPLACE_ITEM
</ul>
'''

# TODO nice looking css, internal links, risk ratings
# TODO record group members for audit user, separate date and time; os and sp
overview_template_html = '''
<html>
<head>
<style type="text/css">
body {color:black}
td
{
vertical-align:top;
}
h1 {font-size: 300%; text-align:center}
h2 {font-size: 200%; margin-top: 25px; margin-bottom: 0px; padding: 5px; background-color: #CCCCCC;}
h3 {font-size: 150%; font-weight: normal; padding: 5px; background-color: #EEEEEE; margin-top: 10px;}
#frontpage {height: 270px; background-color: #F3F3F3;}
p.ex {color:rgb(0,0,255)}

#customers
{
font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;
/* width:100%; */
padding:10px 0px 0px 0px;
border-collapse:collapse;
}
#customers td, #customers th 
{
font-size:1em;
border:1px solid #989898;
padding:3px 7px 2px 7px;
}
#customers th 
{
font-size:1.1em;
text-align:left;
padding-top:5px;
padding-bottom:4px;
background-color:#A7C942;
color:#ffffff;
}
#customers tr.alt td 
{
color:#000000;
background-color:#EAF2D3;
}
</style>
</head>
<div id="frontpage">
<h1><p>windows-privesc-check</p> <p>Audit of Host: </p><p>REPLACE_HOSTNAME</p></h1>
</div>

<h2>Contents</h2>
REPLACE_CONTENTS
<h2>Information about this Audit</h2>
<p>This report was generated on REPLACE_DATETIME by vREPLACE_VERSION of <a href="http://pentestmonkey.net/windows-privesc-check">windows-privesc-check</a>.</p>

<p>The audit was run as the user REPLACE_AUDIT_USER.</p>

<p>The following table provides information about this audit:</p>

<table id="customers" border="1">
<tr>
<td>Hostname</td>
<td>REPLACE_HOSTNAME</td>
</tr>

<tr class="alt">
<td>Domain/Workgroup</td>
<td>REPLACE_DOMWKG</td>
</tr>

<tr>
<td>Operating System</td>
<td>REPLACE_OS</td>
</tr>

<tr class="alt">
<td>IP Addresses</td>
<td><ul>REPLACE_IPS</ul></td>
</tr>

</table> 
<h2>Escalation Vectors</h2>
REPLACE_ISSUES

<h2>Scan Parameters</h2>
For the purposes of the audit the following users were considered to be trusted.  Any privileges assigned to them have not been considered as potential attack vectors:
<ul>
REPLACE_TRUSTED_USERS
</ul>

Additionally members of the following groups were considered trusted:
<ul>
REPLACE_TRUSTED_GROUPS
</ul>

The following file/directory/registry permissions were considered to be potentially dangerous.  This audit exclusively searched for instances of these permissions:
<ul>
REPLACE_DANGEROUS_PERMS
</ul>
</html>
'''

def usage():
	print "Usage: windows-privesc-check [options] checks"
	print ""
	print "checks must be at least one of:"
	print "  -a|--all_checks        Run all security checks (see below)"
	print "  -r|--registry_checks   Check RunOnce and other critical keys"
	print "  -t|--path_checks       Check %PATH% for insecure permissions"
	print "  -S|--service_checks    Check Windows services for insecure permissions"
	print "  -d|--drive_checks      Check for FAT filesystems and weak perms in root dir"
	print "  -E|--eventlog_checks   Check Event Logs for insecure permissions"
	print "  -F|--progfiles_checks  Check Program Files directories for insecure perms"
	print "  -R|--process_checks    Check Running Processes for insecure permissions"
	print "  -H|--share_checks      Check shares for insecure permissions"
	#print "  -T|--patch_checks      Check some important patches"
	print "  -U|--user_groups       Dump users, groups and privileges (no HTML yet)"
	print "  -A|--admin_users       Dump admin users / high priv users (no HTML yet)"
	print "  -O|--processes         Dump process info (no HTML yet)"
	print "  -P|--passpol           Dump password policy (no HTML yet)"
	print "  -i|--host_info         Dump host info - OS, domain controller, ... (no HTML yet)"
	print "  -e|--services          Dump service info (no HTML yet)"
# TODO options to flag a user/group as trusted
	print ""
	print "options are:"
	print "  -h|--help              This help message"
	print "  -w|--write_perms_only  Only list write perms (dump opts only)"
	print "  -I|--ignore_trusted    Ignore trusted users, empty groups (dump opts only)"
	print "  -W|--owner_info        Owner, Group info (dump opts only)"
	print "  -v|--verbose           More detail output (use with -U)"
	print "  -o|--report_file file  Report filename.  Default privesc-report-[host].html"
	print "  -s|--server host       Remote server name.  Only works with -u!"
	print "  -u|--username arg      Remote username.  Only works with -u!"
	print "  -p|--password arg      Remote password.  Only works with -u!"
	print "  -d|--domain arg        Remote domain.  Only works with -u!"
	print ""
	sys.exit(0)

#
# Reporting functions
#

def format_issues(format, issue_template, issue_data):
	report = ""
	toc = ""
	overview = overview_template_html
	overview = overview.replace('REPLACE_HOSTNAME', audit_data['hostname'])
	overview = overview.replace('REPLACE_DOMWKG', audit_data['domwkg'])
	# overview = overview.replace('REPLACE_IPS', "<li>" + "</li><li>".join(audit_data['ips']) + "</li>")
	for item in audit_data['ips']:
		overview = overview.replace('REPLACE_IPS', list_item("REPLACE_IPS", item))
	overview = overview.replace('REPLACE_IPS', '')
	
	overview = overview.replace('REPLACE_OS', audit_data['os_name'] + " (" + audit_data['os_version'] + ")")
	
	overview = overview.replace('REPLACE_VERSION', audit_data['version'])
	overview = overview.replace('REPLACE_DATETIME', audit_data['datetime'])
	overview = overview.replace('REPLACE_AUDIT_USER', audit_data['audit_user'])
	
	for item in audit_data['trusted_users']:
		overview = overview.replace('REPLACE_TRUSTED_USERS', list_item("REPLACE_TRUSTED_USERS", item))
	overview = overview.replace('REPLACE_TRUSTED_USERS', '')
				
	for item in audit_data['trusted_groups']:
		overview = overview.replace('REPLACE_TRUSTED_GROUPS', list_item("REPLACE_TRUSTED_GROUPS", item))
	overview = overview.replace('REPLACE_TRUSTED_GROUPS', '')

	permlist = ''
	for permtype in dangerous_perms_write.keys():
		permlist += "Permission type '" + permtype + "'<p>"
		permlist += "<ul>"
		for location in dangerous_perms_write[permtype].keys():
			for item in dangerous_perms_write[permtype][location]:
				permlist += "\t<li>" + item + "</li>"
		permlist += "</ul>"
				
	#for item in audit_data['dangerous_privs']:
	#	overview = overview.replace('REPLACE_DANGEROUS_PERM', list_item("REPLACE_DANGEROUS_PERM", item))
	#overview = overview.replace('REPLACE_DANGEROUS_PERM', '')
	overview = overview.replace('REPLACE_DANGEROUS_PERMS', permlist)

	for item in audit_data['ips']:
		overview = overview.replace('REPLACE_IP', list_item("REPLACE_IPS", item))
	overview = overview.replace('REPLACE_IP', '')

	for issue_no in issue_data:
		# print "[V] Processing issue issue_no\n"
		report = report + format_issue(format, issue_no, issue_data, issue_template)
		toc = toc + '<a href="#' + issue_template[issue_no]['title'] + '">' + issue_template[issue_no]['title'] + "</a><p>"

	if report:
		overview = overview.replace('REPLACE_ISSUES', report)
		overview = overview.replace('REPLACE_CONTENTS', toc)
	else:
		overview = overview.replace('REPLACE_ISSUES', "No issues found")
		overview = overview.replace('REPLACE_CONTENTS', "No issues found")

	return overview

def list_item(tag, item):
	return "<li>" + item + "</li>\n" + tag

def format_issue(format, issue_no, issue_data, issue_template): # $format is xml, html, or text
	if not issue_no in issue_template:
		print "[E] Can't find an issue template for issue number issue_no.  Bug!"
		sys.exit(1)
	
	issue = issue_template_html
	issue = issue.replace('REPLACE_TITLE', '<a name="' + issue_template[issue_no]['title'] + '">' + issue_template[issue_no]['title'] + '</a>')
	description = issue_template[issue_no]['description']
	description = description.replace('\n\n+', "<p>\n")
	for key in issue_data[issue_no]:
		#print "[D] Processing data for %s" % key
		
		# print "[D] $key has type issue_data[issue_no]['$key']['type']\n"
		#if issue_data[issue_no][key]['type'] == "list":
		# TODO alter data structre to include type
		#section = issue_template[issue_no]['supporting_data'][key]['section']
		# print "[D] Data belongs to section section\n"
		#if (section == "description"):
		preamble = issue_template[issue_no]['supporting_data'][key]['preamble']
		data = issue_list_html
		data = data.replace('REPLACE_PREAMBLE', preamble)
		for item in issue_data[issue_no][key]:
			# TODO alter data structure to include data
			# print "Processing item " + item
			perm_string = " ".join(issue_data[issue_no][key][item])
			data = data.replace('REPLACE_ITEM', list_item("REPLACE_ITEM", item + ": " + perm_string))
		
		data = data.replace('REPLACE_ITEM', '')
		issue = issue.replace('REPLACE_DESCRIPTION_DATA', data + "\nREPLACE_DESCRIPTION_DATA")
		#elif section == "recommendation":
		#	pass
			#issue = issue.replace('REPLACE_RECOMMENDATION_DATA', "data\nREPLACE_DESCRIPTION_DATA', 

	issue = issue.replace('REPLACE_RECOMMENDATION_DATA', '')
	issue = issue.replace('REPLACE_DESCRIPTION_DATA', '')
	issue = issue.replace('REPLACE_DESCRIPTION', description + "<p>\n")
	recommendation = issue_template[issue_no]['recommendation']
	issue = issue.replace('REPLACE_RECOMMENDATION', recommendation + "<p>\n")
	recommendation = recommendation.replace('\n\n+', '<p>\n')
	return issue

def format_audit_data(format, audit_data): # $format is xml, html, or text
	print "format_audit_data not implemented yet"

# Inputs:
#   string: issue_name
#   array:  weak_perms
def save_issue(issue_name, data_type, weak_perms):
	#print weak_perms
	global issues
	if not issue_name in issues:
		issues[issue_name] = {}
	#if not 'supporting_data' in issues[issue_name]:
	#	issues[issue_name]['supporting_data'] = {}
	for weak_perm in weak_perms:
		object = weak_perm[0]
		domain = weak_perm[1]
		name = weak_perm[2]
		permission = weak_perm[3]
		key = object + " has the following permissions granted for " + domain + "\\" + name
		if not data_type in issues[issue_name]:
			issues[issue_name][data_type]= {}
		if not key in issues[issue_name][data_type]:
			issues[issue_name][data_type][key] = []
		issues[issue_name][data_type][key].append(permission)
		issues[issue_name][data_type][key] = list(set(issues[issue_name][data_type][key])) # dedup

def save_issue_string(issue_name, data_type, issue_string):
	#print weak_perms
	global issues
	if not issue_name in issues:
		issues[issue_name] = {}
	if not data_type in issues[issue_name]:
		issues[issue_name][data_type]= {}
	if not issue_string in issues[issue_name][data_type]:
		issues[issue_name][data_type][issue_string] = []

# args: string, string
# Returns 1 if the principle provided is trusted (admin / system / user-definted trusted principle)
# Returns 0 otherwise
def principle_is_trusted(principle, domain):
	
	if domain + "\\" + principle in trusted_principles_fq:
		return 1
	
	if principle in trusted_principles:
		return 1
	
	global tmp_trusted_principles_fq
	if domain + "\\" + principle in tmp_trusted_principles_fq:
		return 1

	# Consider groups with zero members to be trusted too
	try:
		memberdict, total, rh = win32net.NetLocalGroupGetMembers(remote_server, principle , 1 , 0 , 100000 )
		if len(memberdict) == 0:
			return 1
	except:
		# If a user is a member of a trusted group (like administrators), then they are trusted
		try:
			group_attrs = win32net.NetUserGetLocalGroups(remote_server, principle)
			if set(group_attrs).intersection(set(trusted_principles)):
				return 1
		except:
			pass
			
	return 0

#	for memberinfo in memberdict:
#		print "\t" + memberinfo['name'] + " (" + win32security.ConvertSidToStringSid(memberinfo['sid']) + ")"
# TODO ignore groups that only contain administrators
	
# There are all possible objects.  SE_OBJECT_TYPE (http://msdn.microsoft.com/en-us/library/aa379593(VS.85).aspx):
#  win32security.SE_UNKNOWN_OBJECT_TYPE
#  win32security.SE_FILE_OBJECT
#  win32security.SE_SERVICE
#  win32security.SE_PRINTER
#  win32security.SE_REGISTRY_KEY
#  win32security.SE_LMSHARE
#  win32security.SE_KERNEL_OBJECT
#  win32security.SE_WINDOW_OBJECT
#  win32security.SE_DS_OBJECT
#  win32security.SE_DS_OBJECT_ALL
#  win32security.SE_PROVIDER_DEFINED_OBJECT
#  win32security.SE_WMIGUID_OBJECT
#  win32security.SE_REGISTRY_WOW64_32KEY
# object_type_s is one of
#  service
#  file
#  dir
def check_weak_perms(object_name, object_type_s, perms):
	object_type = None
	if object_type_s == 'file':
		object_type = win32security.SE_FILE_OBJECT
	if object_type_s == 'directory':
		object_type = win32security.SE_FILE_OBJECT
	if object_type_s == 'service':
		object_type = win32security.SE_SERVICE
	
	if object_type == win32security.SE_FILE_OBJECT:
#		if not os.path.exists(object_name):
#			print "WARNING: %s doesn't exist" % object_name
			
		if os.path.isfile(object_name):
			object_type_s = 'file'
		else:
			object_type_s = 'directory'
	
	if object_type == None:
		print "ERROR: Unknown object type %s" % object_type_s
		exit(1)
		
	try: 
		sd = win32security.GetNamedSecurityInfo (
			object_name,
			object_type,
			win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
		)
	except:
		# print "WARNING: Can't get security descriptor for " + object_name + ".  skipping.  (" + details[2] + ")"
		return []
	
	return check_weak_perms_sd(object_name, object_type_s, sd, perms)

def check_weak_write_perms_by_sd(object_name, object_type_s, sd):
	return check_weak_perms_sd(object_name, object_type_s, sd, dangerous_perms_write)
	
def check_weak_perms_sd(object_name, object_type_s, sd, perms):
	dacl= sd.GetSecurityDescriptorDacl()
	if dacl == None:
		print "No Discretionary ACL"
		return []

	owner_sid = sd.GetSecurityDescriptorOwner()
	try:
		owner_name, owner_domain, type = win32security.LookupAccountSid(remote_server, owner_sid)
		owner_fq = owner_domain + "\\" + owner_name
	except:
		try:
			owner_fq = owner_name = win32security.ConvertSidToStringSid(owner_sid)
			owner_domain = ""
		except:
			owner_domain = ""
			owner_fq = owner_name = "INVALIDSID!"

	weak_perms = []
	for ace_no in range(0, dacl.GetAceCount()):
		#print "[D] ACE #%d" % ace_no
		ace = dacl.GetAce(ace_no)
		flags = ace[0][1]
		
		try:
			principle, domain, type = win32security.LookupAccountSid(remote_server, ace[2])
		except:
			principle = win32security.ConvertSidToStringSid(ace[2])
			domain = ""
		
		#print "[D] ACE is for %s\\%s" % (principle, domain)
		#print "[D] ACE Perm mask: " + int2bin(ace[1])
		#print "[D] ace_type: " + str(ace[0][0])
		#print "[D] DACL: " + win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
		if principle_is_trusted(principle, domain):
			#print "[D] Ignoring trusted principle %s\\%s" % (principle, domain)
			continue
		
		if principle == "CREATOR OWNER":
			if principle_is_trusted(owner_name, owner_domain):
				continue
			else:
				principle = "CREATOR OWNER [%s]" % owner_fq
		
		for i in ("ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE", "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
			if getattr(ntsecuritycon, i) == ace[0][0]:
				ace_type_s = i
		
		if not ace_type_s == "ACCESS_ALLOWED_ACE_TYPE":
			vprint("WARNING: Unimplmented ACE type encountered: " + ace_type_s + ".  skipping.")
			continue

		for mod, perms_tuple in perms[object_type_s].iteritems():
			for perm in perms_tuple:
				if getattr(mod, perm) & ace[1] == getattr(mod, perm):
					weak_perms.append([object_name, domain, principle, perm])
	return weak_perms

def dump_perms(object_name, object_type_s, options={}):
	object_type = None
	if object_type_s == 'file':
		object_type = win32security.SE_FILE_OBJECT
	if object_type_s == 'directory':
		object_type = win32security.SE_FILE_OBJECT
	if object_type_s == 'service':
		object_type = win32security.SE_SERVICE
	
	if object_type == win32security.SE_FILE_OBJECT:
#		if not os.path.exists(object_name):
#			print "WARNING: %s doesn't exist" % object_name
			
		if os.path.isfile(object_name):
			object_type_s = 'file'
		else:
			object_type_s = 'directory'
	
	if object_type == None:
		print "ERROR: Unknown object type %s" % object_type_s
		exit(1)
		
	try: 
		sd = win32security.GetNamedSecurityInfo (
			object_name,
			object_type,
			win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
		)
	except:
		# print "WARNING: Can't get security descriptor for " + object_name + ".  skipping.  (" + details[2] + ")"
		return []
	
	return dump_sd(object_name, object_type_s, sd, options)

def dump_sd(object_name, object_type_s, sd, options={}):
	perms = all_perms
	if not sd:
		return 
	dacl = sd.GetSecurityDescriptorDacl()
	if dacl == None:
		print "No Discretionary ACL"
		return []

	owner_sid = sd.GetSecurityDescriptorOwner()

	try:
		owner_name, owner_domain, type = win32security.LookupAccountSid(remote_server, owner_sid)
		owner_fq = owner_domain + "\\" + owner_name
	except:
		try:
			owner_fq = owner_name = win32security.ConvertSidToStringSid(owner_sid)
			owner_domain = ""
		except:
			owner_domain = ""
			owner_fq = owner_name = None

	group_sid = sd.GetSecurityDescriptorGroup()
	try:
		group_name, group_domain, type = win32security.LookupAccountSid(remote_server, group_sid)
		group_fq = group_domain + "\\" + group_name
	except:
		try:
			group_fq = group_name = win32security.ConvertSidToStringSid(group_sid)
			group_domain = ""
		except:
			group_domain = ""
			group_fq = group_name = "[none]"

	if owner_info:
		print "\tOwner: " + str(owner_fq)
		print "\tGroup: " + str(group_fq)
		
	weak_perms = []
	dump_acl(object_name, object_type_s, dacl, options)
	return
	
def dump_acl(object_name, object_type_s, sd, options={}):
	dacl = sd
	if dacl == None:
		print "No Discretionary ACL"
		return []

	weak_perms = []
	for ace_no in range(0, dacl.GetAceCount()):
		# print "[D] ACE #%d" % ace_no
		ace = dacl.GetAce(ace_no)
		flags = ace[0][1]
		
		try:
			principle, domain, type = win32security.LookupAccountSid(remote_server, ace[2])
		except:
			principle = win32security.ConvertSidToStringSid(ace[2])
			domain = ""
		
		mask = ace[1]
		if ace[1] < 0:
			mask = ace[1] + 2**32

		if ignore_trusted and principle_is_trusted(principle, domain):
			# print "[D] Ignoring trusted principle %s\\%s" % (principle, domain)
			continue
		
		if principle == "CREATOR OWNER":
			if ignore_trusted and principle_is_trusted(owner_name, owner_domain):
				#print "[D] Ignoring trusted principle (creator owner) %s\\%s" % (principle, domain)
				continue
			else:
				principle = "CREATOR OWNER [%s\%s]" % (domain, principle)
		
		for i in ("ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE", "SYSTEM_AUDIT_ACE_TYPE", "SYSTEM_ALARM_ACE_TYPE"):
			if getattr(ntsecuritycon, i) == ace[0][0]:
				ace_type_s = i
		
		ace_type_short = ace_type_s
		
		if ace_type_s == "ACCESS_DENIED_ACE_TYPE":
			ace_type_short = "DENY"
		
		if ace_type_s == "ACCESS_ALLOWED_ACE_TYPE":
			ace_type_short = "ALLOW"

		if weak_perms_only:
			perms = dangerous_perms_write
		else:
			perms = all_perms
			
		for mod, perms_tuple in perms[object_type_s].iteritems():
			for perm in perms_tuple:
				#print "Checking for perm %s in ACE %s" % (perm, mask)
				if getattr(mod, perm) & mask == getattr(mod, perm):
					weak_perms.append([object_name, domain, principle, perm, ace_type_short])
	print_weak_perms(object_type_s, weak_perms, options)

def check_weak_write_perms(object_name, object_type_s):
	return check_weak_perms(object_name, object_type_s, dangerous_perms_write)

def check_registry():
	for key_string in reg_paths:
		parts = key_string.split("\\")
		hive = parts[0]
		key_string = "\\".join(parts[1:])
		try:
			keyh = win32api.RegOpenKeyEx(getattr(win32con, hive), key_string, 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
		except:
			#print "Can't open: " + hive + "\\" + key_string
			continue
		
		sd = win32api.RegGetKeySecurity(keyh, win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
		weak_perms = check_weak_write_perms_by_sd(hive + "\\" + key_string, 'reg', sd)
		if weak_perms:
			vprint(hive + "\\" + key_string)
			#print weak_perms
			if verbose == 0:
				sys.stdout.write(".")
			save_issue("WPC003", "writable_reg_paths", weak_perms)
			# print_weak_perms("x", weak_perms)
	print

# TODO save_issue("WPC009", "writable_eventlog_key", weak_perms)  # weak perms on event log reg key
def check_event_logs():
	key_string = "HKEY_LOCAL_MACHINE\\" + eventlog_key_hklm
	try:
		keyh = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, eventlog_key_hklm , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
	except:
		print "Can't open: " + key_string
		return 0
		
	subkeys = win32api.RegEnumKeyEx(keyh)
	for subkey in subkeys:
		# print key_string + "\\" + subkey[0]
		sys.stdout.write(".")
		try:
			subkeyh = win32api.RegOpenKeyEx(keyh, subkey[0] , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
		except:
			print "Can't open: " + key_string
		else:
			subkey_count, value_count, mod_time = win32api.RegQueryInfoKey(subkeyh)
			# print "\tChild Nodes: %s subkeys, %s values" % (subkey_count, value_count)
			
			try:
				filename, type = win32api.RegQueryValueEx(subkeyh, "DisplayNameFile")
			except:
				pass
			else:
				weak_perms = check_weak_write_perms(os.path.expandvars(filename), 'file')
				if weak_perms:
					# print "------------------------------------------------"
					# print "Weak permissions found on event log display DLL:"
					# print_weak_perms("File", weak_perms)
					sys.stdout.write("!")
					save_issue("WPC008", "writable_eventlog_dll", weak_perms)
				
			try:
				filename, type = win32api.RegQueryValueEx(subkeyh, "File")
			except:
				pass
			else:
				weak_perms = check_weak_write_perms(os.path.expandvars(filename), 'file')
				if weak_perms:
					# print "------------------------------------------------"
					# print "Weak permissions found on event log file:"
					# print_weak_perms("File", weak_perms)
					sys.stdout.write("!")
					save_issue("WPC007", "writable_eventlog_file", weak_perms)
	print
		#sd = win32api.RegGetKeySecurity(subkeyh, win32security.DACL_SECURITY_INFORMATION) # TODO: get owner too?
		#print "\tDACL: " + win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)

def get_extra_privs():
	# Try to give ourselves some extra privs (only works if we're admin):
	# SeBackupPrivilege   - so we can read anything
	# SeDebugPrivilege    - so we can find out about other processes (otherwise OpenProcess will fail for some)
	# SeSecurityPrivilege - ??? what does this do?
	
	# Problem: Vista+ support "Protected" processes, e.g. audiodg.exe.  We can't see info about these.
	# Interesting post on why Protected Process aren't really secure anyway: http://www.alex-ionescu.com/?p=34
	
	th = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
	privs = win32security.GetTokenInformation(th, TokenPrivileges)
	newprivs = []
	for privtuple in privs:
		if privtuple[0] == win32security.LookupPrivilegeValue(remote_server, "SeBackupPrivilege") or privtuple[0] == win32security.LookupPrivilegeValue(remote_server, "SeDebugPrivilege") or privtuple[0] == win32security.LookupPrivilegeValue(remote_server, "SeSecurityPrivilege"):
			print "Added privilege " + str(privtuple[0])
			# privtuple[1] = 2 # tuples are immutable.  WHY?!
			newprivs.append((privtuple[0], 2)) # SE_PRIVILEGE_ENABLED
		else:
			newprivs.append((privtuple[0], privtuple[1]))
				
	# Adjust privs
	privs = tuple(newprivs)
	str(win32security.AdjustTokenPrivileges(th, False , privs))
		
def audit_processes():
	get_extra_privs()
	# Things we might want to know about a process:
	# TCP/UDP/Local sockets
	# Treads - and the tokens of each (API doesn't support getting a thread handle!)
	# Shared memory
	
	pids = win32process.EnumProcesses()
	for pid in sorted(pids):
		print "---------------------------------------------------------"
		print "PID: %s" % pid
		# TODO there's a security descriptor for each process accessible via GetSecurityInfo according to http://msdn.microsoft.com/en-us/library/ms684880%28VS.85%29.aspx
		
		ph = 0
		gotph = 0
		try:
			# PROCESS_VM_READ is required to list modules (DLLs, EXE)
			ph = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
			gotph = 1
			vprint("OpenProcess with VM_READ and PROCESS_QUERY_INFORMATION: Success")
		except:
			print("OpenProcess with VM_READ and PROCESS_QUERY_INFORMATION: Failed")
			try:
				# We can still get some info without PROCESS_VM_READ
				ph = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION , False, pid)
				gotph = 1
				vprint("OpenProcess with PROCESS_QUERY_INFORMATION: Success")
			except:
				print "OpenProcess with PROCESS_QUERY_INFORMATION: Failed"
				try:
					# If we have to resort to using PROCESS_QUERY_LIMITED_INFORMATION, the process is protected.
					# There's no point trying PROCESS_VM_READ
					ph = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION , False, pid)
					gotph = 1
					vprint("OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION: Success")
				except:
					print "OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION: Failed"
					# Move onto the next process.  We don't have a process handle!
					
		exe = "[unknown]"	
		gotexe = 0
		mhs = 0
		try:
			mhs = win32process.EnumProcessModules(ph)
			mhs = list(mhs)
			exe = win32process.GetModuleFileNameEx(ph, mhs.pop(0))
			gotexe = 1
		except:
			pass
		print "Filename: %s" % exe
			
		gottokenh = 0
		
		try:
			tokenh = win32security.OpenProcessToken(ph, win32con.TOKEN_QUERY)
			gottokenh = 1
			
			sidObj, intVal = win32security.GetTokenInformation(tokenh, TokenUser)
			if sidObj:
				accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sidObj)
				print "TokenUser: %s\%s (type %s)" % (domainName, accountName, accountTypeInt) 
			
			sidObj =  win32security.GetTokenInformation(tokenh, TokenOwner)
			if sidObj:
				accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sidObj)
				print "TokenOwner: %s\%s (type %s)" % (domainName, accountName, accountTypeInt) 
				
			sidObj =  win32security.GetTokenInformation(tokenh, TokenPrimaryGroup)
			if sidObj:
				accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sidObj)
				print "TokenPrimaryGroup: %s\%s (type %s)" % (domainName, accountName, accountTypeInt) 
		except:
			print "OpenProcessToken with TOKEN_QUERY: Failed"
			print "TokenUser: Unknown"
			print "TokenOwner: Unknown"
			print "TokenPrimaryGroup: Unknown"
			pass
			
		user = "unknown\\unknown"
		
		# TODO I'm not sure how to interogate threads.
		# There's no OpenThread() in win32api.  I need a thread handle before I can get Thread Tokens.
		# The code below lists threadid's, be we can't use the handle (it's not a PyHandle)
		#
		# hThreadSnap = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, pid)
		# if hThreadSnap == INVALID_HANDLE_VALUE:
			# print "Failed to get Thread snapshot"
		# else:
			# te32 = Thread32First (hThreadSnap)
			# if te32:
				# while True:
					# if te32.th32OwnerProcessID == pid:
						# hThread = OpenThread (win32con.THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID)
						# print "PID %s, ThreadID %s" % (pid, te32.th32ThreadID)
						# print "Priority: " + str(win32process.GetThreadPriority(hThread))
						# CloseHandle (hThread)
					# te32 = Thread32Next (hThreadSnap)
					# if not te32:
						 # break
			# CloseHandle (hThreadSnap)

#		except:
#			print "EnumProcessModules: Failed"
			# continue
		# print "EnumProcessModules: Success"
		
		if ph:
			print "IsWow64 Process: %s" % win32process.IsWow64Process(ph)
		
		if gottokenh:
			vprint("OpenProcessToken with TOKEN_QUERY: Success")
			imp_levels = {
				"SecurityAnonymous": 0,
				"SecurityIdentification": 1,
				"SecurityImpersonation": 2,
				"SecurityDelegation": 3
			}
			#for ilevel in imp_levels.keys():
				#sys.stdout.write("Trying DuplicateToken with " + ilevel)
				#try:
					#win32security.DuplicateToken(tokenh, imp_levels[ilevel])
					#print "success"
				#except:
					#print "failed"
			tokentype =  win32security.GetTokenInformation(tokenh, TokenType)
			tokentype_str = "TokenImpersonation"
			if tokentype == 1:
				tokentype_str = "TokenPrimary"
			print "Token Type: " + tokentype_str
			print "Logon Session ID: " + str(win32security.GetTokenInformation(tokenh, TokenOrigin))
			try: 
				source = win32security.GetTokenInformation(tokenh, TokenSource)
				print "Token Source: " + source
			except:
				print "Token Source: Unknown (Access Denied)"
				
			try:
				print "TokenImpersonationLevel: %s" % win32security.GetTokenInformation(tokenh, TokenImpersonationLevel) # doesn't work on xp
			except:
				pass
			
			try:
				r = win32security.GetTokenInformation(tokenh, TokenHasRestrictions) # doesn't work on xp
				if r == 0:
					print "TokenHasRestrictions: 0 (not filtered)"
				else:
					print "TokenHasRestrictions: %s (token has been filtered)" % r
			except:
				pass
			
			try:
				e = win32security.GetTokenInformation(tokenh, TokenElevationType) # vista
				if e == 1:
					print "TokenElevationType: TokenElevationTypeDefault"
				elif e == 2:
					print "TokenElevationType: TokenElevationTypeFull"
				elif e == 3:
					print "TokenElevationType: TokenElevationTypeLimited"
				else:
					print "TokenElevationType: Unknown (%s)" % e
			except:
				pass
				
			try:
				print "TokenUIAccess: %s" % win32security.GetTokenInformation(tokenh, TokenUIAccess) # doesn't work on xp
			except:
				pass
			
			try:
				print "TokenLinkedToken: %s" % win32security.GetTokenInformation(tokenh, TokenLinkedToken) # vista
			except:
				pass
			
			try:
				print "TokenLogonSid: %s" % win32security.GetTokenInformation(tokenh, TokenLogonSid) # doesn't work on xp
				print "TokenElevation: %s" % win32security.GetTokenInformation(tokenh, TokenElevation) # vista
			except:
				pass
			
			try:
				sid, i =  win32security.GetTokenInformation(tokenh, TokenIntegrityLevel) # vista
				try:
					accountName, domainName, accountTypeInt = win32security.LookupAccountSid(None, sid)
					user = domainName + "\\" + accountName + " (" + win32security.ConvertSidToStringSid(sid) + ")"
				except:
					user = win32security.ConvertSidToStringSid(sid)
				print "TokenIntegrityLevel: %s %s" % (user, i)
			except:
				pass
			
			try:
				m = win32security.GetTokenInformation(tokenh, TokenMandatoryPolicy) # vista
				if m == 0:
					print "TokenMandatoryPolicy: OFF"
				elif m == 1:
					print "TokenMandatoryPolicy: NO_WRITE_UP"
				elif m == 2:
					print "TokenMandatoryPolicy: NEW_PROCESS_MIN"
				elif m == 3:
					print "TokenMandatoryPolicy: POLICY_VALID_MASK"
				else:
					print "TokenMandatoryPolicy: %s" % m
			except:
				pass
			
			print "Token Resitrcted Sids: " + str(win32security.GetTokenInformation(tokenh, TokenRestrictedSids))
			print "IsTokenRestricted: " + str(win32security.IsTokenRestricted(tokenh))
			print "\nToken Groups: "
			for tup in win32security.GetTokenInformation(tokenh, TokenGroups):
				sid = tup[0]
				attr = tup[1]
				attr_str = attr
				if attr < 0:
					attr = 2**32 + attr
				attr_str_a = []
				if attr & 1:
					# attr_str_a.append("SE_GROUP_MANDATORY")
					attr_str_a.append("MANDATORY")
				if attr & 2:
					# attr_str_a.append("SE_GROUP_ENABLED_BY_DEFAULT")
					attr_str_a.append("ENABLED_BY_DEFAULT")
				if attr & 4:
					# attr_str_a.append("SE_GROUP_ENABLED")
					attr_str_a.append("ENABLED")
				if attr & 8:
					# attr_str_a.append("SE_GROUP_OWNER")
					attr_str_a.append("OWNER")
				if attr & 0x40000000:
					# attr_str_a.append("SE_GROUP_LOGON_ID")
					attr_str_a.append("LOGON_ID")
				attr_str = ("|".join(attr_str_a))
				try:
					accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sid)
					user = domainName + "\\" + accountName + " (" + win32security.ConvertSidToStringSid(sid) + ")"
				except:
					user = win32security.ConvertSidToStringSid(sid)
				print "\t%s: %s" % (user, attr_str)
			# Link that explains how privs are added / removed from tokens:
			# http://support.microsoft.com/kb/326256
			print "\nToken Privileges:"
			privs = win32security.GetTokenInformation(tokenh, TokenPrivileges)
			for priv_tuple in privs:
				priv_val = priv_tuple[0]
				attr = priv_tuple[1]
				attr_str = "unknown_attr(" + str(attr) + ")"
				attr_str_a = []
				if attr == 0:
					attr_str_a.append("[disabled but not removed]")
				if attr & 1:
					# attr_str_a.append("SE_PRIVILEGE_ENABLED_BY_DEFAULT")
					attr_str_a.append("ENABLED_BY_DEFAULT")
				if attr & 2:
					# attr_str_a.append("SE_PRIVILEGE_ENABLED")
					attr_str_a.append("ENABLED")
				if attr & 0x80000000:
					# attr_str_a.append("SE_PRIVILEGE_USED_FOR_ACCESS")
					attr_str_a.append("USED_FOR_ACCESS")
				if attr & 4:
					# attr_str_a.append("SE_PRIVILEGE_REMOVED")
					attr_str_a.append("REMOVED")
				if attr_str_a:
					attr_str = ("|").join(attr_str_a)
				print "\t%s: %s" % (win32security.LookupPrivilegeName(remote_server, priv_val), attr_str)
			
			
			#print "\nProcess ACL (buggy - probably wrong):"
			#dump_acl(pid, 'process', win32security.GetTokenInformation(tokenh, TokenDefaultDacl), {'brief': 1}) # TODO can't understand ACL
			# sidObj = win32security.GetTokenInformation(tokenh, TokenOwner) # Owner returns "Administrators" instead of SYSTEM.  It's not what we want.
			# if sidObj:
				# accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sidObj)
				# print "User: %s\%s (type %s)" % (domainName, accountName, accountTypeInt) 				
		if gotexe:
			print "\nFile permissions on %s:" % exe
			dump_perms(exe, 'file', {'brief': 1})
			print
			
		if mhs and ph:	
			for mh in mhs:
				dll = win32process.GetModuleFileNameEx(ph, mh)
				print "Loaded module: %s" % dll
				dump_perms(dll, 'file', {'brief': 1})

	print
		
		
def check_processes():
	pids = win32process.EnumProcesses()
	# TODO also check out WMI.  It might not be running, but it could help if it is:  
	#      http://groups.google.com/group/comp.lang.python/browse_thread/thread/1f50065064173ccb
	# TODO process explorer can find quite a lot more information than this script.  This script has several problems:
	# TODO I can't open 64-bit processes for a 32-bit app.  I get this error:
	# ERROR: can't open 6100: 299 EnumProcessModules, Only part of a ReadProcessMemory
	#        or WriteProcessMemory request was completed.
	# TODO I can't seem to get the name of elevated processes (user running as me, but with admin privs)
	# TODO I can't get details of certain processes runnign as SYSTEM on xp (e.g. pid 4 "system", csrss.exe)
	# TODO should be able to find name (and threads?) for all processes.  Not necessarily path.

	for pid in sorted(pids):
		# TODO there's a security descriptor for each process accessible via GetSecurityInfo according to http://msdn.microsoft.com/en-us/library/ms684880%28VS.85%29.aspx
		# TODO could we connect with PROCESS_QUERY_LIMITED_INFORMATION instead on Vista+
		try:
			ph = win32api.OpenProcess(win32con.PROCESS_VM_READ | win32con.PROCESS_QUERY_INFORMATION , False, pid)
		except:
			# print "ERROR: can't connected to PID " + str(pid)
			sys.stdout.write("?")
			continue
		else:
			user = "unknown\\unknown"
			try:
				tokenh = win32security.OpenProcessToken(ph, win32con.TOKEN_QUERY)
			except:
				pass
			else:
				sidObj, intVal = win32security.GetTokenInformation(tokenh, TokenUser)
				#source = win32security.GetTokenInformation(tokenh, TokenSource)
				if sidObj:
					accountName, domainName, accountTypeInt = win32security.LookupAccountSid(remote_server, sidObj)
					# print "pid=%d accountname=%s domainname=%s wow64=%s" % (pid, accountName, domainName, win32process.IsWow64Process(ph))
					user = domainName + "\\" + accountName

			# print "PID %d is running as %s" % (pid, user)
			sys.stdout.write(".")
			try:
				mhs = win32process.EnumProcessModules(ph)
				# print mhs
			except:
				continue
			
			mhs = list(mhs)
			exe = win32process.GetModuleFileNameEx(ph, mhs.pop(0))
			weak_perms = check_weak_write_perms(exe, 'file')
			# print_weak_perms("PID " + str(pid) + " running as " + user + ":", weak_perms)
			if weak_perms:
				save_issue("WPC016", "weak_perms_exes", weak_perms)
				sys.stdout.write("!")
				
			for mh in mhs:
				# print "PID %d (%s) has loaded module: %s" % (pid, exe, win32process.GetModuleFileNameEx(ph, mh))
				dll = win32process.GetModuleFileNameEx(ph, mh)
				weak_perms = check_weak_write_perms(dll, 'file')
				# print_weak_perms("DLL used by PID " + str(pid) + " running as " + user + " (" + exe + "):", weak_perms)
				if weak_perms:
					save_issue("WPC016", "weak_perms_dlls", weak_perms)
					sys.stdout.write("!")
	print
	
def check_services():
	sch = win32service.OpenSCManager(remote_server, None, win32service.SC_MANAGER_ENUMERATE_SERVICE )
	try:
		# TODO Haven't seen this work - even when running as SYSTEM
		sd = win32service.QueryServiceObjectSecurity(sch, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
		print check_weak_write_perms_by_sd("Service Manager", 'service_manager', sd)
	except: 
		pass
	
	# Need to connect to service (OpenService) with minimum privs to read DACL.  Here are our options:
	#
	# http://www.pinvoke.net/default.aspx/advapi32/OpenSCManager.html?diff=y
	# SC_MANAGER_ALL_ACCESS (0xF003F)	Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
	# SC_MANAGER_CREATE_SERVICE (0x0002)	Required to call the CreateService function to create a service object and add it to the database.
	# SC_MANAGER_CONNECT (0x0001)	Required to connect to the service control manager.
	# SC_MANAGER_ENUMERATE_SERVICE (0x0004)	Required to call the EnumServicesStatusEx function to list the services that are in the database.
	# SC_MANAGER_LOCK (0x0008)	Required to call the LockServiceDatabase function to acquire a lock on the database.
	# SC_MANAGER_MODIFY_BOOT_CONFIG (0x0020)	Required to call the NotifyBootConfigStatus function.
	# SC_MANAGER_QUERY_LOCK_STATUS (0x0010)Required to call the  QueryServiceLockStatus function to retrieve the lock status information for the database.
	# GENERIC_READ
	# GENERIC_WRITE
	# GENERIC_EXECUTE
	# GENERIC_ALL
	
	services = win32service.EnumServicesStatus(sch, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL )
	for service in services:
		try:
			sh = win32service.OpenService(sch, service[0] , win32service.SC_MANAGER_CONNECT )
			service_info = win32service.QueryServiceConfig(sh)
		except:
			print "WARNING: Can't open service " + service[0]
			continue
		
		try:
			sh = win32service.OpenService(sch, service[0] , win32con.GENERIC_READ )
			sd = win32service.QueryServiceObjectSecurity(sh, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
		except:
			# print "Service Perms: Unknown (Access Denied)"
			continue

		weak_perms = check_weak_write_perms_by_sd("Service \"" + service[1] + "\" (" + service[0] + ") which runs as user \"" + service_info[7] + "\"", 'service', sd)
		binary = None
		weak_perms_binary = []
		if not remote_server:
			binary = get_binary(service_info[3])
			if binary:
				weak_perms_binary = check_weak_write_perms(binary, 'file')
				

		if weak_perms or weak_perms_binary:
			vprint("---------------------------------------")
			vprint("Service:        " + service[0])
			vprint("Description:    " + service[1])
			vprint("Binary:         " + service_info[3])
			if binary:
				vprint("Binary (clean): " + binary)
			else:
				vprint("Binary (clean): [Missing Binary]")
			vprint("Run as:         " + service_info[7])
			vprint("Weak Perms: ")
			# service_info = win32service.QueryServiceConfig2(sh, win32service.SERVICE_CONFIG_DESCRIPTION) # long description of service.  not interesting.
			# print "Service Perms: " + win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, 	win32security.DACL_SECURITY_INFORMATION)
			print_weak_perms("file", weak_perms_binary)
			if weak_perms_binary:
				save_issue("WPC004", "writable_progs", weak_perms_binary)
					
		print_weak_perms("service", weak_perms)
		if weak_perms:
			save_issue("WPC012", "weak_service_perms", weak_perms)
			if verbose == 0:
				sys.stdout.write("!")
		else:
			if verbose == 0:
				sys.stdout.write(".")
	print

def audit_services():
	print
	sch = win32service.OpenSCManager(remote_server, None, win32service.SC_MANAGER_ENUMERATE_SERVICE )
	try:
		# TODO Haven't seen this work - even when running as SYSTEM
		sd = win32service.QueryServiceObjectSecurity(sch, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
		print check_weak_write_perms_by_sd("Service Manager", 'service_manager', sd)
	except: 
		#print "ERROR: Can't get security descriptor for service manager"
		pass
	
	# Need to connect to service (OpenService) with minimum privs to read DACL.  Here are our options:
	#
	# http://www.pinvoke.net/default.aspx/advapi32/OpenSCManager.html?diff=y
	# SC_MANAGER_ALL_ACCESS (0xF003F)	Includes STANDARD_RIGHTS_REQUIRED, in addition to all access rights in this table.
	# SC_MANAGER_CREATE_SERVICE (0x0002)	Required to call the CreateService function to create a service object and add it to the database.
	# SC_MANAGER_CONNECT (0x0001)	Required to connect to the service control manager.
	# SC_MANAGER_ENUMERATE_SERVICE (0x0004)	Required to call the EnumServicesStatusEx function to list the services that are in the database.
	# SC_MANAGER_LOCK (0x0008)	Required to call the LockServiceDatabase function to acquire a lock on the database.
	# SC_MANAGER_MODIFY_BOOT_CONFIG (0x0020)	Required to call the NotifyBootConfigStatus function.
	# SC_MANAGER_QUERY_LOCK_STATUS (0x0010)Required to call the  QueryServiceLockStatus function to retrieve the lock status information for the database.
	# GENERIC_READ
	# GENERIC_WRITE
	# GENERIC_EXECUTE
	# GENERIC_ALL
	
	services = win32service.EnumServicesStatus(sch, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL )
	for service in services:
		sh = win32service.OpenService(sch, service[0] , win32service.SC_MANAGER_CONNECT )
		service_info = win32service.QueryServiceConfig(sh)
		binary = None
		if remote_server:
			print "WARNING: Running agianst remote server.  Checking perms of .exe not implemented."
		else:
			binary = get_binary(service_info[3])
		print "---------------------------------------------------------------"
		print("Service:        " + service[0])
		print("Description:    " + service[1])
		print("Binary:         " + service_info[3])
		if binary:
			print("Binary (clean): " + binary)
		else:
			if remote_server:
				print("Binary (clean): [N/A Running remotely]")
			else:
				print("Binary (clean): [Missing Binary/Remote]")
		print("Run as:         " + service_info[7])
		
		print "\nFile Permissions on executable %s:" % binary
		if binary:
			dump_perms(binary, 'file', {'brief': 1})
		else:
			print "WARNING: Can't get full path of binary.  Skipping."
		
		print "\nPermissions on service:"

		try:
			sh = win32service.OpenService(sch, service[0] , win32con.GENERIC_READ )
		except:
			print "ERROR: OpenService failed"

		try:
			sd = win32service.QueryServiceObjectSecurity(sh, win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
		except:
			print "ERROR: QueryServiceObjectSecurity didn't get security descriptor for service"

		dump_sd("Service \"" + service[1] + "\" (" + service[0] + ") which runs as user \"" + service_info[7] + "\"", 'service', sd, {'brief': 1})
		
		print "\nPermissions on registry data:"
		print "WARNING: Not implmented yet"
		# service_info = win32service.QueryServiceConfig2(sh, win32service.SERVICE_CONFIG_DESCRIPTION) # long description of service.  not interesting.
		# print "Service Perms: " + win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)					
	print

def vprint(string):
	if (verbose):
		print string
		
def get_binary(binary_dirty):
	m = re.search('^[\s]*?"([^"]+)"', binary_dirty)
	
	if m and os.path.exists(m.group(1)):
		return m.group(1)
	else:
		if m:
			binary_dirty = m.group(1)
	
	chunks = binary_dirty.split(" ")
	candidate = ""
	for chunk in chunks:
		if candidate:
			candidate = candidate + " "
		candidate = candidate + chunk
		
		if os.path.exists(candidate) and os.path.isfile(candidate):
			return candidate
		if os.path.exists(candidate + ".exe") and os.path.isfile(candidate + ".exe"):
			return candidate + ".exe"
		global on64bitwindows
		if on64bitwindows:
			candidate2 = candidate.replace("system32", "syswow64")
			if os.path.exists(candidate2) and os.path.isfile(candidate2):
				return candidate2
			if os.path.exists(candidate2 + ".exe") and os.path.isfile(candidate2 + ".exe"):
				return candidate2 + ".exe"
		
	return None

def print_weak_perms(type, weak_perms, options={}):
	brief = 0
	if options:
		if options['brief']:
			brief = 1
	for perms in weak_perms:
		object_name = perms[0]	
		domain = perms[1]
		principle = perms[2]
		perm = perms[3]
		if len(perms) == 5:
			acl_type = perms[4]
			if acl_type == "ALLOW":
				acl_type = ""
			else:
				acl_type = acl_type + " "
		else:
			acl_type = ""
		slash = "\\"
		if domain == "":
			slash = ""
		
		if brief:
			print "\t%s%s%s%s: %s" % (acl_type, domain, slash, principle, perm)
		else:
			print "\t%s%s%s%s has permission %s on %s %s" % (acl_type, domain, slash, principle, perm, type, object_name)
			
def check_path(path, issue_no):
	dirs = set(path.split(';'))
	exts = ('exe', 'com', 'bat', 'dll') # TODO pl, rb, py, php, inc, asp, aspx, ocx, vbs, more?
	for dir in dirs:
		weak_flag = 0
		weak_perms = check_weak_write_perms(dir, 'directory')
		if weak_perms:
			save_issue(issue_no, "weak_perms_dir", weak_perms)
			print_weak_perms("Directory", weak_perms)
			weak_flag = 1
		for ext in exts:
			for file in glob.glob(dir + '\*.' + ext):
				#print "Processing " + file
				weak_perms = check_weak_write_perms(file, 'file')
				if weak_perms:
					save_issue(issue_no, "weak_perms_exe", weak_perms)
					print_weak_perms("File", weak_perms)
					weak_flag = 1
		if weak_flag == 1:
			sys.stdout.write("!")
		else:
			sys.stdout.write(".")

def get_user_paths():
	try:
		keyh = win32api.RegOpenKeyEx(win32con.HKEY_USERS, None , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
	except:
		return 0
	paths = []
	subkeys = win32api.RegEnumKeyEx(keyh)
	for subkey in subkeys:
		try:
			subkeyh = win32api.RegOpenKeyEx(keyh, subkey[0] + "\\Environment" , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
		except:
			pass
		else:
			subkey_count, value_count, mod_time = win32api.RegQueryInfoKey(subkeyh)
			
			try:
				path, type = win32api.RegQueryValueEx(subkeyh, "PATH")
				paths.append((subkey[0], path))
			except:
				pass
	return paths

def get_system_path():
	# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
	key_string = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
	try:
		keyh = win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, key_string , 0, win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | win32con.KEY_READ)
	except:
		return None
		
	try:
		path, type = win32api.RegQueryValueEx(keyh, "PATH")
		return path
	except:
		return None
				
#name=sys.argv[1]
#if not os.path.exists(name):
	#print name, "does not exist!"
	#sys.exit()


def check_user_paths():
	for user_path in get_user_paths():
		user_sid_s = user_path[0]
		try:
			user_sid  = win32security.ConvertStringSidToSid(user_sid_s)
			principle, domain, type = win32security.LookupAccountSid(remote_server, user_sid)
			user_fq = domain + "\\" + principle
		except:
			print "WARNING: Can't convert sid %s to name.  Skipping." % user_sid_s
			continue
	
		path = user_path[1]
		vprint("Checking path of %s" % user_fq)
		global tmp_trusted_principles_fq
		tmp_trusted_principles_fq = (user_fq)
		check_path(path, "WPC015")
		tmp_trusted_principles_fq = ()

def check_current_path():
	vprint("Checking current user's PATH")
	global tmp_trusted_principles_fq
	tmp_trusted_principles_fq = (os.environ['userdomain'] + "\\" + os.environ['username'])	
	check_path(os.environ['path'], "WPC014")
	tmp_trusted_principles_fq = ()
	
def check_system_path():
	vprint("Checking system PATH")
	check_path(get_system_path(), "WPC013")

def check_paths():
	check_system_path()
	check_current_path()
	check_user_paths()
	print

def check_drives():
	for drive in win32api.GetLogicalDriveStrings().split("\x00"):
		sys.stdout.write(".")
		type = win32file.GetDriveType(drive)
		if type == win32con.DRIVE_FIXED:
			fs = win32api.GetVolumeInformation(drive)[4]
			if fs == 'NTFS':
				warning = ""
				weak_perms = check_weak_write_perms(drive, 'directory')
				if weak_perms:
					# print "Weak permissions on drive root %s:" % drive
					# print_weak_perms('directory', weak_perms)
					sys.stdout.write(".")
					save_issue("WPC010", "writable_drive_root", weak_perms) 
			elif fs == 'FAT':
				save_issue_string("WPC011", "fat_fs_drives", "Fixed drive " + drive + ": has " + fs + " filesystem (FAT does not support file permissions)" )
				sys.stdout.write("!")
			elif fs == 'FAT32':
				save_issue_string("WPC011", "fat_fs_drives", "Fixed drive " + drive + ": has " + fs + " filesystem  (FAT32 does not support file permissions)" )
				sys.stdout.write("!")
			else:
				warning = " (not NTFS - might be insecure)"
				save_issue_string("WPC011", "fat_fs_drives", "Fixed drive " + drive + ": has " + fs + " filesystem (Not NTFS - might not be secure)" )
				sys.stdout.write("!")

				 
			# print "Fixed drive %s has %s filesystem%s" % (drive, fs, warning)
			
	print
	
def check_shares():
	resume = 0;
	try:
		(sharelist, total, resume) = win32net.NetShareEnum(None, 502, resume, 9999)
		for share in sharelist:
			sys.stdout.write(".")
			sd = share['security_descriptor']
			# print "%s (%s) %s type=%s" % (share['netname'], share['path'], share['remark'], share['type'])
			if sd:
				weak_perms = check_weak_write_perms_by_sd("Share \"" + share['netname'] + "\" (" + share['path'] + ") ", 'share', sd)
				if weak_perms:
					save_issue("WPC017", "non_admin_shares", weak_perms)
					sys.stdout.write("!")
	except:
		print "[E] Can't check shares - not enough privs?"

# TODO not option to call this yet
def audit_shares():	
	print 
	print "[+] Shares"
	print

	resume = 0;
	try:
		(sharelist, total, resume) = win32net.NetShareEnum(remote_server, 502, resume, 999999)
		#print win32net.NetShareGetInfo(remote_server, ?, 0) # do we need this?

		for share in sharelist:
			# Determine type of share
			types = []
			if share['type'] & getattr(win32netcon, "STYPE_SPECIAL"):
				# print "Share type: "
				types.append("STYPE_SPECIAL")
			share['type'] = share['type'] & 3 # mask off "special"
			#print share['type']
			for stype in share_types:
				if share['type'] == getattr(win32netcon, stype):
					types.append(stype)
					#print "Share type: " + stype
					break
			print "---------------"
			print "Share:        " + share['netname']
			print "Path:         " + share['path']
			print "Remark:       " + share['remark']
			print "Type(s):      " + "|".join(types)
			print "Reserved:     %s" % share['reserved']
			print "Passwd:       %s" % share['passwd']
			print "Current Uses: %s" % share['current_uses']
			print "Max Uses:     %s" % share['max_uses']
			print "Permissions:  %s" % share['permissions']
			print "Sec. Desc.:   " 
			dump_sd(share['netname'], 'share', share['security_descriptor'])
	except:
		print "[E] Couldn't get share information"
	
	print
	print "[+] Server Info (NetServerGetInfo 102)"
	print 
	
def check_progfiles():
	# %ProgramFiles%
	# %ProgramFiles(x86)%
	prog_dirs = []
#	re_exe = re.compile('\.exe$|\.com$|\.bat$|\.dll$', re.IGNORECASE)
	exts = ('exe', 'com', 'bat', 'dll') # TODO pl, rb, py, php, inc, asp, aspx, ocx, vbs, more?

	if os.getenv('ProgramFiles'):
		prog_dirs.append(os.environ['ProgramFiles'])

	if os.getenv('ProgramFiles(x86)'):
		prog_dirs.append(os.environ['ProgramFiles(x86)'])
	
	dot_count = 0
	weak_flag = 0
	for prog_dir in prog_dirs:
		# print "Looking for programs under %s..." % prog_dir
		for root, dirs, files in os.walk(prog_dir):
			#print "root=%s, dirs=%s, files=%s" % (root, dirs, files)
#			for file in files:
#				m = re_exe.search(file)
#				if m is None:
#					continue
#				#print "Checking file %s" % os.path.join(root, file)
#				weak_perms = check_weak_write_perms(os.path.join(root, file), 'file')
#				if weak_perms:
#					print_weak_perms("File", weak_perms)
			for file in dirs:
				#print "Checking dir %s" % os.path.join(root, file)
				weak_perms = check_weak_write_perms(os.path.join(root, file), 'file')
				if weak_perms:
					#print_weak_perms("Directory", weak_perms)
					save_issue("WPC001", "writable_dirs", weak_perms)
					weak_flag = 1
				dir = file
				for ext in exts:
					for f in glob.glob(root + "\\" + dir + '\*.' + ext):
						#print "Processing " + f
						weak_perms = check_weak_write_perms(f, 'file')
						if weak_perms:
							print_weak_perms("File", weak_perms)
							save_issue("WPC001", "writable_progs", weak_perms)
							weak_flag = 1
				dot_count = dot_count + 1;
				# Don't print out all the dots.  There are too many!
				if dot_count > 10:
					if weak_flag == 1:
						sys.stdout.write("!")
					else:
						sys.stdout.write(".")						
					dot_count = 0;
					weak_flag = 0;
	print

def check_patches():
# TODO: This is more difficult than I'd hoped.  You can't just search for the KB number: XP will appear to be vulnerable to dcom.  Need to search for KB number or SP2 in this case.
#	from subprocess import Popen, PIPE
	patchlist = Popen(["systeminfo"], stdout=PIPE).communicate()[0]
#	for kb_no in kb_nos:
#		print "Searching for " + kb_no
#		if re.search(kb_no, patchlist):
#			print "found"
		
	
def print_section(title):
	if (verbose != 0):
		print "================================="
		print title
		print "================================="
		print
	else:
		sys.stdout.write(title + ": ")

# http://www.daniweb.com/code/snippet216539.html
def int2bin(n):
	bStr = ''
	if n < 0: n = n + 2^32
	if n == 0: return '0'
	while n > 0:
		bStr = str(n % 2) + bStr
		n = n >> 1
	return bStr

def impersonate(username, password, domain):
	if username:
		print "Using alternative credentials:"
		print "Username: " + str(username)
		print "Password: " + str(password)
		print "Domain:   " + str(domain)
		handle = win32security.LogonUser( username, domain, password, win32security.LOGON32_LOGON_NEW_CREDENTIALS, win32security.LOGON32_PROVIDER_WINNT50 )
		win32security.ImpersonateLoggedOnUser( handle )
	else:
		print "Running as current user.  No logon creds supplied (-u, -d, -p)."
	print
	
def audit_passpol():
	print 
	print "[+] NetUserModalsGet 0,1,2,3"
	print
	
	try:
		data = win32net.NetUserModalsGet(remote_server, 0)
		for key in data.keys():
			print "%s: %s" % (key, data[key])
		data = win32net.NetUserModalsGet(remote_server, 1)
		for key in data.keys():
			print "%s: %s" % (key, data[key])
		data = win32net.NetUserModalsGet(remote_server, 2)
		for key in data.keys():
			if key == 'domain_id':
				print "%s: %s" % (key, win32security.ConvertSidToStringSid(data[key]))
			elif key == 'lockout_threshold' and data[key] == '0':
				print "%s: %s (accounts aren't locked out)" % (key, data[key])
			else:
				print "%s: %s" % (key, data[key])
		data = win32net.NetUserModalsGet(remote_server, 3)
		for key in data.keys():
			if key == 'lockout_threshold' and data[key] == 0:
				print "%s: %s (accounts aren't locked out)" % (key, data[key])
			else:
				print "%s: %s" % (key, data[key])
	except:
		print "[E] Couldn't get NetUserModals data"

# Recursive function to find group members (and the member of any groups in those groups...)
def get_group_members(server, group, depth):
		resume = 0
		indent = "\t" * depth
		members = []
		while True:
			try:
				m, total, resume = win32net.NetLocalGroupGetMembers(server, group, 2, resume, 999999)
			except:
				break
			for member in m:
				if member['sidusage'] == 4:
					type = "local group"
					g = member['domainandname'].split("\\")
					print indent + member['domainandname'] + " (" + str(type) + ")"
					get_group_members(server, g[1], depth + 1)
				elif member['sidusage'] == 2:
					type = "domain group"
					print indent + member['domainandname'] + " (" + str(type) + ")"
				elif member['sidusage'] == 1:
					type = "user"
					print indent + member['domainandname'] + " (" + str(type) + ")"
				else: 
					type = "type " + str(member['sidusage'])
					print indent + member['domainandname'] + " (" + str(type) + ")"
			if resume == 0:
				break
	
def audit_admin_users():
	print
	for group in ("administrators", "domain admins", "enterprise admins"):
		print "\n[+] Members of " + group + ":"
		get_group_members(remote_server, group, 0)
	print 

# It might be interesting to look up who has powerful privs, but LsaEnumerateAccountsWithUserRight doesn't seem to work as a low priv user
# SE_ASSIGNPRIMARYTOKEN_NAME TEXT("SeAssignPrimaryTokenPrivilege") Required to assign the primary token of a process. User Right: Replace a process-level token.
# SE_BACKUP_NAME TEXT("SeBackupPrivilege") Required to perform backup operations. This privilege causes the system to grant all read access control to any file, regardless of the access control list (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. This privilege is required by the RegSaveKey and RegSaveKeyExfunctions. The following access rights are granted if this privilege is held: READ_CONTROL ACCESS_SYSTEM_SECURITY FILE_GENERIC_READ FILE_TRAVERSE User Right: Back up files and directories.
# SE_CREATE_PAGEFILE_NAME TEXT("SeCreatePagefilePrivilege") Required to create a paging file. User Right: Create a pagefile.
# SE_CREATE_TOKEN_NAME TEXT("SeCreateTokenPrivilege") Required to create a primary token. User Right: Create a token object.
# SE_DEBUG_NAME TEXT("SeDebugPrivilege") Required to debug and adjust the memory of a process owned by another account. User Right: Debug programs.
# SE_ENABLE_DELEGATION_NAME TEXT("SeEnableDelegationPrivilege") Required to mark user and computer accounts as trusted for delegation. User Right: Enable computer and user accounts to be trusted for delegation.
# SE_LOAD_DRIVER_NAME TEXT("SeLoadDriverPrivilege") Required to load or unload a device driver. User Right: Load and unload device drivers.
# SE_MACHINE_ACCOUNT_NAME TEXT("SeMachineAccountPrivilege") Required to create a computer account. User Right: Add workstations to domain.
# SE_MANAGE_VOLUME_NAME TEXT("SeManageVolumePrivilege") Required to enable volume management privileges. User Right: Manage the files on a volume.
# SE_RELABEL_NAME TEXT("SeRelabelPrivilege") Required to modify the mandatory integrity level of an object. User Right: Modify an object label.
# SE_RESTORE_NAME TEXT("SeRestorePrivilege") Required to perform restore operations. This privilege causes the system to grant all write access control to any file, regardless of the ACL specified for the file. Any access request other than write is still evaluated with the ACL. Additionally, this privilege enables you to set any valid user or group SID as the owner of a file. This privilege is required by the RegLoadKey function. The following access rights are granted if this privilege is held: WRITE_DAC WRITE_OWNER ACCESS_SYSTEM_SECURITY FILE_GENERIC_WRITE FILE_ADD_FILE FILE_ADD_SUBDIRECTORY DELETE User Right: Restore files and directories.
# SE_SHUTDOWN_NAME TEXT("SeShutdownPrivilege") Required to shut down a local system. User Right: Shut down the system.
# SE_SYNC_AGENT_NAME TEXT("SeSyncAgentPrivilege") Required for a domain controller to use the LDAP directory synchronization services. This privilege enables the holder to read all objects and properties in the directory, regardless of the protection on the objects and properties. By default, it is assigned to the Administrator and LocalSystem accounts on domain controllers. User Right: Synchronize directory service data.
# SE_TAKE_OWNERSHIP_NAME TEXT("SeTakeOwnershipPrivilege") Required to take ownership of an object without being granted discretionary access. This privilege allows the owner value to be set only to those values that the holder may legitimately assign as the owner of an object. User Right: Take ownership of files or other objects.
# SE_TCB_NAME TEXT("SeTcbPrivilege") This privilege identifies its holder as part of the trusted computer base. Some trusted protected subsystems are granted this privilege. User Right: Act as part of the operating system.
# SE_TRUSTED_CREDMAN_ACCESS_NAME TEXT("SeTrustedCredManAccessPrivilege") Required to access Credential Manager as a trusted caller. User Right: Access Credential Manager as a trusted caller.

# Need: SE_ENABLE_DELEGATION_NAME, SE_MANAGE_VOLUME_NAME, SE_RELABEL_NAME, SE_SYNC_AGENT_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME
#	ph = win32security.LsaOpenPolicy(remote_server, win32security.POLICY_VIEW_LOCAL_INFORMATION | win32security.POLICY_LOOKUP_NAMES)
#	for priv in (SE_ASSIGNPRIMARYTOKEN_NAME, SE_BACKUP_NAME, SE_CREATE_PAGEFILE_NAME, SE_CREATE_TOKEN_NAME, SE_DEBUG_NAME, SE_LOAD_DRIVER_NAME, SE_MACHINE_ACCOUNT_NAME, SE_RESTORE_NAME, SE_SHUTDOWN_NAME, SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME):
#		print "Looking up who has " + priv + "priv"
#		try:
#			sids = win32security.LsaEnumerateAccountsWithUserRight(ph, priv)
#			print sids
#		except:
#			print "[E] Lookup failed"

def audit_logged_in():
	resume = 0
	print "\n[+] Logged in users:"
	try:
		while True:
			users, total, resume = win32net.NetWkstaUserEnum(remote_server, 1 , resume , 999999 )
			for user in users:
				print "User logged in: Logon Server=\"%s\" Logon Domain=\"%s\" Username=\"%s\"" % (user['logon_server'], user['logon_domain'], user['username'])
			if resume == 0:
				break
	except:
		print "[E] Failed"
		
def audit_host_info():
	print "\n"
	if remote_server:
		print "Querying remote server: " + remote_server
	
	# Only works on local host
	#win32net.NetGetJoinInformation()
	
	# This looks interesting, but doesn't seem to work.  Maybe unsupported legacy api.
	#pywintypes.error: (50, 'NetUseEnum', 'The request is not supported.')
	#print
	#print "[+] Getting Net Use info"
	#print

	#resume = 0
	#use, total, resume = win32net.NetUseEnum(remote_server, 2, resume , 999999 )	
	#print use

	print
	print "[+] Workstation Info (NetWkstaGetInfo 102)"
	print
	
	try:
		#print win32net.NetWkstaGetInfo(remote_server, 100)
		#print win32net.NetWkstaGetInfo(remote_server, 101)
		serverinfo = win32net.NetWkstaGetInfo(remote_server, 102)
		print "Computer Name: %s" % serverinfo['computername']
		print "Langroup: %s" % serverinfo['langroup']
		print "OS: %s.%s" % (serverinfo['ver_major'], serverinfo['ver_minor'])
		print "Logged On Users: %s" % serverinfo['logged_on_users']
		print "Lanroot: %s" % serverinfo['lanroot']
		
		if serverinfo['platform_id'] & win32netcon.PLATFORM_ID_NT:
			print "Platform: PLATFORM_ID_NT (means NT family, not NT4)"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_OS2:
			print "Platform: PLATFORM_ID_OS2"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_DOS:
			print "Platform: PLATFORM_ID_DOS"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_OSF:
			print "Platform: PLATFORM_ID_OSF"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_VMS:
			print "Platform: PLATFORM_ID_VMS"
	except:
		print "[E] Couldn't get Workstation Info"
		
	print
	print "[+] Server Info (NetServerGetInfo 102)"
	print
		
	try:
		#print "NetServerGetInfo 100" + str(win32net.NetServerGetInfo(remote_server, 100))
		#print "NetServerGetInfo 101" + str(win32net.NetServerGetInfo(remote_server, 101))
		serverinfo = win32net.NetServerGetInfo(remote_server, 102)
		print "Name: %s" % serverinfo['name']
		print "Comment: %s" % serverinfo['comment']
		print "OS: %s.%s" % (serverinfo['version_major'], serverinfo['version_minor'])
		print "Userpath: %s" % serverinfo['userpath']
		print "Hidden: %s" % serverinfo['hidden']
		
		if serverinfo['platform_id'] & win32netcon.PLATFORM_ID_NT:
			print "Platform: PLATFORM_ID_NT (means NT family, not NT4)"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_OS2:
			print "Platform: PLATFORM_ID_OS2"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_DOS:
			print "Platform: PLATFORM_ID_DOS"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_OSF:
			print "Platform: PLATFORM_ID_OSF"
		if serverinfo['platform_id'] == win32netcon.PLATFORM_ID_VMS:
			print "Platform: PLATFORM_ID_VMS"
		for sv_type in sv_types:
			if serverinfo['type'] & getattr(win32netcon, sv_type):
				print "Type: " + sv_type
	except:
		print "[E] Couldn't get Server Info"

	
	print
	print "[+] LsaQueryInformationPolicy"
	print
	
	try:
		ph = win32security.LsaOpenPolicy(remote_server, win32security.POLICY_VIEW_LOCAL_INFORMATION | win32security.POLICY_LOOKUP_NAMES)
		print "PolicyDnsDomainInformation:"
		print win32security.LsaQueryInformationPolicy(ph, win32security.PolicyDnsDomainInformation)
		print "PolicyDnsDomainInformation:"
		print win32security.LsaQueryInformationPolicy(ph, win32security.PolicyPrimaryDomainInformation)
		print "PolicyPrimaryDomainInformation:"
		print win32security.LsaQueryInformationPolicy(ph, win32security.PolicyAccountDomainInformation)
		print "PolicyLsaServerRoleInformation:"
		print win32security.LsaQueryInformationPolicy(ph, win32security.PolicyLsaServerRoleInformation)
	except:
		print "[E] Couldn't LsaOpenPolicy"
		
	# DsBindWithCred isn't available from python!
	
	# IADsComputer looks useful, but also isn't implemented:
	# http://msdn.microsoft.com/en-us/library/aa705980%28v=VS.85%29.aspx

	# The following always seems to fail:
	# need a dc hostname as remote_server
	# and    domain
	#try:
	#	hds = win32security.DsBind(remote_server, remote_domain)
	#	print "hds: " + hds
	#	print "DsListDomainsInSite: "+ str(win32security.DsListDomainsInSite(hds))
	#except:
	#	pass
	
	# domain can be null.  i think domainguid can be null.  sitename null.  flags = 0.
	
	# lists roles recognised by the server (fsmo roles?)
	# win32security.DsListRoles(hds)
	
	# list misc info for a server
	# win32security.DsListInfoForServer(hds, server)
	
	# but how to get a list of sites?
	# win32security.DsListServersInSite(hds, site )
	
	# win32security.DsCrackNames(hds, flags , formatOffered , formatDesired , names )
	# ...For example, user objects can be identified by SAM account names (Domain\UserName), user principal name (UserName@Domain.com), or distinguished name.

	print
	print "[+] Getting domain controller info"
	print
	
	try:
		domain = None # TODO: could call of each domain if we had a list
		print "PDC: " + win32net.NetGetDCName(remote_server, domain)
		# Try to list some domain controllers for the remote host
		# There are better ways of doing this, but they don't seem to be available via python!
		dc_seen = {}
		for filter in (0, 0x00004000, 0x00000080, 0x00001000, 0x00000400, 0x00000040, 0x00000010):
			dc_info = win32security.DsGetDcName(remote_server, None, None, None, filter)
			if not dc_info['DomainControllerAddress'] in dc_seen:
				print "\n[+] Found DC\n"
				for k in dc_info:
					print k + ": " + str(dc_info[k])
			dc_seen[dc_info['DomainControllerAddress']] = 1
		print "\nWARNING: Above is not necessarily a complete list of DCs\n"
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0)) # any dc
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00004000)) # not the system we connect to
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00000080)) # pdc
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00001000)) # writeable
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00000400)) # kerberos
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00000040)) # gc
		#print "Domain controller: " + str(win32security.DsGetDcName(remote_server, None, None, None, 0x00000010)) # directory service
	except:
		print "[E] Couldn't get DC info"
		
	# This function sounds very much like what lservers.exe does, but the server name must be None
	# according to http://msdn.microsoft.com/en-us/library/aa370623%28VS.85%29.aspx.  No use to us.
	# print win32net.NetServerEnum(remote_server, 100 or 101, win32netcon.SV_TYPE_ALL, "SOMEDOMAIN.COM", 0, 999999)
		
def audit_user_group():
	try:
		ph = win32security.LsaOpenPolicy(remote_server, win32security.POLICY_VIEW_LOCAL_INFORMATION | win32security.POLICY_LOOKUP_NAMES)
	except:
		pass		
		
	print
	print "[+] Local Groups"
	print
	resume = 0
	groups = []
	while True:
		try:
			g, total, resume = win32net.NetLocalGroupEnum(remote_server, 0, resume, 999999)
			groups = groups + g
			if resume == 0:
				break
		except:
			print "[E] NetLocalGroupEnum failed"
			break
	for group in groups:
		members = []
		while True:
			m, total, resume = win32net.NetLocalGroupGetMembers(remote_server, group['name'], 1, resume, 999999)
			for member in m:
				members.append(member['name'])
			if resume == 0:
				break
		sid, s, i = win32security.LookupAccountName(remote_server, group['name'])
		sid_string = win32security.ConvertSidToStringSid(sid)
		print "Group %s has sid %s" % (group['name'], sid_string)
		for m in members:
			print "Group %s has member: %s" % (group['name'], m)
		if verbose:
			try:
				privs = win32security.LsaEnumerateAccountRights(ph, sid)
				for priv in privs:
					print "Group %s has privilege: %s" % (group['name'], priv)
			except:
				print "Group %s: privilege lookup failed " % (group['name'])
		
	print
	print "[+] Non-local Groups"
	print
	resume = 0
	groups = []
	while True:
		try:
			g, total, resume = win32net.NetGroupEnum(remote_server, 0, resume, 999999)
			groups = groups + g
			if resume == 0:
				break
		except:
			print "[E] NetGroupEnum failed"
			break
			
	for group in groups:
		members = []
		while True:
			try:
				m, total, resume = win32net.NetGroupGetUsers(remote_server, group['name'], 0, resume, 999999)
				for member in m:
					members.append(member['name'])
				if resume == 0:
					break
			except:
				print "[E] NetGroupEnum failed"
				break
		sid, s, i = win32security.LookupAccountName(remote_server, group['name'])
		sid_string = win32security.ConvertSidToStringSid(sid)
		print "Group %s has sid %s" % (group['name'], sid_string)
		for m in members:
			print "Group %s has member: %s" % (group['name'], m)
		if verbose:
			try:
				privs = win32security.LsaEnumerateAccountRights(ph, sid)
				for priv in privs:
					print "Group %s has privilege: %s" % (group['name'], priv)
			except:
				print "Group %s has no privileges" % (group['name'])
			
	print
	print "[+] Users"
	print
	resume = 0
	users = []
	if verbose:
		level = 11
	else:
		level = 0
	while True:
		try:
			# u, total, resume = win32net.NetUserEnum(remote_server, 11, 0, resume, 999999) # lots of user detail
			# u, total, resume = win32net.NetUserEnum(remote_server, 0, 0, resume, 999999) # just the username
			u, total, resume = win32net.NetUserEnum(remote_server, level, 0, resume, 999999)
			for user in u:
				if verbose:
					for k in user:
						if k != 'parms':
							print k + "\t: " + str(user[k])
					print 
				users.append(user['name'])
			if resume == 0:
				break
		except:
			print "[E] NetUserEnum failed"
			break
			
	for user in users:
		gprivs = []
		sid, s, i = win32security.LookupAccountName(remote_server, user)
		sid_string = win32security.ConvertSidToStringSid(sid)
		print "User %s has sid %s" % (user, sid_string)
		groups = win32net.NetUserGetLocalGroups(remote_server, user, 0)
		for group in groups:
			gsid, s, i = win32security.LookupAccountName(remote_server, group)
			try:
				privs = win32security.LsaEnumerateAccountRights(ph, gsid)
				gprivs = list(list(gprivs) + list(privs))
			except:
				pass
			print "User %s is in this local group: %s" % (user, group)
		group_list = win32net.NetUserGetGroups(remote_server, user)
		groups = []
		for g in group_list:
			groups.append(g[0])
		for group in groups:
			print "User %s is in this non-local group: %s" % (user, group)
		if verbose:
			privs = []
			try:
				privs = win32security.LsaEnumerateAccountRights(ph, sid)
			except:
				pass
			for priv in list(set(list(gprivs) + list(privs))):
				print "User %s has privilege %s" % (user, priv)

	if verbose:
		print
		print "[+] Privileges"
		print
				
		for priv in windows_privileges:
			try:
				for s in win32security.LsaEnumerateAccountsWithUserRight(ph, priv):
					priv_desc = "NoDesc!"
					try:
						priv_desc = win32security.LookupPrivilegeDisplayName(remote_server, priv)
					except:
						pass
						
					name, domain, type = win32security.LookupAccountSid(remote_server, s)
					type_string = "unknown_type"
					if type == 4:
						type_string = "group"
					if type == 5:
						type_string = "user"
					print "Privilege %s (%s) is held by %s\%s (%s)" % (priv, priv_desc, domain, name, type_string)
					# print "Privilege %s is held by %s\%s (%s)" % (priv, domain, name, type_string)
			except:
				#print "Skipping %s - doesn't exist for this platform" % priv
				pass

print "windows-privesc-check v%s (http://pentestmonkey.net/windows-privesc-check)\n" % version

# Process Command Line Options
try:
	opts, args = getopt.getopt(sys.argv[1:], "artSDEPRHUOMAFILIehwiWvo:s:u:p:d:", ["help", "verbose", "all_checks", "registry_checks", "path_checks", "service_checks", "services", "drive_checks", "eventlog_checks", "progfiles_checks", "passpol", "process_checks", "share_checks", "user_groups", "processes", "ignore_trusted", "owner_info", "write_perms_only", "domain", "patch_checks", "admin_users", "host_info", "logged_in", "report_file=", "username=", "password=", "domain=", "server="])
except getopt.GetoptError, err:
	# print help information and exit:
	print str(err) # will print something like "option -a not recognized"
	usage()
	sys.exit(2)
output = None
for o, a in opts:
	if o in ("-a", "--all_checks"):
		all_checks = 1
	elif o in ("-r", "--registry_checks"):
		registry_checks = 1
	elif o in ("-t", "--path_checks"):
		path_checks = 1
	elif o in ("-S", "--service_checks"):
		service_checks = 1
	elif o in ("-D", "--drive_checks"):
		drive_checks = 1
	elif o in ("-E", "--eventlog_checks"):
		eventlog_checks = 1
	elif o in ("-F", "--progfiles_checks"):
		progfiles_checks = 1
	elif o in ("-R", "--process_checks"):
		process_checks = 1
	elif o in ("-H", "--share_checks"):
		share_checks = 1
#	elif o in ("-T", "--patch_checks"):
#		patch_checks = 1
	elif o in ("-L", "--logged_in_audit"):
		logged_in_audit = 1
	elif o in ("-U", "--user_group_audit"):
		user_group_audit = 1
	elif o in ("-P", "--passpol"):
		passpol_audit = 1
	elif o in ("-A", "--admin_users_audit"):
		admin_users_audit = 1
	elif o in ("-O", "--process_audit"):
		process_audit = 1
	elif o in ("-i", "--host_info"):
		host_info_audit = 1
	elif o in ("-e", "--services"):
		service_audit = 1
	elif o in ("-h", "--help"):
		usage()
		sys.exit()
	elif o in ("-w", "--write_perms_only"):
		weak_perms_only = 1
	elif o in ("-I", "--ignore_trusted"):
		ignore_trusted = 1
	elif o in ("-W", "--owner_info"):
		owner_info  = 1
	elif o in ("-v", "--verbose"):
		verbose = verbose + 1
	elif o in ("-o", "--report_file"):
		report_file_name = a
	elif o in ("-s", "--server"):
		remote_server = a
		print "Remote server selected: " + a
	elif o in ("-u", "--username"):
		remote_username = a
	elif o in ("-p", "--password"):
		remote_password = a
	elif o in ("-d", "--domain"):
		remote_domain = a
	else:
		assert False, "unhandled option"

if all_checks:
	registry_checks  = 1
	path_checks      = 1
	service_checks   = 1
	service_audit    = 1
	drive_checks     = 1
	eventlog_checks  = 1
	progfiles_checks = 1
	process_checks   = 1
	share_checks     = 1
	user_group_audit = 1
	passpol_audit    = 1
	logged_in_audit  = 1
	admin_users_audit= 1
	host_info_audit  = 1
	patch_checks     = 1
	process_audit    = 1

# Print usage message unless at least on type of check is selected
if not (
	registry_checks  or
	path_checks      or
	service_checks   or
	service_audit    or
	drive_checks     or
	eventlog_checks  or
	progfiles_checks or
	process_checks   or
    share_checks     or
	logged_in_audit  or
	user_group_audit or
	passpol_audit    or
	admin_users_audit or
	host_info_audit  or
	process_audit    or
	patch_checks
):
	usage()

if report_file_name == None:
	report_file_name = "privesc-report-" + socket.gethostname() + ".html"

# Better open the report file now in case there's a permissions problem
REPORT = open(report_file_name,"w")

# Print out scan parameters
print "Audit parameters:"
print "Registry Checks: ....... " + str(registry_checks)
print "PATH Checks: ........... " + str(path_checks)
print "Service Checks: ........ " + str(service_checks)
print "Eventlog Checks: ....... " + str(drive_checks)
print "Program Files Checks: .. " + str(eventlog_checks)
print "Process Checks: ........ " + str(progfiles_checks)
print "Patch Checks: ..........." + str(patch_checks)
print "User/Group Audit: ...... " + str(user_group_audit)
print "Password Policy Audit .. " + str(passpol_audit)
print "Logged-in User Audit ... " + str(logged_in_audit)
print "Admin Users Audit: ..... " + str(admin_users_audit)
print "Host Info Audit: ....... " + str(host_info_audit)
print "Process Audit: ......... " + str(process_audit)
print "Service Audit .......... " + str(service_audit)
print "Ignore Trusted ......... " + str(ignore_trusted)
print "Owner Info ............. " + str(owner_info)
print "Weak Perms Only ........ " + str(weak_perms_only)
print "Verbosity .............. " + str(verbose)
print "Output File: ........... " + report_file_name
print

impersonate(remote_username, remote_password, remote_domain)

# Load win32security
#
# Try to open file and ingore the result.  This gets win32security loaded and working.
# We can then turn off WOW64 and call repeatedly.  If we turn off WOW64 first, 
# win32security will fail to work properly.

try:
	sd = win32security.GetNamedSecurityInfo (
		".",
		win32security.SE_FILE_OBJECT,
		win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
	)
except:
	# nothing
	pass

# Load win32net
#
# NetLocalGroupEnum fails with like under Windows 7 64-bit, but not XP 32-bit:
# pywintypes.error: (127, 'NetLocalGroupEnum', 'The specified procedure could not be found.')
dummy = win32net.NetLocalGroupEnum(None, 0, 0, 1000)

# Disable WOW64 - we WANT to see 32-bit areas of the filesystem
#
# Need to wrap in a try because the following call will error on 32-bit windows
try:
	k32.Wow64DisableWow64FsRedirection( ctypes.byref(wow64) )
except:
	on64bitwindows = 0
# WOW64 is now disabled, so we can read file permissions without Windows redirecting us from system32 to syswow64

# Run checks

if registry_checks:
	print_section("Registry Checks")
	check_registry()

if path_checks:
	print_section("PATH Checks")
	check_paths()

if service_checks:
	print_section("Service Checks")
	check_services()

if service_audit:
	print_section("Service Audit")
	audit_services()

if drive_checks:
	print_section("Drive Checks")
	check_drives()

if eventlog_checks:
	print_section("Event Log Checks")
	check_event_logs()

if progfiles_checks:
	print_section("Program Files Checks")
	check_progfiles()

if process_checks:
	print_section("Process Checks")
	check_processes()

if share_checks:
	print_section("Share Checks")
	check_shares()

if logged_in_audit:
	print_section("Logged-in User Audit")
	audit_logged_in()
	
if user_group_audit:
	print_section("User/Group Audit")
	audit_user_group()
	
if passpol_audit:
	print_section("Password Policy")
	audit_passpol()

if admin_users_audit:
	print_section("Admin Users Audit")
	audit_admin_users()
	
if host_info_audit:
	print_section("Host Info Audit")
	audit_host_info()
	
if process_audit:
	print_section("Process Audit")
	audit_processes()

if patch_checks:
	print_section("Patch Checks")
	check_patches()

	# task_name='test_addtask.job'
# ts=pythoncom.CoCreateInstance(taskscheduler.CLSID_CTaskScheduler,None,pythoncom.CLSCTX_INPROC_SERVER,taskscheduler.IID_ITaskScheduler)
# tasks=ts.Enum()
# for task in tasks:
    # print task
# print issues

# Generate report

audit_data = {}

audit_data['hostname'] = socket.gethostname()
ver_list = win32api.GetVersionEx(1)
os_ver = str(ver_list[0]) + "." + str(ver_list[1])
# version numbers from http://msdn.microsoft.com/en-us/library/ms724832(VS.85).aspx
if os_ver == "4.0":
	os_str = "Windows NT"
if os_ver == "5.0":
	os_str = "Windows 2000"
if os_ver == "5.1":
	os_str = "Windows XP"
if os_ver == "5.2":
	os_str = "Windows 2003"
if os_ver == "6.0":
	os_str = "Windows Vista"
if os_ver == "6.0":
	os_str = "Windows 2008"
if os_ver == "6.1":
	os_str = "Windows 2008 R2"
if os_ver == "6.1":
	os_str = "Windows 7"
	
audit_data['os_name'] = os_str
# print ver_list
# audit_data['os_version'] = str(ver_list[0]) + "." + str(ver_list[1]) + "." + str(ver_list[2]) + " SP" + str(ver_list[5])+ "." + str(ver_list[6]) 
audit_data['os_version'] = str(ver_list[0]) + "." + str(ver_list[1]) + "." + str(ver_list[2]) + " SP" + str(ver_list[5])
# http://msdn.microsoft.com/en-us/library/ms724429(VS.85).aspx
audit_data['ips'] = local_ips
audit_data['domwkg'] = win32api.GetDomainName()
audit_data['version'] = version
audit_data['datetime'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
audit_data['audit_user'] = os.environ['USERDOMAIN'] + "\\" + os.environ['USERNAME']
audit_data['trusted_users'] = trusted_principles_fq
audit_data['trusted_groups'] = trusted_principles
audit_data['dangerous_privs'] = 'somedangerous_privs'

REPORT.write(format_issues("html", issue_template, issues))
REPORT.close
print
print
print "Report saved to " + report_file_name
print
