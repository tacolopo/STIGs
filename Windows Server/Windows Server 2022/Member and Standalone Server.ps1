"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Windows Server 2022 V1R4 Member Server"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000020"
"Get-LocalUser -Name * | Select-Object *"
Get-LocalUser -Name * | Select-Object *

"WN22-00-000040"
'Get-LocalGroupMember "Backup Operators"'
Get-LocalGroupMember "Backup Operators"

"WN22-00-000060"
#CHANGE TO INVOKE EXPRESSION
'Net User [application account name] | Find /i "Password Last Set"'
Net User [application account name] | Find /i "Password Last Set"

"WN22-00-000090"
"Get-TPM"
Get-TPM

"WN22-00-000100, WN22-00-000460, WN22-00-000470"
"Get-ComputerInfo"
Get-ComputerInfo

"WN22-00-000110"
'get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName

"WN22-00-000130"
"Get-Volume"
Get-Volume

"WN22-00-000140"
'Invoke-Expression -Command "icacls c:\"'
Invoke-Expression -Command "icacls c:\"

"WN22-00-000150"
'Invoke-Expression -Command "icacls c:\program files"'
Invoke-Expression -Command "icacls 'c:\program files'"
'Invoke-Expression -Command "icacls c:\program files (x86)"'
Invoke-Expression -Command "icacls 'c:\program files (x86)'"

"WN22-00-000160"
'Invoke-Expression -Command "icacls c:\windows"'
Invoke-Expression -Command "icacls c:\windows"

"WN22-00-000170"
'Get-Acl -Path "HKLM:\SYSTEM"'
Get-Acl -Path "HKLM:\SYSTEM"
'Get-Acl -Path "HKLM:\SECURITY"'
Get-Acl -Path "HKLM:\SECURITY"
'Get-Acl -Path "HKLM:\SOFTWARE"'
Get-Acl -Path "HKLM:\SOFTWARE"

"WN22-00-000180"
"Get Printer Properties"
$printers = get-printer * 
foreach ($printer in $printers)
{ 
    get-printerproperty -printerName $printer.name 
}
'Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"'
Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"

"WN22-00-000190"
"Check for outdated accounts"
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
 $user = ([ADSI]$_.Path)
 $lastLogin = $user.Properties.LastLogin.Value
 $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
 if ($lastLogin -eq $null) {
 $lastLogin = 'Never'
 }
 Write-Output $user.Name $lastLogin $enabled 
}

"WN22-00-000200"
'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'
Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount

"WN22-00-000210"
'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'
Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount

"WN22-00-000240"
"Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}"
Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}

"WN22-00-000250"
"Get-BitLockerVolume"
Get-BitLockerVolume

"WN22-00-000270"
"Get-WindowsFeature"
Get-WindowsFeature

"WN22-00-000280"
"Get-NetFirewallProfile"
Get-NetFirewallProfile

"WN22-00-000300"
"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate"
Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate

"WN22-00-000310"
"Only applies if emergency accounts in use"
"Net user [username]"

"WN22-00-000320"
"Get-WindowsFeature | Where Name -eq Fax"
Get-WindowsFeature | Where Name -eq Fax

"WN22-00-000330"
"Get-WindowsFeature | Where Name -eq Web-Ftp-Service"
Get-WindowsFeature | Where Name -eq Web-Ftp-Service

"WN22-00-000340"
"Get-WindowsFeature | Where Name -eq PNRP"
Get-WindowsFeature | Where Name -eq PNRP

"WN22-00-000350"
"Get-WindowsFeature | Where Name -eq Simple-TCPIP"
Get-WindowsFeature | Where Name -eq Simple-TCPIP

"WN22-00-000360"
"Get-WindowsFeature | Where Name -eq Telnet-Client"
Get-WindowsFeature | Where Name -eq Telnet-Client

"WN22-00-000370"
"Get-WindowsFeature | Where Name -eq TFTP-Client"
Get-WindowsFeature | Where Name -eq TFTP-Client

"WN22-00-000380"
"Get-WindowsFeature -Name FS-SMB1"
Get-WindowsFeature -Name FS-SMB1

"WN22-00-000390, WN22-SO-000190, WN22-SO-000200, WN22-SO-000250"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\

"WN22-00-000400"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\

"WN22-00-000410"
"Get-WindowsFeature | Where Name -eq PowerShell-v2"
Get-WindowsFeature | Where Name -eq PowerShell-v2

"WN22-00-000440"
'Invoke-Expression -Command "W32tm /query /configuration"'
Invoke-Expression -Command "W32tm /query /configuration"

"WN22-AU-000030"
"(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto

"WN22-AU-000040"
"(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto

"WN22-AU-000050"
"(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto

"WN22-AU-000060"
"(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto

"WN22-AU-000070, WN22-AU-000080, WN22-AU-000090, WN22-AU-000100, WN22-AU-000110, WN22-AU-000120, WN22-AU-000130, WN22-AU-000140, WN22-AU-000160, WN22-AU-000170, WN22-AU-000180, WN22-AU-000190, WN22-AU-000200, WN22-AU-000210, WN22-AU-000220, WN22-AU-000230, WN22-AU-000240, WN22-AU-000250, WN22-AU-000260, WN22-AU-000270, WN22-AU-000280, WN22-AU-000290, WN22-AU-000300, WN22-AU-000310, WN22-AU-000320, WN22-AU-000330, WN22-AU-000340, WN22-AU-000350, WN22-AU-000360, WN22-AU-000370, WN22-AU-000380, WN22-AU-000390"
"AuditPol /get /category:*"
AuditPol /get /category:*

"WN22-CC-000010"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\

"WN22-CC-000020"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\

"WN22-CC-000030"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

"WN22-CC-000040, WN22-CC-000050"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\

"WN22-CC-000060"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\

"WN22-CC-000070"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\

"WN22-CC-000080"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\

"WN22-CC-000090"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\

"WN22-CC-000100"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\

"WN22-CC-000110, WN22-MS-000140"
"N/A for standalone servers"
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

"WN22-CC-000130"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\

"WN22-CC-000140"
'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"

"WN22-CC-000150, WN22-CC-000160"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\

"WN22-CC-000170, WN22-CC-000300, WN22-MS-000030"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\

"WN22-CC-000180, WN22-CC-000190"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

"WN22-CC-000200"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\

"WN22-CC-000210, WN22-CC-000310, WN22-CC-000320"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\

"WN22-CC-000220, WN22-CC-000230, WN22-CC-000330"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

"WN22-CC-000240"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\

"WN22-CC-000250"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\

"WN22-CC-000260"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\

"WN22-CC-000270"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\

"WN22-CC-000280"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\

"WN22-CC-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\

"WN22-CC-000340, WN22-CC-000350, WN22-CC-000360, WN22-CC-000370, WN22-CC-000380"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\

"WN22-CC-000390, WN22-CC-000400"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\

"WN22-CC-000410"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\

"WN22-CC-000420, WN22-CC-000430, WN22-CC-000440"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\

"WN22-CC-000450, WN22-MS-000020, WN22-SO-000120, WN22-SO-000130, WN22-SO-000140, WN22-SO-000380, WN22-SO-000390, WN22-SO-000400, WN22-SO-000410, WN22-SO-000420, WN22-SO-000430, WN22-SO-000440, WN22-SO-000450"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

"WN22-CC-000460"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\

"WN22-CC-000470, WN22-CC-000480, WN22-CC-000490"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\

"WN22-CC-000500, WN22-CC-000510, WN22-CC-000520"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\

"WN22-CC-000530"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\

"WN22-MS-000010"
"Get-LocalGroupMember Administrators"
Get-LocalGroupMember Administrators

"WN22-MS-000040"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\

"WN22-MS-000050, WN22-SO-000150"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\

"WN22-MS-000060, WN22-SO-000020, WN22-SO-000050, WN22-SO-000220, WN22-SO-000230, WN22-SO-000240, WN22-SO-000260, WN22-SO-000300, WN22-SO-000310, WN19-00-000470"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\

"WN22-PK-000010"
'Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

"WN22-PK-000020"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

"WN22-PK-000030"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

"WN22-SO-000060, WN22-SO-000070, WN22-SO-000080, WN22-SO-000090, WN22-SO-000100, WN22-SO-000110"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

"WN22-SO-000160, WN22-SO-000170, WN22-SO-000180"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\

"WN22-SO-000270, WN22-SO-000330, WN22-SO-000340"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\

"WN22-SO-000280"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\

"WN22-SO-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\

"WN22-SO-000320"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\

"WN22-SO-000350"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\

"WN22-SO-000360"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\

"WN22-SO-000370"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\

"WN22-UC-000010"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\

"WN22-00-000080"
"Prevent output truncation:"
"$FormatEnumerationLimit=-1"
$FormatEnumerationLimit=-1
"Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize"
Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize
