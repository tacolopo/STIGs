"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Windows Server 2019 V2R8 Domain Controller"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000300"
"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate"
Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-AU-000100, WN19-AU-000110, WN19-AU-000120, WN19-AU-000190, WN19-AU-000200, WN19-AU-000160, WN19-AU-000090, WN19-AU-000140, WN19-AU-000260, WN19-AU-000270, WN19-AU-000280, WN19-AU-000290, WN19-AU-000300, WN19-AU-000310, WN19-AU-000320, WN19-AU-000330, WN19-AU-000340, WN19-AU-000350, WN19-AU-000360, WN19-AU-000370, WN19-AU-000380, WN19-AU-000390, WN19-AU-000070, WN19-AU-000080, WN19-AU-000170, WN19-AU-000210, WN19-AU-000220, WN19-AU-000230, WN19-AU-000180, WN19-AU-000130, WN19-AU-000240, WN19-AU-000250, WN19-DC-000230, WN19-DC-000240, WN19-DC-000250, WN19-DC-000260"
"AuditPol /get /category:*"
AuditPol /get /category:*
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000130, WN19-SO-000140, WN19-SO-000120, WN19-SO-000390, WN19-SO-000400, WN19-SO-000420, WN19-SO-000430, WN19-SO-000450, WN19-SO-000380, WN19-SO-000410, WN19-SO-000440, WN19-CC-000450"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000370, WN19-CC-000380, WN19-CC-000350, WN19-CC-000340, WN19-CC-000360"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000090"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000460"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-AU-000030"
"(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-AU-000040"
"(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-AU-000050"
"(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000050, WN19-SO-000300, WN19-SO-000230, WN19-00-000470, WN19-SO-000020, WN19-SO-000220, WN19-SO-000240, WN19-SO-000260, WN19-SO-000310"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000300"
"Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled"
Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-PK-000010"
'Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-PK-000020"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-PK-000030"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000350"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000180, WN19-SO-000160, WN19-SO-000170"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000020"
"Get-LocalUser -Name * | Select-Object *"
Get-LocalUser -Name * | Select-Object *
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000210"
"Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled"
Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000130"
"Get-Volume"
Get-Volume
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000180"
"Get Printer Properties"
$printers = get-printer * 
foreach ($printer in $printers)
{ 
    get-printerproperty -printerName $printer.name 
}
'Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"'
Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000270"
"Get-WindowsFeature"
Get-WindowsFeature
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000320"
"Get-WindowsFeature | Where Name -eq Fax"
Get-WindowsFeature | Where Name -eq Fax
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000340"
"Get-WindowsFeature | Where Name -eq PNRP"
Get-WindowsFeature | Where Name -eq PNRP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000350"
"Get-WindowsFeature | Where Name -eq Simple-TCPIP"
Get-WindowsFeature | Where Name -eq Simple-TCPIP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000370"
"Get-WindowsFeature | Where Name -eq TFTP-Client"
Get-WindowsFeature | Where Name -eq TFTP-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000380"
"Get-WindowsFeature -Name FS-SMB1"
Get-WindowsFeature -Name FS-SMB1
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000390, WN19-SO-000250, WN19-SO-000190, WN19-SO-000200"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000400"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000410"
"Get-WindowsFeature | Where Name -eq PowerShell-v2"
Get-WindowsFeature | Where Name -eq PowerShell-v2
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000010"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000020"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000150, WN19-CC-000160"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000170, WN19-CC-000300"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000200"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000400, WN19-CC-000390"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000410"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000330"
"Get-WindowsFeature | Where Name -eq Web-Ftp-Service"
Get-WindowsFeature | Where Name -eq Web-Ftp-Service
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000360"
"Get-WindowsFeature | Where Name -eq Telnet-Client"
Get-WindowsFeature | Where Name -eq Telnet-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000200"
"Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled"
Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000310"
"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name"
Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000310"
"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate"
Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000470, WN19-CC-000490, WN19-CC-000480"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000500, WN19-CC-000520, WN19-CC-000510"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000240"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000120, WN19-DC-000070, WN19-DC-000320"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000080"
'Invoke-Expression -Command "net share"'
Invoke-Expression -Command "net share"
'Invoke-Expression -Command "icacls c:\Windows\SYSVOL"'
Invoke-Expression -Command "icacls c:\Windows\SYSVOL"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-AU-000060"
"(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000140"
'Invoke-Expression -Command "icacls c:\"'
Invoke-Expression -Command "icacls c:\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000150"
'Invoke-Expression -Command "icacls c:\program files"'
Invoke-Expression -Command "icacls 'c:\program files'"
'Invoke-Expression -Command "icacls c:\program files (x86)"'
Invoke-Expression -Command "icacls 'c:\program files (x86)'"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000160"
'Invoke-Expression -Command "icacls c:\windows"'
Invoke-Expression -Command "icacls c:\windows"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000170"
"Get-Acl -Path HKLM:SECURITY | % { $_.access }"
Get-Acl -Path HKLM:SECURITY | % { $_.access }
"Get-Acl -Path HKLM:SOFTWARE | % { $_.access }"
Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
"Get-Acl -Path HKLM:SYSTEM | % { $_.access }"
Get-Acl -Path HKLM:SYSTEM | % { $_.access }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000010"
"Get-LocalGroupMember Administrators"
Get-LocalGroupMember Administrators
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000270"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000280"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000440"
'Invoke-Expression -Command "W32tm /query /configuration"'
Invoke-Expression -Command "W32tm /query /configuration"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000420, WN19-CC-000430, WN19-CC-000440"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000210, WN19-CC-000310, WN19-CC-000320"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000220, WN19-CC-000230, WN19-CC-000330"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000090, WN19-SO-000060, WN19-SO-000070, WN19-SO-000080, WN19-SO-000110, WN19-SO-000100, WN19-DC-000330"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-DC-000430"
"Get-ADUser krbtgt -Property PasswordLastSet"
Get-ADUser krbtgt -Property PasswordLastSet
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000060"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000360"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000060"
"Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet"
Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000090"
"Get-TPM"
Get-TPM
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000100, WN19-00-000460"
"Get-ComputerInfo"
Get-ComputerInfo
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000110"
'get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000240"
"Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}"
Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000280"
"Get-NetFirewallProfile"
Get-NetFirewallProfile
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000030"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000040, WN19-CC-000050"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000070"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000080"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000100"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000110"
"N/A for standalone servers"
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000130"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000140"
'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000180, WN19-CC-000190"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000250"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000260"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000150"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000270, WN19-SO-000330, WN19-SO-000340"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000280"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000320"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-SO-000370"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-UC-000010"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000451"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-CC-000530"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Get-WindowsFeature"
Get-WindowsFeature
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Get Verbose Group Policy Information"
"gpresult /z"
gpresult /z
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000190"
"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00"
Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Organizational Units"
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"AD.0260"
$BuiltInAdminCheck = Get-ADGroup -Identity Administrators
"Get-ADGroupMember -Identity $BuiltInAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInDhcpAdminCheck = Get-ADGroup -Identity 'DHCP Administrators'
"Get-ADGroupMember -Identity $BuiltInDhcpAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInDhcpAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInDnsAdminCheck = Get-ADGroup -Identity DnsAdmins
"Get-ADGroupMember -Identity $BuiltInDnsAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInDnsAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInDomainAdminCheck = Get-ADGroup -Identity 'Domain Admins'
"Get-ADGroupMember -Identity $BuiltInDomainAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInDomainAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInEnterpriseAdminCheck = Get-ADGroup -Identity 'Enterprise Admins'
"Get-ADGroupMember -Identity $BuiltInDomainAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInEnterpriseAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInEnterpriseKeyAdminCheck = Get-ADGroup -Identity 'Enterprise Key Admins'
"Get-ADGroupMember -Identity $BuiltInEnterpriseKeyAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInEnterpriseKeyAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInHyperVAdminCheck = Get-ADGroup -Identity 'Hyper-V Administrators'
"Get-ADGroupMember -Identity $BuiltInHyperVAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInHyperVAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInKeyAdminCheck = Get-ADGroup -Identity 'Key Admins'
"Get-ADGroupMember -Identity $BuiltInKeyAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltInKeyAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInSchemaAdminCheck = Get-ADGroup -Identity 'Schema Admins'
"Get-ADGroupMember -Identity $BuiltSchemaAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
Get-ADGroupMember -Identity $BuiltSchemaAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
$BuiltInStorageAdminCheck = Get-ADGroup -Identity 'Storage Replica Administrators'
Get-ADGroupMember -Identity $BuiltStorageAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
"Get-ADGroupMember -Identity $BuiltStorageAdminCheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"AD.0260"
"Get Membership groups related to AD Delegation"
$ADDelegationsGroups = Get-ADGroup -SearchBase "DC=blank DC=blank DC=blank" -Properties CanonicalName,Description,info | Sort-Object Name
foreach($Groupcheck in $ADDelegationsGroups){
	Write-Host "Group Name: $($Groupcheck.Name) ($($Groupcheck.DistinguishedName))"
	Write-Host "Description: $($Groupcheck.Description)"
	Write-Host "Members:"
	Get-ADGroupMember -Identity $Groupcheck.Name -Recursive | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object {Write-Host `t$_}
}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN19-00-000080"
"Prevent output truncation:"
"$FormatEnumerationLimit=-1"
$FormatEnumerationLimit=-1
"Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize"
Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize
"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"End of Script"
