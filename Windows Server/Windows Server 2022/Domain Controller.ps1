"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Windows Server 2022 V1R5 Domain Controller"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000020"
"Get-LocalUser -Name * | Select-Object *"
Get-LocalUser -Name * | Select-Object *
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000060"
"Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet"
Get-AdUser -Identity [application account name] -Properties PasswordLastSet | FT Name, PasswordLastSet
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000090"
"Get-TPM"
Get-TPM
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000100, WN22-00-000460, WN22-00-000470"
"Get-ComputerInfo"
Get-ComputerInfo
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Get Installed Software/Apps"
"Get-WmiObject -Class Win32_Product"
Get-WmiObject -Class Win32_Product
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000110"
'get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000130"
"Get-Volume"
Get-Volume
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000140"
'Invoke-Expression -Command "icacls c:\"'
Invoke-Expression -Command "icacls c:\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000150"
'Invoke-Expression -Command "icacls c:\program files"'
Invoke-Expression -Command "icacls 'c:\program files'"
'Invoke-Expression -Command "icacls c:\program files (x86)"'
Invoke-Expression -Command "icacls 'c:\program files (x86)'"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000160"
'Invoke-Expression -Command "icacls c:\windows"'
Invoke-Expression -Command "icacls c:\windows"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000170"
#Note - The Security Key requires System level access to read, so this output will be empty if the script is run directly through a PowerShell session.
"Get-Acl -Path HKLM:SECURITY | % { $_.access }"
Get-Acl -Path HKLM:SECURITY | % { $_.access }
"Get-Acl -Path HKLM:SOFTWARE | % { $_.access }"
Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
"Get-Acl -Path HKLM:SYSTEM | % { $_.access }"
Get-Acl -Path HKLM:SYSTEM | % { $_.access }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000180"
"Get Printer Properties"
$printers = get-printer * 
foreach ($printer in $printers)
{ 
    get-printerproperty -printerName $printer.name 
}
'Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"'
Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000190"
"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00"
Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000200"
"Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled"
Get-Aduser -Filter * -Properties Passwordnotrequired |FT Name, Passwordnotrequired, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000210"
"Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled"
Search-ADAccount -PasswordNeverExpires -UsersOnly | FT Name, PasswordNeverExpires, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000240"
"Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}"
Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000270"
"Get-WindowsFeature"
Get-WindowsFeature
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000280"
"Get-NetFirewallProfile"
Get-NetFirewallProfile
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000300"
"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate"
Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000310"
"Only applies if emergency accounts in use"
"Net user [username]"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000320"
"Get-WindowsFeature | Where Name -eq Fax"
Get-WindowsFeature | Where Name -eq Fax
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000330"
"Get-WindowsFeature | Where Name -eq Web-Ftp-Service"
Get-WindowsFeature | Where Name -eq Web-Ftp-Service
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000340"
"Get-WindowsFeature | Where Name -eq PNRP"
Get-WindowsFeature | Where Name -eq PNRP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000350"
"Get-WindowsFeature | Where Name -eq Simple-TCPIP"
Get-WindowsFeature | Where Name -eq Simple-TCPIP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000360"
"Get-WindowsFeature | Where Name -eq Telnet-Client"
Get-WindowsFeature | Where Name -eq Telnet-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000370"
"Get-WindowsFeature | Where Name -eq TFTP-Client"
Get-WindowsFeature | Where Name -eq TFTP-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000380"
"Get-WindowsFeature -Name FS-SMB1"
Get-WindowsFeature -Name FS-SMB1
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000390, WN22-SO-000190, WN22-SO-000200, WN22-SO-000250"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000400"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000410"
"Get-WindowsFeature | Where Name -eq PowerShell-v2"
Get-WindowsFeature | Where Name -eq PowerShell-v2
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000440"
'Invoke-Expression -Command "W32tm /query /configuration"'
Invoke-Expression -Command "W32tm /query /configuration"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-AU-000030"
"(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-AU-000040"
"(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-AU-000050"
"(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-AU-000060"
"(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-AU-000070, WN22-AU-000080, WN22-AU-000090, WN22-AU-000100, WN22-AU-000110, WN22-AU-000120, WN22-AU-000130, WN22-AU-000140, WN22-AU-000160, WN22-AU-000170, WN22-AU-000180, WN22-AU-000190, WN22-AU-000200, WN22-AU-000210, WN22-AU-000220, WN22-AU-000230, WN22-AU-000240, WN22-AU-000250, WN22-AU-000260, WN22-AU-000270, WN22-AU-000280, WN22-AU-000290, WN22-AU-000300, WN22-AU-000310, WN22-AU-000320, WN22-AU-000330, WN22-AU-000340, WN22-AU-000350, WN22-AU-000360, WN22-AU-000370, WN22-AU-000380, WN22-AU-000390, WN22-DC-000230, WN22-DC-000240, WN22-DC-000250, WN22-DC-000260"
"AuditPol /get /category:*"
AuditPol /get /category:*
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000010"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000020"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000030"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000040, WN22-CC-000050"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000060"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000070"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000080"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000090"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000100"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000110"
"N/A for standalone servers"
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000130"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000140"
'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000150, WN22-CC-000160"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000170, WN22-CC-000300"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000180, WN22-CC-000190"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000200"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000210, WN22-CC-000310, WN22-CC-000320"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000220, WN22-CC-000230, WN22-CC-000330"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000240"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000250"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000260"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000270"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000280"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000340, WN22-CC-000350, WN22-CC-000360, WN22-CC-000370, WN22-CC-000380"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000390, WN22-CC-000400"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000410"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000420, WN22-CC-000430, WN22-CC-000440"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000450, WN22-SO-000120, WN22-SO-000130, WN22-SO-000140, WN22-SO-000380, WN22-SO-000390, WN22-SO-000400, WN22-SO-000410, WN22-SO-000420, WN22-SO-000430, WN22-SO-000440, WN22-SO-000450"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000460"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000470, WN22-CC-000480, WN22-CC-000490"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000500, WN22-CC-000510, WN22-CC-000520"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-CC-000530"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000010"
"Get-LocalGroupMember Administrators"
Get-LocalGroupMember Administrators
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000070, WN22-DC-000120, WN22-DC-000320"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000080"
'Invoke-Expression -Command "net share"'
Invoke-Expression -Command "net share"
'Invoke-Expression -Command "icacls c:\Windows\SYSVOL"'
Invoke-Expression -Command "icacls c:\Windows\SYSVOL"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000300"
"Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled"
Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000310"
"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name"
Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-DC-000430"
"Get-ADUser krbtgt -Property PasswordLastSet"
Get-ADUser krbtgt -Property PasswordLastSet
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000150"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000020, WN22-SO-000050, WN22-SO-000220, WN22-SO-000230, WN22-SO-000240, WN22-SO-000260, WN22-SO-000300, WN22-SO-000310, WN19-00-000470"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-PK-000010"
'Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-PK-000020"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-PK-000030"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000060, WN22-SO-000070, WN22-SO-000080, WN22-SO-000090, WN22-SO-000100, WN22-SO-000110, WN22-DC-000330"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000160, WN22-SO-000170, WN22-SO-000180"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000270, WN22-SO-000330, WN22-SO-000340"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000280"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000320"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000350"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000360"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-SO-000370"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-UC-000010"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
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

"SecureBoot Checks"
function Get-UEFIDatabaseSigner {
    <#
    .SYNOPSIS

    Dumps signature or hash information for whitelisted ('db' variable) or blacklisted ('dbx' variable) UEFI bootloaders.

    .DESCRIPTION

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause

    .PARAMETER Variable

    Specifies a UEFI variable, an instance of which is returned by calling the Get-SecureBootUEFI cmdlet. Only 'db' and 'dbx' are supported.

    .EXAMPLE

    Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSigner

    .EXAMPLE

    Get-SecureBootUEFI -Name dbx | Get-UEFIDatabaseSigner

    .EXAMPLE

    Get-SecureBootUEFI -Name pk | Get-UEFIDatabaseSigner

    .EXAMPLE

    Get-SecureBootUEFI -Name kek | Get-UEFIDatabaseSigner

    .INPUTS

    Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable

    Accepts the output of Get-SecureBootUEFI over the pipeline.

    .OUTPUTS

    UEFIDBXHash

    Outputs a custom object consisting of banned SHA256 hashes and the respective "owner" of each hash. "77fa9abd-0359-4d32-bd60-28f4e78f784b" refers to Microsoft as the owner.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ ($_.GetType().Fullname -eq 'Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable') -and (($_.Name -eq 'kek') -or ($_.Name -eq 'pk') -or ($_.Name -eq 'db') -or ($_.Name -eq 'dbx')) })]
        $Variable
    )

    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$Variable.Bytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    } catch {
        throw $_
        return
    }

    # What follows will be an array of EFI_SIGNATURE_LIST structs

    while ($BinaryReader.PeekChar() -ne -1) {
        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
        $SignatureListSize = $BinaryReader.ReadUInt32()
        $SignatureHeaderSize = $BinaryReader.ReadUInt32()
        $SignatureSize = $BinaryReader.ReadUInt32()

        $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)

        # 0x1C is the size of the EFI_SIGNATURE_LIST header
        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

        $Signature = 1..$SignatureCount | ForEach-Object {
            $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)

            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

            switch ($SignatureType) {
                'EFI_CERT_SHA256_GUID' {
                    $SignatureData = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                }

                'EFI_CERT_X509_GUID' {
                    $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                }
            }

            [PSCustomObject] @{
                PSTypeName = 'EFI.SignatureData'
                SignatureOwner = $SignatureOwner
                SignatureData = $SignatureData
            }
        }

        [PSCustomObject] @{
            PSTypeName = 'EFI.SignatureList'
            SignatureType = $SignatureType
            Signature = $Signature
        }
    }
}
"Confirm-SecureBootUEFI"
Confirm-SecureBootUEFI
"Get-SecureBootUEFI -Name PK | Get-UEFIDatabaseSigner | Format-List"
Get-SecureBootUEFI -Name PK | Get-UEFIDatabaseSigner | Format-List
"Get-SecureBootUEFI -Name KEK | Get-UEFIDatabaseSigner | Format-List"
Get-SecureBootUEFI -Name KEK | Get-UEFIDatabaseSigner | Format-List
"Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSigner | Format-List"
Get-SecureBootUEFI -Name db | Get-UEFIDatabaseSigner | Format-List
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN22-00-000080"
"Prevent output truncation:"
"$FormatEnumerationLimit=-1"
$FormatEnumerationLimit=-1
"Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize"
Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize
"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"End of Script"
