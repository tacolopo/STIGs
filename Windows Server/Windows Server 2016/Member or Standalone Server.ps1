"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Windows Server 2016 V2R6 Member/Standalone Server"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000030"
'Net User ACCOUNTNAME | Find /i "Password Last Set"'
Net User ACCOUNTNAME | Find /i "Password Last Set"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000070"
'Net User [application account name] | Find /i "Password Last Set"'
Net User [application account name] | Find /i "Password Last Set"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000090"
"Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml"
Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000100"
"Get-TPM"
Get-TPM
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000110"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000120"
'get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName
'get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName'
get-service | where {$_.DisplayName -Like "*trellix*"} | Select Status,DisplayName
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000150"
"Get-Volume"
Get-Volume
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000160"
'Invoke-Expression -Command "icacls c:\"'
Invoke-Expression -Command "icacls c:\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000170"
'Invoke-Expression -Command "icacls c:\program files"'
Invoke-Expression -Command "icacls 'c:\program files'"
'Invoke-Expression -Command "icacls c:\program files (x86)"'
Invoke-Expression -Command "icacls 'c:\program files (x86)'"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000180"
'Invoke-Expression -Command "icacls c:\windows"'
Invoke-Expression -Command "icacls c:\windows"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000190"
#Note - The Security Key requires System level access to read, so this output will be empty if the script is run directly through a PowerShell session.
"Get-Acl -Path HKLM:SECURITY | % { $_.access }"
Get-Acl -Path HKLM:SECURITY | % { $_.access }
"Get-Acl -Path HKLM:SOFTWARE | % { $_.access }"
Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
"Get-Acl -Path HKLM:SYSTEM | % { $_.access }"
Get-Acl -Path HKLM:SYSTEM | % { $_.access }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000200"
"Get Printer Properties"
$printers = get-printer * 
foreach ($printer in $printers)
{ 
    get-printerproperty -printerName $printer.name 
}
'Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"'
Invoke-Expression -Command "wmic printer get Name, PortName, DriverName, ShareName"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000210"
"Check for outdated accounts"
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
 $user = ([ADSI]$_.Path)
 $lastLogin = $user.Properties.LastLogin.Value
 $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
 if ($lastLogin -eq $null) {
 $lastLogin = 'Never'
 }
 Write-Host $user.Name $lastLogin $enabled 
}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000220"
'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount'
Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True" | FT Name, PasswordRequired, Disabled, LocalAccount
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000230"
'Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount'
Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True" | FT Name, PasswordExpires, Disabled, LocalAccount
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000250"
$fileshares = Get-FileShare
foreach ($fileshare in $fileshares) {
	Write-Host $fileshare.Name
	Get-FileShareAccessControl -Name $fileshare.Name
}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000270"
"Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}"
Get-PSDrive -PSProvider FileSystem | ForEach-Object {Get-ChildItem -Path $_.Root -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000280"
"Get-NetFirewallProfile"
Get-NetFirewallProfile
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000300"
"Get-WindowsFeature"
Get-WindowsFeature
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000310"
'Invoke-Expression -Command "netsh advfirewall show all"'
Invoke-Expression -Command "netsh advfirewall show all"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000330 & WN16-00-000340"
'Get-AdUser -Filter * -Properties "Name", "SamAccountName","msDS-UserPasswordExpiryTimeComputed" | Select-Object Name, SamAccountName, @{Name="PasswordExpires"; Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}'
Get-AdUser -Filter * -Properties "Name", "SamAccountName","msDS-UserPasswordExpiryTimeComputed" | Select-Object Name, SamAccountName, @{Name="PasswordExpires"; Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000350"
"Get-WindowsFeature | Where Name -eq Fax"
Get-WindowsFeature | Where Name -eq Fax
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000360"
"Get-WindowsFeature | Where Name -eq Web-Ftp-Service"
Get-WindowsFeature | Where Name -eq Web-Ftp-Service
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000370"
"Get-WindowsFeature | Where Name -eq PNRP"
Get-WindowsFeature | Where Name -eq PNRP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000380"
"Get-WindowsFeature | Where Name -eq Simple-TCPIP"
Get-WindowsFeature | Where Name -eq Simple-TCPIP
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000390"
"Get-WindowsFeature | Where Name -eq Telnet-Client"
Get-WindowsFeature | Where Name -eq Telnet-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000400"
"Get-WindowsFeature | Where Name -eq TFTP-Client"
Get-WindowsFeature | Where Name -eq TFTP-Client
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000410"
"Get-WindowsFeature -Name FS-SMB1"
Get-WindowsFeature -Name FS-SMB1
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000411, WN16-SO-000230, WN16-SO-000240, WN16-SO-000300"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000412"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000420"
"Get-WindowsFeature | Where Name -eq PowerShell-v2"
Get-WindowsFeature | Where Name -eq PowerShell-v2
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000450"
'Invoke-Expression -Command "W32tm /query /configuration"'
Invoke-Expression -Command "W32tm /query /configuration"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-00-000470 &  WN16-00-000480"
"Get-ComputerInfo"
Get-ComputerInfo
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Get Installed Software/Apps"
"Get-WmiObject -Class Win32_Product"
Get-WmiObject -Class Win32_Product
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-AU-000030"
"(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Application.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-AU-000040"
"(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\Security.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-AU-000050"
"(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\winevt\Logs\System.evtx).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-AU-000060"
"(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto"
(get-acl C:\Windows\System32\Eventvwr.exe).access | ft IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -auto
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-AU-000070, WN16-AU-000080, WN16-AU-000100, WN16-AU-000120, WN16-AU-000140, WN16-AU-000150, WN16-AU-000160, WN16-AU-000170, WN16-AU-000230, WN16-AU-000240, WN16-AU-000250, WN16-AU-000260, WN16-AU-000270, WN16-AU-000280, WN16-AU-000285, WN16-AU-000286, WN16-AU-000290, WN16-AU-000300, WN16-AU-000310, WN16-AU-000320, WN16-AU-000330, WN16-AU-000340, WN16-AU-000350, WN16-AU-000360, WN16-AU-000370, WN16-AU-000380, WN16-AU-000390, WN16-AU-000400, WN16-AU-000410, WN16-AU-000420, WN16-AU-000440, WN16-AU-000450"
"AuditPol /get /category:*"
AuditPol /get /category:*
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000010"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000030"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000040"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000050, WN16-CC-000060"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000070"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000080"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000090"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000100"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000110"
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000140"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000150"
'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"'
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group` Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000160, WN16-CC-000170"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000180, WN16-CC-000330, WN16-MS-000030"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000210, WN16-CC-000220"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000240"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000250, WN16-CC-000340, WN16-CC-000350"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000260, WN16-CC-000270, WN16-CC-000360, WN16-CC-000421"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000280"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000290"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000300"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000310"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000320"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000370, WN16-CC-000380, WN16-CC-000390, WN16-CC-000400, WN16-CC-000410"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000420, WN16-CC-000430"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000440"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000450, WN16-CC-000460, WN16-CC-000470"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000480, WN16-SO-000140, WN16-SO-000150, WN16-SO-000160, WN16-SO-000460, WN16-SO-000470, WN16-SO-000480, WN16-SO-000490, WN16-SO-000500, WN16-SO-000510, WN16-SO-000520, WN16-SO-000530"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000490"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000500, WN16-CC-000510, WN16-CC-000520"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-CC-000530, WN16-CC-000540, WN16-CC-000550"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000010"
"Get-LocalGroupMember Administrators"
Get-LocalGroupMember Administrators
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000020"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000040"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000050, WN16-SO-000180"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows` NT\CurrentVersion\Winlogon\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000120"
"N/A for standalone"
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-MS-000310, WN16-SO-000020, WN16-SO-000050, WN16-SO-000260, WN16-SO-000270, WN16-SO-000290, WN16-SO-000320, WN16-SO-000350, WN16-SO-000360, WN16-SO-000380"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-PK-000010"
'Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-PK-000020"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-PK-000030"
'Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter'
Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000080, WN16-SO-000090, WN16-SO-000100, WN16-SO-000110, WN16-SO-000120, WN16-SO-000130"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000190, WN16-SO-000200, WN16-SO-000210"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000330, WN16-SO-000400, WN16-SO-000410"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000340"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000350"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000390"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000420"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000430"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-SO-000450"
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-UC-000030"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
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

'Get-Acl -Path "HKLM:\SYSTEM"'
Get-Acl -Path "HKLM:\SYSTEM"
#Note - The Security Key requires System level access to read, so this output will be empty if the script is run directly through a PowerShell session.
'Get-Acl -Path "HKLM:\SECURITY"'
Get-Acl -Path "HKLM:\SECURITY"
'Get-Acl -Path "HKLM:\SOFTWARE"'
Get-Acl -Path "HKLM:\SOFTWARE"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN16-0O-000080"
"$FormatEnumerationLimit=-1"
$FormatEnumerationLimit=-1
"Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize"
Get-AppLockerPolicy -Effective -Xml | Format-Table -AutoSize
