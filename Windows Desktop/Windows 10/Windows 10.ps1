"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Windows 10 V3R1"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#TO DO
# Comment out all STIG ID Titles and descriptions. Print Out STIG ID for fail.
# EDIT DEFENDER CHECKS TO TRELLIX CHECKS

# "WN10-00-000005"
# "Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit version"
$os = Get-ComputerInfo
$os.CsDNSHostName

if ($os.CsDomainRole -eq "MemberWorkstation" -and $os.OsArchitecture -ne "64-bit") { Write-Output "WN10-00-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000010"
# "Verify TPM is present and enabled"
$tpm = Get-Tpm
if ($tpm.TpmPresent -eq $false -or $tpm.TpmEnabled -eq $false) { Write-Output "WN10-00-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000015"
# "System must be configured to run in UEFI mode."
if ($os.BiosFirmwareType -ne "Uefi") { Write-Output "WN10-00-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000020"
# "Secure Boot must be enabled."
$bootState = Confirm-SecureBootUEFI
if ($bootState -eq $false) { Write-Output "WN10-00-000020" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000025"
# "An approved tool for continuous network scanning must be installed and configured to run."
$allInstalledSoftware = Get-WmiObject -Class Win32_Product
$isTenableInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Nessus Agent (x64)" }
if ($isTenableInstalled -eq $null) { Write-Output "WN10-00-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000030"
# "Systems must use BitLocker to encrypt all disks"
$bitLocker = (Get-BitLockerVolume).ProtectionStatus | Out-String
if ($bitLocker.Contains('Off') -eq $true) { Write-Output "WN10-00-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000031"
# "Systems must use a BitLocker PIN for pre-boot authentication."
$bitLockerPin = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE\
if ($bitLockerPin.UseAdvancedStartup -notin @(1,2) -and $bitLockerPin.UseTPMPIN -notin @(1,2)) { Write-Output "WN10-00-000031" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000032"
# "BitLocker PIN must have a minimum length of six digits for pre-boot authentication."
if ($bitLockerPin.MinimumPin -lt 6) { Write-Output "WN10-00-000032" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000035"
# "Verify AppLocker is enabled"
$appLocker = Get-AppLockerPolicy -Effective -Xml
if ($appLocker.Contains('Type="Appx" EnforcementMode="Enabled"') -eq $false) { Write-Output "WN10-00-000035" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000040"
# "Get Build Number"
if ($os.OsBuildNumber -ne 19045) { Write-Output "WN10-00-000040" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000045"
# "Check Defender antivirus is running"
$allWindowsServices = Get-Service
$defender = $allWindowsServices | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName | Out-String
if ($defender.Contains('Running Microsoft Defender Antivirus') -eq $false) { Write-Output "WN10-00-000045" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000050"
# "Local volumes must be formatted using NTFS."
$ntfs = Get-Volume
$ntfsCheck = foreach ($volume in $ntfs) { if ($volume.FileSystemType -ne 'NTFS') { Write-Output "$($volume.FileSystemType), $($volume.SizeRemaining), $($volume.OperationalStatus)" } }
if ($ntfsCheck -eq $null -or $ntfsCheck -eq "") { SilentlyContinue } else { Write-Output "WN10-00-000050 - $ntfsCheck" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000055"
# "Alternate operating systems must not be permitted on the same system."
$alternateOS = bcdedit /enum all | Out-String
if ($alternateOS.Contains("Windows 11") -or $alternateOS.Contains("Linux")) { Write-Output "WN10-00-000055" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Confirm whether print is allowed"
# "WN10-00-000060"
# "Confirm only approved shares exist"
$shares = Get-WmiObject -Class Win32_Share
$allowedShares = @("ADMIN$", "C$", "IPC$", "print$")
$shareNames = $shares.Name
if ($shareNames | Where-Object { $_ -notin $allowedShares }) { Write-Output "WN10-00-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000065"
# "Confirm accounts last login
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
   $user = ([ADSI]$_.Path)
   $lastLogin = $user.Properties.LastLogin.Value
   $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
   if ($lastLogin -eq $null) {
      $lastLogin = 'Never'
   }
   if ($enabled -eq $true -and $user.Name -ne 'noaccess') { Write-Host "WN10-00-000065 $($user.Name) $($lastLogin) $($enabled)" }
}
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#find out what accounts are approved to be administrators
"WN10-00-000070"
"Administrators group must only contain approved accounts"
Get-LocalGroupMember Administrators

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Confirm no backup operators account in BARA"
# "WN10-00-000075"
# "Only accounts responsible for the backup operations must be members of the Backup Operators group."
$backupOperators = Get-LocalGroupMember "Backup Operators"
if ($backupOperators -ne $null) { Write-Output "WN10-00-000075" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000080"
# "Only authorized user accounts must be allowed to create or run virtual machines"
$hyperVAdmins = Get-LocalGroupMember "Hyper-V Administrators"
if ($hyperVAdmins -ne $null) { Write-Output "WN10-00-000080" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"!!!!!!!!!!!!!!!!!!alter xyz to your organization local accounts!!!!!!!!!!!!!!!!!!!"
# "WN10-00-000085"
# "If local users other than the accounts listed below exist on a workstation in a domain, this is a finding."
$localUsers = Get-LocalUser
$localUserNames = $localUsers.Name
$allowedUsers = @("built in admin", "built in guest", "DefaultAccount", "noaccess", "defaultuser0", "WDAGUtilityAccount")
if ($localUserNames | Where-Object { $_ -notin $allowedUsers }) { Write-Output "WN10-00-000085" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000090"
# "Accounts must be configured to require password expiration."
$neverExpireAccounts = Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.Enabled -eq $true }
if ($neverExpireAccounts -ne $null) { Write-Output "WN10-00-000090" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000095, WN10-SO-000160"
# "Permissions for system files and directories must conform to minimum requirements."
$subcategoryAuditing = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
if ($subcategoryAuditing.everyoneincludesanonymous -ne 0) { Write-Output "WN10-00-000095, WN10-SO-000160" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000100"
# "Internet Information System (IIS) or its subcomponents must not be installed"
$iisInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Internet Information Services*" }
if ($iisInstalled -ne $null) { Write-Output "WN10-00-000100" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000105"
# "Simple Network Management Protocol (SNMP) must not be installed on the system."
$snmpInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*SNMP*" }
if ($snmpInstalled -ne $null) { Write-Output "WN10-00-000105" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#"WN10-00-000110"
# "Simple TCPIP Services must not be installed on the system."
$simpletcpipInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Simple TCPIP Services*" }
if ($simpletcpipInstalled -ne $null) { Write-Output "WN10-00-000105" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000115"
# "The Telnet Client must not be installed on the system."
$telnetclientInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Telnet Client*" }
if ($telnetclientInstalled -ne $null) { Write-Output "WN10-00-000115" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000120"
# "The TFTP Client must not be installed on the system."
$tftpclientInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*TFTP Client*" }
if ($tftpclientInstalled -ne $null) { Write-Output "WN10-00-000120" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000130"
# "Software certificate installation files must be removed from Windows 10."
$job = Start-Job -ScriptBlock {
    Get-ChildItem -Path C:\ -Include *.p12,*.pfx -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
}
$lingeringCertificateFiles = if (Wait-Job $job -Timeout 60) {
    Receive-Job $job
} else {
    Stop-Job $job
    $null
}
Remove-Job $job -Force
if ($lingeringCertificateFiles -ne $null) { Write-Output "WN10-00-000130"; Write-Output $lingeringCertificateFiles }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000135"
# "Check Windows Firewall is running"
$windowsFirewall = $allWindowsServices | where {$_.DisplayName -Like "*firewall*"} | Select Status,DisplayName | Out-String
if ($windowsFirewall.Contains('Running Windows Defender Firewall') -eq $false) { Write-Output "WN10-00-000135" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000140"
# "Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts."
$firewallInboundCheck = Get-NetFirewallRule -Direction Inbound | Format-Table -Property Name, DisplayName, Enabled, Action, Protocol, LocalPort, RemotePort | Out-String
if ($firewallInboundCheck.Contains('Microsoft Photos')) { Write-Output "WN10-00-000140" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000145"
# "Data Execution Prevention (DEP) must be configured to at least OptOut."
$optOutTest = bcdedit /enum "{current}" | Out-String
if ($optOutTest.Contains("OptOut") -eq $false -and $optOutTest.Contains("AlwaysOn") -eq $false) { Write-Output "WN10-00-000145" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000150"
# "(SEHOP) must be enabled. This is applicable to Windows 10 prior to v1709."
$exceptionChainValidation = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\kernel\
if ($exceptionChainValidation.DisableExceptionChainValidation -ne 0) { Write-Output "WN10-00-000150" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000155"
# "Ensure PowerShell 2.0 is disabled"
$v2ps = Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2* | Out-String
if ($v2ps.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000155" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000160"
# "The Server Message Block (SMB) v1 protocol must be disabled on the system."
$smbv1Check = Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | Out-String
if ($smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000160" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000165"
# "The SMBv1 protocol must be disabled on the SMB server. If WN16-00-000160 passes, this is N/A."
$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
if ($lanmanServerParameters.SMB1 -ne 0 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000165" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000170"
# "(SMB) v1 protocol must be disabled on the SMB client. If WN16-00-000160 passes, this is N/A."
$smbv1ClientCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
if ($smbv1ClientCheck.Start -ne 4 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000170" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Deviation"
# "WN10-00-000175"
# "The Secondary Logon service must be disabled on Windows 10."
# $secondaryLogonCheck = $allWindowsServices | where {$_.DisplayName -Like "*Secondary*"} | Select Status,DisplayName | Out-String
# if ($secondaryLogonCheck.Contains('Running') -eq $true) { Write-Output "WN10-00-000175" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Go back to add in valid group and user SIDs to compare to"
"WN10-00-000190"
"Orphaned security identifiers (SIDs) must be removed from user rights on Windows 10."
# Grab the content and then compare it to data I pulled from a domain-joined workstation
$userSIDs = @()
$groupSIDs = @()
$exportPath = "$env:TEMP\secpol.inf"
secedit /export /cfg $exportPath
$policyContent = Get-Content $exportPath
$sidLines = $policyContent | Select-String "Se"
$unresolvedSids = $sidLines | Where-Object { $_ -match 'S-1-' }

# Import-Module ActiveDirectory

# Get all AD users and groups and their SIDs
# Get-ADUser -Filter * -Property SID | Select-Object -Property Name, SID
# Get-ADGroup -Filter * -Property SID | Select-Object -Property Name, SID



# # Function to resolve SID to NT Account name
# function Resolve-SID {
#     param (
#         [string]$Sid
#     )
    
#     try {
#         $sid = New-Object System.Security.Principal.SecurityIdentifier($Sid)
#         $account = $sid.Translate([System.Security.Principal.NTAccount])
#         return $account.Value
#     }
#     catch {
#         return $null
#     }
# }

# # Function to check if an account exists in the domain
# function Test-AccountExists {
#     param (
#         [string]$AccountName
#     )
    
#     try {
#         $user = Get-ADUser -Filter {SamAccountName -eq $AccountName} -ErrorAction Stop
#         return $true
#     }
#     catch {
#         return $false
#     }
# }

# # Function to check if a group exists in the domain
# function Test-GroupExists {
#     param (
#         [string]$GroupName
#     )
    
#     try {
#         $group = Get-ADGroup -Filter {SamAccountName -eq $GroupName} -ErrorAction Stop
#         return $true
#     }
#     catch {
#         return $false
#     }
# }

# # Extract the unresolved SIDs from the security policy file
# $exportPath = "$env:TEMP\secpol.inf"
# $policyContent = Get-Content $exportPath
# $sidPattern = 'S-1-\d{2,}'

# $sidLines = $policyContent | Select-String -Pattern $sidPattern

# # Process each SID line
# $report = @()
# $sidLines | ForEach-Object {
#     $line = $_.Line
#     if ($line -match $sidPattern) {
#         $sid = $matches[0]
#         $resolvedAccount = Resolve-SID $sid
        
#         if ($resolvedAccount) {
#             $isUser = Test-AccountExists -AccountName $resolvedAccount
#             $isGroup = Test-GroupExists -GroupName $resolvedAccount
            
#             if (-not ($isUser -or $isGroup)) {
#                 $report += [PSCustomObject]@{
#                     Line = $line
#                     UnresolvedSID = $sid
#                     ResolvedAccount = $resolvedAccount
#                     Status = "Invalid"
#                 }
#             }
#         }
#         else {
#             $report += [PSCustomObject]@{
#                 Line = $line
#                 UnresolvedSID = $sid
#                 ResolvedAccount = $null
#                 Status = "Cannot Resolve"
#             }
#         }
#     }
# }

# # Output the results
# $report | Format-Table -AutoSize
# $report | Export-Csv -Path "$env:TEMP\UnresolvedSIDs_Report.csv" -NoTypeInformation


"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000210, WN10-00-000220, WN10-00-000230"
# "Bluetooth must be turned off"
$bluetoothStatus = Get-NetAdapter Where-Object { $_.Name -like "*Bluetooth*" } | Out-String
if ($bluetoothStatus -ne $null -and $bluetoothStatus.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000210, WN10-00-000220, WN10-00-000230" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000005"
# "account lockout duration must be configured to 15 minutes or greater"
$lockoutDuractionCheck = $policyContent | Select-String "LockoutDuration" | Out-String
if ($lockoutDuractionCheck.Contains('900') -eq $false) { Write-Output "WN10-AC-000005 - $lockoutDuractionCheck" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000010"
# "The number of allowed bad logon attempts must be configured to 3 or less."
$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Output "WN10-AC-000010 - $lockoutBadCountCheck" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000015"
# "The period of time before the bad logon counter is reset must be configured to 15 minutes."
$lockoutCounterReset = $policyContent | Select-String "ResetLockoutCount" | Out-String
if ($lockoutCounterReset.Contains('900') -eq $false) { Write-Output "WN10-AC-000015 - $lockoutCounterReset" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000020"
# "The password history must be configured to 24 passwords remembered."
$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
if ($passwordHistorySize.Contains('24') -eq $false) { Write-Output "WN10-AC-000020 - $passwordHistorySize" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000025"
# "The maximum password age must be configured to 60 days or less."
$maxPasswordAge = $policyContent | Select-String "MaximumPasswordAge" | Out-String
if ($maxPasswordAge.Contains('60') -eq $false) { Write-Output "WN10-AC-000025 - $maxPasswordAge" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000030"
# "The minimum password age must be configured to at least 1 day."
$minPasswordAge = $policyContent | Select-String "MinimumPasswordAge" | Out-String
if ($minPasswordAge.Contains('1') -eq $false) { Write-Output "WN10-AC-000030 - $minPasswordAge" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000035"
# "Passwords must, at a minimum, be 14 characters."
$minPasswordLength = $policyContent | Select-String "MinimumPasswordLength" | Out-String
if ($minPasswordLength.Contains('14') -eq $false) { Write-Output "WN10-AC-000035 - $minPasswordLength" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000040"
# "The built-in Microsoft password complexity filter must be enabled."
$passwordComplexityFilter = $policyContent | Select-String "PasswordComplexity" | Out-String
if ($passwordComplexityFilter.Contains('1') -eq $false) { Write-Output "WN10-AC-000040 - $passwordComplexityFilter" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000045"
# "Reversible password encryption must be disabled."
$reversiblePasswordEncryption = $policyContent | Select-String "ClearTextPassword" | Out-String
if ($reversiblePasswordEncryption.Contains('0') -eq $false) { Write-Output "WN10-AC-000045 - $reversiblePasswordEncryption" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000030"
# "Audit policy using subcategories must be enabled."
# "Subsequent audit policy checks are dependent on this policy being enabled."
if ($subcategoryAuditing.scenoapplylegacyauditpolicy -ne 1) { Write-Output "WN10-SO-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000005, WN10-AU-000010"
# "The system must be configured to audit Account Logon - Credential Validation successes and failures."
$auditPolicyAll = AuditPol /get /category:*
$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
if ($credentialValidationCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000005, WN10-AU-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000030"
# "The system must be configured to audit Account Management - Security Group Management successes."
$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
if ($securityGroupManagementCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000035, WN10-AU-000040"
# "The system must be configured to audit Account Management - User Account Management successes and failures."
$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
if ($userAccountManagementCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000035, WN10-AU-000040" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000045"
# "The system must be configured to audit Detailed Tracking - PNP Activity successes."
$pnpActivityCheck = $auditPolicyAll | Select-String "Plug and Play Events" | Out-String
if ($credentialValidationCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000045" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000050, WN10-AU-000585"
# "The system must be configured to audit Detailed Tracking - Process Creation successes and failures."
$procCreationCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
if ($procCreationCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000050" }
if ($procCreationCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000585" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000054"
# "The system must be configured to audit Logon/Logoff - Account Lockout failures."
$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
if ($accountLockoutCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000054" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000060"
# "The system must be configured to audit Logon/Logoff - Group Membership successes."
$groupMembershipCheck = $auditPolicyAll | Select-String "Group Membership" | Out-String
if ($groupMembershipCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000065"
# "The system must be configured to audit Logon/Logoff - Logoff successes."
$logoffCheck = $auditPolicyAll | Select-String "Logoff" | Out-String
if ($logoffCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000065" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000070, WN10-AU-000075"
# "The system must be configured to audit Logon/Logoff - Logon successes and failures."
$logonCheck = $auditPolicyAll | Select-String "Logon" | Out-String
if ($logonCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000070, WN10-AU-000075" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-AU-000080"
"The system must be configured to audit Logon/Logoff - Special Logon successes."
$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
if ($specialLogonCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000080" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000081, WN10-AU-000082"
# "Windows 10 must be configured to audit Object Access - File Share successes and failures."
$fileShareCheck = $auditPolicyAll | Select-String "File Share" | Out-String
if ($fileShareCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000081, WN10-AU-000082" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000083, WN10-AU-000084"
# "Windows 10 must be configured to audit Object Access - Other Object Access Events successes and failures."
$otherObjectAccessCheck = $auditPolicyAll | Select-String "Other Object Access Events" | Out-String
if ($otherObjectAccessCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000083, WN10-AU-000084" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000085, WN10-AU-000090"
# "The system must be configured to audit Object Access - Removable Storage successes and failures."
$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
if ($removableStorageCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000085, WN10-AU-000090" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000100"
# "The system must be configured to audit Policy Change - Audit Policy Change successes."
$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
if ($auditPolicyChangeCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000100" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000105"
# "The system must be configured to audit Policy Change - Authentication Policy Change successes."
$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
if ($authenticationPolicyChangeCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000105" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000107"
# "The system must be configured to audit Policy Change - Authorization Policy Change successes."
$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
if ($authorizationPolicyChangeCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000107" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000110, WN10-AU-000115"
# "The system must be configured to audit Privilege Use - Sensitive Privilege Use successes and failures."
$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
if ($sensitivePrivilegeUseCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000110, WN10-AU-000115" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000120"
# "The system must be configured to audit System - IPSec Driver failures."
$ipsecDriverCheck = $auditPolicyAll | Select-String "IPSec Driver" | Out-String
if ($ipsecDriverCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000120" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000130, WN10-AU-000135"
# "The system must be configured to audit System - Other System Events successes and failures."
$otherSystemEventsCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
if ($otherSystemEventsCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000130, WN10-AU-000135" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000140"
# "The system must be configured to audit System - Security State Change successes."
$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
if ($securityStateChangeCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000140" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000150"
# "The system must be configured to audit System - Security System Extension successes."
$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
if ($securitySystemExtensionCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000150" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000155, WN10-AU-000160"
# "The system must be configured to audit System - System Integrity successes and failures."
$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
if ($systemIntegrityCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000155, WN10-AU-000160" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000500"
# "The Application event log size must be configured to 32768 KB or greater."
$eventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
if ($eventLogSize.MaxSize -lt 32768) { Write-Output "WN10-AU-000500" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000505"
# "The Security event log size must be configured to 1024000 KB or greater."
$securityEventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
if ($securityEventLogSize.MaxSize -lt 1024000) { Write-Output "WN10-AU-000505" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000510"
# "The System event log size must be configured to 32768 KB or greater."
$systemEventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
if ($systemEventLogSize.MaxSize -lt 32768) { Write-Output "WN10-AU-000510" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000515"
# "Windows 10 permissions for the Application event log must prevent access by non-privileged accounts."
$applicationEventLogACL = (Get-Acl C:\Windows\System32\winevt\Logs\Application.evtx).Access

$requiredPermissions = @(
    @{Identity = "NT SERVICE\EventLog"; Rights = "FullControl"},
    @{Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl"},
    @{Identity = "BUILTIN\Administrators"; Rights = "FullControl"}
)

$missingPermissions = $requiredPermissions | Where-Object {
    $permission = $_
    -not ($applicationEventLogACL | Where-Object {
        $_.IdentityReference -eq $permission.Identity -and
        $_.FileSystemRights -eq $permission.Rights
    })
}

if ($missingPermissions) {
    Write-Output "WN10-AU-000515"
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000520"
# "Windows 10 permissions for the Security event log must prevent access by non-privileged accounts."
$securityEventLogACL = (Get-Acl C:\Windows\System32\winevt\Logs\Security.evtx).Access

$requiredPermissions = @(
    @{Identity = "NT SERVICE\EventLog"; Rights = "FullControl"},
    @{Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl"},
    @{Identity = "BUILTIN\Administrators"; Rights = "FullControl"}
)

$missingPermissions = $requiredPermissions | Where-Object {
    $permission = $_
    -not ($securityEventLogACL | Where-Object {
        $_.IdentityReference -eq $permission.Identity -and
        $_.FileSystemRights -eq $permission.Rights
    })
}

if ($missingPermissions) {
    Write-Output "WN10-AU-000520"
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000525"
# "Windows 10 permissions for the System event log must prevent access by non-privileged accounts."
$systemEventLogACL = (Get-Acl C:\Windows\System32\winevt\Logs\System.evtx).Access

$requiredPermissions = @(
    @{Identity = "NT SERVICE\EventLog"; Rights = "FullControl"},
    @{Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl"},
    @{Identity = "BUILTIN\Administrators"; Rights = "FullControl"}
)

$missingPermissions = $requiredPermissions | Where-Object {
    $permission = $_
    -not ($systemEventLogACL | Where-Object {
        $_.IdentityReference -eq $permission.Identity -and
        $_.FileSystemRights -eq $permission.Rights
    })
}

if ($missingPermissions) {
    Write-Output "WN10-AU-000525"
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000555"
# "Windows 10 must be configured to audit Other Policy Change Events Failures."
$otherPolicyChangeEventsCheck = $auditPolicyAll | Select-String "Other Policy Change Events" | Out-String
if ($otherPolicyChangeEventsCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000555" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000560, WN10-AU-000565"
# "Windows 10 must be configured to audit other Logon/Logoff Events Successes and Failures."
$otherLogonLogoffEventsCheck = $auditPolicyAll | Select-String "Other Logon/Logoff Events" | Out-String
if ($otherLogonLogoffEventsCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000560" }
if ($otherLogonLogoffEventsCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000565" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000570"
# "Windows 10 must be configured to audit Detailed File Share Failures."
$detailedFileShareCheck = $auditPolicyAll | Select-String "Detailed File Share" | Out-String
if ($detailedFileShareCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000570" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000575, WN10-AU-000580"
# "Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Successes."
$mpssvcRuleLevelPolicyChangeCheck = $auditPolicyAll | Select-String "MPSSVC Rule-Level Policy Change" | Out-String
if ($mpssvcRuleLevelPolicyChangeCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000575" }
if ($mpssvcRuleLevelPolicyChangeCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000580" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000005"
# "Camera access from the lock screen must be disabled."
$cameraAccessFromLockScreen = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
if ($cameraAccessFromLockScreen.NoLockScreenCamera -ne 1) { Write-Output "WN10-CC-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000007"
# "Windows 10 must cover or disable the built-in or attached camera when not in use."
$cameraDisableCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
$cameraDisableCheckValue = $cameraDisableCheck.Value
if ($cameraDisableCheckValue -ne 'Deny') { Write-Output "WN10-CC-000007 - $cameraDisableCheckValue" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000010"
# "The display of slide shows on the lock screen must be disabled."
if ($cameraAccessFromLockScreen.NoLockScreenSlideshow -ne 1) { Write-Output "WN10-CC-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000020"
# "IPv6 source routing must be configured to highest protection."
$ip6ParametersCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
if ($ip6ParametersCheck.DisableIPSourceRouting -ne 2) { Write-Output "WN10-CC-000020" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000025"
# "The system must be configured to prevent IP source routing."
$ipParametersCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
if ($ipParametersCheck.DisableIPSourceRouting -ne 2) { Write-Output "WN10-CC-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000030"
# "The system must be configured to prevent ICMP redirects from overriding OSPF generated routes."
if ($ipParametersCheck.EnableICMPRedirect -ne 0) { Write-Output "WN10-CC-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000035"
# "The system must be configured to ignore NetBIOS name release requests except from WINS servers."
$netBTParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
if ($netBTParameters.NoNameReleaseOnDemand -ne 1) { Write-Output "WN10-CC-000035" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000037"
# "Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems."
$currentVersionPoliciesSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
if ($currentVersionPoliciesSystem.LocalAccountTokenFilterPolicy -ne 0) { Write-Output "WN10-CC-000037" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000038"
# "WDigest Authentication must be disabled."
$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Output "WN10-CC-000038" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Deviation"
# "WN10-CC-000039"
# "Run as different user must be removed from context menus."
# $runAsUser = Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\
# if ($runAsUser.SuppressionPolicy -ne 4096) { Write-Output "WN10-CC-000039" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000040"
# "Insecure logons to an SMB server must be disabled."
$lanmanWorkstationInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
if ($lanmanWorkstationInfo.AllowInsecureGuestAuth -ne 0) { Write-Output "WN10-CC-000040" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000044"
# "Internet connection sharing must be disabled."
$networkConnectionsInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network` Connections\
if ($networkConnectionsInfo.NC_ShowSharedAccessUI -ne 0) { Write-Output "WN10-CC-000044" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000052"
# "Windows 10 must be configured to prioritize ECC Curves with longer key lengths first."
$eccCurvesInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
$eccCurvesValue = $eccCurvesInfo.EccCurves
if ($eccCurvesValue.Contains('NistP384') -eq $false -or $eccCurvesValue.Contains('NistP256') -eq $false) { Write-Output "WN10-CC-000052" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000055"
# "Simultaneous connections to the internet or a Windows domain must be limited."
$simultaneousConnectionsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
$simultaneousConnectionsCheckConnectionsValue = $simultaneousConnectionsCheck.fMinimizeConnections  
if ($simultaneousConnectionsCheckConnectionsValue -ne 3) { Write-Output "WN10-CC-000055 - $simultaneousConnectionsCheckConnectionsValue" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000060"
# "Connections to non-domain networks when connected to a domain authenticated network must be blocked."
if ($simultaneousConnectionsCheck.fBlockNonDomain -ne 1) { Write-Output "WN10-CC-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000065"
# "Wi-Fi Sense must be disabled. This is NA as of v1803 of Windows 10"

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000066"
# "Command line data must be included in process creation events."
$commandLineDataCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
if ($commandLineDataCheck.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Output "WN10-CC-000066" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000068"
# "Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials."
$remoteHostDelegationCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
if ($remoteHostDelegationCheck.AllowProtectedCreds -ne 1) { Write-Output "WN10-CC-000068" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000070"
# "Virtualization Based Security must be enabled on Windows 10 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection."
$vbsDetailsCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$vbsRequiredSecurityProperties = $vbsDetailsCheck.RequiredSecurityProperties | Out-String
if ($vbsRequiredSecurityProperties.Contains('2') -eq $false) { Write-Output "WN10-CC-000070" }
if ($vbsDetailsCheck.VirtualizationBasedSecurityStatus -ne 2) { Write-Output "WN10-CC-000070" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000075"
# "Credential Guard must be running on Windows 10 domain-joined systems."
$vbsSecurityServicesRunning = $vbsDetailsCheck.SecurityServicesRunning | Out-String
if ($vbsSecurityServicesRunning.Contains('1') -eq $false) { Write-Output "WN10-CC-000075" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000085"
# "Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers."
$elamCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
if ($elamCheck.DriverLoadPolicy -notin @(1, 3, 8)) { Write-Output "WN10-CC-000085" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000090"
# "Group Policy objects must be reprocessed even if they have not changed."
$gpoReprocessCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ($gpoReprocessCheck.NoGPOListChanges -ne 0) { Write-Output "WN10-CC-000090" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000100"
# "Downloading print driver packages over HTTP must be prevented."
$httpPrintDriverCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\
if ($httpPrintDriverCheck.DisableWebPnPDownload -ne 1) { Write-Output "WN10-CC-000100" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000105"
# "Web publishing and online ordering wizards must be prevented from downloading a list of providers."
$webPubWizards = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
if ($webPubWizards.NoWebServices -ne 1) { Write-Output "WN10-CC-000105" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000110"
# "Printing over HTTP must be prevented."
if ($httpPrintDriverCheck.DisableHTTPPrinting -ne 1) { Write-Output "WN10-CC-000100" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000115"
# "Systems must at least attempt device authentication using certificates."
$certificateDeviceAuthCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
if ($certificateDeviceAuthCheck.DevicePKInitEnabled -eq 0) { Write-Output "WN10-CC-000115" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Deviation"
# "WN10-CC-000120"
# "The network selection user interface (UI) must not be displayed on the logon screen."
$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
# if ($windowsSystemChecks.DontDisplayNetworkSelectionUI -ne 1) { Write-Output "WN10-CC-000120" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000130"
# "Local users on domain-joined computers must not be enumerated."
if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Output "WN10-CC-000130" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000145"
# "Users must be prompted for a password on resume from sleep (on battery)."
$dcSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
if ($dcSettingsCheck.DCSettingIndex -ne 1) { Write-Output "WN10-CC-000145" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000150"
# "The user must be prompted for a password on resume from sleep (plugged in)."
if ($dcSettingsCheck.ACSettingIndex -ne 1) { Write-Output "WN10-CC-000150" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000155"
# "Solicited Remote Assistance must not be allowed."
$terminalServicesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\
if ($terminalServicesCheck.fAllowToGetHelp -ne 0) { Write-Output "WN10-CC-000155" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000165"
# "Unauthenticated RPC clients must be restricted from connecting to the RPC server."
$rpcSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\
if ($rpcSettingsCheck.RestrictRemoteClients -ne 1) { Write-Output "WN10-CC-000165" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000170"
# "The setting to allow Microsoft accounts to be optional for modern style apps must be enabled."
if ($currentVersionPoliciesSystem.MSAOptional -ne 1) { Write-Output "WN10-CC-000170" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000175"
# "The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Output "WN10-CC-000175" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000180"
# "Autoplay must be turned off for non-volume devices."
$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Output "WN10-CC-000180" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000185"
# "The default autorun behavior must be configured to prevent autorun commands."
if ($webPubWizards.NoAutorun -ne 1) { Write-Output "WN10-CC-000185" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000190"
# "Autoplay must be disabled for all drives."
if ($webPubWizards.NoDriveTypeAutoRun -ne 255) { Write-Output "WN10-CC-000190" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000195"
# "Enhanced anti-spoofing for facial recognition must be enabled on Window 10."
$biometricsFacialFeatures = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\
if ($biometricsFacialFeatures.EnhancedAntiSpoofing -ne 1) { Write-Output "WN10-CC-000195" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000197"
# "Microsoft consumer experiences must be turned off."
$cloudContentSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\
if ($cloudContentSettingsCheck.DisableWindowsConsumerFeatures -ne 1) { Write-Output "WN10-CC-000197" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000200"
# "Administrator accounts must not be enumerated during elevation."
$credUIPoliciesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
if ($credUIPoliciesCheck.EnumerateAdministrators -ne 0) { Write-Output "WN10-CC-000200" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000204"
# "If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics."
$dataCollectionSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
$dataCollectionSettingsLimitEnhancedDiagnosticDataWindowsAnalyticsValue = $dataCollectionSettings.LimitEnhancedDiagnosticDataWindowsAnalytics   
if ($dataCollectionSettingsLimitEnhancedDiagnosticDataWindowsAnalyticsValue -ne 1) { Write-Output "WN10-CC-000204 - $dataCollectionSettingsLimitEnhancedDiagnosticDataWindowsAnalyticsValue" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000205"
# "Windows Telemetry must not be configured to Full."
if ($dataCollectionSettings.AllowTelemetry -notin @(0, 1)) { Write-Output "WN10-CC-000205" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000206"
# "Windows Update must not obtain updates from other PCs on the internet."
$deliveryOptimizationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
if ($deliveryOptimizationSettings.DODownloadMode -eq 3) { Write-Output "WN10-CC-000206" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000210"
# "The Windows Defender SmartScreen for Explorer must be enabled."
if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Output "WN10-CC-000210" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000215"
# "Explorer Data Execution Prevention must be enabled."
if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -ne $null -and $windowsExplorerSettingsCheck.NoDataExecutionPrevention -ne 0) { Write-Output "WN10-CC-000215" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000220"
# "Turning off File Explorer heap termination on corruption must be disabled."
if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -ne $null -and $windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -ne 0) { Write-Output "WN10-CC-000220" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000225"
# "File Explorer shell protocol must run in protected mode."
if ($webPubWizards.PreXPSP2ShellProtocolBehavior -ne $null -and $webPubWizards.PreXPSP2ShellProtocolBehavior -ne 0) { Write-Output "WN10-CC-000225" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000230"
# "Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge."
$phishingFilterCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
if ($phishingFilterCheck.PreventOverride -ne 1) { Write-Output "WN10-CC-000230" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000235"
# "Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge."
if ($phishingFilterCheck.PreventOverrideAppRepUnknown -ne 1) { Write-Output "WN10-CC-000235" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000238"
# "Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge."
$edgeInternetSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet` Settings\
$edgeInternetSettingsCheckPreventCertErrorOverridesValue = $edgeInternetSettingsCheck.PreventCertErrorOverrides 
if ($edgeInternetSettingsCheckPreventCertErrorOverridesValue -ne 1) { Write-Output "WN10-CC-000238 - $edgeInternetSettingsCheckPreventCertErrorOverridesValue" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000245"
# "The password manager function in the Edge browser must be disabled."
$mainEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\
if ($mainEdgeSettings.'FormSuggest Passwords' -ne 'no') { Write-Output "WN10-CC-000245" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000250"
# "The Windows Defender SmartScreen filter for Microsoft Edge must be enabled."
if ($phishingFilterCheck.EnabledV9 -ne 1) { Write-Output "WN10-CC-000250" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000252"
# "Windows 10 must be configured to disable Windows Game Recording and Broadcasting."
$gameDVRChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\
if ($gameDVRChecks.AllowGameDVR -ne 0) { Write-Output "WN10-CC-000252" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000255"
# "The use of a hardware security device with Windows Hello for Business must be enabled."
$passportForWorkChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\
if ($passportForWorkChecks.RequireSecurityDevice -ne 1) { Write-Output "WN10-CC-000255" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000260"
# "Windows 10 must be configured to require a minimum pin length of six characters or greater."
$passportPinLength = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\
if ($passportPinLength.MinimumPINLength -lt 6) { Write-Output "WN10-CC-000260" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000270"
# "Passwords must not be saved in the Remote Desktop Client."
if ($terminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Output "WN10-CC-000270" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000275"
# "Local drives must be prevented from sharing with Remote Desktop Session Hosts."
if ($terminalServicesCheck.fDisableCdm -ne 1) { Write-Output "WN10-CC-000275" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000280"
# "Remote Desktop Services must always prompt a client for passwords upon connection."
if ($terminalServicesCheck.fPromptForPassword -ne 1) { Write-Output "WN10-CC-000280" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000285"
# "The Remote Desktop Session Host must require secure RPC communications."
if ($terminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Output "WN10-CC-000285" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000290"
# "Remote Desktop Services must be configured with the client connection encryption set to the required level."
if ($terminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Output "WN10-CC-000290" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000295"
# "Attachments must be prevented from being downloaded from RSS feeds."
$internetExplorerFeeds = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\
if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Output "WN10-CC-000295" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000300"
# "Basic authentication for RSS feeds over HTTP must not be used."
if ($internetExplorerFeeds.AllowBasicAuthInClear -ne 0 -and $internetExplorerFeeds.AllowBasicAuthInClear -ne $null) { Write-Output "WN10-CC-000300" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000305"
# "Indexing of encrypted files must be turned off."
$windowsSearchCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\
if ($windowsSearchCheck.AllowIndexingEncryptedStoresOrItems -ne 0) { Write-Output "WN10-CC-000305" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000310"
# "Users must be prevented from changing installation options."
$installerSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
if ($installerSettings.EnableUserControl -ne 0) { Write-Output "WN10-CC-000310" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000315"
# "The Windows Installer Always install with elevated privileges must be disabled."
if ($installerSettings.AlwaysInstallElevated -ne 0) { Write-Output "WN10-CC-000315" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000320"
# "Users must be notified if a web-based program attempts to install software."
if ($installerSettings.SafeForScripting -ne 0 -and $installerSettings.SafeForScripting -ne $null) { Write-Output "WN10-CC-000320" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000325"
# "Automatically signing in the last interactive user after a system-initiated restart must be disabled."
if ($currentVersionPoliciesSystem.DisableAutomaticRestartSignOn -ne 1) { Write-Output "WN10-CC-000325" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000326"
# "PowerShell script block logging must be enabled on Windows 10."
$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Output "WN10-CC-000326" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000328"
# "The Windows Explorer Preview pane must be disabled for Windows 10."
$webPubWizardsNoPreviewPaneValue = $webPubWizards.NoPreviewPane 
if ($webPubWizardsNoPreviewPaneValue -ne 1) { Write-Output "WN10-CC-000328 - $webPubWizardsNoPreviewPaneValue" }
$webPubWizardsNoReadingPaneValue = $webPubWizards.NoReadingPane
if ($webPubWizardsNoReadingPaneValue -ne 1) { Write-Output "WN10-CC-000328 - $webPubWizardsNoReadingPaneValue" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000330"
# "The Windows Remote Management (WinRM) client must not use Basic authentication."
$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
if ($winrmClientCheck.AllowBasic -ne 0) { Write-Output "WN10-CC-000330" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000335"
# "The Windows Remote Management (WinRM) client must not allow unencrypted traffic."
if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Output "WN10-CC-000335" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000345"
# "The Windows Remote Management (WinRM) service must not use Basic authentication."
$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Output "WN10-CC-000345" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000350"
# "The Windows Remote Management (WinRM) service must not allow unencrypted traffic."
if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Output "WN10-CC-000350" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000355"
# "The Windows Remote Management (WinRM) service must not store RunAs credentials."
if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Output "WN10-CC-000355" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000360"
# "The Windows Remote Management (WinRM) client must not use Digest authentication."
if ($winrmClientCheck.AllowDigest -ne 0) { Write-Output "WN10-CC-000360" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000365"
# "Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked."
$appPrivacySettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\
if ($appPrivacySettings.LetAppsActivateWithVoiceAboveLock -ne 2 -and $appPrivacySettings.LetAppsActivateWithVoice -ne 2) { Write-Output "WN10-CC-000365" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000370"
# "The convenience PIN for Windows 10 must be disabled."
if ($windowsSystemChecks.AllowDomainPINLogon -ne 0) { Write-Output "WN10-CC-000370" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000385"
# "Windows Ink Workspace must be configured to disallow access above the lock."
$windowsInkWorkspace = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\
if ($windowsInkWorkspace.AllowWindowsInkWorkspace -ne 1) { Write-Output "WN10-CC-000385" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000390"
# "Windows 10 should be configured to prevent users from receiving suggestions for third-party or additional applications."
$hkcuCloudContentSettingsCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\
if ($hkcuCloudContentSettingsCheck.DisableThirdPartySuggestions -ne 1) { Write-Output "WN10-CC-000390" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-EP-000310"
# "Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled."
$kernelDmaProtection = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel` DMA` Protection\
if ($kernelDmaProtection.DeviceEnumerationPolicy -ne 0) { Write-Output "WN10-EP-000310" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Deviation"
# "WN10-PK-000005"
# "WN10-PK-000010"
# "WN10-PK-000015"
# "WN10-PK-000020"

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-RG-000005"
# "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained."

$hklmSoftwareACL = Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
$softwareIsInherited = $hklmSoftwareACL.IsInherited
$softwareFullControlAdmin = $hklmSoftwareACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Administrators" }
$softwareReadkeyUsers = $hklmSoftwareACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" }
$hklmSystemACL = Get-Acl -Path HKLM:SYSTEM | % { $_.access }
$systemIsInherited = $hklmSystemACL.IsInherited
$systemFullControlAdmin = $hklmSystemACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Administrators" }
$systemReadkeyUsers = $hklmSystemACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" }

if ($softwareReadkeyUsers.Contains("ReadKey") -eq $false -or $systemReadkeyUsers.Contains("ReadKey") -eq $false) { Write-Output "WN10-RG-000005" }
if ($softwareIsInherited.Contains("True") -eq $true -or $systemIsInherited.Contains("True") -eq $true) { Write-Output "WN10-RG-000005" }
if ($softwareFullControlAdmin.Contains("FullControl") -eq $false -or $systemFullControlAdmin.Contains("FullControl") -eq $false) { Write-Output "WN10-RG-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000005"
# "The built-in administrator account must be disabled."
$disableBuiltInAdminCheck = $policyContent | Select-String "EnableAdminAccount" | Out-String
if ($disableBuiltInAdminCheck.Contains("0") -eq $false) { Write-Output "WN10-SO-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000010"
# "The built-in guest account must be disabled."
$disableBuiltInGuestCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
if ($disableBuiltInGuestCheck.Contains("0") -eq $false) { Write-Output "WN10-SO-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000015"
# "Local accounts with blank passwords must be restricted to prevent access from the network."
if ($subcategoryAuditing.LimitBlankPasswordUse -ne 1) { Write-Output "WN10-SO-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000020"
# "The built-in administrator account must be renamed."
$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
if ($newAdminName.Contains("Administrator") -eq $true) { Write-Output "WN10-SO-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000025"
# "The built-in guest account must be renamed."
$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
if ($newGuestName.Contains("Guest") -eq $true) { Write-Output "WN10-SO-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000035"
# "Outgoing secure channel traffic must be encrypted or signed."
$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Output "WN10-SO-000035" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000040"
# "Outgoing secure channel traffic must be encrypted when possible."
if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Output "WN10-SO-000040" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000045"
# "Outgoing secure channel traffic must be signed when possible."
if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Output "WN10-SO-000045" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000050"
# "The computer account password must not be prevented from being reset."
if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Output "WN10-SO-000050" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000055"
# "The maximum age for machine account passwords must be configured to 30 days or less."
if ($netLogonParameters.MaximumPasswordAge -notin 0..30) { Write-Output "WN10-SO-000055" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000060"
# "The system must be configured to require a strong session key."
if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Output "WN10-SO-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000070"
# "The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver."
if ($currentVersionPoliciesSystem.InactivityTimeoutSecs -notin 1..900) { Write-Output "WN10-SO-000070" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000075"
# "The required legal notice must be configured to display before console logon."
if ($currentVersionPoliciesSystem.LegalNoticeText -eq $null) { Write-Output "WN10-SO-000075" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000080"
# "The Windows dialog box title for the legal banner must be configured."
if ($currentVersionPoliciesSystem.LegalNoticeCaption -eq $null) { Write-Output "WN10-SO-000080" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000085"
# "Caching of logon credentials must be limited."
$cachedLogonsCount = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").CachedLogonsCount -as [int]
if ($cachedLogonsCount -gt 10) { Write-Output "WN10-SO-000085" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Deviation"
# "WN10-SO-000095"

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000100"
# "The Windows SMB client must be configured to always perform SMB packet signing."
$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Output "WN10-SO-000100" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000110"
# "Unencrypted passwords must not be sent to third-party SMB Servers."
if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Output "WN10-SO-000110" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000120"
# "The Windows SMB server must be configured to always perform SMB packet signing."
if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Output "WN10-SO-000120" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000140"
# "Anonymous SID/Name translation must not be allowed."
$lsaAnonymousName = $policyContent | Select-String "LSAAnonymousNameLookup" | Out-String
if ($lsaAnonymousName.Contains("1") -eq $true) { Write-Output "WN10-SO-000140" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000145"
# "Anonymous enumeration of SAM accounts must not be allowed."
if ($subcategoryAuditing.RestrictAnonymousSAM -ne 1) { Write-Output "WN10-SO-000145" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000150"
# "Anonymous enumeration of shares must be restricted."
if ($subcategoryAuditing.RestrictAnonymous -ne 1) { Write-Output "WN10-SO-000150" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000165"
# "Anonymous access to Named Pipes and Shares must be restricted."
if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Output "WN10-SO-000165" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000167"
# "Remote calls to the Security Account Manager (SAM) must be restricted to Administrators."
if ($subcategoryAuditing.RestrictRemoteSAM -ne "O:BAG:BAD:(A;;RC;;;BA)") { Write-Output "WN10-SO-000167" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000180"
# "NTLM must be prevented from falling back to a Null session."
$msv1LSAChecks = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\
if ($msv1LSAChecks.allownullsessionfallback -ne 0) { Write-Output "WN10-SO-000180" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000185"
# "PKU2U authentication using online identities must be prevented."
$pku2LSAChecks = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
if ($pku2LSAChecks.AllowOnlineID -ne 0) { Write-Output "WN10-SO-000185" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000190"
# "Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."
$certificateDeviceAuthCheckSupportedEncryptionTypes = $certificateDeviceAuthCheck.SupportedEncryptionTypes
if ($certificateDeviceAuthCheckSupportedEncryptionTypes -ne "2147483640") { Write-Output "WN10-SO-000190 - $certificateDeviceAuthCheckSupportedEncryptionTypes" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000195"
# "The system must be configured to prevent the storage of the LAN Manager hash of passwords."
if ($subcategoryAuditing.NoLMHash -ne 1) { Write-Output "WN10-SO-000195" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000205"
# "The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM."
if ($subcategoryAuditing.LmCompatibilityLevel -ne 5) { Write-Output "WN10-SO-000205" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000210"
# "The system must be configured to the required LDAP client signing level."
$ldapServicesSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
if ($ldapServicesSettings.LDAPClientIntegrity -ne 1) { Write-Output "WN10-SO-000210" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000215"
# "The system must be configured to meet the minimum session security requirement for NTLM SSP based clients."
if ($msv1LSAChecks.NTLMMinClientSec -ne 537395200) { Write-Output "WN10-SO-000215" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000220"
# "The system must be configured to meet the minimum session security requirement for NTLM SSP based servers."
if ($msv1LSAChecks.NTLMMinServerSec -ne 537395200) { Write-Output "WN10-SO-000220" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000230"
# "The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
$fipsAlgorithmPolicy = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
$fipsAlgorithmPolicyEnabled = $fipsAlgorithmPolicy.Enabled
if ($fipsAlgorithmPolicyEnabled -ne 1) { Write-Output "WN10-SO-000230 - $fipsAlgorithmPolicyEnabled" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000240"
# "The default permissions of global system objects must be increased."
$sessionManagerSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\
if ($sessionManagerSettings.ProtectionMode -ne 1) { Write-Output "WN10-SO-000240" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000245"
# "User Account Control approval mode for the built-in Administrator must be enabled."
if ($currentVersionPoliciesSystem.FilterAdministratorToken -ne 1) { Write-Output "WN10-SO-000245" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000250"
# "User Account Control must, at minimum, prompt administrators for consent on the secure desktop."
if ($currentVersionPoliciesSystem.ConsentPromptBehaviorAdmin -ne 2) { Write-Output "WN10-SO-000250" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Deviation"
# "WN10-SO-000251"
# "Windows 10 must use multifactor authentication for local and network access to privileged and nonprivileged accounts."

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "Dev"
# "WN10-SO-000255"
# "User Account Control must automatically deny elevation requests for standard users."
# if ($currentVersionPoliciesSystem.ConsentPromptBehaviorUser -ne 0) { Write-Output "WN10-SO-000255" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000260"
# "User Account Control must be configured to detect application installations and prompt for elevation."
if ($currentVersionPoliciesSystem.EnableInstallerDetection -ne 1) { Write-Output "WN10-SO-000260" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000265"
# "User Account Control must only elevate UIAccess applications that are installed in secure locations."
if ($currentVersionPoliciesSystem.EnableSecureUIAPaths -ne 1) { Write-Output "WN10-SO-000265" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000270"
# "User Account Control must run all administrators in Admin Approval Mode, enabling UAC."
if ($currentVersionPoliciesSystem.EnableLUA -ne 1) { Write-Output "WN10-SO-000270" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000275"
# "User Account Control must virtualize file and registry write failures to per-user locations."
if ($currentVersionPoliciesSystem.EnableVirtualization -ne 1) { Write-Output "WN10-SO-000275" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000280"
# "Passwords for enabled local Administrator accounts must be changed at least every 60 days."
$adminAccountLastPasswordSet = (Get-LocalUser -Name * | Select-Object * | Where-Object {$_.Description -eq "Built-in account for administering the computer/domain" -and $_.Enabled -eq $true})
if ($adminAccountLastPasswordSet) {
    $lastPasswordSet = $adminAccountLastPasswordSet.PasswordLastSet
    $daysSinceLastChange = (Get-Date) - $lastPasswordSet
    if ($daysSinceLastChange.Days -gt 60) {
        Write-Output "WN10-SO-000280"
    }
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UC-000015"
# "Toast notifications to the lock screen must be turned off."
$pushNotifications = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\
if ($pushNotifications.NoToastApplicationNotificationOnLockScreen -ne 1) { Write-Output "WN10-UC-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UC-000020"
# "Zone information must be preserved when saving attachments."
$attachmentsPolicies = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
if ($attachmentsPolicies.SaveZoneInformation -notin @(2, $null)) { Write-Output "WN10-UC-000020" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000005"
# "The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts."
$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
if ($accessCredManagerCheck.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000010"
# "The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups."
$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-32-555")
$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] }
if ($disallowedSIDs) { Write-Output "WN10-UR-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000015"
# "The Act as part of the operating system user right must not be assigned to any groups or accounts."
$actAsPartOfOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
if ($actAsPartOfOSCheck.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000025"
# "The Allow log on locally user right must only be assigned to the Administrators and Users groups."
$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedlogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
$disallowedlogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedlogonSIDs[0] -and $_ -notlike $allowedlogonSIDs[1] }
if ($disallowedlogonSIDs) { Write-Output "WN10-UR-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000030"
# "The Back up files and directories user right must only be assigned to the Administrators group."
$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedBackupSIDs = @("*S-1-5-32-544")
$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
if ($disallowedBackupSIDs) { Write-Output "WN10-UR-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000035"
# "The Change the system time user right must only be assigned to Administrators and Local Service and NT SERVICE\autotimesvc."
$changeSystemTimeSIDs = ($policyContent | Select-String "SeSystemtimePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedChangeSystemTimeSIDs = @("*S-1-5-19", "*S-1-5-32-544")
$disallowedChangeSystemTimeSIDs = $changeSystemTimeSIDs | Where-Object { $_ -notlike $allowedChangeSystemTimeSIDs[0] -and $_ -notlike $allowedChangeSystemTimeSIDs[1] }
if ($disallowedChangeSystemTimeSIDs) { Write-Output "WN10-UR-000035" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000040"
# "The Create a pagefile user right must only be assigned to the Administrators group."
$createPagefileSIDs = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreatePagefileSIDs = @("*S-1-5-32-544")
$disallowedCreatePagefileSIDs = $createPagefileSIDs | Where-Object { $_ -notlike $allowedCreatePagefileSIDs[0] }
if ($disallowedCreatePagefileSIDs) { Write-Output "WN10-UR-000040" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000045"
# "The Create a token object user right must not be assigned to any groups or accounts."
$createTokenObjectSIDs = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
if ($createTokenObjectSIDs.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000045" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000050"
# "The Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service."
$createGlobalObjectsSIDs = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreateGlobalObjectsSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
$disallowedCreateGlobalObjectsSIDs = $createGlobalObjectsSIDs | Where-Object { $_ -notlike $allowedCreateGlobalObjectsSIDs[0] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[1] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[2] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[3] }
if ($disallowedCreateGlobalObjectsSIDs) { Write-Output "WN10-UR-000050" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000055"
# "The Create permanent shared objects user right must not be assigned to any groups or accounts."
$createPermanentSharedObjectsSIDs = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
if ($createPermanentSharedObjectsSIDs.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000055" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000060"
# "The Create symbolic links user right must only be assigned to the Administrators group."
$createSymbolicLinksSIDs = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreateSymbolicLinksSIDs = @("*S-1-5-32-544")
$disallowedCreateSymbolicLinksSIDs = $createSymbolicLinksSIDs | Where-Object { $_ -notlike $allowedCreateSymbolicLinksSIDs[0] }
if ($disallowedCreateSymbolicLinksSIDs) { Write-Output "WN10-UR-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000065"
# "The Debug programs user right must only be assigned to the Administrators group."
$debugProgramsSIDs = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDebugProgramsSIDs = @("*S-1-5-32-544")
$disallowedDebugProgramsSIDs = $debugProgramsSIDs | Where-Object { $_ -notlike $allowedDebugProgramsSIDs[0] }
if ($disallowedDebugProgramsSIDs) { Write-Output "WN10-UR-000065" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-UR-000070"
# "If the following groups or accounts are not defined for the 'Deny access to this computer from the network' right, this is a finding:

# Domain Systems Only:
# Enterprise Admins group
# Domain Admins group
# Local account (see Note below)

# All Systems:
# Guests group"
"update root domain"
$denyAccessToThisComputerSIDs = ($policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyAccessToThisComputerSIDs = @("*S-1-5-root domain-519", "*S-1-5-root domain-512", "*S-1-5-32-546", "*S-1-5-32-113")
$disallowedDenyAccessToThisComputerSIDs = $denyAccessToThisComputerSIDs | Where-Object { $_ -notlike $allowedDenyAccessToThisComputerSIDs[0] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[1] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[2] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[3] }
if ($disallowedDenyAccessToThisComputerSIDs) { Write-Output "WN10-UR-000070" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-UR-000075"
# "If the following groups or accounts are not defined for the 'Deny log on as a batch job' right, this is a finding: Enterprise Admin Group, Domain Admin Group"
"update root domain"
$denyLogOnAsBatchJobSIDs = ($policyContent | Select-String "SeDenyBatchLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnAsBatchJobSIDs = @("*S-1-5-root domain-519", "*S-1-5-root domain-512")
$disallowedDenyLogOnAsBatchJobSIDs = $denyLogOnAsBatchJobSIDs | Where-Object { $_ -notlike $allowedDenyLogOnAsBatchJobSIDs[0] -and $_ -notlike $allowedDenyLogOnAsBatchJobSIDs[1] }
if ($disallowedDenyLogOnAsBatchJobSIDs) { Write-Output "WN10-UR-000075" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-UR-000080"
# "If the following groups or accounts are not defined for the 'Deny log on as a service' right, this is a finding: Enterprise Admins Group, Domain Admins Group"
"update root domain"
$denyLogOnAsServiceSIDs = ($policyContent | Select-String "SeDenyServiceLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnAsServiceSIDs = @("*S-1-5-root domain-519", "*S-1-5-root domain-512")
$disallowedDenyLogOnAsServiceSIDs = $denyLogOnAsServiceSIDs | Where-Object { $_ -notlike $allowedDenyLogOnAsServiceSIDs[0] -and $_ -notlike $allowedDenyLogOnAsServiceSIDs[1] }
if ($disallowedDenyLogOnAsServiceSIDs) { Write-Output "WN10-UR-000080" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-UR-000085"
# "If the following groups or accounts are not defined for the 'Deny log on locally' right, this is a finding. Enterprise Admins Group, Domain Admins Group, Guests Group"
"update root domain"
$denyLogOnLocallySIDs = ($policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnLocallySIDs = @("*S-1-5-root domain-519", "*S-1-5-root domain-512", "*S-1-5-32-546")
$disallowedDenyLogOnLocallySIDs = $denyLogOnLocallySIDs | Where-Object { $_ -notlike $allowedDenyLogOnLocallySIDs[0] -and $_ -notlike $allowedDenyLogOnLocallySIDs[1] -and $_ -notlike $allowedDenyLogOnLocallySIDs[2] }
if ($disallowedDenyLogOnLocallySIDs) { Write-Output "WN10-UR-000085" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-UR-000090"
# "If the following groups or accounts are not defined for the 'Deny log on through Remote Desktop Services' right, this is a finding. Enterprise Admins Group, Domain Admins Group, Local Account, Guests Group"
"update root domain"
$denyLogOnThroughRemoteDesktopServicesSIDs = ($policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnThroughRemoteDesktopServicesSIDs = @("*S-1-5-root domain-519", "*S-1-5-root domain-512", "*S-1-5-32-546", "*S-1-5-32-113")
$disallowedDenyLogOnThroughRemoteDesktopServicesSIDs = $denyLogOnThroughRemoteDesktopServicesSIDs | Where-Object { $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[0] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[1] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[2] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[3] }
if ($disallowedDenyLogOnThroughRemoteDesktopServicesSIDs) { Write-Output "WN10-UR-000090" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000095"
# "The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts."
$enableComputerAndUserAccountsToBeTrustedForDelegationSIDs = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
if ($enableComputerAndUserAccountsToBeTrustedForDelegationSIDs.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000095" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000100"
# "The Force shutdown from a remote system user right must only be assigned to the Administrators group."
$forceShutdownFromRemoteSystemSIDs = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedForceShutdownFromRemoteSystemSIDs = @("*S-1-5-32-544")
$disallowedForceShutdownFromRemoteSystemSIDs = $forceShutdownFromRemoteSystemSIDs | Where-Object { $_ -notlike $allowedForceShutdownFromRemoteSystemSIDs[0] }
if ($disallowedForceShutdownFromRemoteSystemSIDs) { Write-Output "WN10-UR-000100" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000110"
# "The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service."
$impersonateAClientAfterAuthenticationSIDs = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedImpersonateAClientAfterAuthenticationSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
$disallowedImpersonateAClientAfterAuthenticationSIDs = $impersonateAClientAfterAuthenticationSIDs | Where-Object { $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[0] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[1] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[2] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[3] }
if ($disallowedImpersonateAClientAfterAuthenticationSIDs) { Write-Output "WN10-UR-000110" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000120"
# "The Load and unload device drivers user right must only be assigned to the Administrators group."
$loadAndUnloadDeviceDriversSIDs = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedLoadAndUnloadDeviceDriversSIDs = @("*S-1-5-32-544")
$disallowedLoadAndUnloadDeviceDriversSIDs = $loadAndUnloadDeviceDriversSIDs | Where-Object { $_ -notlike $allowedLoadAndUnloadDeviceDriversSIDs[0] }
if ($disallowedLoadAndUnloadDeviceDriversSIDs) { Write-Output "WN10-UR-000120" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000125"
# "The Lock pages in memory user right must not be assigned to any groups or accounts."
$lockPagesInMemorySIDs = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
if ($lockPagesInMemorySIDs.Contains('*S-1') -eq $true) { Write-Output "WN10-UR-000125" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000130"
# "The Manage auditing and security log user right must only be assigned to the Administrators group."
$manageAuditingAndSecurityLogSIDs = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedManageAuditingAndSecurityLogSIDs = @("*S-1-5-32-544")
$disallowedManageAuditingAndSecurityLogSIDs = $manageAuditingAndSecurityLogSIDs | Where-Object { $_ -notlike $allowedManageAuditingAndSecurityLogSIDs[0] }
if ($disallowedManageAuditingAndSecurityLogSIDs) { Write-Output "WN10-UR-000130" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000140"
# "The Modify firmware environment values user right must only be assigned to the Administrators group."
$modifyFirmwareEnvironmentValuesSIDs = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedModifyFirmwareEnvironmentValuesSIDs = @("*S-1-5-32-544")
$disallowedModifyFirmwareEnvironmentValuesSIDs = $modifyFirmwareEnvironmentValuesSIDs | Where-Object { $_ -notlike $allowedModifyFirmwareEnvironmentValuesSIDs[0] }
if ($disallowedModifyFirmwareEnvironmentValuesSIDs) { Write-Output "WN10-UR-000140" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000145"
# "The Perform volume maintenance tasks user right must only be assigned to the Administrators group."
$performVolumeMaintenanceTasksSIDs = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedPerformVolumeMaintenanceTasksSIDs = @("*S-1-5-32-544")
$disallowedPerformVolumeMaintenanceTasksSIDs = $performVolumeMaintenanceTasksSIDs | Where-Object { $_ -notlike $allowedPerformVolumeMaintenanceTasksSIDs[0] }
if ($disallowedPerformVolumeMaintenanceTasksSIDs) { Write-Output "WN10-UR-000145" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000150"
# "The Profile single process user right must only be assigned to the Administrators group."
$profileSingleProcessSIDs = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedProfileSingleProcessSIDs = @("*S-1-5-32-544")
$disallowedProfileSingleProcessSIDs = $profileSingleProcessSIDs | Where-Object { $_ -notlike $allowedProfileSingleProcessSIDs[0] }
if ($disallowedProfileSingleProcessSIDs) { Write-Output "WN10-UR-000150" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000160"
# "The Restore files and directories user right must only be assigned to the Administrators group."
$restoreFilesAndDirectoriesSIDs = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedRestoreFilesAndDirectoriesSIDs = @("*S-1-5-32-544")
$disallowedRestoreFilesAndDirectoriesSIDs = $restoreFilesAndDirectoriesSIDs | Where-Object { $_ -notlike $allowedRestoreFilesAndDirectoriesSIDs[0] }
if ($disallowedRestoreFilesAndDirectoriesSIDs) { Write-Output "WN10-UR-000160" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-UR-000165"
# "The Take ownership of files or other objects user right must only be assigned to the Administrators group."
$takeOwnershipOfFilesOrOtherObjectsSIDs = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedTakeOwnershipOfFilesOrOtherObjectsSIDs = @("*S-1-5-32-544")
$disallowedTakeOwnershipOfFilesOrOtherObjectsSIDs = $takeOwnershipOfFilesOrOtherObjectsSIDs | Where-Object { $_ -notlike $allowedTakeOwnershipOfFilesOrOtherObjectsSIDs[0] }
if ($disallowedTakeOwnershipOfFilesOrOtherObjectsSIDs) { Write-Output "WN10-UR-000165" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000050"
# "Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares."
$hardenedPaths = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
if ($hardenedPaths."\\*\SYSVOL" -ne 'RequireMutualAuthentication=1,RequireIntegrity=1' -or $hardenedPaths."\\*\NETLOGON" -ne 'RequireMutualAuthentication=1,RequireIntegrity=1') { Write-Output "WN10-CC-000050" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000327"
# "PowerShell Transcription must be enabled on Windows 10."
$psTranscriptionCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
if ($psTranscriptionCheck.EnableTranscripting -ne 1) { Write-Output "WN10-CC-000327" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000080"
# "Virtualization-based protection of code integrity must be enabled."
$secServicesRunningCheck = $vbsDetailsCheck.SecurityServicesRunning | Out-String
if ($secServicesRunningCheck.Contains(2) -eq $false) { Write-Output "WN10-CC-000080" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000391"
# "Internet Explorer must be disabled for Windows 10."
$ieInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Internet Explorer*" }
if ($ieInstalled -ne $null) { Write-Output "WN10-CC-000391" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000395"
# "Windows 10 must not have portproxy enabled or in use."
$portProxyCheck = netsh interface portproxy show all
if ($portProxyCheck -ne $null -and $portProxyCheck.Trim() -ne '') { Write-Output "WN10-00-000395" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"
