"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Windows 10 V3R1"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#TO DO
# Comment out all STIG ID Titles and descriptions. Print Out STIG ID for fail.
# EDIT DEFENDER CHECKS TO TRELLIX CHECKS

"WN10-00-000005"
"Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit version"
$os = Get-ComputerInfo
$os.CsDNSHostName
$os.CsDomainRole #MemberWorkstation
$os.OsName #Windows 10 Enterprise
$os.OsArchitecture #64-bit
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000010"
"Verify TPM is present and enabled"
$tpm = Get-Tpm
$tpm.TpmPresent #True
$tpm.TpmEnabled #True
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000015"
"System must be configured to run in UEFI mode."
$os.BiosFirmwareType #Uefi
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000020"
"Secure Boot must be enabled."
$bootState = Confirm-SecureBootUEFI
$bootState #True
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000025"
"An approved tool for continuous network scanning must be installed and configured to run."
"True"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000030"
"Systems must use BitLocker to encrypt all disks"
$bitLocker = Get-BitLockerVolume
$bitLocker.ProtectionStatus #On
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000031"
"Systems must use a BitLocker PIN for pre-boot authentication."
$bitLockerPin = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE\
$bitLockerPin.UseAdvancedStartup #1
$bitLockerPin.UseTPMPIN #1 or 2
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000032"
"BitLocker PIN must have a minimum length of six digits for pre-boot authentication."
$bitLockerPin.MinimumPin #6 or greater
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000035"
"Verify AppLocker is enabled"
$appLocker = Get-AppLockerPolicy -Effective -Xml
$appLocker.Contains('Type="Appx" EnforcementMode="Enabled"') #True
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000040"
"Get Build Number"
$os.OsBuildNumber #19045
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
$ntfsCheck = foreach ($volume in $ntfs) { if ($volume.FileSystemType -ne 'NTFS') { Write-Output "Fail" } }
if ($ntfsCheck -eq $null ) { SilentlyContinue } else { Write-Output "WN10-00-000050" }
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

"Confirm whether noaccess account is allowed"
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
$everyoneincludesanonymous = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
if ($everyoneincludesanonymous.everyoneincludesanonymous -ne 0) { Write-Output "WN10-00-000095, WN10-SO-000160" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000100"
# "Internet Information System (IIS) or its subcomponents must not be installed"
$allInstalledSoftware = Get-WmiObject -Class Win32_Product
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
# "Currently no policies on what is allowed"
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
$smbv1Check =Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | Out-String
if ($smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000160" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000165"
# "The SMBv1 protocol must be disabled on the SMB server. If WN16-00-000160 passes, this is N/A."
$smbv1ServerCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
if ($smbv1ServerCheck.SMB1 -ne 0 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000165" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-00-000170"
# "(SMB) v1 protocol must be disabled on the SMB client. If WN16-00-000160 passes, this is N/A."
$smbv1ClientCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
if ($smbv1ClientCheck.Start -ne 4 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Output "WN10-00-000170" }
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WN10-00-000175" (Dev.)
"The Secondary Logon service must be disabled on Windows 10."
$secondaryLogonCheck = $allWindowsServices | where {$_.DisplayName -Like "*Secondary*"} | Select Status,DisplayName | Out-String
if ($secondaryLogonCheck.Contains('Running') -eq $true) { Write-Output "WN10-00-000175" }
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

Import-Module ActiveDirectory

# Get all AD users and groups and their SIDs
Get-ADUser -Filter * -Property SID | Select-Object -Property Name, SID
Get-ADGroup -Filter * -Property SID | Select-Object -Property Name, SID



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
if ($lockoutDuractionCheck.Contains('900') -eq $false) { Write-Output "WN10-AC-000005"; Write-Output $lockoutDuractionCheck }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000010"
# "The number of allowed bad logon attempts must be configured to 3 or less."
$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Output "WN10-AC-000010"; Write-Output $lockoutBadCountCheck }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000015"
# "The period of time before the bad logon counter is reset must be configured to 15 minutes."
$lockoutCounterReset = $policyContent | Select-String "ResetLockoutCount" | Out-String
if ($lockoutCounterReset.Contains('900') -eq $false) { Write-Output "WN10-AC-000015"; Write-Output $lockoutCounterReset }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000020"
# "The password history must be configured to 24 passwords remembered."
$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
if ($passwordHistorySize.Contains('24') -eq $false) { Write-Output "WN10-AC-000020"; Write-Output $passwordHistorySize }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000025"
# "The maximum password age must be configured to 60 days or less."
$maxPasswordAge = $policyContent | Select-String "MaximumPasswordAge" | Out-String
if ($maxPasswordAge.Contains('60') -eq $false) { Write-Output "WN10-AC-000025"; Write-Output $maxPasswordAge }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000030"
# "The minimum password age must be configured to at least 1 day."
$minPasswordAge = $policyContent | Select-String "MinimumPasswordAge" | Out-String
if ($minPasswordAge.Contains('1') -eq $false) { Write-Output "WN10-AC-000030"; Write-Output $minPasswordAge }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000035"
# "Passwords must, at a minimum, be 14 characters."
$minPasswordLength = $policyContent | Select-String "MinimumPasswordLength" | Out-String
if ($minPasswordLength.Contains('14') -eq $false) { Write-Output "WN10-AC-000035"; Write-Output $minPasswordLength }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000040"
# "The built-in Microsoft password complexity filter must be enabled."
$passwordComplexityFilter = $policyContent | Select-String "PasswordComplexity" | Out-String
if ($passwordComplexityFilter.Contains('1') -eq $false) { Write-Output "WN10-AC-000040"; Write-Output $passwordComplexityFilter }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AC-000045"
# "Reversible password encryption must be disabled."
$reversiblePasswordEncryption = $policyContent | Select-String "ClearTextPassword" | Out-String
if ($reversiblePasswordEncryption.Contains('0') -eq $false) { Write-Output "WN10-AC-000045"; Write-Output $reversiblePasswordEncryption }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-SO-000030"
# "Audit policy using subcategories must be enabled."
# "Subsequent audit policy checks are dependent on this policy being enabled."
$subcategoryAuditing = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
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

# "WN10-AU-000050"
# "The system must be configured to audit Detailed Tracking - Process Creation successes."
$procCreationCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
if ($procCreationCheck.Contains('Success') -eq $false) { Write-Output "WN10-AU-000050" }

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
if ($otherLogonLogoffEventsCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000560, WN10-AU-000565" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000570"
# "Windows 10 must be configured to audit Detailed File Share Failures."
$detailedFileShareCheck = $auditPolicyAll | Select-String "Detailed File Share" | Out-String
if ($detailedFileShareCheck.Contains('Failure') -eq $false) { Write-Output "WN10-AU-000570" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-AU-000575, WN10-AU-000580"
# "Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Successes."
$mpssvcRuleLevelPolicyChangeCheck = $auditPolicyAll | Select-String "MPSSVC Rule-Level Policy Change" | Out-String
if ($mpssvcRuleLevelPolicyChangeCheck.Contains('Success and Failure') -eq $false) { Write-Output "WN10-AU-000575, WN10-AU-000580" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000005"
# "Camera access from the lock screen must be disabled."
$cameraAccessFromLockScreen = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
if ($cameraAccessFromLockScreen.NoLockScreenCamera -ne 1) { Write-Output "WN10-CC-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "WN10-CC-000007"
# "Windows 10 must cover or disable the built-in or attached camera when not in use."
$cameraDisableCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
if ($cameraDisableCheck.Value -ne 'Deny') { Write-Output "WN10-CC-000007" }

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

#SYNC WITH OTHER INSTANCE

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
$currentversionPoliciesSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
if ($currentversionPoliciesSystem.MSAOptional -ne 1) { Write-Output "WN10-CC-000170" }

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
if ($dataCollectionSettings.LimitEnhancedDiagnosticDataWindowsAnalytics -ne 1) { Write-Output "WN10-CC-000204" }

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


