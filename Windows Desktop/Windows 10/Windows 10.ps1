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

