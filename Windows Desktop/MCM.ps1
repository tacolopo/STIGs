$hostnameForFile = $env:COMPUTERNAME
$tier3FilePathWrite = "$hostnameForFile.txt"

Start-Transcript -Path $tier3FilePathWrite -Force

$os = Get-ComputerInfo
$os.CsDNSHostName
$osArch = $os.OsArchitecture
if ($os.CsDomainRole -eq "MemberWorkstation" -and $os.OsArchitecture -ne "64-bit") { Write-Host "WN10-00-000005 - $osArch" }

$tpm = Get-Tpm
$tpmPresent = $tpm.TpmPresent
$tpmEnabled = $tpm.TpmEnabled
if ($tpmPresent -eq $false -or $tpmEnabled -eq $false) { Write-Host "WN10-00-000010 - $tpmPresent & $tpmEnabled" }

$osBiosType = $os.BiosFirmwareType
if ($osBiosType -ne "Uefi") { Write-Host "WN10-00-000015 - $osBiosType" }

$bootState = Confirm-SecureBootUEFI
if ($bootState -eq $false) { Write-Host "WN10-00-000020 - $bootState" }

$allInstalledSoftware = Get-WmiObject -Class Win32_Product
$isTenableInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Nessus Agent (x64)" }
if ($isTenableInstalled -eq $null) { Write-Host "WN10-00-000025 - Nessus Agent not installed" }

<#
$bitLocker = (Get-BitLockerVolume).ProtectionStatus | Out-String
if ($bitLocker.Contains('Off') -eq $true) { Write-Host "WN10-00-000030 - Bitlockervolume off" }
#>

$bitLockerPin = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\FVE\
$bitLockerPinUseAdvancedStartup = $bitLockerPin.UseAdvancedStartup
$bitLockerPinUseTPMPIN = $bitLockerPin.UseTPMPIN
<#
if ($bitLockerPinUseAdvancedStartup -notin @(1,2) -and $bitLockerPin.UseTPMPIN -notin @(1,2)) { Write-Host "WN10-00-000031 - $bitLockerPinUseAdvancedStartup & $bitLockerPinUseTPMPIN" }
#>

<#
$bitLockerPinMinimumPin = $bitLockerPin.MinimumPin
if ($bitLockerPinMinimumPin -lt 6) { Write-Host "WN10-00-000032 - $bitLockerPinMinimumPin" }
#>

$appLocker = Get-AppLockerPolicy -Effective -Xml
if ($appLocker.Contains('Type="Appx" EnforcementMode="Enabled"') -eq $false) { Write-Host "WN10-00-000035 - Appx Check Failed" }

$osOsBuildNumber = $os.OsBuildNumber
if ($osOsBuildNumber -ne 19045) { Write-Host "WN10-00-000040 - $osOsBuildNumber" }

$allWindowsServices = Get-Service
$trellix = $allWindowsServices | where {$_.DisplayName -Like "*Trellix*"} | Select Status,DisplayName | Out-String
if ($trellix.Contains('Running Trellix Agent') -eq $false) { Write-Host "WN10-00-000045 - $trellix" }

$ntfs = Get-Volume
$ntfsCheck = foreach ($volume in $ntfs) { 
if ($volume.FileSystemType -ne "NTFS" -and $volume.DriveType -eq "Fixed") { 
	Write-Host "WN10-00-000050 - $($volume.DriveLetter) = $($volume.FileSystemType)"
	break
}

$bootConfigurationOSCheck = Get-WmiObject -Class Win32_BootConfiguration
$alternateOS = ($bootConfigurationOSCheck | Measure-Object).Count
if ($alternateOS -gt 1) {Write-Host "WN10-00-000055 - $alternateOS"}

$shares = Get-WmiObject -Class Win32_Share
$allowedShares = @("ADMIN$", "C$", "IPC$", "print$")
$shareNames = $shares.Name
if ($shareNames | Where-Object { $_ -notin $allowedShares }) { Write-Host "WN10-00-000060 - $shareNames" }

([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
   $user = ([ADSI]$_.Path)
   $lastLogin = $user.Properties.LastLogin.Value
   $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
   if ($lastLogin -eq $null) {
      $lastLogin = 'Never'
   }
   if ($enabled -eq $true -and $user.Name -ne 'noaccess') { Write-Host "WN10-00-000065 $($user.Name) $($lastLogin) $($enabled)" }
}

$localUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
$localUserNames = $localUsers | Select-Object -ExpandProperty Name
$allowedUsers = @("cnsadmin", "cnsguest", "DefaultAccount", "noaccess", "defaultuser0", "WDAGUtilityAccount")
if ($localUserNames | Where-Object { $_ -notin $allowedUsers }) { Write-Host "WN10-00-000085" }

$neverExpireAccounts = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Where-Object { $_.PasswordExpires -eq $false -and $_.Disabled -eq $false }
if ($neverExpireAccounts -ne $null) { Write-Host "WN10-00-000090 - $neverExpireAccounts" }

$subcategoryAuditing = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
if ($subcategoryAuditing.everyoneincludesanonymous -ne 0) { Write-Host "WN10-00-000095, WN10-SO-000160 - $($subcategoryAuditing.everyoneincludesanonymous)" }

$iisInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Internet Information Services*" }
if ($iisInstalled -ne $null) { Write-Host "WN10-00-000100 - $iisInstalled" }

$snmpInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*SNMP*" }
if ($snmpInstalled -ne $null) { Write-Host "WN10-00-000105 - $snmpInstalled" }

$simpletcpipInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Simple TCPIP Services*" }
if ($simpletcpipInstalled -ne $null) { Write-Host "WN10-00-000105 - $simpletcpipInstalled" }

$telnetclientInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Telnet Client*" }
if ($telnetclientInstalled -ne $null) { Write-Host "WN10-00-000115 - $telnetclientInstalled" }

$tftpclientInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*TFTP Client*" }
if ($tftpclientInstalled -ne $null) { Write-Host "WN10-00-000120 - $tftpclientInstalled" }

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
if ($lingeringCertificateFiles -ne $null) { Write-Host "WN10-00-000130 - $lingeringCertificateFiles" }

if ($trellix.Contains('Running Trellix Service Controller') -eq $false) { Write-Host "WN10-00-000135 - $trellix" }

$optOutTest = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_SupportPolicy
if ($optOutTest -notin @(3, 1)) { Write-Host "WN10-00-000145 - $optOutTest" }

$exceptionChainValidation = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\kernel\
if ($exceptionChainValidation.DisableExceptionChainValidation -ne 0) { Write-Host "WN10-00-000150 - $($exceptionChainValidation.DisableExceptionChainValidation)" }

$v2ps = Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2* | Out-String
if ($v2ps.Contains('Enabled') -eq $true) { Write-Host "WN10-00-000155 - $v2ps" }

$smbv1Check = Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | Out-String
if ($smbv1Check.Contains('Enabled') -eq $true) { Write-Host "WN10-00-000160 - $smbv1Check" }

$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
if ($lanmanServerParameters.SMB1 -ne 0 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Host "WN10-00-000165 - $($lanmanServerParameters.SMB1)" }

$smbv1ClientCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\
if ($smbv1ClientCheck.Start -ne 4 -and $smbv1Check.Contains('Enabled') -eq $true) { Write-Host "WN10-00-000170 - $($smbv1ClientCheck.Start)" }

$bluetoothStatus = Get-NetAdapter | Where-Object { $_.Name -like "*Bluetooth*" } | Out-String
if ($bluetoothStatus -ne $null) {
    if ($bluetoothStatus.Contains('Enabled') -eq $true) { Write-Host "WN10-00-000210, WN10-00-000220, WN10-00-000230 - $bluetoothStatus" }
}

$exportPath = "$env:TEMP\secpol.inf"
secedit /export /cfg $exportPath
$policyContent = Get-Content $exportPath

$lockoutDuractionCheck = $policyContent | Select-String "LockoutDuration" | Out-String
if ($lockoutDuractionCheck.Contains('900') -eq $false) { Write-Host "WN10-AC-000005 - $lockoutDuractionCheck" }

$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Host "WN10-AC-000010 - $lockoutBadCountCheck" }

$lockoutCounterReset = $policyContent | Select-String "ResetLockoutCount" | Out-String
if ($lockoutCounterReset.Contains('900') -eq $false) { Write-Host "WN10-AC-000015 - $lockoutCounterReset" }

$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
if ($passwordHistorySize.Contains('24') -eq $false) { Write-Host "WN10-AC-000020 - $passwordHistorySize" }

$maxPasswordAge = $policyContent | Select-String "MaximumPasswordAge" | Out-String
if ($maxPasswordAge.Contains('60') -eq $false) { Write-Host "WN10-AC-000025 - $maxPasswordAge" }

$minPasswordAge = $policyContent | Select-String "MinimumPasswordAge" | Out-String
if ($minPasswordAge.Contains('1') -eq $false) { Write-Host "WN10-AC-000030 - $minPasswordAge" }

$minPasswordLength = $policyContent | Select-String "MinimumPasswordLength" | Out-String
if ($minPasswordLength.Contains('14') -eq $false) { Write-Host "WN10-AC-000035 - $minPasswordLength" }

$passwordComplexityFilter = $policyContent | Select-String "PasswordComplexity" | Out-String
if ($passwordComplexityFilter.Contains('1') -eq $false) { Write-Host "WN10-AC-000040 - $passwordComplexityFilter" }

$reversiblePasswordEncryption = $policyContent | Select-String "ClearTextPassword" | Out-String
if ($reversiblePasswordEncryption.Contains('0') -eq $false) { Write-Host "WN10-AC-000045 - $reversiblePasswordEncryption" }

if ($subcategoryAuditing.scenoapplylegacyauditpolicy -ne 1) { Write-Host "WN10-SO-000030 - $($subcategoryAuditing.scenoapplylegacyauditpolicy)" }

$auditPolicyAll = AuditPol /get /category:*
$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
if ($credentialValidationCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000005 - $credentialValidationCheck" }
if ($credentialValidationCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000010 - $credentialValidationCheck" }

$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
if ($securityGroupManagementCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000030 - $securityGroupManagementCheck" }

$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
if ($userAccountManagementCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000035 - $userAccountManagementCheck" }
if ($userAccountManagementCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000040 - $userAccountManagementCheck" }

$pnpActivityCheck = $auditPolicyAll | Select-String "Plug and Play Events" | Out-String
if ($credentialValidationCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000045 - $credentialValidationCheck" }

$procCreationCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
if ($procCreationCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000050 - $procCreationCheck" }
if ($procCreationCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000585 - $procCreationCheck" }

$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
if ($accountLockoutCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000054 - $accountLockoutCheck" }

$groupMembershipCheck = $auditPolicyAll | Select-String "Group Membership" | Out-String
if ($groupMembershipCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000060 - $groupMembershipCheck" }

$logoffCheck = $auditPolicyAll | Select-String "(?<!/)\bLogoff\b" | Out-String
if ($logoffCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000065 - $logoffCheck" }

$logonCheck = $auditPolicyAll | Select-String "^  Logon\s{2,}" | Out-String
if ($logonCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000070 - $logonCheck" }
if ($logonCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000075 - $logonCheck" }

$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
if ($specialLogonCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000080 - $specialLogonCheck" }

$fileShareCheck = $auditPolicyAll | Select-String "File Share" | Out-String
if ($fileShareCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000081 - $fileShareCheck" }
if ($fileShareCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000082 - $fileShareCheck" }

$otherObjectAccessCheck = $auditPolicyAll | Select-String "Other Object Access Events" | Out-String
if ($otherObjectAccessCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000083 - $otherObjectAccessCheck" }
if ($otherObjectAccessCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000084 - $otherObjectAccessCheck" }

$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
if ($removableStorageCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000085 - $removableStorageCheck" }
if ($removableStorageCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000090 - $removableStorageCheck" }

$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
if ($auditPolicyChangeCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000100 - $auditPolicyChangeCheck" }

$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
if ($authenticationPolicyChangeCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000105 - $authenticationPolicyChangeCheck" }

$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
if ($authorizationPolicyChangeCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000107 - $authorizationPolicyChangeCheck" }

$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
if ($sensitivePrivilegeUseCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000110 - $sensitivePrivilegeUseCheck" }
if ($sensitivePrivilegeUseCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000115 - $sensitivePrivilegeUseCheck" }

$ipsecDriverCheck = $auditPolicyAll | Select-String "IPSec Driver" | Out-String
if ($ipsecDriverCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000120 - $ipsecDriverCheck" }

$otherSystemEventsCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
if ($otherSystemEventsCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000130 - $otherSystemEventsCheck" }
if ($otherSystemEventsCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000135 - $otherSystemEventsCheck" }

$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
if ($securityStateChangeCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000140 - $securityStateChangeCheck" }

$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
if ($securitySystemExtensionCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000150 - $securitySystemExtensionCheck" }

$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
if ($systemIntegrityCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000155 - $systemIntegrityCheck" }
if ($systemIntegrityCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000160 - $systemIntegrityCheck" }

$eventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
if ($eventLogSize.MaxSize -lt 32768) { Write-Host "WN10-AU-000500 - $eventLogSize" }

$securityEventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
if ($securityEventLogSize.MaxSize -lt 1024000) { Write-Host "WN10-AU-000505 - $securityEventLogSize" }

$systemEventLogSize = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
if ($systemEventLogSize.MaxSize -lt 32768) { Write-Host "WN10-AU-000510 - $systemEventLogSize" }

$applicationEventLogACL = (((Get-Acl C:\Windows\System32\winevt\Logs\Application.evtx -ErrorAction SilentlyContinue).Access).FileSystemRights).Count
if ($applicationEventLogACL -ne 3) { Write-Host "WN10-AU-000515 - $applicationEventLogACL" }

$securityEventLogACL = (((Get-Acl C:\Windows\System32\winevt\Logs\Security.evtx -ErrorAction SilentlyContinue).Access).FileSystemRights).Count
if ($securityEventLogACL -ne 3) { Write-Host "WN10-AU-000520 - $securityEventLogACL" }

$systemEventLogACL = (((Get-Acl C:\Windows\System32\winevt\Logs\System.evtx -ErrorAction SilentlyContinue).Access).FileSystemRights).Count
if ($systemEventLogACL -ne 3) { Write-Host "WN10-AU-000525 - $systemEventLogACL" }

$otherPolicyChangeEventsCheck = $auditPolicyAll | Select-String "Other Policy Change Events" | Out-String
if ($otherPolicyChangeEventsCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000555 - $otherPolicyChangeEventsCheck" }

$otherLogonLogoffEventsCheck = $auditPolicyAll | Select-String "Other Logon/Logoff Events" | Out-String
if ($otherLogonLogoffEventsCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000560 - $otherLogonLogoffEventsCheck" }
if ($otherLogonLogoffEventsCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000565 - $otherLogonLogoffEventsCheck" }

$detailedFileShareCheck = $auditPolicyAll | Select-String "Detailed File Share" | Out-String
if ($detailedFileShareCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000570 - $detailedFileShareCheck" }

$mpssvcRuleLevelPolicyChangeCheck = $auditPolicyAll | Select-String "MPSSVC Rule-Level Policy Change" | Out-String
if ($mpssvcRuleLevelPolicyChangeCheck.Contains('Success') -eq $false) { Write-Host "WN10-AU-000575 - $mpssvcRuleLevelPolicyChangeCheck" }
if ($mpssvcRuleLevelPolicyChangeCheck.Contains('Failure') -eq $false) { Write-Host "WN10-AU-000580 - $mpssvcRuleLevelPolicyChangeCheck" }

$cameraAccessFromLockScreen = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
if ($cameraAccessFromLockScreen.NoLockScreenCamera -ne 1) { Write-Host "WN10-CC-000005 - $($cameraAccessFromLockScreen.NoLockScreenCamera)" }

$cameraDisableCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam -ErrorAction SilentlyContinue
$cameraDisableCheckValue = $cameraDisableCheck.Value
if ($cameraDisableCheckValue -ne 'Deny') { Write-Host "WN10-CC-000007 - $cameraDisableCheckValue" }

if ($cameraAccessFromLockScreen.NoLockScreenSlideshow -ne 1) { Write-Host "WN10-CC-000010 - $($cameraAccessFromLockScreen.NoLockScreenSlideshow)" }

$ip6ParametersCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
if ($ip6ParametersCheck.DisableIPSourceRouting -ne 2) { Write-Host "WN10-CC-000020 - $($ip6ParametersCheck.DisableIPSourceRouting)" }

$ipParametersCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
if ($ipParametersCheck.DisableIPSourceRouting -ne 2) { Write-Host "WN10-CC-000025 - $($ipParametersCheck.DisableIPSourceRouting)" }

if ($ipParametersCheck.EnableICMPRedirect -ne 0) { Write-Host "WN10-CC-000030 - $($ipParametersCheck.EnableICMPRedirect)" }

$netBTParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
if ($netBTParameters.NoNameReleaseOnDemand -ne 1) { Write-Host "WN10-CC-000035 - $($netBTParameters.NoNameReleaseOnDemand)" }

$currentVersionPoliciesSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
if ($currentVersionPoliciesSystem.LocalAccountTokenFilterPolicy -ne 0) { Write-Host "WN10-CC-000037 - $($currentVersionPoliciesSystem.LocalAccountTokenFilterPolicy)" }

$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Host "WN10-CC-000038 - $($wDigestInfo.UseLogonCredential)" }

$lanmanWorkstationInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
if ($lanmanWorkstationInfo.AllowInsecureGuestAuth -ne 0) { Write-Host "WN10-CC-000040 - $($lanmanWorkstationInfo.AllowInsecureGuestAuth)" }

$networkConnectionsInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network` Connections\
if ($networkConnectionsInfo.NC_ShowSharedAccessUI -ne 0) { Write-Host "WN10-CC-000044 - $($networkConnectionsInfo.NC_ShowSharedAccessUI)" }

$eccCurvesInfo = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
$eccCurvesValue = $eccCurvesInfo.EccCurves
if ($eccCurvesValue.Contains('NistP384') -eq $false -or $eccCurvesValue.Contains('NistP256') -eq $false) { Write-Host "WN10-CC-000052 - $eccCurvesValue" }

$simultaneousConnectionsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
$simultaneousConnectionsCheckConnectionsValue = $simultaneousConnectionsCheck.fMinimizeConnections
if ($simultaneousConnectionsCheckConnectionsValue -ne 3) { Write-Host "WN10-CC-000055 - $simultaneousConnectionsCheckConnectionsValue" }

if ($simultaneousConnectionsCheck.fBlockNonDomain -ne 1) { Write-Host "WN10-CC-000060 - $($simultaneousConnectionsCheck.fBlockNonDomain)" }

$commandLineDataCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
if ($commandLineDataCheck.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Host "WN10-CC-000066 - $($commandLineDataCheck.ProcessCreationIncludeCmdLine_Enabled)" }

$remoteHostDelegationCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
if ($remoteHostDelegationCheck.AllowProtectedCreds -ne 1) { Write-Host "WN10-CC-000068 - $($remoteHostDelegationCheck.AllowProtectedCreds)" }

$vbsDetailsCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$vbsRequiredSecurityProperties = $vbsDetailsCheck.RequiredSecurityProperties | Out-String
<#
if ($vbsRequiredSecurityProperties.Contains('2') -eq $false -or $vbsDetailsCheck.VirtualizationBasedSecurityStatus -ne 2) { Write-Host "WN10-CC-000070 - $($vbsRequiredSecurityProperties) $($vbsDetailsCheck.VirtualizationBasedSecurityStatus)" }
#>

<#
$vbsSecurityServicesRunning = $vbsDetailsCheck.SecurityServicesRunning | Out-String
if ($vbsSecurityServicesRunning.Contains('1') -eq $false) { Write-Host "WN10-CC-000075 - $vbsSecurityServicesRunning" }
#>

$elamCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
if ($elamCheck.DriverLoadPolicy -notin @(1, 3, 8)) { Write-Host "WN10-CC-000085 - $($elamCheck.DriverLoadPolicy)" }

$gpoReprocessCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ($gpoReprocessCheck.NoGPOListChanges -ne 0) { Write-Host "WN10-CC-000090 -  $($gpoReprocessCheck.NoGPOListChanges)" }

$httpPrintDriverCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Printers\
if ($httpPrintDriverCheck.DisableWebPnPDownload -ne 1) { Write-Host "WN10-CC-000100 - $($httpPrintDriverCheck.DisableWebPnPDownload)" }

$webPubWizards = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
if ($webPubWizards.NoWebServices -ne 1) { Write-Host "WN10-CC-000105 - $($webPubWizards.NoWebServices)" }

if ($httpPrintDriverCheck.DisableHTTPPrinting -ne 1) { Write-Host "WN10-CC-000100 -  $($httpPrintDriverCheck.DisableHTTPPrinting)" }

$certificateDeviceAuthCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
if ($certificateDeviceAuthCheck.DevicePKInitEnabled -eq 0) { Write-Host "WN10-CC-000115 - $($certificateDeviceAuthCheck.DevicePKInitEnabled)" }

$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Host "WN10-CC-000130 - $($windowsSystemChecks.EnumerateLocalUsers)" }

$dcSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
if ($dcSettingsCheck.DCSettingIndex -ne 1) { Write-Host "WN10-CC-000145 - $($dcSettingsCheck.DCSettingIndex)" }

if ($dcSettingsCheck.ACSettingIndex -ne 1) { Write-Host "WN10-CC-000150 - $($dcSettingsCheck.ACSettingIndex)" }

$terminalServicesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Terminal` Services\
if ($terminalServicesCheck.fAllowToGetHelp -ne 0) { Write-Host "WN10-CC-000155 - $($terminalServicesCheck.fAllowToGetHelp)" }

$rpcSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows` NT\Rpc\
if ($rpcSettingsCheck.RestrictRemoteClients -ne 1) { Write-Host "WN10-CC-000165 - $($rpcSettingsCheck.RestrictRemoteClients)" }

if ($currentVersionPoliciesSystem.MSAOptional -ne 1) { Write-Host "WN10-CC-000170 - $($currentVersionPoliciesSystem.MSAOptional)" }

$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Host "WN10-CC-000175 - $($appCompatSettingsCheck.DisableInventory)" }

$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Host "WN10-CC-000180 - $($windowsExplorerSettingsCheck.NoAutoplayfornonVolume)" }

if ($webPubWizards.NoAutorun -ne 1) { Write-Host "WN10-CC-000185 - $($webPubWizards.NoAutorun)" }

if ($webPubWizards.NoDriveTypeAutoRun -ne 255) { Write-Host "WN10-CC-000190 - $($webPubWizards.NoDriveTypeAutoRun)" }

$biometricsFacialFeatures = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\
if ($biometricsFacialFeatures.EnhancedAntiSpoofing -ne 1) { Write-Host "WN10-CC-000195 - $($biometricsFacialFeatures.EnhancedAntiSpoofing)" }

$cloudContentSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\
if ($cloudContentSettingsCheck.DisableWindowsConsumerFeatures -ne 1) { Write-Host "WN10-CC-000197 - $($cloudContentSettingsCheck.DisableWindowsConsumerFeatures)" }

$credUIPoliciesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
if ($credUIPoliciesCheck.EnumerateAdministrators -ne 0) { Write-Host "WN10-CC-000200 - $($credUIPoliciesCheck.EnumerateAdministrators)" }

$dataCollectionSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
$dataCollectionSettingsEnhancedDiagnosticValue = $dataCollectionSettings.LimitEnhancedDiagnosticDataWindowsAnalytics
if ($dataCollectionSettingsEnhancedDiagnosticValue -ne 1) { Write-Host "WN10-CC-000204 - $dataCollectionSettingsEnhancedDiagnosticValue" }

if ($dataCollectionSettings.AllowTelemetry -notin @(0, 1)) { Write-Host "WN10-CC-000205 - $($dataCollectionSettings.AllowTelemetry)" }

$deliveryOptimizationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
if ($deliveryOptimizationSettings.DODownloadMode -eq 3) { Write-Host "WN10-CC-000206 - $($deliveryOptimizationSettings.DODownloadMode)" }

if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Host "WN10-CC-000210 - $($windowsSystemChecks.EnableSmartScreen)" }

if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -ne $null -and $windowsExplorerSettingsCheck.NoDataExecutionPrevention -ne 0) { Write-Host "WN10-CC-000215 - $($windowsExplorerSettingsCheck.NoDataExecutionPrevention)" }

if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -ne $null -and $windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -ne 0) { Write-Host "WN10-CC-000220 - $($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption)" }

if ($webPubWizards.PreXPSP2ShellProtocolBehavior -ne $null -and $webPubWizards.PreXPSP2ShellProtocolBehavior -ne 0) { Write-Host "WN10-CC-000225 - $($webPubWizards.PreXPSP2ShellProtocolBehavior)" }

$phishingFilterCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
if ($phishingFilterCheck.PreventOverride -ne 1) { Write-Host "WN10-CC-000230 - $($phishingFilterCheck.PreventOverride)" }

if ($phishingFilterCheck.PreventOverrideAppRepUnknown -ne 1) { Write-Host "WN10-CC-000235 - $($phishingFilterCheck.PreventOverrideAppRepUnknown)" }

$edgeInternetSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet` Settings\
$edgeInternetSettingsCertErrorOverrridesValue = $edgeInternetSettingsCheck.PreventCertErrorOverrides
if ($edgeInternetSettingsCertErrorOverrridesValue -ne 1) { Write-Host "WN10-CC-000238 - $edgeInternetSettingsCertErrorOverrridesValue" }

$mainEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\
if ($mainEdgeSettings.'FormSuggest Passwords' -ne 'no') { Write-Host "WN10-CC-000245 - $($mainEdgeSettings.'FormSuggest Passwords')" }

if ($phishingFilterCheck.EnabledV9 -ne 1) { Write-Host "WN10-CC-000250 - $($phishingFilterCheck.EnabledV9)" }

$gameDVRChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\
if ($gameDVRChecks.AllowGameDVR -ne 0) { Write-Host "WN10-CC-000252 - $($gameDVRChecks.AllowGameDVR)" }

$passportForWorkChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\
if ($passportForWorkChecks.RequireSecurityDevice -ne 1) { Write-Host "WN10-CC-000255 - $($passportForWorkChecks.RequireSecurityDevice)" }

$passportPinLength = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\
if ($passportPinLength.MinimumPINLength -lt 6) { Write-Host "WN10-CC-000260 - $($passportPinLength.MinimumPINLength)" }

if ($terminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Host "WN10-CC-000270 - $($terminalServicesCheck.DisablePasswordSaving)" }

if ($terminalServicesCheck.fDisableCdm -ne 1) { Write-Host "WN10-CC-000275 - $($terminalServicesCheck.fDisableCdm)" }

if ($terminalServicesCheck.fPromptForPassword -ne 1) { Write-Host "WN10-CC-000280 - $($terminalServicesCheck.fPromptForPassword)" }

if ($terminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Host "WN10-CC-000285 - $($terminalServicesCheck.fEncryptRPCTraffic)" }

if ($terminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Host "WN10-CC-000290 - $($terminalServicesCheck.MinEncryptionLevel)" }

$internetExplorerFeeds = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Internet` Explorer\Feeds\
if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Host "WN10-CC-000295 - $($internetExplorerFeeds.DisableEnclosureDownload)" }

if ($internetExplorerFeeds.AllowBasicAuthInClear -ne 0 -and $internetExplorerFeeds.AllowBasicAuthInClear -ne $null) { Write-Host "WN10-CC-000300 - $($internetExplorerFeeds.AllowBasicAuthInClear)" }

$windowsSearchCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows` Search\
if ($windowsSearchCheck.AllowIndexingEncryptedStoresOrItems -ne 0) { Write-Host "WN10-CC-000305 - $($windowsSearchCheck.AllowIndexingEncryptedStoresOrItems)" }

$installerSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
if ($installerSettings.EnableUserControl -ne 0) { Write-Host "WN10-CC-000310 - $($installerSettings.EnableUserControl)" }

if ($installerSettings.AlwaysInstallElevated -ne 0) { Write-Host "WN10-CC-000315 - $($installerSettings.AlwaysInstallElevated)" }

if ($installerSettings.SafeForScripting -ne 0 -and $installerSettings.SafeForScripting -ne $null) { Write-Host "WN10-CC-000320 - $($installerSettings.SafeForScripting)" }

if ($currentVersionPoliciesSystem.DisableAutomaticRestartSignOn -ne 1) { Write-Host "WN10-CC-000325 - $($currentVersionPoliciesSystem.DisableAutomaticRestartSignOn)" }

$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Host "WN10-CC-000326 - $($scriptBlockLogging.EnableScriptBlockLogging)" }

$webPubWizardsNoPreviewPane = $webPubWizards.NoPreviewPane
$webPubWizardsNoReadingPane = $webPubWizards.NoReadingPane
if ($webPubWizardsNoPreviewPane -ne 1 -or $webPubWizardsNoReadingPane -ne 1) { Write-Host "WN10-CC-000328 - $webPubWizardsNoPreviewPane $webPubWizardsNoReadingPane" }

$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
if ($winrmClientCheck.AllowBasic -ne 0) { Write-Host "WN10-CC-000330 - $($winrmClientCheck.AllowBasic)" }

if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN10-CC-000335 - $($winrmClientCheck.AllowUnencryptedTraffic)" }

$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Host "WN10-CC-000345 - $($winrmServiceCheck.AllowBasic)" }

if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN10-CC-000350 - $($winrmServiceCheck.AllowUnencryptedTraffic)" }

if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Host "WN10-CC-000355 - $($winrmServiceCheck.DisableRunAs)" }

if ($winrmClientCheck.AllowDigest -ne 0) { Write-Host "WN10-CC-000360 - $($winrmClientCheck.AllowDigest)" }

<#
$appPrivacySettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\ -ErrorAction SilentlyContinue
if ($appPrivacySettings -ne $null) {
    if ($appPrivacySettings.LetAppsActivateWithVoiceAboveLock -ne 2 -and $appPrivacySettings.LetAppsActivateWithVoice -ne 2) { Write-Host "WN10-CC-000365 - $($appPrivacySettings.LetAppsActivateWithVoiceAboveLock)" }
} else {
    Write-Host "WN10-CC-000365 - Value is null"
}
#>

if ($windowsSystemChecks.AllowDomainPINLogon -ne 0) { Write-Host "WN10-CC-000370 - $($windowsSystemChecks.AllowDomainPINLogon)" }

$windowsInkWorkspace = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\ -ErrorAction SilentlyContinue
if ($windowsInkWorkspace -ne $null) {
    if ($windowsInkWorkspace.AllowWindowsInkWorkspace -ne 1) { Write-Host "WN10-CC-000385 - $($windowsInkWorkspace.AllowWindowsInkWorkspace)" }
} else {
    Write-Host "WN10-CC-000385 - Value is null"
}

$hkcuCloudContentSettingsCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\ -ErrorAction SilentlyContinue
if ($hkcuCloudContentSettingsCheck -ne $null) {
    if ($hkcuCloudContentSettingsCheck.DisableThirdPartySuggestions -ne 1) { Write-Host "WN10-CC-000390 - $($hkcuCloudContentSettingsCheck.DisableThirdPartySuggestions)" }
} else {
    Write-Host "WN10-CC-000390 - Value is null"
}

$kernelDmaProtection = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel` DMA` Protection\ -ErrorAction SilentlyContinue
if ($kernelDmaProtection -ne $null) {
    if ($kernelDmaProtection.DeviceEnumerationPolicy -ne 0) { Write-Host "WN10-EP-000310 - $($kernelDmaProtection.DeviceEnumerationPolicy)" }
} else {
    Write-Host "WN10-EP-000310 - Value is null"
}

$hklmSoftwareACL = Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
$softwareIsInherited = $hklmSoftwareACL.IsInherited | Out-String
$softwareFullControlAdmin = $hklmSoftwareACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Administrators" } | Out-String
$softwareReadkeyUsers = $hklmSoftwareACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" } | Out-String
$hklmSystemACL = Get-Acl -Path HKLM:SYSTEM | % { $_.access }
$systemIsInherited = $hklmSystemACL.IsInherited | Out-String
$systemFullControlAdmin = $hklmSystemACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Administrators" } | Out-String
$systemReadkeyUsers = $hklmSystemACL | Where-Object { $_.IdentityReference -eq "BUILTIN\Users" } | Out-String

if ($softwareIsInherited.Contains("True") -eq $true -or $systemIsInherited.Contains("True") -eq $true -or $softwareFullControlAdmin.Contains("FullControl") -eq $false -or $systemFullControlAdmin.Contains("FullControl") -eq $false) { Write-Host "WN10-RG-000005 - $($softwareIsInherited) $($systemIsInherited)" }

$disableBuiltInAdminCheck = $policyContent | Select-String "EnableAdminAccount" | Out-String
if ($disableBuiltInAdminCheck.Contains("0") -eq $false) { Write-Host "WN10-SO-000005 - $disableBuiltInAdminCheck" }

$disableBuiltInGuestCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
if ($disableBuiltInGuestCheck.Contains("0") -eq $false) { Write-Host "WN10-SO-000010 - $disableBuiltInGuestCheck" }

if ($subcategoryAuditing.LimitBlankPasswordUse -ne 1) { Write-Host "WN10-SO-000015 - $($subcategoryAuditing.LimitBlankPasswordUse)" }

$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
if ($newAdminName.Contains("Administrator") -eq $true) { Write-Host "WN10-SO-000020 - $newAdminName" }

$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
if ($newGuestName.Contains("cnsguest") -eq $false) { Write-Host "WN10-SO-000025 - $newGuestName" }

$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Host "WN10-SO-000035 - $($netLogonParameters.RequireSignOrSeal)" }

if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Host "WN10-SO-000040 - $($netLogonParameters.SealSecureChannel)" }

if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Host "WN10-SO-000045 - $($netLogonParameters.SignSecureChannel)" }

if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Host "WN10-SO-000050 - $($netLogonParameters.DisablePasswordChange)" }

if ($netLogonParameters.MaximumPasswordAge -notin 0..30) { Write-Host "WN10-SO-000055 - $($netLogonParameters.MaximumPasswordAge)" }

if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Host "WN10-SO-000060 - $($netLogonParameters.RequireStrongKey)" }

if ($currentVersionPoliciesSystem.InactivityTimeoutSecs -notin 1..900) { Write-Host "WN10-SO-000070 - $($currentVersionPoliciesSystem.InactivityTimeoutSecs)" }

if ($currentVersionPoliciesSystem.LegalNoticeText -eq $null) { Write-Host "WN10-SO-000075 - Value is null" }

if ($currentVersionPoliciesSystem.LegalNoticeCaption -eq $null) { Write-Host "WN10-SO-000080 - Value is null" }

$cachedLogonsCount = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").CachedLogonsCount -as [int]
if ($cachedLogonsCount -gt 10) { Write-Host "WN10-SO-000085 - $CachedLogonsCount" }

$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Host "WN10-SO-000100 - $($lanmanWorkstationParameters.RequireSecuritySignature)" }

if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Host "WN10-SO-000110 - $($lanmanWorkstationParameters.EnablePlainTextPassword)" }

if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Host "WN10-SO-000120 - $($lanmanServerParameters.RequireSecuritySignature)" }

$lsaAnonymousName = $policyContent | Select-String "LSAAnonymousNameLookup" | Out-String
if ($lsaAnonymousName.Contains("1") -eq $true) { Write-Host "WN10-SO-000140 - $lsaAnonymousName" }

if ($subcategoryAuditing.RestrictAnonymousSAM -ne 1) { Write-Host "WN10-SO-000145 - $($subcategoryAuditing.RestrictAnonymousSAM)" }

if ($subcategoryAuditing.RestrictAnonymous -ne 1) { Write-Host "WN10-SO-000150 - $($subcategoryAuditing.RestrictAnonymous)" }

if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Host "WN10-SO-000165 - $($lanmanServerParameters.RestrictNullSessAccess)" }

if ($subcategoryAuditing.RestrictRemoteSAM -ne "O:BAG:BAD:(A;;RC;;;BA)") { Write-Host "WN10-SO-000167 - $($subcategoryAuditing.RestrictRemoteSAM)" }

$msv1LSAChecks = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\
if ($msv1LSAChecks.allownullsessionfallback -ne 0) { Write-Host "WN10-SO-000180 - $($msv1LSAChecks.allownullsessionfallback)" }

$pku2LSAChecks = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
if ($pku2LSAChecks.AllowOnlineID -ne 0) { Write-Host "WN10-SO-000185 - $($pku2LSAChecks.AllowOnlineID)" }

$certificateDeviceAuthCheckSupportedEncryptionTypes = $certificateDeviceAuthCheck.SupportedEncryptionTypes
if ($certificateDeviceAuthCheckSupportedEncryptionTypes -ne "2147483640") { Write-Host "WN10-SO-000190 - $certificateDeviceAuthCheckSupportedEncryptionTypes" }

if ($subcategoryAuditing.NoLMHash -ne 1) { Write-Host "WN10-SO-000195 - $($subcategoryAuditing.NoLMHash)" }

if ($subcategoryAuditing.LmCompatibilityLevel -ne 5) { Write-Host "WN10-SO-000205 - $($subcategoryAuditing.LmCompatibilityLevel)" }

$ldapServicesSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
if ($ldapServicesSettings.LDAPClientIntegrity -ne 1) { Write-Host "WN10-SO-000210 - $($ldapServicesSettings.LDAPClientIntegrity)" }

if ($msv1LSAChecks.NTLMMinClientSec -ne 537395200) { Write-Host "WN10-SO-000215 - $($msv1LSAChecks.NTLMMinClientSec)" }

if ($msv1LSAChecks.NTLMMinServerSec -ne 537395200) { Write-Host "WN10-SO-000220 - $($msv1LSAChecks.NTLMMinServerSec)" }

$fipsAlgorithmPolicy = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
$fipsAlgorithmPolicyEnabled = $fipsAlgorithmPolicy.Enabled
if ($fipsAlgorithmPolicyEnabled -ne 1) { Write-Host "WN10-SO-000230 - $fipsAlgorithmPolicyEnabled" }

$sessionManagerSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session` Manager\
if ($sessionManagerSettings.ProtectionMode -ne 1) { Write-Host "WN10-SO-000240 - $($sessionManagerSettings.ProtectionMode)" }

if ($currentVersionPoliciesSystem.FilterAdministratorToken -ne 1) { Write-Host "WN10-SO-000245 - $($currentVersionPoliciesSystem.FilterAdministratorToken)" }

if ($currentVersionPoliciesSystem.ConsentPromptBehaviorAdmin -ne 2) { Write-Host "WN10-SO-000250 - $($currentVersionPoliciesSystem.ConsentPromptBehaviorAdmin)" }

if ($currentVersionPoliciesSystem.ConsentPromptBehaviorUser -ne 1) { Write-Host "WN10-SO-000255 - $($currentVersionPoliciesSystem.ConsentPromptBehaviorUser)" }

if ($currentVersionPoliciesSystem.EnableInstallerDetection -ne 1) { Write-Host "WN10-SO-000260 - $($currentVersionPoliciesSystem.EnableInstallerDetection)" }

if ($currentVersionPoliciesSystem.EnableSecureUIAPaths -ne 1) { Write-Host "WN10-SO-000265 - $($currentVersionPoliciesSystem.EnableSecureUIAPaths)" }

if ($currentVersionPoliciesSystem.EnableLUA -ne 1) { Write-Host "WN10-SO-000270 - $($currentVersionPoliciesSystem.EnableLUA)" }

if ($currentVersionPoliciesSystem.EnableVirtualization -ne 1) { Write-Host "WN10-SO-000275 - $($currentVersionPoliciesSystem.EnableVirtualization)" }

$adminAccountLastPasswordSet = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND Description='Built-in account for administering the computer/domain' AND Disabled='False'"
if ($adminAccountLastPasswordSet) {
    $lastPasswordSet = $adminAccountLastPasswordSet.ConvertToDateTime($adminAccountLastPasswordSet.PasswordLastChanged)
    $daysSinceLastChange = (Get-Date) - $lastPasswordSet
    if ($daysSinceLastChange.Days -gt 60) {
        Write-Host "WN10-SO-000280 - $($daysSinceLastChange.Days)"
    }
}

$pushNotifications = Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\ -ErrorAction SilentlyContinue
if ($pushNotifications -ne $null) {
    if ($pushNotifications.NoToastApplicationNotificationOnLockScreen -ne 1) { Write-Host "WN10-UC-000015 - $($pushNotifications.NoToastApplicationNotificationOnLockScreen)" }
} else {
    Write-Host "WN10-UC-000015 - Value is null"
}

$attachmentsPolicies = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\ -ErrorAction SilentlyContinue
if ($attachmentsPolicies.SaveZoneInformation -ne $null) {
    if ($attachmentsPolicies.SaveZoneInformation -ne 2) { Write-Host "WN10-UC-000020 - $($attachmentsPolicies.SaveZoneInformation)" }
}

$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
if ($accessCredManagerCheck.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000005 - $accessCredManagerCheck" }

$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-32-555")
$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] }

<#
if ($disallowedSIDs) { Write-Host "WN10-UR-000010 - $disallowedSIDs" }
#>

$actAsPartOfOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
if ($actAsPartOfOSCheck.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000015 - $actAsPartOfOSCheck" }

$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedlogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
$disallowedlogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedlogonSIDs[0] -and $_ -notlike $allowedlogonSIDs[1] }
if ($disallowedlogonSIDs) { Write-Host "WN10-UR-000025 - $disallowedlogonSIDs" }

$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedBackupSIDs = @("*S-1-5-32-544")
$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
if ($disallowedBackupSIDs) { Write-Host "WN10-UR-000030 - $disallowedBackupSIDs" }

$changeSystemTimeSIDs = ($policyContent | Select-String "SeSystemtimePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedChangeSystemTimeSIDs = @("*S-1-5-19", "*S-1-5-32-544")
$disallowedChangeSystemTimeSIDs = $changeSystemTimeSIDs | Where-Object { $_ -notlike $allowedChangeSystemTimeSIDs[0] -and $_ -notlike $allowedChangeSystemTimeSIDs[1] }
if ($disallowedChangeSystemTimeSIDs) { Write-Host "WN10-UR-000035 - $disallowedChangeSystemTimeSIDs" }

$createPagefileSIDs = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreatePagefileSIDs = @("*S-1-5-32-544")
$disallowedCreatePagefileSIDs = $createPagefileSIDs | Where-Object { $_ -notlike $allowedCreatePagefileSIDs[0] }
if ($disallowedCreatePagefileSIDs) { Write-Host "WN10-UR-000040 - $disallowedCreatePagefileSIDs" }

$createTokenObjectSIDs = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
if ($createTokenObjectSIDs.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000045 - $createTokenObjectSIDs" }

$createGlobalObjectsSIDs = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreateGlobalObjectsSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
$disallowedCreateGlobalObjectsSIDs = $createGlobalObjectsSIDs | Where-Object { $_ -notlike $allowedCreateGlobalObjectsSIDs[0] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[1] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[2] -and $_ -notlike $allowedCreateGlobalObjectsSIDs[3] }
if ($disallowedCreateGlobalObjectsSIDs) { Write-Host "WN10-UR-000050 - $disallowedCreateGlobalObjectsSIDs" }

$createPermanentSharedObjectsSIDs = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
if ($createPermanentSharedObjectsSIDs.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000055 - $createPermanentSharedObjectsSIDs" }

$createSymbolicLinksSIDs = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedCreateSymbolicLinksSIDs = @("*S-1-5-32-544")
$disallowedCreateSymbolicLinksSIDs = $createSymbolicLinksSIDs | Where-Object { $_ -notlike $allowedCreateSymbolicLinksSIDs[0] }
if ($disallowedCreateSymbolicLinksSIDs) { Write-Host "WN10-UR-000060 - $disallowedCreateSymbolicLinksSIDs" }

$debugProgramsSIDs = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDebugProgramsSIDs = @("*S-1-5-32-544")
$disallowedDebugProgramsSIDs = $debugProgramsSIDs | Where-Object { $_ -notlike $allowedDebugProgramsSIDs[0] }
if ($disallowedDebugProgramsSIDs) { Write-Host "WN10-UR-000065 - $disallowedDebugProgramsSIDs" }

$denyAccessToThisComputerSIDs = ($policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyAccessToThisComputerSIDs = @("*S-1-5-21-2475802288-2214110278-505332317-519", "*S-1-5-21-2475802288-2214110278-505332317-512", "*S-1-5-32-546", "*S-1-5-113")
$disallowedDenyAccessToThisComputerSIDs = $denyAccessToThisComputerSIDs | Where-Object { $_ -notlike $allowedDenyAccessToThisComputerSIDs[0] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[1] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[2] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[3] }
if ($disallowedDenyAccessToThisComputerSIDs) { Write-Host "WN10-UR-000070 - $disallowedDenyAccessToThisComputerSIDs" }

$denyLogOnAsBatchJobSIDs = ($policyContent | Select-String "SeDenyBatchLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnAsBatchJobSIDs = @("*S-1-5-21-2475802288-2214110278-505332317-519", "*S-1-5-21-2475802288-2214110278-505332317-512")
$disallowedDenyLogOnAsBatchJobSIDs = $denyLogOnAsBatchJobSIDs | Where-Object { $_ -notlike $allowedDenyLogOnAsBatchJobSIDs[0] -and $_ -notlike $allowedDenyLogOnAsBatchJobSIDs[1] }
if ($disallowedDenyLogOnAsBatchJobSIDs) { Write-Host "WN10-UR-000075 - $disallowedDenyLogOnAsBatchJobSIDs" }

$denyLogOnAsServiceSIDs = ($policyContent | Select-String "SeDenyServiceLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnAsServiceSIDs = @("*S-1-5-21-2475802288-2214110278-505332317-519", "*S-1-5-21-2475802288-2214110278-505332317-512")
$disallowedDenyLogOnAsServiceSIDs = $denyLogOnAsServiceSIDs | Where-Object { $_ -notlike $allowedDenyLogOnAsServiceSIDs[0] -and $_ -notlike $allowedDenyLogOnAsServiceSIDs[1] }
if ($disallowedDenyLogOnAsServiceSIDs) { Write-Host "WN10-UR-000080 - $disallowedDenyLogOnAsServiceSIDs" }

$denyLogOnLocallySIDs = ($policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnLocallySIDs = @("*S-1-5-21-2475802288-2214110278-505332317-519", "*S-1-5-21-2475802288-2214110278-505332317-512", "*S-1-5-32-546")
$disallowedDenyLogOnLocallySIDs = $denyLogOnLocallySIDs | Where-Object { $_ -notlike $allowedDenyLogOnLocallySIDs[0] -and $_ -notlike $allowedDenyLogOnLocallySIDs[1] -and $_ -notlike $allowedDenyLogOnLocallySIDs[2] }
if ($disallowedDenyLogOnLocallySIDs) { Write-Host "WN10-UR-000085 - $disallowedDenyLogOnLocallySIDs" }

$denyLogOnThroughRemoteDesktopServicesSIDs = ($policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedDenyLogOnThroughRemoteDesktopServicesSIDs = @("*S-1-5-21-2475802288-2214110278-505332317-519", "*S-1-5-21-2475802288-2214110278-505332317-512", "*S-1-5-32-546", "*S-1-5-113")
$disallowedDenyLogOnThroughRemoteDesktopServicesSIDs = $denyLogOnThroughRemoteDesktopServicesSIDs | Where-Object { $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[0] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[1] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[2] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[3] }
if ($disallowedDenyLogOnThroughRemoteDesktopServicesSIDs) { Write-Host "WN10-UR-000090 - $disallowedDenyLogOnThroughRemoteDesktopServicesSIDs" }

$enableComputerAndUserAccountsToBeTrustedForDelegationSIDs = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
if ($enableComputerAndUserAccountsToBeTrustedForDelegationSIDs.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000095 - $enableComputerAndUserAccountsToBeTrustedForDelegationSIDs" }

$forceShutdownFromRemoteSystemSIDs = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedForceShutdownFromRemoteSystemSIDs = @("*S-1-5-32-544")
$disallowedForceShutdownFromRemoteSystemSIDs = $forceShutdownFromRemoteSystemSIDs | Where-Object { $_ -notlike $allowedForceShutdownFromRemoteSystemSIDs[0] }
if ($disallowedForceShutdownFromRemoteSystemSIDs) { Write-Host "WN10-UR-000100 - $disallowedForceShutdownFromRemoteSystemSIDs" }

$impersonateAClientAfterAuthenticationSIDs = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedImpersonateAClientAfterAuthenticationSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
$disallowedImpersonateAClientAfterAuthenticationSIDs = $impersonateAClientAfterAuthenticationSIDs | Where-Object { $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[0] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[1] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[2] -and $_ -notlike $allowedImpersonateAClientAfterAuthenticationSIDs[3] }
if ($disallowedImpersonateAClientAfterAuthenticationSIDs) { Write-Host "WN10-UR-000110 - $disallowedImpersonateAClientAfterAuthenticationSIDs" }

$loadAndUnloadDeviceDriversSIDs = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedLoadAndUnloadDeviceDriversSIDs = @("*S-1-5-32-544")
$disallowedLoadAndUnloadDeviceDriversSIDs = $loadAndUnloadDeviceDriversSIDs | Where-Object { $_ -notlike $allowedLoadAndUnloadDeviceDriversSIDs[0] }
if ($disallowedLoadAndUnloadDeviceDriversSIDs) { Write-Host "WN10-UR-000120 - $disallowedLoadAndUnloadDeviceDriversSIDs" }

$lockPagesInMemorySIDs = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
if ($lockPagesInMemorySIDs.Contains('*S-1') -eq $true) { Write-Host "WN10-UR-000125 - $lockPagesInMemorySIDs" }

$manageAuditingAndSecurityLogSIDs = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedManageAuditingAndSecurityLogSIDs = @("*S-1-5-32-544")
$disallowedManageAuditingAndSecurityLogSIDs = $manageAuditingAndSecurityLogSIDs | Where-Object { $_ -notlike $allowedManageAuditingAndSecurityLogSIDs[0] }
if ($disallowedManageAuditingAndSecurityLogSIDs) { Write-Host "WN10-UR-000130 - $disallowedManageAuditingAndSecurityLogSIDs" }

$modifyFirmwareEnvironmentValuesSIDs = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedModifyFirmwareEnvironmentValuesSIDs = @("*S-1-5-32-544")
$disallowedModifyFirmwareEnvironmentValuesSIDs = $modifyFirmwareEnvironmentValuesSIDs | Where-Object { $_ -notlike $allowedModifyFirmwareEnvironmentValuesSIDs[0] }
if ($disallowedModifyFirmwareEnvironmentValuesSIDs) { Write-Host "WN10-UR-000140 - $disallowedModifyFirmwareEnvironmentValuesSIDs" }

$performVolumeMaintenanceTasksSIDs = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedPerformVolumeMaintenanceTasksSIDs = @("*S-1-5-32-544")
$disallowedPerformVolumeMaintenanceTasksSIDs = $performVolumeMaintenanceTasksSIDs | Where-Object { $_ -notlike $allowedPerformVolumeMaintenanceTasksSIDs[0] }
if ($disallowedPerformVolumeMaintenanceTasksSIDs) { Write-Host "WN10-UR-000145 - $disallowedPerformVolumeMaintenanceTasksSIDs" }

$profileSingleProcessSIDs = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedProfileSingleProcessSIDs = @("*S-1-5-32-544")
$disallowedProfileSingleProcessSIDs = $profileSingleProcessSIDs | Where-Object { $_ -notlike $allowedProfileSingleProcessSIDs[0] }
if ($disallowedProfileSingleProcessSIDs) { Write-Host "WN10-UR-000150 - $disallowedProfileSingleProcessSIDs" }

$restoreFilesAndDirectoriesSIDs = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedRestoreFilesAndDirectoriesSIDs = @("*S-1-5-32-544")
$disallowedRestoreFilesAndDirectoriesSIDs = $restoreFilesAndDirectoriesSIDs | Where-Object { $_ -notlike $allowedRestoreFilesAndDirectoriesSIDs[0] }
if ($disallowedRestoreFilesAndDirectoriesSIDs) { Write-Host "WN10-UR-000160 - $disallowedRestoreFilesAndDirectoriesSIDs" }

$takeOwnershipOfFilesOrOtherObjectsSIDs = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
$allowedTakeOwnershipOfFilesOrOtherObjectsSIDs = @("*S-1-5-32-544")
$disallowedTakeOwnershipOfFilesOrOtherObjectsSIDs = $takeOwnershipOfFilesOrOtherObjectsSIDs | Where-Object { $_ -notlike $allowedTakeOwnershipOfFilesOrOtherObjectsSIDs[0] }
if ($disallowedTakeOwnershipOfFilesOrOtherObjectsSIDs) { Write-Host "WN10-UR-000165 - $disallowedTakeOwnershipOfFilesOrOtherObjectsSIDs" }

$hardenedPaths = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
if ($hardenedPaths."\\*\SYSVOL" -ne 'RequireMutualAuthentication=1,RequireIntegrity=1' -or $hardenedPaths."\\*\NETLOGON" -ne 'RequireMutualAuthentication=1,RequireIntegrity=1') { Write-Host "WN10-CC-000050" }

<#
$psTranscriptionCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\ -ErrorAction SilentlyContinue
if ($psTranscriptionCheck -ne $null) {
    if ($psTranscriptionCheck.EnableTranscripting -ne 1) { Write-Host "WN10-CC-000327 - $($psTranscriptionCheck.EnableTranscripting)" }
} else {
    Write-Host "WN10-CC-000327 - Value is null"
}
#>

<#
$secServicesRunningCheck = $vbsDetailsCheck.SecurityServicesRunning | Out-String
if ($secServicesRunningCheck.Contains(2) -eq $false) { Write-Host "WN10-CC-000080 - $secServicesRunningCheck" }
#>

$ieInstalled = $allInstalledSoftware | Where-Object { $_.Name -like "*Internet Explorer*" }
if ($ieInstalled -ne $null) { Write-Host "WN10-CC-000391 - $ieInstalled" }

$portProxyCheck = netsh interface portproxy show all
if ($portProxyCheck -ne $null -and $portProxyCheck.Trim() -ne '') { Write-Host "WN10-00-000395 - $portProxyCheck" }

$validFirefoxUsers = Get-ChildItem C:\Users | Where-Object { $_.PSIsContainer }
foreach ($possibleFirefoxUser in $validFirefoxUsers) {
   $firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
   if (Test-Path $firefoxPath) {
	   $profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
	   if ($profilePath) {
		   $firefoxPreferences = Get-Content "$profilePath\prefs.js" -ErrorAction SilentlyContinue | Out-String
		   $firefoxHandlers = Get-Content "$profilePath\handlers.json" -ErrorAction SilentlyContinue | Out-String
		   break
	   }
   }
}

$firefoxVersion = Get-WmiObject -Class Win32Reg_AddRemovePrograms | Where-Object { $_.DisplayName -like "*Mozilla Firefox (x64 en-US)" }
$mozillaCfg = Get-Content "C:\Program Files\Mozilla Firefox\mozilla.cfg" | Out-String
$firefoxSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\

if ($firefoxVersion.Version -lt 130) { Write-Host "FFOX-00-000001 - $($firefoxVersion.Version)" }

<#
if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.SSLVersionMin -notin @("tls1.2", "tls1.3")) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"security.tls.version.min", 3') -eq $false -and $mozillaCfg.Contains('"security.tls.version.min", 4') -eq $false) { Write-Host "FFOX-00-000002" }
	   }
   }
}
#>

if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"security.default_personal_cert", "Ask Every Time"') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"security.default_personal_cert", "Ask Every Time"') -eq $false) { Write-Host "FFOX-00-000003" }
	   }
   }
}


if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"browser.search.update", false') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"browser.search.update", false') -eq $false) { Write-Host "FFOX-00-000004" }
	   }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.ExtensionUpdate -ne "0") {
	   if ($firefoxPreferences.Contains('"extensions.update.enabled", false') -eq $false {
		   if ($mozillaCfg -ne $null) {
			   if ($mozillaCfg.Contains('"extensions.update.enabled", false') -eq $false) { Write-Host "FFOX-00-000005" }
		   }
	   }
   }
}


$notAllowedMIMEList = @("HTA", "JSE", "JS", "MOCHA", "SHS", "VBE", "VBS", "SCT", "WSC", "FDF", "XFDF", "LSL", "LSO", "LSS", "IQY", "RQY", "DOS", "BAT", "PS", "EPS", "WCH", "WCM", "WB1", "WB3", "WCH", "WCM", "AD")

$violationFound = $false
$handlersJson = Get-Content "$profilePath\handlers.json" | ConvertFrom-Json

foreach ($mimeType in $handlersJson.mimeTypes.PSObject.Properties) {
   $extensions = $mimeType.Value.extensions
   $action = $mimeType.Value.action
   
   foreach ($extension in $extensions) {
	   if ($notAllowedMIMEList -contains $extension) {
		   if ($action -eq 2 -or $action -eq 4) {
			   $violationFound = $true
			   break 2
		   }
	   }
   }
}

if ($violationFound -eq $true) { Write-Host "FFOX-00-000006" }

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableFormHistory -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"browser.formfill.enable", false') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"browser.formfill.enable", false') -eq $false) { Write-Host "FFOX-00-000007" }
			   }
		   }
	   }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.PasswordManagerEnabled -ne "0") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"signon.rememberSignons", false') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"signon.rememberSignons", false') -eq $false) { Write-Host "FFOX-00-000008" }
			   }
		   }
	   }
   }
}

if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"dom.disable_open_during_load", true') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"dom.disable_open_during_load", true') -eq $false) { Write-Host "FFOX-00-000009" }
	   }
   }
}

if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"dom.disable_window_move_resize", true') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"dom.disable_window_move_resize", true') -eq $false) { Write-Host "FFOX-00-000010" }
	   }
   }
}

if ($firefoxPreferences.Contains('"dom.disable_window_flip", true') -eq $false -and $mozillaCfg.Contains('"dom.disable_window_flip", true') -eq $false) { Write-Host "FFOX-00-000011" }

$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission -ErrorAction SilentlyContinue
if ($firefoxAddonsPermissionsCheck -ne $null) {
   if ($firefoxAddonsPermissionsCheck.Default -ne 0) {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"xpinstall.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"xpinstall.enabled", false') -eq $false) { Write-Host "FFOX-00-000013" }
	   } else {
		   if ($firefoxPreferences.Contains('"xpinstall.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"xpinstall.enabled", false') -eq $false) { Write-Host "FFOX-00-000013" }
	   }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableTelemetry -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"datareporting.policy.dataSubmissionEnabled", false') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"datareporting.policy.dataSubmissionEnabled", false') -eq $false) { Write-Host "FFOX-00-000014" }
			   }
		   }
	   }
   }
}

<#
if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableDeveloperTools -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"devtools.policy.disabled", true') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"devtools.policy.disabled", true') -eq $false) { Write-Host "FFOX-00-000015" }
			   }
		   }
	   }
   }
}
#>

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableForgetButton -ne "1") { Write-Host "FFOX-00-000018" }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisablePrivateBrowsing -ne "1") { Write-Host "FFOX-00-000019" }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.SearchSuggestEnabled -ne "0") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"browser.search.suggest.enabled", false') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"browser.search.suggest.enabled", false') -eq $false) { Write-Host "FFOX-00-000020" }
			   }
		   }
	   }
   }
}

$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay -ErrorAction SilentlyContinue
if ($firefoxAutoplayPermissions -ne $null) {
   if ($firefoxAutoplayPermissions.Default -ne "block-audio-video") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) { Write-Host "FFOX-00-000021" }
			   }
		   }
	   }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.NetworkPrediction -ne "0") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"network.dns.disablePrefetch", true') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"network.dns.disablePrefetch", true') -eq $false) { Write-Host "FFOX-00-000022" }
			   }
		   }
	   }
   }
}

$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection -ErrorAction SilentlyContinue
if ($firefoxTrackingProtection -ne $null) {
   if ($firefoxTrackingProtection.Fingerprinting -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false -and $firefoxPreferences.Contains('"privacy.fingerprintingProtection", true') -eq $false) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false -and $mozillaCfg.Contains('"privacy.fingerprintingProtection", true') -eq $false) { Write-Host "FFOX-00-000023" }
			   }
		   }
	   }
   }
} else {
   if ($firefoxPreferences.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -and $firefoxPreferences.Contains('"privacy.fingerprintingProtection", true') -eq $false -and $mozillaCfg.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false -and $mozillaCfg.Contains('"privacy.fingerprintingProtection", true') -eq $false) { Write-Host "FFOX-00-000023" }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.Cryptomining -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"privacy.trackingprotection.cryptomining.enabled", false') -eq $true) {
			   if ($mozillaCfg -ne $null) {
				   if ($mozillaCfg.Contains('"privacy.trackingprotection.cryptomining.enabled", false') -eq $true) { Write-Host "FFOX-00-000024" }
			   }
		   }
	   }
   }
}

if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"browser.contentblocking.category", "strict"') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"browser.contentblocking.category", "strict"') -eq $false) { Write-Host "FFOX-00-000025" }
	   }
   }
}

if ($firefoxPreferences -ne $null) {
   if ($firefoxPreferences.Contains('"extensions.htmlaboutaddons.recommendations.enabled", false') -eq $false -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) {
	   if ($mozillaCfg -ne $null) {
		   if ($mozillaCfg.Contains('"extensions.htmlaboutaddons.recommendations.enabled", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000026" }
	   }
   }
}

$disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers -ErrorAction SilentlyContinue
if ($disabledFirefoxCiphers -ne $null) {
   if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false") -and $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
} else {
   if ($firefoxPreferences -ne $null) {
	   if ($firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
   }
}

$firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging -ErrorAction SilentlyContinue
if ($firefoxUserMessaging -ne $null) {
   if ($firefoxUserMessaging.ExtensionRecommendations -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
} else {
   if ($firefoxPreferences -ne $null) {
	   if ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
	}
}

$firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage -ErrorAction SilentlyContinue
if ($firefoxHomePageSettings -ne $null) {
   if (($firefoxHomePageSettings.TopSites -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false) -or ($firefoxHomePageSettings.SponsoredTopSites -ne "0" -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false) -or ($firefoxHomePageSettings.SponsoredPocket -ne "0" -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false) -or ($firefoxHomePageSettings.Search -ne "0" -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false) -or ($firefoxHomePageSettings.Highlights -ne "0" -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false) -or ($firefoxHomePageSettings.Snippets -ne "0" -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false)) { Write-Host "FFOX-00-000029" }
} else {
   if ($firefoxPreferences -ne $null) {
	   if (($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false) -or ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false) -or ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false) -or ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false) -or ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false) -or ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false)) { Write-Host "FFOX-00-000029" }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableFirefoxAccounts -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"identity.fxaccounts.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"identity.fxaccounts.enabled", false') -eq $false) { Write-Host "FFOX-00-000034" }
	   }
   }
}


if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableFeedbackCommands -ne "1") { Write-Host "FFOX-00-000036" }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.EncryptedMediaExtensions -ne "0") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"media.eme.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"media.eme.enabled", false') -eq $false) { Write-Host "FFOX-00-000037" }
	   }
   }
}

if ($firefoxPreferences -ne $null) {
   if (($firefoxPreferences.Contains('"privacy.sanitize.sanitizeOnShutdown", true')) -or ($mozillaCfg -ne $null -and $mozillaCfg.Contains('"privacy.sanitize.sanitizeOnShutdown", true'))) { Write-Host "FFOX-00-000017" }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisablePocket -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"extensions.pocket.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"extensions.pocket.enabled", false') -eq $false) { Write-Host "FFOX-00-000038" }
	   }
   }
}

if ($firefoxSettings -ne $null) {
   if ($firefoxSettings.DisableFirefoxStudies -ne "1") {
	   if ($firefoxPreferences -ne $null) {
		   if ($firefoxPreferences.Contains('"app.shield.optoutstudies.enabled", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"app.shield.optoutstudies.enabled", false') -eq $false) { Write-Host "FFOX-00-000039" }
	   }
   }
}


$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ -ErrorAction SilentlyContinue
if ($baseEdgeSettings -ne $null -and $baseEdgeSettings -ne "") {
		$edgeProxySettings = $baseEdgeSettings.ProxySettings | Out-String 
	if ($edgeProxySettings.Contains("ProxyMode")) {
		$acceptableValues = @('direct', 'system', 'auto_detect', 'fixed_servers', 'pac_script')
		if (-not ($acceptableValues | Where-Object { $edgeProxySettings.Contains($_) })) {
		Write-Host "EDGE-00-000001 - $edgeProxySettings"
		}
	} else {
		$acceptableValues = @("ProxyPacUrl", "ProxyServer", "ProxyBypassList")
		if (-not ($acceptableValues | Where-Object { $edgeProxySettings.Contains($_) })) {
		Write-Host "EDGE-00-000001 - $edgeProxySettings"
		}
	}

	if ($baseEdgeSettings.PreventSmartScreenPromptOverride -ne 1) { Write-Host "EDGE-00-000002 - $($baseEdgeSettings.PreventSmartScreenPromptOverride)" }


	if ($baseEdgeSettings.PreventSmartScreenPromptOverrideForFiles -ne 1) { Write-Host "EDGE-00-000003 - $($baseEdgeSettings.PreventSmartScreenPromptOverrideForFiles)" }


	if ($baseEdgeSettings.InPrivateModeAvailability -ne 1) { Write-Host "EDGE-00-000005 $($baseEdgeSettings.InPrivateModeAvailability)" }


	if ($baseEdgeSettings.BackgroundModeEnabled -ne 0) { Write-Host "EDGE-00-000006 - $($baseEdgeSettings.BackgroundModeEnabled)" }


	if ($baseEdgeSettings.DefaultPopupsSetting -ne 2) { Write-Host "EDGE-00-000008 - $($baseEdgeSettings.DefaultPopupsSetting)" }


	$edgeManagedSearchEngines = $baseEdgeSettings.ManagedSearchEngines | ConvertFrom-Json
	$edgeNonHttpsSearchEngines = $edgeManagedSearchEngines | Where-Object { $_.search_url -notmatch '^https://' }
	if ($edgeNonHttpsSearchEngines) { Write-Host "EDGE-00-000009 - $($edgeNonHttpsSearchEngines)" }


	if ($baseEdgeSettings.SyncDisabled -ne 1) { Write-Host "EDGE-00-000010 - $($baseEdgeSettings.SyncDisabled)" }


	if ($baseEdgeSettings.NetworkPredictionOptions -ne 2) { Write-Host "EDGE-00-000011 - $($baseEdgeSettings.NetworkPredictionOptions)" }


	if ($baseEdgeSettings.SearchSuggestEnabled -ne 0) { Write-Host "EDGE-00-000012 - $($baseEdgeSettings.SearchSuggestEnabled)" }


	if ($baseEdgeSettings.ImportAutofillFormData -ne 0) { Write-Host "EDGE-00-000013 - $($baseEdgeSettings.ImportAutofillFormData)" }


	if ($baseEdgeSettings.ImportBrowserSettings -ne 0) { Write-Host "EDGE-00-000014 - $($baseEdgeSettings.ImportBrowserSettings)" }


	if ($baseEdgeSettings.ImportCookies -ne 0) { Write-Host "EDGE-00-000015 - $($baseEdgeSettings.ImportCookies)" }


	if ($baseEdgeSettings.ImportExtensions -ne 0) { Write-Host "EDGE-00-000016 - $($baseEdgeSettings.ImportExtensions)" }


	if ($baseEdgeSettings.ImportHistory -ne 0) { Write-Host "EDGE-00-000017 - $($baseEdgeSettings.ImportHistory)" }


	if ($baseEdgeSettings.ImportHomepage -ne 0) { Write-Host "EDGE-00-000018 - $($baseEdgeSettings.ImportHomepage)" }


	if ($baseEdgeSettings.ImportOpenTabs -ne 0) { Write-Host "EDGE-00-000019 - $($baseEdgeSettings.ImportOpenTabs)" }


	if ($baseEdgeSettings.ImportPaymentInfo -ne 0) { Write-Host "EDGE-00-000020 - $($baseEdgeSettings.ImportPaymentInfo)" }


	if ($baseEdgeSettings.ImportSavedPasswords -ne 0) { Write-Host "EDGE-00-000021 - $($baseEdgeSettings.ImportSavedPasswords)" }


	if ($baseEdgeSettings.ImportSearchEngine -ne 0) { Write-Host "EDGE-00-000022 - $($baseEdgeSettings.ImportSearchEngine)" }


	if ($baseEdgeSettings.ImportShortcuts -ne 0) { Write-Host "EDGE-00-000023 $($baseEdgeSettings.ImportShortcuts)" }


	if ($baseEdgeSettings.AutoplayAllowed -ne 0) { Write-Host "EDGE-00-000024 - $($baseEdgeSettings.AutoplayAllowed)" }


	if ($baseEdgeSettings.DefaultWebUsbGuardSetting -ne 2) { Write-Host "EDGE-00-000025 - $($baseEdgeSettings.DefaultWebUsbGuardSetting)" }


	if ($baseEdgeSettings.EnableMediaRouter -ne 0) { Write-Host "EDGE-00-000026 - $($baseEdgeSettings.EnableMediaRouter)" }


	if ($baseEdgeSettings.DefaultWebBluetoothGuardSetting -ne 2) { Write-Host "EDGE-00-000027 - $($baseEdgeSettings.DefaultWebBluetoothGuardSetting)" }


	if ($baseEdgeSettings.AutofillCreditCardEnabled -ne 0) { Write-Host "EDGE-00-000028 - $($baseEdgeSettings.AutofillCreditCardEnabled)" }


	if ($baseEdgeSettings.AutofillAddressEnabled -ne 0) { Write-Host "EDGE-00-000029 - $($baseEdgeSettings.AutofillAddressEnabled)" }

	<#
	if ($baseEdgeSettings.PersonalizationReportingEnabled -ne 0) { Write-Host "EDGE-00-000031 - $($baseEdgeSettings.PersonalizationReportingEnabled)" }
	#>

	<#
	if ($baseEdgeSettings.DefaultGeolocationSetting -ne 2) { Write-Host "EDGE-00-000032 - $($baseEdgeSettings.DefaultGeolocationSetting)" }
	#>

	if ($baseEdgeSettings.AllowDeletingBrowserHistory -ne 0) { Write-Host "EDGE-00-000033 - $($baseEdgeSettings.AllowDeletingBrowserHistory)" }

	<#
	if ($baseEdgeSettings.DeveloperToolsAvailability -ne 2) { Write-Host "EDGE-00-000034 - $($baseEdgeSettings.DeveloperToolsAvailability)" }
	#>

	if ($baseEdgeSettings.DownloadRestrictions -in @(0, 4)) { Write-Host "EDGE-00-000036 - $($baseEdgeSettings.DownloadRestrictions)" }


	$edgeExtensionInstallBlocklist = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist\
	if ($edgeExtensionInstallBlocklist.1 -ne "*") { Write-Host "EDGE-00-000041 - $($edgeExtensionInstallBlocklist.1)" }


	if ($baseEdgeSettings.PasswordManagerEnabled -ne 0) { Write-Host "EDGE-00-000043 - $($baseEdgeSettings.PasswordManagerEnabled)" }


	$edgeVersionCheck = (Get-Command "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe").FileVersionInfo | Select-Object -ExpandProperty FileVersion
	if ($edgeVersionCheck -lt "127") { Write-Host "EDGE-00-000045 - $edgeVersionCheck" }

	<#
	$baseEdgeSettingsSSLVersionMin = $baseEdgeSettings.SSLVersionMin
	if ($baseEdgeSettingsSSLVersionMin -ne "tls1.2") { Write-Host "EDGE-00-000046 - $baseEdgeSettingsSSLVersionMin" }
	#>

	if ($baseEdgeSettings.SitePerProcess -ne 1) { Write-Host "EDGE-00-000047 - $($baseEdgeSettings.SitePerProcess)" }


	if ($baseEdgeSettings.AuthSchemes -ne "ntlm,negotiate" -and $baseEdgeSettings.AuthSchemes -ne "basic,ntlm,negotiate") { Write-Host "EDGE-00-000048 - $($baseEdgeSettings.AuthSchemes)" }


	if ($baseEdgeSettings.SmartScreenEnabled -ne 1) { Write-Host "EDGE-00-000050 - $($baseEdgeSettings.SmartScreenEnabled)" }


	if ($baseEdgeSettings.SmartScreenPuaEnabled -ne 1) { Write-Host "EDGE-00-000051 - $($baseEdgeSettings.SmartScreenPuaEnabled)" }


	if ($baseEdgeSettings.PromptForDownloadLocation -ne 1) { Write-Host "EDGE-00-000052 - $($baseEdgeSettings.PromptForDownloadLocation)" }


	if ($baseEdgeSettings.TrackingPrevention -notin @(2, 3)) { Write-Host "EDGE-00-000054 - $($baseEdgeSettings.TrackingPrevention)" }


	if ($baseEdgeSettings.PaymentMethodQueryEnabled -ne 0) { Write-Host "EDGE-00-000055 - $($baseEdgeSettings.PaymentMethodQueryEnabled)" }


	if ($baseEdgeSettings.AlternateErrorPagesEnabled -ne 0) { Write-Host "EDGE-00-000056 - $($baseEdgeSettings.AlternateErrorPagesEnabled)" }


	if ($baseEdgeSettings.UserFeedbackAllowed -ne 0) { Write-Host "EDGE-00-000057 - $($baseEdgeSettings.UserFeedbackAllowed)" }


	if ($baseEdgeSettings.EdgeCollectionsEnabled -ne 0) { Write-Host "EDGE-00-000058 - $($baseEdgeSettings.EdgeCollectionsEnabled)" }


	if ($baseEdgeSettings.ConfigureShare -ne 1) { Write-Host "EDGE-00-000059 - $($baseEdgeSettings.ConfigureShare)" }


	if ($baseEdgeSettings.BrowserGuestModeEnabled -ne 0) { Write-Host "EDGE-00-000060 - $($baseEdgeSettings.BrowserGuestModeEnabled)" }


	if ($baseEdgeSettings.RelaunchNotification -ne 2) { Write-Host "EDGE-00-000061 - $($baseEdgeSettings.RelaunchNotification)" }


	if ($baseEdgeSettings.BuiltInDnsClientEnabled -ne 0) { Write-Host "EDGE-00-000062 - $($baseEdgeSettings.BuiltInDnsClientEnabled)" }

	$baseEdgeSettingsQuicAllowed = $baseEdgeSettings.QuicAllowed
	if ($baseEdgeSettingsQuicAllowed -ne 0) { Write-Host "EDGE-00-000063 - $baseEdgeSettingsQuicAllowed" }


	if ($baseEdgeSettings.VisualSearchEnabled -ne 0) { Write-Host "EDGE-00-000065 - $($baseEdgeSettings.VisualSearchEnabled)" }


	if ($baseEdgeSettings.HubsSidebarEnabled -ne 0) { Write-Host "EDGE-00-000066 - $($baseEdgeSettings.HubsSidebarEnabled)" }


	if ($baseEdgeSettings.DefaultCookiesSetting -ne 4) { Write-Host "EDGE-00-000067 - $($baseEdgeSettings.DefaultCookiesSetting)" }
}


Stop-Transcript