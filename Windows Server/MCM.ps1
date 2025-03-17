#build file and start transcript 
$hostnameForFile = $env:COMPUTERNAME
$transcriptPath = "\\onenet\home\Admin\Logging\Cyber\WinServerTier3\$hostnameForFile.txt"
Start-Transcript -Path $transcriptPath -Force


$computerInfo2 = Get-CimInstance Win32_OperatingSystem | Select-Object -expand Caption | Out-String
$computerInfo3 = (Get-WmiObject Win32_OperatingSystem).Version
$edge = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Microsoft Edge*" } 2>$null
$computerInfo = Get-ComputerInfo 2>$null
$wnVers = $computerInfo.WindowsProductName

#Windows Server 2012 MS/DC
if ($computerInfo2.Contains("2012") -or $computerInfo3.Contains("2012")) {

	$adminAccount = Get-LocalUser -Name "Administrator"

	$csDomainRole = $computerInfo.CsDomainRole

	$allWindowsServices = Get-Service
	$trellix = $allWindowsServices | where {$_.DisplayName -like "*Trellix*"} | Select Status,DisplayName | Out-String
	$symantec = $allWindowsServices | where {$_.DisplayName -like "*Symantec*"} | Select Status,DisplayName | Out-String
	$defender = $allWindowsServices | where {$_.DisplayName -like "*Defender*"} | Select Status,DisplayName | Out-String
	if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN12-00-000100" }

	$ntfs = Get-Volume

	$subcategoryAuditing = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
	
		$appLocker = Get-AppLockerPolicy -Effective -Xml
	if($appLocker.Contains('Type="Appx"') -eq $false) { Write-Host "WN12-00-000018" }

	if ($csDomainRole -eq "MemberServer" -or $csDomainRole -eq "StandaloneServer") {
		([ADSI] ('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
			$user = ([ADSI]$_.Path)
			$lastLogin = $user.Properties.LastLogin.Value
			$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
			if ($lastLogin -eq $null) {$lastLogin = 'Never'}
			if ($enabled -eq $true -and $user.Name -ne 'no access') { Write-Host "WN12-GE-000014 - $($user.Name) $lastLogin $enabled"}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$noPasswordUsers = Get-ADUser -Filter * -Properties Passwordnotrequired | Where-Object {$_.Enabled -eq $true -and $_.Passwordnotrequired -eq $true} | Select-Object -First 1
		if ($noPasswordUsers) {
			Write-Host "WN12-GE-000015 - $($noPasswordUsers.Name)"
		}
	} else {
		$noPasswordAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True"
		foreach ($account in $noPasswordAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN12-GE-000015 - $($account.Name)"
				break
			}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$neverExpiringAccounts = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1
		if ($neverExpiringAccounts) {
			Write-Host "WN12-GE-000016 - $($neverExpiringAccounts.Name)"
		}
	} else {
		$neverExpiringAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True"
		foreach ($account in $neverExpiringAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN12-GE-000016 - $($account.Name)"
				break
			}
		}
	}

	$job = Start-Job -ScriptBlock {
		Get-ChildItem -Path C:\ -Include *.p12,*.pfx -File -Recurse 2>$null | Select-Object -First 1
	}
	$lingeringCertificateFiles = if (Wait-Job $job -Timeout 60) {
		Receive-Job $job
	} else {
		Stop-Job $job
		$null
	}
	Remove-Job $job -Force
	if ($lingeringCertificateFiles -ne $null) {
		Write-Host "WN12-GE-000020 - $($lingeringCertificateFiles)"
	}


	$faxInstallCheck = Get-WindowsFeature | Where Name -eq Fax
	if ($faxInstallCheck.InstallState -eq "Installed") { Write-Host "WN12-SV-000100" }

	$simpletcpipInstallCheck = Get-WindowsFeature | Where Name -eq Simple-TCPIP
	if ($simpletcpipInstallCheck.InstallState -eq "Installed") { Write-Host "WN12-SV-000104" }

	$telnetClientInstallCheck = Get-WindowsFeature | Where Name -eq tlntsvr
	if ($telnetClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN12-00-000105" }

	$smbv1InstallCheck = Get-WindowsFeature -Name FS-SMB1
	if ($smbv1InstallCheck.InstallState -eq "Installed") { 
		$smb1LanmanServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").SMB1
		if ($smb1LanmanServer -ne 0) {
			Write-Host "WN12-00-000170 $($smbv1InstallCheck.InstallState) $($smb1LanmanServer)" 
		}
	}

	$powershell2InstallCheck = Get-WindowsFeature | Where Name -eq PowerShell-V2
	if ($powershell2InstallCheck.InstallState -eq "Installed") { Write-Host "WN12-00-000220" }

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpAnonymousAuth = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\"
		if ($ftpAnonymousAuth.Value -eq $true) {
			Write-Host "WN12-GE-000026 $($ftpAnonymousAuth.Value)"
		}
	}

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpSites = Get-WebConfiguration "/system.applicationHost/sites/site" -PSPath "IIS:\"
		foreach ($site in $ftpSites) {
			$ftpRoot = $site.ftpServer.virtualDirectories.physicalPath
			if ($ftpRoot -like "C:*") {
				Write-Host "WN12-GE-000027 - $ftpRoot"
				break
			}
		}
	}

	$exportPath = "$env:TEMP\secpol.inf"
	secedit /export /cfg $exportPath
	$policyContent = Get-Content -Path $exportPath

	$lockoutDurationCheck = $policyContent | Select-String "LockoutDuration" | Out-String
	if ($lockoutDurationCheck.Contains('900') -eq $false) { Write-Host "WN12-AC-000001 - $lockoutDurationCheck" }

	$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
	if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Host "WN12-AC-000002 - $lockoutBadCountCheck" }

	$lockoutCounterResetCheck = $policyContent | Select-String "ResetLockoutCount" | Out-String
	if ($lockoutCounterResetCheck.Contains('900') -eq $false) { Write-Host "WN12-AC-000003 - $lockoutCounterResetCheck" }

	$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
	if ($passwordHistorySize.Contains('24') -eq $false) { Write-Host "WN12-AC-000004 - $passwordHistorySize" }

	$maxPasswordAgeCheck = $policyContent | Select-String "MaximumPasswordAge" | Out-String
	if ($maxPasswordAgeCheck.Contains('60') -eq $false) { Write-Host "WN12-AC-000005 - $maxPasswordAgeCheck" }

	$minPasswordAgeCheck = $policyContent | Select-String "MinimumPasswordAge" | Out-String
	if ($minPasswordAgeCheck.Contains('1') -eq $false) { Write-Host "WN12-AC-000006 - $minPasswordAgeCheck" }

	$minPasswordLengthCheck = $policyContent | Select-String "MinimumPasswordLength" | Out-String
	if ($minPasswordLengthCheck.Contains('10') -eq $false) { Write-Host "WN12-AC-000007 - $minPasswordLengthCheck" }

	$passwordComplexityCheck = $policyContent | Select-String "PasswordComplexity" | Out-String
	if ($passwordComplexityCheck.Contains('1') -eq $false) { Write-Host "WN12-AC-000008 - $passwordComplexityCheck" }

	$reversiblePasswordEncryptionCheck = $policyContent | Select-String "ClearTextPassword" | Out-String
	if ($reversiblePasswordEncryptionCheck.Contains('1') -eq $True) { Write-Host "WN12-AC-000009 - $reversiblePasswordEncryptionCheck" }

	$applicationEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Application.evtx 2>$null).Access).FileSystemRights).Count
	if ($applicationEventLogACL -ne 3) { Write-Host "WN12-AU-000204 - $applicationEventLogACL" }

	$securityEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Security.evtx 2>$null).Access).FileSystemRights).Count
	if ($securityEventLogACL -ne 3) { Write-Host "WN12-AU-000205 - $securityEventLogACL" }

	$systemEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\System.evtx 2>$null).Access).FileSystemRights).Count
	if ($systemEventLogACL -ne 3) { Write-Host "WN12-AU-000206 - $systemEventLogACL" }

	$eventvwrPath = "$env:SystemRoot\System32\eventvwr.exe"
	$eventvwrACL = (Get-Acl $eventvwrPath 2>$null).Access
	$fullControlCount = ($eventvwrACL | Where-Object {$_.FileSystemRights -eq "Full Control"}).Count
	if ($fullControlCount -gt 1) { Write-Host "WN12-AU-000213 - $fullControlCount" }

	$lltdioDriverCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD
	if ($lltdioDriverCheck.EnableLLTDIO -eq 1) { Write-Host "WN12-CC-000001 - $($lltdioDriverCheck.EnableLLTDIO)" }
	if ($lltdioDriverCheck.EnableRspndr -eq 1) { Write-Host "WN12-CC-000002 - $($lltdioDriverCheck.EnableRspndr)" }

	$peerNetCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PeerNet\
	if ($peerNetCheck.Disabled -ne 1) { Write-Host "WN12-CC-000003 - $($peerNetCheck.Disabled)" }

	$networkBridgeCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
	if ($networkBridgeCheck.NC_AllowNetBridge_NLA -ne 0) { Write-Host "WN12-CC-000004 - $($networkBridgeCheck.NC_AllowNetBridge_NLA)" }
	if ($networkBridgeCheck.NC_StdDomainUserSetLocation -ne 1) { Write-Host "WN12-CC-000005 - $($networkBridgeCheck.NC_StdDomainUserSetLocation)" } 

	$forceTunnelCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition\
	if ($forceTunnelCheck.Force_Tunneling -ne 1 -or $forceTunnelCheck.Force_Tunneling -ne "Enabled") { Write-Host "WN12-CC-000006 - $($forceTunnelCheck.Force_Tunneling)" }

	$auditPolicyAll = AuditPol /get /category:*
	$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
	if ($credentialValidationCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000001 - $credentialValidationCheck" }
	if ($credentialValidationCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000002 - $credentialValidationCheck" }

	$otherAccountManagementCheck = $auditPolicyAll | Select-String "Other Account Management Events" | Out-String
	if ($otherAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000015 - $otherAccountManagementCheck" }

	$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
	if ($securityGroupManagementCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000017 - $securityGroupManagementCheck" }

	$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
	if ($userAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000019 - $userAccountManagementCheck" }
	if ($userAccountManagementCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000020 - $userAccountManagementCheck" }

	$processTrackingCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
	if ($processTrackingCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000023 - $processTrackingCheck" }

	$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
	if ($accountLockoutCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000031 - $accountLockoutCheck" }

	$logoffEventsCheck = $auditPolicyAll | Select-String "(?<!/)\bLogoff\b" | Out-String
	if ($logoffEventsCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000045 - $logoffEventsCheck" }

	$logonEventsCheck = $auditPolicyAll | Select-String "^  Logon\s{2,}" | Out-String
	if ($logonEventsCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000047 - $logonEventsCheck" }
	if ($logonEventsCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000048 - $logonEventsCheck" }

	$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
	if ($specialLogonCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000053 - $specialLogonCheck" }
	
	$centralPolicyStagingCheck = $auditPolicyAll | Select-String "Central Policy Staging" | Out-String
	if ($centralPolicyStagingCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000059 - $centralPolicyStagingCheck" }
	if ($centralPolicyStagingCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000060 - $centralPolicyStagingCheck" }

	$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
	if ($removableStorageCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000081 - $removableStorageCheck" }
	if ($removableStorageCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000082 - $removableStorageCheck" }

	$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
	if ($auditPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000085 - $auditPolicyChangeCheck" }
	if ($auditPolicyChangeCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000086 - $auditPolicyChangeCheck" }

	$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
	if ($authenticationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000087 - $authenticationPolicyChangeCheck" }

	$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
	if ($authorizationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000089 - $authorizationPolicyChangeCheck" }

	$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
	if ($sensitivePrivilegeUseCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000101 - $sensitivePrivilegeUseCheck" }
	if ($sensitivePrivilegeUseCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000102 - $sensitivePrivilegeUseCheck" }

	$ipSecDriverCheck = $auditPolicyAll | Select-String "IPsec Driver" | Out-String
	if ($ipSecDriverCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000103 - $ipSecDriverCheck" }
	if ($ipSecDriverCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000104 - $ipSecDriverCheck" }

	$otherSystemEventCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
	if ($otherSystemEventCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000105 - $otherSystemEventCheck" }
	if ($otherSystemEventCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000106 - $otherSystemEventCheck" }

	$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
	if ($securityStateChangeCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000107 - $securityStateChangeCheck" }

	$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
	if ($securitySystemExtensionCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000109 - $securitySystemExtensionCheck" }

	$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
	if ($systemIntegrityCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000111 - $systemIntegrityCheck" }
	if ($systemIntegrityCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000112 - $systemIntegrityCheck" }

	$lockScreenAccess = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
	if ($lockScreenAccess.NoLockScreenSlideshow -ne 1) { Write-Host "WN12-CC-000138 - $($lockScreenAccess.NoLockScreenSlideshow)" }

	$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\
	if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Host "WN12-CC-000150 - $($wDigestInfo.UseLogonCredential)" }

	$tcpip6Parameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
	if ($tcpip6Parameters.DisableIPSourceRouting -ne 2) { Write-Host "WN12-SO-000037 - $($tcpip6Parameters.DisableIPSourceRouting)" }

	$tcpipParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
	if ($tcpipParameters.DisableIPSourceRouting -ne 2) { Write-Host "WN12-SO-000038 - $($tcpipParameters.DisableIPSourceRouting)" }
	if ($tcpipParameters.EnableIPAutoConfigurationLimits -ne 1) { Write-Host "WN12-CC-000011 - $($tcpipParameters.EnableIPAutoConfigurationLimits)" }
	if ($tcpipParameters.EnableICMPRedirect -ne 0) { Write-Host "WN12-SO-000039 - $($tcpipParameters.EnableICMPRedirect)" }

	$configurationWirelessSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars
	if ($configurationWirelessSettingsCheck.EnableRegistrars -ne 0) { Write-Host "WN12-CC-000012 - $($configurationWirelessSettingsCheck.EnableRegistrars)" }

	$wcnUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI\
	if ($wcnUICheck.DisableWCNUI -ne 1) { Write-Host "WN12-CC-000013 - $($wcnUICheck.DisableWCNUI)" }

	$netbtParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
	if ($netbtParameters.NoNameReleaseOnDemand -ne 1) { Write-Host "WN12-SO-000043 - $($netbtParameters.NoNameReleaseOnDemand)" }

	$systemAuditSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
	if ($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Host "WN12-CC-000139 - $($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled)" }

	$earlyLaunchCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
	if ($earlyLaunchCheck.DriverLoadPolicy -ne 1) { Write-Host "WN12-CC-000027 - $($earlyLaunchCheck.DriverLoadPolicy)" }

	$gpoChangesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
	if ($gpoChangesCheck.NoGPOListChanges -ne 0) { Write-Host "WN12-CC-000028 - $($gpoChangesCheck.NoGPOListChanges)" }
	if ($gpoChangesCheck.NoBackgroundPolicy -ne 0) { Write-Host "WN12-CC-000029 - $($gpoChangesCheck.NoBackgroundPolicy)" }

	$windowsNTPrintersCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
	if ($windowsNTPrintersCheck.DisableWebPnPDownload -ne 1) { Write-Host "WN12-CC-000032 - $($windowsNTPrintersCheck.DisableWebPnPDownload)" }
	if ($windowsNTPrintersCheck.DisableHTTPPrinting -ne 1) { Write-Host "WN12-CC-000039 - $($windowsNTPrintersCheck.DisableHTTPPrinting)" }
	if ($windowsNTPrintersCheck.DoNotInstallCompatibleDriversFromWindowsUpdate -ne 1) { Write-Host "WN12-CC-000016 - $($windowsNTPrintersCheck.DoNotInstallCompatibleDriversFromWindowsUpdate)" }

	$servicingPoliciesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\
	if ($servicingPoliciesCheck.UseWindowsUpdate -ne 2) { Write-Host "WN12-CC-000018 - $($servicingPoliciesCheck.UseWindowsUpdate)" }

	$microsoftEventVwrDisableCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\EventViewer\
	if ($microsoftEventVwrDisableCheck.Disable -ne 1) { Write-Host "WN12-CC-000033 - $($microsoftEventVwrDisableCheck.Disable)" }

	$handwritingErrorReportsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports\
	if ($handwritingErrorReportsCheck.PreventHandwritingErrorReports -ne 1) { Write-Host "WN12-CC-000035 - $($handwritingErrorReportsCheck.PreventHandwritingErrorReports)" }

	$deviceInstallSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings
	if ($deviceInstallSettingsCheck.AllowRemoteRPC -ne 0) { Write-Host "WN12-CC-000019 - $($deviceInstallSettingsCheck.AllowRemoteRPC)" }
	if ($deviceInstallSettingsCheck.DisableSendGenericDriverNotFoundToWER -ne 1) { Write-Host "WN12-CC-000020 - $($deviceInstallSettingsCheck.DisableSendGenericDriverNotFoundToWER)" }
	if ($deviceInstallSettingsCheck.DisableSystemRestore -ne 0) { Write-Host "WN12-CC-000021 - $($deviceInstallSettingsCheck.DisableSystemRestore)" }
	if ($deviceInstallSettingsCheck.DisableSendRequestAdditionalSoftwareToWER -ne 1) { Write-Host "WN12-CC-000023 - $($deviceInstallSettingsCheck.DisableSendRequestAdditionalSoftwareToWER)" }

	$deviceMetadataCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\"
	if ($deviceMetadataCheck.PreventDeviceMetadataFromNetwork -ne 1) { Write-Host "WN12-CC-000022 - $($deviceMetadataCheck.PreventDeviceMetadataFromNetwork)" }

	$driverSearchingWindowsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching
	if ($driverSearchingWindowsCheck.SearchOrderConfig -ne 2) { Write-Host "WN12-CC-000024 - $($driverSearchingWindowsCheck.SearchOrderConfig)" }
	if ($driverSearchingWindowsCheck.DriverServerSelection -notin @(1, 2)) { Write-Host "WN12-CC-000025 - $($driverSearchingWindowsCheck.DriverServerSelection)" }
	if ($driverSearchingWindowsCheck.DontPromptForWindowsUpdate -ne 1) { Write-Host "WN12-CC-000026 - $($driverSearchingWindowsCheck.DontPromptForWindowsUpdate)" }
	if ($driverSearchingWindowsCheck.DontSearchWindowsUpdate -ne 1) { Write-Host "WN12-CC-000047 - $($driverSearchingWindowsCheck.DontSearchWindowsUpdate)" }

	$sqmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows\
	if ($sqmClientCheck.CEIPEnable -ne 0) { Write-Host "WN12-CC-000045 - $($sqmClientCheck.CEIPEnable)" }

	$internationalControlPanelCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International\"
	if ($internationalControlPanelCheck.BlockUserInputMethodsForSignIn -ne 1) { Write-Host "WN12-CC-000048 - $($internationalControlPanelCheck.BlockUserInputMethodsForSignIn)" }

	$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
	if ($windowsSystemChecks.DontDisplayNetworkSelectionUI -ne 1) { Write-Host "WN12-CC-000140 - $($windowsSystemChecks.DontDisplayNetworkSelectionUI)" }
	if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Host "WN12-CC-000088 - $($windowsSystemChecks.EnableSmartScreen)" }
	if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Host "WN12-CC-000051 - $($windowsSystemChecks.EnumerateLocalUsers)" }
	if ($windowsSystemChecks.DisableLockScreenAppNotifications -ne 1) { Write-Host "WN12-CC-000052 - $($windowsSystemChecks.DisableLockScreenAppNotifications)" }

	$powerSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
	if ($powerSettingsCheck.DCSettingIndex -ne 1) { Write-Host "WN12-CC-000054 - $($powerSettingsCheck.DCSettingIndex)" }
	if ($powerSettingsCheck.ACSettingIndex -ne 1) { Write-Host "WN12-CC-000055 - $($powerSettingsCheck.ACSettingIndex)" }

	$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
	if ($appCompatSettingsCheck.DisablePcaUI -notin @(0, 1)) { Write-Host "WN12-CC-000065 - $($appCompatSettingsCheck.DisableInventory)" }
	if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Host "WN12-CC-000071 - $($appCompatSettingsCheck.DisableInventory)" }

	$appxTrustedAppsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\
	if ($appxTrustedAppsCheck.AllowAllTrustedApps -ne 1) { Write-Host "WN12-CC-000070 - $($appxTrustedAppsCheck.AllowAllTrustedApps)" }
	 
	$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
	if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Host "WN12-CC-000072 - $($windowsExplorerSettingsCheck.NoAutoplayfornonVolume)" }
	if ($windowsExplorerSettingsCheck.NoAutorun -ne 1) { Write-Host "WN12-CC-000073 - $($windowsExplorerSettingsCheck.NoAutorun)" }
	if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -eq 1) { Write-Host "WN12-CC-000089 - $($windowsExplorerSettingsCheck.NoDataExecutionPrevention)" }
	if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -eq 1) { Write-Host "WN12-CC-000090 - $($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption)" }
	if ($windowsExplorerSettingsCheck.NoUseStoreOpenWith -ne 1) { Write-Host "WN12-CC-000030 - $($windowsExplorerSettingsCheck.NoUseStoreOpenWith)" }

	$windowsPoliciesExplorerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
	if ($windowsPoliciesExplorerCheck.NoAutorun -ne 1) { Write-Host "WN12-CC-000073 - $($windowsPoliciesExplorerCheck.NoAutorun)" }
	if ($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun -ne 255) { Write-Host "WN12-CC-000074 - $($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun)" }
	if ($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior -eq 1) { Write-Host "WN12-CC-000091 - $($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior)" }
	if ($windowsPoliciesExplorerCheck.NoPreviewPane -ne 1 -or $windowsPoliciesExplorerCheck.NoReadingPane -ne 1) { Write-Host "WN12-CC-000142 - $($windowsPoliciesExplorerCheck.NoPreviewPane) $($windowsPoliciesExplorerCheck.NoReadingPane)" }
	if ($windowsPoliciesExplorerCheck.NoInternetOpenWith -ne 1) { Write-Host "WN12-CC-000038 - $($windowsPoliciesExplorerCheck.NoInternetOpenWith)" }

	$credUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI\
	if ($credUICheck.DisablePasswordReveal -ne 1) { Write-Host "WN12-CC-000076 - $($credUICheck.DisablePasswordReveal)" }

	$credUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
	if ($credUICheck.EnumerateAdministrators -ne 0) { Write-Host "WN12-CC-000077 - $($credUICheck.EnumerateAdministrators)" }

	$eventLogApplication = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
	if ($eventLogApplication.MaxSize -lt 32768) { Write-Host "WN12-CC-000084 - $($eventLogApplication.MaxSize)" }

	$eventLogSecurity = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
	if ($eventLogSecurity.MaxSize -lt 196608) { Write-Host "WN12-CC-000085 - $($eventLogSecurity.MaxSize)" }

	$eventLogSetup = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup\
	if ($eventLogSetup.MaxSize -lt 32768) { Write-Host "WN12-CC-000086 - $($eventLogSetup.MaxSize)" }

	$eventLogSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
	if ($eventLogSystem.MaxSize -lt 32768) { Write-Host "WN12-CC-000087 - $($eventLogSystem.MaxSize)" }

	$locationAndSensorsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors\
	if ($locationAndSensorsCheck.DisableLocation -ne 1) { Write-Host "WN12-CC-000095 - $($locationAndSensorsCheck.DisableLocation)" }

	$ntTerminalServicesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
	if ($ntTerminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Host "WN12-CC-000096 - $($ntTerminalServicesCheck.DisablePasswordSaving)" }
	if ($ntTerminalServicesCheck.fDisableCdm -ne 1) { Write-Host "WN12-CC-000098 - $($ntTerminalServicesCheck.fDisableCdm)" }
	if ($ntTerminalServicesCheck.fDisableCcm -ne 1) { Write-Host "WN12-CC-000132 - $($ntTerminalServicesCheck.fDisableCcm)" }
	if ($ntTerminalServicesCheck.fDisableLPT -ne 1) { Write-Host "WN12-CC-000133 - $($ntTerminalServicesCheck.fDisableLPT)" }
	if ($ntTerminalServicesCheck.fEnableSmartCard -ne 1) { Write-Host "WN12-CC-000134 - $($ntTerminalServicesCheck.fEnableSmartCard)" }
	if ($ntTerminalServicesCheck.fDisablePNPRedirection -ne 1) { Write-Host "WN12-CC-000135 - $($ntTerminalServicesCheck.fDisablePNPRedirection)" }
	if ($ntTerminalServicesCheck.fPromptForPassword -ne 1) { Write-Host "WN12-CC-000099 - $($ntTerminalServicesCheck.fPromptForPassword)" }
	if ($ntTerminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Host "WN12-CC-000130 - $($ntTerminalServicesCheck.fEncryptRPCTraffic)" }
	if ($ntTerminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Host "WN12-CC-000100 - $($ntTerminalServicesCheck.MinEncryptionLevel)" }
	if ($ntTerminalServicesCheck.fAllowUnsolicited -ne 0) { Write-Host "WN12-CC-000058 - $($ntTerminalServicesCheck.fAllowUnsolicited)" }
	if ($ntTerminalServicesCheck.fAllowToGetHelp -ne 0) { Write-Host "WN12-CC-000059 - $($ntTerminalServicesCheck.fAllowToGetHelp)" }
	if ($ntTerminalServicesCheck.LoggingEnabled -ne 1) { Write-Host "WN12-CC-000062 - $($ntTerminalServicesCheck.LoggingEnabled)" }
	if ($ntTerminalServicesCheck.DeleteTempDirsOnExit -ne 1) { Write-Host "WN12-CC-000103 - $($ntTerminalServicesCheck.DeleteTempDirsOnExit)" }
	if ($ntTerminalServicesCheck.PerSessionTempDir -ne 1) { Write-Host "WN12-CC-000104 - $($ntTerminalServicesCheck.PerSessionTempDir)" }

	$internetExplorerFeeds = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
	if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Host "WN12-CC-000105 - $($internetExplorerFeeds.DisableEnclosureDownload)" }
	if ($internetExplorerFeeds.AllowBasicAuthInClear -eq 1) { Write-Host "WN12-CC-000106 - $($internetExplorerFeeds.AllowBasicAuthInClear)" }

	$windowsInstallerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
	if ($windowsInstallerCheck.EnableUserControl -ne 0) { Write-Host "WN12-CC-000115 - $($windowsInstallerCheck.EnableUserControl)" }
	if ($windowsInstallerCheck.AlwaysInstallElevated -ne 0) { Write-Host "WN12-CC-000116 - $($windowsInstallerCheck.AlwaysInstallElevated)" }
	if ($windowsInstallerCheck.SafeForScripting -eq 1) { Write-Host "WN12-CC-000117 - $($windowsInstallerCheck.SafeForScripting)" }
	if ($windowsInstallerCheck.DisableLUAPatching -eq 0) { Write-Host "WN12-CC-000118 - $($windowsInstallerCheck.DisableLUAPatching)" }

	$drmDisableOnlineCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DRM\
	if ($drmDisableOnlineCheck.DisableOnline -ne 1) { Write-Host "WN12-CC-000119 - $($drmDisableOnlineCheck.DisableOnline)" }

	$firstUseDialogBoxesCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer
	if ($firstUseDialogBoxesCheck.GroupPrivacyAcceptance -ne 1) { Write-Host "WN12-CC-000121 - $($firstUseDialogBoxesCheck.GroupPrivacyAcceptance)" }
	if ($firstUseDialogBoxesCheck.DisableAutoUpdate -ne 1) { Write-Host "WN12-CC-000122 - $($firstUseDialogBoxesCheck.DisableAutoUpdate)" }

	$currentVersionSystemPolicies = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
	if ($currentVersionSystemPolicies.DisableAutomaticRestartSignOn -ne 1) { Write-Host "WN12-CC-000145 - $($currentVersionSystemPolicies.DisableAutomaticRestartSignOn)" }

	$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
	if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Host "WN12-00-000210 - $($scriptBlockLogging.EnableScriptBlockLogging)" }

	$scriptedDiagnosticsProviderCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy
	if ($scriptedDiagnosticsProviderCheck.DisableQueryRemoteServer -ne 1) { Write-Host "WN12-CC-000066 - $($scriptedDiagnosticsProviderCheck.DisableQueryRemoteServer)" }
	if ($scriptedDiagnosticsProviderCheck.EnableQueryRemoteServer -ne 0) { Write-Host "WN12-CC-000067 - $($scriptedDiagnosticsProviderCheck.EnableQueryRemoteServer)" }

	$disablePerfTrackCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
	if ($disablePerfTrackCheck.ScenarioExecutionEnabled -ne 0) { Write-Host "WN12-CC-000068 - $($disablePerfTrackCheck.Disable)" }

	$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
	if ($winrmClientCheck.AllowBasic -ne 0) { Write-Host "WN12-CC-000123 - $($winrmClientCheck.AllowBasic)" }
	if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN12-CC-000124 - $($winrmClientCheck.AllowUnencryptedTraffic)" }
	if ($winrmClientCheck.AllowDigest -ne 0) { Write-Host "WN12-CC-000125 - $($winrmClientCheck.AllowDigest)" }

	$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
	if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Host "WN12-CC-000126 - $($winrmServiceCheck.AllowBasic)" }
	if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN12-CC-000127 - $($winrmServiceCheck.AllowUnencryptedTraffic)" }
	if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Host "WN12-CC-000128 - $($winrmServiceCheck.DisableRunAs)" }

	#Common Paths
	$windowsntWinLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
	$lsaSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
	$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\


	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		foreach ($volume in $ntfs) {
		if ($volume.FileSystemType -notin @("NTFS", "ReFS", "CSV") -and $volume.DriveType -eq "Fixed") {
			Write-Host "WN12-GE-000005 - $($volume.DriveLetter) = $($volume.FileSystemType)"
			break
			}
		}

		$adminPasswordLastSet = Get-ADUser -Filter * -Properties SID, PasswordLastSet | Where SID -Like "*-500" | FL Name, SID, PasswordLastSet
		if ($adminPasswordLastSet.PasswordLastSet -gt (Get-Date).AddDays(-365)) { Write-Host "WN12-SO-000007 - $($adminPasswordLastSet.PasswordLastSet)" }

			$userLogonRestrictionsCheck = $policyContent | Select-String "TicketValidateClient" | Out-String
		if ($userLogonRestrictionsCheck.Contains("0") -eq $true) { Write-Host "WN12-AC-000010-DC - $($userLogonRestrictionsCheck)" }

		$maxServiceAgeCheck = $policyContent | Select-String "MaxServiceAge" | Out-String
		if ($maxServiceAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..600) { Write-Host "WN12-AC-000011-DC - $($maxServiceAgeCheck)" }

		$maxTicketAgeCheck = $policyContent | Select-String "MaxTicketAge" | Out-String
		if ($maxTicketAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..11) { Write-Host "WN12-AC-000012-DC - $($maxTicketAgeCheck)" }

		$maxRenewAgeCheck = $policyContent | Select-String "MaxRenewAge" | Out-String
		if ($maxRenewAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..7) { Write-Host "WN12-AC-000013-DC - $($maxRenewAgeCheck)" }

		$maxClockSkewCheck = $policyContent | Select-String "MaxClockSkew" | Out-String
		if ($maxClockSkewCheck -match '\d+' -and [int]($matches[0]) -notin 0..5) { Write-Host "WN12-AC-000014-DC - $($maxClockSkewCheck)" }

		$wn32timeNTPClient = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient
		if ($wn32timeNTPClient.Enabled -ne 1) { Write-Host "WN12-AD-000007-DC - $($wn32timeNTPClient.Enabled)" }

		$wn32timeConfig = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config\
		if ($wn32timeConfig.EventLogFlags -notin @(2,3)) { Write-Host "WN12-AD-000008-DC - $($wn32timeConfig.EventLogFlags)" }

		$computerAccountManagementAudit = $auditPolicyAll | Select-String "Computer Account Management" | Out-String
		if ($computerAccountManagementAudit.Contains("Success") -eq $false) { Write-Host "WN12-AU-000011-DC - $computerAccountManagementAudit" }

		$directoryServiceAccessCheck = $auditPolicyAll | Select-String "Directory Service Access" | Out-String
		if ($directoryServiceAccessCheck.Contains("Success") -eq $false) { Write-Host "WN12-AU-000031-DC - $directoryServiceAccessCheck" }
		if ($directoryServiceAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN12-AU-000032-DC - $directoryServiceAccessCheck" }

		$directoryServiceChangesAudit = $auditPolicyAll | Select-String "Directory Service Changes" | Out-String
		if ($directoryServiceChangesAudit.Contains("Success") -eq $false) { Write-Host "WN12-AU-000035-DC - $directoryServiceChangesAudit" }
		
		$ntdsParameters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
		if ($ntdsParameters.LDAPServerIntegrity -ne 2) { Write-Host "WN12-SO-000090-DC - $($ntdsParameters.LDAPServerIntegrity)" }
		
		if ($netLogonParameters.RefusePasswordChange -ne 0) { Write-Host "WN12-SO-000091-DC - $($netLogonParameters.RefusePasswordChange)" }

		if ($lanmanServerParameters.NullSessionPipes -notin @("netlogon", "samr", "lsarpc")) { Write-Host "WN12-SO-000055-DC - $($lanmanServerParameters.NullSessionPipes)" }

		$remoteInteractiveLogonRightSID = ($policyContent | Select-String "SeRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($remoteInteractiveLogonRightSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000006-DC - $($remoteInteractiveLogonRightSID)" }

		$denyNetworkLogonRightSID = $policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String
		if ($denyNetworkLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN12-UR-000017-DC - $($denyNetworkLogonRightSID)" }

		$denyBatchLogonRightSID = $policyContent | Select-String "SeDenyBatchLogonRight" | Out-String
		if ($denyBatchLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN12-UR-000018-DC - $($denyBatchLogonRightSID)" }

		$denyServiceLogonRightSID = $policyContent | Select-String "SeDenyServiceLogonRight" | Out-String
		if ($denyServiceLogonRightSID.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000019-DC - $($denyServiceLogonRightSID)" }

		$denyInteractiveLogonRightSID = $policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String
		if ($denyInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN12-UR-000020-DC - $($denyInteractiveLogonRightSID)" }

		$denyRemoteInteractiveLogonRightSID = $policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String
		if ($denyRemoteInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN12-UR-000021-DC - $($denyRemoteInteractiveLogonRightSID)" }

		$enableDelegationPrivilegeCheckSID = ($policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($enableDelegationPrivilegeCheckSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000022-DC - $($enableDelegationPrivilegeCheckSID)" }

		$krbtgtAccount = Get-ADUser krbtgt -Property PasswordLastSet
		$daysSincePasswordChange = ((Get-Date) - $krbtgtAccount.PasswordLastSet).Days
		if ($daysSincePasswordChange -gt 180) { Write-Host "WN12-AD-000015-DC - $($krbtgtAccount.PasswordLastSet)" }
	}

	#Member Server and Standalone Server Checks
	if ($csDomainRole -eq "MemberServer" -or $csDomainRole -eq "StandaloneServer") {

		$windowsntRPCCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
		if ($windowsntRPCCheck.RestrictRemoteClients -ne 1) { Write-Host "WN12-CC-000064 - $($windowsntRPCCheck.RestrictRemoteClients)" }

		if ($windowsntWinLogon.CachedLogonsCount -le 4) { Write-Host "WN12-SO-000024 - $($windowsntWinLogon.CachedLogonsCount)" }

		$enableDelegationPrivilegeCheck = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
		if ($enableDelegationPrivilegeCheck.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000022 - $($enableDelegationPrivilegeCheck)" }

		if ($windowsntWinLogon.DefaultPassword -eq 1) { Write-Host "WN12-SO-000036 - $($windowsntWinLogon.DefaultPassword)" }

		$forceShutdownFromRemoteSystemSID = ($policyContent | Select-String "SeRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($forceShutdownFromRemoteSystemSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000006 - $($forceShutdownFromRemoteSystemSID)" }

		if ($edge -ne $null) {
			
			$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ 2>$null
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
		}
		
		$validFirefoxUsers = Get-ChildItem C:\Users | Where-Object { $_.PSIsContainer }
		foreach ($possibleFirefoxUser in $validFirefoxUsers) {
			$firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
			if (Test-Path $firefoxPath) {
				$profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
				if ($profilePath) {
					$firefoxPreferences = Get-Content "$profilePath\prefs.js" 2>$null | Out-String
					$firefoxHandlers = Get-Content "$profilePath\handlers.json" 2>$null | Out-String
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
			   if ($firefoxPreferences.Contains('"extensions.update.enabled", false') -eq $false) {
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

		$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission 2>$null
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

		$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay 2>$null
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

		$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection 2>$null
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

		$disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers 2>$null
		if ($disabledFirefoxCiphers -ne $null) {
		   if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false") -and $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		   }
		}

		$firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging 2>$null
		if ($firefoxUserMessaging -ne $null) {
		   if ($firefoxUserMessaging.ExtensionRecommendations -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
			}
		}

		$firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage 2>$null
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
	}

	$disableBuiltInGuestAccountCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
	if ($disableBuiltInGuestAccountCheck.Contains("1") -eq $true) { Write-Host "WN12-SO-000003 - $($disableBuiltInGuestAccountCheck)" }

	if ($lsaSettings.LimitBlankPasswordUse -ne 1) { Write-Host "WN12-SO-000004 - $($lsaSettings.LimitBlankPasswordUse)" }

	$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
	if ($newAdminName.Contains("Administrator") -eq $true) { Write-Host "WN12-SO-000005 - $($newAdminName)" }

	$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
	if ($newGuestName -match '="Guest"') { Write-Host "WN12-SO-000006 - $($newGuestName)" }

	if ($lsaSettings.SCENoApplyLegacyAuditPolicy -ne 1) { Write-Host "WN12-SO-000009 - $($lsaSettings.SCENoApplyLegacyAuditPolicy)" }

	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
	if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Host "WN12-SO-000012 - $($netLogonParameters.RequireSignOrSeal)" }
	if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Host "WN12-SO-000013 - $($netLogonParameters.SealSecureChannel)" }
	if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Host "WN12-SO-000014 - $($netLogonParameters.SignSecureChannel)" }
	if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Host "WN12-SO-000015 - $($netLogonParameters.DisablePasswordChange)" }
	if ($netLogonParameters.MaximumPasswordAge -gt 30 -or $netLogonParameters.MaximumPasswordAge -eq 0) { Write-Host "WN12-SO-000016 - $($netLogonParameters.MaximumPasswordAge)" }
	if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Host "WN12-SO-000017 - $($netLogonParameters.RequireStrongKey)" }

	if ($currentVersionSystemPolicies.InactivityTimeoutSecs -notin 1..900) { Write-Host "WN12-SO-000021 - $($currentVersionSystemPolicies.InactivityTimeoutSecs)" }
	if ($currentVersionSystemPolicies.LegalNoticeText -eq $null) { Write-Host "WN12-SO-000022 - $($currentVersionSystemPolicies.LegalNoticeText)" }
	if ($currentVersionSystemPolicies.LegalNoticeCaption -eq $null) { Write-Host "WN12-SO-000023 - $($currentVersionSystemPolicies.LegalNoticeCaption)" }

	$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
	if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Host "WN12-SO-000028 - $($lanmanWorkstationParameters.RequireSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnableSecuritySignature -ne 1) { Write-Host "WN12-SO-000029 - $($lanmanWorkstationParameters.EnableSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Host "WN12-SO-000030 - $($lanmanWorkstationParameters.EnablePlainTextPassword)" }

	if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Host "WN12-SO-000032 - $($lanmanServerParameters.RequireSecuritySignature)" }
	if ($lanmanServerParameters.EnableSecuritySignature -ne 1) { Write-Host "WN12-SO-000032 - $($lanmanServerParameters.EnableSecuritySignature)" }

	if ($lsaSettings.RestrictAnonymousSAM -ne 1) { Write-Host "WN12-SO-000051 - $($lsaSettings.RestrictAnonymousSAM)" }
	if ($lsaSettings.RestrictAnonymous -ne 1) { Write-Host "WN12-SO-000052 - $($lsaSettings.RestrictAnonymous)" }
	if ($lsaSettings.EveryoneIncludesAnonymous -ne 0) { Write-Host "WN12-SO-000054 - $($lsaSettings.EveryoneIncludesAnonymous)" }

	if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Host "WN12-SO-000062 - $($lanmanServerParameters.RestrictNullSessAccess)" }

	if ($lsaSettings.UseMachineId -ne 1) { Write-Host "WN12-SO-000061 - $($lsaSettings.UseMachineId)" }

	$lsaMSV = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
	if ($lsaMSV.allownullsessionfallback -ne 0) { Write-Host "WN12-SO-000062 - $($lsaMSV.allownullsessionfallback)" }

	$lsaPKU2U = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
	if ($lsaPKU2U.AllowOnlineID -ne 0) { Write-Host "WN12-SO-000063 - $($lsaPKU2U.AllowOnlineID)" }

	$kerbParameters = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		if ($kerbParameters.SupportedEncryptionTypes -ne 2147483640) { Write-Host "WN12-SO-000064 - $($kerbParameters.SupportedEncryptionTypes)" }
	}

	if ($lsaSettings.NoLMHash -ne 1) { Write-Host "WN12-SO-000065 - $($lsaSettings.NoLMHash)" }
	if ($lsaSettings.LmCompatibilityLevel -ne 5) { Write-Host "WN12-SO-000067 - $($lsaSettings.LmCompatibilityLevel)" }

	$ldapServicesCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
	if ($ldapServicesCheck.LDAPClientIntegrity -ne 1) { Write-Host "WN12-SO-000068 - $($ldapServicesCheck.LDAPClientIntegrity)" }

	if ($lsaMSV.NTLMMinClientSec -ne 537395200) { Write-Host "WN12-SO-000069 - $($lsaMSV.NTLMMinClientSec)" }
	if ($lsaMSV.NtlmMinServerSec -ne 537395200) { Write-Host "WN12-SO-000070 - $($lsaMSV.NtlmMinServerSec)" }

	$microsoftCryptographyCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
	if ($microsoftCryptographyCheck.ForceKeyProtection -ne 2) { Write-Host "WN12-SO-000092 - $($microsoftCryptographyCheck.ForceKeyProtection)" }

	$lsaFIPSCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
	if ($lsaFIPSCheck.Enabled -ne 1) { Write-Host "WN12-SO-000074 - $($lsaFIPSCheck.Enabled)" }

	$registrySessionManagerCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
	if ($registrySessionManagerCheck.ProtectionMode -ne 1) { Write-Host "WN12-SO-000076 - $($registrySessionManagerCheck.ProtectionMode)" }

	if ($currentVersionSystemPolicies.FilterAdministratorToken -ne 1) { Write-Host "WN12-SO-000077 - $($currentVersionSystemPolicies.FilterAdministratorToken)" }
	if ($currentVersionSystemPolicies.EnableUIADesktopToggle -ne 0) { Write-Host "WN12-SO-000086 - $($currentVersionSystemPolicies.EnableUIADesktopToggle)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin -notin @(1, 2)) { Write-Host "WN12-SO-000078 - $($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorUser -ne 0) { Write-Host "WN12-SO-000079 - $($currentVersionSystemPolicies.ConsentPromptBehaviorUser)" }
	if ($currentVersionSystemPolicies.EnableInstallerDetection -ne 1) { Write-Host "WN12-SO-000080 - $($currentVersionSystemPolicies.EnableInstallerDetection)" }
	if ($currentVersionSystemPolicies.EnableSecureUIAPaths -ne 1) { Write-Host "WN12-SO-000082 - $($currentVersionSystemPolicies.EnableSecureUIAPaths)" }
	if ($currentVersionSystemPolicies.EnableLUA -ne 1) { Write-Host "WN12-SO-000083 - $($currentVersionSystemPolicies.EnableLUA)" }
	if ($currentVersionSystemPolicies.EnableVirtualization -ne 1) { Write-Host "WN12-SO-000085 - $($currentVersionSystemPolicies.EnableVirtualization)" }

	$attachmentPoliciesCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
	if ($attachmentPoliciesCheck.SaveZoneInformation -eq 1) { Write-Host "WN12-UC-000009 - $($attachmentPoliciesCheck.SaveZoneInformation)" }
	if ($attachmentPoliciesCheck.ScanWithAntiVirus -ne 3) { Write-Host "WN12-UC-000011 - $($attachmentPoliciesCheck.ScanWithAntiVirus)" }

	$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
	if ($accessCredManagerCheck.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000001 - $($accessCredManagerCheck)" }

	$actAsPartofOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
	if ($actAsPartofOSCheck.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000003 - $($actAsPartofOSCheck)" }

	$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedLogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
	$disallowedLogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedLogonSIDs[0] -and $_ -notlike $allowedLogonSIDs[1] }
	if ($disallowedLogonSIDs.Count -gt 0) { Write-Host "WN12-UR-000005 - $($disallowedLogonSIDs)" }

	$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedBackupSIDs = @("*S-1-5-32-544")
	$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
	if ($disallowedBackupSIDs.Count -gt 0) { Write-Host "WN12-UR-000007 - $($disallowedBackupSIDs)" }

	$createPagefileSID = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createPagefileSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000011 - $($createPagefileSID)" }

	$createTokenObjectsSID = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
	if ($createTokenObjectsSID.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000012 - $($createTokenObjectsSID)" }

	$createGlobalPrivilegeSID = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedCreateGlobalSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedCreateGlobalSIDs = $createGlobalPrivilegeSID | Where-Object { $_ -notlike $allowedCreateGlobalSIDs[0] -and $_ -notlike $allowedCreateGlobalSIDs[1] -and $_ -notlike $allowedCreateGlobalSIDs[2] -and $_ -notlike $allowedCreateGlobalSIDs[3] }
	if ($disallowedCreateGlobalSIDs.Count -gt 0) { Write-Host "WN12-UR-000013 - $($disallowedCreateGlobalSIDs)" }

	$createPermanentSharedObjectSID = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
	if ($createPermanentSharedObjectSID.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000014 - $($createPermanentSharedObjectSID)" }

	$createSymbolicLinkSID = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createSymbolicLinkSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000015 - $($createSymbolicLinkSID)" }

	$debugPrivilegeSID = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($debugPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000016 - $($debugPrivilegeSID)" }

	$forceShutdownFromRemoteSystemSID = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($forceShutdownFromRemoteSystemSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000023 - $($forceShutdownFromRemoteSystemSID)" }

	$auditPrivilegeSID = ($policyContent | Select-String "SeAuditPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedAuditSIDs = @("*S-1-5-19", "*S-1-5-20")
	$disallowedAuditSIDs = $auditPrivilegeSID | Where-Object { $_ -notlike $allowedAuditSIDs[0] -and $_ -notlike $allowedAuditSIDs[1] }
	if ($disallowedAuditSIDs.Count -gt 0) { Write-Host "WN12-UR-000024 - $($disallowedAuditSIDs)" }

	$impersonateAClientAfterAuthenticationSID = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedImpersonateSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedImpersonateSIDs = $impersonateAClientAfterAuthenticationSID | Where-Object { $_ -notlike $allowedImpersonateSIDs[0] -and $_ -notlike $allowedImpersonateSIDs[1] -and $_ -notlike $allowedImpersonateSIDs[2] -and $_ -notlike $allowedImpersonateSIDs[3] }
	if ($disallowedImpersonateSIDs.Count -gt 0) { Write-Host "WN12-UR-000025 - $($disallowedImpersonateSIDs)" }

	$increaseBasePrioritySID = ($policyContent | Select-String "SeIncreaseBasePriorityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($increaseBasePrioritySID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000027 - $($increaseBasePrioritySID)" }

	$loadDriverSID = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($loadDriverSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000028 - $($loadDriverSID)" }

	$lockMemorySID = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
	if ($lockMemorySID.Contains("*S-1") -eq $true) { Write-Host "WN12-UR-000029 - $($lockMemorySID)" }

	$manageAuditingAndSecurityLogSID = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($manageAuditingAndSecurityLogSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000032 - $($manageAuditingAndSecurityLogSID)" }

	$modifyFirmwareEnvironmentSID = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($modifyFirmwareEnvironmentSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000034 - $($modifyFirmwareEnvironmentSID)" }

	$performVolumeMaintenanceSID = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($performVolumeMaintenanceSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000035 - $($performVolumeMaintenanceSID)" }

	$profileSingleProcessSID = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($profileSingleProcessSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000036 - $($profileSingleProcessSID)" }

	$restorePrivilegeSID = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($restorePrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000040 - $($restorePrivilegeSID)" }

	$takeOwnershipSID = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($takeOwnershipSID -notlike "*S-1-5-32-544") { Write-Host "WN12-UR-000042 - $($takeOwnershipSID)" }
	
} elseif ($wnVers.Contains("2016") -or $computerInfo2.Contains("2016") -or $computerInfo3.Contains("2016")) {
	
	#Windows Server 2016 MS/DC
	$tpm = Get-Tpm 2>$null
	$tpmPresent = $tpm.TpmPresent
	$tpmEnabled = $tpm.TpmEnabled

	$adminAccount = Get-LocalUser -Name "Administrator"
	$currentDate = Get-Date
	$passwordLastSet = $adminAccount.PasswordLastSet
	$daysSincePasswordSet = ($currentDate - $passwordLastSet).Days
	if ($daysSincePasswordSet -gt 60) { Write-Host "WN16-00-000030 - $daysSincePasswordSet" }

	$shares = Get-WmiObject -Class Win32_Share
	$shareNames = $shares.Name
	$allowedShares = @("C$", "ADMIN$", "IPC$", "print$")
	if ($shareNames | Where-Object { $_ -notin $allowedShares }) { Write-Host "WN16-00-000250 - $($shareNames | Where-Object { $_ -notin $allowedShares })" }

	$appLocker = Get-AppLockerPolicy -Effective -Xml
	if($appLocker.Contains('Type="Appx"') -eq $false) { Write-Host "WN16-00-000090" }

	$csDomainRole = $computerInfo.CsDomainRole
	if($csDomainRole -ne "StandaloneServer") {
		if ($tpmPresent -eq $false -or $tpmEnabled -eq $false) { Write-Host "WN16-00-000100 - $tpmPresent $tpmEnabled" }
	}

	$windowsOSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
	if($windowsOSVersion -lt "14393") { Write-Host "WN16-00-000110 - $windowsOSVersion" }

	$allWindowsServices = Get-Service
	$trellix = $allWindowsServices | where {$_.DisplayName -like "*Trellix*"} | Select Status,DisplayName | Out-String
	$symantec = $allWindowsServices | where {$_.DisplayName -like "*Symantec*"} | Select Status,DisplayName | Out-String
	$defender = $allWindowsServices | where {$_.DisplayName -like "*Defender*"} | Select Status,DisplayName | Out-String
	if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN16-00-000120" }

	$ntfs = Get-Volume
	foreach ($volume in $ntfs) {
		if ($volume.FileSystemType -ne "NTFS" -and $volume.DriveType -eq "Fixed") {
			Write-Host "WN16-00-000150 - $($volume.DriveLetter) = $($volume.FileSystemType)"
			break
		}
	}

	$subcategoryAuditing = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
	if ($subcategoryAuditing.everyoneincludesanonymous -ne 0) { 
		Write-Host "WN16-SO-000290, WN16-00-000160, WN16-00-000170, WN16-00-000180 - $($subcategoryAuditing.everyoneincludesanonymous)"
	}

	$hklmSoftwareACL = Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
	$softwareIsInherited = $hklmSoftwareACL.IsInherited | Out-String
	$hklmSystemACL = Get-Acl -Path HKLM:SYSTEM | % { $_.access }
	$systemIsInherited = $hklmSystemACL.IsInherited | Out-String
	if ($softwareIsInherited.Contains("True") -or $systemIsInherited.Contains("True")) { Write-Host "WN16-00-000190 - $softwareIsInherited $systemIsInherited" }

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$inactiveAccounts = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object {$_.Enabled -eq $true}
		if ($inactiveAccounts) { Write-Host "WN16-00-000210 - $($inactiveAccounts.Name)" }
	} else {
		([ADSI] ('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
			$user = ([ADSI]$_.Path)
			$lastLogin = $user.Properties.LastLogin.Value
			$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
			if ($lastLogin -eq $null) {$lastLogin = 'Never'}
			if ($enabled -eq $true -and $user.Name -ne 'no access') { Write-Host "WN16-00-000210 - $($user.Name) $lastLogin $enabled"}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$noPasswordUsers = Get-ADUser -Filter * -Properties Passwordnotrequired | Where-Object {$_.Enabled -eq $true -and $_.Passwordnotrequired -eq $true} | Select-Object -First 1
		if ($noPasswordUsers) {
			Write-Host "WN16-00-000220 - $($noPasswordUsers.Name)"
		}
	} else {
		$noPasswordAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True"
		foreach ($account in $noPasswordAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN16-00-000220 - $($account.Name)"
				break
			}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$neverExpiringAccounts = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1
		if ($neverExpiringAccounts) {
			Write-Host "WN16-00-000230 - $($neverExpiringAccounts.Name)"
		}
	} else {
		$neverExpiringAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True"
		foreach ($account in $neverExpiringAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN16-00-000230 - $($account.Name)"
				break
			}
		}
	}

	$job = Start-Job -ScriptBlock {
		Get-ChildItem -Path C:\ -Include *.p12,*.pfx -File -Recurse 2>$null | Select-Object -First 1
	}
	$lingeringCertificateFiles = if (Wait-Job $job -Timeout 60) {
		Receive-Job $job
	} else {
		Stop-Job $job
		$null
	}
	Remove-Job $job -Force
	if ($lingeringCertificateFiles -ne $null) {
		Write-Host "WN16-00-000270 - $($lingeringCertificateFiles)"
	}

	if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN16-00-000310" }

	$faxInstallCheck = Get-WindowsFeature | Where Name -eq Fax
	if ($faxInstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000350" }

	$pnrpInstallCheck = Get-WindowsFeature | Where Name -eq PNRP
	if ($pnrpInstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000370" }

	$simpletcpipInstallCheck = Get-WindowsFeature | Where Name -eq Simple-TCPIP
	if ($simpletcpipInstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000380" }

	$telnetClientInstallCheck = Get-WindowsFeature | Where Name -eq Telnet-Client
	if ($telnetClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000390" }

	$tftpClientInstallCheck = Get-WindowsFeature | Where Name -eq TFTP-Client
	if ($tftpClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000400" }

	$smbv1InstallCheck = Get-WindowsFeature -Name FS-SMB1
	if ($smbv1InstallCheck.InstallState -eq "Installed") { 
		$smb1LanmanServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").SMB1
		if ($smb1LanmanServer -ne 0) {
			Write-Host "WN16-00-000410 $($smbv1InstallCheck.InstallState) $($smb1LanmanServer)" 
		}
	}

	$powershell2InstallCheck = Get-WindowsFeature | Where Name -eq PowerShell-V2
	if ($powershell2InstallCheck.InstallState -eq "Installed") { Write-Host "WN16-00-000420" }

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpAnonymousAuth = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\"
		if ($ftpAnonymousAuth.Value -eq $true) {
			Write-Host "WN16-00-000430 $($ftpAnonymousAuth.Value)"
		}
	}

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpSites = Get-WebConfiguration "/system.applicationHost/sites/site" -PSPath "IIS:\"
		foreach ($site in $ftpSites) {
			$ftpRoot = $site.ftpServer.virtualDirectories.physicalPath
			if ($ftpRoot -like "C:*") {
				Write-Host "WN16-00-000440 - $ftpRoot"
				break
			}
		}
	}

	$uefiStatus = $computerInfo.BiosFirmwareType
	if ($uefiStatus -ne "Uefi") { Write-Host "WN16-00-000470 - $uefiStatus" }

	$bootState = Confirm-SecureBootUEFI
	if ($bootState -eq $false) { Write-Host "WN16-00-000480 - $bootState" }

	$exportPath = "$env:TEMP\secpol.inf"
	secedit /export /cfg $exportPath
	$policyContent = Get-Content -Path $exportPath

	$lockoutDurationCheck = $policyContent | Select-String "LockoutDuration" | Out-String
	if ($lockoutDurationCheck.Contains('900') -eq $false -and $lockoutDurationCheck.Contains('15') -eq $false) { Write-Host "WN16-AC-000010 - $lockoutDurationCheck" }

	$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
	if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Host "WN16-AC-000020 - $lockoutBadCountCheck" }

	$lockoutCounterResetCheck = $policyContent | Select-String "ResetLockoutCount" | Out-String
	if ($lockoutCounterResetCheck.Contains('900') -eq $false) { Write-Host "WN16-AC-000030 - $lockoutCounterResetCheck" }

	$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
	if ($passwordHistorySize.Contains('24') -eq $false) { Write-Host "WN16-AC-000040 - $passwordHistorySize" }

	$maxPasswordAgeCheck = $policyContent | Select-String "MaximumPasswordAge" | Out-String
	if ($maxPasswordAgeCheck.Contains('60') -eq $false) { Write-Host "WN16-AC-000050 - $maxPasswordAgeCheck" }

	$minPasswordAgeCheck = $policyContent | Select-String "MinimumPasswordAge" | Out-String
	if ($minPasswordAgeCheck.Contains('1') -eq $false) { Write-Host "WN16-AC-000060 - $minPasswordAgeCheck" }

	$minPasswordLengthCheck = $policyContent | Select-String "MinimumPasswordLength" | Out-String
	if ($minPasswordLengthCheck.Contains('10') -eq $false -and $minPasswordLengthCheck.Contains('14') -eq $false) { Write-Host "WN16-AC-000070 - $minPasswordLengthCheck" }

	$passwordComplexityCheck = $policyContent | Select-String "PasswordComplexity" | Out-String
	if ($passwordComplexityCheck.Contains('1') -eq $false) { Write-Host "WN16-AC-000080 - $passwordComplexityCheck" }

	$reversiblePasswordEncryptionCheck = $policyContent | Select-String "ClearTextPassword" | Out-String
	if ($reversiblePasswordEncryptionCheck.Contains('1') -eq $True) { Write-Host "WN16-AC-000090 - $reversiblePasswordEncryptionCheck" }

	$applicationEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Application.evtx 2>$null).Access).FileSystemRights).Count
	if ($applicationEventLogACL -ne 3) { Write-Host "WN16-AU-000030 - $applicationEventLogACL" }

	$securityEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Security.evtx 2>$null).Access).FileSystemRights).Count
	if ($securityEventLogACL -ne 3) { Write-Host "WN16-AU-000040 - $securityEventLogACL" }

	$systemEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\System.evtx 2>$null).Access).FileSystemRights).Count
	if ($systemEventLogACL -ne 3) { Write-Host "WN16-AU-000050 - $systemEventLogACL" }

	$eventvwrPath = "$env:SystemRoot\System32\eventvwr.exe"
	$eventvwrACL = (Get-Acl $eventvwrPath 2>$null).Access
	$fullControlCount = ($eventvwrACL | Where-Object {$_.FileSystemRights -eq "Full Control"}).Count
	if ($fullControlCount -gt 1) { Write-Host "WN16-AU-000060 - $fullControlCount" }

	$auditPolicyAll = AuditPol /get /category:*
	$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
	if ($credentialValidationCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000070 - $credentialValidationCheck" }
	if ($credentialValidationCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000080 - $credentialValidationCheck" }

	$otherAccountManagementCheck = $auditPolicyAll | Select-String "Other Account Management Events" | Out-String
	if ($otherAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000100 - $otherAccountManagementCheck" }

	$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
	if ($securityGroupManagementCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000120 - $securityGroupManagementCheck" }

	$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
	if ($userAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000140 - $userAccountManagementCheck" }
	if ($userAccountManagementCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000150 - $userAccountManagementCheck" }

	$pnpEventsCheck = $auditPolicyAll | Select-String "Plug and Play Events" | Out-String
	if ($pnpEventsCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000160 - $pnpEventsCheck" }

	$processTrackingCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
	if ($processTrackingCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000170 - $processTrackingCheck" }

	$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
	if ($accountLockoutCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000230 - $accountLockoutCheck" }

	$groupMembershipCheck = $auditPolicyAll | Select-String "Group Membership" | Out-String
	if ($groupMembershipCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000240 - $groupMembershipCheck" }

	$logoffEventsCheck = $auditPolicyAll | Select-String "(?<!/)\bLogoff\b" | Out-String
	if ($logoffEventsCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000250 - $logoffEventsCheck" }

	$logonEventsCheck = $auditPolicyAll | Select-String "^  Logon\s{2,}" | Out-String
	if ($logonEventsCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000260 - $logonEventsCheck" }
	if ($logonEventsCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000270 - $logonEventsCheck" }

	$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
	if ($specialLogonCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000280 - $specialLogonCheck" }

	$otherObjectAccessCheck = $auditPolicyAll | Select-String "Other Object Access Events" | Out-String
	if ($otherObjectAccessCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000285 - $otherObjectAccessCheck" }
	if ($otherObjectAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000286 - $otherObjectAccessCheck" }

	$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
	if ($removableStorageCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000290 - $removableStorageCheck" }
	if ($removableStorageCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000300 - $removableStorageCheck" }

	$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
	if ($auditPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000310 - $auditPolicyChangeCheck" }
	if ($auditPolicyChangeCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000320 - $auditPolicyChangeCheck" }

	$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
	if ($authenticationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000330 - $authenticationPolicyChangeCheck" }

	$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
	if ($authorizationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000340 - $authorizationPolicyChangeCheck" }

	$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
	if ($sensitivePrivilegeUseCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000350 - $sensitivePrivilegeUseCheck" }
	if ($sensitivePrivilegeUseCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000360 - $sensitivePrivilegeUseCheck" }

	$ipSecDriverCheck = $auditPolicyAll | Select-String "IPsec Driver" | Out-String
	if ($ipSecDriverCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000370 - $ipSecDriverCheck" }
	if ($ipSecDriverCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000380 - $ipSecDriverCheck" }

	$otherSystemEventCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
	if ($otherSystemEventCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000390 - $otherSystemEventCheck" }
	if ($otherSystemEventCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000400 - $otherSystemEventCheck" }

	$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
	if ($securityStateChangeCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000410 - $securityStateChangeCheck" }

	$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
	if ($securitySystemExtensionCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000420 - $securitySystemExtensionCheck" }

	$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
	if ($systemIntegrityCheck.Contains("Success") -eq $false) { Write-Host "WN16-AU-000440 - $systemIntegrityCheck" }
	if ($systemIntegrityCheck.Contains("Failure") -eq $false) { Write-Host "WN16-AU-000450 - $systemIntegrityCheck" }

	$lockScreenAccess = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
	if ($lockScreenAccess.NoLockScreenSlideshow -ne 1) { Write-Host "WN16-CC-000010 - $($lockScreenAccess.NoLockScreenSlideshow)" }

	$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\
	if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Host "WN16-CC-000030 - $($wDigestInfo.UseLogonCredential)" }

	$tcpip6Parameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
	if ($tcpip6Parameters.DisableIPSourceRouting -ne 2) { Write-Host "WN16-CC-000040 - $($tcpip6Parameters.DisableIPSourceRouting)" }

	$tcpipParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
	if ($tcpipParameters.DisableIPSourceRouting -ne 2) { Write-Host "WN16-CC-000050 - $($tcpipParameters.DisableIPSourceRouting)" }

	if ($tcpipParameters.EnableICMPRedirect -ne 0) { Write-Host "WN16-CC-000060 - $($tcpipParameters.EnableICMPRedirect)" }

	$netbtParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
	if ($netbtParameters.NoNameReleaseOnDemand -ne 1) { Write-Host "WN16-CC-000070 - $($netbtParameters.NoNameReleaseOnDemand)" }

	$lanmanWorkstationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
	if ($lanmanWorkstationSettings.AllowInsecureGuestAuth -ne 0) { Write-Host "WN16-CC-000080 - $($lanmanWorkstationSettings.AllowInsecureGuestAuth)" }

	$networkProviderHardenedPaths = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
	if (($networkProviderHardenedPaths."\\*\SYSVOL" -ne "RequireMutualAuthentication=1, RequireIntegrity=1" -and $networkProviderHardenedPaths."\\*\SYSVOL" -ne "RequireMutualAuthentication=1,RequireIntegrity=1") -or ($networkProviderHardenedPaths."\\*\NETLOGON" -ne "RequireMutualAuthentication=1, RequireIntegrity=1" -and $networkProviderHardenedPaths."\\*\NETLOGON" -ne "RequireMutualAuthentication=1,RequireIntegrity=1")) { Write-Host "WN16-CC-000090 - $($networkProviderHardenedPaths."\\*\SYSVOL") $($networkProviderHardenedPaths."\\*\NETLOGON")" }

	$systemAuditSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
	if ($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Host "WN16-CC-000100 - $($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled)" }

	$vbsDetailsCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard\
	$vbsRequiredSecurityProperties = $vbsDetailsCheck.RequiredSecurityProperties | Out-String
	if ($vbsRequiredSecurityProperties.Contains("2") -eq $false -or $vbsDetailsCheck.VirtualizationBasedSecurityStatus -ne 2) { Write-Host "WN16-CC-000110 - $($vbsDetailsCheck.VirtualizationBasedSecurityStatus)" }

	$earlyLaunchCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
	if ($earlyLaunchCheck.DriverLoadPolicy -eq 7) { Write-Host "WN16-CC-000140 - $($earlyLaunchCheck.DriverLoadPolicy)" }

	$gpoChangesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
	if ($gpoChangesCheck.NoGPOListChanges -ne 0) { Write-Host "WN16-CC-000150 - $($gpoChangesCheck.NoGPOListChanges)" }

	$windowsNTPrintersCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
	if ($windowsNTPrintersCheck.DisableWebPnPDownload -ne 1) { Write-Host "WN16-CC-000160 - $($windowsNTPrintersCheck.DisableWebPnPDownload)" }
	if ($windowsNTPrintersCheck.DisableHTTPPrinting -ne 1) { Write-Host "WN16-CC-000170 - $($windowsNTPrintersCheck.DisableHTTPPrinting)" }

	$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
	if ($windowsSystemChecks.DontDisplayNetworkSelectionUI -ne 1) { Write-Host "WN16-CC-000180 - $($windowsSystemChecks.DontDisplayNetworkSelectionUI)" }
	if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Host "WN16-CC-000330 - $($windowsSystemChecks.EnableSmartScreen)" }

	$powerSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
	if ($powerSettingsCheck.DCSettingIndex -ne 1) { Write-Host "WN16-CC-000210 - $($powerSettingsCheck.DCSettingIndex)" }
	if ($powerSettingsCheck.ACSettingIndex -ne 1) { Write-Host "WN16-CC-000220 - $($powerSettingsCheck.ACSettingIndex)" }

	$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
	if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Host "WN16-CC-000240 - $($appCompatSettingsCheck.DisableInventory)" }
	 
	$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
	if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Host "WN16-CC-000250 - $($windowsExplorerSettingsCheck.NoAutoplayfornonVolume)" }
	if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -eq 1) { Write-Host "WN16-CC-000340 - $($windowsExplorerSettingsCheck.NoDataExecutionPrevention)" }
	if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -eq 1) { Write-Host "WN16-CC-000350 - $($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption)" }

	$windowsPoliciesExplorerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
	if ($windowsPoliciesExplorerCheck.NoAutorun -ne 1) { Write-Host "WN16-CC-000260 - $($windowsPoliciesExplorerCheck.NoAutorun)" }
	if ($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun -ne 255) { Write-Host "WN16-CC-000270 - $($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun)" }
	if ($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior -eq 1) { Write-Host "WN16-CC-000360 - $($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior)" }
	if ($windowsPoliciesExplorerCheck.NoPreviewPane -ne 1 -or $windowsPoliciesExplorerCheck.NoReadingPane -ne 1) { Write-Host "WN16-CC-000421 - $($windowsPoliciesExplorerCheck.NoPreviewPane) $($windowsPoliciesExplorerCheck.NoReadingPane)" }

	$credUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
	if ($credUICheck.EnumerateAdministrators -ne 0) { Write-Host "WN16-CC-000280 - $($credUICheck.EnumerateAdministrators)" }

	$dataCollectionCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
	if ($dataCollectionCheck.AllowTelemetry -notin @(0, 1, 3)) { Write-Host "WN16-CC-000290 - $($dataCollectionCheck.AllowTelemetry)" }

	$eventLogApplication = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
	if ($eventLogApplication.MaxSize -lt 32768) { Write-Host "WN16-CC-000300 - $($eventLogApplication.MaxSize)" }

	$eventLogSecurity = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
	if ($eventLogSecurity.MaxSize -lt 196608) { Write-Host "WN16-CC-000310 - $($eventLogSecurity.MaxSize)" }

	$eventLogSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
	if ($eventLogSystem.MaxSize -lt 32768) { Write-Host "WN16-CC-000320 - $($eventLogSystem.MaxSize)" }

	$ntTerminalServicesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
	if ($ntTerminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Host "WN16-CC-000370 - $($ntTerminalServicesCheck.DisablePasswordSaving)" }
	if ($ntTerminalServicesCheck.fDisableCdm -ne 1) { Write-Host "WN16-CC-000380 - $($ntTerminalServicesCheck.fDisableCdm)" }
	if ($ntTerminalServicesCheck.fPromptForPassword -ne 1) { Write-Host "WN16-CC-000390 - $($ntTerminalServicesCheck.fPromptForPassword)" }
	if ($ntTerminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Host "WN16-CC-000400 - $($ntTerminalServicesCheck.fEncryptRPCTraffic)" }
	if ($ntTerminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Host "WN16-CC-000410 - $($ntTerminalServicesCheck.MinEncryptionLevel)" }

	$internetExplorerFeeds = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
	if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Host "WN16-CC-000420 - $($internetExplorerFeeds.DisableEnclosureDownload)" }
	if ($internetExplorerFeeds.AllowBasicAuthInClear -eq 1) { Write-Host "WN16-CC-000430 - $($internetExplorerFeeds.AllowBasicAuthInClear)" }

	$windowsWindowsSearch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
	if ($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems -ne 0) { Write-Host "WN16-CC-000440 - $($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems)" }

	$windowsInstallerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
	if ($windowsInstallerCheck.EnableUserControl -ne 0) { Write-Host "WN16-CC-000450 - $($windowsInstallerCheck.EnableUserControl)" }
	if ($windowsInstallerCheck.AlwaysInstallElevated -ne 0) { Write-Host "WN16-CC-000460 - $($windowsInstallerCheck.AlwaysInstallElevated)" }
	if ($windowsInstallerCheck.SafeForScripting -eq 1) { Write-Host "WN16-CC-000470 - $($windowsInstallerCheck.SafeForScripting)" }

	$currentVersionSystemPolicies = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
	if ($currentVersionSystemPolicies.DisableAutomaticRestartSignOn -ne 1) { Write-Host "WN16-CC-000480 - $($currentVersionSystemPolicies.DisableAutomaticRestartSignOn)" }

	$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
	if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Host "WN16-CC-000490 - $($scriptBlockLogging.EnableScriptBlockLogging)" }

	$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
	if ($winrmClientCheck.AllowBasic -ne 0) { Write-Host "WN16-CC-000500 - $($winrmClientCheck.AllowBasic)" }
	if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN16-CC-000510 - $($winrmClientCheck.AllowUnencryptedTraffic)" }
	if ($winrmClientCheck.AllowDigest -ne 0) { Write-Host "WN16-CC-000520 - $($winrmClientCheck.AllowDigest)" }

	$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
	if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Host "WN16-CC-000530 - $($winrmServiceCheck.AllowBasic)" }
	if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN16-CC-000540 - $($winrmServiceCheck.AllowUnencryptedTraffic)" }
	if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Host "WN16-CC-000550 - $($winrmServiceCheck.DisableRunAs)" }

	$powershellTranscriptCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
	if ($powershellTranscriptCheck.EnableTranscripting -ne 1) { Write-Host "WN16-CC-000555 - $($powershellTranscriptCheck.EnableTranscripting)" }

	#Common Paths
	$windowsntWinLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
	$lsaSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$userLogonRestrictionsCheck = $policyContent | Select-String "TicketValidateClient" | Out-String
		if ($userLogonRestrictionsCheck.Contains("0") -eq $true) { Write-Host "WN16-DC-000020 - $($userLogonRestrictionsCheck)" }

		$maxServiceAgeCheck = $policyContent | Select-String "MaxServiceAge" | Out-String
		if ($maxServiceAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..600) { Write-Host "WN16-DC-000030 - $($maxServiceAgeCheck)" }

		$maxTicketAgeCheck = $policyContent | Select-String "MaxTicketAge" | Out-String
		if ($maxTicketAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..11) { Write-Host "WN16-DC-000040 - $($maxTicketAgeCheck)" }

		$maxRenewAgeCheck = $policyContent | Select-String "MaxRenewAge" | Out-String
		if ($maxRenewAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..7) { Write-Host "WN16-DC-000050 - $($maxRenewAgeCheck)" }

		$maxClockSkewCheck = $policyContent | Select-String "MaxClockSkew" | Out-String
		if ($maxClockSkewCheck -match '\d+' -and [int]($matches[0]) -notin 0..5) { Write-Host "WN16-DC-000060 - $($maxClockSkewCheck)" }

		$computerAccountManagementAudit = $auditPolicyAll | Select-String "Computer Account Management" | Out-String
		if ($computerAccountManagementAudit.Contains("Success") -eq $false) { Write-Host "WN16-DC-000230 - $computerAccountManagementAudit" }

		$directoryServiceAccessCheck = $auditPolicyAll | Select-String "Directory Service Access" | Out-String
		if ($directoryServiceAccessCheck.Contains("Success") -eq $false) { Write-Host "WN16-DC-000240 - $directoryServiceAccessCheck" }
		if ($directoryServiceAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN16-DC-000250 - $directoryServiceAccessCheck" }

		$directoryServiceChangesAudit = $auditPolicyAll | Select-String "Directory Service Changes" | Out-String
		if ($directoryServiceChangesAudit.Contains("Success") -eq $false) { Write-Host "WN16-DC-000260 - $directoryServiceChangesAudit" }
		
		$ntdsParameters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
		if ($ntdsParameters.LDAPServerIntegrity -ne 2) { Write-Host "WN16-DC-000320 - $($ntdsParameters.LDAPServerIntegrity)" }
		
		if ($netLogonParameters.RefusePasswordChange -ne 0) { Write-Host "WN16-DC-000330 - $($netLogonParameters.RefusePasswordChange)" }

		$machineAccountPrivilegeSID = ($policyContent | Select-String "SeMachineAccountPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($machineAccountPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN16-DC-000350 - $($machineAccountPrivilegeSID)" }

		$remoteInteractiveLogonRightSID = ($policyContent | Select-String "SeRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($remoteInteractiveLogonRightSID -notlike "*S-1-5-32-544") { Write-Host "WN16-DC-000360 - $($remoteInteractiveLogonRightSID)" }

		$denyNetworkLogonRightSID = $policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String
		if ($denyNetworkLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN16-DC-000370 - $($denyNetworkLogonRightSID)" }

		$denyBatchLogonRightSID = $policyContent | Select-String "SeDenyBatchLogonRight" | Out-String
		if ($denyBatchLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN16-DC-000380 - $($denyBatchLogonRightSID)" }

		$denyServiceLogonRightSID = $policyContent | Select-String "SeDenyServiceLogonRight" | Out-String
		if ($denyServiceLogonRightSID.Contains("*S-1") -eq $true) { Write-Host "WN16-DC-000390 - $($denyServiceLogonRightSID)" }

		$denyInteractiveLogonRightSID = $policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String
		if ($denyInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN16-DC-000400 - $($denyInteractiveLogonRightSID)" }

		$denyRemoteInteractiveLogonRightSID = $policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String
		if ($denyRemoteInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN16-DC-000410 - $($denyRemoteInteractiveLogonRightSID)" }

		$enableDelegationPrivilegeCheckSID = ($policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($enableDelegationPrivilegeCheckSID -notlike "*S-1-5-32-544") { Write-Host "WN16-DC-000420 - $($enableDelegationPrivilegeCheckSID)" }

		$krbtgtAccount = Get-ADUser krbtgt -Property PasswordLastSet
		$daysSincePasswordChange = ((Get-Date) - $krbtgtAccount.PasswordLastSet).Days
		if ($daysSincePasswordChange -gt 180) { Write-Host "WN16-DC-000430 - $($krbtgtAccount.PasswordLastSet)" }
		
	}

	$windowsntWinLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
	$lsaSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\

	#Member Server and Standalone Server Checks
	if ($csDomainRole -eq "MemberServer" -or $csDomainRole -eq "StandaloneServer") {
		if ($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy -ne 0) { Write-Host "WN16-MS-000020 - $($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy)" }
		if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Host "WN16-MS-000030 - $($windowsSystemChecks.EnumerateLocalUsers)" }

		$windowsntRPCCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
		if ($windowsntRPCCheck.RestrictRemoteClients -ne 1) { Write-Host "WN16-MS-000040 - $($windowsntRPCCheck.RestrictRemoteClients)" }

		if ($windowsntWinLogon.CachedLogonsCount -gt 4) { Write-Host "WN16-MS-000050 - $($windowsntWinLogon.CachedLogonsCount)" }

		if ($lsaSettings.RestrictRemoteSAM -ne "O:BAG:BAD:(A;;RC;;;BA)") { Write-Host "WN16-MS-000310 - $($lsaSettings.RestrictRemoteSAM)" }

		$vbsSecurityServicesRunning = $vbsDetailsCheck.SecurityServicesRunning | Out-String
		if ($vbsSecurityServicesRunning.Contains("1") -eq $false) { Write-Host "WN16-MS-000120 - $($vbsSecurityServicesRunning)" }
		
		$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-11*")
		$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] }
		if ($disallowedSIDs) { Write-Host "WN16-MS-000340 - $disallowedSIDs" }

		$enableDelegationPrivilegeCheck = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
		if ($enableDelegationPrivilegeCheck.Contains("*S-1") -eq $true) { Write-Host "WN16-MS-000420 - $($enableDelegationPrivilegeCheck)" }

		if ($CsDomainRole -ne "StandaloneServer") {
			
			$denyAccessToThisComputerSIDs = ($policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedDenyAccessToThisComputerSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
			$disallowedDenyAccessToThisComputerSIDs = $denyAccessToThisComputerSIDs | Where-Object { $_ -notlike $allowedDenyAccessToThisComputerSIDs[0] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[1] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[2] }
			if ($disallowedDenyAccessToThisComputerSIDs) { Write-Host "WN16-MS-000370 - $disallowedDenyAccessToThisComputerSIDs" }
		
			$allowedBatchLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
			$disallowedBatchLogonRightSIDs = $denyBatchLogonRightSIDs | Where-Object { $_ -notlike $allowedBatchLogonRightSIDs[0] -and $_ -notlike $allowedBatchLogonRightSIDs[1] -and $_ -notlike $allowedBatchLogonRightSIDs[2] }
			if ($disallowedBatchLogonRightSIDs) { Write-Host "WN16-MS-000380 - $disallowedBatchLogonRightSIDs" }
		
			$denyServiceLogonRightSIDS = ($policyContent | Select-String "SeDenyServiceLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedServiceLogonRightSIDS = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512")
			$disallowedServiceLogonRightSIDS = $denyServiceLogonRightSIDS | Where-Object { $_ -notlike $allowedServiceLogonRightSIDS[0] -and $_ -notlike $allowedServiceLogonRightSIDS[1] }
			if ($disallowedServiceLogonRightSIDS) { Write-Host "WN16-MS-000390 - $disallowedBatchLogonRightSIDs" }
			
			$denyInteractiveLogonRightSIDs = ($policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedInteractiveLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
			$disallowedInteractiveLogonRightSIDs = $denyInteractiveLogonRightSIDs | Where-Object { $_ -notlike $allowedInteractiveLogonRightSIDs[0] -and $_ -notlike $allowedInteractiveLogonRightSIDs[1] -and $_ -notlike $allowedInteractiveLogonRightSIDs[2] }
			if ($disallowedInteractiveLogonRightSIDs) { Write-Host "WN16-MS-000400 - $disallowedBatchLogonRightSIDs" }
			
			$denyLogOnThroughRemoteDesktopServicesSIDs = ($policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedDenyLogOnThroughRemoteDesktopServicesSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546", "*S-1-5-113")
			$disallowedDenyLogOnThroughRemoteDesktopServicesSIDs = $denyLogOnThroughRemoteDesktopServicesSIDs | Where-Object { $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[0] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[1] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[2] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[3] }
			if ($disallowedDenyLogOnThroughRemoteDesktopServicesSIDs) { Write-Host "WN16-MS-000410 - $disallowedDenyLogOnThroughRemoteDesktopServicesSIDs" }
		
		}
		
		if ($edge -ne $null) {
			
			$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ 2>$null
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
		}
		
		foreach ($possibleFirefoxUser in $validFirefoxUsers) {
			$firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
			if (Test-Path $firefoxPath) {
				$profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
				if ($profilePath) {
					$firefoxPreferences = Get-Content "$profilePath\prefs.js" 2>$null | Out-String
					$firefoxHandlers = Get-Content "$profilePath\handlers.json" 2>$null | Out-String
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
			   if ($firefoxPreferences.Contains('"extensions.update.enabled", false') -eq $false) {
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

		$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission 2>$null
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

		$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay 2>$null
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

		$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection 2>$null
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

		$disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers 2>$null
		if ($disabledFirefoxCiphers -ne $null) {
		   if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false") -and $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		   }
		}

		$firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging 2>$null
		if ($firefoxUserMessaging -ne $null) {
		   if ($firefoxUserMessaging.ExtensionRecommendations -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
			}
		}

		$firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage 2>$null
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
	}

	$disableBuiltInGuestAccountCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
	if ($disableBuiltInGuestAccountCheck.Contains("1") -eq $true) { Write-Host "WN16-SO-000010 - $($disableBuiltInGuestAccountCheck)" }

	if ($lsaSettings.LimitBlankPasswordUse -ne 1) { Write-Host "WN16-SO-000020 - $($lsaSettings.LimitBlankPasswordUse)" }

	$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
	if ($newAdminName.Contains("Administrator") -eq $true) { Write-Host "WN16-SO-000030 - $($newAdminName)" }

	$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
	if ($newGuestName -match '="Guest"') { Write-Host "WN16-SO-000040 - $($newGuestName)" }

	if ($lsaSettings.SCENoApplyLegacyAuditPolicy -ne 1) { Write-Host "WN16-SO-000050 - $($lsaSettings.SCENoApplyLegacyAuditPolicy)" }

	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
	if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Host "WN16-SO-000080 - $($netLogonParameters.RequireSignOrSeal)" }
	if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Host "WN16-SO-000090 - $($netLogonParameters.SealSecureChannel)" }
	if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Host "WN16-SO-000100 - $($netLogonParameters.SignSecureChannel)" }
	if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Host "WN16-SO-000110 - $($netLogonParameters.DisablePasswordChange)" }
	if ($netLogonParameters.MaximumPasswordAge -gt 30 -or $netLogonParameters.MaximumPasswordAge -eq 0) { Write-Host "WN16-SO-000120 - $($netLogonParameters.MaximumPasswordAge)" }
	if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Host "WN16-SO-000130 - $($netLogonParameters.RequireStrongKey)" }

	if ($currentVersionSystemPolicies.InactivityTimeoutSecs -notin 1..900) { Write-Host "WN16-SO-000140 - $($currentVersionSystemPolicies.InactivityTimeoutSecs)" }
	if ($currentVersionSystemPolicies.LegalNoticeText -eq $null) { Write-Host "WN16-SO-000150 - $($currentVersionSystemPolicies.LegalNoticeText)" }
	if ($currentVersionSystemPolicies.LegalNoticeCaption -eq $null) { Write-Host "WN16-SO-000160 - $($currentVersionSystemPolicies.LegalNoticeCaption)" }

	$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
	if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Host "WN16-SO-000190 - $($lanmanWorkstationParameters.RequireSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnableSecuritySignature -ne 1) { Write-Host "WN16-SO-000200 - $($lanmanWorkstationParameters.EnableSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Host "WN16-SO-000210 - $($lanmanWorkstationParameters.EnablePlainTextPassword)" }

	$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
	if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Host "WN16-SO-000230 - $($lanmanServerParameters.RequireSecuritySignature)" }
	if ($lanmanServerParameters.EnableSecuritySignature -ne 1) { Write-Host "WN16-SO-000240 - $($lanmanServerParameters.EnableSecuritySignature)" }

	$lsaAnonymousName = $policyContent | Select-String "LsaAnonymousNameLookup" | Out-String
	if ($lsaAnonymousName.Contains("1") -eq $true) { Write-Host "WN16-SO-000250 - $($lsaAnonymousName)" }

	if ($lsaSettings.RestrictAnonymousSAM -ne 1) { Write-Host "WN16-SO-000260 - $($lsaSettings.RestrictAnonymousSAM)" }
	if ($lsaSettings.RestrictAnonymous -ne 1) { Write-Host "WN16-SO-000270 - $($lsaSettings.RestrictAnonymous)" }
	if ($lsaSettings.EveryoneIncludesAnonymous -ne 0) { Write-Host "WN16-SO-000290 - $($lsaSettings.EveryoneIncludesAnonymous)" }

	if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Host "WN16-SO-000300 - $($lanmanServerParameters.RestrictNullSessAccess)" }

	if ($lsaSettings.UseMachineId -ne 1) { Write-Host "WN16-SO-000320 - $($lsaSettings.UseMachineId)" }

	$lsaMSV = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
	if ($lsaMSV.allownullsessionfallback -ne 0) { Write-Host "WN16-SO-000330 - $($lsaMSV.allownullsessionfallback)" }

	$lsaPKU2U = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
	if ($lsaPKU2U.AllowOnlineID -ne 0) { Write-Host "WN16-SO-000340 - $($lsaPKU2U.AllowOnlineID)" }

	$kerbParameters = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		if ($kerbParameters.SupportedEncryptionTypes -ne 2147483640) { Write-Host "WN16-SO-000350 - $($kerbParameters.SupportedEncryptionTypes)" }
	}

	if ($lsaSettings.NoLMHash -ne 1) { Write-Host "WN16-SO-000360 - $($lsaSettings.NoLMHash)" }
	if ($lsaSettings.LmCompatibilityLevel -ne 5) { Write-Host "WN16-SO-000380 - $($lsaSettings.LmCompatibilityLevel)" }

	$ldapServicesCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
	if ($ldapServicesCheck.LDAPClientIntegrity -ne 1) { Write-Host "WN16-SO-000390 - $($ldapServicesCheck.LDAPClientIntegrity)" }

	if ($lsaMSV.NTLMMinClientSec -ne 537395200) { Write-Host "WN16-SO-000400 - $($lsaMSV.NTLMMinClientSec)" }
	if ($lsaMSV.NtlmMinServerSec -ne 537395200) { Write-Host "WN16-SO-000410 - $($lsaMSV.NtlmMinServerSec)" }

	$microsoftCryptographyCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
	if ($microsoftCryptographyCheck.ForceKeyProtection -ne 2) { Write-Host "WN16-SO-000420 - $($microsoftCryptographyCheck.ForceKeyProtection)" }

	$lsaFIPSCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
	if ($lsaFIPSCheck.Enabled -ne 1) { Write-Host "WN16-SO-000430 - $($lsaFIPSCheck.Enabled)" }

	$registrySessionManagerCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
	if ($registrySessionManagerCheck.ProtectionMode -ne 1) { Write-Host "WN16-SO-000450 - $($registrySessionManagerCheck.ProtectionMode)" }

	if ($currentVersionSystemPolicies.FilterAdministratorToken -ne 1) { Write-Host "WN16-SO-000460 - $($currentVersionSystemPolicies.FilterAdministratorToken)" }
	if ($currentVersionSystemPolicies.EnableUIADesktopToggle -ne 0) { Write-Host "WN16-SO-000470 - $($currentVersionSystemPolicies.EnableUIADesktopToggle)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin -notin @(1, 2)) { Write-Host "WN16-SO-000480 - $($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorUser -ne 0) { Write-Host "WN16-SO-000490 - $($currentVersionSystemPolicies.ConsentPromptBehaviorUser)" }
	if ($currentVersionSystemPolicies.EnableInstallerDetection -ne 1) { Write-Host "WN16-SO-000500 - $($currentVersionSystemPolicies.EnableInstallerDetection)" }
	if ($currentVersionSystemPolicies.EnableSecureUIAPaths -ne 1) { Write-Host "WN16-SO-000510 - $($currentVersionSystemPolicies.EnableSecureUIAPaths)" }
	if ($currentVersionSystemPolicies.EnableLUA -ne 1) { Write-Host "WN16-SO-000520 - $($currentVersionSystemPolicies.EnableLUA)" }
	if ($currentVersionSystemPolicies.EnableVirtualization -ne 1) { Write-Host "WN16-SO-000530 - $($currentVersionSystemPolicies.EnableVirtualization)" }

	$attachmentPoliciesCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
	if ($attachmentPoliciesCheck.SaveZoneInformation -eq 1) { Write-Host "WN16-UC-000030 - $($attachmentPoliciesCheck.SaveZoneInformation)" }

	$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
	if ($accessCredManagerCheck.Contains("*S-1") -eq $true) { Write-Host "WN16-UR-000010 - $($accessCredManagerCheck)" }

	$actAsPartofOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
	if ($actAsPartofOSCheck.Contains("*S-1") -eq $true) { Write-Host "WN16-UR-000030 - $($actAsPartofOSCheck)" }

	$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedLogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
	$disallowedLogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedLogonSIDs[0] -and $_ -notlike $allowedLogonSIDs[1] }
	if ($disallowedLogonSIDs.Count -gt 0) { Write-Host "WN16-UR-000050 - $($disallowedLogonSIDs)" }

	$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedBackupSIDs = @("*S-1-5-32-544")
	$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
	if ($disallowedBackupSIDs.Count -gt 0) { Write-Host "WN16-UR-000070 - $($disallowedBackupSIDs)" }

	$createPagefileSID = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createPagefileSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000080 - $($createPagefileSID)" }

	$createTokenObjectsSID = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
	if ($createTokenObjectsSID.Contains("*S-1") -eq $true) { Write-Host "WN16-UR-000090 - $($createTokenObjectsSID)" }

	$createGlobalPrivilegeSID = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedCreateGlobalSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedCreateGlobalSIDs = $createGlobalPrivilegeSID | Where-Object { $_ -notlike $allowedCreateGlobalSIDs[0] -and $_ -notlike $allowedCreateGlobalSIDs[1] -and $_ -notlike $allowedCreateGlobalSIDs[2] -and $_ -notlike $allowedCreateGlobalSIDs[3] }
	if ($disallowedCreateGlobalSIDs.Count -gt 0) { Write-Host "WN16-UR-000100 - $($disallowedCreateGlobalSIDs)" }

	$createPermanentSharedObjectSID = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
	if ($createPermanentSharedObjectSID.Contains("*S-1") -eq $true) { Write-Host "WN16-UR-000110 - $($createPermanentSharedObjectSID)" }

	$createSymbolicLinkSID = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createSymbolicLinkSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000120 - $($createSymbolicLinkSID)" }

	$debugPrivilegeSID = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($debugPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000130 - $($debugPrivilegeSID)" }

	$forceShutdownFromRemoteSystemSID = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($forceShutdownFromRemoteSystemSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000200 - $($forceShutdownFromRemoteSystemSID)" }

	$auditPrivilegeSID = ($policyContent | Select-String "SeAuditPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedAuditSIDs = @("*S-1-5-19", "*S-1-5-20")
	$disallowedAuditSIDs = $auditPrivilegeSID | Where-Object { $_ -notlike $allowedAuditSIDs[0] -and $_ -notlike $allowedAuditSIDs[1] }
	if ($disallowedAuditSIDs.Count -gt 0) { Write-Host "WN16-UR-000210 - $($disallowedAuditSIDs)" }

	$impersonateAClientAfterAuthenticationSID = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedImpersonateSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedImpersonateSIDs = $impersonateAClientAfterAuthenticationSID | Where-Object { $_ -notlike $allowedImpersonateSIDs[0] -and $_ -notlike $allowedImpersonateSIDs[1] -and $_ -notlike $allowedImpersonateSIDs[2] -and $_ -notlike $allowedImpersonateSIDs[3] }
	if ($disallowedImpersonateSIDs.Count -gt 0) { Write-Host "WN16-UR-000220 - $($disallowedImpersonateSIDs)" }

	$increaseBasePrioritySID = ($policyContent | Select-String "SeIncreaseBasePriorityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($increaseBasePrioritySID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000230 - $($increaseBasePrioritySID)" }

	$loadDriverSID = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($loadDriverSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000240 - $($loadDriverSID)" }

	$lockMemorySID = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
	if ($lockMemorySID.Contains("*S-1") -eq $true) { Write-Host "WN16-UR-000250 - $($lockMemorySID)" }

	$manageAuditingAndSecurityLogSID = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($manageAuditingAndSecurityLogSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000260 - $($manageAuditingAndSecurityLogSID)" }

	$modifyFirmwareEnvironmentSID = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($modifyFirmwareEnvironmentSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000270 - $($modifyFirmwareEnvironmentSID)" }

	$performVolumeMaintenanceSID = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($performVolumeMaintenanceSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000280 - $($performVolumeMaintenanceSID)" }

	$profileSingleProcessSID = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($profileSingleProcessSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000290 - $($profileSingleProcessSID)" }

	$restorePrivilegeSID = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($restorePrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000300 - $($restorePrivilegeSID)" }

	$takeOwnershipSID = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($takeOwnershipSID -notlike "*S-1-5-32-544") { Write-Host "WN16-UR-000310 - $($takeOwnershipSID)" }
	
} elseif ($wnVers.Contains("2019") -or $computerInfo2.Contains("2019") -or $computerInfo3.Contains("2019")) {
	
	#Windows Server 2019 MS/DC
	$tpm = Get-Tpm 2>$null
	$tpmPresent = $tpm.TpmPresent
	$tpmEnabled = $tpm.TpmEnabled

	$adminAccount = Get-LocalUser -Name "Administrator"
	$currentDate = Get-Date
	$passwordLastSet = $adminAccount.PasswordLastSet
	$daysSincePasswordSet = ($currentDate - $passwordLastSet).Days
	if ($daysSincePasswordSet -gt 60) { Write-Host "WN19-00-000020 - $daysSincePasswordSet" }

	$shares = Get-WmiObject -Class Win32_Share
	$shareNames = $shares.Name
	$allowedShares = @("C$", "ADMIN$", "IPC$", "print$")
	if ($shareNames | Where-Object { $_ -notin $allowedShares }) { Write-Host "WN19-00-000030 - $($shareNames | Where-Object { $_ -notin $allowedShares })" }

	$appLocker = Get-AppLockerPolicy -Effective -Xml
	if($appLocker.Contains('Type="Appx"') -eq $false) { Write-Host "WN19-00-000080" }

	$csDomainRole = $computerInfo.CsDomainRole
	if($csDomainRole -ne "StandaloneServer") {
		if ($tpmPresent -eq $false -or $tpmEnabled -eq $false) { Write-Host "WN19-00-000090 - $tpmPresent $tpmEnabled" }
	}

	$windowsOSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
	if($windowsOSVersion -lt "17763") { Write-Host "WN19-00-000100 - $windowsOSVersion" }

	$allWindowsServices = Get-Service
	$trellix = $allWindowsServices | where {$_.DisplayName -like "*Trellix*"} | Select Status,DisplayName | Out-String
	$symantec = $allWindowsServices | where {$_.DisplayName -like "*Symantec*"} | Select Status,DisplayName | Out-String
	$defender = $allWindowsServices | where {$_.DisplayName -like "*Defender*"} | Select Status,DisplayName | Out-String
	if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN19-00-000110" }

	$ntfs = Get-Volume
	foreach ($volume in $ntfs) {
		if ($volume.FileSystemType -ne "NTFS" -and $volume.DriveType -eq "Fixed") {
			Write-Host "WN19-00-000130 - $($volume.DriveLetter) = $($volume.FileSystemType)"
			break
		}
	}

	$subcategoryAuditing = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
	if ($subcategoryAuditing.everyoneincludesanonymous -ne 0) { 
		Write-Host "WN19-00-000140, WN19-00-000150, WN19-00-000160 - $($subcategoryAuditing.everyoneincludesanonymous)"
	}

	$hklmSoftwareACL = Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
	$softwareIsInherited = $hklmSoftwareACL.IsInherited | Out-String
	$hklmSystemACL = Get-Acl -Path HKLM:SYSTEM | % { $_.access }
	$systemIsInherited = $hklmSystemACL.IsInherited | Out-String
	if ($softwareIsInherited.Contains("True") -or $systemIsInherited.Contains("True")) { Write-Host "WN19-00-000170 - $softwareIsInherited $systemIsInherited" }

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$inactiveAccounts = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object {$_.Enabled -eq $true}
		if ($inactiveAccounts) { Write-Host "WN19-00-000190 - $($inactiveAccounts.Name)" }
	} else {
		([ADSI] ('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
			$user = ([ADSI]$_.Path)
			$lastLogin = $user.Properties.LastLogin.Value
			$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
			if ($lastLogin -eq $null) {$lastLogin = 'Never'}
			if ($enabled -eq $true -and $user.Name -ne 'no access') { Write-Host "WN19-00-000190 - $($user.Name) $lastLogin $enabled"}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$noPasswordUsers = Get-ADUser -Filter * -Properties Passwordnotrequired | Where-Object {$_.Enabled -eq $true -and $_.Passwordnotrequired -eq $true} | Select-Object -First 1
		if ($noPasswordUsers) {
			Write-Host "WN19-00-000200 - $($noPasswordUsers.Name)"
		}
	} else {
		$noPasswordAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True"
		foreach ($account in $noPasswordAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN19-00-000200 - $($account.Name)"
				break
			}
		}
	}

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$neverExpiringAccounts = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1
		if ($neverExpiringAccounts) {
			Write-Host "WN19-00-000210 - $($neverExpiringAccounts.Name)"
		}
	} else {
		$neverExpiringAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True"
		foreach ($account in $neverExpiringAccounts) {
			if ($account.Disabled -eq $false) {
				Write-Host "WN19-00-000210 - $($account.Name)"
				break
			}
		}
	}

	$job = Start-Job -ScriptBlock {
		Get-ChildItem -Path C:\ -Include *.p12,*.pfx -File -Recurse 2>$null | Select-Object -First 1
	}
	$lingeringCertificateFiles = if (Wait-Job $job -Timeout 60) {
		Receive-Job $job
	} else {
		Stop-Job $job
		$null
	}
	Remove-Job $job -Force
	if ($lingeringCertificateFiles -ne $null) {
		Write-Host "WN19-00-000240 - $($lingeringCertificateFiles)"
	}

	if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN19-00-000290" }

	$faxInstallCheck = Get-WindowsFeature | Where Name -eq Fax
	if ($faxInstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000320" }

	$pnrpInstallCheck = Get-WindowsFeature | Where Name -eq PNRP
	if ($pnrpInstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000340" }

	$simpletcpipInstallCheck = Get-WindowsFeature | Where Name -eq Simple-TCPIP
	if ($simpletcpipInstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000350" }

	$telnetClientInstallCheck = Get-WindowsFeature | Where Name -eq Telnet-Client
	if ($telnetClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000360" }

	$tftpClientInstallCheck = Get-WindowsFeature | Where Name -eq TFTP-Client
	if ($tftpClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000370" }

	$smbv1InstallCheck = Get-WindowsFeature -Name FS-SMB1
	if ($smbv1InstallCheck.InstallState -eq "Installed") { 
		$smb1LanmanServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").SMB1
		if ($smb1LanmanServer -ne 0) {
			Write-Host "WN19-00-000380 $($smbv1InstallCheck.InstallState) $($smb1LanmanServer)" 
		}
	}

	$powershell2InstallCheck = Get-WindowsFeature | Where Name -eq PowerShell-V2
	if ($powershell2InstallCheck.InstallState -eq "Installed") { Write-Host "WN19-00-000410" }

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpAnonymousAuth = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\"
		if ($ftpAnonymousAuth.Value -eq $true) {
			Write-Host "WN19-00-000420 $($ftpAnonymousAuth.Value)"
		}
	}

	$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
	if ($ftpInstallCheck.InstallState -eq "Installed") {
		$ftpSites = Get-WebConfiguration "/system.applicationHost/sites/site" -PSPath "IIS:\"
		foreach ($site in $ftpSites) {
			$ftpRoot = $site.ftpServer.virtualDirectories.physicalPath
			if ($ftpRoot -like "C:*") {
				Write-Host "WN19-00-000430 - $ftpRoot"
				break
			}
		}
	}

	$uefiStatus = $computerInfo.BiosFirmwareType
	if ($uefiStatus -ne "Uefi") { Write-Host "WN19-00-000460 - $uefiStatus" }

	$bootState = Confirm-SecureBootUEFI
	if ($bootState -eq $false) { Write-Host "WN19-00-000470 - $bootState" }

	$exportPath = "$env:TEMP\secpol.inf"
	secedit /export /cfg $exportPath
	$policyContent = Get-Content -Path $exportPath

	$lockoutDurationCheck = $policyContent | Select-String "LockoutDuration" | Out-String
	if ($lockoutDurationCheck.Contains('900') -eq $false) { Write-Host "WN19-AC-000010 - $lockoutDurationCheck" }

	$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
	if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Host "WN19-AC-000020 - $lockoutBadCountCheck" }

	$lockoutCounterResetCheck = $policyContent | Select-String "ResetLockoutCount" | Out-String
	if ($lockoutCounterResetCheck.Contains('900') -eq $false) { Write-Host "WN19-AC-000030 - $lockoutCounterResetCheck" }

	$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
	if ($passwordHistorySize.Contains('24') -eq $false) { Write-Host "WN19-AC-000040 - $passwordHistorySize" }

	$maxPasswordAgeCheck = $policyContent | Select-String "MaximumPasswordAge" | Out-String
	if ($maxPasswordAgeCheck.Contains('60') -eq $false) { Write-Host "WN19-AC-000050 - $maxPasswordAgeCheck" }

	$minPasswordAgeCheck = $policyContent | Select-String "MinimumPasswordAge" | Out-String
	if ($minPasswordAgeCheck.Contains('1') -eq $false) { Write-Host "WN19-AC-000060 - $minPasswordAgeCheck" }

	$minPasswordLengthCheck = $policyContent | Select-String "MinimumPasswordLength" | Out-String
	if ($minPasswordLengthCheck.Contains('10') -eq $false) { Write-Host "WN19-AC-000070 - $minPasswordLengthCheck" }

	$passwordComplexityCheck = $policyContent | Select-String "PasswordComplexity" | Out-String
	if ($passwordComplexityCheck.Contains('1') -eq $false) { Write-Host "WN19-AC-000080 - $passwordComplexityCheck" }

	$reversiblePasswordEncryptionCheck = $policyContent | Select-String "ClearTextPassword" | Out-String
	if ($reversiblePasswordEncryptionCheck.Contains('1') -eq $True) { Write-Host "WN19-AC-000090 - $reversiblePasswordEncryptionCheck" }

	$applicationEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Application.evtx 2>$null).Access).FileSystemRights).Count
	if ($applicationEventLogACL -ne 3) { Write-Host "WN19-AU-000030 - $applicationEventLogACL" }

	$securityEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Security.evtx 2>$null).Access).FileSystemRights).Count
	if ($securityEventLogACL -ne 3) { Write-Host "WN19-AU-000040 - $securityEventLogACL" }

	$systemEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\System.evtx 2>$null).Access).FileSystemRights).Count
	if ($systemEventLogACL -ne 3) { Write-Host "WN19-AU-000050 - $systemEventLogACL" }

	$eventvwrPath = "$env:SystemRoot\System32\eventvwr.exe"
	$eventvwrACL = (Get-Acl $eventvwrPath 2>$null).Access
	$fullControlCount = ($eventvwrACL | Where-Object {$_.FileSystemRights -eq "Full Control"}).Count
	if ($fullControlCount -gt 1) { Write-Host "WN19-AU-000060 - $fullControlCount" }

	$auditPolicyAll = AuditPol /get /category:*
	$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
	if ($credentialValidationCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000070 - $credentialValidationCheck" }
	if ($credentialValidationCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000080 - $credentialValidationCheck" }

	$otherAccountManagementCheck = $auditPolicyAll | Select-String "Other Account Management Events" | Out-String
	if ($otherAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000090 - $otherAccountManagementCheck" }

	$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
	if ($securityGroupManagementCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000100 - $securityGroupManagementCheck" }

	$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
	if ($userAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000110 - $userAccountManagementCheck" }
	if ($userAccountManagementCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000120 - $userAccountManagementCheck" }

	$pnpEventsCheck = $auditPolicyAll | Select-String "Plug and Play Events" | Out-String
	if ($pnpEventsCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000130 - $pnpEventsCheck" }

	$processTrackingCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
	if ($processTrackingCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000140 - $processTrackingCheck" }

	$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
	if ($accountLockoutCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000160 - $accountLockoutCheck" }

	$groupMembershipCheck = $auditPolicyAll | Select-String "Group Membership" | Out-String
	if ($groupMembershipCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000170 - $groupMembershipCheck" }

	$logoffEventsCheck = $auditPolicyAll | Select-String "(?<!/)\bLogoff\b" | Out-String
	if ($logoffEventsCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000180 - $logoffEventsCheck" }

	$logonEventsCheck = $auditPolicyAll | Select-String "^  Logon\s{2,}" | Out-String
	if ($logonEventsCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000190 - $logonEventsCheck" }
	if ($logonEventsCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000200 - $logonEventsCheck" }

	$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
	if ($specialLogonCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000210 - $specialLogonCheck" }

	$otherObjectAccessCheck = $auditPolicyAll | Select-String "Other Object Access Events" | Out-String
	if ($otherObjectAccessCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000220 - $otherObjectAccessCheck" }
	if ($otherObjectAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000230 - $otherObjectAccessCheck" }

	$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
	if ($removableStorageCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000240 - $removableStorageCheck" }
	if ($removableStorageCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000250 - $removableStorageCheck" }

	$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
	if ($auditPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000260 - $auditPolicyChangeCheck" }
	if ($auditPolicyChangeCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000270 - $auditPolicyChangeCheck" }

	$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
	if ($authenticationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000280 - $authenticationPolicyChangeCheck" }

	$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
	if ($authorizationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000290 - $authorizationPolicyChangeCheck" }

	$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
	if ($sensitivePrivilegeUseCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000300 - $sensitivePrivilegeUseCheck" }
	if ($sensitivePrivilegeUseCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000310 - $sensitivePrivilegeUseCheck" }

	$ipSecDriverCheck = $auditPolicyAll | Select-String "IPsec Driver" | Out-String
	if ($ipSecDriverCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000320 - $ipSecDriverCheck" }
	if ($ipSecDriverCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000330 - $ipSecDriverCheck" }

	$otherSystemEventCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
	if ($otherSystemEventCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000340 - $otherSystemEventCheck" }
	if ($otherSystemEventCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000350 - $otherSystemEventCheck" }

	$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
	if ($securityStateChangeCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000360 - $securityStateChangeCheck" }

	$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
	if ($securitySystemExtensionCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000370 - $securitySystemExtensionCheck" }

	$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
	if ($systemIntegrityCheck.Contains("Success") -eq $false) { Write-Host "WN19-AU-000380 - $systemIntegrityCheck" }
	if ($systemIntegrityCheck.Contains("Failure") -eq $false) { Write-Host "WN19-AU-000390 - $systemIntegrityCheck" }

	$lockScreenAccess = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
	if ($lockScreenAccess.NoLockScreenSlideshow -ne 1) { Write-Host "WN19-CC-000010 - $($lockScreenAccess.NoLockScreenSlideshow)" }

	$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\
	if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Host "WN19-CC-000020 - $($wDigestInfo.UseLogonCredential)" }

	$tcpip6Parameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
	if ($tcpip6Parameters.DisableIPSourceRouting -ne 2) { Write-Host "WN19-CC-000030 - $($tcpip6Parameters.DisableIPSourceRouting)" }

	$tcpipParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
	if ($tcpipParameters.DisableIPSourceRouting -ne 2) { Write-Host "WN19-CC-000040 - $($tcpipParameters.DisableIPSourceRouting)" }

	if ($tcpipParameters.EnableICMPRedirect -ne 0) { Write-Host "WN19-CC-000050 - $($tcpipParameters.EnableICMPRedirect)" }

	$netbtParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
	if ($netbtParameters.NoNameReleaseOnDemand -ne 1) { Write-Host "WN19-CC-000060 - $($netbtParameters.NoNameReleaseOnDemand)" }

	$lanmanWorkstationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
	if ($lanmanWorkstationSettings.AllowInsecureGuestAuth -ne 0) { Write-Host "WN19-CC-000070 - $($lanmanWorkstationSettings.AllowInsecureGuestAuth)" }

	$networkProviderHardenedPaths = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
	if ((($networkProviderHardenedPaths."\\*\SYSVOL" -ne "RequireMutualAuthentication=1, RequireIntegrity=1") -and ($networkProviderHardenedPaths."\\*\SYSVOL" -ne "RequireMutualAuthentication=1,RequireIntegrity=1")) -or ($networkProviderHardenedPaths."\\*\NETLOGON" -ne "RequireMutualAuthentication=1, RequireIntegrity=1") -and ($networkProviderHardenedPaths."\\*\NETLOGON" -ne "RequireMutualAuthentication=1,RequireIntegrity=1")) { Write-Host "WN19-CC-000080 - $($networkProviderHardenedPaths."\\*\SYSVOL") $($networkProviderHardenedPaths."\\*\NETLOGON")" }

	$systemAuditSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
	if ($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Host "WN19-CC-000090 - $($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled)" }

	$credentialsDelegationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
	if ($credentialsDelegationSettings.AllowProtectedCreds -ne 1) { Write-Host "WN19-CC-000100 - $($credentialsDelegationSettings.AllowProtectedCreds)" }

	$vbsDetailsCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard\
	$vbsRequiredSecurityProperties = $vbsDetailsCheck.RequiredSecurityProperties | Out-String
	if ($vbsRequiredSecurityProperties.Contains("2") -eq $false -or $vbsDetailsCheck.VirtualizationBasedSecurityStatus -ne 2) { Write-Host "WN19-CC-000110 - $($vbsDetailsCheck.VirtualizationBasedSecurityStatus)" }

	$earlyLaunchCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
	if ($earlyLaunchCheck.DriverLoadPolicy -eq 7) { Write-Host "WN19-CC-000130 - $($earlyLaunchCheck.DriverLoadPolicy)" }

	$gpoChangesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
	if ($gpoChangesCheck.NoGPOListChanges -ne 0) { Write-Host "WN19-CC-000140 - $($gpoChangesCheck.NoGPOListChanges)" }

	$windowsNTPrintersCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
	if ($windowsNTPrintersCheck.DisableWebPnPDownload -ne 1) { Write-Host "WN19-CC-000150 - $($windowsNTPrintersCheck.DisableWebPnPDownload)" }
	if ($windowsNTPrintersCheck.DisableHTTPPrinting -ne 1) { Write-Host "WN19-CC-000160 - $($windowsNTPrintersCheck.DisableHTTPPrinting)" }

	$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
	if ($windowsSystemChecks.DontDisplayNetworkSelectionUI -ne 1) { Write-Host "WN19-CC-000170 - $($windowsSystemChecks.DontDisplayNetworkSelectionUI)" }
	if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Host "WN19-CC-000300 - $($windowsSystemChecks.EnableSmartScreen)" }

	$powerSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
	if ($powerSettingsCheck.DCSettingIndex -ne 1) { Write-Host "WN19-CC-000180 - $($powerSettingsCheck.DCSettingIndex)" }
	if ($powerSettingsCheck.ACSettingIndex -ne 1) { Write-Host "WN19-CC-000190 - $($powerSettingsCheck.ACSettingIndex)" }

	$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
	if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Host "WN19-CC-000200 - $($appCompatSettingsCheck.DisableInventory)" }
	 
	$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
	if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Host "WN19-CC-000210 - $($windowsExplorerSettingsCheck.NoAutoplayfornonVolume)" }
	if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -eq 1) { Write-Host "WN19-CC-000310 - $($windowsExplorerSettingsCheck.NoDataExecutionPrevention)" }
	if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -eq 1) { Write-Host "WN19-CC-000320 - $($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption)" }

	$windowsExplorerSettings2Check = Get-ItemProperty -Path \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
	if ($windowsExplorerSettings2Check.NoAutorun -ne 1) { Write-Host "WN19-CC-000220 - $($windowsExplorerSettingsCheck.NoAutorun)" }

	$windowsPoliciesExplorerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
	if ($windowsPoliciesExplorerCheck.NoAutorun -ne 1) { Write-Host "WN19-CC-000220 - $($windowsPoliciesExplorerCheck.NoAutorun)" }
	if ($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun -ne 255) { Write-Host "WN19-CC-000230 - $($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun)" }
	if ($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior -eq 1) { Write-Host "WN19-CC-000330 - $($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior)" }

	$credUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
	if ($credUICheck.EnumerateAdministrators -ne 0) { Write-Host "WN19-CC-000240 - $($credUICheck.EnumerateAdministrators)" }

	$dataCollectionCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
	if ($dataCollectionCheck.AllowTelemetry -notin @(0, 1, 3)) { Write-Host "WN19-CC-000250 - $($dataCollectionCheck.AllowTelemetry)" }

	$deliveryOptimizationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
	if ($deliveryOptimizationSettings.DODownloadMode -eq 3) { Write-Host "WN19-CC-000260 - $($deliveryOptimizationSettings.DODownloadMode)" }

	$eventLogApplication = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
	if ($eventLogApplication.MaxSize -lt 32768) { Write-Host "WN19-CC-000270 - $($eventLogApplication.MaxSize)" }

	$eventLogSecurity = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
	if ($eventLogSecurity.MaxSize -lt 196608) { Write-Host "WN19-CC-000280 - $($eventLogSecurity.MaxSize)" }

	$eventLogSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
	if ($eventLogSystem.MaxSize -lt 32768) { Write-Host "WN19-CC-000290 - $($eventLogSystem.MaxSize)" }

	$ntTerminalServicesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
	if ($ntTerminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Host "WN19-CC-000340 - $($ntTerminalServicesCheck.DisablePasswordSaving)" }
	if ($ntTerminalServicesCheck.fDisableCdm -ne 1) { Write-Host "WN19-CC-000350 - $($ntTerminalServicesCheck.fDisableCdm)" }
	if ($ntTerminalServicesCheck.fPromptForPassword -ne 1) { Write-Host "WN19-CC-000360 - $($ntTerminalServicesCheck.fPromptForPassword)" }
	if ($ntTerminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Host "WN19-CC-000370 - $($ntTerminalServicesCheck.fEncryptRPCTraffic)" }
	if ($ntTerminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Host "WN19-CC-000380 - $($ntTerminalServicesCheck.MinEncryptionLevel)" }

	$internetExplorerFeeds = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
	if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Host "WN19-CC-000390 - $($internetExplorerFeeds.DisableEnclosureDownload)" }
	if ($internetExplorerFeeds.AllowBasicAuthInClear -eq 1) { Write-Host "WN19-CC-000400 - $($internetExplorerFeeds.AllowBasicAuthInClear)" }

	$windowsWindowsSearch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
	if ($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems -ne 0) { Write-Host "WN19-CC-000410 - $($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems)" }

	$windowsInstallerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
	if ($windowsInstallerCheck.EnableUserControl -ne 0) { Write-Host "WN19-CC-000420 - $($windowsInstallerCheck.EnableUserControl)" }
	if ($windowsInstallerCheck.AlwaysInstallElevated -ne 0) { Write-Host "WN19-CC-000430 - $($windowsInstallerCheck.AlwaysInstallElevated)" }
	if ($windowsInstallerCheck.SafeForScripting -eq 1) { Write-Host "WN19-CC-000440 - $($windowsInstallerCheck.SafeForScripting)" }

	$currentVersionSystemPolicies = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
	if ($currentVersionSystemPolicies.DisableAutomaticRestartSignOn -ne 1) { Write-Host "WN19-CC-000450 - $($currentVersionSystemPolicies.DisableAutomaticRestartSignOn)" }

	$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
	if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Host "WN19-CC-000460 - $($scriptBlockLogging.EnableScriptBlockLogging)" }

	$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
	if ($winrmClientCheck.AllowBasic -ne 0) { Write-Host "WN19-CC-000470 - $($winrmClientCheck.AllowBasic)" }
	if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN19-CC-000480 - $($winrmClientCheck.AllowUnencryptedTraffic)" }
	if ($winrmClientCheck.AllowDigest -ne 0) { Write-Host "WN19-CC-000490 - $($winrmClientCheck.AllowDigest)" }

	$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
	if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Host "WN19-CC-000500 - $($winrmServiceCheck.AllowBasic)" }
	if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN19-CC-000510 - $($winrmServiceCheck.AllowUnencryptedTraffic)" }
	if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Host "WN19-CC-000520 - $($winrmServiceCheck.DisableRunAs)" }

	$powershellTranscriptCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
	if ($powershellTranscriptCheck.EnableTranscripting -ne 1) { Write-Host "WN19-CC-000530 - $($powershellTranscriptCheck.EnableTranscripting)" }

	#Common Paths
	$windowsntWinLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
	$lsaSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		$userLogonRestrictionsCheck = $policyContent | Select-String "TicketValidateClient" | Out-String
		if ($userLogonRestrictionsCheck.Contains("0") -eq $true) { Write-Host "WN19-DC-000020 - $($userLogonRestrictionsCheck)" }

		$maxServiceAgeCheck = $policyContent | Select-String "MaxServiceAge" | Out-String
		if ($maxServiceAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..600) { Write-Host "WN19-DC-000030 - $($maxServiceAgeCheck)" }

		$maxTicketAgeCheck = $policyContent | Select-String "MaxTicketAge" | Out-String
		if ($maxTicketAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..11) { Write-Host "WN19-DC-000040 - $($maxTicketAgeCheck)" }

		$maxRenewAgeCheck = $policyContent | Select-String "MaxRenewAge" | Out-String
		if ($maxRenewAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..7) { Write-Host "WN19-DC-000050 - $($maxRenewAgeCheck)" }

		$maxClockSkewCheck = $policyContent | Select-String "MaxClockSkew" | Out-String
		if ($maxClockSkewCheck -match '\d+' -and [int]($matches[0]) -notin 0..5) { Write-Host "WN19-DC-000060 - $($maxClockSkewCheck)" }

		$computerAccountManagementAudit = $auditPolicyAll | Select-String "Computer Account Management" | Out-String
		if ($computerAccountManagementAudit.Contains("Success") -eq $false) { Write-Host "WN19-DC-000230 - $computerAccountManagementAudit" }

		$directoryServiceAccessCheck = $auditPolicyAll | Select-String "Directory Service Access" | Out-String
		if ($directoryServiceAccessCheck.Contains("Success") -eq $false) { Write-Host "WN19-DC-000240 - $directoryServiceAccessCheck" }
		if ($directoryServiceAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN19-DC-000250 - $directoryServiceAccessCheck" }

		$directoryServiceChangesAudit = $auditPolicyAll | Select-String "Directory Service Changes" | Out-String
		if ($directoryServiceChangesAudit.Contains("Success") -eq $false) { Write-Host "WN19-DC-000260 - $directoryServiceChangesAudit" }
		
		$ntdsParameters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
		if ($ntdsParameters.LDAPServerIntegrity -ne 2) { Write-Host "WN19-DC-000320 - $($ntdsParameters.LDAPServerIntegrity)" }
		
		if ($netLogonParameters.RefusePasswordChange -ne 0) { Write-Host "WN19-DC-000330 - $($netLogonParameters.RefusePasswordChange)" }
		
		$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-11*","*S-1-5-9*")
		$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] -and $_ -notlike $allowedSIDs[2] }
		if ($disallowedSIDs) { Write-Host "WN19-DC-000340 - $disallowedSIDs" }

		$machineAccountPrivilegeSID = ($policyContent | Select-String "SeMachineAccountPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($machineAccountPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN19-DC-000350 - $($machineAccountPrivilegeSID)" }

		$remoteInteractiveLogonRightSID = ($policyContent | Select-String "SeRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($remoteInteractiveLogonRightSID -notlike "*S-1-5-32-544") { Write-Host "WN19-DC-000360 - $($remoteInteractiveLogonRightSID)" }

		$denyNetworkLogonRightSID = $policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String
		if ($denyNetworkLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN19-DC-000370 - $($denyNetworkLogonRightSID)" }

		$denyBatchLogonRightSID = $policyContent | Select-String "SeDenyBatchLogonRight" | Out-String
		if ($denyBatchLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN19-DC-000380 - $($denyBatchLogonRightSID)" }

		$denyServiceLogonRightSID = $policyContent | Select-String "SeDenyServiceLogonRight" | Out-String
		if ($denyServiceLogonRightSID.Contains("*S-1") -eq $true) { Write-Host "WN19-DC-000390 - $($denyServiceLogonRightSID)" }

		$denyInteractiveLogonRightSID = $policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String
		if ($denyInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN19-DC-000400 - $($denyInteractiveLogonRightSID)" }

		$denyRemoteInteractiveLogonRightSID = $policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String
		if ($denyRemoteInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN19-DC-000410 - $($denyRemoteInteractiveLogonRightSID)" }

		$enableDelegationPrivilegeCheckSID = ($policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($enableDelegationPrivilegeCheckSID -notlike "*S-1-5-32-544") { Write-Host "WN19-DC-000420 - $($enableDelegationPrivilegeCheckSID)" }

		$krbtgtAccount = Get-ADUser krbtgt -Property PasswordLastSet
		$daysSincePasswordChange = ((Get-Date) - $krbtgtAccount.PasswordLastSet).Days
		if ($daysSincePasswordChange -gt 180) { Write-Host "WN19-DC-000430 - $($krbtgtAccount.PasswordLastSet)" }
	}

	#Member Server and Standalone Server Checks
	if ($csDomainRole -eq "MemberServer" -or $csDomainRole -eq "StandaloneServer") {
		
		if ($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy -ne 0) { Write-Host "WN19-MS-000020 - $($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy)" }
		if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Host "WN19-MS-000030 - $($windowsSystemChecks.EnumerateLocalUsers)" }

		$windowsntRPCCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
		if ($windowsntRPCCheck.RestrictRemoteClients -ne 1) { Write-Host "WN19-MS-000040 - $($windowsntRPCCheck.RestrictRemoteClients)" }

		if ($windowsntWinLogon.CachedLogonsCount -le 4) { Write-Host "WN19-MS-000050 - $($windowsntWinLogon.CachedLogonsCount)" }

		if ($lsaSettings.RestrictRemoteSAM -ne "O:BAG:BAD:(A;;RC;;;BA)") { Write-Host "WN19-MS-000060 - $($lsaSettings.RestrictRemoteSAM)" }
		
		$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-11*")
		$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] }
		if ($disallowedSIDs) { Write-Host "WN19-MS-000070 - $disallowedSIDs" }

		$vbsSecurityServicesRunning = $vbsDetailsCheck.SecurityServicesRunning | Out-String
		if ($vbsSecurityServicesRunning.Contains("1") -eq $false) { Write-Host "WN19-MS-000140 - $($vbsSecurityServicesRunning)" }

		$enableDelegationPrivilegeCheck = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
		if ($enableDelegationPrivilegeCheck.Contains("*S-1") -eq $true) { Write-Host "WN19-MS-000310 - $($enableDelegationPrivilegeCheck)" }

		if ($CsDomainRole -ne "StandaloneServer") {
			
			$denyAccessToThisComputerSIDs = ($policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedDenyAccessToThisComputerSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546", "S-1-5-114", "S-1-5-113")
			$disallowedDenyAccessToThisComputerSIDs = $denyAccessToThisComputerSIDs | Where-Object { $_ -notlike $allowedDenyAccessToThisComputerSIDs[0] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[1] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[2] }
			if ($disallowedDenyAccessToThisComputerSIDs) { Write-Host "WN19-MS-000080 - $disallowedDenyAccessToThisComputerSIDs" }
		
			$denyBatchLogonRightSIDs = ($policyContent | Select-String "SeDenyBatchLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedBatchLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
			$disallowedBatchLogonRightSIDs = $denyBatchLogonRightSIDs | Where-Object { $_ -notlike $allowedBatchLogonRightSIDs[0] -and $_ -notlike $allowedBatchLogonRightSIDs[1] -and $_ -notlike $allowedBatchLogonRightSIDs[2] }
			if ($disallowedBatchLogonRightSIDs) { Write-Host "WN19-MS-000090 - $disallowedBatchLogonRightSIDs" }
		
			$denyServiceLogonRightSIDS = ($policyContent | Select-String "SeDenyServiceLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedServiceLogonRightSIDS = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512")
			$disallowedServiceLogonRightSIDS = $denyServiceLogonRightSIDS | Where-Object { $_ -notlike $allowedServiceLogonRightSIDS[0] -and $_ -notlike $allowedServiceLogonRightSIDS[1] }
			if ($disallowedServiceLogonRightSIDS) { Write-Host "WN19-MS-000100 - $disallowedBatchLogonRightSIDs" }
			
			$denyInteractiveLogonRightSIDs = ($policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedInteractiveLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
			$disallowedInteractiveLogonRightSIDs = $denyInteractiveLogonRightSIDs | Where-Object { $_ -notlike $allowedInteractiveLogonRightSIDs[0] -and $_ -notlike $allowedInteractiveLogonRightSIDs[1] -and $_ -notlike $allowedInteractiveLogonRightSIDs[2] }
			if ($disallowedInteractiveLogonRightSIDs) { Write-Host "WN19-MS-000110 - $disallowedBatchLogonRightSIDs" }
			
			$denyLogOnThroughRemoteDesktopServicesSIDs = ($policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedDenyLogOnThroughRemoteDesktopServicesSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546", "*S-1-5-113")
			$disallowedDenyLogOnThroughRemoteDesktopServicesSIDs = $denyLogOnThroughRemoteDesktopServicesSIDs | Where-Object { $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[0] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[1] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[2] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[3] }
			if ($disallowedDenyLogOnThroughRemoteDesktopServicesSIDs) { Write-Host "WN19-MS-000120 - $disallowedDenyLogOnThroughRemoteDesktopServicesSIDs" }
		
		}
		
		if ($edge -ne $null) {
			
			$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ 2>$null
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
		}
		
		foreach ($possibleFirefoxUser in $validFirefoxUsers) {
			$firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
			if (Test-Path $firefoxPath) {
				$profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
				if ($profilePath) {
					$firefoxPreferences = Get-Content "$profilePath\prefs.js" 2>$null | Out-String
					$firefoxHandlers = Get-Content "$profilePath\handlers.json" 2>$null | Out-String
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
			   if ($firefoxPreferences.Contains('"extensions.update.enabled", false') -eq $false) {
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

		$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission 2>$null
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

		$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay 2>$null
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

		$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection 2>$null
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

		$disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers 2>$null
		if ($disabledFirefoxCiphers -ne $null) {
		   if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false") -and $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
		   }
		}

		$firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging 2>$null
		if ($firefoxUserMessaging -ne $null) {
		   if ($firefoxUserMessaging.ExtensionRecommendations -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
		} else {
		   if ($firefoxPreferences -ne $null) {
			   if ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
			}
		}

		$firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage 2>$null
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
	}

	$disableBuiltInGuestAccountCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
	if ($disableBuiltInGuestAccountCheck.Contains("1") -eq $true) { Write-Host "WN19-SO-000010 - $($disableBuiltInGuestAccountCheck)" }

	if ($lsaSettings.LimitBlankPasswordUse -ne 1) { Write-Host "WN19-SO-000020 - $($lsaSettings.LimitBlankPasswordUse)" }

	$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
	if ($newAdminName.Contains("Administrator") -eq $true) { Write-Host "WN19-SO-000030 - $($newAdminName)" }

	$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
	if ($newGuestName -match '="Guest"') { Write-Host "WN19-SO-000040 - $($newGuestName)" }

	if ($lsaSettings.SCENoApplyLegacyAuditPolicy -ne 1) { Write-Host "WN19-SO-000050 - $($lsaSettings.SCENoApplyLegacyAuditPolicy)" }

	$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
	if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Host "WN19-SO-000060 - $($netLogonParameters.RequireSignOrSeal)" }
	if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Host "WN19-SO-000070 - $($netLogonParameters.SealSecureChannel)" }
	if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Host "WN19-SO-000080 - $($netLogonParameters.SignSecureChannel)" }
	if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Host "WN19-SO-000090 - $($netLogonParameters.DisablePasswordChange)" }
	if ($netLogonParameters.MaximumPasswordAge -gt 30 -or $netLogonParameters.MaximumPasswordAge -eq 0) { Write-Host "WN19-SO-000100 - $($netLogonParameters.MaximumPasswordAge)" }
	if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Host "WN19-SO-000110 - $($netLogonParameters.RequireStrongKey)" }

	if ($currentVersionSystemPolicies.InactivityTimeoutSecs -notin 1..900) { Write-Host "WN19-SO-000120 - $($currentVersionSystemPolicies.InactivityTimeoutSecs)" }
	if ($currentVersionSystemPolicies.LegalNoticeText -eq $null) { Write-Host "WN19-SO-000130 - $($currentVersionSystemPolicies.LegalNoticeText)" }
	if ($currentVersionSystemPolicies.LegalNoticeCaption -eq $null) { Write-Host "WN19-SO-000140 - $($currentVersionSystemPolicies.LegalNoticeCaption)" }

	$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
	if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Host "WN19-SO-000160 - $($lanmanWorkstationParameters.RequireSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnableSecuritySignature -ne 1) { Write-Host "WN19-SO-000170 - $($lanmanWorkstationParameters.EnableSecuritySignature)" }
	if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Host "WN19-SO-000180 - $($lanmanWorkstationParameters.EnablePlainTextPassword)" }

	$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
	if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Host "WN19-SO-000190 - $($lanmanServerParameters.RequireSecuritySignature)" }
	if ($lanmanServerParameters.EnableSecuritySignature -ne 1) { Write-Host "WN19-SO-000200 - $($lanmanServerParameters.EnableSecuritySignature)" }

	$lsaAnonymousName = $policyContent | Select-String "LsaAnonymousNameLookup" | Out-String
	if ($lsaAnonymousName.Contains("1") -eq $true) { Write-Host "WN19-SO-000210 - $($lsaAnonymousName)" }

	if ($lsaSettings.RestrictAnonymousSAM -ne 1) { Write-Host "WN19-SO-000220 - $($lsaSettings.RestrictAnonymousSAM)" }
	if ($lsaSettings.RestrictAnonymous -ne 1) { Write-Host "WN19-SO-000230 - $($lsaSettings.RestrictAnonymous)" }
	if ($lsaSettings.EveryoneIncludesAnonymous -ne 0) { Write-Host "WN19-SO-000240 - $($lsaSettings.EveryoneIncludesAnonymous)" }

	if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Host "WN19-SO-000250 - $($lanmanServerParameters.RestrictNullSessAccess)" }

	if ($lsaSettings.UseMachineId -ne 1) { Write-Host "WN19-SO-000260 - $($lsaSettings.UseMachineId)" }

	$lsaMSV = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
	if ($lsaMSV.allownullsessionfallback -ne 0) { Write-Host "WN19-SO-000270 - $($lsaMSV.allownullsessionfallback)" }

	$lsaPKU2U = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
	if ($lsaPKU2U.AllowOnlineID -ne 0) { Write-Host "WN19-SO-000280 - $($lsaPKU2U.AllowOnlineID)" }

	$kerbParameters = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
	if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
		if ($kerbParameters.SupportedEncryptionTypes -ne 2147483640) { Write-Host "WN19-SO-000290 - $($kerbParameters.SupportedEncryptionTypes)" }
	}

	if ($lsaSettings.NoLMHash -ne 1) { Write-Host "WN19-SO-000300 - $($lsaSettings.NoLMHash)" }
	if ($lsaSettings.LmCompatibilityLevel -ne 5) { Write-Host "WN19-SO-000310 - $($lsaSettings.LmCompatibilityLevel)" }

	$ldapServicesCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
	if ($ldapServicesCheck.LDAPClientIntegrity -ne 1) { Write-Host "WN19-SO-000320 - $($ldapServicesCheck.LDAPClientIntegrity)" }

	if ($lsaMSV.NTLMMinClientSec -ne 537395200) { Write-Host "WN19-SO-000330 - $($lsaMSV.NTLMMinClientSec)" }
	if ($lsaMSV.NtlmMinServerSec -ne 537395200) { Write-Host "WN19-SO-000340 - $($lsaMSV.NtlmMinServerSec)" }

	$microsoftCryptographyCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
	if ($microsoftCryptographyCheck.ForceKeyProtection -ne 2) { Write-Host "WN19-SO-000350 - $($microsoftCryptographyCheck.ForceKeyProtection)" }

	$lsaFIPSCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
	if ($lsaFIPSCheck.Enabled -ne 1) { Write-Host "WN19-SO-000360 - $($lsaFIPSCheck.Enabled)" }

	$registrySessionManagerCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
	if ($registrySessionManagerCheck.ProtectionMode -ne 1) { Write-Host "WN19-SO-000370 - $($registrySessionManagerCheck.ProtectionMode)" }

	if ($currentVersionSystemPolicies.FilterAdministratorToken -ne 1) { Write-Host "WN19-SO-000380 - $($currentVersionSystemPolicies.FilterAdministratorToken)" }
	if ($currentVersionSystemPolicies.EnableUIADesktopToggle -ne 0) { Write-Host "WN19-SO-000390 - $($currentVersionSystemPolicies.EnableUIADesktopToggle)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin -notin @(1, 2)) { Write-Host "WN19-SO-000400 - $($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin)" }
	if ($currentVersionSystemPolicies.ConsentPromptBehaviorUser -ne 0) { Write-Host "WN19-SO-000410 - $($currentVersionSystemPolicies.ConsentPromptBehaviorUser)" }
	if ($currentVersionSystemPolicies.EnableInstallerDetection -ne 1) { Write-Host "WN19-SO-000420 - $($currentVersionSystemPolicies.EnableInstallerDetection)" }
	if ($currentVersionSystemPolicies.EnableSecureUIAPaths -ne 1) { Write-Host "WN19-SO-000430 - $($currentVersionSystemPolicies.EnableSecureUIAPaths)" }
	if ($currentVersionSystemPolicies.EnableLUA -ne 1) { Write-Host "WN19-SO-000440 - $($currentVersionSystemPolicies.EnableLUA)" }
	if ($currentVersionSystemPolicies.EnableVirtualization -ne 1) { Write-Host "WN19-SO-000450 - $($currentVersionSystemPolicies.EnableVirtualization)" }

	$attachmentPoliciesCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
	if ($attachmentPoliciesCheck.SaveZoneInformation -eq 1) { Write-Host "WN19-UC-000010 - $($attachmentPoliciesCheck.SaveZoneInformation)" }

	$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
	if ($accessCredManagerCheck.Contains("*S-1") -eq $true) { Write-Host "WN19-UR-000010 - $($accessCredManagerCheck)" }

	$actAsPartofOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
	if ($actAsPartofOSCheck.Contains("*S-1") -eq $true) { Write-Host "WN19-UR-000020 - $($actAsPartofOSCheck)" }

	$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedLogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
	$disallowedLogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedLogonSIDs[0] -and $_ -notlike $allowedLogonSIDs[1] }
	if ($disallowedLogonSIDs.Count -gt 0) { Write-Host "WN19-UR-000030 - $($disallowedLogonSIDs)" }

	$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedBackupSIDs = @("*S-1-5-32-544")
	$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
	if ($disallowedBackupSIDs.Count -gt 0) { Write-Host "WN19-UR-000040 - $($disallowedBackupSIDs)" }

	$createPagefileSID = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createPagefileSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000050 - $($createPagefileSID)" }

	$createTokenObjectsSID = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
	if ($createTokenObjectsSID.Contains("*S-1") -eq $true) { Write-Host "WN19-UR-000060 - $($createTokenObjectsSID)" }

	$createGlobalPrivilegeSID = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedCreateGlobalSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedCreateGlobalSIDs = $createGlobalPrivilegeSID | Where-Object { $_ -notlike $allowedCreateGlobalSIDs[0] -and $_ -notlike $allowedCreateGlobalSIDs[1] -and $_ -notlike $allowedCreateGlobalSIDs[2] -and $_ -notlike $allowedCreateGlobalSIDs[3] }
	if ($disallowedCreateGlobalSIDs.Count -gt 0) { Write-Host "WN19-UR-000070 - $($disallowedCreateGlobalSIDs)" }

	$createPermanentSharedObjectSID = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
	if ($createPermanentSharedObjectSID.Contains("*S-1") -eq $true) { Write-Host "WN19-UR-000080 - $($createPermanentSharedObjectSID)" }

	$createSymbolicLinkSID = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($createSymbolicLinkSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000090 - $($createSymbolicLinkSID)" }

	$debugPrivilegeSID = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($debugPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000100 - $($debugPrivilegeSID)" }

	$forceShutdownFromRemoteSystemSID = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($forceShutdownFromRemoteSystemSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000110 - $($forceShutdownFromRemoteSystemSID)" }

	$auditPrivilegeSID = ($policyContent | Select-String "SeAuditPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedAuditSIDs = @("*S-1-5-19", "*S-1-5-20")
	$disallowedAuditSIDs = $auditPrivilegeSID | Where-Object { $_ -notlike $allowedAuditSIDs[0] -and $_ -notlike $allowedAuditSIDs[1] }
	if ($disallowedAuditSIDs.Count -gt 0) { Write-Host "WN19-UR-000120 - $($disallowedAuditSIDs)" }

	$impersonateAClientAfterAuthenticationSID = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	$allowedImpersonateSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
	$disallowedImpersonateSIDs = $impersonateAClientAfterAuthenticationSID | Where-Object { $_ -notlike $allowedImpersonateSIDs[0] -and $_ -notlike $allowedImpersonateSIDs[1] -and $_ -notlike $allowedImpersonateSIDs[2] -and $_ -notlike $allowedImpersonateSIDs[3] }
	if ($disallowedImpersonateSIDs.Count -gt 0) { Write-Host "WN19-UR-000130 - $($disallowedImpersonateSIDs)" }

	$increaseBasePrioritySID = ($policyContent | Select-String "SeIncreaseBasePriorityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($increaseBasePrioritySID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000140 - $($increaseBasePrioritySID)" }

	$loadDriverSID = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($loadDriverSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000150 - $($loadDriverSID)" }

	$lockMemorySID = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
	if ($lockMemorySID.Contains("*S-1") -eq $true) { Write-Host "WN19-UR-000160 - $($lockMemorySID)" }

	$manageAuditingAndSecurityLogSID = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($manageAuditingAndSecurityLogSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000170 - $($manageAuditingAndSecurityLogSID)" }

	$modifyFirmwareEnvironmentSID = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($modifyFirmwareEnvironmentSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000180 - $($modifyFirmwareEnvironmentSID)" }

	$performVolumeMaintenanceSID = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($performVolumeMaintenanceSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000190 - $($performVolumeMaintenanceSID)" }

	$profileSingleProcessSID = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($profileSingleProcessSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000200 - $($profileSingleProcessSID)" }

	$restorePrivilegeSID = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($restorePrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000210 - $($restorePrivilegeSID)" }

	$takeOwnershipSID = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
	if ($takeOwnershipSID -notlike "*S-1-5-32-544") { Write-Host "WN19-UR-000220 - $($takeOwnershipSID)" }
	
} else {
	
	#Windows Server 2022 MS/DC
	if ($wnVers.Contains("2022") -or $computerInfo2.Contains("2022") -or $computerInfo3.Contains("2022")) {
		$tpm = Get-Tpm 2>$null
		$tpmPresent = $tpm.TpmPresent
		$tpmEnabled = $tpm.TpmEnabled

		$adminAccount = Get-LocalUser -Name "Administrator"
		$currentDate = Get-Date
		$passwordLastSet = $adminAccount.PasswordLastSet
		$daysSincePasswordSet = ($currentDate - $passwordLastSet).Days
		if ($daysSincePasswordSet -gt 60) { Write-Host "WN22-00-000020 - $daysSincePasswordSet" }

		$appLocker = Get-AppLockerPolicy -Effective -Xml
		if($appLocker.Contains('Type="Appx"') -eq $false) { Write-Host "WN22-00-000080" }

		$csDomainRole = $computerInfo.CsDomainRole
		if($csDomainRole -ne "StandaloneServer") {
			if ($tpmPresent -eq $false -or $tpmEnabled -eq $false) { Write-Host "WN22-00-000090 - $tpmPresent $tpmEnabled" }
		}

		$windowsOSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
		if($windowsOSVersion -lt "20348.1070") { Write-Host "WN22-00-000100 - $windowsOSVersion" }

		$allWindowsServices = Get-Service
		$trellix = $allWindowsServices | where {$_.DisplayName -like "*Trellix*"} | Select Status,DisplayName | Out-String
		$symantec = $allWindowsServices | where {$_.DisplayName -like "*Symantec*"} | Select Status,DisplayName | Out-String
		$defender = $allWindowsServices | where {$_.DisplayName -like "*Defender*"} | Select Status,DisplayName | Out-String
		if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN22-00-000110 - $allWindowsServices" }

		$ntfs = Get-Volume
		foreach ($volume in $ntfs) {
			if ($volume.FileSystemType -ne "NTFS" -and $volume.DriveType -eq "Fixed") {
				Write-Host "WN22-00-000130 - $($volume.DriveLetter) = $($volume.FileSystemType)"
				break
			}
		}

		$subcategoryAuditing = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
		if ($subcategoryAuditing.everyoneincludesanonymous -ne 0) { 
			Write-Host "WN22-00-000140, WN22-00-000150, WN22-00-000160 - $($subcategoryAuditing.everyoneincludesanonymous)"
		}

		$hklmSoftwareACL = Get-Acl -Path HKLM:SOFTWARE | % { $_.access }
		$softwareIsInherited = $hklmSoftwareACL.IsInherited | Out-String
		$hklmSystemACL = Get-Acl -Path HKLM:SYSTEM | % { $_.access }
		$systemIsInherited = $hklmSystemACL.IsInherited | Out-String
		if ($softwareIsInherited.Contains("True") -or $systemIsInherited.Contains("True")) { Write-Host "WN22-00-000170 - $softwareIsInherited $systemIsInherited" }

		if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
			$inactiveAccounts = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 35.00:00:00 | Where-Object {$_.Enabled -eq $true}
			if ($inactiveAccounts) { Write-Host "WN22-00-000190 - $($inactiveAccounts.Name)" }
		} else {
			([ADSI] ('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
				$user = ([ADSI]$_.Path)
				$lastLogin = $user.Properties.LastLogin.Value
				$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
				if ($lastLogin -eq $null) {$lastLogin = 'Never'}
				if ($enabled -eq $true -and $user.Name -ne 'no access') { Write-Host "WN22-00-000190 - $($user.Name) $lastLogin $enabled"}
			}
		}

		if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
			$noPasswordUsers = Get-ADUser -Filter * -Properties Passwordnotrequired | Where-Object {$_.Enabled -eq $true -and $_.Passwordnotrequired -eq $true} | Select-Object -First 1
			if ($noPasswordUsers) {
				Write-Host "WN22-00-000200 - $($noPasswordUsers.Name)"
			}
		} else {
			$noPasswordAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordRequired=False and LocalAccount=True"
			foreach ($account in $noPasswordAccounts) {
				if ($account.Disabled -eq $false) {
					Write-Host "WN22-00-000200 - $($account.Name)"
					break
				}
			}
		}

		if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
			$neverExpiringAccounts = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true} | Select-Object -First 1
			if ($neverExpiringAccounts) {
				Write-Host "WN22-00-000210 - $($neverExpiringAccounts.Name)"
			}
		} else {
			$neverExpiringAccounts = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True"
			foreach ($account in $neverExpiringAccounts) {
				if ($account.Disabled -eq $false) {
					Write-Host "WN22-00-000210 - $($account.Name)"
					break
				}
			}
		}

		$job = Start-Job -ScriptBlock {
			Get-ChildItem -Path C:\ -Include *.p12,*.pfx -File -Recurse 2>$null | Select-Object -First 1
		}
		$lingeringCertificateFiles = if (Wait-Job $job -Timeout 60) {
			Receive-Job $job
		} else {
			Stop-Job $job
			$null
		}
		Remove-Job $job -Force
		if ($lingeringCertificateFiles -ne $null) {
			Write-Host "WN22-00-000240 - $($lingeringCertificateFiles)"
		}

		if ($trellix.Contains("Running Trellix Agent") -eq $false -and $symantec.Contains("Running Symantec Endpoint Protection") -eq $false -and $defender.Contains("Running Windows Defender Antivirus Service") -eq $false) { Write-Host "WN22-00-000290" }

		$faxInstallCheck = Get-WindowsFeature | Where Name -eq Fax
		if ($faxInstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000320" }

		$pnrpInstallCheck = Get-WindowsFeature | Where Name -eq PNRP
		if ($pnrpInstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000340" }

		$simpletcpipInstallCheck = Get-WindowsFeature | Where Name -eq Simple-TCPIP
		if ($simpletcpipInstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000350" }

		$telnetClientInstallCheck = Get-WindowsFeature | Where Name -eq Telnet-Client
		if ($telnetClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000360" }

		$tftpClientInstallCheck = Get-WindowsFeature | Where Name -eq TFTP-Client
		if ($tftpClientInstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000370" }

		$smbv1InstallCheck = Get-WindowsFeature -Name FS-SMB1
		if ($smbv1InstallCheck.InstallState -eq "Installed") { 
			$smb1LanmanServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters").SMB1
			if ($smb1LanmanServer -ne 0) {
				Write-Host "WN22-00-000380 $($smbv1InstallCheck.InstallState) $($smb1LanmanServer)" 
			}
		}

		$powershell2InstallCheck = Get-WindowsFeature | Where Name -eq PowerShell-V2
		if ($powershell2InstallCheck.InstallState -eq "Installed") { Write-Host "WN22-00-000410" }

		$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
		if ($ftpInstallCheck.InstallState -eq "Installed") {
			$ftpAnonymousAuth = Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/ftpServer/security/authentication/anonymousAuthentication" -Name "enabled" -PSPath "IIS:\"
			if ($ftpAnonymousAuth.Value -eq $true) {
				Write-Host "WN22-00-000420 $($ftpAnonymousAuth.Value)"
			}
		}

		$ftpInstallCheck = Get-WindowsFeature | Where Name -eq Web-Ftp-Service
		if ($ftpInstallCheck.InstallState -eq "Installed") {
			$ftpSites = Get-WebConfiguration "/system.applicationHost/sites/site" -PSPath "IIS:\"
			foreach ($site in $ftpSites) {
				$ftpRoot = $site.ftpServer.virtualDirectories.physicalPath
				if ($ftpRoot -like "C:*") {
					Write-Host "WN22-00-000430 - $ftpRoot"
					break
				}
			}
		}

		# $timeConfig = Invoke-Expression -Command "W32tm /query /configuration"

		$uefiStatus = $computerInfo.BiosFirmwareType
		if ($uefiStatus -ne "Uefi") { Write-Host "WN22-00-000460 - $uefiStatus" }

		$bootState = Confirm-SecureBootUEFI
		if ($bootState -eq $false) { Write-Host "WN22-00-000470 - $bootState" }

		$exportPath = "$env:TEMP\secpol.inf"
		secedit /export /cfg $exportPath
		$policyContent = Get-Content -Path $exportPath

		$lockoutDurationCheck = $policyContent | Select-String "LockoutDuration" | Out-String
		if ($lockoutDurationCheck.Contains('900') -eq $false) { Write-Host "WN22-AC-000010 - $lockoutDurationCheck" }

		$lockoutBadCountCheck = $policyContent | Select-String "LockoutBadCount" | Out-String
		if ($lockoutBadCountCheck.Contains('3') -eq $false) { Write-Host "WN22-AC-000020 - $lockoutBadCountCheck" }

		$lockoutCounterResetCheck = $policyContent | Select-String "ResetLockoutCount" | Out-String
		if ($lockoutCounterResetCheck.Contains('900') -eq $false) { Write-Host "WN22-AC-000030 - $lockoutCounterResetCheck" }

		$passwordHistorySize = $policyContent | Select-String "PasswordHistorySize" | Out-String
		if ($passwordHistorySize.Contains('24') -eq $false) { Write-Host "WN22-AC-000040 - $passwordHistorySize" }

		$maxPasswordAgeCheck = $policyContent | Select-String "MaximumPasswordAge" | Out-String
		if ($maxPasswordAgeCheck.Contains('60') -eq $false) { Write-Host "WN22-AC-000050 - $maxPasswordAgeCheck" }

		$minPasswordAgeCheck = $policyContent | Select-String "MinimumPasswordAge" | Out-String
		if ($minPasswordAgeCheck.Contains('1') -eq $false) { Write-Host "WN22-AC-000060 - $minPasswordAgeCheck" }

		$minPasswordLengthCheck = $policyContent | Select-String "MinimumPasswordLength" | Out-String
		if ($minPasswordLengthCheck.Contains('10') -eq $false) { Write-Host "WN22-AC-000070 - $minPasswordLengthCheck" }

		$passwordComplexityCheck = $policyContent | Select-String "PasswordComplexity" | Out-String
		if ($passwordComplexityCheck.Contains('1') -eq $false) { Write-Host "WN22-AC-000080 - $passwordComplexityCheck" }

		$reversiblePasswordEncryptionCheck = $policyContent | Select-String "ClearTextPassword" | Out-String
		if ($reversiblePasswordEncryptionCheck.Contains('1') -eq $True) { Write-Host "WN22-AC-000090 - $reversiblePasswordEncryptionCheck" }

		$applicationEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Application.evtx 2>$null).Access).FileSystemRights).Count
		if ($applicationEventLogACL -ne 3) { Write-Host "WN22-AU-000030 - $applicationEventLogACL" }

		$securityEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\Security.evtx 2>$null).Access).FileSystemRights).Count
		if ($securityEventLogACL -ne 3) { Write-Host "WN22-AU-000040 - $securityEventLogACL" }

		$systemEventLogACL = (((Get-Acl C:\Windows\System32\Winevt\Logs\System.evtx 2>$null).Access).FileSystemRights).Count
		if ($systemEventLogACL -ne 3) { Write-Host "WN22-AU-000050 - $systemEventLogACL" }

		$eventvwrPath = "$env:SystemRoot\System32\eventvwr.exe"
		$eventvwrACL = (Get-Acl $eventvwrPath 2>$null).Access
		$fullControlCount = ($eventvwrACL | Where-Object {$_.FileSystemRights -eq "Full Control"}).Count
		if ($fullControlCount -gt 1) { Write-Host "WN22-AU-000060 - $fullControlCount" }

		$auditPolicyAll = AuditPol /get /category:*
		$credentialValidationCheck = $auditPolicyAll | Select-String "Credential Validation" | Out-String
		if ($credentialValidationCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000070 - $credentialValidationCheck" }
		if ($credentialValidationCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000080 - $credentialValidationCheck" }

		$otherAccountManagementCheck = $auditPolicyAll | Select-String "Other Account Management Events" | Out-String
		if ($otherAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000090 - $otherAccountManagementCheck" }

		$securityGroupManagementCheck = $auditPolicyAll | Select-String "Security Group Management" | Out-String
		if ($securityGroupManagementCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000100 - $securityGroupManagementCheck" }

		$userAccountManagementCheck = $auditPolicyAll | Select-String "User Account Management" | Out-String
		if ($userAccountManagementCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000110 - $userAccountManagementCheck" }
		if ($userAccountManagementCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000120 - $userAccountManagementCheck" }

		$pnpEventsCheck = $auditPolicyAll | Select-String "Plug and Play Events" | Out-String
		if ($pnpEventsCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000130 - $pnpEventsCheck" }

		$processTrackingCheck = $auditPolicyAll | Select-String "Process Creation" | Out-String
		if ($processTrackingCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000140 - $processTrackingCheck" }

		$accountLockoutCheck = $auditPolicyAll | Select-String "Account Lockout" | Out-String
		if ($accountLockoutCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000160 - $accountLockoutCheck" }

		$groupMembershipCheck = $auditPolicyAll | Select-String "Group Membership" | Out-String
		if ($groupMembershipCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000170 - $groupMembershipCheck" }

		$logoffEventsCheck = $auditPolicyAll | Select-String "(?<!/)\bLogoff\b" | Out-String
		if ($logoffEventsCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000180 - $logoffEventsCheck" }

		$logonEventsCheck = $auditPolicyAll | Select-String "^  Logon\s{2,}" | Out-String
		if ($logonEventsCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000190 - $logonEventsCheck" }
		if ($logonEventsCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000200 - $logonEventsCheck" }

		$specialLogonCheck = $auditPolicyAll | Select-String "Special Logon" | Out-String
		if ($specialLogonCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000210 - $specialLogonCheck" }

		$otherObjectAccessCheck = $auditPolicyAll | Select-String "Other Object Access Events" | Out-String
		if ($otherObjectAccessCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000220 - $otherObjectAccessCheck" }
		if ($otherObjectAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000230 - $otherObjectAccessCheck" }

		$removableStorageCheck = $auditPolicyAll | Select-String "Removable Storage" | Out-String
		if ($removableStorageCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000240 - $removableStorageCheck" }
		if ($removableStorageCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000250 - $removableStorageCheck" }

		$auditPolicyChangeCheck = $auditPolicyAll | Select-String "Audit Policy Change" | Out-String
		if ($auditPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000260 - $auditPolicyChangeCheck" }
		if ($auditPolicyChangeCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000270 - $auditPolicyChangeCheck" }

		$authenticationPolicyChangeCheck = $auditPolicyAll | Select-String "Authentication Policy Change" | Out-String
		if ($authenticationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000280 - $authenticationPolicyChangeCheck" }

		$authorizationPolicyChangeCheck = $auditPolicyAll | Select-String "Authorization Policy Change" | Out-String
		if ($authorizationPolicyChangeCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000290 - $authorizationPolicyChangeCheck" }

		$sensitivePrivilegeUseCheck = $auditPolicyAll | Select-String "Sensitive Privilege Use" | Out-String
		if ($sensitivePrivilegeUseCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000300 - $sensitivePrivilegeUseCheck" }
		if ($sensitivePrivilegeUseCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000310 - $sensitivePrivilegeUseCheck" }

		$ipSecDriverCheck = $auditPolicyAll | Select-String "IPsec Driver" | Out-String
		if ($ipSecDriverCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000320 - $ipSecDriverCheck" }
		if ($ipSecDriverCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000330 - $ipSecDriverCheck" }

		$otherSystemEventCheck = $auditPolicyAll | Select-String "Other System Events" | Out-String
		if ($otherSystemEventCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000340 - $otherSystemEventCheck" }
		if ($otherSystemEventCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000350 - $otherSystemEventCheck" }

		$securityStateChangeCheck = $auditPolicyAll | Select-String "Security State Change" | Out-String
		if ($securityStateChangeCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000360 - $securityStateChangeCheck" }

		$securitySystemExtensionCheck = $auditPolicyAll | Select-String "Security System Extension" | Out-String
		if ($securitySystemExtensionCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000370 - $securitySystemExtensionCheck" }

		$systemIntegrityCheck = $auditPolicyAll | Select-String "System Integrity" | Out-String
		if ($systemIntegrityCheck.Contains("Success") -eq $false) { Write-Host "WN22-AU-000380 - $systemIntegrityCheck" }
		if ($systemIntegrityCheck.Contains("Failure") -eq $false) { Write-Host "WN22-AU-000390 - $systemIntegrityCheck" }

		$lockScreenAccess = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\
		if ($lockScreenAccess.NoLockScreenSlideshow -ne 1) { Write-Host "WN22-CC-000010 - $($lockScreenAccess.NoLockScreenSlideshow)" }

		$wDigestInfo = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\
		if ($wDigestInfo.UseLogonCredential -ne 0) { Write-Host "WN22-CC-000020 - $($wDigestInfo.UseLogonCredential)" }

		$tcpip6Parameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
		if ($tcpip6Parameters.DisableIPSourceRouting -ne 2) { Write-Host "WN22-CC-000030 - $($tcpip6Parameters.DisableIPSourceRouting)" }

		$tcpipParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
		if ($tcpipParameters.DisableIPSourceRouting -ne 2) { Write-Host "WN22-CC-000040 - $($tcpipParameters.DisableIPSourceRouting)" }

		if ($tcpipParameters.EnableICMPRedirect -ne 0) { Write-Host "WN22-CC-000050 - $($tcpipParameters.EnableICMPRedirect)" }

		$netbtParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\
		if ($netbtParameters.NoNameReleaseOnDemand -ne 1) { Write-Host "WN22-CC-000060 - $($netbtParameters.NoNameReleaseOnDemand)" }

		$lanmanWorkstationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
		if ($lanmanWorkstationSettings.AllowInsecureGuestAuth -ne 0) { Write-Host "WN22-CC-000070 - $($lanmanWorkstationSettings.AllowInsecureGuestAuth)" }

		$networkProviderHardenedPaths = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
		if ($networkProviderHardenedPaths."\\*\SYSVOL" -ne "RequireMutualAuthentication=1, RequireIntegrity=1" -or $networkProviderHardenedPaths."\\*\NETLOGON" -ne "RequireMutualAuthentication=1, RequireIntegrity=1") { Write-Host "WN22-CC-000080 - $($networkProviderHardenedPaths."\\*\SYSVOL") $($networkProviderHardenedPaths."\\*\NETLOGON")" }

		$systemAuditSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
		if ($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled -ne 1) { Write-Host "WN22-CC-000090 - $($systemAuditSettings.ProcessCreationIncludeCmdLine_Enabled)" }

		$credentialsDelegationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
		if ($credentialsDelegationSettings.AllowProtectedCreds -ne 1) { Write-Host "WN22-CC-000100 - $($credentialsDelegationSettings.AllowProtectedCreds)" }

		$vbsDetailsCheck = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard\
		$vbsRequiredSecurityProperties = $vbsDetailsCheck.RequiredSecurityProperties | Out-String
		if ($vbsRequiredSecurityProperties.Contains("2") -eq $false -or $vbsDetailsCheck.VirtualizationBasedSecurityStatus -ne 2) { Write-Host "WN22-CC-000110 - $($vbsDetailsCheck.VirtualizationBasedSecurityStatus)" }

		$earlyLaunchCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
		if ($earlyLaunchCheck.DriverLoadPolicy -eq 7) { Write-Host "WN22-CC-000130 - $($earlyLaunchCheck.DriverLoadPolicy)" }

		$gpoChangesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"
		if ($gpoChangesCheck.NoGPOListChanges -ne 0) { Write-Host "WN22-CC-000140 - $($gpoChangesCheck.NoGPOListChanges)" }

		$windowsNTPrintersCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\"
		if ($windowsNTPrintersCheck.DisableWebPnPDownload -ne 1) { Write-Host "WN22-CC-000150 - $($windowsNTPrintersCheck.DisableWebPnPDownload)" }
		if ($windowsNTPrintersCheck.DisableHTTPPrinting -ne 1) { Write-Host "WN22-CC-000160 - $($windowsNTPrintersCheck.DisableHTTPPrinting)" }

		$windowsSystemChecks = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\
		if ($windowsSystemChecks.DontDisplayNetworkSelectionUI -ne 1) { Write-Host "WN22-CC-000170 - $($windowsSystemChecks.DontDisplayNetworkSelectionUI)" }
		if ($windowsSystemChecks.EnableSmartScreen -ne 1) { Write-Host "WN22-CC-000300 - $($windowsSystemChecks.EnableSmartScreen)" }

		$powerSettingsCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"
		if ($powerSettingsCheck.DCSettingIndex -ne 1) { Write-Host "WN22-CC-000180 - $($powerSettingsCheck.DCSettingIndex)" }
		if ($powerSettingsCheck.ACSettingIndex -ne 1) { Write-Host "WN22-CC-000190 - $($powerSettingsCheck.ACSettingIndex)" }

		$appCompatSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\
		if ($appCompatSettingsCheck.DisableInventory -ne 1) { Write-Host "WN22-CC-000200 - $($appCompatSettingsCheck.DisableInventory)" }
		 
		$windowsExplorerSettingsCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\
		if ($windowsExplorerSettingsCheck.NoAutoplayfornonVolume -ne 1) { Write-Host "WN22-CC-000210 - $($windowsExplorerSettingsCheck.NoAutoplayfornonVolume)" }
		if ($windowsExplorerSettingsCheck.NoDataExecutionPrevention -eq 1) { Write-Host "WN22-CC-000310 - $($windowsExplorerSettingsCheck.NoDataExecutionPrevention)" }
		if ($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption -eq 1) { Write-Host "WN22-CC-000320 - $($windowsExplorerSettingsCheck.NoHeapTerminationOnCorruption)" }

		$windowsExplorerSettings2Check = Get-ItemProperty -Path \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
		if ($windowsExplorerSettings2Check.NoAutorun -ne 1) { Write-Host "WN22-CC-000220 - $($windowsExplorerSettingsCheck.NoAutorun)" }


		$windowsPoliciesExplorerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
		if ($windowsPoliciesExplorerCheck.NoAutorun -ne 1) { Write-Host "WN22-CC-000220 - $($windowsPoliciesExplorerCheck.NoAutorun)" }
		if ($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun -ne 255) { Write-Host "WN22-CC-000230 - $($windowsPoliciesExplorerCheck.NoDriveTypeAutoRun)" }
		if ($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior -eq 1) { Write-Host "WN22-CC-000330 - $($windowsPoliciesExplorerCheck.PreXPSP2ShellProtocolBehavior)" }

		$credUICheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
		if ($credUICheck.EnumerateAdministrators -ne 0) { Write-Host "WN22-CC-000240 - $($credUICheck.EnumerateAdministrators)" }

		$dataCollectionCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\
		if ($dataCollectionCheck.AllowTelemetry -notin @(0, 1, 3)) { Write-Host "WN22-CC-000250 - $($dataCollectionCheck.AllowTelemetry)" }

		$deliveryOptimizationSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\
		if ($deliveryOptimizationSettings.DODownloadMode -eq 3) { Write-Host "WN22-CC-000260 - $($deliveryOptimizationSettings.DODownloadMode)" }

		$eventLogApplication = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
		if ($eventLogApplication.MaxSize -lt 32768) { Write-Host "WN22-CC-000270 - $($eventLogApplication.MaxSize)" }

		$eventLogSecurity = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
		if ($eventLogSecurity.MaxSize -lt 196608) { Write-Host "WN22-CC-000280 - $($eventLogSecurity.MaxSize)" }

		$eventLogSystem = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
		if ($eventLogSystem.MaxSize -lt 32768) { Write-Host "WN22-CC-000290 - $($eventLogSystem.MaxSize)" }

		$ntTerminalServicesCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
		if ($ntTerminalServicesCheck.DisablePasswordSaving -ne 1) { Write-Host "WN22-CC-000340 - $($ntTerminalServicesCheck.DisablePasswordSaving)" }
		if ($ntTerminalServicesCheck.fDisableCdm -ne 1) { Write-Host "WN22-CC-000350 - $($ntTerminalServicesCheck.fDisableCdm)" }
		if ($ntTerminalServicesCheck.fPromptForPassword -ne 1) { Write-Host "WN22-CC-000360 - $($ntTerminalServicesCheck.fPromptForPassword)" }
		if ($ntTerminalServicesCheck.fEncryptRPCTraffic -ne 1) { Write-Host "WN22-CC-000370 - $($ntTerminalServicesCheck.fEncryptRPCTraffic)" }
		if ($ntTerminalServicesCheck.MinEncryptionLevel -ne 3) { Write-Host "WN22-CC-000380 - $($ntTerminalServicesCheck.MinEncryptionLevel)" }

		$internetExplorerFeeds = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\"
		if ($internetExplorerFeeds.DisableEnclosureDownload -ne 1) { Write-Host "WN22-CC-000390 - $($internetExplorerFeeds.DisableEnclosureDownload)" }
		if ($internetExplorerFeeds.AllowBasicAuthInClear -eq 1) { Write-Host "WN22-CC-000400 - $($internetExplorerFeeds.AllowBasicAuthInClear)" }

		$windowsWindowsSearch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\"
		if ($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems -ne 0) { Write-Host "WN22-CC-000410 - $($windowsWindowsSearch.AllowIndexingEncryptedStoresOrItems)" }

		$windowsInstallerCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\
		if ($windowsInstallerCheck.EnableUserControl -ne 0) { Write-Host "WN22-CC-000420 - $($windowsInstallerCheck.EnableUserControl)" }
		if ($windowsInstallerCheck.AlwaysInstallElevated -ne 0) { Write-Host "WN22-CC-000430 - $($windowsInstallerCheck.AlwaysInstallElevated)" }
		if ($windowsInstallerCheck.SafeForScripting -eq 1) { Write-Host "WN22-CC-000440 - $($windowsInstallerCheck.SafeForScripting)" }

		$currentVersionSystemPolicies = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
		if ($currentVersionSystemPolicies.DisableAutomaticRestartSignOn -ne 1) { Write-Host "WN22-CC-000450 - $($currentVersionSystemPolicies.DisableAutomaticRestartSignOn)" }

		$scriptBlockLogging = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
		if ($scriptBlockLogging.EnableScriptBlockLogging -ne 1) { Write-Host "WN22-CC-000460 - $($scriptBlockLogging.EnableScriptBlockLogging)" }

		$winrmClientCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
		if ($winrmClientCheck.AllowBasic -ne 0) { Write-Host "WN22-CC-000470 - $($winrmClientCheck.AllowBasic)" }
		if ($winrmClientCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN22-CC-000480 - $($winrmClientCheck.AllowUnencryptedTraffic)" }
		if ($winrmClientCheck.AllowDigest -ne 0) { Write-Host "WN22-CC-000490 - $($winrmClientCheck.AllowDigest)" }

		$winrmServiceCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
		if ($winrmServiceCheck.AllowBasic -ne 0) { Write-Host "WN22-CC-000500 - $($winrmServiceCheck.AllowBasic)" }
		if ($winrmServiceCheck.AllowUnencryptedTraffic -ne 0) { Write-Host "WN22-CC-000510 - $($winrmServiceCheck.AllowUnencryptedTraffic)" }
		if ($winrmServiceCheck.DisableRunAs -ne 1) { Write-Host "WN22-CC-000520 - $($winrmServiceCheck.DisableRunAs)" }

		$powershellTranscriptCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
		if ($powershellTranscriptCheck.EnableTranscripting -ne 1) { Write-Host "WN22-CC-000530 - $($powershellTranscriptCheck.EnableTranscripting)" }

		#Common Paths
		$windowsntWinLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
		$lsaSettings = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\
		$netLogonParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\

		#Domain Controller Checks
		if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
			$userLogonRestrictionsCheck = $policyContent | Select-String "TicketValidateClient" | Out-String
			if ($userLogonRestrictionsCheck.Contains("0") -eq $true) { Write-Host "WN22-DC-000020 - $($userLogonRestrictionsCheck)" }

			$maxServiceAgeCheck = $policyContent | Select-String "MaxServiceAge" | Out-String
			if ($maxServiceAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..600) { Write-Host "WN22-DC-000030 - $($maxServiceAgeCheck)" }

			$maxTicketAgeCheck = $policyContent | Select-String "MaxTicketAge" | Out-String
			if ($maxTicketAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..11) { Write-Host "WN22-DC-000040 - $($maxTicketAgeCheck)" }

			$maxRenewAgeCheck = $policyContent | Select-String "MaxRenewAge" | Out-String
			if ($maxRenewAgeCheck -match '\d+' -and [int]($matches[0]) -notin 0..7) { Write-Host "WN22-DC-000050 - $($maxRenewAgeCheck)" }

			$maxClockSkewCheck = $policyContent | Select-String "MaxClockSkew" | Out-String
			if ($maxClockSkewCheck -match '\d+' -and [int]($matches[0]) -notin 0..5) { Write-Host "WN22-DC-000060 - $($maxClockSkewCheck)" }

			$computerAccountManagementAudit = $auditPolicyAll | Select-String "Computer Account Management" | Out-String
			if ($computerAccountManagementAudit.Contains("Success") -eq $false) { Write-Host "WN22-DC-000230 - $computerAccountManagementAudit" }

			$directoryServiceAccessCheck = $auditPolicyAll | Select-String "Directory Service Access" | Out-String
			if ($directoryServiceAccessCheck.Contains("Success") -eq $false) { Write-Host "WN22-DC-000240 - $directoryServiceAccessCheck" }
			if ($directoryServiceAccessCheck.Contains("Failure") -eq $false) { Write-Host "WN22-DC-000250 - $directoryServiceAccessCheck" }

			$directoryServiceChangesAudit = $auditPolicyAll | Select-String "Directory Service Changes" | Out-String
			if ($directoryServiceChangesAudit.Contains("Success") -eq $false) { Write-Host "WN22-DC-000260 - $directoryServiceChangesAudit" }
			
			$ntdsParameters = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\"
			if ($ntdsParameters.LDAPServerIntegrity -ne 2) { Write-Host "WN22-DC-000320 - $($ntdsParameters.LDAPServerIntegrity)" }
			
			if ($netLogonParameters.RefusePasswordChange -ne 0) { Write-Host "WN22-DC-000330 - $($netLogonParameters.RefusePasswordChange)" }
			
			$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-11*","*S-1-5-9*")
			$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] -and $_ -notlike $allowedSIDs[2] }
			if ($disallowedSIDs) { Write-Host "WN22-DC-000340 - $disallowedSIDs" }

			$machineAccountPrivilegeSID = ($policyContent | Select-String "SeMachineAccountPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			if ($machineAccountPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN22-DC-000350 - $($machineAccountPrivilegeSID)" }

			$remoteInteractiveLogonRightSID = ($policyContent | Select-String "SeRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			if ($remoteInteractiveLogonRightSID -notlike "*S-1-5-32-544") { Write-Host "WN22-DC-000360 - $($remoteInteractiveLogonRightSID)" }

			$denyNetworkLogonRightSID = $policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String
			if ($denyNetworkLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN22-DC-000370 - $($denyNetworkLogonRightSID)" }

			$denyBatchLogonRightSID = $policyContent | Select-String "SeDenyBatchLogonRight" | Out-String
			if ($denyBatchLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN22-DC-000380 - $($denyBatchLogonRightSID)" }

			$denyServiceLogonRightSID = $policyContent | Select-String "SeDenyServiceLogonRight" | Out-String
			if ($denyServiceLogonRightSID.Contains("*S-1") -eq $true) { Write-Host "WN22-DC-000390 - $($denyServiceLogonRightSID)" }

			$denyInteractiveLogonRightSID = $policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String
			if ($denyInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN22-DC-000400 - $($denyInteractiveLogonRightSID)" }

			$denyRemoteInteractiveLogonRightSID = $policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String
			if ($denyRemoteInteractiveLogonRightSID.Contains("*S-1-5-32-546") -eq $false) { Write-Host "WN22-DC-000410 - $($denyRemoteInteractiveLogonRightSID)" }

			$enableDelegationPrivilegeCheckSID = ($policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			if ($enableDelegationPrivilegeCheckSID -notlike "*S-1-5-32-544") { Write-Host "WN22-DC-000420 - $($enableDelegationPrivilegeCheckSID)" }

			$krbtgtAccount = Get-ADUser krbtgt -Property PasswordLastSet
			$daysSincePasswordChange = ((Get-Date) - $krbtgtAccount.PasswordLastSet).Days
			if ($daysSincePasswordChange -gt 180) { Write-Host "WN22-DC-000430 - $($krbtgtAccount.PasswordLastSet)" }

		}

		#Member Server and Standalone Server Checks
		if ($csDomainRole -eq "MemberServer" -or $csDomainRole -eq "StandaloneServer") {
			
			if ($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy -ne 0) { Write-Host "WN22-MS-000020 - $($currentVersionSystemPolicies.LocalAccountTokenFilterPolicy)" }
			if ($windowsSystemChecks.EnumerateLocalUsers -ne 0) { Write-Host "WN22-MS-000030 - $($windowsSystemChecks.EnumerateLocalUsers)" }

			$windowsntRPCCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\"
			if ($windowsntRPCCheck.RestrictRemoteClients -ne 1) { Write-Host "WN22-MS-000040 - $($windowsntRPCCheck.RestrictRemoteClients)" }

			if ($windowsntWinLogon.CachedLogonsCount -gt 4) { Write-Host "WN22-MS-000050 - $($windowsntWinLogon.CachedLogonsCount)" }

			if ($lsaSettings.RestrictRemoteSAM -ne "O:BAG:BAD:(A;;RC;;;BA)") { Write-Host "WN22-MS-000060 - $($lsaSettings.RestrictRemoteSAM)" }

			$accessThisComputerCheck = ($policyContent | Select-String "SeNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
			$allowedSIDs = @("*S-1-5-32-544", "*S-1-5-11*")
			$disallowedSIDs = $accessThisComputerCheck | Where-Object { $_ -notlike $allowedSIDs[0] -and $_ -notlike $allowedSIDs[1] }
			if ($disallowedSIDs) { Write-Host "WN22-MS-000070 - $disallowedSIDs" }

			$vbsSecurityServicesRunning = $vbsDetailsCheck.SecurityServicesRunning | Out-String
			if ($vbsSecurityServicesRunning.Contains("2") -eq $false) { Write-Host "WN22-MS-000140 - $($vbsSecurityServicesRunning)" }

			$enableDelegationPrivilegeCheck = $policyContent | Select-String "SeEnableDelegationPrivilege" | Out-String
			if ($enableDelegationPrivilegeCheck.Contains("*S-1") -eq $true) { Write-Host "WN22-MS-000310 - $($enableDelegationPrivilegeCheck)" }
			
			if ($CsDomainRole -ne "StandaloneServer") {
				
				$denyAccessToThisComputerSIDs = ($policyContent | Select-String "SeDenyNetworkLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
				$allowedDenyAccessToThisComputerSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546", "*S-1-5-114", "*S-1-5-113")
				$disallowedDenyAccessToThisComputerSIDs = $denyAccessToThisComputerSIDs | Where-Object { $_ -notlike $allowedDenyAccessToThisComputerSIDs[0] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[1] -and $_ -notlike $allowedDenyAccessToThisComputerSIDs[2] }
				if ($disallowedDenyAccessToThisComputerSIDs) { Write-Host "WN22-MS-000080 - $disallowedDenyAccessToThisComputerSIDs" }
				
				$denyBatchLogonRightSIDs = ($policyContent | Select-String "SeDenyBatchLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
				$allowedBatchLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
				$disallowedBatchLogonRightSIDs = $denyBatchLogonRightSIDs | Where-Object { $_ -notlike $allowedBatchLogonRightSIDs[0] -and $_ -notlike $allowedBatchLogonRightSIDs[1] -and $_ -notlike $allowedBatchLogonRightSIDs[2] }
				if ($disallowedBatchLogonRightSIDs) { Write-Host "WN22-MS-000090 - $disallowedBatchLogonRightSIDs" }
				
				$denyServiceLogonRightSIDS = ($policyContent | Select-String "SeDenyServiceLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
				$allowedServiceLogonRightSIDS = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512")
				$disallowedServiceLogonRightSIDS = $denyServiceLogonRightSIDS | Where-Object { $_ -notlike $allowedServiceLogonRightSIDS[0] -and $_ -notlike $allowedServiceLogonRightSIDS[1] }
				if ($disallowedServiceLogonRightSIDS) { Write-Host "WN22-MS-000100 - $disallowedBatchLogonRightSIDs" }
				
				$denyInteractiveLogonRightSIDs = ($policyContent | Select-String "SeDenyInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
				$allowedInteractiveLogonRightSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546")
				$disallowedInteractiveLogonRightSIDs = $denyInteractiveLogonRightSIDs | Where-Object { $_ -notlike $allowedInteractiveLogonRightSIDs[0] -and $_ -notlike $allowedInteractiveLogonRightSIDs[1] -and $_ -notlike $allowedInteractiveLogonRightSIDs[2] }
				if ($disallowedInteractiveLogonRightSIDs) { Write-Host "WN22-MS-000110 - $disallowedBatchLogonRightSIDs" }
				
				$denyLogOnThroughRemoteDesktopServicesSIDs = ($policyContent | Select-String "SeDenyRemoteInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
				$allowedDenyLogOnThroughRemoteDesktopServicesSIDs = @("*S-1-5-21-Replace_With_Domain_Info-519", "*S-1-5-21-Replace_With_Domain_Info-512", "*S-1-5-32-546", "*S-1-5-113")
				$disallowedDenyLogOnThroughRemoteDesktopServicesSIDs = $denyLogOnThroughRemoteDesktopServicesSIDs | Where-Object { $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[0] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[1] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[2] -and $_ -notlike $allowedDenyLogOnThroughRemoteDesktopServicesSIDs[3] }
				if ($disallowedDenyLogOnThroughRemoteDesktopServicesSIDs) { Write-Host "WN22-MS-000120 - $disallowedDenyLogOnThroughRemoteDesktopServicesSIDs" }
				
			}
			
			if ($edge -ne $null) {
			
			$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ 2>$null
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
				
			}
			
			foreach ($possibleFirefoxUser in $validFirefoxUsers) {
				$firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
				if (Test-Path $firefoxPath) {
					$profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
					if ($profilePath) {
						$firefoxPreferences = Get-Content "$profilePath\prefs.js" 2>$null | Out-String
						$firefoxHandlers = Get-Content "$profilePath\handlers.json" 2>$null | Out-String
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
				   if ($firefoxPreferences.Contains('"extensions.update.enabled", false') -eq $false) {
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

			$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission 2>$null
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

			$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay 2>$null
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

			$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection 2>$null
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

			$disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers 2>$null
			if ($disabledFirefoxCiphers -ne $null) {
			   if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false") -and $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
			} else {
			   if ($firefoxPreferences -ne $null) {
				   if ($firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) { Write-Host "FFOX-00-000027" }
			   }
			}

			$firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging 2>$null
			if ($firefoxUserMessaging -ne $null) {
			   if ($firefoxUserMessaging.ExtensionRecommendations -ne "0" -and $firefoxPreferences -ne $null -and $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
			} else {
			   if ($firefoxPreferences -ne $null) {
				   if ($firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false -and $mozillaCfg -ne $null -and $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) { Write-Host "FFOX-00-000028" }
				}
			}

			$firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage 2>$null
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
		}

		$disableBuiltInGuestAccountCheck = $policyContent | Select-String "EnableGuestAccount" | Out-String
		if ($disableBuiltInGuestAccountCheck.Contains("1") -eq $true) { Write-Host "WN22-SO-000010 - $($disableBuiltInGuestAccountCheck)" }

		if ($lsaSettings.LimitBlankPasswordUse -ne 1) { Write-Host "WN22-SO-000020 - $($lsaSettings.LimitBlankPasswordUse)" }

		$newAdminName = $policyContent | Select-String "NewAdministratorName" | Out-String
		if ($newAdminName.Contains("Administrator") -eq $true) { Write-Host "WN22-SO-000030 - $($newAdminName)" }

		$newGuestName = $policyContent | Select-String "NewGuestName" | Out-String
		if ($newGuestName -match '="Guest"') { Write-Host "WN22-SO-000040 - $($newGuestName)" }

		if ($lsaSettings.SCENoApplyLegacyAuditPolicy -ne 1) { Write-Host "WN22-SO-000050 - $($lsaSettings.SCENoApplyLegacyAuditPolicy)" }

		if ($netLogonParameters.RequireSignOrSeal -ne 1) { Write-Host "WN22-SO-000060 - $($netLogonParameters.RequireSignOrSeal)" }
		if ($netLogonParameters.SealSecureChannel -ne 1) { Write-Host "WN22-SO-000070 - $($netLogonParameters.SealSecureChannel)" }
		if ($netLogonParameters.SignSecureChannel -ne 1) { Write-Host "WN22-SO-000080 - $($netLogonParameters.SignSecureChannel)" }
		if ($netLogonParameters.DisablePasswordChange -ne 0) { Write-Host "WN22-SO-000090 - $($netLogonParameters.DisablePasswordChange)" }
		if ($netLogonParameters.MaximumPasswordAge -gt 30 -or $netLogonParameters.MaximumPasswordAge -eq 0) { Write-Host "WN22-SO-000100 - $($netLogonParameters.MaximumPasswordAge)" }
		if ($netLogonParameters.RequireStrongKey -ne 1) { Write-Host "WN22-SO-000110 - $($netLogonParameters.RequireStrongKey)" }

		if ($currentVersionSystemPolicies.InactivityTimeoutSecs -notin 1..900) { Write-Host "WN22-SO-000120 - $($currentVersionSystemPolicies.InactivityTimeoutSecs)" }
		if ($currentVersionSystemPolicies.LegalNoticeText -eq $null) { Write-Host "WN22-SO-000130 - $($currentVersionSystemPolicies.LegalNoticeText)" }
		if ($currentVersionSystemPolicies.LegalNoticeCaption -eq $null) { Write-Host "WN22-SO-000140 - $($currentVersionSystemPolicies.LegalNoticeCaption)" }

		$lanmanWorkstationParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
		if ($lanmanWorkstationParameters.RequireSecuritySignature -ne 1) { Write-Host "WN22-SO-000160 - $($lanmanWorkstationParameters.RequireSecuritySignature)" }
		if ($lanmanWorkstationParameters.EnableSecuritySignature -ne 1) { Write-Host "WN22-SO-000170 - $($lanmanWorkstationParameters.EnableSecuritySignature)" }
		if ($lanmanWorkstationParameters.EnablePlainTextPassword -ne 0) { Write-Host "WN22-SO-000180 - $($lanmanWorkstationParameters.EnablePlainTextPassword)" }

		$lanmanServerParameters = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
		if ($lanmanServerParameters.RequireSecuritySignature -ne 1) { Write-Host "WN22-SO-000190 - $($lanmanServerParameters.RequireSecuritySignature)" }
		if ($lanmanServerParameters.EnableSecuritySignature -ne 1) { Write-Host "WN22-SO-000200 - $($lanmanServerParameters.EnableSecuritySignature)" }

		$lsaAnonymousName = $policyContent | Select-String "LsaAnonymousNameLookup" | Out-String
		if ($lsaAnonymousName.Contains("1") -eq $true) { Write-Host "WN22-SO-000210 - $($lsaAnonymousName)" }

		if ($lsaSettings.RestrictAnonymousSAM -ne 1) { Write-Host "WN22-SO-000220 - $($lsaSettings.RestrictAnonymousSAM)" }
		if ($lsaSettings.RestrictAnonymous -ne 1) { Write-Host "WN22-SO-000230 - $($lsaSettings.RestrictAnonymous)" }
		if ($lsaSettings.EveryoneIncludesAnonymous -ne 0) { Write-Host "WN22-SO-000240 - $($lsaSettings.EveryoneIncludesAnonymous)" }

		if ($lanmanServerParameters.RestrictNullSessAccess -ne 1) { Write-Host "WN22-SO-000250 - $($lanmanServerParameters.RestrictNullSessAccess)" }

		if ($lsaSettings.UseMachineId -ne 1) { Write-Host "WN22-SO-000260 - $($lsaSettings.UseMachineId)" }

		$lsaMSV = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
		if ($lsaMSV.allownullsessionfallback -ne 0) { Write-Host "WN22-SO-000270 - $($lsaMSV.allownullsessionfallback)" }

		$lsaPKU2U = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\
		if ($lsaPKU2U.AllowOnlineID -ne 0) { Write-Host "WN22-SO-000280 - $($lsaPKU2U.AllowOnlineID)" }

		$kerbParameters = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
		if ($csDomainRole -eq "PrimaryDomainController" -or $csDomainRole -eq "BackupDomainController") {
			if ($kerbParameters.SupportedEncryptionTypes -ne 2147483640) { Write-Host "WN22-SO-000290 - $($kerbParameters.SupportedEncryptionTypes)" }
		}

		if ($lsaSettings.NoLMHash -ne 1) { Write-Host "WN22-SO-000300 - $($lsaSettings.NoLMHash)" }
		if ($lsaSettings.LmCompatibilityLevel -ne 5) { Write-Host "WN22-SO-000310 - $($lsaSettings.LmCompatibilityLevel)" }

		$ldapServicesCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\
		if ($ldapServicesCheck.LDAPClientIntegrity -ne 1) { Write-Host "WN22-SO-000320 - $($ldapServicesCheck.LDAPClientIntegrity)" }

		if ($lsaMSV.NTLMMinClientSec -ne 537395200) { Write-Host "WN22-SO-000330 - $($lsaMSV.NTLMMinClientSec)" }
		if ($lsaMSV.NtlmMinServerSec -ne 537395200) { Write-Host "WN22-SO-000340 - $($lsaMSV.NtlmMinServerSec)" }

		$microsoftCryptographyCheck = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\
		if ($microsoftCryptographyCheck.ForceKeyProtection -ne 2) { Write-Host "WN22-SO-000350 - $($microsoftCryptographyCheck.ForceKeyProtection)" }

		$lsaFIPSCheck = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
		if ($lsaFIPSCheck.Enabled -ne 1) { Write-Host "WN22-SO-000360 - $($lsaFIPSCheck.Enabled)" }

		$registrySessionManagerCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
		if ($registrySessionManagerCheck.ProtectionMode -ne 1) { Write-Host "WN22-SO-000370 - $($registrySessionManagerCheck.ProtectionMode)" }

		if ($currentVersionSystemPolicies.FilterAdministratorToken -ne 1) { Write-Host "WN22-SO-000380 - $($currentVersionSystemPolicies.FilterAdministratorToken)" }
		if ($currentVersionSystemPolicies.EnableUIADesktopToggle -ne 0) { Write-Host "WN22-SO-000390 - $($currentVersionSystemPolicies.EnableUIADesktopToggle)" }
		if ($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin -notin @(1, 2)) { Write-Host "WN22-SO-000400 - $($currentVersionSystemPolicies.ConsentPromptBehaviorAdmin)" }
		if ($currentVersionSystemPolicies.ConsentPromptBehaviorUser -ne 0) { Write-Host "WN22-SO-000410 - $($currentVersionSystemPolicies.ConsentPromptBehaviorUser)" }
		if ($currentVersionSystemPolicies.EnableInstallerDetection -ne 1) { Write-Host "WN22-SO-000420 - $($currentVersionSystemPolicies.EnableInstallerDetection)" }
		if ($currentVersionSystemPolicies.EnableSecureUIAPaths -ne 1) { Write-Host "WN22-SO-000430 - $($currentVersionSystemPolicies.EnableSecureUIAPaths)" }
		if ($currentVersionSystemPolicies.EnableLUA -ne 1) { Write-Host "WN22-SO-000440 - $($currentVersionSystemPolicies.EnableLUA)" }
		if ($currentVersionSystemPolicies.EnableVirtualization -ne 1) { Write-Host "WN22-SO-000450 - $($currentVersionSystemPolicies.EnableVirtualization)" }

		$attachmentPoliciesCheck = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
		if ($attachmentPoliciesCheck.SaveZoneInformation -eq 1) { Write-Host "WN22-UC-000010 - $($attachmentPoliciesCheck.SaveZoneInformation)" }

		$accessCredManagerCheck = $policyContent | Select-String "SeTrustedCredManAccessPrivilege" | Out-String
		if ($accessCredManagerCheck.Contains("*S-1") -eq $true) { Write-Host "WN22-UR-000010 - $($accessCredManagerCheck)" }

		$actAsPartofOSCheck = $policyContent | Select-String "SeTcbPrivilege" | Out-String
		if ($actAsPartofOSCheck.Contains("*S-1") -eq $true) { Write-Host "WN22-UR-000020 - $($actAsPartofOSCheck)" }

		$logOnLocallySIDs = ($policyContent | Select-String "SeInteractiveLogonRight" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedLogonSIDs = @("*S-1-5-32-544", "*S-1-5-32-545")
		$disallowedLogonSIDs = $logOnLocallySIDs | Where-Object { $_ -notlike $allowedLogonSIDs[0] -and $_ -notlike $allowedLogonSIDs[1] }
		if ($disallowedLogonSIDs.Count -gt 0) { Write-Host "WN22-UR-000030 - $($disallowedLogonSIDs)" }

		$backupPrivilegeSIDs = ($policyContent | Select-String "SeBackupPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedBackupSIDs = @("*S-1-5-32-544")
		$disallowedBackupSIDs = $backupPrivilegeSIDs | Where-Object { $_ -notlike $allowedBackupSIDs[0] }
		if ($disallowedBackupSIDs.Count -gt 0) { Write-Host "WN22-UR-000040 - $($disallowedBackupSIDs)" }

		$createPagefileSID = ($policyContent | Select-String "SeCreatePagefilePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($createPagefileSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000050 - $($createPagefileSID)" }

		$createTokenObjectsSID = $policyContent | Select-String "SeCreateTokenPrivilege" | Out-String
		if ($createTokenObjectsSID.Contains("*S-1") -eq $true) { Write-Host "WN22-UR-000060 - $($createTokenObjectsSID)" }

		$createGlobalPrivilegeSID = ($policyContent | Select-String "SeCreateGlobalPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedCreateGlobalSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
		$disallowedCreateGlobalSIDs = $createGlobalPrivilegeSID | Where-Object { $_ -notlike $allowedCreateGlobalSIDs[0] -and $_ -notlike $allowedCreateGlobalSIDs[1] -and $_ -notlike $allowedCreateGlobalSIDs[2] -and $_ -notlike $allowedCreateGlobalSIDs[3] }
		if ($disallowedCreateGlobalSIDs.Count -gt 0) { Write-Host "WN22-UR-000070 - $($disallowedCreateGlobalSIDs)" }

		$createPermanentSharedObjectSID = $policyContent | Select-String "SeCreatePermanentPrivilege" | Out-String
		if ($createPermanentSharedObjectSID.Contains("*S-1") -eq $true) { Write-Host "WN22-UR-000080 - $($createPermanentSharedObjectSID)" }

		$createSymbolicLinkSID = ($policyContent | Select-String "SeCreateSymbolicLinkPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($createSymbolicLinkSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000090 - $($createSymbolicLinkSID)" }

		$debugPrivilegeSID = ($policyContent | Select-String "SeDebugPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($debugPrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000100 - $($debugPrivilegeSID)" }

		$forceShutdownFromRemoteSystemSID = ($policyContent | Select-String "SeRemoteShutdownPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($forceShutdownFromRemoteSystemSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000110 - $($forceShutdownFromRemoteSystemSID)" }

		$auditPrivilegeSID = ($policyContent | Select-String "SeAuditPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedAuditSIDs = @("*S-1-5-19", "*S-1-5-20")
		$disallowedAuditSIDs = $auditPrivilegeSID | Where-Object { $_ -notlike $allowedAuditSIDs[0] -and $_ -notlike $allowedAuditSIDs[1] }
		if ($disallowedAuditSIDs.Count -gt 0) { Write-Host "WN22-UR-000120 - $($disallowedAuditSIDs)" }

		$impersonateAClientAfterAuthenticationSID = ($policyContent | Select-String "SeImpersonatePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		$allowedImpersonateSIDs = @("*S-1-5-32-544", "*S-1-5-6", "*S-1-5-19", "*S-1-5-20")
		$disallowedImpersonateSIDs = $impersonateAClientAfterAuthenticationSID | Where-Object { $_ -notlike $allowedImpersonateSIDs[0] -and $_ -notlike $allowedImpersonateSIDs[1] -and $_ -notlike $allowedImpersonateSIDs[2] -and $_ -notlike $allowedImpersonateSIDs[3] }
		if ($disallowedImpersonateSIDs.Count -gt 0) { Write-Host "WN22-UR-000130 - $($disallowedImpersonateSIDs)" }

		$increaseBasePrioritySID = ($policyContent | Select-String "SeIncreaseBasePriorityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($increaseBasePrioritySID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000140 - $($increaseBasePrioritySID)" }

		$loadDriverSID = ($policyContent | Select-String "SeLoadDriverPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($loadDriverSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000150 - $($loadDriverSID)" }

		$lockMemorySID = $policyContent | Select-String "SeLockMemoryPrivilege" | Out-String
		if ($lockMemorySID.Contains("*S-1") -eq $true) { Write-Host "WN22-UR-000160 - $($lockMemorySID)" }

		$manageAuditingAndSecurityLogSID = ($policyContent | Select-String "SeSecurityPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($manageAuditingAndSecurityLogSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000170 - $($manageAuditingAndSecurityLogSID)" }

		$modifyFirmwareEnvironmentSID = ($policyContent | Select-String "SeSystemEnvironmentPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($modifyFirmwareEnvironmentSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000180 - $($modifyFirmwareEnvironmentSID)" }

		$performVolumeMaintenanceSID = ($policyContent | Select-String "SeManageVolumePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($performVolumeMaintenanceSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000190 - $($performVolumeMaintenanceSID)" }

		$profileSingleProcessSID = ($policyContent | Select-String "SeProfileSingleProcessPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($profileSingleProcessSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000200 - $($profileSingleProcessSID)" }

		$restorePrivilegeSID = ($policyContent | Select-String "SeRestorePrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($restorePrivilegeSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000210 - $($restorePrivilegeSID)" }

		$takeOwnershipSID = ($policyContent | Select-String "SeTakeOwnershipPrivilege" | Out-String) -replace '.*=\s*' -split ',' | Where-Object { $_ -match 'S-1-\d+-\d+(-\d+)*' } | ForEach-Object { $_.Trim() }
		if ($takeOwnershipSID -notlike "*S-1-5-32-544") { Write-Host "WN22-UR-000220 - $($takeOwnershipSID)" }
			
	}
	
}
Stop-Transcript

