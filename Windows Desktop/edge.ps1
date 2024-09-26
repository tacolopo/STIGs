"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Edge V2R1"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000001"
# "User control of proxy settings must be disabled."
$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\
$edgeProxySettings = $baseEdgeSettings.ProxySettings | Out-String
if ($edgeProxySettings.Contains("ProxyMode")) {
    $acceptableValues = @('direct', 'system', 'auto_detect', 'fixed_servers', 'pac_script')
    if (-not ($acceptableValues | Where-Object { $edgeProxySettings.Contains($_) })) {
        Write-Output "EDGE-00-000001"
    }
} else {
    $acceptableValues = @("ProxyPacUrl", "ProxyServer", "ProxyBypassList")
    if (-not ($acceptableValues | Where-Object { $edgeProxySettings.Contains($_) })) {
        Write-Output "EDGE-00-000001"
    }
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000002"
# "Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled."
if ($baseEdgeSettings.PreventSmartScreenPromptOverride -ne 1) { Write-Output "EDGE-00-000002" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000003"
# "Bypassing of Microsoft Defender SmartScreen warnings about downloads must be disabled."
if ($baseEdgeSettings.PreventSmartScreenPromptOverrideForFiles -ne 1) { Write-Output "EDGE-00-000003" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000004"
# "This requirement for 'SmartScreenAllowListDomains' is not required; this is optional."

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000005"
# "InPrivate mode must be disabled."
if ($baseEdgeSettings.InPrivateModeAvailability -ne 1) { Write-Output "EDGE-00-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000006"
# "Background processing must be disabled."
if ($baseEdgeSettings.BackgroundModeEnabled -ne 0) { Write-Output "EDGE-00-000006" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000008"
# "The ability of sites to show pop-ups must be disabled."
if ($baseEdgeSettings.DefaultPopupsSetting -ne 2) { Write-Output "EDGE-00-000008" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000009"
# "The default search provider must be set to use an encrypted connection."
$edgeManagedSearchEngines = $baseEdgeSettings.ManagedSearchEngines | ConvertFrom-Json
$edgeNonHttpsSearchEngines = $edgeManagedSearchEngines | Where-Object { $_.search_url -notmatch '^https://' }

if ($edgeNonHttpsSearchEngines) { Write-Output "EDGE-00-000009" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000010"
# "Data Synchronization must be disabled."
if ($baseEdgeSettings.SyncDisabled -ne 1) { Write-Output "EDGE-00-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000011"
# "Network prediction must be disabled."
if ($baseEdgeSettings.NetworkPredictionOptions -ne 2) { Write-Output "EDGE-00-000011" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000012"
# "Search suggestions must be disabled."
if ($baseEdgeSettings.SearchSuggestEnabled -ne 0) { Write-Output "EDGE-00-000012" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000013"
# "Importing of autofill form data must be disabled."
if ($baseEdgeSettings.ImportAutofillFormData -ne 0) { Write-Output "EDGE-00-000013" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000014"
# "Importing of browser settings must be disabled."
if ($baseEdgeSettings.ImportBrowserSettings -ne 0) { Write-Output "EDGE-00-000014" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000015"
# "Importing of cookies must be disabled."
if ($baseEdgeSettings.ImportCookies -ne 0) { Write-Output "EDGE-00-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000016"
# "Importing of extensions must be disabled."
if ($baseEdgeSettings.ImportExtensions -ne 0) { Write-Output "EDGE-00-000016" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000017"
# "Importing of browsing history must be disabled."
if ($baseEdgeSettings.ImportHistory -ne 0) { Write-Output "EDGE-00-000017" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000018"
# "Importing of home page settings must be disabled."
if ($baseEdgeSettings.ImportHomepage -ne 0) { Write-Output "EDGE-00-000018" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000019"
# "Importing of open tabs must be disabled."
if ($baseEdgeSettings.ImportOpenTabs -ne 0) { Write-Output "EDGE-00-000019" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000020"
# "Importing of payment info must be disabled."
if ($baseEdgeSettings.ImportPaymentInfo -ne 0) { Write-Output "EDGE-00-000020" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000021"
# "Importing of saved passwords must be disabled."
if ($baseEdgeSettings.ImportSavedPasswords -ne 0) { Write-Output "EDGE-00-000021" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000022"
# "Importing of search engine settings must be disabled."
if ($baseEdgeSettings.ImportSearchEngine -ne 0) { Write-Output "EDGE-00-000022" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000023"
# "Importing of shortcuts must be disabled."
if ($baseEdgeSettings.ImportShortcuts -ne 0) { Write-Output "EDGE-00-000023" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000024"
# "Autoplay must be disabled."
if ($baseEdgeSettings.AutoplayAllowed -ne 0) { Write-Output "EDGE-00-000024" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000025"
# "WebUSB must be disabled."
if ($baseEdgeSettings.DefaultWebUsbGuardSetting -ne 2) { Write-Output "EDGE-00-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000026"
# "Google Cast must be disabled."
if ($baseEdgeSettings.EnableMediaRouter -ne 0) { Write-Output "EDGE-00-000026" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000027"
# "Web Bluetooth API must be disabled."
if ($baseEdgeSettings.DefaultWebBluetoothGuardSetting -ne 2) { Write-Output "EDGE-00-000027" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000028"
# "Autofill for Credit Cards must be disabled."
if ($baseEdgeSettings.AutofillCreditCardEnabled -ne 0) { Write-Output "EDGE-00-000028" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000029"
# "Autofill for addresses must be disabled."
if ($baseEdgeSettings.AutofillAddressEnabled -ne 0) { Write-Output "EDGE-00-000029" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000030"
# "Online revocation checks must be performed."
if ($baseEdgeSettings.EnableOnlineRevocationChecks -ne 1) { Write-Output "EDGE-00-000030" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000031"
# "Personalization of ads, search, and news by sending browsing history to Microsoft must be disabled."
if ($baseEdgeSettings.PersonalizationReportingEnabled -ne 0) { Write-Output "EDGE-00-000031" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000032"
# "Site tracking of a user’s location must be disabled."
if ($baseEdgeSettings.DefaultGeolocationSetting -ne 2) { Write-Output "EDGE-00-000032" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000033"
# "Browser history must be saved."
if ($baseEdgeSettings.AllowDeletingBrowserHistory -ne 0) { Write-Output "EDGE-00-000033" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000034"
# "Edge development tools must be disabled."
if ($baseEdgeSettings.DeveloperToolsAvailability -ne 2) { Write-Output "EDGE-00-000034" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000036"
# "Download restrictions must be configured."
if ($baseEdgeSettings.DownloadRestrictions -in @(0, 4)) { Write-Output "EDGE-00-000036" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000039"
# "URLs must be allowlisted for plugin use if used."
# "This requirement for 'Allow pop-up windows on specific sites' is not required; this is optional."

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000041"
# "Extensions installation must be blocklisted by default."
$edgeExtensionInstallBlocklist = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist\
if ($edgeExtensionInstallBlocklist.1 -ne "*") { Write-Output "EDGE-00-000041" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000042"
# "Extensions that are approved for use must be allowlisted if used."
# "This requirement for 'Allow specific extensions to be installed' is not required; this is optional."

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000043"
# "The Password Manager must be disabled."
if ($baseEdgeSettings.PasswordManagerEnabled -ne 0) { Write-Output "EDGE-00-000043" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000045"
# "The version of Microsoft Edge running on the system must be a supported version."
$edgeVersionCheck = (Get-AppxPackage -Name "Microsoft.MicrosoftEdge.Stable").Version
if ($edgeVersionCheck -lt "127") { Write-Output "EDGE-00-000045" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000046"
# "Edge must be configured to allow only TLS."
if ($baseEdgeSettings.SSLVersionMin -ne "tls1.2") { Write-Output "EDGE-00-000046" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000047"
# "Site isolation for every site must be enabled."
if ($baseEdgeSettings.SitePerProcess -ne 1) { Write-Output "EDGE-00-000047" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000048"
# "Supported authentication schemes must be configured."
if ($baseEdgeSettings.AuthSchemes -ne "ntlm,negotiate") { Write-Output "EDGE-00-000048" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000050"
# "Microsoft Defender SmartScreen must be enabled."
if ($baseEdgeSettings.SmartScreenEnabled -ne 1) { Write-Output "EDGE-00-000050" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000051"
# "Microsoft Defender SmartScreen must be configured to block potentially unwanted apps."
if ($baseEdgeSettings.SmartScreenPuaEnabled -ne 1) { Write-Output "EDGE-00-000051" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000052"
# "The download location prompt must be configured."
if ($baseEdgeSettings.PromptForDownloadLocation -ne 1) { Write-Output "EDGE-00-000052" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000054"
# "Tracking of browsing activity must be disabled."
if ($baseEdgeSettings.TrackingPrevention -notin @(2, 3)) { Write-Output "EDGE-00-000054" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000055"
# "A website's ability to query for payment methods must be disabled."
if ($baseEdgeSettings.PaymentMethodQueryEnabled -ne 0) { Write-Output "EDGE-00-000055" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000056"
# "Suggestions of similar web pages in the event of a navigation error must be disabled."
if ($baseEdgeSettings.AlternateErrorPagesEnabled -ne 0) { Write-Output "EDGE-00-000056" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000057"
# "User feedback must be disabled."
if ($baseEdgeSettings.UserFeedbackAllowed -ne 0) { Write-Output "EDGE-00-000057" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000058"
# "The collections feature must be disabled."
if ($baseEdgeSettings.EdgeCollectionsEnabled -ne 0) { Write-Output "EDGE-00-000058" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000059"
# "The Share Experience feature must be disabled."
if ($baseEdgeSettings.ConfigureShare -ne 1) { Write-Output "EDGE-00-000059" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000060"
# "Guest mode must be disabled."
if ($baseEdgeSettings.BrowserGuestModeEnabled -ne 0) { Write-Output "EDGE-00-000060" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000061"
# "Relaunch notification must be required."
if ($baseEdgeSettings.RelaunchNotification -ne 2) { Write-Output "EDGE-00-000061" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000062"
# "The built-in DNS client must be disabled."
if ($baseEdgeSettings.BuiltInDnsClientEnabled -ne 0) { Write-Output "EDGE-00-000062" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000063"
# "Use of the QUIC protocol must be disabled."
if ($baseEdgeSettings.QuicAllowed -ne 0) { Write-Output "EDGE-00-000063" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000064"
# "The list of domains media autoplay allows must be allowlisted if used."
# "This requirement for 'AutoplayAllowlist' is not required; this is optional."

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000065"
# "Visual Search must be disabled."
if ($baseEdgeSettings.VisualSearchEnabled -ne 0) { Write-Output "EDGE-00-000065" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000066"
# "Copilot must be disabled."
if ($baseEdgeSettings.HubsSidebarEnabled -ne 0) { Write-Output "EDGE-00-000066" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000067"
# "Session only-based cookies must be enabled."
if ($baseEdgeSettings.DefaultCookiesSetting -ne 4) { Write-Output "EDGE-00-000067" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"
