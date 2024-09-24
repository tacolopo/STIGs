"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft Edge V2R1"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000001"
# "User control of proxy settings must be disabled."
$baseEdgeSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\
$edgeProxySettings = $baseEdgeSettings.ProxySettings | Out-String
$acceptableValues = @('direct', 'system', 'auto_detect', 'fixed_servers', 'pac_script')
if (-not ($acceptableValues | Where-Object { $edgeProxySettings.Contains($_) })) {
    Write-Output "EDGE-00-000001"
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "EDGE-00-000002"
# "Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled."
if ($baseEdgeSettings.PreventSmartScreenOverride -ne 1) { Write-Output "EDGE-00-000002" }

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

