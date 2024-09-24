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
