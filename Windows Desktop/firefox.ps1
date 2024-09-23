"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Mozilla Firefox V6R5"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#Registry Keys come from https://admx.help?Category=Firefox&Policy=Mozilla.Policies.Firefox and https://mozilla.github.io/policy-templates/

# "FFOX-00-000001"
# "The installed version of Firefox must be supported."
$firefoxVersion = (Get-ItemProperty "HKLM:\Software\Mozilla\Mozilla Firefox").CurrentVersion | Out-String
if ($firefoxVersion.Contains("130.0") -eq $false) { Write-Output "FFOX-00-000001" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000002"
# "Firefox must be configured to allow only TLS 1.2 or above."
$firefoxSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\
if ($firefoxSettings.SSLVersionMin -ne "tls1.2") { Write-Output "FFOX-00-000002" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000003"
# "Firefox must be configured to ask which certificate to present to a website when a certificate is required."
$validFirefoxUsers = Get-ChildItem C:\Users | Where-Object { $_.PSIsContainer }
foreach ($possibleFirefoxUser in $validFirefoxUsers) {
    $firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
    if (Test-Path $firefoxPath) {
        $profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
        if ($profilePath) {
            $firefoxPreferences = Get-Content "$profilePath\prefs.js"
            break
        }
    }
}
if ($firefoxPreferences -notcontains 'user_pref("security.default_personal_cert", "Ask Every Time");') { Write-Output "FFOX-00-000003" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000004"
# "Firefox must be configured to not automatically check for updated versions of installed search plugins."
if ($firefoxPreferences -notcontains 'user_pref("browser.search.update", false);') { Write-Output "FFOX-00-000004" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000005"
# "Firefox must be configured to not automatically update installed add-ons and plugins."
if ($firefoxSettings.ExtensionUpdate -ne "0") { Write-Output "FFOX-00-000005" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000006"
# "Firefox must be configured to not automatically execute or download MIME types that are not authorized for auto-download."

foreach ($possibleFirefoxUser in $validFirefoxUsers) {
    $firefoxPath = "$($possibleFirefoxUser.FullName)\AppData\Roaming\Mozilla\Firefox"
    if (Test-Path $firefoxPath) {
        $profilePath = Get-ChildItem -Path "$firefoxPath\Profiles" -Directory | Where-Object { $_.Name -like "*.default-release" } | Select-Object -First 1 -ExpandProperty FullName
        if ($profilePath) {
            $firefoxHandlers = Get-Content "$profilePath\handlers.json"
            break
        }
    }
}
$list = @("HTA", "JSE", "JS", "MOCHA", "SHS", "VBE", "VBS", "SCT", "WSC", "FDF", "XFDF", "LSL", "LSO", "LSS", "IQY", "RQY", "DOS", "BAT", "PS", "EPS", "WCH", "WCM", "WB1", "WB3", "WCH", "WCM", "AD")

foreach ($item in $list) {
    if ($firefoxHandlers.Contains($item)) {
        Write-Output "FFOX-00-000006"
        break
    }
}

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000007"
# "Firefox must be configured to disable form fill assistance."
if ($firefoxSettings.DisableFormHistory -ne "1") { Write-Output "FFOX-00-000007" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000008"
# "Firefox must be configured to not use a password store with or without a master password."
if ($firefoxSettings.PasswordManagerEnabled -ne "0") { Write-Output "FFOX-00-000008" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000009"
"Firefox must be configured to block pop-up windows."
"Need access to the content-prefs.sqlite file"
$firefoxPopUpBlocker = Get-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking"
if ($firefoxPopUpBlocker.Enabled -ne "1") { Write-Output "FFOX-00-000009" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000010"
# "Firefox must be configured to prevent JavaScript from moving or resizing windows."
if ($firefoxPreferences -notcontains 'user_pref("dom.disable_window_move_resize", true);') { Write-Output "FFOX-00-000010" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000011"
# "Firefox must be configured to prevent JavaScript from raising or lowering windows."
if ($firefoxPreferences -notcontains 'user_pref("dom.disable_window_flip", true);') { Write-Output "FFOX-00-000011" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000013"
# "Firefox must be configured to disable the installation of extensions."
$firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission
if ($firefoxAddonsPermissionsCheck -eq $null) { Write-Output "FFOX-00-000013" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000014"
# "Background submission of information to Mozilla must be disabled."
if ($firefoxSettings.DisableTelemetry -ne "1" -or $firefoxPreferences -notcontains 'user_pref("toolkit.telemetry.rejected", true);') { Write-Output "FFOX-00-000014" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000015"
# "Firefox development tools must be disabled."
if ($firefoxSettings.DisableDeveloperTools -ne "1") { Write-Output "FFOX-00-000015" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000016"
# "Deviation"

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000018"
# "Firefox must prevent the user from quickly deleting data."
if ($firefoxSettings.DisableForgetButton -ne "1") { Write-Output "FFOX-00-000018" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000019"
# "Firefox private browsing must be disabled."
if ($firefoxSettings.DisablePrivateBrowsing -ne "1") { Write-Output "FFOX-00-000019" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000020"
# "Firefox search suggestions must be disabled."
if ($firefoxPreferences -notcontains 'user_pref("browser.search.suggest.enabled", false);') { Write-Output "FFOX-00-000020" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000021"
# "Firefox autoplay must be disabled."
$firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay
if ($firefoxAutoplayPermissions.Default -ne "block-audio-video") { Write-Output "FFOX-00-000021" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000022"
# "Firefox network prediction must be disabled."
if ($firefoxSettings.NetworkPrediction -ne "0") { Write-Output "FFOX-00-000022" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000023"
# "Firefox fingerprinting protection must be enabled."
$firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection
if ($firefoxTrackingProtection.Fingerprinting -ne "1") { Write-Output "FFOX-00-000023" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000024"
# "Firefox cryptomining protection must be enabled."
if ($firefoxTrackingProtection.Cryptomining -ne "1") { Write-Output "FFOX-00-000024" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000025"
# "Firefox Enhanced Tracking Protection must be enabled."
if ($firefoxPreferences -notcontains 'user_pref("browser.contentblocking.category", "strict");') { Write-Output "FFOX-00-000025" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

# "FFOX-00-000026"
# "Firefox extension recommendations must be disabled."
if ($firefoxPreferences -notcontains 'user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);') { Write-Output "FFOX-00-000026" }

"----------------------------------------------------------------------------------------------------------------------------------------------------------"

