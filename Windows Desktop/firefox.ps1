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

