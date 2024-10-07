"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Mozilla Firefox V6R5"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

#Registry Keys come from https://admx.help?Category=Firefox&Policy=Mozilla.Policies.Firefox and https://mozilla.github.io/policy-templates/

# Define variables with default values
$firefoxPreferences = ""
$mozillaCfg = ""
$firefoxSettings = ""
#define some commonly used variables
$firefoxVersion = (Get-ItemProperty "HKLM:\Software\Mozilla\Mozilla Firefox").CurrentVersion | Out-String
if ($firefoxVersion -ne $null -and $firefoxVersion -ne "") {
    $mozillaCfg = Get-Content "C:\Program Files\Mozilla Firefox\mozilla.cfg" | Out-String
    $firefoxSettings = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\

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


    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000001"
    # "The installed version of Firefox must be supported."
    if ($firefoxVersion -eq $null -or $firefoxVersion -eq "" -or $firefoxVersion.Contains("130.0") -eq $false) { Write-Output "FFOX-00-000001" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000002"
    # "Firefox must be configured to allow only TLS 1.2 or above."
    if ($firefoxSettings -eq $null -or $firefoxSettings.SSLVersionMin -notin @("tls1.2", "tls1.3")) {
        if ($mozillaCfg -eq $null -or ($mozillaCfg.Contains('"security.tls.version.min", 3') -eq $false -and $mozillaCfg.Contains('"security.tls.version.min", 4') -eq $false)) {
            Write-Output "FFOX-00-000002"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000003"
    # "Firefox must be configured to ask which certificate to present to a website when a certificate is required."
    if (($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"security.default_personal_cert", "Ask Every Time"') -eq $false) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"security.default_personal_cert", "Ask Every Time"') -eq $false)) {
        Write-Output "FFOX-00-000003"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000004"
    # "Firefox must be configured to not automatically check for updated versions of installed search plugins."
    if (($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.search.update", false') -eq $false) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.search.update", false') -eq $false)) {
        Write-Output "FFOX-00-000004"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000005"
    # "Firefox must be configured to not automatically update installed add-ons and plugins."
    if (($firefoxSettings -eq $null -or $firefoxSettings.ExtensionUpdate -ne "0") -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"extensions.update.enabled", false') -eq $false)) {
        Write-Output "FFOX-00-000005"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000006"
    # "Firefox must be configured to not automatically execute or download MIME types that are not authorized for auto-download."

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

    if ($violationFound -eq $true) { Write-Output "FFOX-00-000006" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000007"
    # "Firefox must be configured to disable form fill assistance."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableFormHistory -ne "1") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.formfill.enable", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.formfill.enable", false') -eq $false) {
                Write-Output "FFOX-00-000007"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000008"
    # "Firefox must be configured to not use a password store with or without a master password."
    if ($firefoxSettings -eq $null -or $firefoxSettings.PasswordManagerEnabled -ne "0") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"signon.rememberSignons", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"signon.rememberSignons", false') -eq $false) {
                Write-Output "FFOX-00-000008"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000009"
    # "Firefox must be configured to block pop-up windows."
    # "Need access to the permissions.sqlite and content-prefs.sqlite files"
    # $firefoxPopUpBlocker = Get-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking"
    # if ($firefoxPopUpBlocker.Enabled -ne "1") { Write-Output "FFOX-00-000009" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000010"
    # "Firefox must be configured to prevent JavaScript from moving or resizing windows."
    if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"dom.disable_window_move_resize", true') -eq $false) {
        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"dom.disable_window_move_resize", true') -eq $false) {
            Write-Output "FFOX-00-000010"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000011"
    # "Firefox must be configured to prevent JavaScript from raising or lowering windows."
    if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"dom.disable_window_flip", true') -eq $false) {
        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"dom.disable_window_flip", true') -eq $false) {
            Write-Output "FFOX-00-000011"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000013"
    # "Firefox must be configured to disable the installation of extensions."
    $firefoxAddonsPermissionsCheck = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission -ErrorAction SilentlyContinue
    if ($firefoxAddonsPermissionsCheck -ne $null) {
        if ($firefoxAddonsPermissionsCheck.Default -ne 0) {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"xpinstall.enabled", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"xpinstall.enabled", false') -eq $false) {
                    Write-Output "FFOX-00-000013"
                }
            }
        }
    } else {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"xpinstall.enabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"xpinstall.enabled", false') -eq $false) {
                Write-Output "FFOX-00-000013"
            }
        }
    }
    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000014"
    # "Background submission of information to Mozilla must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableTelemetry -ne "1") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"datareporting.policy.dataSubmissionEnabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"datareporting.policy.dataSubmissionEnabled", false') -eq $false) {
                Write-Output "FFOX-00-000014"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000015"
    # "Firefox development tools must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableDeveloperTools -ne "1") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"devtools.policy.disabled", true') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"devtools.policy.disabled", true') -eq $false) {
                Write-Output "FFOX-00-000015"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000016"
    # "Deviation"

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000018"
    # "Firefox must prevent the user from quickly deleting data."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableForgetButton -ne "1") { Write-Output "FFOX-00-000018" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000019"
    # "Firefox private browsing must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisablePrivateBrowsing -ne "1") { Write-Output "FFOX-00-000019" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000020"
    # "Firefox search suggestions must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.SearchSuggestEnabled -ne "0") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.search.suggest.enabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.search.suggest.enabled", false') -eq $false) {
                Write-Output "FFOX-00-000020"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000021"
    # "Firefox autoplay must be disabled."

    $firefoxAutoplayPermissions = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay -ErrorAction SilentlyContinue
    if ($firefoxAutoplayPermissions -ne $null) {
        if ($firefoxAutoplayPermissions.Default -ne "block-audio-video") {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) {
                if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"media.autoplay.default", 5') -eq $false) {
                    if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) {
                        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"media.autoplay.default", 5') -eq $false) {
                            Write-Output "FFOX-00-000021"
                        }
                    }
                }
            }
        }
    } else {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"media.autoplay.default", 5') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"media.autoplay.default", "block-audio-video"') -eq $false) {
                    if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"media.autoplay.default", 5') -eq $false) {
                        Write-Output "FFOX-00-000021"
                    }
                }
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000022"
    # "Firefox network prediction must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.NetworkPrediction -ne "0") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"network.dns.disablePrefetch", true') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"network.dns.disablePrefetch", true') -eq $false) {
                Write-Output "FFOX-00-000022"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000023"
    # "Firefox fingerprinting protection must be enabled."
    $firefoxTrackingProtection = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection -ErrorAction SilentlyContinue
    if ($firefoxTrackingProtection -ne $null) {
        if ($firefoxTrackingProtection.Fingerprinting -ne "1") {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false) {
                if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.fingerprintingProtection", true') -eq $false) {
                    if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false) {
                        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.fingerprintingProtection", true') -eq $false) {
                            Write-Output "FFOX-00-000023"
                        }
                    }
                }
            }
        }
    } else {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false) {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.fingerprintingProtection", true') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.trackingprotection.fingerprinting.enabled", true') -eq $false) {
                    if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.fingerprintingProtection", true') -eq $false) {
                        Write-Output "FFOX-00-000023"
                    }
                }
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000024"
    # "Firefox cryptomining protection must be enabled."
    if (($firefoxTrackingProtection -eq $null -or $firefoxTrackingProtection.Cryptomining -ne "1") -and 
        ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.trackingprotection.cryptomining.enabled", false') -eq $true) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.trackingprotection.cryptomining.enabled", false') -eq $true)) {
        Write-Output "FFOX-00-000024"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000025"
    # "Firefox Enhanced Tracking Protection must be enabled."
    if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.contentblocking.category", "strict"') -eq $false) {
        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.contentblocking.category", "strict"') -eq $false) {
            Write-Output "FFOX-00-000025"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000026"
    # "Firefox extension recommendations must be disabled."
    if (($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"extensions.htmlaboutaddons.recommendations.enabled", false') -eq $false) -and 
        ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"extensions.htmlaboutaddons.recommendations.enabled", false') -eq $false) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false)) {
        Write-Output "FFOX-00-000026"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000027"
    # "Firefox deprecated ciphers must be disabled."
    $disabledFirefoxCiphers = Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers -ErrorAction SilentlyContinue
    if ($disabledFirefoxCiphers -ne $null) {
        if ($disabledFirefoxCiphers.TLS_RSA_WITH_3DES_EDE_CBC_SHA -notin @("0", "false")) {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) {
                    Write-Output "FFOX-00-000027"
                }
            }
        }
    } else {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"security.ssl3.deprecated.rsa_des_ede3_sha", false') -eq $false) {
                Write-Output "FFOX-00-000027"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000028"
    # "Firefox must not recommend extensions as the user is using the browser."
    $firefoxUserMessaging = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging -ErrorAction SilentlyContinue
    if ($firefoxUserMessaging -ne $null) {
        if ($firefoxUserMessaging.ExtensionRecommendations -ne "0") {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) {
                    Write-Output "FFOX-00-000028"
                }
            }
        }
    } else {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false') -eq $false) {
                Write-Output "FFOX-00-000028"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000029"
    # "The Firefox New Tab page must not show Top Sites, Sponsored Top Sites, Pocket Recommendations, Sponsored Pocket Stories, Searches, Highlights, or Snippets."
    $firefoxHomePageSettings = Get-ItemProperty -Path HKLM:\Software\Policies\Mozilla\Firefox\HomePage -ErrorAction SilentlyContinue
    if ($firefoxHomePageSettings -ne $null) {
        if (($firefoxHomePageSettings.TopSites -ne "0") -or ($firefoxHomePageSettings.SponsoredTopSites -ne "0") -or ($firefoxHomePageSettings.SponsoredPocket -ne "0") -or ($firefoxHomePageSettings.Search -ne "0") -or ($firefoxHomePageSettings.Highlights -ne "0") -or ($firefoxHomePageSettings.Snippets -ne "0")) {
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
            if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false) {
                if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false) {
                    Write-Output "FFOX-00-000029"
                }
            }
        }
    } else {
        if (($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.topsites", false') -eq $false) -or 
            ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsoredTopSites", false') -eq $false) -or 
            ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSponsored", false') -eq $false) -or 
            ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.showSearch", false') -eq $false) -or 
            ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.section.highlights", false') -eq $false) -or 
            ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"browser.newtabpage.activity-stream.feeds.snippets", false') -eq $false)) {
            Write-Output "FFOX-00-000029"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000033"
    # "Firefox must be configured so that DNS over HTTPS is disabled."
    # "Disagree with STIG recommendation so N/A"

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000034"
    # "Firefox accounts must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableFirefoxAccounts -ne "1") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"identity.fxaccounts.enabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"identity.fxaccounts.enabled", false') -eq $false) {
                Write-Output "FFOX-00-000034"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000036"
    # "Firefox feedback reporting must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisableFeedbackCommands -ne "1") { Write-Output "FFOX-00-000036" }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000037"
    # "Firefox encrypted media extensions must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.EncryptedMediaExtensions -ne "0") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"media.eme.enabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"media.eme.enabled", false') -eq $false) {
                Write-Output "FFOX-00-000037"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000017"
    # "Firefox must be configured to not delete data upon shutdown."
    if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"privacy.sanitize.sanitizeOnShutdown", true') -eq $true) {
        if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"privacy.sanitize.sanitizeOnShutdown", true') -eq $true) {
            Write-Output "FFOX-00-000017"
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000038"
    # "Pocket must be disabled."
    if ($firefoxSettings -eq $null -or $firefoxSettings.DisablePocket -ne "1") {
        if ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"extensions.pocket.enabled", false') -eq $false) {
            if ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"extensions.pocket.enabled", false') -eq $false) {
                Write-Output "FFOX-00-000038"
            }
        }
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"

    # "FFOX-00-000039"
    # "Firefox Studies must be disabled."
    if (($firefoxSettings -eq $null -or $firefoxSettings.DisableFirefoxStudies -ne "1") -and 
        ($firefoxPreferences -eq $null -or $firefoxPreferences.Contains('"app.shield.optoutstudies.enabled", false') -eq $false) -and 
        ($mozillaCfg -eq $null -or $mozillaCfg.Contains('"app.shield.optoutstudies.enabled", false') -eq $false)) {
        Write-Output "FFOX-00-000039"
    }

    "----------------------------------------------------------------------------------------------------------------------------------------------------------"
}