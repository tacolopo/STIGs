"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Mozilla Firefox V6R5"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000001"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Mozilla\Mozilla` Firefox\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000002, FFOX-00-000005, FFOX-00-000007, FFOX-00-000008, FFOX-00-000014"
"FFOX-00-000015, FFOX-00-000018, FFOX-00-000019, FFOX-00-000020, FFOX-00-000022"
"FFOX-00-000034, FFOX-00-000036, FFOX-00-000038, FFOX-00-000039"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000003, FFOX-00-000004, FFOX-00-000006, FFOX-00-000010, FFOX-00-000011"
"FFOX-00-000025, FFOX-00-000026"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\ | Format-List -Property Preferences"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\ | Format-List -Property Preferences
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000009"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000013"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000016"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Certificates
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000021"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\AutoPlay\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\AutoPlay\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000023, FFOX-00-000024"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000027"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000028"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000029"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000033"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000037"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"FFOX-00-000017"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Script Complete"