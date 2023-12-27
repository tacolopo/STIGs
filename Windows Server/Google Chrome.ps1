"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Google Chrome V2R8"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"DTBC-0001, DTBC-0002, DTBC-0004, DTBC-0007, DTBC-0008, DTBC-0009, DTBC-0011, DTBC-0017, DTBC-0020, DTBC-0023, DTBC-0025, DTBC-0026, DTBC-0027, DTBC-0029, DTBC-0030, DTBC-0037, DTBC-0038, DTBC-0039, DTBC-0052, DTBC-0053, DTBC-0055, DTBC-0057, DTBC-0058, DTBC-0060, DTBC-0061, DTBC-0063, DTBC-0064, DTBC-0065, DTBC-0066, DTBC-0067, DTBC-0068, DTBC-0069, DTBC-0070, DTBC-0071, DTBC-0072, DTBC-0056, DTBC-0073, DTBC-0074"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\

"DTBC-0005"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist\

"DTBC-0006"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist\

"DTBC-0021"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist\

"DTBC-0045"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\CookiesSessionOnlyForUrls\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome\CookiesSessionOnlyForUrls\
