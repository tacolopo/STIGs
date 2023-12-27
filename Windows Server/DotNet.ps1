"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft DotNet Framework 4.0 V2R2"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0031"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\StrongName\Verification\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\StrongName\Verification\

"APPNET0046"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust` Providers\Software` Publishing\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust` Providers\Software` Publishing\

"APPNET0061"
"Get-WindowsFeature"
Get-WindowsFeature

"APPNET0063, APPNET0075"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\
"Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\

"APPNET0064"
'FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config'

"APPNET0065"
'FINDSTR /i /s "loadFromRemoteSource" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "loadFromRemoteSource" c:\*.exe.config'

"APPNET0066"
'FINDSTR /i /s "defaultProxy" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "defaultProxy" c:\*.exe.config'
'FINDSTR /i /s "defaultProxy" c:\*.machine.config'
Invoke-Expression -Command 'FINDSTR /i /s "defaultProxy" c:\*.machine.config'

"APPNET0066"
'FINDSTR /i /s "ewtEnable enabled" c:\*'
Invoke-Expression -Command 'FINDSTR /i /s "ewtEnable enabled" c:\*'

"APPNET0048, APPNET0052, APPNET0060, APPNET0062, APPNET0071"
"Get-Content -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config"
Get-Content -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config
"cd C:\Windows\Microsoft.NET\Framework\v4.0.30319"
cd C:\Windows\Microsoft.NET\Framework\v4.0.30319
'Invoke-Expression -Command "caspol.exe -m -lg"'
Invoke-Expression -Command "caspol.exe -m -lg"

