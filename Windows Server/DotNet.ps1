"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Microsoft DotNet Framework 4.0 V2R2"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0031"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\StrongName\Verification\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\StrongName\Verification\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0046"
"Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust` Providers\Software` Publishing\"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust` Providers\Software` Publishing\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"Primary caspol config check. If fails, defer to subsequent string searches."
"APPNET0060, APPNET0064, APPNET0065, APPNET0066"
"Get-Content 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe.config'"
Get-Content 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0060"
'FINDSTR /i /s "channel" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "channel" c:\*.exe.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0061"
"ls 'C:\Windows\Microsoft.NET\Framework64'"
ls 'C:\Windows\Microsoft.NET\Framework64'
"ls 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\'"
ls 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\'
"ls 'C:\Windows\Microsoft.NET\Framework'"
ls 'C:\Windows\Microsoft.NET\Framework'
"ls 'C:\Windows\Microsoft.NET\Framework\v1.0.3705'"
ls 'C:\Windows\Microsoft.NET\Framework\v1.0.3705'
"ls 'C:\Windows\Microsoft.NET\Framework\v1.1.4322'"
ls 'C:\Windows\Microsoft.NET\Framework\v1.1.4322'
"ls 'C:\Windows\Microsoft.NET\Framework\v2.0.50727'"
ls 'C:\Windows\Microsoft.NET\Framework\v2.0.50727'
"ls 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\'"
ls 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0063, APPNET0075"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0063, APPNET0075"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0063, APPNET0075"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0064"
'FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0065"
'FINDSTR /i /s "loadFromRemoteSource" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "loadFromRemoteSource" c:\*.exe.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0066"
'FINDSTR /i /s "defaultProxy" c:\*.exe.config'
Invoke-Expression -Command 'FINDSTR /i /s "defaultProxy" c:\*.exe.config'
'FINDSTR /i /s "defaultProxy" c:\*.machine.config'
Invoke-Expression -Command 'FINDSTR /i /s "defaultProxy" c:\*.machine.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0067"
'FINDSTR /i /s "ewtEnable enabled" c:\*'
Invoke-Expression -Command 'FINDSTR /i /s "ewtEnable enabled" c:\*.exe.config'
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"APPNET0048, APPNET0052, APPNET0060, APPNET0062, APPNET0071"
"Get-Content -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config"
Get-Content -Path C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

