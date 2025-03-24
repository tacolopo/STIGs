"----------------------------------------------------------------------------------------------------------------------------------------------------------"
"Security Technical Implementation Guide (STIG) Windows Defender Firewall V2R2"
"----------------------------------------------------------------------------------------------------------------------------------------------------------"

"WNFWA-000001, WNFWA-000004, WNFWA-000005"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\

"WNFWA-000002, WNFWA-000012, WNFWA-000013"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\

"WNFWA-000003, WNFWA-000020, WNFWA-000021, WNFWA-000024, WNFWA-000025"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\

"WNFWA-000009, WNFWA-000010, WNFWA-000011"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging\

"WNFWA-000017, WNFWA-000018, WNFWA-000019"
"Get-ItemProperty -Path HKLM: \SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\"
Get-ItemProperty -Path HKLM: \SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging\

"WNFA-000027, WNFA-000028, WNFA-000029"
"Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\"
Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\
"Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging\
