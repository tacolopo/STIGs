# Other STIGs
Some of the Windows Server 2016 STIGs are checked through the Local Group Policy Editor, gpedit.msc. With the search tool in the bottom left of the home screen, enter gpedit.msc.
Then, traverse to Computer Configuration > Windows Settings > Security Settings > Account Policies and Local Policies. Right click on the child elements to export as a list (.txt).
You'll want to export Password Policy, Account Lockout Policy, Kerberos Policy (for Domain Controllers), Audit Policy, User Rights Assignment, and Security Options. Most STIGs
that cannot be checked through the PowerShell script can be checked in these export files.
