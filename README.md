# HashMatch - Current Version 1.9

![HashMatch](https://github.com/rmdavy/hashmatch/blob/master/hash_match1.JPG)

More often than not during a pentest password reuse is identified for things like local administrator and solutions exist to combat this like LAPS. However with AD accounts and historic accounts in particular it can often be time consuming to find where passwords are reused.

HashMatch will compare hash values and clearly indicate were password sharing exists. 

Optionally a list of Domain Administrator account names can be supplied and these will be checked and indicated in red when found and Domain Admin will be appended to the end of the string.

Optionally a second list of hashes from a second domain can also be supplied and HashMatch will identify common passwords between the two domains.

Optionally HashMatch will correlate the hashcat cracked passwords output with reused hashes and display the shared password in the header line.

Optionally HashMatch will correlate Enabled/Disabled users from provided lists.
These can easily be generated using the following Powershell commands

Import-Module activedirectory  
Get-Aduser -Filter 'Enabled -eq $false' -Properties *|select SamAccountName |export-csv C:\outputDisabled.csv  
Get-Aduser -Filter 'Enabled -eq $true' -Properties *|select SamAccountName  |export-csv C:\outputEnabled.csv  
