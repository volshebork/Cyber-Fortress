# List the accounts that were made in the last 2 weeks.
Get-ADuser -Filter * -Properties whencreated, description |
Where-object {$_.whencreated -ge ((Get-Date).AddDays(-14)).Date} |
Select-Object samaccountname, description