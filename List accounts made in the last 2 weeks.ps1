<#
.SYNOPSIS
    This script will list the accounts that were made in the last two weeks.

.DESCRIPTION
    This script will list the accounts that were made in the last two weeks.

.NOTES
    Author: Oscar Cortez
    Created: 2024-08-15
    Last Updated: 2024-08-15
#>

Get-ADuser -Filter * -Properties whencreated, description |
Where-object {$_.whencreated -ge ((Get-Date).AddDays(-14)).Date} |
Select-Object samaccountname, description