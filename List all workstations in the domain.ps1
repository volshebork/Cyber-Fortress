<#
.SYNOPSIS
    This script will list all Windows computers in the domain.

.DESCRIPTION
    This script will list all Windows computers in the domain.
    Windows Server operating systems will not be listed.

.NOTES
    Author: Oscar Cortez
    Created: 2024-08-15
    Last Updated: 2024-08-15
#>

Get-ADcomputer -filter {OperatingSystem -like '*Windows*' -and OperatingSystem -notlike '*Server*'} -properties name |
select-object name