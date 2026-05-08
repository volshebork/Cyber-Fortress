<#
.SYNOPSIS
    This script will disable the accounts from a list.

.DESCRIPTION
    This script will delete the user accounts listed in C:\Temp\Remove_Users\Users_to_remove.txt
    You will first need to create C:\Temp\Remove_Users\Users_to_remove.txt
    This file should contain the samaccountnames of the users you want disabled.

.NOTES
    Author: Oscar Cortez
    Created: 2024-08-15
    Last Updated: 2024-08-15
#>

# Set path of the Users_to_remove.txt
$DomainUsersPath = "C:\Temp\Remove_Users\Users_to_remove.txt"

# Initialize variable with the contents of Users_to_remove.txt
$DomainUsers = Get-content -Path $DomainUsersPath

foreach ($user in $DomainUsers) {
    
# Disable the user account.
disable-ADAccount -identity $user

# Set pass never expires to false.
# Set change pass at login to true.
set-aDUser -identity $user -passwordneverexpires $false -changepasswordatlogon $true
}

write-output 'Complete.'