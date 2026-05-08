<#
.SYNOPSIS
    This script will remove a list of users from the Domain Admins OU.

.DESCRIPTION
    This script will remove a list of users from the Domain Admins OU.
    You must first create C:\Temp\Remove_Domain_Admins\Users_To_Remove_From_Domain_Admins.txt
    This file should contain the samaccountnames of the users you want removed from Domain Admins.

.NOTES
    Author: Oscar Cortez
    Created: 2024-08-15
    Last Updated: 2024-08-15
#>

# Set the path of Users_To_Remove_From_Domain_Admins.txt
$UsersFile = "C:\Temp\Remove_Domain_Admins\Users_To_Remove_From_Domain_Admins.txt"
$UsersToRemove = Get-Content $UsersFile
$DomainAdminsGroup = "Domain Admins"

foreach ($User in $UsersToRemove) {
    $User = $User.Trim()
    if (Get-ADUser -Filter {SamAccountName -eq $User}) {
        try {
            Remove-ADGroupMember -Identity $DomainAdminsGroup -Members $User -Confirm:$false
            Write-Output "Removed $User from Domain Admins group"
        }
        catch {
            Write-Warning "Failed to remove $User from Domain Admins group: $_"
        }
    }
    else {
        Write-Warning "User $User not found in Active Directory"
    }
}

# Save the list of users to remove as C:\Scripts\Users_To_Remove_From_Domain_Admins.txt