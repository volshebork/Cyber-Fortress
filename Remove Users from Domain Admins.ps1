# You must first create a .txt file with the list of users you want to remove.
# Set the path of Users_To_Remove_From_Domain_Admins.txt
$UsersFile = "C:\Scripts\Users_To_Remove_From_Domain_Admins.txt"
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

