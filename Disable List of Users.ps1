# Set path of the Users_to_remove.txt
$DomainUsersPath = "C:\Scripts\Users_to_remove.txt"

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

# Save the list of users to remove as "C:\Scripts\Users_to_remove.txt"
