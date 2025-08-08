# Get workstations in the domain.
Get-ADcomputer -filter {OperatingSystem -like '*Windows*' -and OperatingSystem -notlike '*Server*'} -properties name |
select-object name
