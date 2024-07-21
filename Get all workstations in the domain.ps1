# Get workstations in the domain.
Get-ADcomputer -filter {Operatingsystem -like '*Windows8Workstation*'} -properties name |
select-object name