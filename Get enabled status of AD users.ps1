# Get enabled/disabled status of AD users.
Get-aDuser -filter * -properties samaccountname, enabled |
select-object samaccountname, enabled