# Get the date a specified samaccountname was made.
Get-adUser -identity <samaccountname> -properties whencreated |
select samaccountname, whencreated