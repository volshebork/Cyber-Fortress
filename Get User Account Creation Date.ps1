# Get the date a specified samaccountname was made.
# <samaccountname> is a placeholder. It needs to be replaced with the actual samaccountname.
Get-adUser -identity <samaccountname> -properties whencreated |

select samaccountname, whencreated
