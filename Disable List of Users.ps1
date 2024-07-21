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

# This is the list of users that this script will update.
# Save this list as C:\Scripts\Users_to_remove.txt
Elena.Morrison
alexandra.ward
ali.conner
angeline.moses
ash.willis
ben.lane
benjamin.spencer
bethany.palmer
blair.fletcher
blake.parry
brad.stone
britney.newman
caitlyn.kelly
chanel.gardner
chris.gallagher
cory.hall
danielle.mcdonald
danni.saunders
dante.vazquez
david.barker
david.hawkins
elaine.terry
emely.zhang
emilia.green
emiliano.morrison
ervin.maxwell
evan.green
evan.thomson
felicity.cohen
felix.leach
gabrielle.winters
haiden.black
harriet.ryan
isabel.evans
jadon.dale
jared.rosa
jasmine.lowe
jessie.patel
jo.mitchell
josh.dean
josh.knapp
josh.pearson
kameron.klein
kash.hess
katherine.barrett
keaton.rowe
kenia.todd
kian.burns
kieran.willis
kiley.floyd
lane.cook
leo.moss
lily.morgan
linda.larsen
martin.richardson
mason.baxter
maxwell.rosales
meredith.hartman
mia.brooks
mia.knight
nicole.campbell
noah.jordan
phoebe.kaur
poppy.reid
raiden.battle
rhys.west
river.ellison
ryan.tanner
sam.daniel
sam.lewis
sarah.hudson
steff.harrell
talia.gould
taliyah.michael
teagan.newton
terrence.lang
tilly.read
tom.may
tommy.hendersen
tripp.irwin
tyler.butler
william.morgan
zara.macdonald
margaret.encino