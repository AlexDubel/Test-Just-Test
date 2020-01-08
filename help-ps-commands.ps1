#Сеть
Resolve-DnsName microsoft.com
Test-NetConnection 8.8.8.8
Get-NetIPConfiguration
Get-NetIPAddress |? AddressFamily -eq IPv4 | ft -AutoSize
# Работа с AD
Get-ADUser -Filter * -Properties mobile | Where-Object {$_.mobile -like "*+38 091 114-34-72*"} 
Get-ADUser -Filter { Name -like "*Дубель *" } -Properties mobile
#Получить список установленного ПО на компьютере
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
#Отключить SMB1 протокол
Set-SmbServerConfiguration -EnableSMB1Protocol $FALSE
# удалить его из системы
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove 
#проверка
Get-WindowsOptionalFeature –Online -FeatureName SMB1Protocol
# Надо проверить
#Чтобы отключить поддержку SMB v1 на стороне клиента, выполните команды:
#sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
#sc.exe config mrxsmb10 start= disabled
#Группы в которые входит пользователь
Get-ADPrincipalGroupMembership -Identity "p.kashpyrev"
(Get-ADGroupMember kv-ho-crm-billing-testers).name
(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf
([ADSISEARCHER]"samaccountname=$($env:USERNAME)").Findone().Properties.memberof
(GET-ADUSER –Identity odubel –Properties MemberOf | Select-Object MemberOf).MemberOf
net user odubel /domain
net group  kv-ho-crm-billing-dev /domain
Get-ADGroupMember -identity kv-ho-crm-billing-testers -recursive | select name,samaccountname
#Блокирование/разблокирование учетных записей
#Get-Content "D:\Documents\Проект\Внешние поставщики\block-records.txt" | foreach { Enable-ADAccount $PSItem}
#Get-Content "D:\Documents\Проект\Внешние поставщики\block-records.txt" | foreach {Disable-ADAccount $PSItem}
$host.ui.RawUI.WindowTitle = "adm-odubel"+" started at $curdate"
new-item -itemtype file -path $profile -force 
# перечитать профиль не перезагружая powershell
. $PROFILE
Get-ADUser -Identity "odnovikova" -Properties * | Get-Member -MemberType property
#Получить список групп, в которые входит пользователь. 



#Получить перечень уникальных СЛД из AD
(Get-ADUser -filter * -Properties department).department | Where-Object {$PSItem -like "Станційно-лінійна дільниця*"} | Get-Unique

#получить название отдела и город где работает сотрудник

(Get-ADUser odubel -Properties *).department
#Відділ впровадження білінгових систем та CRM

(Get-ADUser odubel -Properties *).city
#м. Київ
(Get-ADUser odubel -Properties *).l
#м. Київ
#выбрать из AD всех подчиненных и показать их имена и e-mail'ы
(get-aduser -filter {name -like "Контов*"} -Properties *).directreports  | foreach {get-aduser -Identity $PSItem -Properties * | Select-Object name,userprincipalname,l, enabled| Where-Object {$PSItem.l -like "*Київ*" -and $PSItem.enabled -eq $True } } | ft name, userprincipalname -AutoSize
(get-aduser odubel -Properties *).directreports  | foreach {get-aduser -Identity $PSItem -Properties * | Select-Object name,userprincipalname,l, enabled,title| Where-Object {$PSItem.enabled -eq $True } } | ft name, title -AutoSize
(get-aduser odubel -Properties *).directreports  | foreach {get-aduser -Identity $PSItem -Properties * | Select-Object name,userprincipalname,l,enabled,title,company,givenname |`
 Where-Object {$PSItem.enabled -eq $True -and $PSItem.company -like "*Укртелеком*" -and $PSItem.givenname -ne $null} } | ft name, title -AutoSize



 $userlist = Get-Content "D:\Documents\Powershell\Test-Just-Test\444.txt"
#$userlist="odubel"
foreach ($username in $userlist) {
    $grplist = (Get-ADUser $username –Properties MemberOf | Select-Object MemberOf).MemberOf -replace '^CN=([^,]+).+$','$1'|Select-String  "all-CRM"
    foreach ($group in $grplist) { Out-File -InputObject $username, $group -Append "D:\Documents\Powershell\Test-Just-Test\444-rezz.txt"}  
} 
#(Get-ADUser nklovanych –Properties MemberOf | Select-Object MemberOf).MemberOf -replace '^CN=([^,]+).+$','$1'|Select-String "CRM"

$userlist = Get-Content "D:\Documents\Powershell\Test-Just-Test\444.txt"
#$userlist="odubel"
foreach ($username in $userlist) {
    $grplist = (Get-ADUser $username –Properties MemberOf | Select-Object MemberOf).MemberOf -replace '^CN=([^,]+).+$','$1'|Select-String  "all-CRM"
    foreach ($group in $grplist) { Write-Output $username, $group }  
} 
#(Get-ADUser nklovanych –Properties MemberOf | Select-Object MemberOf).MemberOf -replace '^CN=([^,]+).+$','$1'|Select-String "CRM"


$list = 'odubel','odubel','odubel'
$list | `
    %{  
        $user = $_; 
        get-aduser $user -Properties memberof | `
        select -expand memberof | `
        %{new-object PSObject -property @{User=$user;Group=$_;}} `-replace '^CN=([^,]+).+$','$1'
    }


    ([ADSISEARCHER]"samaccountname=$("odubel")").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'

#Посчитать количество пользователей которые находятся в OU, в названиях которых встречается "Blocked Accounts". 
((Get-ADOrganizationalUnit -filter *) | Where-Object DistinguishedName -like "*Blocked Accounts*").DistinguishedName | ForEach-Object {(Get-ADUser -Filter * -searchbase $PSItem).Name } | measure
((Get-ADOrganizationalUnit -filter *) | Where-Object DistinguishedName -like "*Blocked Accounts*").DistinguishedName | ForEach-Object {(Get-ADUser -Filter * -searchbase $PSItem) | Select-Object name, DistinguishedName } | measure
# перечень групп в АД, в названии которых есть *CRM* исключая группы которые перечислены после слова "-notmatch"
(Get-ADGroup -Filter *).name | Where-Object {$PSItem -like "*CRM*" -and $PSItem -notmatch "precrm|mediation|reklama|sale|crmail|suitecrm|KV-TERM-03v3-Users_CRM"}

#Сравнение списка пользователей из бпмм с проверка того, что эти же пользователи активны или не активны в AD. 

##Get-Content c:\temp\Myfile-all.txt | ForEach-Object {(get-aduser -filter {samaccountname -like $PSItem}) | Select-Object samaccountname, enabled } | Out-File c:\temp\Myfile-outrez.txt
Get-Content C:\temp\Myfile-all.txt | ForEach-Object {get-aduser $PSItem | Where-Object {($PSItem).enabled -like "False"} | Select-Object samaccountname, enabled } | Out-File c:\temp\Myfile-outrez.txt
#Скопировать пользователей из одной группы в другую
Add-ADGroupMember -Identity 'New Group' -Members (Get-ADGroupMember -Identity 'Old Group' -Recursive)