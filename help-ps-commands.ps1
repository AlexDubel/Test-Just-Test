#Сеть
Resolve-DnsName microsoft.com
Test-NetConnection 8.8.8.8
Get-NetIPConfiguration
Get-NetIPAddress | Where-Object AddressFamily -eq IPv4 | Format-Table -AutoSize
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
Get-ADGroupMember -identity kv-ho-crm-billing-testers -recursive | Select-Object name,samaccountname
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
(get-aduser -filter {name -like "Контов*"} -Properties *).directreports  | ForEach-Object {get-aduser -Identity $PSItem -Properties * |`
     Select-Object name,userprincipalname,l, enabled| Where-Object {$PSItem.l -like "*Київ*" -and $PSItem.enabled -eq $True } } | Format-Table name, userprincipalname -AutoSize
(get-aduser odubel -Properties *).directreports  | ForEach-Object {get-aduser -Identity $PSItem -Properties * |`
     Select-Object name,userprincipalname,l, enabled,title| Where-Object {$PSItem.enabled -eq $True } } | Format-Table name, title -AutoSize
(get-aduser odubel -Properties *).directreports  | ForEach-Object {get-aduser -Identity $PSItem -Properties * | Select-Object name,userprincipalname, l, enabled, title, company, givenname |`
 Where-Object {$PSItem.enabled -eq $True -and $PSItem.company -like "*Укртелеком*" -and $PSItem.givenname -ne $null} } | Format-Table name, title -AutoSize 


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
    ForEach-Object{  
        $user = $_; 
        get-aduser $user -Properties memberof | `
        Select-Object -expand memberof | `
        ForEach-Object{new-object PSObject -property @{User=$user;Group=$_;}} `-replace '^CN=([^,]+).+$','$1'
    }


    ([ADSISEARCHER]"samaccountname=$("odubel")").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'

#Посчитать количество пользователей которые находятся в OU, в названиях которых встречается "Blocked Accounts". 
((Get-ADOrganizationalUnit -filter *) | Where-Object DistinguishedName -like "*Blocked Accounts*").DistinguishedName |`
         ForEach-Object {(Get-ADUser -Filter * -searchbase $PSItem).Name } | Measure-Object
((Get-ADOrganizationalUnit -filter *) | Where-Object DistinguishedName -like "*Blocked Accounts*").DistinguishedName |`
         ForEach-Object {(Get-ADUser -Filter * -searchbase $PSItem) | Select-Object name, DistinguishedName } | Measure-Object
         
         
# перечень групп в АД, в названии которых есть *CRM* исключая группы которые перечислены после слова "-notmatch"
(Get-ADGroup -Filter *).name | Where-Object {$PSItem -like "*CRM*" -and $PSItem -notmatch "precrm|mediation|reklama|sale|crmail|suitecrm|KV-TERM-03v3-Users_CRM"}

#Сравнение списка пользователей из бпмм с проверка того, что эти же пользователи активны или не активны в AD. 

##Get-Content c:\temp\Myfile-all.txt | ForEach-Object {(get-aduser -filter {samaccountname -like $PSItem}) | Select-Object samaccountname, enabled } | Out-File c:\temp\Myfile-outrez.txt
Get-Content C:\temp\Myfile-all.txt | ForEach-Object {get-aduser $PSItem | Where-Object {($PSItem).enabled -like "False"} | Select-Object samaccountname, enabled } | Out-File c:\temp\Myfile-outrez.txt
#Скопировать пользователей из одной группы в другую
Add-ADGroupMember -Identity 'New Group' -Members (Get-ADGroupMember -Identity 'Old Group' -Recursive)

#(Get-ADUser -Filter {department -like "Група з технічного обліку"} -Properties * ) | Sort-Object -Property city | Format-Table name, department, company, city, samaccountname
(Get-ADUser -Filter {department -like "Група з технічного обліку"} -Properties * )  | Sort-Object -Property company |`
 Select-Object name, department, company, city, samaccountname | export-csv -Delimiter ";" -Path $texoblicuserscsv -Encoding default
#Полученный файл открываем в excel, затем добавляем названия групп (техоблик) в колонке справа. Делаем Экспорт файла в csv с новым именем. 
#что-то не то с кириллицей, файл не находится, поэтому строчка ниже закомментирована. 
#$mypath = "D:\Documents\Проект\Ролевая модель"
# Перенес файл в каталог, где только английские буквы в пути к файлу.
$mypath = "C:\temp\Groups\Add-new"
$myfile = "Techoblic-only-3.csv"
#несмотря на то, что эксель пишет, что сохраняет файл csv с разделителем "запятая", в команде import-csv нужно/можно указывать ";"
$a=Import-Csv -Path $mypath\$myfile -Encoding default -Delimiter ";"
#Write-host ($a).grouptoadd
#exit
#добавляем пользователей из колонки samaccountname в группу grouptoadd
$a | ForEach-Object {Add-ADGroupMember -Identity ($PSItem).grouptoadd -Members ($PSItem).samaccountname}

#Получение всех сотрудников, которые входят в группы ФФМ (группы содержат в своем названии BPM)
(Get-ADGroup -Filter {name -like "*bpm*"}).name | Sort-Object | ForEach-Object {Write-Host $PSItem;(Get-ADGroupMember $PSItem).name}
#Создать новую группу в АД 
New-ADGroup -Description "Группа для тестов в BPM реогранизации ТД" -GroupCategory Security`
 -GroupScope Universal -Name test-TD-new-struct-1 -SamAccountName "test-TD-new-struct-1"`
  -Path "OU=BPM,OU=Applications,OU=Groups,OU=ICS,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc"
New-ADGroup -Description "Дільниця транспортної мережі №116/2 м. Мукачево" -GroupCategory Security`
 -GroupScope Universal -Name UG-BPM-CTM-DTM1162 -SamAccountName "UG-BPM-CTM-DTM1162"`
  -Path "OU=BPM,OU=Applications,OU=Groups,OU=ICS,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc"
New-ADGroup -Description "Дільниця транспортної мережі №116/1 м. Ужгород"  -GroupCategory Security`
 -GroupScope Universal -Name UG-BPM-CTM-DTM1161 -SamAccountName "UG-BPM-CTM-DTM1161"`
  -Path "OU=BPM,OU=Applications,OU=Groups,OU=ICS,OU=KYIV,DC=corp,DC=ukrtelecom,DC=loc"
#Errors to file
Get-Content "C:\Temp\TD-reorg\delete-all-users-from-groups.txt" | ForEach-Object {(Get-ADGroup $PSItem).name}  2>> C:\temp\errors.txt

  #Найти все группі в имени которіх есть BPM и сделать их експорт в CSV файл. 
  Get-ADGroup -Filter {name -like "*BPM*"} -Properties * | Select-Object name, description | Export-Csv -Path "c:\temp\group-bpm-export.csv" -Encodi
  ng UTF8 -Delimiter ";"
  #Найти все группі в описании которіх есть "Орг. Роль*" и сделать их експорт в CSV файл.
  Get-ADGroup -Filter {description -like "Орг. Роль*"} -Properties * | Select-Object name, description | Export-Csv -Path "c:\temp\group-export.csv"
 -Encoding UTF8 -Delimiter ";"
# Проверяем реальній MTU к хосту, работает на PowerShell Core
 Test-Connection -TargetName kv-dc-01 -MTUSizeDetect
 
 #Remove all users from group
 Remove-ADGroupMember "test_group" -Members (Get-ADGroupMember "test_group") -Confirm:$false

 Rename-ADObject -Identity "CN=HQ,CN=Sites,CN=Configuration,DC=FABRIKAM,DC=COM" -NewName "UnitedKingdomHQ"
 #Remove all users from AD group 
 Get-ADGroupMember "$Group" | ForEach-Object {Remove-ADGroupMember "$Group" $_ -Confirm:$false} 
 #получение перечня актівніх аккаунтов имя, логин, и короткий формат даті действия учетки. 
 Get-ADUser -Filter {enabled -eq $True} -SearchBase $sbase -Properties * |`
  Select-Object -Property name, samaccountname, enabled, @{label="Date"; expression={($PSItem.AccountExpirationDate).ToShortDateString()}} |`
   Export-Csv -Path "c:\temp\b_accounts.csv" -Delimiter ";"
#тоже что и віше, только учетки из файла
Get-Content C:\temp\users-extendaccess2020.txt | ForEach-Object {get-aduser $PSItem -Properties *} |`
 Select-Object -Property name, samaccountname, enabled, @{label="Date"; expression={($PSItem.AccountExpirationDate).ToShortDateString()}}
#Установить удаленную сессию к powershell 7
 New-PSSession -ComputerName kv-crmqa -Credential $admcred -EnableNetworkAccess -ConfigurationName PowerShell.7
 #Для того, чтобі команда работала надо віполнить скрипт (путь к нему powershell знает). 
 Install-PowerShellRemoting.ps1
#Можно использовать как в примерах ниже
$s = New-PSSession -ComputerName kv-crmqa -Credential $admcred -EnableNetworkAccess -ConfigurationName PowerShell.7
$command = {Test-Connection -TargetName kv-dc-01 -MTUSizeDetect}
Invoke-Command -Session $s -ScriptBlock $command

#Опросить сервера на предмет открітіх портов
$computers="kv-crmapp-01","kv-crmapp-02","kv-crmapp-03"
Invoke-Command -ComputerName $computers -ScriptBlock { Get-NetTCPConnection | Where-Object state -eq "Listen" |`
 Select-Object $($env:computername),LocalAddress,LocalPort,state| Format-Table }
 #Если нужно віводить имя компьютера в каждой строчке, то поможет такая команда
 Invoke-Command -ComputerName $computers -ScriptBlock {Get-NetTCPConnection | Where-Object state -eq "Listen"} | Format-Table PSComputerName,LocalAddress,LocalPort,state

