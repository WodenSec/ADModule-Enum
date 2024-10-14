# ADModule-Enum
Script to enumerate an Active Directory for exploitation vectors using strictly ADModule to avoid AV detection.

## Main script (ADModule-Enum) usage
The main script will import AD Module automatically if it's in the current directory

Download the script and run it:
```
.\ADModule-Enum.ps1
```
Follow menu instructions.

For now the best way to save into a file is:
```
Start-Transcript -Path .\ADEnum.txt ; .\ADModule-Enum.ps1 ; Stop-Transcript
```

## Domain mapping usage
You'll need to import the dll yourself for now (I'm lazy)
Load the script in memory, then execute it. You can add `-Verbose`
```
. .\Get-ADMap.ps1
Get-ADMap
```

## To do
- [x] Improve output's readability
- [ ] Add more GUID mapping
- [ ] Improve README
- [x] Integrate AD module and import automatically
- [x] Add gMSA enumeration
- [x] Add password policy (including fine-grained) enumeration
- [ ] Add LAPS enumeration
