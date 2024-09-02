# ADModule-Enum
Script to enumerate an Active Directory for exploitation vectors using strictly ADModule to avoid AV detection.

## Installation
- Follow the steps to import ADModule : https://github.com/samratashok/ADModule
- Run the script
- Choose which task to do

## Usage
Download the script and run it:
```
.\ADModule-Enum.ps1
```
Follow menu instructions.

For now the best way to save into a file is:
```
Start-Transcript -Path .\ADEnum.txt ; .\ADModule-Enum.ps1 ; Stop-Transcript
```

## To do
- [x] Improve output's readability
- [ ] Add more GUID mapping
- [ ] Improve README
- [ ] Integrate AD Management DLL in the script (?)
- [x] Add gMSA enumeration
- [x] Add password policy (including fine-grained) enumeration
- [ ] Add LAPS enumeration
