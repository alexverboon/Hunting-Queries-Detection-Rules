# Developers - GIT Remote

## Query Information

### Description

DESCRIPTION


#### References



### Microsoft 365 Defender




```kql
DeviceProcessEvents
| where FileName == "git.exe"
| where ProcessCommandLine startswith "git remote"
| extend Remote = extract(@"origin\s+(https:\/\/[^\s]+)", 1, ProcessCommandLine)
| project Remote, FileName, InitiatingProcessFileName, ProcessCommandLine, AccountUpn, DeviceName
| summarize Devices = make_set(DeviceName), TotalDevices = dcount(DeviceName), Users = make_set(AccountUpn), TotalUsers = dcount(AccountUpn) by Remote
```






DeviceProcessEvents
| where ProcessCommandLine contains "git "
| extend GitRepo = extract(@"(https?:\/\/[^\s]+\.git|https?:\/\/[^\s]+_git\/[^\s]+)", 0, ProcessCommandLine)
| where isnotempty(GitRepo)
| project GitRepo, FileName, InitiatingProcessFileName, ProcessCommandLine, AccountUpn, DeviceName
| summarize Devices = make_set(DeviceName), TotalDevices = dcount(DeviceName), Users = make_set(AccountUpn), TotalUsers = dcount(AccountUpn) by GitRepo



DeviceProcessEvents
| where ProcessCommandLine contains "-c include.path="
| extend LocalPath = extract(@"-c include\.path=([a-zA-Z]:\\[^\s]+)", 1, ProcessCommandLine)
| where isnotempty(LocalPath)
| extend UserPath = parse_path(LocalPath).DirectoryPath
| project TimeGenerated,UserPath, DeviceName,AccountName, AccountUpn, ProcessCommandLine


DeviceProcessEvents
| where FileName contains "pip.exe"
| where ProcessCommandLine contains "install"
| extend ModuleName = extract("install\\s+([^\\s]+)", 1, ProcessCommandLine)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, ModuleName


let developersoftware = dynamic(['jetbrains','Eclipse']);
DeviceTvmSoftwareInventory
| where SoftwareVendor has_any (developersoftware)

let exclude = dynamic(['++']);
let developersoftware = dynamic(['Code','Visual']);
DeviceTvmSoftwareInventory
| where not(SoftwareName  has_any(exclude))
| where SoftwareName  has_any (developersoftware)
| summarize count() by SoftwareName



