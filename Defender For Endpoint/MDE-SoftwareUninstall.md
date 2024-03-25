# TITLE

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

DESCRIPTION


#### References



### Microsoft 365 Defender




```kql
let ProductCodeGuid = "{23170F69-40C1-2702-2401-000001000000}";
DeviceProcessEvents
| where FileName contains "msiexec.exe"
| where ProcessCommandLine contains "\"msiexec.exe\" /qb /x" and ProcessCommandLine contains ProductCodeGuid 

let ProductCodeGuid = "{23170F69-40C1-2702-2401-000001000000}";
DeviceRegistryEvents
| where ActionType == "RegistryKeyDeleted"
| where PreviousRegistryKey == strcat("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",ProductCodeGuid)


// define the Installer GUIDs
let ProductGuids = datatable(GUID:string, ProductName:string,Version:string)
[
"23170F69-40C1-2702-2401-000001000000","7-Zip","24.01",
"23170F69-40C1-2702-2301-000001000000","7-Zip","23.01",
"7F39DBC3-B170-42A1-904A-660C6C3E886A","VNC",""
];
DeviceRegistryEvents
| where ActionType == "RegistryKeyDeleted" or ActionType == "RegistryKeyCreated"  // or ActionType == 'RegistryValueDeleted' or ActionType == 'RegistryValueSet'
| where InitiatingProcessFileName == "msiexec.exe"
| where PreviousRegistryKey has "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" or RegistryKey has "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
| extend UninstallGUID = case (
    isnotempty( PreviousRegistryKey),extract(@"\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}", 1, PreviousRegistryKey),
    isnotempty(RegistryKey),extract(@"\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}", 1, RegistryKey),"Unknown"
)
| extend CheckKey = case (
    isnotempty(RegistryKey), RegistryKey,
    isnotempty(PreviousRegistryKey), PreviousRegistryKey,"Unknown"
)
| where UninstallGUID has_any (ProductGuids)
| lookup kind=leftouter ProductGuids on $left. UninstallGUID == $right.GUID
| sort by TimeGenerated asc 
| extend TimeDiffMinutes = datetime_diff('minute', prev(TimeGenerated, 1), TimeGenerated)
| extend NextAction = next(ActionType)
| extend PrevAction = prev(ActionType)
| project TimeGenerated, DeviceName, UninstallGUID , ProductName, Version, CheckKey, InitiatingProcessCommandLine, RegistryKey, PreviousRegistryKey, ActionType, PrevAction, NextAction, TimeDiffMinutes
| summarize arg_max(TimeGenerated,*) by DeviceName, ProductName