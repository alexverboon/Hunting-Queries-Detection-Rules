
# AD Group Policy changes on devices

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1484.001 | Domain Policy Modification: Group Policy Modification | https://attack.mitre.org/techniques/T1484/001/ |

### Description

Use the below queries to to detect the following events on Defender for Endpoint devices

- Audit Policy changes
- Audit policy configuration file changes on domain controllers (Sysvol)
- Audit policy configuration file changes on clients 
- Scripts are added/modified within the SYSVOL share 
- Group Policy logon scripts are executed on clients 

#### References

- [[MS-GPAC]: Group Policy: Audit Configuration Extension](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/10d91136-2d82-46b9-9677-cf4d47ba2261)
- [2.2.1.2 Subcategory and SubcategoryGUID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [4719(S): System audit policy was changed](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719)

### Microsoft 365 Defender

Audit Policy Changes

```kql
DeviceEvents
| where ActionType == "AuditPolicyModification"
| extend polmod = parse_json(AdditionalFields)
| extend AuditPolicyChange = polmod.AuditPolicyChanges
| extend CategoryId = trim(@"[^\w]+",tostring(polmod.CategoryId))
| extend SubcategoryGuid = toupper(polmod.SubcategoryGuid)
| extend SubcategoryId = trim(@"[^\w]+",tostring(polmod.SubcategoryId))
// | project Timestamp, DeviceName, AuditPolicyChange, CategoryId, SubcategoryGuid, SubcategoryId
| mv-expand split(AuditPolicyChange,",")
| extend AuditPolicyChange = trim(@"[^\w]+",tostring(AuditPolicyChange))
| extend AuditPolicyChangesName = case(
    AuditPolicyChange  == "8448","Success Removed",
    AuditPolicyChange  == "8450","Failure Removed",
    AuditPolicyChange  == "8449","Success Added",
    AuditPolicyChange  == "8451","Failure Added","undefined")
| extend CategoryName = case (
CategoryId  == "8280","Account Logon",
CategoryId  == "8278","Account Management",
CategoryId  == "8276","Detrailed Tracking",
CategoryId  == "8279","DS Access",
CategoryId  == "8273","Logon/Logoff",
CategoryId  == "8274","Object Access",
CategoryId  == "8277","Policy Change",
CategoryId  == "8275","Privilege Use",
CategoryId  == "8272","System",
"undefined")
| extend SubcategoryName = case(
    // Accont Logon
    SubcategoryGuid == "0CCE923F-69AE-11D9-BED3-505054503030", "Credential Validation",
    SubcategoryGuid == "0CCE9242-69AE-11D9-BED3-505054503030", "Kerberos Authentication Service ",
    SubcategoryGuid == "0CCE9240-69AE-11D9-BED3-505054503030", "Kerberos Service Ticket Operations",
    SubcategoryGuid == "0CCE9241-69AE-11D9-BED3-505054503030", "Other Account Logon Events",
    // Account Managent
    SubcategoryGuid == "0CCE9239-69AE-11D9-BED3-505054503030", "Application Group Management",
    SubcategoryGuid == "0CCE9236-69AE-11D9-BED3-505054503030", "Computer Account Management",
    SubcategoryGuid == "0CCE9238-69AE-11D9-BED3-505054503030", "Distribution Group Management",
    SubcategoryGuid == "0CCE923A-69AE-11D9-BED3-505054503030", "Other Account Management Events",
    SubcategoryGuid == "0CCE9237-69AE-11D9-BED3-505054503030", "Security Group Management",
    SubcategoryGuid == "0CCE9235-69AE-11D9-BED3-505054503030", "User Account Management",
    // Detailed Tracking
    SubcategoryGuid == "0CCE922D-69AE-11D9-BED3-505054503030", "DPAPI Activity",
    SubcategoryGuid == "0CCE9248-69AE-11D9-BED3-505054503030", "PNP Activity",
    SubcategoryGuid == "0CCE922B-69AE-11D9-BED3-505054503030", "Process Creation",
    SubcategoryGuid == "0CCE922C-69AE-11D9-BED3-505054503030", "Process Termination",
    SubcategoryGuid == "0CCE922E-69AE-11D9-BED3-505054503030", "RPC Events",
    SubcategoryGuid == "0CCE924A-69AE-11D9-BED3-505054503030", "Audit Token Right Adjusted",
    // DS Access
    SubcategoryGuid == "0CCE923E-69AE-11D9-BED3-505054503030", "Detailed Directory Service Replication",
    SubcategoryGuid == "0CCE923B-69AE-11D9-BED3-505054503030", "Directory Service Access",
    SubcategoryGuid == "0CCE923C-69AE-11D9-BED3-505054503030", "Directory Service Changes",
    SubcategoryGuid == "0CCE923D-69AE-11D9-BED3-505054503030", "Directory Service Replication",
    // Logon - Logoff
    SubcategoryGuid == "0CCE9217-69AE-11D9-BED3-505054503030", "Account Lockout",
    SubcategoryGuid == "0CCE9247-69AE-11d9-BED3-505054503030", "User/Device Claims",
    SubcategoryGuid == "0CCE9249-69AE-11d9-BED3-505054503030", "Group Membership",
    SubcategoryGuid == "0CCE921A-69AE-11D9-BED3-505054503030", "IPsec Extended Mode",
    SubcategoryGuid == "0CCE9218-69AE-11D9-BED3-505054503030", "IPsec Main Mode",
    SubcategoryGuid == "0CCE9219-69AE-11D9-BED3-505054503030", "IPsec Quick Mode",
    SubcategoryGuid == "0CCE9216-69AE-11D9-BED3-505054503030", "Logoff",
    SubcategoryGuid == "0CCE9215-69AE-11D9-BED3-505054503030", "Logon",
    SubcategoryGuid == "0CCE9243-69AE-11D9-BED3-505054503030", "Network Policy Server",
    SubcategoryGuid == "0CCE921C-69AE-11D9-BED3-505054503030", "Other Logon/Logoff Events",
    SubcategoryGuid == "0CCE921B-69AE-11D9-BED3-505054503030", "Special Logon",
    // Object Access
    SubcategoryGuid == "0CCE9222-69AE-11D9-BED3-505054503030", "Application Generated",
    SubcategoryGuid == "0CCE9221-69AE-11D9-BED3-505054503030", "Certification Services",
    SubcategoryGuid == "0CCE9244-69AE-11D9-BED3-505054503030", "Detailed File Share",
    SubcategoryGuid == "0CCE9224-69AE-11D9-BED3-505054503030", "File Share",
    SubcategoryGuid == "0CCE921D-69AE-11D9-BED3-505054503030", "File System",
    SubcategoryGuid == "0CCE9226-69AE-11D9-BED3-505054503030", "Filtering Platform Connection",
    SubcategoryGuid == "0CCE9225-69AE-11D9-BED3-505054503030", "Filtering Platform Packet Drop",
    SubcategoryGuid == "0CCE9223-69AE-11D9-BED3-505054503030", "Handle Manipulation",
    SubcategoryGuid == "0CCE921F-69AE-11D9-BED3-505054503030", "Kernel Object",
    SubcategoryGuid == "0CCE9227-69AE-11D9-BED3-505054503030", "Other Object Access",
    SubcategoryGuid == "0CCE9227-69AE-11D9-BED3-505054503030", "Other Object Access",
    SubcategoryGuid == "0CCE921E-69AE-11D9-BED3-505054503030", "Registry",
    SubcategoryGuid == "0CCE9245-69AE-11D9-BED3-505054503030", "Removable Storage",
    SubcategoryGuid == "0CCE9220-69AE-11D9-BED3-505054503030", "SAM",
    SubcategoryGuid == "0CCE9246-69AE-11D9-BED3-505054503030", "Central Access Policy Staging",
    // Policy Change
    SubcategoryGuid == "0CCE922F-69AE-11D9-BED3-505054503030", "Audit Policy Change",
    SubcategoryGuid == "0CCE9230-69AE-11D9-BED3-505054503030", "Authentication Policy Change",
    SubcategoryGuid == "0CCE9231-69AE-11D9-BED3-505054503030", "Authorization Policy Change",
    SubcategoryGuid == "0CCE9233-69AE-11D9-BED3-505054503030", "Filtering Platform Policy Change",
    SubcategoryGuid == "0CCE9232-69AE-11D9-BED3-505054503030", "MPSSVC Rule-Level Policy Change",
    SubcategoryGuid == "0CCE9234-69AE-11D9-BED3-505054503030", "Other Policy Change Events",
    // Privilege Use
    SubcategoryGuid == "0CCE9229-69AE-11D9-BED3-505054503030", "Non Sensitive Privilege Use",
    SubcategoryGuid == "0CCE922A-69AE-11D9-BED3-505054503030", "Other Privilege Use Events",
    SubcategoryGuid == "0CCE9228-69AE-11D9-BED3-505054503030", "Sensitive Privilege Use",
    // System
    SubcategoryGuid == "0CCE9213-69AE-11D9-BED3-505054503030", "IPsec Driver",
    SubcategoryGuid == "0CCE9214-69AE-11D9-BED3-505054503030", "Other System Events",
    SubcategoryGuid == "0CCE9210-69AE-11D9-BED3-505054503030", "Security State Change",
    SubcategoryGuid == "0CCE9211-69AE-11D9-BED3-505054503030", "Security System Extension",
    SubcategoryGuid == "0CCE9212-69AE-11D9-BED3-505054503030", "the System Integrity",
    "undefined")
| project Timestamp, DeviceName, AuditPolicyChange, AuditPolicyChangesName, CategoryId, CategoryName, SubcategoryGuid, SubcategoryName,SubcategoryId 
| sort by Timestamp
// find events where auditing was Removed
// | where AuditPolicyChangesName contains "Removed"
```

Audit policy configuration file changes on domain controllers

```kql
let domainsysvol = @"\\corp.net\SysVol\";
DeviceFileEvents
| where FolderPath startswith domainsysvol
| where FileName == "audit.csv"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountUpn

```

Audit policy configuration file changes on clients

```kql
DeviceFileEvents
| where FileName == "audit.csv"
| distinct DeviceName, FileName, FolderPath, InitiatingProcessAccountName
| where FolderPath !contains "Sysvol"
| where InitiatingProcessAccountName != "system"
```

Scripts added/modified in SSYSVVOL

```kql
let domainsysvol = @"\\corp.net\SysVol\";
DeviceFileEvents
| where FolderPath startswith domainsysvol
| where FileName has_any (".exe",".ps1",".bat",".cmd","vbs","wsh",".wsf",".py")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountUpn

```

Logon Script execution

```kql
DeviceProcessEvents
| where FileName == "powershell.exe" or FileName == "cmd.exe"
| where InitiatingProcessFileName == 'gpscript.exe'
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
```

GPO Logon Script registry

```kql
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts"
| where RegistryValueData contains @"\SysVol\"
| where RegistryValueData has_any (".exe",".ps1",".bat",".cmd","vbs","wsh",".wsf",".py")
| project Timestamp, DeviceName, RegistryValueData, RegistryKey
```

### PowerShell

```PowerShell
# Retrieve Policy changes from Windows Event log
$polchanges = Get-WinEvent -FilterHashtable @{
   LogName='Security'
   id ='4719'
}
$event = $polchanges[0]
$eventXML = [xml]$event.ToXml() 
$eventXML.Event.EventData.Data
```

