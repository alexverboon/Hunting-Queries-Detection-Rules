# Defender for Identity - Automatic Windows auditing configuration

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

Microsoft is introducing a new opt-in feature for automatic event-auditing configuration in Defender for Identity unified sensors (V3.x). This enhancement simplifies deployment by allowing admins to automatically apply the required Windows event-auditing settings on their sensors. It reduces manual post-deployment steps and ensures consistent policy enforcement across all onboarded sensors.

Use the below KQL query to see the events related to automatic event auditing settings configuration.

#### References

- [Defender for Identity — Automatic Windows event auditing configuration](https://medium.com/@verboonalex/defender-for-identity-automatic-windows-event-auditing-configuration-0e7ed8e89f62)
- [MC1187403 - Automatic Windows event auditing configuration now available for unified sensors (V3.x)](https://mc.merill.net/message/MC1187403)
- [Configure audit policies for Windows event logs](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-windows-event-auditing-with-the-defender-for-identity-sensor-v3x)
- [Configure Windows event auditing](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-windows-event-auditing-with-the-defender-for-identity-sensor-v3x)
- [Configure Advanced Audit Policy settings from the UI](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection#configure-advanced-audit-policy-settings-from-the-ui)

### Author

- **Alex Verboon**

## Defender XDR

```kql
DeviceEvents
| where ActionType == "AuditPolicyModification"
| extend polmod = parse_json(AdditionalFields)
| extend AuditPolicyChange = polmod.AuditPolicyChanges
| extend CategoryId = trim(@"[^\w]+",tostring(polmod.CategoryId))
| extend SubcategoryGuid = toupper(polmod.SubcategoryGuid)
| extend SubcategoryId = trim(@"[^\w]+",tostring(polmod.SubcategoryId))
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
| project Timestamp, DeviceName, AuditPolicyChange, AuditPolicyChangesName, CategoryName, SubcategoryGuid, SubcategoryName, CategoryId,SubcategoryId, InitiatingProcessFileName 
| sort by Timestamp
| extend Status = case(
        AuditPolicyChangesName endswith "Added", "🟢",
        AuditPolicyChangesName endswith "Removed", "🔴",
        ""
    )
| extend EventIds = case(
        // ACCOUNT LOGON
        SubcategoryName == "Credential Validation", "4776",
        // ACCOUNT MANAGEMENT
        SubcategoryName == "Computer Account Management", "4741, 4743",
        SubcategoryName == "Distribution Group Management", "4753, 4763",
        SubcategoryName == "Security Group Management", "4728, 4729, 4730, 4732, 4733, 4756, 4757, 4758",
        SubcategoryName == "User Account Management", "4726",
        // DS ACCESS
        SubcategoryName == "Directory Service Changes", "5136",
        SubcategoryName == "Directory Service Access", "4662",
        // SYSTEM
        SubcategoryName == "Security System Extension", "7045",
        // DEFAULT
        "Unknown"
    )
//| where InitiatingProcessFileName == @"senseidentity.exe"
//| distinct CategoryName, SubcategoryName, Status
```
