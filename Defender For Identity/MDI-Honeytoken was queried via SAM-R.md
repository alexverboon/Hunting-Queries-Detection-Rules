# Defender for Identity - Honeytoken was queried via SAM-R

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.002 | Account Discovery - Domain Account | https://attack.mitre.org/techniques/T1087/002/ |

### Description

Use the below query to identify Honeytoken accounts that are queried via SAM-R.

#### References

- [Microsoft Defender for Identity: "Honeytoken was queried via SAM-R alert" retires June 30, 2024](https://admin.microsoft.com/Adminportal/Home?ref=MessageCenter/:/messages/MC797115)

### Microsoft Sentinel

```kql
// add your honeyoken account SIDs here
let users = pack_array("S-1-5-21-", "S-1-5-21-");
IdentityQueryEvents
| where ActionType =='SAMR query'
| where QueryType == "QueryUser"
| extend TargetSid = tostring(parse_json(AdditionalFields.TargetAccountSid))
| where TargetSid in (users)
| extend TARGET_OBJECT_ENTITY_USER = tostring(AdditionalFields.["TARGET_OBJECT.ENTITY_USER"])
| extend FROM_DEVICE = tostring(AdditionalFields.["FROM.DEVICE"])
| extend TO_DEVICE = tostring(AdditionalFields.["TO.DEVICE"])
| project TimeGenerated, ActionType, TargetAccountDisplayName, TARGET_OBJECT_ENTITY_USER, FROM_DEVICE, TO_DEVICE
```
