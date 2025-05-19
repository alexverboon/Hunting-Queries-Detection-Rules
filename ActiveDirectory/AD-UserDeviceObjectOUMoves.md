# Active Directory - User or Device object OU moves

## Query Information

### Description

Use the below query to find Active Directory User or Device Object OU moves

#### References

### Microsoft Defender XDR

```kql
IdentityDirectoryEvents
| where ActionType == @"Account Path changed"
| extend FROMAccountPath = parse_json(AdditionalFields)["FROM Account Path"]
| extend TOAccountPath = parse_json(AdditionalFields)["TO Account Path"]
| project Timestamp, TargetAccountUpn, TargetDeviceName, FROMAccountPath, TOAccountPath

```
