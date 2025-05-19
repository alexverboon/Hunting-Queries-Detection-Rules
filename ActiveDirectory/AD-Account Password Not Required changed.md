# Active Directory - Account Password Not Required changed

## Query Information

### Description

Use the below query to see ***Account Password Not Required changed*** events

#### References

### Microsoft Defender XDR

```kql
IdentityDirectoryEvents
| where ActionType == @"Account Password Not Required changed"
| extend NewValue = parse_json(AdditionalFields)["NewValue"]
| extend OldValue = parse_json(AdditionalFields)["OldValue"]
| project Timestamp, TargetAccountUpn, TargetAccountDisplayName, AccountName, AccountUpn, NewValue, OldValue
```
