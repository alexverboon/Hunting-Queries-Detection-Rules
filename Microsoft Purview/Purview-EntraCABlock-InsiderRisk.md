# Microsoft Purview - Entra ID - Conditional Access - Block - Insider Risk

## Query Information

### Description

Identify Conditional Acces block events due to Microsoft Purview Insider Risk.

#### References

### Microsoft Sentinel

```kql
SigninLogs
| where ResultType == "53003"
| mv-expand ConditionalAccessPolicies
| extend CAdisplayName = tostring(ConditionalAccessPolicies.displayName)
| where CAdisplayName has "Insider Risk"
| extend EnforcedGrantControls = tostring(parse_json(tostring(ConditionalAccessPolicies.enforcedGrantControls))[0])
| where EnforcedGrantControls == "Block"
| where ConditionalAccessPolicies.result == "failure"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress, Location, CAdisplayName
```
