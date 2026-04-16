# Microsoft Defender XDR - Critical Assets

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

The below queries retrieve Defender XDR Critical Asset Information. 

#### References

- [Overview of critical asset management](https://learn.microsoft.com/en-us/security-exposure-management/critical-asset-management)
- [Critical assets protection in Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/critical-assets-protection)

### Author

- **Alex Verboon**

### Credits

- **Nicola Suter**

## Defender XDR

Retrieve Defender XDR - Identities with Criticality Information

```kql
IdentityInfo
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| extend CriticalityLabel = case(
    CriticalityLevel == 0, "Very High",
    CriticalityLevel == 1, "High",
    CriticalityLevel == 2, "Medium",
    CriticalityLevel == 3, "Low",
    CriticalityLevel == 4, "Not defined",
    "Unknown"
)
| project AccountName,AccountUpn, AccountDisplayName, CriticalityLabel, Type
| sort by Type
```

All Assets

```kql
ExposureGraphNodes 
| where isnotempty(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| mv-expand RuleName = NodeProperties.rawData.criticalityLevel.ruleNames
| extend RuleBasedCriticalityLevel = NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel
| extend CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel
| extend isSensitive = NodeProperties.rawData.tags has "Sensitive"
| extend CriticalityLabel = case(
    CriticalityLevel == 0, "Very High",
    CriticalityLevel == 1, "High",
    CriticalityLevel == 2, "Medium",
    CriticalityLevel == 3, "Low",
    "Not Defined"
)
| extend RuleBasedCriticalityLabel = case(
    RuleBasedCriticalityLevel == 0, "Very High",
    RuleBasedCriticalityLevel == 1, "High",
    RuleBasedCriticalityLevel == 2, "Medium",
    RuleBasedCriticalityLevel == 3, "Low",
    "Not Defined"
)
| project NodeName, NodeLabel, RuleName, RuleBasedCriticalityLevel, RuleBasedCriticalityLabel, CriticalityLevel, CriticalityLabel, isSensitive
| sort by NodeLabel
```

Assets where the Criticality Level is assigned manually

```kql
ExposureGraphNodes 
| where isnotempty(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| mv-expand RuleName = NodeProperties.rawData.criticalityLevel.ruleNames
| extend RuleBasedCriticalityLevel = NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel
| extend CriticalityLevel = NodeProperties.rawData.criticalityLevel.criticalityLevel
| extend isSensitive = NodeProperties.rawData.tags has "Sensitive"
| extend CriticalityLabel = case(
    CriticalityLevel == 0, "Very High",
    CriticalityLevel == 1, "High",
    CriticalityLevel == 2, "Medium",
    CriticalityLevel == 3, "Low",
    "Not Defined"
)
| extend RuleBasedCriticalityLabel = case(
    RuleBasedCriticalityLevel == 0, "Very High",
    RuleBasedCriticalityLevel == 1, "High",
    RuleBasedCriticalityLevel == 2, "Medium",
    RuleBasedCriticalityLevel == 3, "Low",
    "Not Defined"
)
| project NodeName, NodeLabel, RuleName, RuleBasedCriticalityLevel, RuleBasedCriticalityLabel, CriticalityLevel, CriticalityLabel, isSensitive
| sort by NodeLabel
| where RuleName == "Manually Assigned"
```

