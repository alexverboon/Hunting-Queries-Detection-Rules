# Microsoft Security Exposure Management - Critical Assets

## Query Information

### Description

Use the below queries to identify critical assets in Microsoft Security Exposure Management

#### References


### Microsoft Defender XDR

```kql
// Critical Identities
ExposureGraphNodes
| where set_has_element(Categories, "identity")
| where isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend criticalityLevel = parse_json(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| extend RuleNames = parse_json(NodeProperties.rawData.criticalityLevel.ruleNames)
| extend AccountUPN = tostring(NodeProperties.rawData.accountUpn);
```

```kql
// Critical Devices
ExposureGraphNodes
| where set_has_element(Categories, "compute")
| where isnotnull(NodeProperties.rawData.criticalityLevel) and NodeProperties.rawData.criticalityLevel.criticalityLevel < 4
| extend criticalityLevel = parse_json(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| extend eDeviceRole = parse_json(NodeProperties.rawData.deviceRole)[0]
| extend Devicename = tostring(NodeProperties.rawData.deviceName);

```

