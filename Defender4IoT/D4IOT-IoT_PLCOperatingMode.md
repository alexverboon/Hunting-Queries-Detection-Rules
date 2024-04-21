# Defender for IoT - PLC Operating Mode Changed

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T0858 | Change Operating Mode | https://attack.mitre.org/techniques/T0858/ |

### Description

Use the below query to retrieve Security Alerts from Defender for IoT when a PLC Operating Mode change was detected.

#### References

- [Defender for IoT - Operational Engine Alerts](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/alert-engine-messages#operational-engine-alerts)

### Microsoft Sentinel

```kql
SecurityAlert
| where ProviderName == "IoTSecurity"
| where AlertName == "PLC Operating Mode Changed"
| extend SourceDeviceAddress = tostring(parse_json(ExtendedProperties).SourceDeviceAddress)
| extend SensorId = tostring(parse_json(ExtendedProperties).SensorId)
| project TimeGenerated, AlertName, AlertSeverity, AlertType,SensorId, SourceDeviceAddress, Description, Tactics, Techniques, ProductComponentName,RemediationSteps
```
