# Defender for IoT - FTP Authentication failure

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T0867 | Lateral Tool Transfer | https://attack.mitre.org/techniques/T0867/ |

### Description

Use the below query to retrieve Security Alerts from Defender for IoT when a failed FTP authentication event was detected.

You must create a custom alert rule in Defender for IoT

Name: FTP Authentication failure
Message: FTP Authentication failure
Conditions: FTPresponse_code > 0   or more specific (230 success / 530 failed)
Action: Alert

#### References

### Microsoft Sentinel

```kql
SecurityAlert
| where ProviderName == "IoTSecurity"
| where AlertType == "IoT_UserDefinedAlert"
| extend Description = tostring(parse_json(ExtendedProperties).["User Defined Description"])
| where parse_json(ExtendedProperties).["User Defined Description"] == "FTP Authentication failure"
| extend DestinationDevice = tostring(parse_json(ExtendedProperties).DestinationDevice)
| extend DestinationDeviceAddress = tostring(parse_json(ExtendedProperties).DestinationDeviceAddress)
| extend SourceDevice = tostring(parse_json(ExtendedProperties).SourceDevice)
| extend SourceDeviceAddress = tostring(parse_json(ExtendedProperties).SourceDeviceAddress)
| extend SensorId = tostring(parse_json(ExtendedProperties).SensorId)
| extend Protocol = tostring(parse_json(ExtendedProperties).Protocol)
| project TimeGenerated, AlertName, AlertSeverity, AlertType,SensorId, SourceDeviceAddress,DestinationDeviceAddress, Description, Tactics, Techniques, ProductComponentName, RemediationSteps, SourceDevice, DestinationDevice, Protocol
```
