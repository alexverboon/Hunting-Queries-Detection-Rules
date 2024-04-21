# Defender for IoT - MaliciousNameQueriesDetection

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T0883 | Internet Accessible Device | https://attack.mitre.org/techniques/T0883/ |
| T0884 | Connection Proxy | https://attack.mitre.org/techniques/T0884/ |

### Description

Use the below query to retrieve Security Alerts from Defender for IoT when a request was made to resolve a domain name that is a known malicious domain. Requests made for this domain IP address may indicate that the source making the request is infected with malware.

Microsoft Defender for IoT creates an Alert automatically called "Malicious Domain Name Request", use the below query to gather information or to create a custom Sentinel Analytics rule.

#### References

- [Defender for IoT - Malware engine alerts](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/alert-engine-messages#malware-engine-alerts)

### Microsoft Sentinel

```kql
SecurityAlert
| where ProviderName == "IoTSecurity"
| where AlertType == "IoT_MaliciousNameQueriesDetection"
| extend SourceDeviceAddress = tostring(parse_json(ExtendedProperties).SourceDeviceAddress)
| extend SensorId = tostring(parse_json(ExtendedProperties).SensorId)
| extend Additional_Information = tostring(parse_json(ExtendedProperties).["Additional Information"])
| extend IOC = tostring(parse_json(ExtendedProperties).IOC)
| extend Port = tostring(parse_json(ExtendedProperties).Port)
| project TimeGenerated, AlertName, AlertSeverity, AlertType,SensorId, SourceDeviceAddress, Description, Tactics, Techniques, ProductComponentName, Additional_Information, IOC, Port, RemediationSteps
```
