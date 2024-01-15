# Microsoft Defender for Endpoint - Streamlined Connectivity

## Query Information

### Description

Use the below queries to get an overview of the devices connecting through the new streamlined connectivity for Microsoft Defender for Endpoint.

#### References

- [Announcing a streamlined device connectivity experience for Microsoft Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/announcing-a-streamlined-device-connectivity-experience-for/ba-p/3956236)
- [Onboarding devices using streamlined connectivity for Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-device-connectivity?view=o365-worldwide&branch=connect-devices)

### Microsoft Defener XDR

Show the total of devices per connectivity method

```kql
DeviceInfo
| where Timestamp > ago(30d)
| where OnboardingStatus == 'Onboarded'
| where DeviceCategory == 'Endpoint'
| summarize arg_max(Timestamp,*) by DeviceId
| where isempty( HostDeviceId) // exclude WSL, as they will create duplicate and adopt the connectivity type of the host
| extend ConnectivityType = iff(isempty( ConnectivityType),"Not-Streamlined",ConnectivityType)
| project DeviceName, OSPlatform, ConnectivityType, DeviceId 
| summarize Total = count() by ConnectivityType
```

### Microsoft Sentinel

The attribute ***ConnectivityType*** is currently not synched throuhg the Microosft Defender XDR Data connector in Sentinel, therefore the query cannot be executed there currently.
