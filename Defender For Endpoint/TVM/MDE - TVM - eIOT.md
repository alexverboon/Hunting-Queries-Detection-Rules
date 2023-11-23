# Microsoft Defender for Endpoint - Enterprise IOT Exposure

## Query Information

### Description

Use the below queries to retreive the expore level information for MDE discovered EIOT devices. 

#### References

- [Get started with enterprise IoT monitoring in Microsoft 365 Defender](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/eiot-defender-for-endpoint)


### Microsoft Sentinel

Count of devices by exposure level

```kql
DeviceInfo
| summarize arg_max(TimeGenerated,*) by DeviceId
| where DeviceCategory == "IoT"
| summarize count() by ExposureLevel
```

Count of devices broken down by EIOT Device Type and Exposure level

```kql
DeviceInfo
| summarize arg_max(TimeGenerated,*) by DeviceId
| where DeviceCategory == "IoT"
| summarize count() by DeviceType, DeviceSubtype, ExposureLevel
```
