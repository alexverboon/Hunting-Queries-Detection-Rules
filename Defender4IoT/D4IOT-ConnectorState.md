# Detect disconnected Defender for IoT Sensors

## Query Information

### Description

Use the below queries to retrieve the Defender for IoT Connector Status

#### References

- [Tutorial: Set up automatic sensor disconnection notifications with Microsoft Defender for IoT and Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/automate-sensor-disconnection-alerts)

### Author

- **Marian Hristov**
- **Alex Verboon**

## Defender XDR

```kql
arg("").iotsecurityresources  
| where type =='microsoft.iotsecurity/locations/sites/sensors'  
|extend Status=properties.sensorStatus  
|extend LastConnectivityTime=properties.connectivityTime  
|extend Status=iif(LastConnectivityTime<ago(5m),'Disconnected',Status)  
|project SensorName=name, Status, LastConnectivityTime  
//|where Status == 'Disconnected'
```

## Resource Graph

```kql
iotsecurityresources  
| where type =='microsoft.iotsecurity/locations/sites/sensors'  
|extend Status=properties.sensorStatus  
|extend LastConnectivityTime=properties.connectivityTime  
|extend Status=iif(LastConnectivityTime<ago(5m),'Disconnected',Status)  
|project SensorName=name, Status, LastConnectivityTime  
|where Status == 'Disconnected'
```
