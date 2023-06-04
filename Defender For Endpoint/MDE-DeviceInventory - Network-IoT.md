# Microsoft Defender - Device Inventory - Network and IoT

## Query Information

### Description

Use the below queires to retrieve device inventory information of discovered Network and IoT devices

### References


### Microsoft 365 Defender


IoT Device Inventory

```Kusto
// IoT Device Inventory
DeviceInfo
| where DeviceCategory == @"IoT"
| summarize arg_max(Timestamp, *) by DeviceId
| join (
    DeviceNetworkInfo
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(parse_json(IPAddresses).IPAddress)
    | summarize arg_max(Timestamp, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| project Timestamp, DeviceId, DeviceName, DeviceType, DeviceSubtype, IPAddress, MacAddress, Model, Vendor, OSPlatform, OSVersion, OSDistribution, ExposureLevel
//| summarize count() by DeviceType, DeviceSubtype
```

Network Device Inventory

```kusto
// Network Device Inventory
DeviceInfo
| where DeviceCategory == @"NetworkDevice"
| summarize arg_max(Timestamp, *) by DeviceId
| join (
    DeviceNetworkInfo
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(parse_json(IPAddresses).IPAddress)
    | summarize arg_max(Timestamp, *) by DeviceId
    )
    on $left.DeviceId == $right.DeviceId
| project Timestamp, DeviceId, DeviceName, DeviceType, DeviceSubtype, IPAddress, MacAddress, Model, Vendor, OSPlatform, OSVersion, OSDistribution
//| summarize count() by DeviceType, DeviceSubtype
```


