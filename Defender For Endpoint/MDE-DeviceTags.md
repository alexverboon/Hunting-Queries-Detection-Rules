# Defender for Endpoint - Device Tags

## Query Information

### Description

DESCRIPTION

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
DeviceInfo
| project DeviceName, OnboardingStatus, DeviceCategory,MachineGroup, DeviceManualTags, DeviceDynamicTags, RegistryDeviceTag


DeviceInfo
| summarize ManualTags  = make_set(DeviceManualTags, 10000),
            DynamicTags = make_set(DeviceDynamicTags, 10000),
            RegTags     = make_set(RegistryDeviceTag, 10000)


// Unique Tags set, regardless of method

// Manual tags
let ManualTags =
    DeviceInfo
    | mv-expand Tag = parse_json(DeviceManualTags)
    | where isnotempty(Tag)
    | project Tag = tostring(Tag);
// Dynamic tags
let DynamicTags =
    DeviceInfo
    | mv-expand Tag = parse_json(DeviceDynamicTags)
    | where isnotempty(Tag)
    | project Tag = tostring(Tag);
// Registry tags
let RegistryTags =
    DeviceInfo
    | mv-expand Tag = parse_json(RegistryDeviceTag)
    | where isnotempty(RegistryDeviceTag)
    | project Tag = tostring(RegistryDeviceTag);
// All unique tags
ManualTags
| union DynamicTags
| union RegistryTags
| summarize UniqueTags = make_set(Tag)
```

## Sentinel

```kql
```
