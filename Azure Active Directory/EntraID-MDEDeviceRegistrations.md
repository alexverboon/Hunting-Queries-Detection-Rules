# EntraID - Microsoft Defender for Endpoint - Security Settings Management - Device Registrations

## Query Information

### Description

Use the below queries to see the Device registrations and deviceOSType changes in Entra ID initiated by Microsoft Defender for Endpoint Security Management.

#### References

- [Windows Server devices managed by Defender for Endpoint now recognized as a new OS platform](https://techcommunity.microsoft.com/t5/intune-customer-success/windows-server-devices-managed-by-defender-for-endpoint-now/ba-p/3767773)
- [Manage endpoint security policies on devices onboarded to Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/mem/intune/protect/mde-security-integration)
- [Security Settings Management in Microsoft Defender for Endpoint is now generally available](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/security-settings-management-in-microsoft-defender-for-endpoint/ba-p/3356970)
- [Simplified security settings management is now generally available](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/simplified-security-settings-management-is-now-generally/ba-p/3975158)
- [Manage security settings for Windows, macOS, and Linux natively in Defender for Endpoint](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/manage-security-settings-for-windows-macos-and-linux-natively-in/ba-p/3870617)
- [Manage endpoint security policies on devices onboarded to Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/mem/intune/protect/mde-security-integration#create-azure-ad-groups)


### Microsoft Sentinel

Auditlogs - Microsoft Entra ID Connector

```kql
AuditLogs
| where OperationName == "Update device" or OperationName == 'Add device'
| where Identity == "Microsoft Intune"
| extend modifiedProperties = parse_json(TargetResources)[0].modifiedProperties
| mv-expand modifiedProperties
| where modifiedProperties.displayName == "DeviceOSType"
| extend OldValue = tostring(parse_json(tostring(modifiedProperties.oldValue))[0])
| extend NewValue = tostring(parse_json(tostring(modifiedProperties.newValue))[0])
| extend DeviceName = tostring(TargetResources[0].displayName)
| project TimeGenerated, DeviceName, OldValue, NewValue, Identity, AADOperationType
```

CloudAppEvents - Defender for Cloud Apps Connector

```kql
CloudAppEvents
| where ActionType == "Add device." or ActionType == 'Update device.'
| where AccountDisplayName == "Microsoft Intune"
| extend modifiedProperties = parse_json(RawEventData).ModifiedProperties
| mv-expand modifiedProperties
| where modifiedProperties.Name == "DeviceOSType"
| extend NewValue = tostring(parse_json(tostring(modifiedProperties.NewValue))[0])
| extend OldValue = tostring(parse_json(tostring(modifiedProperties.OldValue))[0])
| project TimeGenerated, OldValue, NewValue, ActionType, AccountDisplayName, RawEventData
| mv-apply TargetResource = RawEventData.ModifiedProperties on (
    extend TargetResourcesTypes = extract_json("$.DisplayName","Name",typeof(string))
    | where TargetResource.Name == "DisplayName"
    )
| extend DeviceName = tostring(parse_json(tostring(TargetResource.NewValue))[0])
| project TimeGenerated, DeviceName, OldValue, NewValue, ActionType, AccountDisplayName
```
