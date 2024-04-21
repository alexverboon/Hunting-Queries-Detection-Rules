# Defender for Endpoint - Azure Information Protection Client

## Query Information

### Description

Use the below queries to find devices with Azure Information protection client installed.

#### References

- [Azure Information Protection Add-in for Office retires in April](https://admin.microsoft.com/Adminportal/Home?ref=MessageCenter/:/messages/MC724833)

- [Azure Information Protection unified labeling client - Release management and supportability](https://learn.microsoft.com/en-us/azure/information-protection/rms-client/unifiedlabelingclient-version-release-history)

- [Retirement notification for the Azure Information Protection Unified Labeling add-in for Office](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/retirement-notification-for-the-azure-information-protection/ba-p/3791908)

### Microsoft Defender XDR

// list all devices that have the Azure Information Protection Client installed

```kql
DeviceTvmSoftwareInventory
| where SoftwareName == @"microsoft_azure_information_protection"
| project DeviceId, DeviceName,SoftwareName, SoftwareVersion
```
