# MDE - Microsoft Exchange Server version

## Query Information

### Description

Use the below query to find exchange servers and then lookup the exchange version information, release date and build name

#### References

- [HAFNIUM - Exchange](https://security.microsoft.com/threatanalytics3/4ef1fbc5-5659-4d9b-b32e-97a694475955/overview)

### Microsoft 365 Defender / Microsoft Sentinel

```kql
// Find exchange servers that run umworkerprocess.exe and then lookup the exchange version information, release date and build name

let exchangeserverioninfo = (externaldata (ProductName:string, ReleaseDate:string, Build_short:string, Build_long:string)
[@"https://raw.githubusercontent.com/alexverboon/MDATP/master/AdvancedHunting/Exchange/exchnage_versions.csv"]
with(format="csv",ignoreFirstRecord=true))
| where ProductName !startswith "#"
| project ProductName,ReleaseDate, Build_long, Build_short;
// exchangeserverioninfo
// Identify Exchange servers with umworkerprocess.exe
DeviceProcessEvents
| where FileName contains "umworkerprocess.exe"
| where FolderPath  contains @"\Exchange\Bin\"
| distinct DeviceName,tostring(ProcessVersionInfoProductName), ProcessVersionInfoProductVersion, FolderPath
| join kind=leftouter  exchangeserverioninfo
on $left.ProcessVersionInfoProductVersion == $right. Build_long
```

```kql
// Find Exchange servers using Defender for Endpoint Threat and vulnerability inventory data

let exchangeserverioninfo = (externaldata (ProductName:string, ReleaseDate:string, Build_short:string, Build_long:string)
[@"https://raw.githubusercontent.com/alexverboon/Hunting-Queries-Detection-Rules/main/ExternalData/exchnage_versions.csv"]
with(format="csv",ignoreFirstRecord=true))
| where ProductName !startswith "#"
| project ProductName,ReleaseDate, Build_long, Build_short;
// Identify Exchange servers based on TVM inventory data
DeviceTvmSoftwareInventory 
| where SoftwareVendor contains "Microsoft"
| where SoftwareName == @"exchange_server"
| distinct DeviceName, SoftwareName, SoftwareVendor, SoftwareVersion, OSPlatform, OSVersion, OSArchitecture  
| join kind=leftouter  exchangeserverioninfo
on $left.SoftwareVersion == $right. Build_short
| project DeviceName, OSPlatform, OSVersion, OSArchitecture, SoftwareName, SoftwareVersion, ProductName, ReleaseDate, Build_short
```
