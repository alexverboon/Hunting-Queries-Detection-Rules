# Microsoft Office 365 - Version History Information

## Query Information

### Description

Use this KQL query to retreive information about your Microsoft Office installations across MDE managed devices. The query joins endpoint inventory data with public Office update history feed data. The query extend the MDE Software Inventory data with the following information:

- Office deployment Channel
- Release Date
- The total # of months the release was supported until its EOS date
- The total of months since the release of the appropriate version.

#### Office Update Feed Data

The [Office Update history feed](https://github.com/alexverboon/Feeds/blob/main/data/office_update_history_2018-present.csv) is updated every day at 06:00 UTC

#### Author

- **Alex Verboon**

#### References

- [Update history for Microsoft 365 Apps (listed by date)](https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date)

## Defender XDR

```kql
let officeversionhistory = (externaldata(ReleaseDate:datetime , Channel:string, Version:string,Build:string)[@'https://raw.githubusercontent.com/alexverboon/Feeds/refs/heads/main/data/office_update_history_2018-present.csv']
with (format="csv", ignoreFirstRecord=true));
DeviceTvmSoftwareInventory
| where SoftwareVendor contains "microsoft"
| where SoftwareName == 'office'
| project DeviceName, SoftwareName, SoftwareVersion, EndOfSupportDate, EndOfSupportStatus
| extend Shortbuild = strcat_array(array_slice(split(SoftwareVersion, "."), 2, -1), ".")
| extend EndOfSupportDate = todatetime(format_datetime(EndOfSupportDate, 'yyyy-MM-dd'))
| join kind=leftouter (officeversionhistory
| extend ReleaseDate = todatetime(format_datetime(ReleaseDate, 'yyyy-MM-dd'))
)
on $left. Shortbuild == $right.Build
| extend MnthsSupported = datetime_diff('month', EndOfSupportDate, ReleaseDate)
| extend MonthsSinceRelease = datetime_diff('month',now(),ReleaseDate)
| summarize TotalDevices = dcount(DeviceName,4) by SoftwareName, SoftwareVersion, EndOfSupportDate,EndOfSupportStatus, Shortbuild, ReleaseDate,Channel, Version, Build,MnthsSupported,MonthsSinceRelease
```

## Sentinel

n/a, because the **DeviceTvmSoftwareInventory** is not present in Sentinel.
