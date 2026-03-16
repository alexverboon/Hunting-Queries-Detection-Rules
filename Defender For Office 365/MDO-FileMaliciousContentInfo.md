# Defender for Office - FileMaliciousContentInfo

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)

## Query Information

### Description

The FileMaliciousContentInfo table in the advanced hunting schema contains information about files that were processed by Microsoft Defender for Office 365 in SharePoint Online, OneDrive, and Microsoft Teams.

#### References

- [FileMaliciousContentInfo (Preview)](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-filemaliciouscontentinfo-table)

### Author

- **Alex Verboon**

## Defender XDR

```kql
FileMaliciousContentInfo
| where isnotempty( ThreatTypes)
| project TimeGenerated, Workload,FileName, FolderPath, FileOwnerUpn, ThreatNames, ThreatTypes, DetectionMethods, SHA256, ReportId
| sort by ThreatNames
```


