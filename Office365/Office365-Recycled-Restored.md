# Office 365 - SharePoint and OneDrive - Compare recycled vs. restored files

## Query Information

### Description

Use the below query to list all recycled (deleted) and compare with restored files

#### References

### Microsoft Sentinel / Defender XDR

```kql
let SourcePath = "Service Catalog/ServiceCatalog/";
let restored = (OfficeActivity
| where Operation in ("FileRestored","FolderRestored")
| where SourceRelativeUrl has (SourcePath)
| where ItemType <> "Folder"
| project TimeGenerated, Operation, UserId, Site_Url, SourceRelativeUrl, SourceFileName, SourceFileExtension, OfficeObjectId,ItemType, OfficeWorkload);
let recycled = (OfficeActivity
| where Operation in ("FileRecycled","FolderRecycled")
| where SourceRelativeUrl has  (SourcePath)
| where ItemType <> "Folder"
| project TimeGenerated, Operation, UserId, Site_Url, SourceRelativeUrl, SourceFileName, SourceFileExtension, OfficeObjectId,ItemType, OfficeWorkload);
recycled
| join kind=leftouter (restored)
on $left. OfficeObjectId == $right. OfficeObjectId
```
