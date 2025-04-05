# Defender for Endpoint - Identify Portable Apps

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title       | Link   |
|--------------|-------------|--------------------------------------------|
| T1036        | Masquerading| https://attack.mitre.org/techniques/T1036  |

### Description

Use the below query to find portable applications across endpoints onboarded to Defender for Endpoint.

### Risk

Portable apps can be used to mimic legitimate software without installation, helping attackers evade detection.

### Author

- **Alex Verboon**

#### References

### Microsoft Defender XDR

Show Portable files

```kql
DeviceFileEvents
| where parse_json( AdditionalFields).FileType has_any ("PortableExecutable")
| extend FileExtension = parse_path(FolderPath).Extension
| where FileExtension == "exe"
| project FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, AdditionalFields
| where isnotempty( FileOriginUrl)
```

Show Portable files by download URL

```kql
DeviceFileEvents
| where parse_json( AdditionalFields).FileType has_any ("PortableExecutable")
| extend FileExtension = parse_path(FolderPath).Extension
| where FileExtension == "exe"
| project FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, AdditionalFields
| where isnotempty( FileOriginUrl)
| summarize  Files = make_set(FileName), count() by FileOriginReferrerUrl
```

Show files downloaded from [portableapps.com](https://portableapps.com/)

```kql
DeviceFileEvents
| where FileOriginReferrerUrl == "https://portableapps.com/"
```

List executed Portable Apps from User folders or other locations other than Windows / Program Files and Program Data

```kql
DeviceProcessEvents
| where AccountName <> "system"
| where FolderPath matches regex @"^[A-Z]:\\.*$" // Any drive letter
    or FolderPath startswith @"\\" // Network shares
    or FolderPath matches regex @"^C:\\Users\\[^\\]+\\Downloads\\.*$" // Include C:\Users\*\Downloads
    or FolderPath matches regex @"^C:\\Users\\[^\\]+\\Desktop\\.*$" // Include C:\Users\*\Desktop
| where not(FolderPath matches regex @"^C:\\Windows\\.*$") // Exclude C:\Windows and subfolders
| where not(FolderPath matches regex @"^C:\\Program Files( \(x86\))?\\.*$") // Exclude C:\Program Files and Program Files (x86)
| where not(FolderPath matches regex @"^C:\\ProgramData\\.*$") // Exclude C:\ProgramData
| where not(AccountSid startswith "S-1-5-18") // Exclude Local System Account
| where not(AccountSid startswith "S-1-5-20") // Exclude Network Service Account
| project TimeGenerated, FileName, FolderPath, AccountName, AccountUpn, ProcessVersionInfoProductName
```

List executed portable apps that have portable in the executable product name

```kql
DeviceProcessEvents
| project TimeGenerated, FileName, FolderPath, AccountName, AccountUpn, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName
| where ProcessVersionInfoProductName has "portable"
```
