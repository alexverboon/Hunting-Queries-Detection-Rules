# Microsoft Defender for Endpoint - Certificates - DigiCert Global Root G2

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

The below KQL queries assist in identifying devices that don't have the DigiCert Global Root G2 Certificate installed.

- Query 1: Find all devices with and without the DigiCert Global Root G2 certificate
- Query 2: Same as the first query but enriched with missing security updates information when available.
- Query 3: Devices that have no Defender TVM Certificate Invetory Data

> To use this query and retrieve data from the *DeviceTvmCertificateInfo* table you'll require Microsoft Defender Vulnerability Management Standalone or if you're already a Microsoft Defender for Endpoint Plan 2 customer, the Defender Vulnerability Management add-on.

#### References

- [MC1193408 - (Update)Action Required: Trust DigiCert Global Root G2 Certificate Authority for using Entra services by January 7, 2026](https://mc.merill.net/message/MC1193408)
- [Microsoft Defender Vulnerability Management - Certificate inventory](https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-certificate-inventory)
- [ConfigMgr - Connectivity issues if the DigiCert Global Root G2 root certificate is not installed](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/setup-migrate-backup-recovery/connectivity-issues-digicert-global-root-g2-not-installed)
- [DigiCert Trusted Root Authority Certificates](https://knowledge.digicert.com/general-information/digicert-trusted-root-authority-certificates)

### Author

- **Alex Verboon**

## Defender XDR

Find all devices with and without the DigiCert Global Root G2 certificate

```kql
let CertCount = DeviceTvmCertificateInfo
| summarize TotalCerts = count() by DeviceId;
DeviceInfo
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(Timestamp,*) by DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, JoinType
| join kind=leftouter (DeviceTvmCertificateInfo
| extend IssuedTo_CommonName = tostring(parse_json(IssuedTo)["CommonName"])
| where IssuedTo_CommonName == "DigiCert Global Root G2")
on $left. DeviceId == $right. DeviceId
| summarize arg_max(Timestamp,*) by DeviceId
| extend CertPresent = iff(isnotempty( IssuedTo_CommonName),"Yes","No")
| project Timestamp,DeviceId, DeviceName,OSPlatform, JoinType, CertPresent, IssuedTo_CommonName, ExpirationDate,Path
| join kind=leftouter  CertCount
on $left. DeviceId == $right. DeviceId
| extend TotalCerts = iff(TotalCerts > 0,TotalCerts,0)
| project Timestamp, DeviceId,DeviceName, OSPlatform, JoinType,TotalCerts, CertPresent, IssuedTo_CommonName, ExpirationDate,Path
//| where CertPresent == "No" and TotalCerts > 0
```

Find all devices without the DigiCert Global Root G2 certificate and missing security updates information.

```kql
let missingkb = DeviceTvmSoftwareVulnerabilities
| where SoftwareVendor == 'microsoft'
| where SoftwareName matches regex @"(?i)^windows.*\d+$"
| where isnotempty(RecommendedSecurityUpdate)
| distinct DeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| join kind=leftouter (
    DeviceInfo
    | where isnotempty(OSPlatform)
    | where OnboardingStatus == 'Onboarded'
    | where isnotempty(OSVersionInfo)
    | summarize arg_max(Timestamp, *) by DeviceId)
    on $left.DeviceId == $right.DeviceId
| summarize MissingKBs = make_set(RecommendedSecurityUpdate) by DeviceName, DeviceId
| extend TotalMissingKB = array_length(MissingKBs);
let CertCount = DeviceTvmCertificateInfo
| summarize TotalCerts = count() by DeviceId;
DeviceInfo
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(Timestamp,*) by DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, JoinType
| join kind=leftouter (DeviceTvmCertificateInfo
| extend IssuedTo_CommonName = tostring(parse_json(IssuedTo)["CommonName"])
| where IssuedTo_CommonName == "DigiCert Global Root G2")
on $left. DeviceId == $right. DeviceId
| summarize arg_max(Timestamp,*) by DeviceId
| extend CertPresent = iff(isnotempty( IssuedTo_CommonName),"Yes","No")
| project Timestamp,DeviceId, DeviceName,OSPlatform, JoinType, CertPresent, IssuedTo_CommonName,ExpirationDate, Path
| join kind=leftouter missingkb
on $left. DeviceId == $right. DeviceId
| project Timestamp, DeviceId,DeviceName, OSPlatform, JoinType, CertPresent, IssuedTo_CommonName, ExpirationDate, TotalMissingKB, MissingKBs,Path 
| join kind=leftouter  CertCount
on $left. DeviceId == $right. DeviceId
| extend TotalCerts = iff(TotalCerts > 0,TotalCerts,0)
| project Timestamp, DeviceId,DeviceName, OSPlatform, JoinType,TotalCerts, CertPresent, TotalMissingKB, MissingKBs, IssuedTo_CommonName, ExpirationDate,Path
| where CertPresent == "No" and TotalCerts > 0
```

Devices that have no Defender TVM Certificate Invetory Data

```kql
let CertCount = DeviceTvmCertificateInfo
    | summarize TotalCerts = count() by DeviceId;
DeviceInfo
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceId, DeviceName, OSPlatform, ClientVersion, OSBuild, OsBuildRevision, JoinType
| join kind=leftouter CertCount
    on $left.DeviceId == $right.DeviceId
| extend TotalCerts = iff(TotalCerts > 0, TotalCerts, 0)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ClientVersion,
    OSPlatform,
    OSBuild,
    OsBuildRevision,
    JoinType,
    TotalCerts
| where TotalCerts == 0
```
