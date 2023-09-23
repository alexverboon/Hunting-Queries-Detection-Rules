
# Defender External Attack Surface Management - Risky Assets

## Query Information

### Description

Use the below queries to find risky assets in Defender External Attack Surface Management

#### References

- [Tweet from @ellishlomo](https://twitter.com/ellishlomo/status/1668507719794319362?s=20)

### Microsoft Sentinel

List risky assets

```kql
EasmRisk_CL
| where AssetLastSeen_t >= ago(7d)
| where CategoryName_s == "High Severity"
| extend Rule = tostring(parse_json(AssetDiscoveryAuditTrail_s)[0].Rule)
| project TimeGenerated, AssetType_s, AssetName_s, CategoryName_s, Rule
```

List of all risky assets

```kql
EasmRisk_CL 
| where TimeGenerated > ago(180d)
| extend Severity = CategoryName_s
| extend Description = MetricDisplayName_s
| extend AssetType = AssetType_s
| extend AssetName = AssetName_s
| extend IPAddress = iff(AssetType == 'IP_ADDRESS',AssetName_s,"")
| extend Host = iff(AssetType == 'HOST',AssetName_s,"")
| extend Page = iff(AssetType == 'PAGE',AssetName_s,"")
| extend Domain = iff(AssetType == 'DOMAIN',AssetName_s,"")
| extend SSLCert = iff(AssetType == 'SSL_CERT',AssetName_s,"")
| project TimeGenerated, Severity, Description, AssetType, AssetName, IPAddress,Host, Domain, SSLCert, Page, AssetUuid_g
```
