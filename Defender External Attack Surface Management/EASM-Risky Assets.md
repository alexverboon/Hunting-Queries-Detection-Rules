
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


