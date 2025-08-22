# Microsoft Defender XDR - Threat Protection Reporting

## Query Information

### Description

Microsoft anounced that they will be retiring the Threat Protection report page - https://security.microsoft.com/mde-reports/threatProtection (accessed through Reports > Endpoints > Threat protection). Instead, they recommend the utilization of ***Advanced hunting queries*** and Alert queue filter in Defender XDR.

Use the below KQL queries to retrieve the information previously shown on the Threat Protection report.  

#### References

- [Threat Protection report page retirement](https://admin.microsoft.com/AdminPortal/home?ref=MessageCenter/:/messages/MC698130)

### Microsoft Defender XDR

Alert Techniques

```kql
AlertInfo
| extend Techniques = parse_json(AttackTechniques)
| mv-expand Techniques
| extend Technique = tostring(Techniques)
| summarize count() by Technique, bin(Timestamp, 1d)
| render timechart 
```

Alert Categories

```kql
AlertInfo
| summarize AlertCount=count() by Category , bin(Timestamp,1d)
| render timechart 
```

Detection sources

```kql
AlertInfo
| summarize AlertCount=count() by DetectionSource, bin(Timestamp, 1d)
| render timechart
```

Severity levels

```kql
AlertInfo
| summarize Total=count() by Severity, bin(Timestamp,1d)
| render timechart
```
