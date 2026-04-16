# Microsoft Sentinel - E5 Security benefit

## Query Information

### Description

Use the below query to identify when the Sentinel E5 Security benefit is used.

#### References

- [Microsoft Sentinel benefit for Microsoft 365 E5, A5, F5, and G5 customers](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer#:~:text=Microsoft%20365%20E5%2C%20A5%2C%20F5%2C%20and%20G5%20and%20Microsoft,data%20ingestion%20into%20Microsoft%20Sentinel.)

- [Microsoft Sentinel]

```kql
Operation
| where OperationKey == "Benefit type used: SentinelMicrosoft365"

```

Each user has a Data Grant of 5 MB per day with the E5 Benefit. The query below shows the total GB and total Users. 

```kql
Operation
| where OperationKey == "Benefit type used: SentinelMicrosoft365"
| extend GBUsed = toreal(extract(@"Benefit amount used: (\d+\.\d+) GB", 1, Detail))
| summarize TotalGBUsed = sum(GBUsed)
| extend TotalUsers = (TotalGBUsed * 1024) / 5
```
