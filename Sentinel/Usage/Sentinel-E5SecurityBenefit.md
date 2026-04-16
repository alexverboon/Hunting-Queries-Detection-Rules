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

```kql
Operation
| where OperationKey == "Benefit type used: MicrosoftDefender"
| extend GBUsed = toreal(extract(@"Benefit amount used: (\d+\.\d+) GB", 1, Detail))
| summarize TotalGBUsed = sum(GBUsed)
| extend TotalP2 = (TotalGBUsed * 1024) / 500
```


let PricePerGB = 5.59;
let Days = 30;
// Sentinel M365 benefit
let M365_MBPerUserPerDay = 5;
let M365_GBPerUser = (M365_MBPerUserPerDay * Days) / 1024.0;
// Defender P2 benefit
let Defender_MBPerServer = 500;
let Defender_GBPerServer = Defender_MBPerServer / 1024.0;
Operation
| where TimeGenerated > ago(30d)
| where OperationKey in (
    "Benefit type used: SentinelMicrosoft365",
    "Benefit type used: MicrosoftDefender"
)
| extend GBUsed = toreal(extract(@"Benefit amount used: (\d+\.\d+) GB", 1, Detail))
| summarize TotalGBUsed = sum(GBUsed) by OperationKey
| extend
    EstimatedCount = case(
        OperationKey == "Benefit type used: SentinelMicrosoft365",
            round(TotalGBUsed / M365_GBPerUser, 0),
        OperationKey == "Benefit type used: MicrosoftDefender",
            round(TotalGBUsed / Defender_GBPerServer, 0),
        real(null)
    ),
    Unit = case(
        OperationKey == "Benefit type used: SentinelMicrosoft365", "Users",
        OperationKey == "Benefit type used: MicrosoftDefender", "Servers",
        ""
    ),
    EstSaving = round(TotalGBUsed * PricePerGB, 2)
| project
    Benefit = OperationKey,
    TotalGBUsed = round(TotalGBUsed, 2),
    EstimatedCount,
    Unit,
    PricePerGB = round(PricePerGB, 2),
    EstSaving




    let PricePerGB = 5.59;
Usage
| where TimeGenerated > ago(30d)
| summarize VolumeGB = sum(Quantity / 1024) by DataType, IsBillable
| summarize
    DeviceTablesGB     = round(sumif(VolumeGB, IsBillable == true  and DataType startswith "Device"), 2),
    OtherBillableGB    = round(sumif(VolumeGB, IsBillable == true  and not(DataType startswith "Device")), 2),
    TotalBillableGB    = round(sumif(VolumeGB, IsBillable == true), 2),
    TotalNonBillableGB = round(sumif(VolumeGB, IsBillable == false), 2)
| extend
    TotalGB = round(TotalBillableGB + TotalNonBillableGB, 2)
| extend
    DevicePctOfBillable = round(iff(TotalBillableGB == 0, 0.0, DeviceTablesGB * 100 / TotalBillableGB), 2),
    DevicePctOfTotal    = round(iff(TotalGB == 0, 0.0, DeviceTablesGB * 100 / TotalGB), 2),
    DeviceCost          = round(DeviceTablesGB * PricePerGB, 2),
    TotalCost           = round(TotalBillableGB * PricePerGB, 2)




    let PricePerGB = 5.59;
let Days = 30;
// -------------------------
// Ingestion (Usage)
// -------------------------
let Ingestion =
Usage
| where TimeGenerated > ago(30d)
| summarize VolumeGB = sum(Quantity / 1024) by DataType, IsBillable
| summarize
    DeviceTablesGB     = round(sumif(VolumeGB, IsBillable == true  and DataType startswith "Device"), 2),
    OtherBillableGB    = round(sumif(VolumeGB, IsBillable == true  and not(DataType startswith "Device")), 2),
    TotalBillableGB    = round(sumif(VolumeGB, IsBillable == true), 2),
    TotalNonBillableGB = round(sumif(VolumeGB, IsBillable == false), 2)
| extend
    TotalGB            = round(TotalBillableGB + TotalNonBillableGB, 2),
    TotalIngestionCost = round(TotalBillableGB * PricePerGB, 2);
// -------------------------
// Benefits (Operation)
// -------------------------
let M365_MBPerUserPerDay = 5;
let M365_GBPerUser = (M365_MBPerUserPerDay * Days) / 1024.0;
let Defender_MBPerServer = 500;
let Defender_GBPerServer = Defender_MBPerServer / 1024.0;
let Benefits =
Operation
| where TimeGenerated > ago(30d)
| where OperationKey in (
    "Benefit type used: SentinelMicrosoft365",
    "Benefit type used: MicrosoftDefender"
)
| extend GBUsed = toreal(extract(@"Benefit amount used: (\d+\.\d+) GB", 1, Detail))
| summarize TotalBenefitGB = round(sum(GBUsed), 2)
| extend
    TotalBenefitSaving = round(TotalBenefitGB * PricePerGB, 2);
// -------------------------
// Final result
// -------------------------
Ingestion
| extend joinKey = 1
| join kind=inner (
    Benefits
    | extend joinKey = 1
) on joinKey
| project-away joinKey
| extend
    NetCostAfterBenefits = round(TotalIngestionCost - TotalBenefitSaving, 2),
    BenefitCoveragePct   = round(iff(TotalBillableGB == 0, 0.0, TotalBenefitGB * 100 / TotalBillableGB), 2)