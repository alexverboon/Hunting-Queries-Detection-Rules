# MDE - Local Account Creation

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.001  | Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001/ |

### Description

Use the below query to detect new local user account creation events. The query excludes domain controllers and let's you also specific LAPS accounts (Microsoft Local Administrator Account Solution)


#### References


### Microsoft 365 Defender


```kql
let AllDomainControllers =
        DeviceNetworkEvents
        | where Timestamp > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        //| extend DCDevicename = tostring(split(DeviceName,".")[0])
        | extend DCDevicename = DeviceName
        | distinct DCDevicename;
// COM003 – Local User creation 
let LapsAccounts = dynamic (["locadm","pcadm"]);
DeviceEvents
| where ActionType == "UserAccountCreated" 
| where AccountName !in (LapsAccounts)
| where DeviceName !in (AllDomainControllers)
| where AccountName != "defaultuser1"
```

### Microsoft Sentiel

```
let AllDomainControllers =
        DeviceNetworkEvents
        | where TimeGenerated > ago(7d)
        | where LocalPort == 88
        | where LocalIPType == "FourToSixMapping"
        | extend DCDevicename = DeviceName
        | distinct DCDevicename;
let LapsAccounts = dynamic (["locadm","pcadm"]);
DeviceEvents
| where ActionType == "UserAccountCreated" 
| where AccountName !in (LapsAccounts)
| where DeviceName !in (AllDomainControllers)
| where AccountName != "defaultuser1"

