# Defender - Sentinel - UEBA Generic Queries

## Query Information

### Description

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
BehaviorAnalytics
| summarize count() by ActionType
```


```kql
BehaviorEntities
| summarize count() by ActionType
```


```kql
BehaviorInfo
| summarize count() by ActionType
```



```kql
Anomalies
| distinct RuleName

```

```kql
UserPeerAnalytics


```




