# Entra ID - Administrative Units

## Query Information

### Description

Queries for Entra ID Administrtive Units related activities

#### References

- [Administrative units in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units)
- [Protection of privileged users and groups by Azure AD Restricted Management Administrative Units](https://www.cloud-architekt.net/restricted-management-administrative-unit/)
- [Monitoring Restricted Management Administrative Units Abuse](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules/blob/4158320dc80ea58891c043321e293b21458d00b5/Sentinel/Monitoring%20restricted%20management%20administrative%20units%20abuse.kql)
- [Exploring Entra ID Restricted Management Administrative Units with KQL](https://kaidojarvemets.com/exploring-azure-active-directorys-restricted-management-administrative-units-with-kql/)

### Microsoft Defender XDR / Sentinel

Entra ID Audit log

```kql
let monitoredOperations = dynamic([
    "Add member to administrative unit",
    "Add member to role scoped over Restricted Management Administrative Unit",
    "Remove member from role scoped over Restricted Management Administrative Unit",
    "Add member to restricted management administrative unit",
    "Remove member from restricted management administrative unit"
]);
AuditLogs
| where OperationName in~ (monitoredOperations)
```

CloudAppEvents (Defender for Cloud Apps Connector) (note the . (dot) at the end of the ActionTpe name)

```kql
let monitoredOperations = dynamic([
    "Add member to administrative unit.",
    "Add member to role scoped over Restricted Management Administrative Unit.",
    "Remove member from role scoped over Restricted Management Administrative Unit.",
    "Add member to restricted management administrative unit.",
    "Remove member from restricted management administrative unit."
]);
CloudAppEvents
| where ActionType  in~ (monitoredOperations)
```
