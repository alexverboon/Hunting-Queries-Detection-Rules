# Microsoft Defender for Endpoint - Offboarding

## Query Information

### Description

Use the below queries to identify devices where the MDE offboarding file is saved or executed

#### References

- [Offboard devices from the Microsoft Defender for Endpoint service](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/offboard-machines?view=o365-worldwide)

### Defender 365

```kql
// MDE Offboarding script executed
DeviceProcessEvents
| where ProcessCommandLine contains @"MicrosoftDefenderATPOffboarding"
```

```kql
// MDE offboarding script detected on endpoint
DeviceFileEvents
| where FileName contains @"MicrosoftDefenderATPOffboarding"
```
