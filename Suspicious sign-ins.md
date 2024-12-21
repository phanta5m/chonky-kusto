### Looking for suspicious sign-ins based off IOC's identified in sign-in and audit logs

#### A join of 2 tables

- Sign-in logs with obvious IOC's like:
  - "OfficeHome"
  - Where the device is not AD joined
  - Where the IP location != the local region (in context, this would be "Illinois")
  - Where the IP is an IPv4
 
- Audit logs with artifacts like:
  - "User registered info"
  - "User deleted security info"
 
```kusto
Let sus_Users = SigninLogs
| where AppDisplayName == "OfficeHome"
| where not(DeviceDetail has "Hybrid Azure AD joined")
| where not(LocationDetail has "Illinois")
| where IPAddress matches regex @"^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
| summarize by UserPrincipalName;
AuditLogs
| where OperationName == "User registered security info" or OperationName == "User deleted security info"
| extend userPrincipalName = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| where userPrincipalName in (sus_Users)
| summarize by userPrincipalName
```
