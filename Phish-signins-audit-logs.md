## Interactive sign-in Logs, Risk Logs, Audit logs
#### A quick check when remediating a phishing incident

<p>Combines via 'union' the interactive sign-ins, risk events, and audit logs for a quick glance to see if the attacker was successful, 
  made MFA changes, increased the risk score, or all three</p>

- First function is for SigninLogs
- Second function is for Risk Events
- Third function is for AuditLogs
- 'Union' all 3 for a birds eye view

```kusto
let User1 = dynamic([
"mbolton@test.org", "michael.bolton@test.org"
]);
let days = 12h;
//╚═════════════════════════════════════════════╝
let signins = SigninLogs
| where TimeGenerated > ago(days) | where UserPrincipalName has_any(User1)
| extend auth = tostring(parse_json(AuthenticationDetails)[0].succeeded) | extend mfa = tostring(parse_json(AuthenticationDetails)[1].succeeded) | extend auth_mthd = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend ParsedJson1 = parse_json(MfaDetail) | extend authDetail = tostring(ParsedJson1.authDetail) | extend AuthDetail = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| extend deviceName = tostring(parse_json(DeviceDetail).displayName) | extend deviceID = tostring(parse_json(DeviceDetail.deviceId)) | extend Trust = tostring(parse_json(DeviceDetail.trustType)) | extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend city = tostring(parse_json(LocationDetails).city) | extend state = tostring(parse_json(LocationDetails).state) | extend region = strcat(city, ", ", state, ", ", Location) | extend CAS = ConditionalAccessStatus | extend Source = "SI_Logs"
| summarize arg_min(TimeGenerated, *) by Source,UserDisplayName,UserPrincipalName,region, IPAddress, AuthenticationRequirement, auth, CAS, AuthDetail, authDetail, deviceName, deviceID, Trust, OS, AppDisplayName, UserAgent, RiskDetail, RiskLevelDuringSignIn, RiskState
| project Source,TimeGenerated, UserDisplayName,UserPrincipalName,region, IPAddress, AuthenticationRequirement, auth, CAS, AuthDetail, authDetail, deviceName, deviceID, Trust, OS, AppDisplayName, UserAgent, RiskDetail, RiskLevelDuringSignIn, RiskState | sort by TimeGenerated desc ;
//-------------function below-----------------------------
let risk = AADUserRiskEvents
| where UserPrincipalName has_any (User1) | where TimeGenerated > ago (days) | extend parsed1 = parse_json(AdditionalInfo) | mv-expand parsed1 | where isnotempty(parsed1.Key)
| extend userAgent = tostring(parsed1.Value) | extend parsed2 = parse_json(Location) | extend city = tostring(Location.city) | extend state = tostring(Location.state) | extend country = tostring(Location.countryOrRegion)
| where isnotempty(RiskDetail) | project TimeGenerated, UserDisplayName,RiskDetail, city, state, country, userAgent | extend Source = "Risk" | sort by TimeGenerated desc;
let audit = AuditLogs
| where TargetResources has_any (User1) | where TimeGenerated > ago (days)
| where isnotempty(OperationName) | where not(OperationName has_any("synchronization","import")) | where isnotempty(ResultDescription)
| extend InitiatedByUser = parse_json(InitiatedBy) | extend InitiatedBy = InitiatedByUser.user.userPrincipalName
| extend Source = "Aud" //| where ResultDescription has "successfully"
| project TimeGenerated,Source,InitiatedBy,OperationName,ResultDescription, ResultReason;
//-------------function below-----------------------------
union signins,risk,audit | project-reorder Source | sort by Source,TimeGenerated desc
```
