## Interactive sign-ins ; querying from ADX b/c nothing is slower than Entra

###    1) The results here will show the location, auth details, device details, and risk events
###    2) It will also render a pie chart allowing one to quickly see a pattern of sign-in locations (and any anomalies)

```kusto
let User 1 = dynamic(["username_here"]);
let days = 30d; //<---Set the lookback period here (╭ರ_•́)
SigninLogs
| where TimeGenerated > ago (days)
| where AlternateSignInName has_any (User1)
| extend auth = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| extend mfa = tostring(parse_json(AuthenticationDetails)[1].succeeded)
| extend auth_mthd = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend ParsedJson1 = parse_json(MfaDetail)
| extend authDetail = tostring(ParsedJson1.authDetail)
| extend AuthDetail = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| extend deviceName = tostring(parse_json(DeviceDetail).displayName)
| extend deviceID = tostring(parse_json(DeviceDetail.deviceId))
| extend Trust = tostring(parse_json(
| extend OS = tostring(parse_json(
| extend city = tostring(parse_json(
| extend state = tostring(parse_json(
| extend region = tostring(parse_json(
| project-rename CAS = ConditionalAccessStatus
| sort by TimeGenerated desc
| project TimeGenerated, region, IPAddress
    ,AuthenticationRequirement, auth, CAS, AuthDetail
    ,deviceName, deviceID, Trust, OS, AppDisplayName, RiskDetail
| summarize LocationCount=count() by tostring(region), IPAddress 
| sort by LocationCount | render piechart with(title="Historical Location Data (30 Days)")
```


