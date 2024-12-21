# Audit logs
# union of 2 tables: AADUserRiskEvents & AuditLogs
#
let User1 = dynamic(["username_here"]);
let days = 30d;
let risk = AADUserRiskEvents
| where UserPrincipalName has_any (User1)
| where TimeGenerated > ago (days)
| extend parsed1 = parse_json(AdditionalInfo)
| mv-expand parsed1
| where parsed1.Key has_any ("","userAgent")
| extend userAgent = tostring(parsed1.Value)
| extend parsed2 = parse_json(Location)
| extend city = tostring(Location.city)
| extend state = tostring (Location.state)
| extend country = tostring(Location.countryOrRegion)
| where RiskDetail != "none" // has "adminConfirmedUserCompromised"
| project TimeGenerated, RiskRetail, city, state, country, userAgent
| sort by TimeGenerated desc;
let audit = AuditLogs
| where TargetResounces has_any (User1)
| where TimeGenerated > ago (days)
| where OperationName has_any ("")
| extend InitiatedByUser = parse_json(InitiatedRy)
| extend InitiatedBy = InitiatedByUser.user.userPrincipalName
| project TimeGenerated.OperationName.ResultRescription,ResultReason,InitiatedBy;
union withsource=Table risk,audit | sort by TimeGenerated desc