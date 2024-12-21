```kusto
IdentityLogonEvents
| where Timestamp > ago (7d)
| where IPAdress startswith "23.127." // or IPAdress startswith "185.211"
//| where OSPlatform has_any ("OS X", "iOS")
| extend Addlparsed = parse_json(AdditionalFields)
| extend Addl = tostring(Addlparsed["ARG.CLOUD_SERVICE"])
| project-away AccountDomain, AccountObjectId, AccountUpn, AdditionalFields
| project-reorder AccountDisplayName
  ,AccountName
  ,Addl
  ,IPAddress
  ,ISP
//| distinct ADNcommas = strcat(tostring(AccoundDisplayName), ",")
```
