## Non-interactive sign-ins

### Set for 14 days b/c of the sheer volume of results it can return

```kusto
let User 1 = dynamic(["username_here"]);
let days = 30d;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago (days)
| where UserPrincipalName has_any (User1)
| extend Device1 = tostring(parse_json(DeviceDetail).deviceId)
| extend Device2 = tostring(parse_json(DeviceDetail).operatingSystem)
| extend trust = tostring(parse_json(DeviceDetail).trustType)
| extend loc1 = tostring(parse_json(LocationDetails).city)
| extend loc2 = tostring(parse_json(LocationDetails).state)
| extend region = strcat(loc1, ", ", loc2, ", ", Location) // New column 'region'
| project Time Generated, Identity, region, IPAdress, Device1, Device2, trust, AppDisplayName
| sort by TimeGenerated desc
//| distinct Identity, region, IPAdress, Device1, Device2, trust, AppDisplayName
//| where isnotempty(Device1)
#
# uncomment out the last 2 lines to get a condensed view 
```