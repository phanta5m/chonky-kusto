## Non-interactive sign-ins

<p>
A noisier set of results; 14 days due to the sheer volume of results that are possible.<br>
Presenting the data in this way allows one to see which IPs are correlated with an Azure<br>
managed device, which are less likely to pose a threat.                                                                                    
</p>

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
