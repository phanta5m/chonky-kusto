## This query scrapes a list of vulnerable drivers from LOLDrivers, and then runs it against your DeviceEvents table.

<ul>
<li>A lot needs to go wrong in order for an attacker to leverage a sus driver</li>
<li>This query can identify the devices in your environment that are susceptible</li>
<li>The query was pulled from the LOLDrivers site, but slightly tweaked for functionality (ie the original syntax doesn't work, but this one does)</li>
<li><a href="https://www.loldrivers.io/">loldrivers</a> — A great site for your sus driver investigations</li>

</ul>

```kusto
let LOLDrivers = externaldata (Category:string, KnownVulnerableSamples:dynamic, Verified:string ) [h@"https://www.loldrivers.io/api/drivers.json"]
     with (
       format='multijson'
       ,ingestionMapping=@'[{"Column":"Category","Properties":{"Path":"$.Category"}},{"Column":"KnownVulnerableSamples","Properties":{"Path":"$.KnownVulnerableSamples"}},{"Column":"Verified","Properties":{"Path":"$.Verified"}}]')
| mv-expand KnownVulnerableSamples
| extend SHA1 = tostring(KnownVulnerableSamples.SHA1), SHA256 = tostring(KnownVulnerableSamples.SHA256)
;
// you can filter the drivers further based on category or verified status
DeviceEvents
| where ActionType == "DriverLoad"
| join kind=inner (LOLDrivers | where isnotempty(SHA256)) on SHA256
| union (
  DeviceEvents
  | where ActionType == "DriverLoad"
  | join kind=inner (LOLDrivers | where isnotempty(SHA1)) on SHA1
)
| summarize arg_min(TimeGenerated,*) by DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, ProcessCreationTime, AdditionalFields, Type, Category, tostring(KnownVulnerableSamples), Verified
| distinct TimeGenerated, ProcessCreationTime,DeviceName, Type,ActionType, FileName, Category,FolderPath, SHA1, SHA256, AdditionalFields, KnownVulnerableSamples, Verified
```
