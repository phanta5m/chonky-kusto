#
# This script pulls the daily updated list of sus IPs from StamParm's github repo, and runs them through the Device Network Events on the Remote IP column.
# The 'make_set' aggregates the connection actions by IP, wihle the 'where not' in line 15 removes any lines where only a connection attempt or acknowledgement was made.
#
let sus_IPs = externaldata(IP: string) [
    @"https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt"
] with (format="txt")
| project IP
| project IP = tostring(split(IP, "\t")[0])
| where not(* has "#");
//sus_IPs
DeviceNetworkEvents
| where Timestamp > ago (7d)
| where RemoteIP in (sus_IPs)
| where not(ActionType has_any ("ConnectionAttempt","ConnectionAcknowledged"))
| summarize ActionType = make_set(ActionType) by RemoteIP
