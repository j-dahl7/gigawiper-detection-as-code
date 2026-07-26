extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-005-candy-rename-burst'
  displayName: 'NLS-GW-005 - Candy Extension Rename Burst'
  description: 'nlzt-owner:gigawiper-detection-as-code:v1'
  status: 'enabled'
  queryCondition: {
    queryText: '''
let CandyEvents = DeviceFileEvents
| where ActionType == "FileRenamed"
| where FileName endswith ".candy"
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
let LookupWindow = 5m;
let LookupBin = LookupWindow / 2.0;
CandyEvents
| project DeviceId, WindowStart=Timestamp, TimeKey=bin(Timestamp, LookupBin)
| join kind=inner (
    CandyEvents
    | project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256,
        TimeKey=range(bin(Timestamp - LookupWindow, LookupBin), bin(Timestamp, LookupBin), LookupBin)
    | mv-expand TimeKey to typeof(datetime)
  ) on DeviceId, TimeKey
| where Timestamp between (WindowStart .. WindowStart + LookupWindow)
| summarize CandyFileCount=count(), SampleFiles=make_set(FileName, 20), SampleFolders=make_set(FolderPath, 10), arg_max(Timestamp, ReportId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256) by DeviceId, WindowStart
| where CandyFileCount >= 5
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceId, ReportId, DeviceName, CandyFileCount, SampleFiles, SampleFolders, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Burst of .candy file renames on {{DeviceName}}'
      description: 'Detects a burst of file renames to the .candy extension. This is an impact-stage signal, not proof that encryption succeeded and not a pre-impact control. Immediately investigate the initiating process and isolate the device when malicious activity is confirmed.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Impact'
          techniques: [
            {
              technique: 'T1486'
            }
          ]
        }
      ]
      entityMappings: {
        hosts: [
          {
            id: 'device'
            deviceIdColumn: 'DeviceId'
          }
        ]
      }
    }
  }
}
