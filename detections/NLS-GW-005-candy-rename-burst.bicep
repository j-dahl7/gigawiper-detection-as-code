extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-005-candy-rename-burst'
  displayName: 'NLS-GW-005 - Candy Extension Rename Burst'
  status: 'enabled'
  queryCondition: {
    queryText: '''
DeviceFileEvents
| where ActionType == "FileRenamed"
| where FileName endswith ".candy"
| extend DetectionWindow=bin(Timestamp, 5m)
| summarize CandyFileCount=count(), SampleFiles=make_set(FileName, 20), SampleFolders=make_set(FolderPath, 10), arg_max(Timestamp, ReportId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256) by DeviceId, DetectionWindow
| where CandyFileCount >= 5
| project Timestamp, DeviceId, ReportId, DeviceName, CandyFileCount, SampleFiles, SampleFolders, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Burst of .candy file renames on {{DeviceName}}'
      description: 'Detects a burst of file renames to the .candy extension. This is an impact-stage confirmation signal, not a pre-impact control. Immediately investigate the initiating process and isolate the device when malicious activity is confirmed.'
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
