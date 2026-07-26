extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-003-event-log-destruction'
  displayName: 'NLS-GW-003 - Windows Event Log Destruction'
  description: 'nlzt-owner:gigawiper-detection-as-code:v1'
  status: 'enabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (" cl ", " clear-log ")
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessIntegrityLevel, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Windows event log clearing observed on {{DeviceName}}'
      description: 'Detects wevtutil clear operations. Confirm the targeted log, administrator intent, and whether several logs or Security.evtx were affected. Tune approved maintenance tooling explicitly.'
      severity: 'high'
      tactics: [
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1070.001'
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
