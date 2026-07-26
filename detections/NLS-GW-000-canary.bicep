extension MicrosoftSecurity

// Disabled deployment canary. This proves the resource provider path without
// creating a rule that can match ordinary tenant activity.
resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-000-canary'
  displayName: 'NLS-GW-000 - Detection as Code Canary'
  description: 'nlzt-owner:gigawiper-detection-as-code:v1'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ "nls-gigawiper-canary.exe"
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'NLS canary process observed on {{DeviceName}}'
      description: 'Disabled deployment canary for the Nine Lives detection-as-code lab. It has no automated response action.'
      severity: 'low'
      tactics: [
        {
          tactic: 'Execution'
          techniques: [
            {
              technique: 'T1059'
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
