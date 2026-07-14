extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-native-retest-20260713-37a294dfb360489d'
  displayName: 'NLS-GW Native Repository Retest - Disabled Canary'
  status: 'disabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName == "__nls_gw_native_retest_20260713_37a294dfb360489d__.exe"
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'NLS native Repository retest canary on {{DeviceName}}'
      description: 'Disabled impossible-match canary for an isolated native Repository-path retest. No response actions.'
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

