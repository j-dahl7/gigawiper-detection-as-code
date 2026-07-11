extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-001-onedrive-persistence'
  displayName: 'NLS-GW-001 - OneDrive-Lookalike Task and Registry Persistence'
  status: 'enabled'
  queryCondition: {
    queryText: '''
let RegistrySignals = DeviceRegistryEvents
| where RegistryKey endswith @"\SOFTWARE\OneDrive\Environment"
| project DeviceId, RegistryTimestamp=Timestamp, RegistryReportId=ReportId, RegistryKey, RegistryValueName, RegistryValueData, RegistryInitiatingProcess=InitiatingProcessFileName;
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "OneDrive Update"
| where ProcessCommandLine has_any (" /create ", " -create ", "/create")
| join kind=innerunique RegistrySignals on DeviceId
| where abs(datetime_diff('minute', RegistryTimestamp, Timestamp)) <= 15
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, RegistryTimestamp, RegistryKey, RegistryValueName, RegistryValueData, RegistryInitiatingProcess
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'OneDrive-lookalike persistence chain on {{DeviceName}}'
      description: 'Correlates creation of a scheduled task named OneDrive Update with activity under HKCU\\SOFTWARE\\OneDrive\\Environment. Review the task action, executable path, signer, parent process, and nearby network activity before containment.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Persistence'
          techniques: [
            {
              technique: 'T1053.005'
            }
          ]
        }
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1112'
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
