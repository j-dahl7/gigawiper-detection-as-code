extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-004-minio-transfer-staging'
  displayName: 'NLS-GW-004 - Unusual MinIO Client Transfer Staging'
  description: 'nlzt-owner:gigawiper-detection-as-code:v1'
  status: 'enabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where FileName =~ "mc.exe"
| where ProcessCommandLine has_any (" mirror ", " cp ", " pipe ", " alias set ")
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessVersionInfoCompanyName, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Unusual MinIO client transfer activity on {{DeviceName}}'
      description: 'Detects execution of mc.exe with MinIO transfer-oriented arguments. The MinIO client is legitimate software, so validate installation path, signer, destination, account, and business purpose before escalation.'
      severity: 'medium'
      tactics: [
        {
          tactic: 'Exfiltration'
          techniques: [
            {
              technique: 'T1567.002'
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
