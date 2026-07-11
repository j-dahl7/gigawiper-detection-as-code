extension MicrosoftSecurity

resource detectionRule 'Microsoft.Security/detectionRules@2026-06-01-preview' = {
  id: 'nls-gw-002-recovery-boot-tampering'
  displayName: 'NLS-GW-002 - Recovery and Boot Tampering'
  status: 'enabled'
  queryCondition: {
    queryText: '''
DeviceProcessEvents
| where
    (FileName =~ "reagentc.exe" and ProcessCommandLine has "/disable")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_all ("recoveryenabled", "no"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_all ("bootstatuspolicy", "ignoreallfailures"))
    or (FileName in~ ("takeown.exe", "icacls.exe") and ProcessCommandLine has_any ("winload.efi", "bootmgfw.efi", "ntoskrnl.exe", "\\Boot\\BCD"))
| project Timestamp, DeviceId, ReportId, DeviceName, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
'''
  }
  schedule: {
    frequency: 'PT1H'
  }
  detectionAction: {
    alertTemplate: {
      title: 'Possible recovery or boot tampering on {{DeviceName}}'
      description: 'Detects command-line patterns associated with disabling Windows recovery, ignoring boot failures, or changing permissions on critical boot and kernel files. This rule is behavior based and is not proof of GigaWiper by itself.'
      severity: 'high'
      tactics: [
        {
          tactic: 'Impact'
          techniques: [
            {
              technique: 'T1490'
            }
          ]
        }
        {
          tactic: 'DefenseEvasion'
          techniques: [
            {
              technique: 'T1222.001'
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
