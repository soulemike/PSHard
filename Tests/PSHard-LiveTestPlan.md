# PSHard Live System Test Plan
## Target: Windows Server at 20.125.96.137

### Overview
This test plan validates the PSHard PowerShell hardening module functionality on a live Windows Server instance. Tests are organized by functional area and risk level.

### Test Environment
- **Target System**: Windows Server (20.125.96.137)
- **Module Version**: 0.1.0
- **PowerShell Versions**: Windows PowerShell 5.1 and PowerShell 7+

---

## Phase 1: Module Load & Basic Functionality
**Objective**: Verify module loads correctly and all components are accessible

| Test ID | Test Name | Expected Result | Risk Level |
|---------|-----------|-----------------|------------|
| 1.1 | Module Import | Import-Module succeeds without errors | Low |
| 1.2 | Public Functions Exported | All 14 public functions available | Low |
| 1.3 | Service Classes Available | All 5 service classes instantiable | Low |
| 1.4 | Model Classes Available | PolicyResult class accessible | Low |

---

## Phase 2: Registry-Based Policy Tests
**Objective**: Validate registry manipulation for PowerShell security policies

| Test ID | Test Name | Function | Expected Result | Risk Level |
|---------|-----------|----------|-----------------|------------|
| 2.1 | Execution Policy - LocalMachine | Set-PSHardExecutionPolicy | Sets HKLM execution policy | Medium |
| 2.2 | Execution Policy - CurrentUser | Set-PSHardExecutionPolicy | Sets HKCU execution policy | Low |
| 2.3 | AMSI Enable | Set-PSHardAMSI | Creates/enables AMSI registry key | Medium |
| 2.4 | Script Block Logging | Set-PSHardScriptBlockLogging | Enables script block logging | Medium |
| 2.5 | Script Block Invocation | Set-PSHardScriptBlockLogging -EnableInvocationLogging | Enables invocation logging | Medium |
| 2.6 | Module Logging | Set-PSHardModuleLogging | Enables module logging with wildcard | Medium |
| 2.7 | Transcription | Set-PSHardTranscription | Configures transcription settings | Medium |

**Validation**: Registry keys created at:
- `HKLM:\Software\Policies\Microsoft\Windows\PowerShell`
- `HKLM:\Software\Microsoft\Windows\CurrentVersion\AMSI`

---

## Phase 3: System Hardening Tests
**Objective**: Validate system-level security configurations

| Test ID | Test Name | Function | Expected Result | Risk Level |
|---------|-----------|----------|-----------------|------------|
| 3.1 | Firewall Rules | Set-PSHardFirewall | Creates inbound block rules | Medium |
| 3.2 | WinRM Configuration | Set-PSHardRemoting | Configures WinRM settings | High |
| 3.3 | Basic Auth Disable | Set-PSHardRemoting -DisableBasicAuth | Disables basic auth | Medium |
| 3.4 | Unencrypted Disable | Set-PSHardRemoting -DisableUnencrypted | Disables unencrypted traffic | Medium |
| 3.5 | Audit Policy | Set-PSHardAuditPolicy | Enables audit subcategories | Medium |
| 3.6 | Legacy Removal | Set-PSHardLegacyRemoval | Disables legacy features | Medium |

**Validation**:
- `Get-NetFirewallRule` shows PSHard rules
- `WSMan:\localhost\Service` settings updated
- `auditpol /get` shows enabled subcategories

---

## Phase 4: Configuration Query Tests
**Objective**: Validate configuration status reporting

| Test ID | Test Name | Function | Expected Result | Risk Level |
|---------|-----------|----------|-----------------|------------|
| 4.1 | Configuration Status | Test-PSHardConfiguration | Returns configuration object | Low |
| 4.2 | Execution Policy Query | Test-PSHardConfiguration | Reports current execution policy | Low |
| 4.3 | Module Logging Query | Test-PSHardConfiguration | Reports module logging status | Low |
| 4.4 | Script Block Query | Test-PSHardConfiguration | Reports script block status | Low |
| 4.5 | AMSI Query | Test-PSHardConfiguration | Reports AMSI status | Low |

---

## Phase 5: Provisioning Service Tests
**Objective**: Validate advanced provisioning capabilities

| Test ID | Test Name | Function | Expected Result | Risk Level |
|---------|-----------|----------|-----------------|------------|
| 5.1 | JEA Endpoint | New-PSHardJEAEndpoint | Creates session configuration | High |
| 5.2 | WDAC Policy | New-PSHardWDACPolicy | Creates policy XML file | Medium |

**Note**: GPO and Tier Model tests require Active Directory - may be skipped if not domain-joined.

---

## Test Execution Commands

### Pre-Test
```powershell
# Get baseline
Get-ExecutionPolicy -List
Get-Item WSMan:\localhost\Service\AllowUnencrypted
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "PSHard*"}
```

### Test Execution
```powershell
# Phase 1
Import-Module PSHard -Force
Get-Command -Module PSHard

# Phase 2 (WhatIf first)
Set-PSHardExecutionPolicy -Policy AllSigned -WhatIf
Set-PSHardAMSI -WhatIf
Set-PSHardScriptBlockLogging -WhatIf
Set-PSHardModuleLogging -WhatIf
Set-PSHardTranscription -WhatIf

# Phase 3 (WhatIf first)
Set-PSHardFirewall -WhatIf
Set-PSHardRemoting -WhatIf
Set-PSHardAuditPolicy -WhatIf

# Phase 4
Test-PSHardConfiguration
```

### Post-Test Validation
```powershell
# Registry validation
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell -ErrorAction SilentlyContinue
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\AMSI -ErrorAction SilentlyContinue

# System validation
Get-NetFirewallRule -DisplayName "PSHard*"
Get-PSSessionConfiguration | Where-Object {$_.Name -like "PSHard*"}
```

---

## Success Criteria

1. **Module Load**: All components load without errors
2. **Registry Tests**: All registry keys created with correct values
3. **System Tests**: Firewall rules created, WinRM configured
4. **Query Tests**: Configuration status accurately reported
5. **Provisioning**: JEA endpoint and WDAC policy created

## Rollback Plan

If issues occur:
1. Remove firewall rules: `Remove-NetFirewallRule -DisplayName "PSHard*"`
2. Remove registry keys under `HKLM:\Software\Policies\Microsoft\Windows\PowerShell`
3. Unregister JEA: `Unregister-PSSessionConfiguration -Name <Name> -Force`
