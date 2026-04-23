# PSHard Module Remediation Actions

## Issues Fixed During Testing

### 1. Syntax Errors in Service Classes

#### ProvisioningService.ps1
**Problem**: Unix-style line continuations (`\`) instead of PowerShell backticks (`` ` ``)

**Fixed Code**:
```powershell
# Before (Broken):
New-PSSessionConfigurationFile \
    -SessionType RestrictedRemoteServer \
    -Path $psscPath \
    -VisibleCmdlets $VisibleCmdlets \
    -Force

# After (Fixed):
New-PSSessionConfigurationFile `
    -SessionType RestrictedRemoteServer `
    -Path $psscPath `
    -VisibleCmdlets $VisibleCmdlets `
    -Force
```

**Also Fixed**: XML here-string escaping in CreateWdacPolicy method
```powershell
# Before:
$policy = @"
<?xml version=\"1.0\" encoding=\"utf-8\"?>

# After:
$policy = @"
<?xml version="1.0" encoding="utf-8"?>
```

#### SystemHardeningService.ps1
**Problem**: Same line continuation issue in ConfigureFirewall method

**Fixed Code**:
```powershell
# Before (Broken):
New-NetFirewallRule \
    -DisplayName $name \
    -Direction Inbound \
    -Protocol TCP \
    -LocalPort $port \
    -Action Block \
    -Group $RuleGroup | Out-Null

# After (Fixed):
New-NetFirewallRule `
    -DisplayName $name `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $port `
    -Action Block `
    -Group $RuleGroup | Out-Null
```

### 2. Module Manifest Function Exports

**Problem**: `FunctionsToExport = @()` prevented any functions from being exported

**Fixed in PSHard.psd1**:
```powershell
# Before:
FunctionsToExport = @()

# After:
FunctionsToExport = @(
    'Set-PSHardExecutionPolicy',
    'Set-PSHardRemoting',
    'Set-PSHardAuditPolicy',
    'Set-PSHardModuleLogging',
    'Set-PSHardScriptBlockLogging',
    'Set-PSHardTranscription',
    'Set-PSHardAMSI',
    'Set-PSHardFirewall',
    'Set-PSHardLegacyRemoval',
    'Test-PSHardConfiguration',
    'New-PSHardJEAEndpoint',
    'New-PSHardWDACPolicy',
    'New-PSHardTierModel',
    'New-PSHardGpo'
)
```

---

## Recommended Future Fixes

### 1. Add Timeout Handling

For functions that may hang (Set-PSHardFirewall, New-PSHardJEAEndpoint):

```powershell
function Set-PSHardFirewall {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [int[]]$BlockInboundPorts = @(5985,5986),
        [string]$RuleGroup = 'PSHard Remoting',
        [int]$TimeoutSeconds = 30
    )

    $job = Start-Job {
        param($Ports, $Group)
        $service = [SystemHardeningService]::new()
        $service.ConfigureFirewall($Ports, $Group)
    } -ArgumentList $BlockInboundPorts, $RuleGroup

    $completed = $job | Wait-Job -Timeout $TimeoutSeconds
    if (-not $completed) {
        Stop-Job $job
        Remove-Job $job
        throw "Operation timed out after $TimeoutSeconds seconds"
    }
    
    Receive-Job $job
    Remove-Job $job
}
```

### 2. Add Verbose Logging

Add detailed logging to service classes:

```powershell
class PolicyRegistryService {
    hidden [Logger]$Logger

    PolicyRegistryService() {
        $this.Logger = [Logger]::new('PolicyRegistryService')
    }

    [void] EnableAMSI() {
        $this.Logger.Info('Starting AMSI configuration')
        # ... existing code ...
        $this.Logger.Info('AMSI configuration completed')
    }
}
```

### 3. Fix PowerShell 5.1 Class Export

For PowerShell 5.1 compatibility, export classes using a different pattern:

```powershell
# In PSHard.psm1, after loading classes:
$TypeAccelerators = [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")
@(
    'PolicyRegistryService',
    'SystemHardeningService', 
    'ProvisioningService',
    'ConfigurationQueryService',
    'Logger',
    'PolicyResult'
) | ForEach-Object {
    $TypeAccelerators::Add($_, ($_ -as [Type]))
}
```

### 4. Add Force Parameter to JEA Endpoint

```powershell
function New-PSHardJEAEndpoint {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string[]]$VisibleCmdlets,
        [string]$ConfigurationPath = "$env:ProgramData\PowerShell\Configuration",
        [switch]$Force
    )

    $service = [ProvisioningService]::new()

    if ($Force -or $PSCmdlet.ShouldProcess($Name, 'Create and register JEA endpoint')) {
        $service.CreateJeaEndpoint($Name, $VisibleCmdlets, $ConfigurationPath, $Force)
    }
}
```

Then update the service method:
```powershell
[void] CreateJeaEndpoint([string]$Name, [string[]]$VisibleCmdlets, [string]$ConfigurationPath, [bool]$Force) {
    # ... existing code ...
    
    $regParams = @{
        Path = $psscPath
        Name = $Name
        Force = $Force
    }
    Register-PSSessionConfiguration @regParams
}
```

---

## Testing Checklist for Future Releases

- [ ] Test on Windows PowerShell 5.1
- [ ] Test on PowerShell 7.x
- [ ] Test on Windows Server 2016/2019/2022/2025
- [ ] Test on Windows 10/11
- [ ] Verify all 14 functions export correctly
- [ ] Verify registry modifications work
- [ ] Verify firewall rules creation
- [ ] Verify JEA endpoint creation (with timeout handling)
- [ ] Verify WDAC policy creation
- [ ] Test WhatIf parameter on all ShouldProcess functions
- [ ] Test class instantiation in PowerShell 7
- [ ] Run Pester tests if available

---

## Deployment Verification Commands

After deploying PSHard, run these commands to verify installation:

```powershell
# 1. Module Import
Import-Module PSHard -Force
Get-Module PSHard

# 2. Function Export Verification
Get-Command -Module PSHard | Measure-Object

# 3. Configuration Test
Test-PSHardConfiguration

# 4. Registry Verification
Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell -ErrorAction SilentlyContinue

# 5. Firewall Rules Verification
Get-NetFirewallRule -DisplayName "PSHard*"
```

---

## Rollback Procedures

If issues occur, use these commands to rollback:

```powershell
# Remove firewall rules
Get-NetFirewallRule -DisplayName "PSHard*" | Remove-NetFirewallRule

# Remove registry keys (use with caution)
Remove-Item -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Recurse -Force

# Unregister JEA endpoints
Unregister-PSSessionConfiguration -Name "PSHard*" -Force -ErrorAction SilentlyContinue

# Remove module
Remove-Module PSHard -Force
Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\PSHard" -Recurse -Force
```
