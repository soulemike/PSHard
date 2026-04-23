class ProvisioningService {

    [void] CreateGpo([string]$Name, [string]$Comment, [string]$LinkTarget) {
        Import-Module GroupPolicy -ErrorAction Stop

        $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue

        if (-not $existing) {
            New-GPO -Name $Name -Comment $Comment | Out-Null
        }

        if ($LinkTarget) {
            New-GPLink -Name $Name -Target $LinkTarget -ErrorAction SilentlyContinue | Out-Null
        }
    }

    
    [void] CreateJeaEndpoint([string]$Name, [string[]]$VisibleCmdlets, [string]$ConfigurationPath) {
        if (-not (Test-Path $ConfigurationPath)) {
            New-Item -Path $ConfigurationPath -ItemType Directory -Force | Out-Null
        }

        $psscPath = Join-Path $ConfigurationPath "$Name.pssc"

        New-PSSessionConfigurationFile `
            -SessionType RestrictedRemoteServer `
            -Path $psscPath `
            -VisibleCmdlets $VisibleCmdlets `
            -Force

        Register-PSSessionConfiguration -Path $psscPath -Name $Name -Force
    }

    
    [void] CreateTierModel([string]$DomainName, [string[]]$Tiers, [string]$GroupPrefix) {
        Import-Module ActiveDirectory -ErrorAction Stop

        foreach ($tier in $Tiers) {
            $roles = @('Administrator','Operator','Consumer','Asset')

            foreach ($role in $roles) {
                $name = "$GroupPrefix-$tier-$role-PowerShell"
                $description = "$tier PowerShell $role role"

                if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {
                    New-ADGroup -Name $name `
                                -GroupScope DomainLocal `
                                -GroupCategory Security `
                                -Description $description | Out-Null
                }
            }
        }
    }

    
    [void] CreateWdacPolicy([string]$OutputPath, [string]$Mode, [string[]]$AllowedExecutables) {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        $policyPath = Join-Path $OutputPath 'PSHardWDAC.xml'

        $enforcementValue = if ($Mode -eq 'Enforced') { 'Enabled' } else { 'AuditOnly' }

        $fileRules = foreach ($exe in $AllowedExecutables) {
            "        <Allow FileName=\"$exe\" />"
        }

        $policy = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy PolicyType="EXE">
    <Rules>
        <Rule EnforcementMode="$enforcementValue" />
    </Rules>
    <FileRules>
$(($fileRules -join "`n"))
    </FileRules>
</SiPolicy>
"@

        $policy | Out-File -FilePath $policyPath -Encoding UTF8 -Force
    }

}
