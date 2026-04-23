class SystemHardeningService {

    [void] ConfigureFirewall([int[]]$Ports, [string]$RuleGroup) {
        foreach ($port in $Ports) {
            $name = "PSHard-Block-Inbound-$port"

            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule `
                    -DisplayName $name `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort $port `
                    -Action Block `
                    -Group $RuleGroup | Out-Null
            }
        }
    }

    [void] ConfigureRemoting([bool]$EnableWinRM, [bool]$DisableBasicAuth, [bool]$DisableUnencrypted) {
        if ($EnableWinRM) {
            Enable-PSRemoting -Force
        }

        if ($DisableBasicAuth) {
            $servicePath = 'WSMan:\localhost\Service\Auth'
            Set-Item -Path $servicePath -Name Basic -Value $false -Force
        }

        if ($DisableUnencrypted) {
            Set-Item -Path 'WSMan:\localhost\Service' -Name AllowUnencrypted -Value $false -Force
        }
    }

    [void] ConfigureAuditPolicy([string[]]$Subcategories) {
        foreach ($subcategory in $Subcategories) {
            & auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
        }
    }

    [void] RemoveLegacyFeatures([string[]]$FeatureNames) {
        foreach ($feature in $FeatureNames) {
            try {
                $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction Stop

                if ($state.State -ne 'Disabled') {
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                }
            }
            catch {
                Write-Verbose "Feature '$feature' not found or not applicable on this system."
            }
        }
    }

}
