class PolicyRegistryService {

    [string] GetHive([string]$Scope) {
        switch ($Scope) {
            'LocalMachine' { return 'HKLM' }
            'CurrentUser' { return 'HKCU' }
            default { return 'HKLM' }
        }
        return 'HKLM'
    }

    [string] EnsureRegistryPath([string]$Scope) {
        $hive = $this.GetHive($Scope)
        $path = "$hive`:\Software\Policies\Microsoft\Windows\PowerShell"

        if (-not (Test-Path -Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }

        return $path
    }

    [void] SetExecutionPolicy([string]$Scope, [string]$Policy, [bool]$EnableScripts, $CallerPSCmdlet) {
        $path = $this.EnsureRegistryPath($Scope)

        $currentPolicy = $null
        $currentEnableScripts = $null

        try {
            $item = Get-Item -Path $path
            $currentPolicy = $item.GetValue('ExecutionPolicy', $null)
            $currentEnableScripts = $item.GetValue('EnableScripts', $null)
        }
        catch {
            $currentPolicy = $null
            $currentEnableScripts = $null
        }

        if ($currentPolicy -ne $Policy) {
            if ($CallerPSCmdlet -and $CallerPSCmdlet.ShouldProcess("ExecutionPolicy", "Set to $Policy")) {
                New-ItemProperty -Path $path -Name 'ExecutionPolicy' -Value $Policy -PropertyType String -Force | Out-Null
            }
            elseif (-not $CallerPSCmdlet) {
                New-ItemProperty -Path $path -Name 'ExecutionPolicy' -Value $Policy -PropertyType String -Force | Out-Null
            }
        }

        $enableScriptsValue = if ($EnableScripts) { 1 } else { 0 }
        if ($currentEnableScripts -ne $enableScriptsValue) {
            if ($CallerPSCmdlet -and $CallerPSCmdlet.ShouldProcess("EnableScripts", "Set to $enableScriptsValue")) {
                New-ItemProperty -Path $path -Name 'EnableScripts' -Value $enableScriptsValue -PropertyType DWord -Force | Out-Null
            }
            elseif (-not $CallerPSCmdlet) {
                New-ItemProperty -Path $path -Name 'EnableScripts' -Value $enableScriptsValue -PropertyType DWord -Force | Out-Null
            }
        }
    }

    [void] EnableAMSI() {
        $registryPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\AMSI'

        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }

        $propertyName = 'Enabled'
        $currentValue = $null

        try {
            $currentValue = (Get-Item -Path $registryPath).GetValue($propertyName, $null)
        } catch {
            $currentValue = $null
        }

        if ($currentValue -ne 1) {
            New-ItemProperty -Path $registryPath -Name $propertyName -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }

    [void] EnableScriptBlockLogging() {
        $registryPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }

        $propertyName = 'EnableScriptBlockLogging'
        $currentValue = $null

        try {
            $currentValue = (Get-Item -Path $registryPath).GetValue($propertyName, $null)
        } catch {
            $currentValue = $null
        }

        if ($currentValue -ne 1) {
            New-ItemProperty -Path $registryPath -Name $propertyName -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }

    [void] EnableScriptBlockInvocationLogging() {
        $registryPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

        if (-not (Test-Path -Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }

        $propertyName = 'EnableScriptBlockInvocationLogging'
        $currentValue = $null

        try {
            $currentValue = (Get-Item -Path $registryPath).GetValue($propertyName, $null)
        } catch {
            $currentValue = $null
        }

        if ($currentValue -ne 1) {
            New-ItemProperty -Path $registryPath -Name $propertyName -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }

    [void] SetModuleLogging([string[]]$ModuleNames) {
        $basePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

        if (-not (Test-Path -Path $basePath)) {
            New-Item -Path $basePath -Force | Out-Null
        }

        $enableProperty = 'EnableModuleLogging'
        $currentValue = $null
        try {
            $currentValue = (Get-Item -Path $basePath).GetValue($enableProperty, $null)
        } catch {
            $currentValue = $null
        }

        if ($currentValue -ne 1) {
            New-ItemProperty -Path $basePath -Name $enableProperty -PropertyType DWord -Value 1 -Force | Out-Null
        }

        $moduleNamesPath = Join-Path -Path $basePath -ChildPath 'ModuleNames'
        if (-not (Test-Path -Path $moduleNamesPath)) {
            New-Item -Path $moduleNamesPath -Force | Out-Null
        }

        foreach ($moduleName in $ModuleNames) {
            if ([string]::IsNullOrWhiteSpace($moduleName)) {
                continue
            }

            $existingValue = $null
            try {
                $existingValue = (Get-Item -Path $moduleNamesPath).GetValue($moduleName, $null)
            } catch {
                $existingValue = $null
            }

            if ($existingValue -ne $moduleName) {
                New-ItemProperty -Path $moduleNamesPath -Name $moduleName -PropertyType String -Value $moduleName -Force | Out-Null
            }
        }
    }

    [void] SetTranscription([string]$OutputDirectory, [bool]$EnableInvocationHeader) {
        $basePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'

        # Ensure base key exists
        if (-not (Test-Path -Path $basePath)) {
            New-Item -Path $basePath -Force | Out-Null
        }

        # Ensure EnableTranscripting = 1 (DWord)
        New-ItemProperty -Path $basePath -Name 'EnableTranscripting' -Value 1 -PropertyType DWord -Force | Out-Null

        # Ensure EnableInvocationHeader = 1 (DWord) if requested
        if ($EnableInvocationHeader) {
            New-ItemProperty -Path $basePath -Name 'EnableInvocationHeader' -Value 1 -PropertyType DWord -Force | Out-Null
        }

        # Ensure OutputDirectory = $OutputDirectory (String)
        New-ItemProperty -Path $basePath -Name 'OutputDirectory' -Value $OutputDirectory -PropertyType String -Force | Out-Null
    }
}
