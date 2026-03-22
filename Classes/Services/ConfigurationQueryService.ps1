class ConfigurationQueryService {

    [PSCustomObject] GetConfigurationStatus() {
        $results = @{}

        # Execution Policy
        $policy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        $results.ExecutionPolicy = $policy

        # Module Logging
        $modulePath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        $results.ModuleLoggingEnabled = if (Test-Path $modulePath) {
            (Get-Item $modulePath).GetValue('EnableModuleLogging') -eq 1
        } else { $false }

        # Script Block Logging
        $scriptPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        $results.ScriptBlockLoggingEnabled = if (Test-Path $scriptPath) {
            (Get-Item $scriptPath).GetValue('EnableScriptBlockLogging') -eq 1
        } else { $false }

        # AMSI
        $amsiPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\AMSI'
        $results.AMSIEnabled = if (Test-Path $amsiPath) {
            (Get-Item $amsiPath).GetValue('Enabled') -eq 1
        } else { $false }

        return [PSCustomObject]$results
    }

}
