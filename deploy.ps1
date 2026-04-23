# PSHard Module Deployment Script
$ErrorActionPreference = 'Stop'

$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\PSHard"

# Ensure directory structure exists
$directories = @(
    $modulePath,
    "$modulePath\Public",
    "$modulePath\Classes\Models",
    "$modulePath\Classes\Services",
    "$modulePath\Tests"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created: $dir"
    }
}

# File content mapping - base64 encoded to preserve special characters
$files = @{
    "$modulePath\PSHard.psd1" = @"
@{
    RootModule        = 'PSHard.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '11111111-1111-1111-1111-111111111111'
    Author            = 'PSHard'
    CompanyName       = 'PSHard'
    Copyright         = '(c) PSHard. All rights reserved.'
    Description       = 'Enterprise-balanced PowerShell hardening framework supporting Windows PowerShell 5.1 and PowerShell 7+'
    PowerShellVersion = '5.1'
    FunctionsToExport = @()
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
"@
}

foreach ($file in $files.GetEnumerator()) {
    Set-Content -Path $file.Key -Value $file.Value -Force
    Write-Host "Created: $($file.Key)"
}

Write-Host "Deployment complete!"
