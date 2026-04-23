@{
    RootModule        = 'PSHard.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '11111111-1111-1111-1111-111111111111'
    Author            = 'PSHard'
    CompanyName       = 'PSHard'
    Copyright         = '(c) PSHard. All rights reserved.'
    Description       = 'Enterprise-balanced PowerShell hardening framework supporting Windows PowerShell 5.1 and PowerShell 7+'
    PowerShellVersion = '5.1'
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
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
