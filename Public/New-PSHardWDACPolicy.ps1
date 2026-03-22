function New-PSHardWDACPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('Audit','Enforced')]
        [string]$Mode = 'Audit',

        [string[]]$AllowedExecutables = @('pwsh.exe','powershell.exe')
    )

    $service = [ProvisioningService]::new()

    if ($PSCmdlet.ShouldProcess($OutputPath, 'Create WDAC policy XML')) {
        $service.CreateWdacPolicy($OutputPath, $Mode, $AllowedExecutables)
    }
}
