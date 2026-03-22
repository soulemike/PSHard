function New-PSHardGpo {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Comment = 'PowerShell security hardening policy',

        [string]$LinkTarget
    )

    $service = [ProvisioningService]::new()

    if ($PSCmdlet.ShouldProcess($Name, 'Create or link GPO')) {
        $service.CreateGpo($Name, $Comment, $LinkTarget)
    }
}
