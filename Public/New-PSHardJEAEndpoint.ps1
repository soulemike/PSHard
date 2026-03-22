function New-PSHardJEAEndpoint {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$VisibleCmdlets,

        [string]$ConfigurationPath = "$env:ProgramData\PowerShell\Configuration"
    )

    $service = [ProvisioningService]::new()

    if ($PSCmdlet.ShouldProcess($Name, 'Create and register JEA endpoint')) {
        $service.CreateJeaEndpoint($Name, $VisibleCmdlets, $ConfigurationPath)
    }
}
