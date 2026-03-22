function New-PSHardTierModel {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,

        [string[]]$Tiers = @('T0','T1','T2'),

        [string]$GroupPrefix = 'SG'
    )

    $service = [ProvisioningService]::new()

    if ($PSCmdlet.ShouldProcess('Tier Model Provisioning', 'Create AD security groups for tier model')) {
        $service.CreateTierModel($DomainName, $Tiers, $GroupPrefix)
    }
}
