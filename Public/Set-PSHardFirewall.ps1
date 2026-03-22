function Set-PSHardFirewall {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [int[]]$BlockInboundPorts = @(5985,5986),
        [string]$RuleGroup = 'PSHard Remoting'
    )

    $service = [SystemHardeningService]::new()

    if ($PSCmdlet.ShouldProcess($RuleGroup, "Configure inbound firewall block rules")) {
        $service.ConfigureFirewall($BlockInboundPorts, $RuleGroup)
    }
}
