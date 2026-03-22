function Set-PSHardAMSI {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $service = [PolicyRegistryService]::new()

    if ($PSCmdlet.ShouldProcess('AMSI registry configuration', 'Enable AMSI')) {
        $service.EnableAMSI()
    }
}
