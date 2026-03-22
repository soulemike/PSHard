function Set-PSHardRemoting {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch]$EnableWinRM,
        [switch]$DisableBasicAuth,
        [switch]$DisableUnencrypted
    )

    $service = [SystemHardeningService]::new()

    if ($PSCmdlet.ShouldProcess('Remoting Configuration', 'Configure WinRM and WSMan security settings')) {
        $service.ConfigureRemoting(
            [bool]$EnableWinRM,
            [bool]$DisableBasicAuth,
            [bool]$DisableUnencrypted
        )
    }
}
