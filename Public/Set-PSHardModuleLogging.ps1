function Set-PSHardModuleLogging {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [string[]]$ModuleNames = '*'
    )

    if ($PSCmdlet.ShouldProcess('ModuleLogging', 'Set module logging')) {
        $service = [PolicyRegistryService]::new()
        $service.SetModuleLogging($ModuleNames)
    }
}
