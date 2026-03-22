function Set-PSHardScriptBlockLogging {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$EnableInvocationLogging
    )

    $service = [PolicyRegistryService]::new()

    if ($PSCmdlet.ShouldProcess('ScriptBlockLogging', 'Enable script block logging')) {
        $service.EnableScriptBlockLogging()
    }

    if ($EnableInvocationLogging) {
        if ($PSCmdlet.ShouldProcess('ScriptBlockLogging', 'Enable script block invocation logging')) {
            $service.EnableScriptBlockInvocationLogging()
        }
    }
}
