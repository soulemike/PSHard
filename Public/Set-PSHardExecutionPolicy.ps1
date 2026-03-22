function Set-PSHardExecutionPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidateSet('LocalMachine','CurrentUser')]
        [string]$Scope = 'LocalMachine',

        [ValidateSet('AllSigned','RemoteSigned','Unrestricted')]
        [string]$Policy = 'AllSigned',

        [bool]$EnableScripts = $true
    )

    $service = [PolicyRegistryService]::new()

    $service.EnsureRegistryPath($Scope, $PSCmdlet)
    $service.SetExecutionPolicy($Scope, $Policy, $EnableScripts, $PSCmdlet)
}
