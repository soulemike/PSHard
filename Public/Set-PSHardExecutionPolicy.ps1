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

    if ($PSCmdlet.ShouldProcess("Execution Policy ($Scope)", "Set to $Policy with EnableScripts=$EnableScripts")) {
        $service.SetExecutionPolicy($Scope, $Policy, $EnableScripts, $PSCmdlet)
    }
}
