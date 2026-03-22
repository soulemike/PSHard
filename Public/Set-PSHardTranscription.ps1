function Set-PSHardTranscription {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [string]$OutputDirectory = "$env:SystemRoot\System32\LogFiles\PowerShell",
        [switch]$EnableInvocationHeader
    )

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    $service = [PolicyRegistryService]::new()

    if ($PSCmdlet.ShouldProcess('PowerShell Transcription Policy', 'Set transcription settings')) {
        $service.SetTranscription($OutputDirectory, $EnableInvocationHeader)
    }
}
