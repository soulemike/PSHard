function Set-PSHardLegacyRemoval {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string[]]$FeatureNames = @('MicrosoftWindowsPowerShellV2')
    )

    $service = [SystemHardeningService]::new()

    if ($PSCmdlet.ShouldProcess('Legacy Feature Removal', 'Disable selected Windows optional features')) {
        $service.RemoveLegacyFeatures($FeatureNames)
    }
}
