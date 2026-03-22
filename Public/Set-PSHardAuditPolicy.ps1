function Set-PSHardAuditPolicy {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [ValidateSet('File System','Process Creation','Process Termination','Registry')]
        [string[]]$Subcategories = @('File System','Process Creation','Process Termination','Registry')
    )

    $service = [SystemHardeningService]::new()

    if ($PSCmdlet.ShouldProcess('Audit Policy Configuration', 'Enable Success and Failure auditing for selected subcategories')) {
        $service.ConfigureAuditPolicy($Subcategories)
    }
}
