function Test-PSHardConfiguration {
    [CmdletBinding()]
    param()

    $service = [ConfigurationQueryService]::new()
    return $service.GetConfigurationStatus()
}
