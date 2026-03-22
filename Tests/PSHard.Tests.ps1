Import-Module "$PSScriptRoot/../PSHard.psm1" -Force

Describe 'PSHard Module Load' {

    It 'Loads without errors' {
        (Get-Module PSHard) | Should -Not -BeNullOrEmpty
    }

    It 'Exports public functions' {
        $commands = Get-Command -Module PSHard
        $commands.Count | Should -BeGreaterThan 0
    }

    It 'Has PolicyRegistryService class' {
        [PolicyRegistryService] | Should -Not -BeNullOrEmpty
    }

    It 'Has SystemHardeningService class' {
        [SystemHardeningService] | Should -Not -BeNullOrEmpty
    }

    It 'Has ProvisioningService class' {
        [ProvisioningService] | Should -Not -BeNullOrEmpty
    }

    It 'Has ConfigurationQueryService class' {
        [ConfigurationQueryService] | Should -Not -BeNullOrEmpty
    }
}
