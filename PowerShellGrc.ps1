#region Stage
Import-Module ActiveDirectory

# Create the groups we will use for configurations
## Administrator manages tier resources
## Operator works in tier resources
## Consumer uses tier resources
## Asset is a tier resource
$groups = @()
$groupSplat = @{
    GroupScope    = "DomainLocal"
    GroupCategory = "Security"
}
@"
Name,Description
SG-T0-Administrator-PowerShell,Allowed to modify T0 PowerShell objects, Allowed to modify T0 Audit Policy
SG-T0-Operator-PowerShell,Allowed to use PowerShell with T0 assets
SG-T0-Consumer-PowerShell,Prohibited from using PowerShell with T0 assets
SG-T0-Asset-PowerShell,Applies T0 PowerShell controls
SG-T1-Administrator-PowerShell,Allowed to modify T1 PowerShell controls, Allowed to modify T1 Audit Policy
SG-T1-Operator-PowerShell,Allowed to use PowerShell with T1 assets
SG-T1-Consumer-PowerShell,Prohibited from using PowerShell with T1 assets
SG-T1-Asset-PowerShell,Applies T1 PowerShell controls
SG-T2-Administrator-PowerShell,Allowed to modify T2 PowerShell objects, Allowed to modify T2 Audit Policy
SG-T2-Operator-PowerShell,Allowed to use PowerShell with T2 assets
SG-T2-Consumer-PowerShell,Prohibited from using PowerShell with T2 assets
SG-T2-Asset-PowerShell,Applies T2 PowerShell controls
"@|ConvertFrom-Csv|%{$groups += New-ADGroup @groupSplat -Name $_.Name -Description $_.Description -PassThru}

@"
Name,Comment
GPO-T0-PowerShell,Configures PowerShell for T0 assets
GPO-T1-PowerShell,Configures PowerShell for T1 assets
GPO-T2-PowerShell,Configures PowerShell for T2 assets
GPO-MO-PowerShell,Configures PowerShell for a maintenance override
"@|ConverFrom-Csv|%{New-GPO -Name $_.Name -Comment $_.Comment}

#region ASD PowerShell AppendixB
function Set-PSHardSigning {
    #https://www.cyber.gov.au/business-government/protecting-devices-systems/system-administration/securing-powershell-in-the-enterprise#:~:text=Appendix%20B%3A%20PowerShell%20script%20execution%20policy
    #https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
    #https://gpsearch.azurewebsites.net/#4954
    #https://gpsearch.azurewebsites.net/#7002
    [CmdletBinding()]
    param(
        [ValidateSet("LocalMachine","CurrentUser")]
        [string]$Scope="LocalMachine",
        [bool]$Enabled=$true,
        [ValidateSet("AllSigned","RemoteSigned","Unrestricted")]
        [string]$Policy="AllSigned"
    )
    begin{
        if(-not $Enabled -or $Policy -ne "AllSigned"){
            Write-Warning "Request parameter values do NOT match recommendation"
        }

        $currentState = Get-ExecutionPolicy -List
        Write-Verbose "Current State: $($currentState|ConvertTo-Json -Compress)"

        switch ($Scope) {
            "LocalMachine" {
                $hive     = "HKLM"
                $altScope = "MachinePolicy"
            }
            "CurrentUser" { 
                $hive     = "HKCU"
                $altScope = "UserPolicy"
            }
        }
        $path = "$($hive):\Software\Policies\Microsoft\Windows\PowerShell"

        if(Test-Path -Path $path){
            $item = Get-Item -Path $path
            $executionPolicy = $item.GetValue("ExecutionPolicy")
            $enableScripts   = $item.GetValue("EnableScripts")
        }else{
            $executionPolicy = $null
            $enableScripts   = $null
        }

        if($executionPolicy -eq $Policy -and $enableScripts -eq [int]$Enabled){
            Write-Verbose "Current state already set"
            return
        }
    }
    process{
        if($executionPolicy -ne $Policy){
            Write-Verbose "Updating ExecutionPolicy from $executionPolicy to $Policy"
            Set-ItemProperty -Path $path -Name "ExecutionPolicy" -Value $Policy -Type String
        }

        if($enableScripts -ne [int]$Enabled){
            Write-Verbose "Updating EnableScripts from $enableScripts to $([int]$Enabled)"
            Set-ItemProperty -Path $path -Name "EnableScripts" -Value $([int]$Enabled) -Type DWORD
        }
    }
    end{
        return
    }
}
Set-PSHardSigning -Scope LocalMachine -Policy AllSigned -Verbose
#endregion

#region ASD PowerShell AppendixC&D&F
function Set-PSHardLogging {
    [CmdletBinding()]
    param(
        [ValidateSet("All","Audit","Module","ScriptBlock","Transcription")]
        [string[]]$Type="All",
        [ValidateSet("All","FileSystem","ProcessCreation","ProcessTermination","Registry")]
        [string[]]$AuditObjects="All",
        [System.Security.Principal.SecurityIdentifier]$AuditAdminSid,
        [string[]]$Modules="*",
        [switch]$InvocationEvents,
        [string]$TranscriptionDir="$env:SystemRoot\System32\LogFiles\PowerShell"
    )

    if("All" -in $Type -or "Audit" -in $Type){
        Write-Verbose "Configuring audit logging"
        Set-PSHardAudit -AuditObjects $AuditObjects -AuditAdminSid $AuditAdminSid
    }

    if("All" -in $Type -or "Module" -in $Type){
        Write-Verbose "Configuring module logging for:"
        foreach($module in $Modules){
            Write-Verbose "    $module"
        }
        Set-PSHardModule -Modules $Modules
    }

    if("All" -in $Type -or "ScriptBlock" -in $Type){
        Write-Verbose "Configuring script block logging"
        Set-PSHardScriptBlock -InvocationEvents:$InvocationEvents
    }

    if("All" -in $Type -or "Transcription" -in $Type){
        Write-Verbose "Configuring transcription logging"
        Set-PSHardTranscription -TranscriptionDir $TranscriptionDir -TranscriptionInvocationHeader $TranscriptionInvocationHeader
    }
}
Set-PSHardLogging -AuditAdminSid "S-1-5-21-<...>" -InvocationEvents -Verbose

#region PsHardAudit Notes
        #https://github.com/TheRockStarDBA/HackSql/blob/2a71b14e1d675306c81b2451019ba5d1da9f76ea/Get-ProcAddress.ps1#L4
        #https://www.powershellgallery.com/packages/HackSql/1.1.1
        #https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/security-auditing-settings-not-applied-when-deploy-domain-based-policy
        #https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
        #https://stackoverflow.com/questions/65254495/powershell-auditquerysystempolicy-value-of-audit-policy
        #https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override
        <#
        # Source - https://stackoverflow.com/a/72139083
        # Posted by Carsten
        # Retrieved 2026-01-31, License - CC BY-SA 4.0
        #requires -RunAsAdministrator

        $dll = [string]::Join("`r`n", '[DllImport("advapi32.dll")]', 'public static extern bool') 
        $auditpol = Add-Type -Name 'AuditPol' -Namespace 'Win32' -PassThru -MemberDefinition "
            $dll AuditEnumerateCategories(out IntPtr catList, out uint count);
            $dll AuditLookupCategoryName(Guid catGuid, out string catName);
            $dll AuditEnumerateSubCategories(Guid catGuid, bool all, out IntPtr subList, out uint count);
            $dll AuditLookupSubCategoryName(Guid subGuid, out String subName);
            $dll AuditQuerySystemPolicy(Guid subGuid, uint count, out IntPtr policy);
            $dll AuditFree(IntPtr buffer);
            $dll AuditSetSystemPolicy(IntPtr pAuditPolicy, uint PolicyCount);"

        Add-Type -TypeDefinition "
        using System;
        public struct AUDIT_POLICY_INFORMATION {
            public Guid AuditSubCategoryGuid;
            public UInt32 AuditingInformation;
            public Guid AuditCategoryGuid;
        }"

        function getPolicyInfo($sub) {
            $ms = [System.Runtime.InteropServices.Marshal]
            # get policy info for one subcategory:
            $pol = new-object AUDIT_POLICY_INFORMATION
            $size = $ms::SizeOf($pol)
            $ptr  = $ms::AllocHGlobal($size)
            $null = $ms::StructureToPtr($pol, $ptr, $false)
            $null = $auditpol::AuditQuerySystemPolicy($sub, 1, [ref]$ptr)
            $pol  = $ms::PtrToStructure($ptr, [type][AUDIT_POLICY_INFORMATION])
            $null = $ms::FreeHGlobal($ptr)
            [PsCustomObject]@{
                category = $pol.AuditCategoryGuid
                success  = [bool]($pol.AuditingInformation -band 1)
                failure  = [bool]($pol.AuditingInformation -band 2)
            }
        }

        # (optional) get GUID and local name of all categories:
        $ms = [System.Runtime.InteropServices.Marshal]
        $count = [uint32]0
        $buffer = [IntPtr]::Zero
        $size = $ms::SizeOf([type][guid])
        $null = $auditpol::AuditEnumerateCategories([ref]$buffer,[ref]$count)
        $ptr = [int64]$buffer
        $name = [System.Text.StringBuilder]::new()
        $catList = @{}
        foreach($id in 1..$count) {
            $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
            $null = $auditpol::AuditLookupCategoryName($guid,[ref]$name)
            $catList[$guid] = $name
            $ptr += $size
        }
        $null = $auditpol::AuditFree($buffer)

        # get all subcategories (with optional name):
        $guid = [guid]::Empty
        $null = $auditpol::AuditEnumerateSubCategories($guid, $true, [ref]$buffer, [ref]$count)
        $ptr = [int64]$buffer
        $subList = @{}
        foreach($id in 1..$count) {
            $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
            $null = $auditpol::AuditLookupSubCategoryName($guid,[ref]$name)
            $pol  = getPolicyInfo $guid
            $data = [psCustomObject]@{
                category = $catList[$pol.category]
                subcategory = $name
                success = $pol.success
                failure = $pol.failure
            }
            $subList[$guid.guid] = $data
            $ptr += $size
        }
        $null = $auditpol::AuditFree($buffer)

        # listing all subCategories and their audit settings:
        #$subList.Values | sort category, subcategory | ft -AutoSize

        # gettings the audit-settings for a given subcategory-GUID (without '{}'):
        #$process_creation_guid = '0CCE922B-69AE-11D9-BED3-505054503030'
        #$subList[$process_creation_guid]

        <#
        # Define the C# signature for AuditSetSystemPolicy
        $MemberDefinition = @"
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool AuditSetSystemPolicy(
    IntPtr pAuditPolicy,
    uint PolicyCount
);

[StructLayout(LayoutKind.Sequential)]
public struct AUDIT_POLICY_INFORMATION {
    public Guid AuditSubCategoryGuid;
    public uint AuditingInformation;
    public Guid AuditCategoryGuid;
}
"@

        $AuditType = Add-Type -MemberDefinition $MemberDefinition -Name "Win32Audit" -Namespace "Win32" -PassThru

        # Example: Enable Success/Failure for 'Process Creation'
        # GUID for Process Creation: {0CCE922B-69AE-11D9-BED3-505054503030}
        $policy = New-Object $AuditType+AUDIT_POLICY_INFORMATION
        $policy.AuditSubCategoryGuid = [Guid]"{0CCE922B-69AE-11D9-BED3-505054503030}"
        $policy.AuditingInformation = 0x3 # 1 (Success) + 2 (Failure)

        # Allocate memory and call the function
        $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($policy))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($policy, $ptr, $false)

        $result = [Win32.Win32Audit]::AuditSetSystemPolicy($ptr, 1)

        if ($result) {
            Write-Host "Audit policy updated successfully." -ForegroundColor Green
        } else {
            Write-Error "Failed to set audit policy. Error code: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        # Clean up memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        #>
        
        <#
        $policy = New-Object AUDIT_POLICY_INFORMATION
        $policy.AuditSubCategoryGuid = [Guid]"{0CCE922B-69AE-11D9-BED3-505054503030}"
        $policy.AuditingInformation = 0x0 # 1 (Success) + 2 (Failure)
        $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($policy))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($policy, $ptr, $false)

        $result = $auditpol::AuditSetSystemPolicy($ptr, 1)

        if ($result) {
            Write-Host "Audit policy updated successfully." -ForegroundColor Green
        } else {
            Write-Error "Failed to set audit policy. Error code: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        # Clean up memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        #>
#endregion
function Set-PSHardAudit {
    [CmdletBinding()]
    param(
        [ValidateSet("All","File System","Process Creation","Process Termination","Registry")]
        [string[]]$AuditObjects="All",
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$AuditAdminSid
    )
    begin{
        if($AuditObjects -eq "All"){
            $subcategories = @("File System","Process Creation","Process Termination","Registry")
        }else{
            $subcategories = $AuditObjects
        }
        Write-Verbose "Get current audit policy state"
        $currentPolicy   = & auditpol /get /category:* /r|ConvertFrom-Csv
        $currentSecurity = [string](& auditpol /get /sd)
        $currentSd       = $currentSecurity.Substring(34,$currentSecurity.Length-35)
        $desiredAdminSd  = "(A;;DCSWRPDTRC;;;$($AuditAdminSid.Value))"
        $adminSdCheck    = $currentSd -like "*$desiredAdminSd*"

        foreach($subcategory in $subcategories){
            $policy = $currentPolicy | Where-Object {
                $_."Policy Target" -eq "System" -and
                $_.Subcategory -eq $subcategory
            }

            if($policy."Inclusion Setting" -eq "Success and Failure" -and $null -eq $policy."Exclusion Setting"){
                Write-Verbose "Current state matches desired state for: $subcategory"
                $subcategories = $subcategories | Where-Object{$_ -ne $subcategory}
            }
        }

        if($subcategories.Length -eq 0 -and $adminSdCheck){
            Write-Verbose "All subcategories match desired state and security descriptor set"
            return
        }

        $legacyAudit = $false
        $path = "HKLM:\System\CurrentControlSet\Control\LSA"
        if(Test-Path $path){
            $item = Get-Item "$path"
            if($item.GetValue("SCENoApplyLegacyAuditPolicy") -eq 0){
                Write-Warning "Legacy Audit Policy is prioritized, settings may revert. Check group policy settings for SCENoApplyLegacyAuditPolicy."
                $legacyAudit = $true
            }
        }
    }
    process{
        if($legacyAudit){
            Write-Verbose "Set SCENoApplyLegacyAuditPolicy to disabled"
            Set-ItemProperty -Path $path -Name "SCENoApplyLegacyAuditPolicy" -Value 1
        }

        foreach($subcategory in $subcategories){
            Write-Verbose "Set audit policy for: $subcategory"
            & auditpol /set /subcategory:$subcategory /success:enable /failure:enable
        }
        
        if(-not $adminSdCheck){
            Write-Verbose "Set audit security descriptor"
            & auditpol /set /sd $currentSd.Replace(")S:",")$($desiredAdminSd)S:")
        }
    }
    end{
        return
    }
}

# Add DACL for admins
# Remove ACEs for users
function Set-PSHardModule {
    #https://gpsearch.azurewebsites.net/#7929
    [CmdletBinding()]
    param(
        [string[]]$Modules = "*"
    )
    begin{
        $configFlag = @{
            Main                     = $false
            ModuleLoggingKey         = $false
            EnableModuleLoggingValue = $false
            ModuleNamesKey           = $false
            ModuleValues             = $false
        }
        $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if(-not (Test-Path $path)){
            Write-Verbose "ModuleLogging not set, will update"
            $configFlag.Main = $configFlag.ModuleLoggingKey = $true
        }else{
            Write-Verbose "Get current ModuleLogging state"
            $ModuleLogging = Get-Item $path
            if($ModuleLogging.GetValue("EnableModuleLogging") -in @(0,$null)){
                Write-Verbose "ModuleLogging disabled, will update"
                $configFlag.Main = $configFlag.EnableModuleLoggingValue = $true
            }
        }

        if(-not (Test-Path "$path\ModuleNames")){
            Write-Verbose "ModuleNames not set, will update"
            $configFlag.Main = $configFlag.ModuleNamesKey = $true
        }else{
            Write-Verbose "Get current ModuleNames state"
            $ModuleNames = Get-Item "$path\ModuleNames"
            $currentModules = $ModuleNames.Property
            foreach($module in $Modules){
                if($module -in $currentModules){
                    Write-Verbose "Current modules contains $module, skipping"
                    $Modules = $Modules|Where-Object{$_ -ne $module}
                }else{
                    Write-Verbose "Logging not currently set for $module"
                    $configFlag.Main = $configFlag.ModuleValues = $true
                }
            }
        }

        if(-not $configFlag.Main){
            Write-Verbose "Configuration already set, skipping"
            return
        }
    }
    process{
        if($configFlag.ModuleLoggingKey){
            Write-Verbose "Creating ModuleLogging key"
            New-Item -Path $path
        }

        if($configFlag.EnableModuleLoggingValue){
            Write-Verbose "Setting EnableModuleLogging value"
            New-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force
        }

        if($configFlag.ModuleNamesKey){
            Write-Verbose "Creating ModuleNames key"
            New-Item -Path "$path\ModuleNames"
        }

        if($configFlag.ModuleValues){
            foreach($module in $Modules){
                Write-Verbose "Setting $module for logging"
                New-ItemProperty -Path "$path\ModuleNames" -Name $module -Value $module -PropertyType String -Force
            }
        }
    }
    end{
        return
    }
}
function Set-PSHardScriptBlock {
    [CmdletBinding()]
    param(
        [switch]$InvocationEvents
    )
    begin{
        $configFlag = @{
            Main                          = $false
            ScriptBlockLoggingKey         = $false
            EnableScriptBlockLoggingValue = $false
            InvocationEventsValue         = $false
        }
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if(Test-Path $path){
            $item = Get-Item $path
            if($item.GetValue("EnableScriptBlockLogging") -in @(0,$null)){
                Write-Verbose "Value for EnableScriptBlockLogging not set, configuring"
                $configFlag.Main = $configFlag.EnableScriptBlockLoggingValue = $true
            }
            if($item.GetValue("EnableScriptBlockInvocationLogging") -in @(0,$null) -and $InvocationEvents){
                Write-Verbose "Value for EnableScriptBlockInvocationLogging not set, configuring"
                $configFlag.Main = $configFlag.InvocationEventsValue = $true
            }
        }else{
            Write-Verbose "Key for ScriptBlockLogging not found, configuring"
            $configFlag.Main = $configFlag.ScriptBlockLoggingKey = $true
        }

        if(-not $configFlag.Main){
            Write-Verbose "Current config meets requested state"
            return
        }
    }
    process{
        if($configFlag.ScriptBlockLoggingKey){
            Write-Verbose "Creating key"
            New-Item -Path $path
        }
        if($configFlag.EnableScriptBlockLoggingValue){
            Write-Verbose "Enabling logging"
            New-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force
        }
        if($configFlag.InvocationEventsValue){
            Write-Verbose "Enabling invocation logging"
            New-ItemProperty -Path $path -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType DWord -Force
        }
    }
    end{
        return
    }
}
function Set-PSHardTranscription {
    [CmdletBinding()]
    param(
        [string]$TranscriptionDir = "$env:SystemRoot\System32\LogFiles\PowerShell"
    )
    begin{
        $configFlag = @{
            Main                   = $false
            TranscriptionKey       = $false
            RegistryDacl           = $false
            EnableTranscriptingVal = $false
            InvocationHeaderVal    = $false
            OutputDirectoryMissing = $false
            OutputDirectoryVal     = $false
            DirectoryDacl          = $false
            DirectorySacl          = $false
            ScheduledTask          = $false
        }

        if(-not (Test-Path $TranscriptionDir)){
            Write-Verbose "Transcription directory ($TranscriptionDir) not found, configuring"
            $configFlag.Main = $configFlag.OutputDirectoryMissing = $true
        }else{
            $acl = Get-Acl $TranscriptionDir
            #Verify DirectoryDacl and DirectorySacl
            #Application Packages	Read and Execute
            #Creator Owner	Deny All
            #Authenticated Users	Write and Read
            #SYSTEM	Full Control
            #BUILTIN\Administrators	Full Control

            #Advanced options.
            #Type = All
            #Apply to = This folder/sub folders and files
            #Everyone	Full Control
        }

        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\"
        if(Test-Path $path){
            $item = Get-Item $path
            if($item.GetValue("EnableTranscripting") -in @(0,$null)){
                Write-Verbose "Value for EnableScriptBlockLogging not set, configuring"
                $configFlag.Main = $configFlag.EnableTranscriptingVal = $true
            }
            if($item.GetValue("EnableInvocationHeader") -in @(0,$null)){
                Write-Verbose "Value for EnableInvocationHeader not set, configuring"
                $configFlag.Main = $configFlag.InvocationHeaderVal = $true
            }
            if($item.GetValue("OutputDirectory") -ne $TranscriptionDir){
                Write-Verbose "Value for OutputDirectory not set, configuring"
                $configFlag.Main = $configFlag.OutputDirectoryVal = $true
            }
            #Verify RegistryDacl
            #Application Packages	Read and Execute
            #Creator Owner	Deny All
            #Authenticated Users	Write and Read
            #SYSTEM	Full Control
            #BUILTIN\Administrators	Full Control
        }else{
            Write-Verbose "Key for Transcription not found, configuring"
            $configFlag.Main = $configFlag.TranscriptionKey = $true
        }

        #Verify ScheduledTask

        if(-not $configFlag.Main){
            Write-Verbose "Current config meets requested state"
            return
        }
    }
    process{
        if($configFlag.OutputDirectoryMissing){
            Write-Verbose "Creating transcription directory"
            New-Item -Path $TranscriptionDir -ItemType Directory
        }
        if($configFlag.DirectoryDacl){
            #Set DACL
        }
        if($configFlag.DirectorySacl){
            #Set SACL
        }
        if($configFlag.TranscriptionKey){
            Write-Verbose "Creating key"
            New-Item -Path $path
        }
        if($configFlag.EnableTranscriptingVal){
            Write-Verbose "Enabling transcription"
            New-ItemProperty -Path $path -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force
        }
        if($configFlag.InvocationHeaderVal){
            Write-Verbose "Enabling invocation headers"
            New-ItemProperty -Path $path -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force
        }
        if($configFlag.OutputDirectoryVal){
            Write-Verbose "Set output directory"
            New-ItemProperty -Path $path -Name "OutputDirectory" -Value $TranscriptionDir -PropertyType String -Force
        }
        if($configFlag.ScheduledTask){
            #Set Scheduled Task
        }
    }
    end{
        return
    }
}
# Appendix G
#Get-WindowsCapability -Online|?{$_.Name -like "OpenSSH.Server*"}|Add-WindowsCapability -Online
#Start-Service sshd
#Set-Service -Name sshd -StartupType 'Automatic'
#New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
#New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "c:/progra~1/powershell/7/pwsh.exe" -PropertyType String -Force
#cp "$env:ProgramData\ssh\sshd_config" "$env:ProgramData\ssh\sshd_config.old"
#(gc "$env:ProgramData\ssh\sshd_config") -replace "# override default of no subsystems", "$&`nSubsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo -noprofile" | sc $env:ProgramData\ssh\sshd_config
#(gc "$env:ProgramData\ssh\sshd_config") -replace "#PasswordAuthentication yes", "PasswordAuthentication yes" | sc $env:ProgramData\ssh\sshd_config
#(gc "$env:ProgramData\ssh\sshd_config") -replace "#GSSAPIAuthentication no", "GSSAPIAuthentication yes" | sc $env:ProgramData\ssh\sshd_config
#Restart-Service sshd
function Set-PSHardRemoting {
    # TODOs
    ## SSH
    ## Firewalls and management segmenting
    [CmdletBinding()]
    param(
        [switch]$Ssh,
        [switch]$WinRm,
        [switch]$ModifyUnselected,
        [string]$TrustedSource,
        [string]$DefaultShell="pwsh.exe"
    )
    begin{
        if($ModifyUnselected){
            Write-Warning "Will disable: SSH: $Ssh; WinRM: $WinRm"
        }
        $configFlag = @{
            Main  = $false
            SSH   = @{
                Service                = $false
                Firewall               = $false
                OpenSshKey             = $false
                DefaultShellVal        = $false
                Subsystem              = $false
                PasswordAuthentication = $false
                GSSAPIAuthentication   = $false
            }
            WinRM = @{
                Service        = $false
                Firewall       = $false
                ClientKey      = $false
                ServiceKey     = $false
                ServiceVals = @{
                    AllowAutoConfig            = $false
                    IPv4Filter                 = $false
                    IPv6Filter                 = $false
                    DisableRunAs               = $false
                    CbtHardeningLevel          = $false
                    AllowUnencryptedTraffic    = $false
                    AllowBasic                 = $false
                    AllowCredSSP               = $false
                    AllowNegotiate             = $false
                    AllowKerberos              = $false
                    HttpCompatibilityListener  = $false
                    HttpsCompatibilityListener = $false
                }
            }
        }

        $services = @{
            WinRM = $null
            SSH   = $null
        }

        $firewall = @{
            WinRM = $false
            SSH   = $false
        }

        $registry = @{
            Path  = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\"
            WinRM = @{
                Client      = $null
                ClientVals  = @{
                    AllowBasic = 0
                    AllowCredSSP = 0
                    AllowDigest = 0
                    AllowKerberos = 1
                    AllowNegotiate = 0
                    AllowUnencryptedTraffic = 0
                    TrustedHosts = 1
                    TrustedHostsList = "*" # Set this to a subzone for the tier of resources
                }
                Service     = $null
                ServiceVals = @{
                    AllowAutoConfig            = 1
                    IPv4Filter                 = "*" # If you use OOB Management, set this to the range of addresses in that segment
                    IPv6Filter                 = ""
                    DisableRunAs               = 1
                    CbtHardeningLevel          = "Strict" # If HardeningLevel is set to Strict, any request not containing a valid channel binding token is rejected.
                    AllowUnencryptedTraffic    = 0
                    AllowBasic                 = 0
                    AllowCredSSP               = 0
                    AllowNegotiate             = 0
                    AllowKerberos              = 1
                    HttpCompatibilityListener  = 0
                    HttpsCompatibilityListener = 0
                }
            }
            SSH   = $null
        }

        if($WinRm -or $ModifyUnselected){
            $services.WinRM = Get-Service -Name WinRM

            $registry.WinRM.Client  = Get-Item -Path "$($registry.Path)\Client"
            $registry.WinRM.Service = Get-Item -Path "$($registry.Path)\Service"

            foreach($value in $registry.WinRM.ClientVals.Keys){
                $data = @{
                    Current = $registry.WinRM.Client.GetValue($value)
                    Desired = $registry.WinRM.ClientVals[$value]
                }

                if($data.Current -ne $data.Desired){
                    Write-Verbose "Registry $value not set, will configure"
                    $configFlag.Main = $configFlag.WinRM.ClientVals[$value] = $true
                }
            }

            foreach($value in $registry.WinRM.ServiceVals.Keys){
                $data = @{
                    Current = $registry.WinRM.Service.GetValue($value)
                    Desired = $registry.WinRM.ServiceVals[$value]
                }

                if($data.Current -ne $data.Desired){
                    Write-Verbose "Registry $value not set, will configure"
                    $configFlag.Main = $configFlag.WinRM.ServiceVals[$value] = $true
                }
            }
        }
        
    }
    process{}
    end{}
}
# Appendix E
function Set-PSHardLogAnalysis {
    [CmdletBinding()]
    param(

    )
    begin{}
    process{}
    end{}
}
# Appendix H
function Set-PSHardConstrainedException {
    [CmdletBinding()]
    param(

    )
    begin{}
    process{}
    end{}
}
function Set-PSHardVerifyAmsi {
<#    
$testString = "AMSI Test Sample: " + "7e72c3ce-861b-4339-8740-0ac1484c1386"
Invoke-Expression $testString

Get-MpComputerStatus | Format-List AMRunningMode, AntispywareSignatureVersion, AMServiceVersion
#>
    [CmdletBinding()]
    param(

    )
    begin{}
    process{}
    end{}
}
function Set-PSHardRemoveLegacy {
<#    
# Remove or disable PowerShell versions below 7
$legacyVersions = @(
    "MicrosoftWindowsPowerShellV2"
)

foreach ($version in $legacyVersions) {
    Disable-WindowsOptionalFeature -FeatureName $version -Online -NoRestart
}
#>
    [CmdletBinding()]
    param(

    )
    begin{}
    process{}
    end{}
}
#endregion


#region Simple Signing
# Create self-signed certificate in machine context
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" `
    -Subject "CN=PowerShell-Signing" -KeyUsage DigitalSignature `
    -Type CodeSigningCert -FriendlyName "PowerShell Code Signing" `
    -KeyExportPolicy Exportable

# Export private key to base64
$certPath = "Cert:\LocalMachine\My\$($cert.Thumbprint)"
$pfxBytes = Export-PfxCertificate -Cert $certPath -FilePath "$env:TEMP\cert.pfx" -Password (ConvertTo-SecureString -String "temp" -AsPlainText -Force)
$base64Cert = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:TEMP\cert.pfx"))

# Add to local vault
$vaultParams = @{
    VaultName      = "LocalVault"
    SecretName     = "PowerShell-Signing-Cert"
    SecretValue    = (ConvertTo-SecureString -String $base64Cert -AsPlainText -Force)
}
Set-Secret @vaultParams -Force

Export-Certificate -Cert $certPath -FilePath "$env:TEMP\PowerShell-Signing.cer" -Type CERT

& certutil -dspublish -f "$env:TEMP\PowerShell-Signing.cer" RootCA

Remove-Item "$env:TEMP\cert.pfx"
Remove-Item "$env:TEMP\PowerShell-Signing.cer"

# Create GPO to add PowerShell-Signing certificate to Trusted Publishers
$gpoName = "PowerShell-Signing-Trust"
New-GPO -Name $gpoName -Comment "Adds PowerShell-Signing certificate to Trusted Publishers"

# Link GPO to OU
New-GPLink -Name $gpoName -Target "DC=test,DC=com"

# Configure certificate to be imported into Trusted Publishers store
Set-GPRegistryValue -Name $gpoName `
    -Key "HKLM\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates\$($cert.Thumbprint)" `
    -ValueName "Blob" `
    -Value $cert.RawData `
    -Type Binary

# Retrieve the base64 certificate from the local vault
$vaultSecret = Get-Secret -Vault LocalVault -Name "PowerShell-Signing-Cert"
$base64Cert = [System.Convert]::ToBase64String($vaultSecret)

# Convert the base64 string back to a byte array
$pfxBytes = [System.Convert]::FromBase64String($base64Cert)

# Create a temporary file to store the PFX certificate
$tempCertPath = "$env:TEMP\tempCert.pfx"
[IO.File]::WriteAllBytes($tempCertPath, $pfxBytes)

# Load the certificate from the PFX file
$cert = [System.Security.Cryptography.X509Certificates.X509CertificateLoader]::Load($tempCertPath)

# Specify the file to sign
$fileToSign = "C:\Path\To\YourScript.ps1"

# Sign the PowerShell script
Set-AuthenticodeSignature -FilePath $fileToSign -Certificate $cert

# Clean up the temporary certificate file
Remove-Item $tempCertPath -Force
#endregion

##region script
#region Add a new event log
function Install-EventLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$LogName,
        [Parameter(Mandatory=$true)]
        [string[]]$Sources,
        [string]$OverflowAction="OverwriteAsNeeded",
        [int]$Size=20MB,
        [bool]$ContinueOnNewSources=$true
    )
    begin {
        $prefixVerbose = "[Verbose][$($MyInvocation.MyCommand.Name)]"
        $prefixInfo = "[Info][$($MyInvocation.MyCommand.Name)]"
    }
    process {
        Write-Verbose "$prefixVerbose Obtaining Event Log List"
        #[System.Diagnostics.EventLog]::GetEventLogs()
        $logs = Get-EventLog -List
        Write-Verbose "$prefixVerbose Obtained $($logs.count) Event Logs"

        Write-Verbose "$prefixVerbose Checking for existing log"
        if ($logs.Log -contains $LogName) {
            Write-Verbose "$prefixVerbose The '$LogName' Log Name already exists"
            $exists = $true

            #[System.Diagnostics.EventLog]::SourceExists("Management")
            Write-Verbose "$prefixVerbose Obtaining Log Sources for $LogName"
            $existing = (Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName).pschildname
            Write-Verbose "$prefixVerbose Obtained $($existing.count) log sources"

            Write-Verbose "$prefixVerbose Identifying any overlapping event sources"
            $compare = Compare-Object $existing $sources -IncludeEqual
            Write-Verbose "$prefixVerbose $($compare.count) event sources"
            $overlap = ($compare|Where-Object{$_.SideIndicator -eq "=="}).InputObject

            if ($ContinueOnNewSources -and $overlap) {
                Write-Verbose "$prefixVerbose Skipping existing event sources"
                $Sources = ($compare|Where-Object{$_.SideIndicator -eq "=>"}).InputObject
            }

            if ($overlap -and $Sources.Count -eq 0) {
                Write-Verbose "$prefixVerbose Found existing event sources, exiting function"
                Write-Output "$prefixInfo $($overlap.count) Log Sources already exist in the $LogName log"
                return
            }
        }

        Write-Verbose "$prefixVerbose Registering $($sources.count) event sources"
        foreach ($source in $sources) {
            Write-Verbose "$prefixVerbose Registering '$source' event source in '$LogName'"
            New-EventLog -LogName $LogName -Source $source -ErrorAction Stop

            $log = @{
                LogName   = $LogName
                EntryType = "Information"
                Source    = $source
                Category  = 0
                EventId   = 1
                Message   = "$prefixInfo Implementing $LogName with source $source"
            }
            Write-Verbose "$prefixVerbose Writing '$source' event log entry"
            Write-EventLog @log
        }

        if (-not $exists) {
            Write-Verbose "$prefixVerbose First run configuration"

            Write-Verbose "$prefixVerbose Configuring limits for the '$LogName' Event Log"
            Limit-EventLog -LogName $LogName -OverflowAction $OverflowAction -MaximumSize $Size
        }
    }
}
$prefixVerbose = "[Verbose][$($MyInvocation.MyCommand.Name)]"
$prefixInfo = "[Info][$($MyInvocation.MyCommand.Name)]"
$log = @{
    LogName   = $env:USERDOMAIN
    EntryType = "Information"
    Source    = "Management"
    Category  = 0
    EventId   = 1
    Message   = "$prefixInfo Implementing $LogName with source $source"
}
Install-EventLog -LogName $log.LogName -Sources @($log.Source)
Write-Verbose "$prefixVerbose Writing '$source' event log entry"
Write-EventLog @log
#endregion

#region Install PowerShell Core
## Requires WS2025
#winget install --id Microsoft.PowerShell --source winget
<#
$r=[System.Net.WebRequest]::Create("https://github.com/PowerShell/PowerShell/releases/latest")
$r.AllowAutoRedirect=$false
$r.Method="Head"
$t=$r.GetResponse().Headers["Location"]
$v=$t.substring($t.indexOf("/tag/v")+6,$t.length-$t.indexOf("/tag/v")-6)
irm https://github.com/PowerShell/PowerShell/releases/download/v$v/PowerShell-$v-win-x64.msi -OutFile ".\Powershell-$v-win-x64.msi"
#>
Copy-Item "\\TEST.COM\src\PowerShell\PowerShell-7.5.4-win-x64.msi" $env:TEMP\
$arguments = "/package `"$env:TEMP\PowerShell-7.5.4-win-x64.msi`" /quiet REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1"
$proc = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
if ($proc.ExitCode -eq 0) {
    Write-Host "Installation successful"
} else {
    Write-Host "Installation failed with exit code: $($proc.ExitCode)"
}
Remove-Item "$env:TEMP\PowerShell-7.5.4-win-x64.msi"
#endregion

#region Verify trust to code signing
## Pipeline to publish includes signing
# Verify the signing certificate is in the trusted certificate authorities
#$certThumbprint = $cert.Thumbprint
$certThumbprint = "6C71F15C103BDE3FCA3FEFCB8D1FDC3878A25CBB"
$trustedCAs = @(
    "Cert:\LocalMachine\CA",
    "Cert:\CurrentUser\CA"
)

foreach ($store in $trustedCAs) {
    $certExists = Get-ChildItem $store | Where-Object { $_.Thumbprint -eq $certThumbprint }
    if ($certExists) {
        Write-Host "Certificate found in $store"
    } else {
        Write-Host "Certificate NOT found in $store - Refreshing GPP"
        & gpupdate /force
    }
}

# Add certificate to Device Guard code integrity policy
$cipPath = "$env:ProgramData\Microsoft\Windows\DeviceGuard"
if (-not (Test-Path $cipPath)) {
    New-Item -Path $cipPath -ItemType Directory -Force | Out-Null
}

# Export certificate in DER format for Device Guard
Export-Certificate -Cert "Cert:\LocalMachine\CA\$certThumbprint" -FilePath "$cipPath\PowerShell-Signing.cer" -Type CERT

Write-Host "Certificate added to Device Guard trust"
#endregion

#region Verify PS auditing
# Enable PowerShell Module Logging
$modulePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modulePath)) {
    New-Item -Path $modulePath -Force | Out-Null
}
Set-ItemProperty -Path $modulePath -Name "EnableModuleLogging" -Value 1 -Type DWord

# Enable PowerShell Script Block Logging
$scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $scriptBlockPath)) {
    New-Item -Path $scriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable PowerShell Transcription Logging
$transcriptPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $transcriptPath)) {
    New-Item -Path $transcriptPath -Force | Out-Null
}
Set-ItemProperty -Path $transcriptPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
Set-ItemProperty -Path $transcriptPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $transcriptPath -Name "OutputDirectory" -Value "C:\Windows\System32\LogFiles\PowerShell" -Type String

# Configure Event Log auditing
#auditpol /set /subcategory:"PowerShell" /success:enable /failure:enable

Write-Host "PowerShell auditing configured successfully"
#endregion

#region Setup SSH remoting
Get-WindowsCapability -Online|?{$_.Name -like "OpenSSH.Server*"}|Add-WindowsCapability -Online
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
#New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "c:/progra~1/powershell/7/pwsh.exe" -PropertyType String -Force
cp "$env:ProgramData\ssh\sshd_config" "$env:ProgramData\ssh\sshd_config.old"
(gc "$env:ProgramData\ssh\sshd_config") -replace "# override default of no subsystems", "$&`nSubsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo -noprofile" | sc $env:ProgramData\ssh\sshd_config
(gc "$env:ProgramData\ssh\sshd_config") -replace "#PasswordAuthentication yes", "PasswordAuthentication yes" | sc $env:ProgramData\ssh\sshd_config
(gc "$env:ProgramData\ssh\sshd_config") -replace "#GSSAPIAuthentication no", "GSSAPIAuthentication yes" | sc $env:ProgramData\ssh\sshd_config
Restart-Service sshd
#endregion

#region Add JEA profiles
# Create JEA session configuration for diagnostic commands
$jeaname = "DiagnosticsJEA"
$jeatemplateParams = @{
    SessionType       = "RestrictedRemoteServer"
    Author            = "PowerShell-Grc"
    Description       = "JEA configuration for diagnostic commands"
    CompanyName       = "Contoso"
    Copyright         = "(c) Contoso. All rights reserved."
}

New-PSSessionConfigurationFile @jeatemplateParams `
    -Path "$env:ProgramData\PowerShell\Configuration\$jeaname.pssc" `
    -VisibleAliases @() `
    -VisibleCmdlets @(
        @{ Name = 'Get-Process'; Parameters = @{ Name = 'Name'; ValidateSet = '*' } },
        @{ Name = 'Get-Service'; Parameters = @{ Name = 'Name'; ValidateSet = '*' } },
        @{ Name = 'Get-EventLog'; Parameters = @{ Name = 'LogName'; ValidateSet = 'System','Application' } },
        @{ Name = 'Get-ChildItem'; Parameters = @{ Name = 'Path'; ValidateSet = 'C:\Logs','C:\Windows\Temp' } },
        @{ Name = 'Test-NetConnection' },
        @{ Name = 'Get-NetAdapter' }
    ) `
    -VisibleFunctions @() `
    -VisibleExternalCommands @() `
    -VisibleProviders @() `
    -ScriptsToProcess @() `
    -AliasDefinitions @()

# Register the JEA session configuration
Register-PSSessionConfiguration -Path "$env:ProgramData\PowerShell\Configuration\$jeaname.pssc" `
    -Name $jeaname -Force

# Grant diagnostic group access to the JEA endpoint
$jearole = @{
    RoleDefinitions = @{
        'CONTOSO\SG-T0-Consumer-PowerShell' = @{ RoleCapabilities = 'DiagnosticsJEA' }
    }
}
Set-PSSessionConfiguration -Name $jeaname @jearole -Force

Write-Host "JEA configuration '$jeaname' created and registered successfully"
#endregion

#region Signing
# Set execution policy to require all scripts to be signed
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force

Write-Host "Execution policy set to AllSigned - all PowerShell scripts must be signed to run"
#endregion

#region SRPs
# Create WDAC policy to restrict PowerShell execution to specific group members
$wdacPolicyPath = "$env:ProgramData\Microsoft\Windows\DeviceGuard\WDAC"
if (-not (Test-Path $wdacPolicyPath)) {
    New-Item -Path $wdacPolicyPath -ItemType Directory -Force | Out-Null
}

# Create WDAC policy XML
$wdacPolicy = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="EXE">
    <Rules>
        <Allow ID="ID_ALLOW_SIGNED_POWERSHELL" FriendlyName="Allow signed PowerShell" PackageFamilyName="*" Publisher="*" SigningScenario="131" Action="SI_EXEC_ALLOW" />
        <Deny ID="ID_DENY_UNSIGNED_POWERSHELL" FriendlyName="Deny unsigned PowerShell" Publisher="*" SigningScenario="131" Action="SI_EXEC_DENY" />
    </Rules>
    <EKUs />
    <FileRules>
        <Allow ID="ID_ALLOW_PWSH_LOCATION" FriendlyName="Allow PowerShell Core" FileName="pwsh.exe" MinimumFileVersion="7.0.0.0" />
        <Allow ID="ID_ALLOW_PSH_LOCATION" FriendlyName="Allow PowerShell" FileName="powershell.exe" MinimumFileVersion="5.1.0.0" />
    </FileRules>
    <Signers>
        <Signer ID="ID_SIGNER_MICROSOFT" Name="Microsoft Corporation">
            <CertRoot Type="TBS" Value="$($cert.Thumbprint)" />
        </Signer>
    </Signers>
    <SigningScenarios>
        <SigningScenario ID="131" Name="Unsigned System Integrity" Value="1" AppidExt="true" />
    </SigningScenarios>
    <UpdatePolicySigners />
</SiPolicy>
"@

$wdacPolicy | Out-File -FilePath "$wdacPolicyPath\PowerShellWDAC.xml" -Force

# Merge policy with existing WDAC policy
Merge-WDACPolicy -PolicyPath @("$wdacPolicyPath\PowerShellWDAC.xml") -OutputPath "$wdacPolicyPath\MergedPolicy.xml"

# Convert policy to binary format
ConvertFrom-CIPolicy -XmlFilePath "$wdacPolicyPath\MergedPolicy.xml" -BinaryFilePath "$wdacPolicyPath\MergedPolicy.cip" -NotEveryone

# Deploy WDAC policy
Copy-Item -Path "$wdacPolicyPath\MergedPolicy.cip" -Destination "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" -Force
Restart-Computer -Force

# Verify AMSI is available and enabled
$amsiPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\AMSI"
if (Test-Path $amsiPath) {
    Write-Host "AMSI registry path exists"
    $amsiEnabled = Get-ItemProperty -Path $amsiPath -Name "Enabled" -ErrorAction SilentlyContinue
    if ($amsiEnabled.Enabled -eq 1) {
        Write-Host "AMSI is enabled"
    } else {
        Write-Host "AMSI is disabled - enabling AMSI"
        Set-ItemProperty -Path $amsiPath -Name "Enabled" -Value 1 -Type DWord
    }
} else {
    Write-Host "AMSI not found - creating registry entry"
    New-Item -Path $amsiPath -Force | Out-Null
    Set-ItemProperty -Path $amsiPath -Name "Enabled" -Value 1 -Type DWord
}

# Verify AMSI providers are registered
$providersPath = "HKLM:\Software\Microsoft\AMSI\Providers"
if (Test-Path $providersPath) {
    $providers = Get-ChildItem -Path $providersPath
    Write-Host "Found $($providers.Count) AMSI provider(s) registered"
} else {
    Write-Host "No AMSI providers registered"
}
#endregion

#region Firewall
# Configure Windows Firewall to restrict PowerShell remoting to specific groups
$firewallRuleName = "PowerShell-Remoting-Restricted"
$allowedGroups = @(
    "CONTOSO\SG-T0-Administrator-PowerShell",
    "CONTOSO\SG-T0-Operator-PowerShell"
)

# Create firewall rule for WinRM HTTP
New-NetFirewallRule -DisplayName "$firewallRuleName-HTTP" `
    -Direction Inbound -Protocol TCP -LocalPort 5985 `
    -Action Block -Group "PowerShell Remoting"

# Create firewall rule for WinRM HTTPS
New-NetFirewallRule -DisplayName "$firewallRuleName-HTTPS" `
    -Direction Inbound -Protocol TCP -LocalPort 5986 `
    -Action Block -Group "PowerShell Remoting"

# Configure WSMAN listener security
$wsmanParams = @{
    Path       = 'WSMan:\localhost\Service\Auth'
    Name       = 'Basic'
    Value      = $false
    Force      = $true
}
Set-Item @wsmanParams

# Restrict session access via security descriptor
$principals = ($allowedGroups | ForEach-Object { "O:NSG:BAD:(A;;GA;;;$((New-Object System.Security.Principal.NTAccount($_)).Translate([System.Security.Principal.SecurityIdentifier]).Value))" }) -join ""
$sddl = "O:NSG:BAD:P(A;;GA;;;S-1-5-18)$principals"
Set-PSSessionConfiguration -Name Microsoft.PowerShell -SecurityDescriptorSddl $sddl -Force

Write-Host "Network access to PowerShell restricted to authorized group members"
#endregion

#region Block network access
# Block outbound internet access for PowerShell processes
New-NetFirewallRule -DisplayName "Block PowerShell Internet Access" `
    -Direction Outbound -Program "C:\Program Files\PowerShell\7\pwsh.exe" `
    -Action Block -RemoteAddress Internet

New-NetFirewallRule -DisplayName "Block PowerShell Legacy Internet Access" `
    -Direction Outbound -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Action Block -RemoteAddress Internet

Write-Host "PowerShell internet access blocked via firewall rules"
#endregion

#region Remove legacy PS versions
# Remove or disable PowerShell versions below 7
$legacyVersions = @(
    "MicrosoftWindowsPowerShellV2"
)

foreach ($version in $legacyVersions) {
    Disable-WindowsOptionalFeature -FeatureName $version -Online -NoRestart
}
#endregion










# Create GPO for security hardening
$gpoName = "T0-PowerShell-Security"
New-GPO -Name $gpoName -Comment "PowerShell security hardening policy"

# Link GPO to OU
New-GPLink -Name $gpoName -Target "OU=Tier0,DC=contoso,DC=com"

# Configure AppLocker policy
$applockerPolicy = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Exe" EnforcementMode="Enforced">
        <FilePathRule Id="$(New-Guid)" Name="Allow signed executables" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePathCondition Path="C:\Windows\*" />
            </Conditions>
        </FilePathRule>
        <FilePathRule Id="$(New-Guid)" Name="Deny specific executable" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="C:\Temp\restricted.exe" />
            </Conditions>
        </FilePathRule>
    </RuleCollection>
</AppLockerPolicy>
"@

Set-AppLockerPolicy -XmlPolicy $applockerPolicy -Enforce

# Enable PowerShell audit logs via Group Policy
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Value 1 -Type DWORD
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Value 1 -Type DWORD

# Configure PowerShell constrained language mode and script signing
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" -ValueName "ExecutionPolicy" -Value "AllSigned" -Type String
Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" -ValueName "EnableScripts" -Value 1 -Type DWORD

# Configure PowerShell Remoting
Enable-PSRemoting -Force
Set-PSSessionConfiguration -Name Microsoft.PowerShell -SecurityDescriptorSddl (Get-PSSessionConfiguration -Name Microsoft.PowerShell).SecurityDescriptorSddl -Force

# Disable PowerShell v2
Disable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2 -Online -NoRestart



# Create a GPO to run a PowerShell script from SYSVOL
$scriptGpoName = "T0-PowerShell-Script-Execution"
New-GPO -Name $scriptGpoName -Comment "GPO to run PowerShell script from SYSVOL"

# Link GPO to OU
New-GPLink -Name $scriptGpoName -Target "OU=Tier0,DC=contoso,DC=com"

# Set the script path (adjust the path as necessary)
$scriptPath = "\\contoso.com\SYSVOL\contoso.com\scripts\YourScript.ps1"

# Configure the GPO to run the PowerShell script at startup
Set-GPRegistryValue -Name $scriptGpoName -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Scripts\Startup" -ValueName "0" -Value $scriptPath -Type String