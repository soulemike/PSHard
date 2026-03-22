$ErrorActionPreference = 'Stop'

# Load class definitions first (Models → Services)
$ModelFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Classes/Models') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name
$ServiceFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Classes/Services') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name

foreach ($file in $ModelFiles) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load model file: $($file.FullName). $_"
    }
}

foreach ($file in $ServiceFiles) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load service file: $($file.FullName). $_"
    }
}

# Load Private and Public functions deterministically
$Private = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name
$Public  = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name

foreach ($file in $Private) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load private file: $($file.FullName). $_"
    }
}

foreach ($file in $Public) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to load public file: $($file.FullName). $_"
    }
}

if ($Public) {
    $functionNames = $Public | ForEach-Object {
        [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
    }
    Export-ModuleMember -Function $functionNames
}
