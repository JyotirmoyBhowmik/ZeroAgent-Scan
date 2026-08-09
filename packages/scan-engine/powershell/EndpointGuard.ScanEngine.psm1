# Root Module for EndpointGuard.ScanEngine

$functionsDir = Join-Path -Path $PSScriptRoot -ChildPath "functions"
$functionFiles = Get-ChildItem -Path $functionsDir -Filter "*.ps1"

foreach ($file in $functionFiles) {
    . $file.FullName
}

Export-ModuleMember -Function @(
    "Get-BiosFirmwareInventory",
    "Get-CpuInventory",
    "Get-MemoryInventory",
    "Get-StorageInventory",
    "Get-TpmInventory",
    "Get-NetworkInventory",
    "Get-PeripheralInventory",
    "Get-SoftwareInventory",
    "Get-SecurityBaselineSnapshot",
    "Get-UserAccessAudit",
    "Invoke-FullHostAudit"
)
