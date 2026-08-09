@{
    RootModule           = 'EndpointGuard.ScanEngine.psm1'
    ModuleVersion        = '1.2.0'
    GUID                 = 'e9c5f884-1d89-4a0e-9276-8e541b68a9df'
    Author               = 'EndpointGuard Security Engineering'
    CompanyName          = 'EndpointGuard'
    Copyright            = '(c) 2026 EndpointGuard. All rights reserved.'
    Description          = 'Agentless Hardware, Firmware, Security Posture, and Identity Audit Engine for Windows 11 & Windows Server.'
    PowerShellVersion    = '5.1'
    FunctionsToExport    = @(
        'Get-BiosFirmwareInventory',
        'Get-CpuInventory',
        'Get-MemoryInventory',
        'Get-StorageInventory',
        'Get-TpmInventory',
        'Get-NetworkInventory',
        'Get-PeripheralInventory',
        'Get-SoftwareInventory',
        'Get-SecurityBaselineSnapshot',
        'Get-UserAccessAudit',
        'Invoke-FullHostAudit'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
}
