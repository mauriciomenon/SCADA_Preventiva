# SCRIPT DE MANUTENCAO PREVENTIVA - SSP - AMBIENTE SCADA
# Versão: 1.0 - Baseado no NMR5_Baseline_v9.0 + COMISSIONAMENTO DA SOPHO/STH
# Autor: Mauricio Menon             25/06/2025
#
# Compatível com PowerShell 5.1+ e PowerShell 7+

param(
    [ValidateSet("localhost", "ems", "pds", "custom")]
    [string]$Environment = "localhost",
    [string]$TargetComputer = "localhost",
    [string]$OutputBasePath = "",
    [switch]$ParallelExecution = $false,
    [int]$MaxParallelJobs = 5,
    [int]$ConnectionTimeout = 3000,
    [int]$MaxRetries = 3
)

# Configurações
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Listas de sistemas por ambiente
$EMSConsoleList = @('bitcon1', 'bitcon2', 'bitcon3', 'bitcon4', 'bitcon5', 'bitcon6', 'bitcon7', 'bitcon8', 'bitcon9', 'bitcon10', 'bitcon11', 'bitcon12', 'bitcon13', 'bitcon14', 'bitcon15', 'bitcon16', 'bitcon17', 'bitcon18', 'bitcon19', 'bitcon20', 'bitcon21', 'bitcon22', 'bitcon23', 'bitcon24', 'bitcon25', 'bitcon26', 'bitcon27', 'bitcon28', 'bitcon29', 'bitcon30', 'bitdtcon1', 'bitdtcon2', 'bitdtcon3', 'bitdtcon4', 'bitdtcon5', 'bitdtcon6', 'bitdtvaps1')
$EMSServerList = @('bitora1', 'bitora2', 'bithis1', 'bithis2', 'bitood1', 'bitood2', 'bitaps1', 'bitaps2', 'biticcp1', 'biticcp2', 'bitdmc1', 'bitdmc2', 'bitpcu1', 'bitpcu2', 'bitims1', 'bitims2', 'bitdtaps1')
$PDSConsoleList = @('bitpdcon1', 'bitpdcon2', 'bitpdcon3', 'bitpdcon4')
$PDSServerList = @('bitpdaps1', 'bitpdvaps1', 'bitpdpcu1', 'bitpdora1', 'bitpdviccp1', 'bitpdvhis1')

# Função para limpar variáveis
function Clear-AllVariable {
    $variables = Get-Variable -Scope Global -Exclude PWD, OLDPWD
    $variables | ForEach-Object {
        if ($_.Options -ne "Constant" -and $_.Options -ne "ReadOnly") {
            Set-Variable -Name $_.Name -Value $null -Force -ErrorAction SilentlyContinue
        }
    }
}

# Função para verificar privilégios
function Test-AdminPrivilege {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning 'Este script deve ser executado com privilégios de administrador para funcionalidades completas.'
    }
    else {
        Write-Host 'Privilégios administrativos confirmados.' -ForegroundColor Green
    }
    return $isAdmin
}

# Função para verificar versão do PowerShell
function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    $versionFlag = 0

    Write-Host "Versão do PowerShell: $psVersion" -ForegroundColor Cyan

    if ($psVersion.Major -eq 5 -and $psVersion.Minor -eq 1) {
        $versionFlag = 1
        Write-Host "PowerShell 5.1 detectado" -ForegroundColor Green
    }
    elseif ($psVersion.Major -gt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)) {
        $versionFlag = 2
        Write-Host "PowerShell $($psVersion.Major) detectado - Funcionalidades avançadas disponíveis" -ForegroundColor Green
    }
    else {
        Write-Error "Versão do PowerShell não suportada. Mínimo: 5.1"
        return $null
    }
    return $versionFlag
}

# Função para verificar versão do SO
function Test-OSVersion {
    try {
        $osVersion = (Get-CimInstance -ClassName CIM_OperatingSystem -ErrorAction Stop).Version
    }
    catch {
        $osVersion = (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop).Version
    }

    Write-Host "Versão do Windows: $osVersion" -ForegroundColor Cyan
    
    if ($osVersion -notmatch '6\.3|10\.0') {
        Write-Warning "Este script foi otimizado para Windows Server 2012 R2+ e Windows 10+. Alguns recursos podem não funcionar corretamente."
    }
    return $osVersion
}

# Função para obter ambiente
function Get-Environment {
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        $domain = $domain.ToLower()
        
        if ($domain -match 'ems') {
            return "EMS"
        }
        elseif ($domain -match 'pds') {
            return "PDS"
        }
        elseif ($domain -match 'itaipu') {
            return "LOCAL"
        }
    }
    
    # Fallback baseado no nome do computador
    $computerName = $env:COMPUTERNAME.ToLower()
    if ($computerName -match '^bit(con|ora|his|ood|aps|iccp|dmc|pcu|ims|dt)') {
        return "EMS"
    }
    elseif ($computerName -match '^bitpd') {
        return "PDS"
    }
    
    return "LOCAL"
}

# Função para obter lista de targets
function Get-TargetList {
    param ([string]$domain)

    $ConsoleList = @()
    $ServerList = @()

    switch ($domain) {
        'EMS' {
            $ConsoleList = $EMSConsoleList
            $ServerList = $EMSServerList
        }
        'PDS' {
            $ConsoleList = $PDSConsoleList
            $ServerList = $PDSServerList
        }
        'LOCAL' {
            $ConsoleList = @('localhost')
        }
        default {
            Write-Warning "Domínio $domain não reconhecido"
            return @()
        }
    }

    $targets = $ConsoleList + $ServerList
    return $targets
}

# Função Get-RemoteProgram
function Get-RemoteProgram {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [string[]]$Property = @('DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation'),
        [int]$TimeoutMs = 10000
    )

    begin {
        $RegistryLocation = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        )
    }

    process {
        foreach ($Computer in $ComputerName) {
            $Results = @()
            $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
            
            if ($isLocal) {
                Write-Verbose "Executando análise de software LOCAL"
                
                # MÉTODO 1: Registry local direto
                try {
                    foreach ($RegPath in $RegistryLocation) {
                        $FullPath = "HKLM:\$RegPath"
                        if (Test-Path $FullPath) {
                            Get-ChildItem -Path $FullPath -ErrorAction SilentlyContinue | ForEach-Object {
                                $RegKey = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                                if ($RegKey.DisplayName) {
                                    $HashProperty = [ordered]@{
                                        ComputerName = $Computer
                                        ProgramName  = $RegKey.DisplayName
                                    }
                                    
                                    foreach ($Prop in $Property) {
                                        $HashProperty[$Prop] = $RegKey.$Prop
                                    }
                                    
                                    $Results += [PSCustomObject]$HashProperty
                                }
                            }
                        }
                    }
                    Write-Verbose "Registry local: $($Results.Count) programas encontrados"
                }
                catch {
                    Write-Warning "Falha no Registry local: $($_.Exception.Message)"
                }
                
                # FALLBACK: WMIC local
                if ($Results.Count -eq 0) {
                    try {
                        Write-Verbose "Tentando WMIC local como fallback..."
                        $wmicOutput = cmd /c "wmic product get Name,Version,Vendor,InstallDate /format:csv 2>nul"
                        if ($wmicOutput -and $wmicOutput.Count -gt 2) {
                            $wmicOutput | Select-Object -Skip 1 | Where-Object { $_ -and $_ -notmatch "^Node" } | ForEach-Object {
                                $fields = $_ -split ','
                                if ($fields.Count -ge 4 -and $fields[2]) {
                                    $Results += [PSCustomObject]@{
                                        ComputerName    = $Computer
                                        ProgramName     = $fields[2].Trim()
                                        DisplayVersion  = if ($fields[4]) {
                                            $fields[4].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        Publisher       = if ($fields[3]) {
                                            $fields[3].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        InstallDate     = if ($fields[1]) {
                                            $fields[1].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        InstallLocation = ""
                                    }
                                }
                            }
                        }
                        Write-Verbose "WMIC local: $($Results.Count) programas encontrados"
                    }
                    catch {
                        Write-Warning "WMIC local falhou: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Verbose "Executando análise de software REMOTA para $Computer"
                
                # MÉTODO 1: Registry remoto
                try {
                    $socket = New-Object Net.Sockets.TcpClient
                    $socket.ReceiveTimeout = $TimeoutMs
                    $socket.SendTimeout = $TimeoutMs
                    
                    if ($socket.ConnectAsync($Computer, 445).Wait($TimeoutMs)) {
                        $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)
                        
                        foreach ($CurrentReg in $RegistryLocation) {
                            $CurrentRegKey = $null
                            try {
                                $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                                if ($CurrentRegKey) {
                                    $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                        $SubKey = $null
                                        try {
                                            $SubKey = $RegBase.OpenSubKey("$CurrentReg$_")
                                            $DisplayName = $SubKey.GetValue('DisplayName')
                                            
                                            if ($DisplayName) {
                                                $HashProperty = [ordered]@{
                                                    ComputerName = $Computer
                                                    ProgramName  = $DisplayName
                                                }
                                                
                                                foreach ($Prop in $Property) {
                                                    $HashProperty[$Prop] = $SubKey.GetValue($Prop)
                                                }
                                                
                                                $Results += [PSCustomObject]$HashProperty
                                            }
                                        }
                                        finally {
                                            if ($SubKey) {
                                                try {
                                                    $SubKey.Close() 
                                                }
                                                catch { 
                                                } 
                                            }
                                        }
                                    }
                                }
                            }
                            finally {
                                if ($CurrentRegKey) {
                                    try {
                                        $CurrentRegKey.Close() 
                                    }
                                    catch { 
                                    } 
                                }
                            }
                        }
                        $RegBase.Close()
                    }
                    $socket.Close()
                    Write-Verbose "Registry remoto: $($Results.Count) programas encontrados"
                }
                catch {
                    Write-Warning "Registry remoto falhou: $($_.Exception.Message)"
                }
                
                # FALLBACK: WMIC remoto
                if ($Results.Count -eq 0) {
                    try {
                        Write-Verbose "Tentando WMIC remoto como fallback..."
                        $wmicOutput = cmd /c "wmic /node:$Computer product get Name,Version,Vendor,InstallDate /format:csv 2>nul"
                        if ($wmicOutput -and $wmicOutput.Count -gt 2) {
                            $wmicOutput | Select-Object -Skip 1 | Where-Object { $_ -and $_ -notmatch "^Node" } | ForEach-Object {
                                $fields = $_ -split ','
                                if ($fields.Count -ge 4 -and $fields[2]) {
                                    $Results += [PSCustomObject]@{
                                        ComputerName    = $Computer
                                        ProgramName     = $fields[2].Trim()
                                        DisplayVersion  = if ($fields[4]) {
                                            $fields[4].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        Publisher       = if ($fields[3]) {
                                            $fields[3].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        InstallDate     = if ($fields[1]) {
                                            $fields[1].Trim() 
                                        }
                                        else {
                                            "" 
                                        }
                                        InstallLocation = ""
                                    }
                                }
                            }
                        }
                        Write-Verbose "WMIC remoto: $($Results.Count) programas encontrados"
                    }
                    catch {
                        Write-Warning "WMIC remoto falhou: $($_.Exception.Message)"
                    }
                }
            }
            
            return $Results
        }
    }
}

# Função para obter informações do sistema com fallbacks
function Get-SystemInformationComplete {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $Results = @{}
    
    Write-Host "Coletando informações do sistema $Computer..." -ForegroundColor Cyan
    
    # INFORMAÇÕES DO SO 
    Write-Host "  • Informações do Sistema Operacional..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            }
            catch {
                try {
                    $Results.OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                }
                catch {
                    $wmicOS = cmd /c "wmic os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $Results.OSInfo = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                    }
                }
            }
        }
        else {
            try {
                $Results.OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicOS = cmd /c "wmic /node:$Computer os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $Results.OSInfo = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter informações do SO: $($_.Exception.Message)"
    }

    # COMPUTER SYSTEM (wmic)
    Write-Host "  • Informações do Computer System..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            }
            catch {
                try {
                    $Results.ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                }
                catch {
                    $wmicCS = cmd /c "wmic computersystem get AdminPasswordStatus,AutomaticManagedPagefile,AutomaticResetBootOption,AutomaticResetCapability,BootOptionOnLimit,BootOptionOnWatchDog,BootROMSupported,BootStatus,BootupState,Caption,ChassisBootupState,ChassisSKUNumber,CreationClassName,CurrentTimeZone,DaylightInEffect,Description,DNSHostName,Domain,DomainRole,EnableDaylightSavingsTime,FrontPanelResetStatus,HypervisorPresent,InfraredSupported,InitialLoadInfo,InstallDate,KeyboardPasswordStatus,LastLoadInfo,Manufacturer,Model,Name,NameFormat,NetworkServerModeEnabled,NumberOfLogicalProcessors,NumberOfProcessors,OEMLogoBitmap,OEMStringArray,PartOfDomain,PauseAfterReset,PCSystemType,PCSystemTypeEx,PowerManagementCapabilities,PowerManagementSupported,PowerOnPasswordStatus,PowerState,PowerSupplyState,PrimaryOwnerContact,PrimaryOwnerName,ResetCapability,ResetCount,ResetLimit,Roles,Status,SupportContactDescription,SystemFamily,SystemSKUNumber,SystemStartupDelay,SystemStartupOptions,SystemStartupSetting,SystemType,ThermalState,TotalPhysicalMemory,UserName,WakeUpType,Workgroup /format:csv 2>nul"
                    if ($wmicCS) {
                        $Results.ComputerSystem = $wmicCS | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
        else {
            try {
                $Results.ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicCS = cmd /c "wmic /node:$Computer computersystem get AdminPasswordStatus,AutomaticManagedPagefile,AutomaticResetBootOption,AutomaticResetCapability,BootOptionOnLimit,BootOptionOnWatchDog,BootROMSupported,BootStatus,BootupState,Caption,ChassisBootupState,ChassisSKUNumber,CreationClassName,CurrentTimeZone,DaylightInEffect,Description,DNSHostName,Domain,DomainRole,EnableDaylightSavingsTime,FrontPanelResetStatus,HypervisorPresent,InfraredSupported,InitialLoadInfo,InstallDate,KeyboardPasswordStatus,LastLoadInfo,Manufacturer,Model,Name,NameFormat,NetworkServerModeEnabled,NumberOfLogicalProcessors,NumberOfProcessors,OEMLogoBitmap,OEMStringArray,PartOfDomain,PauseAfterReset,PCSystemType,PCSystemTypeEx,PowerManagementCapabilities,PowerManagementSupported,PowerOnPasswordStatus,PowerState,PowerSupplyState,PrimaryOwnerContact,PrimaryOwnerName,ResetCapability,ResetCount,ResetLimit,Roles,Status,SupportContactDescription,SystemFamily,SystemSKUNumber,SystemStartupDelay,SystemStartupOptions,SystemStartupSetting,SystemType,ThermalState,TotalPhysicalMemory,UserName,WakeUpType,Workgroup /format:csv 2>nul"
                    if ($wmicCS) {
                        $Results.ComputerSystem = $wmicCS | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Computer System: $($_.Exception.Message)"
    }

    # CPU (wmic)
    Write-Host "  • Informações do Processador..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.CPU = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
            }
            catch {
                try {
                    $Results.CPU = Get-WmiObject -Class Win32_Processor -ErrorAction Stop
                }
                catch {
                    $wmicCPU = cmd /c "wmic cpu get /format:csv 2>nul"
                    if ($wmicCPU) {
                        $Results.CPU = $wmicCPU | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
        else {
            try {
                $Results.CPU = Get-CimInstance -ClassName Win32_Processor -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.CPU = Get-WmiObject -Class Win32_Processor -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicCPU = cmd /c "wmic /node:$Computer cpu get /format:csv 2>nul"
                    if ($wmicCPU) {
                        $Results.CPU = $wmicCPU | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter CPU: $($_.Exception.Message)"
    }

    # MEMÓRIA FÍSICA (wmic)
    Write-Host "  • Informações de Memória..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.MemoryChip = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop
            }
            catch {
                try {
                    $Results.MemoryChip = Get-WmiObject -Class Win32_PhysicalMemory -ErrorAction Stop
                }
                catch {
                    $wmicMC = cmd /c "wmic memorychip get /format:csv 2>nul"
                    if ($wmicMC) {
                        $Results.MemoryChip = $wmicMC | ConvertFrom-Csv | Where-Object { $_.Capacity }
                    }
                }
            }
        }
        else {
            try {
                $Results.MemoryChip = Get-CimInstance -ClassName Win32_PhysicalMemory -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.MemoryChip = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicMC = cmd /c "wmic /node:$Computer memorychip get /format:csv 2>nul"
                    if ($wmicMC) {
                        $Results.MemoryChip = $wmicMC | ConvertFrom-Csv | Where-Object { $_.Capacity }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Memory Chip: $($_.Exception.Message)"
    }

    # LOGICAL DISKS (wmic)
    Write-Host "  • Informações de Discos..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop
            }
            catch {
                try {
                    $Results.LogicalDisks = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop
                }
                catch {
                    $wmicLD = cmd /c "wmic logicaldisk get /format:csv 2>nul"
                    if ($wmicLD) {
                        $Results.LogicalDisks = $wmicLD | ConvertFrom-Csv | Where-Object { $_.DeviceID }
                    }
                }
            }
        }
        else {
            try {
                $Results.LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.LogicalDisks = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicLD = cmd /c "wmic /node:$Computer logicaldisk get /format:csv 2>nul"
                    if ($wmicLD) {
                        $Results.LogicalDisks = $wmicLD | ConvertFrom-Csv | Where-Object { $_.DeviceID }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Logical Disks: $($_.Exception.Message)"
    }

    # SERVIÇOS
    Write-Host "  • Informações de Serviços..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.Services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
            }
            catch {
                try {
                    $Results.Services = Get-WmiObject -Class Win32_Service -ErrorAction Stop
                }
                catch {
                    $wmicServices = cmd /c "wmic service get Name,Caption,State,StartMode,PathName,StartName,ProcessId,ServiceType /format:csv 2>nul"
                    if ($wmicServices) {
                        $Results.Services = $wmicServices | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
        else {
            try {
                $Results.Services = Get-CimInstance -ClassName Win32_Service -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.Services = Get-WmiObject -Class Win32_Service -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicServices = cmd /c "wmic /node:$Computer service get Name,Caption,State,StartMode,PathName,StartName,ProcessId,ServiceType /format:csv 2>nul"
                    if ($wmicServices) {
                        $Results.Services = $wmicServices | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Services: $($_.Exception.Message)"
    }

    # PROCESSOS COMPLETOS
    Write-Host "  • Informações de Processos..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.Processes = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
            }
            catch {
                try {
                    $Results.Processes = Get-WmiObject -Class Win32_Process -ErrorAction Stop
                }
                catch {
                    try {
                        $Results.Processes = Get-Process -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Falha em obter processos locais"
                    }
                }
            }
        }
        else {
            try {
                $Results.Processes = Get-CimInstance -ClassName Win32_Process -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.Processes = Get-WmiObject -Class Win32_Process -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    Write-Warning "Falha em obter processos remotos para $Computer"
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Processes: $($_.Exception.Message)"
    }

    # HOTFIXES
    Write-Host "  • Informações de Atualizações..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.HotFixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop
            }
            catch {
                try {
                    $Results.HotFixes = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop
                }
                catch {
                    try {
                        $Results.HotFixes = Get-HotFix -ErrorAction Stop
                    }
                    catch {
                        $wmicHF = cmd /c "wmic qfe get Description,FixComments,HotFixID,InstalledBy,InstalledOn,ServicePackInEffect /format:csv 2>nul"
                        if ($wmicHF) {
                            $Results.HotFixes = $wmicHF | ConvertFrom-Csv | Where-Object { $_.HotFixID }
                        }
                    }
                }
            }
        }
        else {
            try {
                $Results.HotFixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.HotFixes = Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicHF = cmd /c "wmic /node:$Computer qfe get Description,FixComments,HotFixID,InstalledBy,InstalledOn,ServicePackInEffect /format:csv 2>nul"
                    if ($wmicHF) {
                        $Results.HotFixes = $wmicHF | ConvertFrom-Csv | Where-Object { $_.HotFixID }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter HotFixes: $($_.Exception.Message)"
    }

    # BIOS
    Write-Host "  • Informações de BIOS..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
            }
            catch {
                try {
                    $Results.BIOS = Get-WmiObject -Class Win32_BIOS -ErrorAction Stop
                }
                catch {
                    $wmicBIOS = cmd /c "wmic bios get Manufacturer,Name,Version,Status,BIOSVERSION,Description,EmbeddedControllerMajorVersion,EmbeddedControllerMinorVersion,InstallDate,PrimaryBios,releasedate,serialnumber,smbiosbiosversion,SMBIOSMajorVersion,SMBIOSMinorVersion,SMBIOSPresent,SystemBiosMajorVersion,SystemBiosMinorVersion /format:csv 2>nul"
                    if ($wmicBIOS) {
                        $Results.BIOS = $wmicBIOS | ConvertFrom-Csv | Where-Object { $_.Manufacturer }
                    }
                }
            }
        }
        else {
            try {
                $Results.BIOS = Get-CimInstance -ClassName Win32_BIOS -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.BIOS = Get-WmiObject -Class Win32_BIOS -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicBIOS = cmd /c "wmic /node:$Computer bios get Manufacturer,Name,Version,Status,BIOSVERSION,Description,EmbeddedControllerMajorVersion,EmbeddedControllerMinorVersion,InstallDate,PrimaryBios,releasedate,serialnumber,smbiosbiosversion,SMBIOSMajorVersion,SMBIOSMinorVersion,SMBIOSPresent,SystemBiosMajorVersion,SystemBiosMinorVersion /format:csv 2>nul"
                    if ($wmicBIOS) {
                        $Results.BIOS = $wmicBIOS | ConvertFrom-Csv | Where-Object { $_.Manufacturer }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter BIOS: $($_.Exception.Message)"
    }

    # DRIVERS DE SISTEMA
    Write-Host "  • Informações de Drivers..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.SystemDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop
            }
            catch {
                try {
                    $Results.SystemDrivers = Get-WmiObject -Class Win32_SystemDriver -ErrorAction Stop
                }
                catch {
                    $wmicDrivers = cmd /c "wmic sysdriver get Name,DisplayName,State,StartMode,PathName,ServiceType,Status,Started /format:csv 2>nul"
                    if ($wmicDrivers) {
                        $Results.SystemDrivers = $wmicDrivers | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
        else {
            try {
                $Results.SystemDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ComputerName $Computer -ErrorAction Stop
            }
            catch {
                try {
                    $Results.SystemDrivers = Get-WmiObject -Class Win32_SystemDriver -ComputerName $Computer -ErrorAction Stop
                }
                catch {
                    $wmicDrivers = cmd /c "wmic /node:$Computer sysdriver get Name,DisplayName,State,StartMode,PathName,ServiceType,Status,Started /format:csv 2>nul"
                    if ($wmicDrivers) {
                        $Results.SystemDrivers = $wmicDrivers | ConvertFrom-Csv | Where-Object { $_.Name }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter System Drivers: $($_.Exception.Message)"
    }

    # PERFORMANCE-FOOTPRINT
    Write-Host "  • Informações de Performance..." -ForegroundColor White
    $Results.Performance = @{}
    
    # CPU Usage
    try {
        if ($isLocal) {
            $cpuUsage = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue
            if ($cpuUsage) {
                $Results.Performance.CPUUsage = ($cpuUsage.CounterSamples | Measure-Object -Property CookedValue -Average).Average
            }
        }
    }
    catch {
        Write-Verbose "Falha ao obter CPU usage: $($_.Exception.Message)"
    }
    
    # Memory Usage
    try {
        if ($Results.OSInfo) {
            $totalMemory = if ($Results.OSInfo.TotalVisibleMemorySize) {
                $Results.OSInfo.TotalVisibleMemorySize 
            }
            else {
                $Results.ComputerSystem.TotalPhysicalMemory / 1KB 
            }
            $freeMemory = if ($Results.OSInfo.FreePhysicalMemory) {
                $Results.OSInfo.FreePhysicalMemory 
            }
            else {
                0 
            }
            $usedMemory = $totalMemory - $freeMemory
            $Results.Performance.MemoryUsagePercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
            $Results.Performance.TotalMemoryGB = [math]::Round($totalMemory / 1MB, 2)
            $Results.Performance.FreeMemoryGB = [math]::Round($freeMemory / 1MB, 2)
            $Results.Performance.UsedMemoryGB = [math]::Round($usedMemory / 1MB, 2)
        }
    }
    catch {
        Write-Verbose "Falha ao calcular memory usage: $($_.Exception.Message)"
    }

    # CONEXÕES DE REDE
    Write-Host "  • Informações de Rede..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.NetworkConnections = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' }
            }
            catch {
                try {
                    $netstatOutput = netstat -an 2>$null
                    if ($netstatOutput) {
                        $Results.NetworkConnections = $netstatOutput | Where-Object { $_ -match "TCP|UDP" }
                    }
                }
                catch {
                    Write-Warning "Falha ao obter conexões de rede"
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter Network Connections: $($_.Exception.Message)"
    }

    # Salvar todos os dados coletados
    try {
        # Criar estrutura de pastas
        $targetPath = Join-Path $OutputPath $Computer
        $subFolders = @(
            "01_Software_Instalado",
            "02_ATUALIZACOES_SISTEMA", 
            "03_Servicos_Sistema",
            "04_PROCESSOS_SISTEMA",
            "05_INFORMACOES_SISTEMA",
            "06_HARDWARE_BIOS",
            "07_DRIVERS_SISTEMA",
            "08_PERFORMANCE_SISTEMA",
            "09_CONEXOES_REDE",
            "10_UTILIZACAO_DISCO",
            "11_LOGS_EVENTOS",
            "12_CONFIGURACOES_SEGURANCA",
            "13_INVENTARIO_HARDWARE",
            "14_RELATORIOS_CONSOLIDADOS"
        )
        
        foreach ($folder in $subFolders) {
            $folderPath = Join-Path $targetPath $folder
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
            }
        }

        Write-Host "  • Salvando dados coletados..." -ForegroundColor White

        # === SALVAR INFORMAÇÕES DO SO ===
        if ($Results.OSInfo) {
            $osPath = Join-Path $targetPath "05_INFORMACOES_SISTEMA"
            $Results.OSInfo | Export-Csv -Path (Join-Path $osPath "${Timestamp}_OS_INFO.csv") -NoTypeInformation -Encoding UTF8
            $Results.OSInfo | Format-List | Out-File -FilePath (Join-Path $osPath "${Timestamp}_OS_INFO.txt") -Encoding UTF8
        }

        # === SALVAR COMPUTER SYSTEM ===
        if ($Results.ComputerSystem) {
            $csPath = Join-Path $targetPath "05_INFORMACOES_SISTEMA"
            $Results.ComputerSystem | Export-Csv -Path (Join-Path $csPath "${Timestamp}_COMPUTER_SYSTEM.csv") -NoTypeInformation -Encoding UTF8
            $Results.ComputerSystem | Format-List | Out-File -FilePath (Join-Path $csPath "${Timestamp}_COMPUTER_SYSTEM.txt") -Encoding UTF8
        }

        # === SALVAR CPU ===
        if ($Results.CPU) {
            $cpuPath = Join-Path $targetPath "13_INVENTARIO_HARDWARE"
            $Results.CPU | Export-Csv -Path (Join-Path $cpuPath "${Timestamp}_CPU_INFO.csv") -NoTypeInformation -Encoding UTF8
            $Results.CPU | Format-List | Out-File -FilePath (Join-Path $cpuPath "${Timestamp}_CPU_INFO.txt") -Encoding UTF8
        }

        # === SALVAR MEMORY ===
        if ($Results.MemoryChip) {
            $memPath = Join-Path $targetPath "13_INVENTARIO_HARDWARE"
            $Results.MemoryChip | Export-Csv -Path (Join-Path $memPath "${Timestamp}_MEMORY_CHIPS.csv") -NoTypeInformation -Encoding UTF8
            $Results.MemoryChip | Format-List | Out-File -FilePath (Join-Path $memPath "${Timestamp}_MEMORY_CHIPS.txt") -Encoding UTF8
        }

        # === SALVAR LOGICAL DISKS ===
        if ($Results.LogicalDisks) {
            $diskPath = Join-Path $targetPath "10_UTILIZACAO_DISCO"
            $Results.LogicalDisks | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_LOGICAL_DISKS.csv") -NoTypeInformation -Encoding UTF8
            $Results.LogicalDisks | Format-List | Out-File -FilePath (Join-Path $diskPath "${Timestamp}_LOGICAL_DISKS.txt") -Encoding UTF8
        }

        # === SALVAR SERVIÇOS ===
        if ($Results.Services) {
            $svcPath = Join-Path $targetPath "03_SERVICOS_SISTEMA"
            $Results.Services | Export-Csv -Path (Join-Path $svcPath "${Timestamp}_SERVICES_COMPLETE.csv") -NoTypeInformation -Encoding UTF8
            $Results.Services | Sort-Object State, Name | Format-Table Name, DisplayName, State, StartMode, PathName -AutoSize | Out-File -FilePath (Join-Path $svcPath "${Timestamp}_SERVICES_COMPLETE.txt") -Encoding UTF8 -Width 200
        }

        # === SALVAR PROCESSOS COMPLETOS ===
        if ($Results.Processes) {
            $procPath = Join-Path $targetPath "04_PROCESSOS_SISTEMA"
            $Results.Processes | Export-Csv -Path (Join-Path $procPath "${Timestamp}_PROCESSES_COMPLETE.csv") -NoTypeInformation -Encoding UTF8
            
            # Relatório de processos com uso de recursos
            $processReport = @()
            foreach ($proc in $Results.Processes) {
                $processReport += [PSCustomObject]@{
                    ProcessName     = $proc.Name
                    ProcessId       = $proc.ProcessId
                    ParentProcessId = $proc.ParentProcessId
                    ExecutablePath  = $proc.ExecutablePath
                    CommandLine     = $proc.CommandLine
                    WorkingSetSize  = if ($proc.WorkingSetSize) {
                        [math]::Round($proc.WorkingSetSize / 1MB, 2) 
                    }
                    else {
                        0 
                    }
                    PageFileUsage   = if ($proc.PageFileUsage) {
                        [math]::Round($proc.PageFileUsage / 1MB, 2) 
                    }
                    else {
                        0 
                    }
                    CPUTime         = $proc.UserModeTime
                    ThreadCount     = $proc.ThreadCount
                    HandleCount     = $proc.HandleCount
                    CreationDate    = $proc.CreationDate
                }
            }
            
            $processReport | Sort-Object WorkingSetSize -Descending | Format-Table -AutoSize | Out-File -FilePath (Join-Path $procPath "${Timestamp}_PROCESSES_COMPLETE.txt") -Encoding UTF8 -Width 300
        }

        # === SALVAR HOTFIXES ===
        if ($Results.HotFixes) {
            $hfPath = Join-Path $targetPath "02_ATUALIZACOES_SISTEMA"
            $Results.HotFixes | Export-Csv -Path (Join-Path $hfPath "${Timestamp}_HOTFIXES_COMPLETE.csv") -NoTypeInformation -Encoding UTF8
            $Results.HotFixes | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledBy, InstalledOn -AutoSize | Out-File -FilePath (Join-Path $hfPath "${Timestamp}_HOTFIXES_COMPLETE.txt") -Encoding UTF8
        }

        # === SALVAR BIOS ===
        if ($Results.BIOS) {
            $biosPath = Join-Path $targetPath "06_HARDWARE_BIOS"
            $Results.BIOS | Export-Csv -Path (Join-Path $biosPath "${Timestamp}_BIOS_INFO.csv") -NoTypeInformation -Encoding UTF8
            $Results.BIOS | Format-List | Out-File -FilePath (Join-Path $biosPath "${Timestamp}_BIOS_INFO.txt") -Encoding UTF8
        }

        # === SALVAR DRIVERS ===
        if ($Results.SystemDrivers) {
            $drvPath = Join-Path $targetPath "07_DRIVERS_SISTEMA"
            $Results.SystemDrivers | Export-Csv -Path (Join-Path $drvPath "${Timestamp}_SYSTEM_DRIVERS.csv") -NoTypeInformation -Encoding UTF8
            $Results.SystemDrivers | Sort-Object State, Name | Format-Table Name, DisplayName, State, StartMode, PathName -AutoSize | Out-File -FilePath (Join-Path $drvPath "${Timestamp}_SYSTEM_DRIVERS.txt") -Encoding UTF8 -Width 200
        }

        # === SALVAR PERFORMANCE ===
        if ($Results.Performance) {
            $perfPath = Join-Path $targetPath "08_PERFORMANCE_SISTEMA"
            $Results.Performance | ConvertTo-Json | Out-File -FilePath (Join-Path $perfPath "${Timestamp}_PERFORMANCE_METRICS.json") -Encoding UTF8
            
            # Relatório de performance em formato legível
            $perfReport = @"
RELATÓRIO DE PERFORMANCE DO SISTEMA
===================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

UTILIZAÇÃO DE RECURSOS:
$(if ($Results.Performance.CPUUsage) { "• CPU Usage: $([math]::Round($Results.Performance.CPUUsage, 2))%" } else { "• CPU Usage: Não disponível" })
$(if ($Results.Performance.MemoryUsagePercent) { "• Memory Usage: $($Results.Performance.MemoryUsagePercent)%" } else { "• Memory Usage: Não disponível" })
$(if ($Results.Performance.TotalMemoryGB) { "• Total Memory: $($Results.Performance.TotalMemoryGB) GB" } else { "• Total Memory: Não disponível" })
$(if ($Results.Performance.FreeMemoryGB) { "• Free Memory: $($Results.Performance.FreeMemoryGB) GB" } else { "• Free Memory: Não disponível" })
$(if ($Results.Performance.UsedMemoryGB) { "• Used Memory: $($Results.Performance.UsedMemoryGB) GB" } else { "• Used Memory: Não disponível" })

FOOTPRINT DO SISTEMA:
• Total de Processos: $(if ($Results.Processes) { $Results.Processes.Count } else { "Não disponível" })
• Total de Serviços: $(if ($Results.Services) { $Results.Services.Count } else { "Não disponível" })
• Serviços Executando: $(if ($Results.Services) { ($Results.Services | Where-Object { $_.State -eq 'Running' }).Count } else { "Não disponível" })
• Total de Drivers: $(if ($Results.SystemDrivers) { $Results.SystemDrivers.Count } else { "Não disponível" })
• Drivers Carregados: $(if ($Results.SystemDrivers) { ($Results.SystemDrivers | Where-Object { $_.State -eq 'Running' }).Count } else { "Não disponível" })
"@
            $perfReport | Out-File -FilePath (Join-Path $perfPath "${Timestamp}_PERFORMANCE_REPORT.txt") -Encoding UTF8
        }

        # === SALVAR CONEXÕES DE REDE ===
        if ($Results.NetworkConnections) {
            $netPath = Join-Path $targetPath "09_CONEXOES_REDE"
            if ($Results.NetworkConnections -is [System.Array] -and $Results.NetworkConnections[0] -is [string]) {
                # Saída do netstat
                $Results.NetworkConnections | Out-File -FilePath (Join-Path $netPath "${Timestamp}_NETWORK_CONNECTIONS.txt") -Encoding UTF8
            }
            else {
                # Saída do Get-NetTCPConnection
                $Results.NetworkConnections | Export-Csv -Path (Join-Path $netPath "${Timestamp}_NETWORK_CONNECTIONS.csv") -NoTypeInformation -Encoding UTF8
                $Results.NetworkConnections | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -AutoSize | Out-File -FilePath (Join-Path $netPath "${Timestamp}_NETWORK_CONNECTIONS.txt") -Encoding UTF8
            }
        }

    }
    catch {
        Write-Warning "Erro ao salvar dados: $($_.Exception.Message)"
    }

    Write-Host "  Sistema analisado: $(if($Results.Services){$Results.Services.Count}else{0}) serviços, $(if($Results.Processes){$Results.Processes.Count}else{0}) processos, $(if($Results.HotFixes){$Results.HotFixes.Count}else{0}) atualizações" -ForegroundColor Green
    
    return $Results
}

# Função para análise de disco estilo WinDirStat
function Get-DiskUsageAnalysis {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    Write-Host "Analisando utilização de disco para $Computer..." -ForegroundColor Cyan
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $diskAnalysis = @()
    
    try {
        # Obter informações de discos
        if ($isLocal) {
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            }
            catch {
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            }
        }
        else {
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            }
            catch {
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
            }
        }
        
        foreach ($drive in $drives) {
            $totalGB = [math]::Round($drive.Size / 1GB, 2)
            $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $usedGB = [math]::Round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
            $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100, 1)
            
            # Criar barra visual de utilização
            $barLength = 50
            $filledLength = [math]::Round(($usedPercent / 100) * $barLength)
            $emptyLength = $barLength - $filledLength
            $visualBar = "[" + ("█" * $filledLength) + ("░" * $emptyLength) + "]"
            
            $diskAnalysis += [PSCustomObject]@{
                Drive       = $drive.DeviceID
                Label       = $drive.VolumeName
                TotalGB     = $totalGB
                UsedGB      = $usedGB
                FreeGB      = $freeGB
                UsedPercent = $usedPercent
                VisualBar   = "$visualBar $usedPercent%"
                FileSystem  = $drive.FileSystem
                Status      = if ($usedPercent -gt 90) {
                    "CRÍTICO" 
                }
                elseif ($usedPercent -gt 80) {
                    "ATENÇÃO" 
                }
                else {
                    "OK" 
                }
            }
        }
        
        # Análise de pasta raiz para simulação WinDirStat (somente local)
        $folderAnalysis = @()
        if ($isLocal -and $drives) {
            foreach ($drive in $drives) {
                try {
                    $drivePath = $drive.DeviceID + "\"
                    Write-Host "  • Analisando pastas do drive $($drive.DeviceID)..." -ForegroundColor White
                    
                    $folders = Get-ChildItem -Path $drivePath -Directory -ErrorAction SilentlyContinue | Select-Object -First 20
                    foreach ($folder in $folders) {
                        try {
                            $folderSize = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                            if ($folderSize -gt 0) {
                                $folderSizeGB = [math]::Round($folderSize / 1GB, 3)
                                $folderPercent = [math]::Round(($folderSize / $drive.Size) * 100, 2)
                                
                                # Criar mini-barra para pastas
                                $miniBarLength = 20
                                $miniFilledLength = [math]::Round(($folderPercent / 100) * $miniBarLength)
                                if ($miniFilledLength -lt 1 -and $folderPercent -gt 0) {
                                    $miniFilledLength = 1 
                                }
                                $miniEmptyLength = $miniBarLength - $miniFilledLength
                                $miniBar = "[" + ("█" * $miniFilledLength) + ("░" * $miniEmptyLength) + "]"
                                
                                $folderAnalysis += [PSCustomObject]@{
                                    Drive          = $drive.DeviceID
                                    FolderName     = $folder.Name
                                    FullPath       = $folder.FullName
                                    SizeGB         = $folderSizeGB
                                    PercentOfDrive = $folderPercent
                                    VisualBar      = "$miniBar $folderPercent%"
                                    FileCount      = (Get-ChildItem -Path $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Erro ao analisar pasta $($folder.FullName): $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-Warning "Erro ao analisar drive $($drive.DeviceID): $($_.Exception.Message)"
                }
            }
        }
        
        # Salvar análise
        $diskPath = Join-Path $OutputPath $Computer "10_UTILIZACAO_DISCO"
        
        # Relatório principal de discos
        $diskAnalysis | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_DISK_ANALYSIS.csv") -NoTypeInformation -Encoding UTF8
        
        # Relatório visual estilo WinDirStat
        $diskReport = @"
Análise de Utilização de Disco
==============================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

Resumo dos Drives:
"@
        
        foreach ($disk in $diskAnalysis) {
            $diskReport += @"

Drive $($disk.Drive) [$($disk.Label)]
$($disk.VisualBar)
Total: $($disk.TotalGB) GB | Usado: $($disk.UsedGB) GB | Livre: $($disk.FreeGB) GB
Status: $($disk.Status) | Sistema: $($disk.FileSystem)

"@
        }
        
        if ($folderAnalysis.Count -gt 0) {
            $diskReport += @"

Análise de Diretórios Principais:
=================================
"@
            
            $topFolders = $folderAnalysis | Sort-Object SizeGB -Descending | Select-Object -First 30
            foreach ($folder in $topFolders) {
                $diskReport += @"
$($folder.Drive) - $($folder.FolderName)
$($folder.VisualBar)
Tamanho: $($folder.SizeGB) GB ($($folder.PercentOfDrive)% do drive)
Arquivos: $($folder.FileCount)
Path: $($folder.FullPath)

"@
            }
        }
        
        $diskReport | Out-File -FilePath (Join-Path $diskPath "${Timestamp}_DISK_ANALYSIS_WINDIRSTAT.txt") -Encoding UTF8
        
        # CSV das pastas se disponível
        if ($folderAnalysis.Count -gt 0) {
            $folderAnalysis | Sort-Object SizeGB -Descending | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_FOLDER_ANALYSIS.csv") -NoTypeInformation -Encoding UTF8
        }
        
        Write-Host "  Análise de disco concluída" -ForegroundColor Green
        return $diskAnalysis
    }
    catch {
        Write-Warning "Erro na análise de disco para $Computer : $($_.Exception.Message)"
        return @()
    }
}

# Função para coleta de logs de eventos com tradução
function Get-EventLogAnalysis {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    Write-Host "Coletando logs de eventos críticos..." -ForegroundColor Cyan
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $eventAnalysis = @()
    
    # Dicionário de tradução de eventos críticos
    $eventTranslation = @{
        # System Events
        "1074" = "Sistema foi desligado pelo usuário"
        "1076" = "Sistema foi desligado inesperadamente"
        "6005" = "Serviço Event Log foi iniciado"
        "6006" = "Serviço Event Log foi parado"
        "6008" = "Desligamento inesperado do sistema"
        "6009" = "Versão do sistema operacional detectada"
        "6013" = "Tempo de atividade do sistema"
        "7001" = "Logon do usuário"
        "7002" = "Logoff do usuário"
        "7034" = "Serviço terminou inesperadamente"
        "7035" = "Serviço enviou controle de estado"
        "7036" = "Serviço entrou em estado parado/iniciado"
        
        # Security Events
        "4624" = "Logon bem-sucedido"
        "4625" = "Falha no logon"
        "4634" = "Logoff de conta"
        "4647" = "Logoff iniciado pelo usuário"
        "4648" = "Tentativa de logon com credenciais explícitas"
        "4672" = "Privilégios especiais atribuídos ao logon"
        "4720" = "Conta de usuário criada"
        "4726" = "Conta de usuário excluída"
        "4732" = "Membro adicionado ao grupo de segurança local"
        "4733" = "Membro removido do grupo de segurança local"
        "4740" = "Conta de usuário bloqueada"
        "4767" = "Conta de usuário desbloqueada"
        
        # Application Events
        "1000" = "Falha na aplicação"
        "1001" = "Relatório de erro do Windows"
        "1002" = "Travamento da aplicação"
        
        # BSOD e Kernel
        "41"   = "Sistema reiniciou sem desligar corretamente"
        # "1001" = "Erro crítico do sistema (BSOD)"
        # "6008" = "Desligamento inesperado anterior"
        
        # Disk Events
        "7"    = "Erro de dispositivo"
        "11"   = "Driver detectou erro no controlador"
        "51"   = "Erro de página no disco"
        
        # Network Events
        "4201" = "Adaptador de rede desconectado"
        "4202" = "Adaptador de rede conectado"
        
        # Hardware Events
        "6"    = "Driver carregado"
        "219"  = "Driver instalado com sucesso"
    }
    
    try {
        $logCategories = @("System", "Application", "Security")
        
        foreach ($logName in $logCategories) {
            Write-Host "  • Coletando eventos do log $logName..." -ForegroundColor White
            
            try {
                $events = @()
                
                if ($isLocal) {
                    $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue | 
                        Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Critical" -or $_.Id -in $eventTranslation.Keys }
                }
                else {
                    $events = Get-WinEvent -ComputerName $Computer -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue | 
                        Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Critical" -or $_.Id -in $eventTranslation.Keys }
                }
                
                foreach ($event in $events) {
                    $translatedDescription = if ($eventTranslation.ContainsKey($event.Id.ToString())) {
                        $eventTranslation[$event.Id.ToString()]
                    }
                    else {
                        $event.LevelDisplayName + " - " + $event.TaskDisplayName
                    }
                    
                    $eventAnalysis += [PSCustomObject]@{
                        LogName               = $logName
                        TimeCreated           = $event.TimeCreated
                        Id                    = $event.Id
                        Level                 = $event.LevelDisplayName
                        Source                = $event.ProviderName
                        TaskCategory          = $event.TaskDisplayName
                        Description           = $event.Message
                        TranslatedDescription = $translatedDescription
                        Computer              = $Computer
                        UserId                = $event.UserId
                        ProcessId             = $event.ProcessId
                        ThreadId              = $event.ThreadId
                        Severity              = switch ($event.LevelDisplayName) {
                            "Critical" {
                                "CRÍTICO" 
                            }
                            "Error" {
                                "ERRO" 
                            }
                            "Warning" {
                                "AVISO" 
                            }
                            default {
                                "INFO" 
                            }
                        }
                    }
                }
                
                Write-Host "    - Coletados $(($events | Measure-Object).Count) eventos de $logName" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Erro ao coletar eventos do log $logName : $($_.Exception.Message)"
            }
        }
        
        # Salvar logs de eventos
        $logPath = Join-Path $OutputPath $Computer "11_LOGS_EVENTOS"
        
        # CSV completo
        $eventAnalysis | Sort-Object TimeCreated -Descending | Export-Csv -Path (Join-Path $logPath "${Timestamp}_EVENT_LOGS_COMPLETE.csv") -NoTypeInformation -Encoding UTF8
        
        # Relatório traduzido e organizado
        $logReport = @"
ANÁLISE DE LOGS DE EVENTOS DO SISTEMA
=====================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de eventos coletados: $($eventAnalysis.Count)

EVENTOS CRÍTICOS (últimas 24 horas):
==================================
"@
        
        $criticalEvents = $eventAnalysis | Where-Object { $_.Level -eq "Critical" -and $_.TimeCreated -gt (Get-Date).AddDays(-1) } | Sort-Object TimeCreated -Descending | Select-Object -First 20
        if ($criticalEvents.Count -gt 0) {
            foreach ($event in $criticalEvents) {
                $logReport += @"

$($event.Severity) ID: $($event.Id) - $($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))
Fonte: $($event.Source)
Tradução: $($event.TranslatedDescription)
Descrição: $($event.Description -replace "`r`n", " " -replace "`n", " ")
---

"@
            }
        }
        else {
            $logReport += "`nNenhum evento crítico nas últimas 24 horas.`n"
        }
        
        $logReport += @"

ERROS MAIS FREQUENTES (últimos 7 dias):
=======================================
"@
        
        $frequentErrors = $eventAnalysis | Where-Object { $_.Level -eq "Error" -and $_.TimeCreated -gt (Get-Date).AddDays(-7) } | 
            Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
        
        foreach ($errorGroup in $frequentErrors) {
            $sampleEvent = ($eventAnalysis | Where-Object { $_.Id -eq $errorGroup.Name } | Select-Object -First 1)
            $logReport += @"

🟡 ID: $($errorGroup.Name) - Ocorrências: $($errorGroup.Count)
Tradução: $($sampleEvent.TranslatedDescription)
Fonte: $($sampleEvent.Source)
Última ocorrência: $($sampleEvent.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))
---

"@
        }
        
        $logReport += @"

RESUMO POR CATEGORIA:
====================
Sistema: $(($eventAnalysis | Where-Object { $_.LogName -eq "System" }).Count) eventos
Aplicação: $(($eventAnalysis | Where-Object { $_.LogName -eq "Application" }).Count) eventos
Segurança: $(($eventAnalysis | Where-Object { $_.LogName -eq "Security" }).Count) eventos

RESUMO POR SEVERIDADE:
=====================
Crítico: $(($eventAnalysis | Where-Object { $_.Level -eq "Critical" }).Count) eventos
Erro: $(($eventAnalysis | Where-Object { $_.Level -eq "Error" }).Count) eventos
Aviso: $(($eventAnalysis | Where-Object { $_.Level -eq "Warning" }).Count) eventos

EVENTOS DE SEGURANÇA RELEVANTES:
===============================
"@
        
        $securityEvents = $eventAnalysis | Where-Object { $_.LogName -eq "Security" -and $_.Id -in @("4624", "4625", "4720", "4726", "4740") } | 
            Sort-Object TimeCreated -Descending | Select-Object -First 15
        
        foreach ($secEvent in $securityEvents) {
            $logReport += @"
$($secEvent.Severity) ID: $($secEvent.Id) - $($secEvent.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))
Tradução: $($secEvent.TranslatedDescription)
---
"@
        }
        
        $logReport | Out-File -FilePath (Join-Path $logPath "${Timestamp}_EVENT_LOGS_TRANSLATED.txt") -Encoding UTF8
        
        # Relatório separado por categoria
        foreach ($logName in $logCategories) {
            $categoryEvents = $eventAnalysis | Where-Object { $_.LogName -eq $logName }
            if ($categoryEvents.Count -gt 0) {
                $categoryEvents | Sort-Object TimeCreated -Descending | 
                    Select-Object TimeCreated, Id, Level, Source, TranslatedDescription, Severity | 
                        Format-Table -AutoSize | 
                            Out-File -FilePath (Join-Path $logPath "${Timestamp}_EVENTS_$logName.txt") -Encoding UTF8 -Width 200
            }
        }
        
        Write-Host "  Logs de eventos coletados" -ForegroundColor Green
        return $eventAnalysis
    }
    catch {
        Write-Warning "Erro na análise de logs de eventos: $($_.Exception.Message)"
        return @()
    }
}

# Função para gerar relatório final consolidado e RICO
function New-ConsolidatedReport {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Domain,
        [string]$Timestamp,
        [hashtable]$SystemInfo,
        [array]$SoftwareList,
        [array]$DiskAnalysis,
        [array]$EventAnalysis
    )
    
    Write-Host "Gerando relatório consolidado..." -ForegroundColor Cyan
    
    try {
        $reportPath = Join-Path $OutputPath $Computer "14_RELATORIOS_CONSOLIDADOS"
        $finalReportPath = Join-Path $reportPath "RELATORIO_FINAL_$Computer.txt"
        
        # Calcular estatísticas avançadas
        $totalSoftware = if ($SoftwareList) {
            $SoftwareList.Count 
        }
        else {
            0 
        }
        $totalServices = if ($SystemInfo.Services) {
            $SystemInfo.Services.Count 
        }
        else {
            0 
        }
        $runningServices = if ($SystemInfo.Services) {
 ($SystemInfo.Services | Where-Object { $_.State -eq 'Running' }).Count 
        }
        else {
            0 
        }
        $totalProcesses = if ($SystemInfo.Processes) {
            $SystemInfo.Processes.Count 
        }
        else {
            0 
        }
        $totalDrivers = if ($SystemInfo.SystemDrivers) {
            $SystemInfo.SystemDrivers.Count 
        }
        else {
            0 
        }
        $loadedDrivers = if ($SystemInfo.SystemDrivers) {
 ($SystemInfo.SystemDrivers | Where-Object { $_.State -eq 'Running' }).Count 
        }
        else {
            0 
        }
        $totalUpdates = if ($SystemInfo.HotFixes) {
            $SystemInfo.HotFixes.Count 
        }
        else {
            0 
        }
        $criticalEvents = if ($EventAnalysis) {
 ($EventAnalysis | Where-Object { $_.Level -eq "Critical" -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }).Count 
        }
        else {
            0 
        }
        $errorEvents = if ($EventAnalysis) {
 ($EventAnalysis | Where-Object { $_.Level -eq "Error" -and $_.TimeCreated -gt (Get-Date).AddDays(-7) }).Count 
        }
        else {
            0 
        }
        
        # Identificar softwares que requerem atenção
        $suspiciousSoftware = @()
        if ($SoftwareList) {
            $keywords = @("eval", "trial", "demo", "crack", "keygen", "patch", "portable", "unknown")
            $suspiciousSoftware = $SoftwareList | Where-Object { 
                $name = $_.ProgramName.ToLower()
                $keywords | ForEach-Object { if ($name -match $_) {
                        $true 
                    } }
            }
        }
        
        # Analisar utilização de recursos
        $diskCritical = if ($DiskAnalysis) {
 ($DiskAnalysis | Where-Object { $_.UsedPercent -gt 90 }).Count 
        }
        else {
            0 
        }
        $diskWarning = if ($DiskAnalysis) {
 ($DiskAnalysis | Where-Object { $_.UsedPercent -gt 80 -and $_.UsedPercent -le 90 }).Count 
        }
        else {
            0 
        }
        
        # Score de saúde do sistema (0-100)
        $healthScore = 100
        if ($criticalEvents -gt 0) {
            $healthScore -= ($criticalEvents * 10) 
        }
        if ($errorEvents -gt 5) {
            $healthScore -= ($errorEvents * 2) 
        }
        if ($diskCritical -gt 0) {
            $healthScore -= ($diskCritical * 15) 
        }
        if ($diskWarning -gt 0) {
            $healthScore -= ($diskWarning * 5) 
        }
        if ($suspiciousSoftware.Count -gt 0) {
            $healthScore -= ($suspiciousSoftware.Count * 3) 
        }
        if ($healthScore -lt 0) {
            $healthScore = 0 
        }
        
        $healthStatus = switch ($healthScore) {
            { $_ -ge 90 } {
                "EXCELENTE" 
            }
            { $_ -ge 75 } {
                "BOM" 
            }
            { $_ -ge 60 } {
                "ATENÇÃO" 
            }
            { $_ -ge 40 } {
                "CRÍTICO" 
            }
            default {
                "FALHA CRÍTICA" 
            }
        }

        $consolidatedReport = @"
################################################################################
                    RELATÓRIO - SISTEMA SCADA
################################################################################

 INFORMAÇÕES GERAIS:
════════════════════════════════════════════════════════════════════════════════
Sistema Analisado: $Computer
Domínio/Ambiente: $Domain
Data/Hora da execucao: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Versão do Script: 4.0 - Baseado NMR5_Baseline v9.0 + SOPHO
Duração da Análise: $(((Get-Date) - $Global:AuditStartTime).ToString('hh\:mm\:ss'))

 STATUS GERAL DO SISTEMA:
════════════════════════════════════════════════════════════════════════════════
Score de Saúde: $healthScore/100 - $healthStatus
$(if ($SystemInfo.OSInfo) { "Sistema Operacional: $($SystemInfo.OSInfo.Caption) $($SystemInfo.OSInfo.Version)" } else { "Sistema Operacional: Não disponível" })
$(if ($SystemInfo.OSInfo -and $SystemInfo.OSInfo.LastBootUpTime) { "Último Boot: $($SystemInfo.OSInfo.LastBootUpTime)" } else { "Último Boot: Não disponível" })
$(if ($SystemInfo.ComputerSystem) { "Modelo: $($SystemInfo.ComputerSystem.Manufacturer) $($SystemInfo.ComputerSystem.Model)" } else { "Modelo: Não disponível" })
$(if ($SystemInfo.Performance -and $SystemInfo.Performance.TotalMemoryGB) { "Memória Total: $($SystemInfo.Performance.TotalMemoryGB) GB" } else { "Memória Total: Não disponível" })
$(if ($SystemInfo.CPU) { "Processador: $($SystemInfo.CPU[0].Name)" } else { "Processador: Não disponível" })

 RESUMO EXECUTIVO - INDICADORES TÉCNICOS:
════════════════════════════════════════════════════════════════════════════════
• Software Instalado: $totalSoftware programas
• Programas Suspeitos: $($suspiciousSoftware.Count) requerem verificação manual
• Serviços do Sistema: $totalServices ($runningServices executando)
• Processos em Execução: $totalProcesses
• Drivers do Sistema: $totalDrivers ($loadedDrivers carregados)
• Atualizações/Patches: $totalUpdates aplicadas
• Eventos Críticos (7 dias): $criticalEvents
• Eventos de Erro (7 dias): $errorEvents

 ANÁLISE DE ARMAZENAMENTO:
════════════════════════════════════════════════════════════════════════════════
"@

        if ($DiskAnalysis -and $DiskAnalysis.Count -gt 0) {
            foreach ($disk in $DiskAnalysis) {
                $consolidatedReport += @"
Drive $($disk.Drive) [$($disk.Label)] - $($disk.Status)
$($disk.VisualBar)
Total: $($disk.TotalGB) GB | Usado: $($disk.UsedGB) GB | Livre: $($disk.FreeGB) GB

"@
            }
        }
        else {
            $consolidatedReport += "Informações de disco não disponíveis`n"
        }

        $consolidatedReport += @"

 PERFORMANCE E RECURSOS:
════════════════════════════════════════════════════════════════════════════════
$(if ($SystemInfo.Performance.MemoryUsagePercent) { "• Uso de Memória: $($SystemInfo.Performance.MemoryUsagePercent)%" } else { "• Uso de Memória: Não disponível" })
$(if ($SystemInfo.Performance.CPUUsage) { "• Uso de CPU: $([math]::Round($SystemInfo.Performance.CPUUsage, 2))%" } else { "• Uso de CPU: Não disponível" })
$(if ($SystemInfo.Performance.UsedMemoryGB) { "• Memória Utilizada: $($SystemInfo.Performance.UsedMemoryGB) GB" } else { "• Memória Utilizada: Não disponível" })
$(if ($SystemInfo.Performance.FreeMemoryGB) { "• Memória Livre: $($SystemInfo.Performance.FreeMemoryGB) GB" } else { "• Memória Livre: Não disponível" })

 ANÁLISE DE SEGURANÇA E EVENTOS:
════════════════════════════════════════════════════════════════════════════════
"@

        if ($EventAnalysis -and $EventAnalysis.Count -gt 0) {
            $recentCritical = $EventAnalysis | Where-Object { $_.Level -eq "Critical" -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
            $recentErrors = $EventAnalysis | Where-Object { $_.Level -eq "Error" -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
            $securityEvents = $EventAnalysis | Where-Object { $_.LogName -eq "Security" -and $_.Id -in @("4624", "4625", "4740") -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
            
            $consolidatedReport += @"
• Eventos Críticos (24h): $($recentCritical.Count)
• Eventos de Erro (24h): $($recentErrors.Count)
• Eventos de Segurança (24h): $($securityEvents.Count)

ÚLTIMOS EVENTOS CRÍTICOS:
"@
            if ($recentCritical.Count -gt 0) {
                foreach ($event in ($recentCritical | Select-Object -First 5)) {
                    $consolidatedReport += @"
   $($event.TimeCreated.ToString('dd/MM HH:mm')) - ID:$($event.Id) - $($event.TranslatedDescription)
"@
                }
            }
            else {
                $consolidatedReport += @"
   Nenhum evento crítico nas últimas 24 horas
"@
            }
        }
        else {
            $consolidatedReport += "Análise de eventos não disponível`n"
        }

        $consolidatedReport += @"

 ANÁLISE DE SOFTWARE:
════════════════════════════════════════════════════════════════════════════════
"@

        if ($suspiciousSoftware.Count -gt 0) {
            $consolidatedReport += "⚠️  PROGRAMAS QUE REQUEREM VERIFICAÇÃO MANUAL:`n"
            foreach ($software in ($suspiciousSoftware | Select-Object -First 10)) {
                $consolidatedReport += "  • $($software.ProgramName) - $($software.Publisher)`n"
            }
        }
        else {
            $consolidatedReport += " Nenhum software suspeito identificado`n"
        }

        # Top 10 softwares por instalação recente (se disponível)
        if ($SoftwareList) {
            $recentSoftware = $SoftwareList | Where-Object { $_.InstallDate } | Sort-Object InstallDate -Descending | Select-Object -First 10
            if ($recentSoftware.Count -gt 0) {
                $consolidatedReport += @"

SOFTWARES INSTALADOS RECENTEMENTE:
"@
                foreach ($software in $recentSoftware) {
                    $consolidatedReport += "  • $($software.ProgramName) - $(if ($software.InstallDate) { $software.InstallDate } else { 'Data não disponível' })`n"
                }
            }
        }

        $consolidatedReport += @"

 SERVIÇOS E PROCESSOS CRÍTICOS:
════════════════════════════════════════════════════════════════════════════════
"@

        if ($SystemInfo.Services) {
            $stoppedCriticalServices = $SystemInfo.Services | Where-Object { 
                $_.State -eq "Stopped" -and 
                $_.StartMode -eq "Automatic" -and 
                $_.Name -match "Windows|System|Security|Network|SQL|IIS|Apache|SCADA"
            }
            
            if ($stoppedCriticalServices.Count -gt 0) {
                $consolidatedReport += "  SERVIÇOS CRÍTICOS PARADOS:`n"
                foreach ($service in ($stoppedCriticalServices | Select-Object -First 10)) {
                    $consolidatedReport += "  • $($service.DisplayName) ($($service.Name)) - Estado: $($service.State)`n"
                }
            }
            else {
                $consolidatedReport += " Todos os serviços críticos estão executando`n"
            }
        }

        $consolidatedReport += @"

 CONECTIVIDADE E REDE:
════════════════════════════════════════════════════════════════════════════════
"@

        if ($SystemInfo.NetworkConnections) {
            $establishedConnections = if ($SystemInfo.NetworkConnections -is [System.Array] -and $SystemInfo.NetworkConnections[0] -is [string]) {
                ($SystemInfo.NetworkConnections | Where-Object { $_ -match "ESTABLISHED" }).Count
            }
            else {
                ($SystemInfo.NetworkConnections | Where-Object { $_.State -eq "Established" }).Count
            }
            
            $listeningPorts = if ($SystemInfo.NetworkConnections -is [System.Array] -and $SystemInfo.NetworkConnections[0] -is [string]) {
                ($SystemInfo.NetworkConnections | Where-Object { $_ -match "LISTENING" }).Count
            }
            else {
                ($SystemInfo.NetworkConnections | Where-Object { $_.State -eq "Listen" }).Count
            }
            
            $consolidatedReport += @"
• Conexões Estabelecidas: $establishedConnections
• Portas em Escuta: $listeningPorts
• Total de Conexões Analisadas: $(if ($SystemInfo.NetworkConnections) { $SystemInfo.NetworkConnections.Count } else { 0 })
"@
        }
        else {
            $consolidatedReport += "Informações de rede não disponíveis`n"
        }

        $consolidatedReport += @"

################################################################################
                              RECOMENDAÇÕES TÉCNICAS
################################################################################
"@

        $recommendations = @()
        
        if ($suspiciousSoftware.Count -gt 0) {
            $recommendations += "🔍 ALTA PRIORIDADE: Revisar e validar $($suspiciousSoftware.Count) programas identificados para verificação manual"
        }
        
        if ($diskCritical -gt 0) {
            $recommendations += "💾 URGENTE: $diskCritical drive(s) com utilização crítica (>90%) - Liberar espaço imediatamente"
        }
        
        if ($diskWarning -gt 0) {
            $recommendations += "💾 ATENÇÃO: $diskWarning drive(s) com utilização em atenção (>80%) - Monitorar crescimento"
        }
        
        if ($criticalEvents -gt 0) {
            $recommendations += "🚨 CRÍTICO: $criticalEvents eventos críticos registrados nos últimos 7 dias - Investigar causas"
        }
        
        if ($errorEvents -gt 10) {
            $recommendations += "⚠️ ATENÇÃO: Alto número de eventos de erro ($errorEvents) - Revisar logs detalhados"
        }
        
        if ($SystemInfo.Services) {
            $stoppedAuto = ($SystemInfo.Services | Where-Object { $_.State -eq "Stopped" -and $_.StartMode -eq "Automatic" }).Count
            if ($stoppedAuto -gt 0) {
                $recommendations += "🔧 VERIFICAR: $stoppedAuto serviços automáticos estão parados - Validar se é intencional"
            }
        }
        
        if ($SystemInfo.Performance.MemoryUsagePercent -and $SystemInfo.Performance.MemoryUsagePercent -gt 85) {
            $recommendations += "🧠 PERFORMANCE: Uso de memória acima de 85% - Considerar otimização ou upgrade"
        }
        
        # Recomendações de segurança baseadas nos eventos
        if ($EventAnalysis) {
            $failedLogons = ($EventAnalysis | Where-Object { $_.Id -eq "4625" -and $_.TimeCreated -gt (Get-Date).AddDays(-1) }).Count
            if ($failedLogons -gt 5) {
                $recommendations += "🔐 SEGURANÇA: $failedLogons tentativas de logon falharam nas últimas 24h - Verificar possível ataque"
            }
        }
        
        # Adicionar recomendações padrão
        $recommendations += " MANUTENÇÃO: Implementar monitoramento contínuo dos sistemas críticos"
        $recommendations += " ATUALIZAÇÃO: Verificar e aplicar atualizações de segurança pendentes"
        $recommendations += " OTIMIZAÇÃO: Analisar processos com alto consumo de recursos"
        $recommendations += " CONFIGURAÇÃO: Validar configurações de hardware e BIOS"
        $recommendations += " BASELINE: Estabelecer baseline de performance para monitoramento futuro"
        
        for ($i = 0; $i -lt $recommendations.Count; $i++) {
            $consolidatedReport += "$($i + 1). $($recommendations[$i])`n"
        }

        $consolidatedReport += @"

################################################################################
                           INFORMAÇÕES TÉCNICAS
################################################################################
Data do Relatório: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')

SCRIPT DE MANUTENCAO PREVENTIVA - SSP - AMBIENTE SCADA
Versão: 1.0 - Baseado no NMR5_Baseline_v9.0 + COMISSIONAMENTO DA SOPHO/STH
Autor: Mauricio Menon             25/06/2025

Compatibilidade: PowerShell 5.1+ / PowerShell 7+ / Windows Server 2012 R2+ / Windows 10+
Métodos de Coleta: CIM + WMI + WMIC + Registry + Comandos Nativos
Scope de Análise: Sistema + Performance + Segurança + Inventário

 ESTRUTURA DE ARQUIVOS GERADOS:
$(Join-Path $OutputPath $Computer)
├── 01_SOFTWARE_INSTALADO\          │ Inventário de software
├── 02_ATUALIZACOES_SISTEMA\        │ Patches e hotfixes instalados  
├── 03_SERVICOS_SISTEMA\            │ Serviços do Windows
├── 04_PROCESSOS_SISTEMA\           │ Processos em execução
├── 05_INFORMACOES_SISTEMA\         │ Informações gerais do SO
├── 06_HARDWARE_BIOS\               │ Informações de hardware e BIOS
├── 07_DRIVERS_SISTEMA\             │ Drivers instalados
├── 08_PERFORMANCE_SISTEMA\         │ Métricas de performance
├── 09_CONEXOES_REDE\               │ Conexões de rede ativas
├── 10_UTILIZACAO_DISCO\            │ Análise de uso de disco
├── 11_LOGS_EVENTOS\                │ Logs de eventos traduzidos
├── 12_CONFIGURACOES_SEGURANCA\     │ Configurações de segurança
├── 13_INVENTARIO_HARDWARE\         │ Inventário detalhado de hardware
└── 14_RELATORIOS_CONSOLIDADOS\     │ Relatórios finais e resumos

🏷️ CONVENÇÃO DE NOMENCLATURA DOS ARQUIVOS:
YYYYMMDDHHMMSS_NOME_DO_ARQUIVO.ext (ex: $(Get-Date -Format 'yyyyMMddHHmmss')_SOFTWARE_INSTALADO.csv)

################################################################################
                                   EOF
################################################################################
"@

        # Salvar relatório final
        $consolidatedReport | Out-File -FilePath $finalReportPath -Encoding UTF8
        
        # Salvar também uma versão JSON para processamento automatizado
        $reportData = @{
            Computer           = $Computer
            Domain             = $Domain
            Timestamp          = $Timestamp
            HealthScore        = $healthScore
            HealthStatus       = $healthStatus
            TotalSoftware      = $totalSoftware
            SuspiciousSoftware = $suspiciousSoftware.Count
            TotalServices      = $totalServices
            RunningServices    = $runningServices
            TotalProcesses     = $totalProcesses
            TotalDrivers       = $totalDrivers
            TotalUpdates       = $totalUpdates
            CriticalEvents     = $criticalEvents
            ErrorEvents        = $errorEvents
            DiskCritical       = $diskCritical
            DiskWarning        = $diskWarning
            Recommendations    = $recommendations
        }
        
        $reportData | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $reportPath "${Timestamp}_AUDIT_SUMMARY.json") -Encoding UTF8
        
        Write-Host "Relatório consolidado gerado: $finalReportPath" -ForegroundColor Green
        return $finalReportPath
    }
    catch {
        Write-Error "Erro ao gerar relatório consolidado: $($_.Exception.Message)"
        return $null
    }
}

# Função principal do Levantamento
function Start-SystemAudit {
    param(
        [string]$Computer = "localhost",
        [string]$OutputBasePath = "",
        [string]$Domain = ""
    )
    
    $Global:AuditStartTime = Get-Date
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    
    Write-Host " "  -ForegroundColor Cyan
    Write-Host "INICIANDO MANUTENÇÃO PREVENTIVA" -ForegroundColor Cyan
    Write-Host " "  -ForegroundColor Cyan
    
    try {
        # Configurar caminhos
        if (-not $OutputBasePath) {
            $OutputBasePath = Join-Path $PSScriptRoot $Domain
        }
        
        $targetPath = Join-Path $OutputBasePath $Computer
        
        # Verificar se existe pasta anterior e perguntar sobre exclusão
        if (Test-Path $targetPath) {
            Write-Host "Pasta de resultados anterior encontrada: $targetPath" -ForegroundColor White
            $response = Read-Host "Deseja apagar os resultados anteriores? (N/s)"
            if ($response -eq 's' -or $response -eq 'S' -or $response -eq 'sim' -or $response -eq 'SIM') {
                Write-Host "Removendo resultados anteriores..." -ForegroundColor White
                Remove-Item -Path $targetPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Resultados anteriores removidos." -ForegroundColor Green
            }
        }
        
        # Criar estrutura de pastas
        $subFolders = @(
            "01_SOFTWARE_INSTALADO",
            "02_ATUALIZACOES_SISTEMA", 
            "03_SERVICOS_SISTEMA",
            "04_PROCESSOS_SISTEMA",
            "05_INFORMACOES_SISTEMA",
            "06_HARDWARE_BIOS",
            "07_DRIVERS_SISTEMA",
            "08_PERFORMANCE_SISTEMA",
            "09_CONEXOES_REDE",
            "10_UTILIZACAO_DISCO",
            "11_LOGS_EVENTOS",
            "12_CONFIGURACOES_SEGURANCA",
            "13_INVENTARIO_HARDWARE",
            "14_RELATORIOS_CONSOLIDADOS"
        )
        
        foreach ($folder in $subFolders) {
            $folderPath = Join-Path $targetPath $folder
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
            }
        }
        
        # Iniciar transcript
        $logFile = Join-Path $targetPath "14_RELATORIOS_CONSOLIDADOS\LOG_LEVANTAMENTO_${timestamp}.txt"
        Start-Transcript -Path $logFile -Append
        
        Write-Host "1. Executando inventário de software instalado..." -ForegroundColor White
        $softwareList = Get-RemoteProgram -ComputerName $Computer
        
        if ($softwareList -and $softwareList.Count -gt 0) {
            # Salvar lista de software
            $softwarePath = Join-Path $targetPath "01_SOFTWARE_INSTALADO"
            $softwareList | Export-Csv -Path (Join-Path $softwarePath "${timestamp}_SOFTWARE_INSTALADO_COMPLETO.csv") -NoTypeInformation -Encoding UTF8
            $softwareList | Sort-Object ProgramName | Format-Table ProgramName, DisplayVersion, Publisher, InstallDate -AutoSize | Out-File -FilePath (Join-Path $softwarePath "${timestamp}_SOFTWARE_INSTALADO_COMPLETO.txt") -Encoding UTF8 -Width 300
            
            # Identificar softwares suspeitos
            $keywords = @("eval", "trial", "demo", "crack", "keygen", "patch", "portable", "unknown")
            $suspiciousSoftware = $softwareList | Where-Object { 
                $name = $_.ProgramName.ToLower()
                $keywords | ForEach-Object { if ($name -match $_) {
                        return $true 
                    } }
            }
            
            if ($suspiciousSoftware.Count -gt 0) {
                $suspiciousSoftware | Export-Csv -Path (Join-Path $softwarePath "${timestamp}_SOFTWARE_SUSPEITO.csv") -NoTypeInformation -Encoding UTF8
            }
            
            Write-Host "   Software analisado: $($softwareList.Count) programas, $($suspiciousSoftware.Count) requerem verificação" -ForegroundColor Green
        }
        else {
            Write-Warning "Nenhum software detectado ou erro na coleta"
            $softwareList = @()
        }
        
        Write-Host "2. Coletando informações do sistema..." -ForegroundColor White
        $systemInfo = Get-SystemInformationComplete -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
        
        Write-Host "3. Executando análise detalhada de utilização de disco..." -ForegroundColor White
        $diskAnalysis = Get-DiskUsageAnalysis -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
        
        Write-Host "4. Coletando informações de performance..." -ForegroundColor White
        # A performance já foi coletada no Get-SystemInformationComplete
        if ($systemInfo.Performance) {
            Write-Host "   Performance coletada: CPU, Memória, Footprint do sistema" -ForegroundColor Green
        }
        else {
            Write-Warning "Informações de performance limitadas"
        }
        
        Write-Host "5. Analisando conexões de rede..." -ForegroundColor White
        # As conexões já foram coletadas no Get-SystemInformationComplete
        if ($systemInfo.NetworkConnections) {
            $connectionCount = if ($systemInfo.NetworkConnections -is [System.Array]) {
                $systemInfo.NetworkConnections.Count 
            }
            else {
                1 
            }
            Write-Host "   Conexões de rede analisadas: $connectionCount conexões" -ForegroundColor Green
        }
        else {
            Write-Warning "Informações de rede limitadas"
        }
        
        Write-Host "6. Coletando logs de eventos críticos..." -ForegroundColor White
        $eventAnalysis = Get-EventLogAnalysis -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
        
        if ($eventAnalysis -and $eventAnalysis.Count -gt 0) {
            Write-Host "   Logs de eventos coletados: $($eventAnalysis.Count) eventos analisados" -ForegroundColor Green
        }
        else {
            Write-Warning "Logs de eventos limitados"
            $eventAnalysis = @()
        }
        
        # Gerar relatório consolidado
        Write-Host "7. Gerando relatório consolidado..." -ForegroundColor White
        $finalReport = New-ConsolidatedReport -Computer $Computer -OutputPath $OutputBasePath -Domain $Domain -Timestamp $timestamp -SystemInfo $systemInfo -SoftwareList $softwareList -DiskAnalysis $diskAnalysis -EventAnalysis $eventAnalysis
        
        Stop-Transcript
        
        Write-Host " "  -ForegroundColor Green 
        Write-Host "Levantamento Concluído com Sucesso" -ForegroundColor Green
        Write-Host " "  -ForegroundColor Green 
        
        # Resumo
        Write-Host "Sistema analisado: $Computer" -ForegroundColor Cyan
        Write-Host "Domínio: $Domain" -ForegroundColor Cyan
        Write-Host "Estrutura: $OutputBasePath\$Computer\" -ForegroundColor Cyan
        Write-Host "Relatórios salvos em: $targetPath" -ForegroundColor Cyan
        
        Write-Host " "  -ForegroundColor Cyan
        Write-Host "RESUMO DOS INDICADORES TÉCNICOS:" -ForegroundColor Cyan
        Write-Host "• Software instalado: $(if ($softwareList) { $softwareList.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Programas para verificação: $(if ($softwareList) { ($softwareList | Where-Object { $name = $_.ProgramName.ToLower(); @('eval', 'trial', 'demo', 'crack', 'keygen', 'patch', 'portable', 'unknown') | ForEach-Object { if ($name -match $_) { return $true } } }).Count } else { 0 })" -ForegroundColor White
        Write-Host "• Serviços do sistema: $(if ($systemInfo.Services) { $systemInfo.Services.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Processos em execução: $(if ($systemInfo.Processes) { $systemInfo.Processes.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Atualizações aplicadas: $(if ($systemInfo.HotFixes) { $systemInfo.HotFixes.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Drivers analisados: $(if ($systemInfo.SystemDrivers) { $systemInfo.SystemDrivers.Count } else { 0 })" -ForegroundColor White
        
        $suspiciousCount = if ($softwareList) {
 ($softwareList | Where-Object { $name = $_.ProgramName.ToLower(); @('eval', 'trial', 'demo', 'crack', 'keygen', 'patch', 'portable', 'unknown') | ForEach-Object { if ($name -match $_) {
                        return $true 
                    } } }).Count 
        }
        else {
            0 
        }
        if ($suspiciousCount -gt 0) {
            Write-Host "RECOMENDAÇÃO: Revisar $suspiciousCount programas identificados para verificação manual." -ForegroundColor Yellow
        }
        
        Write-Host "ESTRUTURA DE PASTAS GERADA:" -ForegroundColor Cyan
        Write-Host "   $OutputBasePath\" -ForegroundColor White
        Write-Host "   └── $Computer\" -ForegroundColor White
        foreach ($folder in $subFolders) {
            Write-Host "       ├── $folder\" -ForegroundColor Gray
        }
        
        Write-Host " "  -ForegroundColor Green 
        
        return @{
            Success         = $true
            Computer        = $Computer
            Domain          = $Domain
            OutputPath      = $targetPath
            FinalReport     = $finalReport
            SoftwareCount   = if ($softwareList) {
                $softwareList.Count 
            }
            else {
                0 
            }
            SuspiciousCount = $suspiciousCount
            SystemInfo      = $systemInfo
            DiskAnalysis    = $diskAnalysis
            EventAnalysis   = $eventAnalysis
        }
        
    }
    catch {
        Write-Error "Erro durante o levantamento: $($_.Exception.Message)"
        try {
            Stop-Transcript 
        }
        catch { 
        }
        return @{
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}

# Função principal que coordena todo o processo
function Start-IndustrialAudit {
    param(
        [string]$Environment = "",
        [string]$TargetComputer = "",
        [string]$OutputPath = "",
        [switch]$AllSystems = $false
    )
    
    # Limpar variáveis
    Clear-AllVariable
    
    # Verificações iniciais
    Write-Host "SCRIPT DE MANUTENCAO PREVENTIVA - SSP - AMBIENTE SCADA" -ForegroundColor Cyan
    Write-Host "Versão: 1.0 - Baseado no NMR5_Baseline_v9.0 + COMISSIONAMENTO DA SOPHO/STH" -ForegroundColor Cyan
    Write-Host "Autor: Mauricio Menon             25/06/2025" -ForegroundColor Cyan
    Write-Host " "  -ForegroundColor Cyan

   
    # Verificar privilégios
    $isAdmin = Test-AdminPrivilege
    
    # Verificar versão do PowerShell
    $psVersion = Test-PowerShellVersion
    if (-not $psVersion) {
        Write-Error "Versão do PowerShell incompatível. Saindo..."
        return
    }
    
    # Verificar versão do SO
    $osVersion = Test-OSVersion
    
    # Determinar ambiente se não especificado
    if (-not $Environment) {
        $Environment = Get-Environment
    }
    
    # Determinar target se não especificado
    if (-not $TargetComputer) {
        if ($AllSystems) {
            $targets = Get-TargetList -domain $Environment
        }
        else {
            $targets = @("localhost")
        }
    }
    else {
        $targets = @($TargetComputer)
    }
    
    # Configurar caminho de saída
    if (-not $OutputPath) {
        $OutputPath = Join-Path $PSScriptRoot $Environment
    }
    
    Write-Host "Ambiente detectado: $Environment" -ForegroundColor Green
    Write-Host "Sistemas a auditar: $($targets -join ', ')" -ForegroundColor Green
    Write-Host "Caminho de saída: $OutputPath" -ForegroundColor Green
    Write-Host " "  -ForegroundColor Cyan
    
    # Executar levantamento para cada sistema
    $results = @()
    foreach ($target in $targets) {
        Write-Host "Iniciando levantamento para: $target" -ForegroundColor White
        $result = Start-SystemAudit -Computer $target -OutputBasePath $OutputPath -Domain $Environment
        $results += $result
        
        if ($result.Success) {
            Write-Host " Levantamento concluído com sucesso para $target" -ForegroundColor Green
        }
        else {
            Write-Host " Falha na execucao para $target : $($result.Error)" -ForegroundColor Red
        }
        
        Write-Host ""
    }
    
    # Resumo final
    $successCount = ($results | Where-Object { $_.Success }).Count
    $failCount = ($results | Where-Object { -not $_.Success }).Count
    
    Write-Host " "  -ForegroundColor Cyan
    Write-Host "RESUMO" -ForegroundColor Cyan
    Write-Host " "  -ForegroundColor Cyan
    Write-Host "Sistemas verificados com sucesso: $successCount" -ForegroundColor Green
    Write-Host "Sistemas com falha: $failCount" -ForegroundColor Red
    Write-Host "Total de sistemas processados: $($results.Count)" -ForegroundColor Cyan
    Write-Host "Ambiente: $Environment" -ForegroundColor Cyan
    Write-Host "Caminho dos resultados: $OutputPath" -ForegroundColor Cyan
    Write-Host " "  -ForegroundColor Cyan
    
    return $results
}

# ==================
# EXECUÇÃO PRINCIPAL
# ==================

# Executar se chamado diretamente
if ($MyInvocation.InvocationName -ne '.') {
    # Parâmetros podem ser passados via linha de comando
    $auditResults = Start-IndustrialAudit -Environment $Environment -TargetComputer $TargetComputer -OutputPath $OutputBasePath -AllSystems:$ParallelExecution
    
    if ($auditResults -and $auditResults.Count -gt 0) {
        $successfulAudits = $auditResults | Where-Object { $_.Success }
        if ($successfulAudits.Count -gt 0) {
            Write-Host ""
            Write-Host "RELATÓRIOS GERADOS:" -ForegroundColor Green
            foreach ($audit in $successfulAudits) {
                if ($audit.FinalReport) {
                    Write-Host "• $($audit.Computer): $($audit.FinalReport)" -ForegroundColor White
                }
            }
        }
    }
}

# Exportar funções para uso em outros scripts
Export-ModuleMember -Function Start-IndustrialAudit, Start-SystemAudit, Get-RemoteProgram, Get-SystemInformationComplete, Get-DiskUsageAnalysis, Get-EventLogAnalysis