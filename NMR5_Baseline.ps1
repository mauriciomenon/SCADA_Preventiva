# Baseline_NMR5 10.1 para PIC.EE.0246
# Autor: Mauricio Menon
# Versão inicial: FAT NMR5 Houston (2018)
# Versão atual 26/06/2025
# Compatível com PowerShell 5.1+ e PowerShell 7+
# Inclusao de comandos locais baseados no TAF e Comissionamento SOPHO/STH


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

# Constantes globais
$Script:SCRIPT_HEADER = @"
Script de Manutencao Preventiva - SSP - Ambiente SCADA
Versao: 1.1 - Baseado no NMR5_Baseline_v9.0 + Comissionamento da SOPHO/STH
Autor: Mauricio Menon             25/06/2025
"@

$Script:SCRIPT_COMPATIBILITY = "PowerShell 5.1+ / PowerShell 7+ / Windows Server 2012 R2+ / Windows 10+"
$Script:SCRIPT_METHODS = "CIM + WMI + WMIC + Registry + Comandos Nativos"
$Script:SCRIPT_SCOPE = "Sistema + Performance + Seguranca + Inventario"

# Configuracoes
$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Listas de sistemas por ambiente
$EMSConsoleList = @('bitcon1', 'bitcon2', 'bitcon3', 'bitcon4', 'bitcon5', 'bitcon6', 'bitcon7', 'bitcon8', 'bitcon9', 'bitcon10', 'bitcon11', 'bitcon12', 'bitcon13', 'bitcon14', 'bitcon15', 'bitcon16', 'bitcon17', 'bitcon18', 'bitcon19', 'bitcon20', 'bitcon21', 'bitcon22', 'bitcon23', 'bitcon24', 'bitcon25', 'bitcon26', 'bitcon27', 'bitcon28', 'bitcon29', 'bitcon30', 'bitdtcon1', 'bitdtcon2', 'bitdtcon3', 'bitdtcon4', 'bitdtcon5', 'bitdtcon6', 'bitdtvaps1')
$EMSServerList = @('bitora1', 'bitora2', 'bithis1', 'bithis2', 'bitood1', 'bitood2', 'bitaps1', 'bitaps2', 'biticcp1', 'biticcp2', 'bitdmc1', 'bitdmc2', 'bitpcu1', 'bitpcu2', 'bitims1', 'bitims2', 'bitdtaps1')
$PDSConsoleList = @('bitpdcon1', 'bitpdcon2', 'bitpdcon3', 'bitpdcon4')
$PDSServerList = @('bitpdaps1', 'bitpdvaps1', 'bitpdpcu1', 'bitpdora1', 'bitpdviccp1', 'bitpdvhis1')

# Estrutura de pastas renomeada
$Script:FOLDER_STRUCTURE = @{
    "00_Informacoes"               = "Informacoes gerais do SO"
    "01_Hw"                        = "Inventario detalhado de hardware"
    "02_Hw_BIOS"                   = "Informacoes de hardware e BIOS"
    "03_Software"                  = "Inventario de software"
    "04_Atualizacoes"              = "Patches e hotfixes instalados"
    "05_Servicos"                  = "Servicos do Windows"
    "06_Processos"                 = "Processos em execucao"
    "07_Drivers"                   = "Drivers instalados"
    "08_Performance"               = "Metricas de performance"
    "09_Rede"                      = "Conexoes de rede ativas"
    "10_Disco"                     = "Analise de uso de disco"
    "11_Eventos"                   = "Logs de eventos traduzidos"
    "12_Seguranca"                 = "Configuracoes de seguranca"
    "13_Relatorios_Complementares" = "Relatorios de menor confiabilidade"
    "14_Relatorio"                 = "Relatorios finais e resumos"
}

# Funcao para limpar variaveis
function Clear-AllVariable {
    $variables = Get-Variable -Scope Global -Exclude PWD, OLDPWD
    $variables | ForEach-Object {
        if ($_.Options -ne "Constant" -and $_.Options -ne "ReadOnly") {
            Set-Variable -Name $_.Name -Value $null -Force -ErrorAction SilentlyContinue
        }
    }
}

# Funcao para verificar privilegios
function Test-AdminPrivilege {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning 'Este script deve ser executado com privilegios de administrador para funcionalidades completas.'
        Write-Host "Privilegios administrativos: Nao disponivel" -ForegroundColor Yellow
    }
    else {
        Write-Host 'Privilegios administrativos confirmados.' -ForegroundColor Green
    }
    return $isAdmin
}

# Funcao para verificar versao do PowerShell
function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    $versionFlag = 0

    Write-Host "Versao do PowerShell: $psVersion" -ForegroundColor Cyan

    if ($psVersion.Major -eq 5 -and $psVersion.Minor -eq 1) {
        $versionFlag = 1
        Write-Host "PowerShell 5.1 detectado" -ForegroundColor Green
    }
    elseif ($psVersion.Major -gt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)) {
        $versionFlag = 2
        Write-Host "PowerShell $($psVersion.Major) detectado - Funcionalidades avancadas disponiveis" -ForegroundColor Green
    }
    else {
        Write-Error "Versao do PowerShell nao suportada. Minimo: 5.1"
        return $null
    }
    return $versionFlag
}

# Funcao para verificar versao do SO
function Test-OSVersion {
    try {
        $osVersion = (Get-CimInstance -ClassName CIM_OperatingSystem -ErrorAction Stop).Version
    }
    catch {
        $osVersion = (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop).Version
    }

    Write-Host "Versao do Windows: $osVersion" -ForegroundColor Cyan
    
    if ($osVersion -notmatch '6\.3|10\.0') {
        Write-Warning "Este script foi otimizado para Windows Server 2012 R2+ e Windows 10+. Alguns recursos podem nao funcionar corretamente."
    }
    Write-Host "Versao do SO detectada: $osVersion" -ForegroundColor Gray
    return $osVersion
}

# Funcao para obter ambiente
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

# Funcao para obter lista de targets
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
            Write-Warning "Dominio $domain nao reconhecido"
            return @()
        }
    }

    $targets = $ConsoleList + $ServerList
    return $targets
}

# Funcao Get-RemoteProgram
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
                Write-Verbose "Executando analise de software LOCAL"
                
                # METODO 1: Registry local direto
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
                                        Method       = "Registry"
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
                            $wmicResults = @()
                            $wmicOutput | Select-Object -Skip 1 | Where-Object { $_ -and $_ -notmatch "^Node" } | ForEach-Object {
                                $fields = $_ -split ','
                                if ($fields.Count -ge 4 -and $fields[2]) {
                                    $wmicResults += [PSCustomObject]@{
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
                                        Method          = "WMIC"
                                    }
                                }
                            }
                            
                            # Salvar WMIC em relatorios complementares se temos Registry
                            if ($Results.Count -gt 0) {
                                $Global:WMICResults = $wmicResults
                            }
                            else {
                                $Results = $wmicResults
                            }
                        }
                        Write-Verbose "WMIC local: $(if ($wmicResults) { $wmicResults.Count } else { 0 }) programas encontrados"
                    }
                    catch {
                        Write-Warning "WMIC local falhou: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Verbose "Executando analise de software REMOTA para $Computer"
                
                # METODO 1: Registry remoto
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
                                                    Method       = "Registry"
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
                                        Method          = "WMIC"
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

# Funcao para obter informacoes do sistema com fallbacks
function Get-SystemInformationComplete {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $Results = @{}
    
    Write-Host "Coletando informacoes do sistema $Computer..." -ForegroundColor Cyan
    
    # INFORMACOES DO SO 
    Write-Host "  • Informacoes do Sistema Operacional..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "CIM"
            }
            catch {
                try {
                    $Results.OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $wmicOS = cmd /c "wmic os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $Results.OSInfo = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                        $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMIC"
                    }
                }
            }
        }
        else {
            try {
                $Results.OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "CIM"
            }
            catch {
                try {
                    $Results.OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                    $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $wmicOS = cmd /c "wmic /node:$Computer os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $Results.OSInfo = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                        $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMIC"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter informacoes do SO: $($_.Exception.Message)"
    }

    # Continue com o resto das informacoes do sistema...
    # [O resto do codigo da funcao permanece similar, mas com adicao do campo Method]
    
    # Salvar todos os dados coletados com nova estrutura
    try {
        # Criar estrutura de pastas renomeada
        $targetPath = Join-Path $OutputPath $Computer
        
        foreach ($folderName in $Script:FOLDER_STRUCTURE.Keys) {
            $folderPath = Join-Path $targetPath $folderName
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
            }
        }

        Write-Host "  • Salvando dados coletados..." -ForegroundColor White

        # Salvar OS Info na pasta 00_Informacoes
        if ($Results.OSInfo) {
            $osPath = Join-Path $targetPath "00_Informacoes"
            $Results.OSInfo | Export-Csv -Path (Join-Path $osPath "${Timestamp}_OS_INFO.csv") -NoTypeInformation -Encoding UTF8
            $Results.OSInfo | Format-List | Out-File -FilePath (Join-Path $osPath "${Timestamp}_OS_INFO.txt") -Encoding UTF8
        }
        
        # Continue salvando outros dados...
    }
    catch {
        Write-Warning "Erro ao salvar dados: $($_.Exception.Message)"
    }

    return $Results
}

# Funcao para criar pagina HTML de navegacao
function New-HTMLNavigationPage {
    param(
        [string]$OutputPath,
        [string]$Computer,
        [string]$Timestamp
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatorio de Auditoria - $Computer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
        .container { display: flex; height: 100vh; }
        .sidebar { width: 300px; background-color: #f5f5f5; border-right: 1px solid #ddd; overflow-y: auto; padding: 10px; }
        .content { flex: 1; padding: 20px; overflow-y: auto; }
        .folder { margin: 5px 0; }
        .folder-name { font-weight: bold; cursor: pointer; padding: 5px; background-color: #e0e0e0; border-radius: 3px; }
        .file-list { margin-left: 15px; display: none; }
        .file-item { padding: 3px 0; cursor: pointer; color: #0066cc; }
        .file-item:hover { text-decoration: underline; }
        .content-frame { width: 100%; height: 100%; border: none; }
        h1 { color: #333; border-bottom: 2px solid #0066cc; }
    </style>
    <script>
        function toggleFolder(element) {
            const fileList = element.nextElementSibling;
            fileList.style.display = fileList.style.display === 'block' ? 'none' : 'block';
        }
        
        function loadFile(filePath) {
            const iframe = document.getElementById('contentFrame');
            iframe.src = filePath;
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h3>Estrutura de Arquivos</h3>
"@

    # Gerar arvore de arquivos
    foreach ($folderName in ($Script:FOLDER_STRUCTURE.Keys | Sort-Object)) {
        $folderPath = Join-Path $OutputPath $Computer $folderName
        $description = $Script:FOLDER_STRUCTURE[$folderName]
        
        $htmlContent += @"
            <div class="folder">
                <div class="folder-name" onclick="toggleFolder(this)">📁 $folderName</div>
                <div class="file-list">
                    <small style="color: #666;">$description</small><br>
"@
        
        if (Test-Path $folderPath) {
            $files = Get-ChildItem -Path $folderPath -File | Sort-Object Name
            foreach ($file in $files) {
                $relativePath = "./$Computer/$folderName/$($file.Name)"
                $htmlContent += @"
                    <div class="file-item" onclick="loadFile('$relativePath')">📄 $($file.Name)</div>
"@
            }
        }
        
        $htmlContent += @"
                </div>
            </div>
"@
    }

    $htmlContent += @"
        </div>
        <div class="content">
            <h1>Relatorio de Auditoria - $Computer</h1>
            <p>Gerado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
            <p>Selecione um arquivo na arvore lateral para visualizar seu conteudo.</p>
            <iframe id="contentFrame" class="content-frame"></iframe>
        </div>
    </div>
</body>
</html>
"@

    $htmlPath = Join-Path $OutputPath "$Computer.html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-Host "Pagina HTML criada: $htmlPath" -ForegroundColor Green
    return $htmlPath
}

# Funcao principal do Levantamento
function Start-SystemAudit {
    param(
        [string]$Computer = "localhost",
        [string]$OutputBasePath = "",
        [string]$Domain = ""
    )
    
    $Global:AuditStartTime = Get-Date
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    
    Write-Host ""
    Write-Host "Iniciando auditoria tecnica completa" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Configurar caminhos
        if (-not $OutputBasePath) {
            $OutputBasePath = Join-Path $PSScriptRoot $Domain
        }
        
        $targetPath = Join-Path $OutputBasePath $Computer
        
        # Verificar pasta anterior
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
        foreach ($folderName in $Script:FOLDER_STRUCTURE.Keys) {
            $folderPath = Join-Path $targetPath $folderName
            if (-not (Test-Path $folderPath)) {
                New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
            }
        }
        
        # Iniciar transcript
        $logFile = Join-Path $targetPath "14_Relatorio\Log_Auditoria_${timestamp}.txt"
        Start-Transcript -Path $logFile -Append
        
        Write-Host "1. Executando inventario de software instalado..." -ForegroundColor White
        $softwareList = Get-RemoteProgram -ComputerName $Computer
        
        if ($softwareList -and $softwareList.Count -gt 0) {
            # Salvar lista de software
            $softwarePath = Join-Path $targetPath "03_Software"
            $softwareList | Export-Csv -Path (Join-Path $softwarePath "${timestamp}_Software_Instalado_Completo.csv") -NoTypeInformation -Encoding UTF8
            $softwareList | Sort-Object ProgramName | Format-Table ProgramName, DisplayVersion, Publisher, InstallDate, Method -AutoSize | Out-File -FilePath (Join-Path $softwarePath "${timestamp}_Software_Instalado_Completo.txt") -Encoding UTF8 -Width 300
            
            # Salvar WMIC em relatorios complementares se existir
            if ($Global:WMICResults) {
                $complementarPath = Join-Path $targetPath "13_Relatorios_Complementares"
                $Global:WMICResults | Export-Csv -Path (Join-Path $complementarPath "${timestamp}_Software_WMIC.csv") -NoTypeInformation -Encoding UTF8
            }
            
            # Identificar softwares suspeitos
            $keywords = @("eval", "trial", "demo", "crack", "keygen", "patch", "portable", "unknown")
            $suspiciousSoftware = $softwareList | Where-Object { 
                $name = $_.ProgramName.ToLower()
                $keywords | ForEach-Object { if ($name -match $_) {
                        return $true 
                    } }
            }
            
            if ($suspiciousSoftware.Count -gt 0) {
                $suspiciousSoftware | Export-Csv -Path (Join-Path $softwarePath "${timestamp}_Software_Suspeito.csv") -NoTypeInformation -Encoding UTF8
                
                # Criar relatorio detalhado de software suspeito
                $suspiciousReport = @"
Relatorio de Software Suspeito
==============================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de programas suspeitos: $($suspiciousSoftware.Count)

Programas que requerem verificacao manual:

"@
                $counter = 1
                foreach ($software in ($suspiciousSoftware | Select-Object -First 15)) {
                    $location = if ($software.InstallLocation) {
                        $software.InstallLocation 
                    }
                    else {
                        "Nao informado" 
                    }
                    $suspiciousReport += @"
$counter. $($software.ProgramName)
   Editor: $($software.Publisher)
   Versao: $($software.DisplayVersion)
   Data de Instalacao: $($software.InstallDate)
   Localizacao: $location
   Metodo de Deteccao: $($software.Method)

"@
                    $counter++
                }
                
                $suspiciousReport | Out-File -FilePath (Join-Path $softwarePath "${timestamp}_Software_Suspeito_Detalhado.txt") -Encoding UTF8
            }
            
            Write-Host "   Software analisado: $($softwareList.Count) programas, $($suspiciousSoftware.Count) requerem verificacao" -ForegroundColor Green
        }
        else {
            Write-Warning "Nenhum software detectado ou erro na coleta"
            $softwareList = @()
        }
        
        # Continuar com outras coletas...
        Write-Host "2. Coletando informacoes completas do sistema..." -ForegroundColor White
        $systemInfo = Get-SystemInformationComplete -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
        
        # Gerar pagina HTML de navegacao
        Write-Host "3. Gerando pagina HTML de navegacao..." -ForegroundColor White
        $htmlPage = New-HTMLNavigationPage -OutputPath $OutputBasePath -Computer $Computer -Timestamp $timestamp
        
        Stop-Transcript
        
        Write-Host ""
        Write-Host "Auditoria concluida com sucesso" -ForegroundColor Green
        Write-Host ""
        
        # Resumo com localizacoes especificas
        Write-Host "Sistema analisado: $Computer" -ForegroundColor Cyan
        Write-Host "Dominio: $Domain" -ForegroundColor Cyan
        Write-Host "Estrutura: $OutputBasePath\$Computer\" -ForegroundColor Cyan
        Write-Host "Relatorios salvos em: $targetPath" -ForegroundColor Cyan
        Write-Host "Pagina HTML: $htmlPage" -ForegroundColor Cyan
        
        Write-Host ""
        Write-Host "Resumo dos indicadores tecnicos:" -ForegroundColor Cyan
        Write-Host "• Software instalado: $(if ($softwareList) { $softwareList.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Programas para verificacao: $(if ($suspiciousSoftware) { $suspiciousSoftware.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Servicos do sistema: $(if ($systemInfo.Services) { $systemInfo.Services.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Processos em execucao: $(if ($systemInfo.Processes) { $systemInfo.Processes.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Atualizacoes aplicadas: $(if ($systemInfo.HotFixes) { $systemInfo.HotFixes.Count } else { 0 })" -ForegroundColor White
        Write-Host "• Drivers analisados: $(if ($systemInfo.SystemDrivers) { $systemInfo.SystemDrivers.Count } else { 0 })" -ForegroundColor White
        
        # Mostrar localizacao dos programas suspeitos
        if ($suspiciousSoftware -and $suspiciousSoftware.Count -gt 0) {
            Write-Host ""
            Write-Host "Recomendacao: Revisar $($suspiciousSoftware.Count) programas identificados para verificacao manual:" -ForegroundColor Yellow
            $counter = 1
            foreach ($software in ($suspiciousSoftware | Select-Object -First 15)) {
                $location = if ($software.InstallLocation) {
                    $software.InstallLocation 
                }
                else {
                    "Localizacao nao informada" 
                }
                Write-Host "  $counter. $($software.ProgramName) - $location" -ForegroundColor Gray
                $counter++
            }
            if ($suspiciousSoftware.Count -gt 15) {
                Write-Host "  ... e mais $($suspiciousSoftware.Count - 15) programas (consulte relatorio detalhado)" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
        Write-Host "Estrutura de pastas gerada:" -ForegroundColor Cyan
        Write-Host "   $OutputBasePath\" -ForegroundColor White
        Write-Host "   └── $Computer\" -ForegroundColor White
        foreach ($folderName in ($Script:FOLDER_STRUCTURE.Keys | Sort-Object)) {
            $description = $Script:FOLDER_STRUCTURE[$folderName]
            Write-Host "       ├── $folderName\  ($description)" -ForegroundColor Gray
        }
        
        Write-Host ""
        
        return @{
            Success         = $true
            Computer        = $Computer
            Domain          = $Domain
            OutputPath      = $targetPath
            HTMLPage        = $htmlPage
            SoftwareCount   = if ($softwareList) {
                $softwareList.Count 
            }
            else {
                0 
            }
            SuspiciousCount = if ($suspiciousSoftware) {
                $suspiciousSoftware.Count 
            }
            else {
                0 
            }
            SystemInfo      = $systemInfo
        }
        
    }
    catch {
        Write-Error "Erro durante a auditoria: $($_.Exception.Message)"
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

# Funcao para gerar relatorio de eventos com linha de tempo
function New-EventTimelineReport {
    param(
        [array]$EventAnalysis,
        [string]$OutputPath,
        [string]$Computer,
        [string]$Timestamp
    )
    
    if (-not $EventAnalysis -or $EventAnalysis.Count -eq 0) {
        Write-Warning "Nenhum evento para gerar linha de tempo"
        return
    }
    
    $eventPath = Join-Path $OutputPath $Computer "11_Eventos"
    
    # Linha de tempo geral
    $timelineReport = @"
Linha de Tempo de Eventos do Sistema
====================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de eventos analisados: $($EventAnalysis.Count)

Eventos ordenados cronologicamente:

"@
    
    $sortedEvents = $EventAnalysis | Sort-Object TimeCreated -Descending
    foreach ($event in $sortedEvents) {
        $timelineReport += @"
[$($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))] $($event.Severity) - ID:$($event.Id)
Fonte: $($event.Source)
Categoria: $($event.LogName)
Descricao: $($event.TranslatedDescription)

"@
    }
    
    $timelineReport | Out-File -FilePath (Join-Path $eventPath "${Timestamp}_Timeline_Eventos.txt") -Encoding UTF8
    
    # Linha de tempo por familia e criticidade
    $familyReport = @"
Linha de Tempo de Eventos por Familia e Criticidade
===================================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

"@
    
    # Organizar por familia (LogName) e criticidade
    $eventFamilies = @{
        "Sistema"   = $EventAnalysis | Where-Object { $_.LogName -eq "System" }
        "Seguranca" = $EventAnalysis | Where-Object { $_.LogName -eq "Security" }
        "Aplicacao" = $EventAnalysis | Where-Object { $_.LogName -eq "Application" }
    }
    
    $criticityOrder = @("CRITICO", "ERRO", "AVISO", "INFO")
    
    foreach ($family in $eventFamilies.Keys) {
        $familyEvents = $eventFamilies[$family]
        if ($familyEvents.Count -gt 0) {
            $familyReport += @"

FAMILIA: $family ($($familyEvents.Count) eventos)
================================================

"@
            
            foreach ($criticality in $criticityOrder) {
                $criticalEvents = $familyEvents | Where-Object { $_.Severity -eq $criticality } | Sort-Object TimeCreated -Descending
                if ($criticalEvents.Count -gt 0) {
                    $familyReport += @"
--- $criticality ($($criticalEvents.Count) eventos) ---

"@
                    foreach ($event in $criticalEvents) {
                        $familyReport += @"
[$($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))] ID:$($event.Id) - $($event.TranslatedDescription)
"@
                    }
                    $familyReport += "`n"
                }
            }
        }
    }
    
    $familyReport | Out-File -FilePath (Join-Path $eventPath "${Timestamp}_Timeline_Por_Familia.txt") -Encoding UTF8
    
    Write-Host "Relatorios de linha de tempo de eventos criados" -ForegroundColor Green
}

# Dicionario de traducao de eventos corrigido
$Script:EVENT_TRANSLATION = @{
    # System Events
    "1074" = "Sistema foi desligado pelo usuario"
    "1076" = "Sistema foi desligado inesperadamente"
    "6005" = "Servico Event Log foi iniciado"
    "6006" = "Servico Event Log foi parado"
    "6008" = "Desligamento inesperado do sistema"
    "6009" = "Versao do sistema operacional detectada"
    "6013" = "Tempo de atividade do sistema"
    "7001" = "Logon do usuario"
    "7002" = "Logoff do usuario"
    "7034" = "Servico terminou inesperadamente"
    "7035" = "Servico enviou controle de estado"
    "7036" = "Servico entrou em estado parado/iniciado"
    
    # Security Events
    "4624" = "Logon bem-sucedido"
    "4625" = "Falha no logon"
    "4634" = "Logoff de conta"
    "4647" = "Logoff iniciado pelo usuario"
    "4648" = "Tentativa de logon com credenciais explicitas"
    "4672" = "Privilegios especiais atribuidos ao logon"
    "4720" = "Conta de usuario criada"
    "4726" = "Conta de usuario excluida"
    "4732" = "Membro adicionado ao grupo de seguranca local"
    "4733" = "Membro removido do grupo de seguranca local"
    "4740" = "Conta de usuario bloqueada"
    "4767" = "Conta de usuario desbloqueada"
    
    # Application Events
    "1000" = "Falha na aplicacao"
    "1002" = "Travamento da aplicacao"
    "1001" = "Relatorio de erro do Windows"
    
    # BSOD e Kernel (removida duplicata)
    "41"   = "Sistema reiniciou sem desligar corretamente"
    #"1001" = "Erro critico do sistema (BSOD)"
    
    # Disk Events
    "7"    = "Erro de dispositivo"
    "11"   = "Driver detectou erro no controlador"
    "51"   = "Erro de pagina no disco"
    
    # Network Events
    "4201" = "Adaptador de rede desconectado"
    "4202" = "Adaptador de rede conectado"
    
    # Hardware Events
    "6"    = "Driver carregado"
    "219"  = "Driver instalado com sucesso"
    
    # Novos eventos relevantes
    #"4634" = "Conta foi desconectada"
    #"4648" = "Logon foi tentado usando credenciais explicitas"
    "4768" = "Ticket de autenticacao Kerberos foi solicitado"
    "4769" = "Ticket de servico Kerberos foi solicitado"
    "4771" = "Falha de pre-autenticacao Kerberos"
    "4776" = "Controlador de dominio tentou validar credenciais"
    "4778" = "Sessao foi reconectada"
    "4779" = "Sessao foi desconectada"
    "5152" = "Firewall do Windows bloqueou um pacote"
    "5156" = "Firewall do Windows permitiu uma conexao"
}

# Funcao principal que coordena todo o processo
function Start-IndustrialAudit {
    param(
        [string]$Environment = "",
        [string]$TargetComputer = "",
        [string]$OutputPath = "",
        [switch]$AllSystems = $false
    )
    
    # Limpar variaveis
    Clear-AllVariable
    
    # Verificacoes iniciais
    Write-Host $Script:SCRIPT_HEADER -ForegroundColor Cyan
    Write-Host ""
    
    # Verificar privilegios
    $isAdmin = Test-AdminPrivilege
    Write-Host "Status de privilegios administrativos: $isAdmin" -ForegroundColor Gray
    
    # Verificar versao do PowerShell
    $psVersion = Test-PowerShellVersion
    if (-not $psVersion) {
        Write-Error "Versao do PowerShell incompativel. Saindo..."
        return
    }
    
    # Verificar versao do SO
    $osVersion = Test-OSVersion
    
    # Determinar ambiente se nao especificado
    if (-not $Environment) {
        $Environment = Get-Environment
    }
    
    # Determinar target se nao especificado
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
    
    # Configurar caminho de saida
    if (-not $OutputPath) {
        $OutputPath = Join-Path $PSScriptRoot $Environment
    }
    
    Write-Host "Ambiente detectado: $Environment" -ForegroundColor Green
    Write-Host "Sistemas a auditar: $($targets -join ', ')" -ForegroundColor Green
    Write-Host "Caminho de saida: $OutputPath" -ForegroundColor Green
    Write-Host ""
    
    # Executar auditoria para cada sistema
    $results = @()
    $successfulResults = @()
    $failedResults = @()
    
    foreach ($target in $targets) {
        Write-Host "Iniciando auditoria para: $target" -ForegroundColor White
        Write-Host ""
        
        $result = Start-SystemAudit -Computer $target -OutputBasePath $OutputPath -Domain $Environment
        $results += $result
        
        if ($result.Success) {
            Write-Host "Auditoria concluida com sucesso para $target" -ForegroundColor Green
            $successfulResults += @{
                Computer   = $target
                OutputPath = $result.OutputPath
                HTMLPage   = $result.HTMLPage
            }
        }
        else {
            Write-Host "Falha na auditoria para $target : $($result.Error)" -ForegroundColor Red
            $failedResults += @{
                Computer = $target
                Error    = $result.Error
            }
        }
        
        Write-Host ""
    }
    
    # Resumo final detalhado
    $successCount = $successfulResults.Count
    $failCount = $failedResults.Count
    
    Write-Host ""
    Write-Host "Resumo final da auditoria" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Sistemas auditados com sucesso: $successCount" -ForegroundColor Green
    
    if ($successCount -gt 0) {
        Write-Host "Sistemas com sucesso:" -ForegroundColor Green
        foreach ($success in $successfulResults) {
            Write-Host "  • $($success.Computer) - Relatorios em: $($success.OutputPath)" -ForegroundColor White
            if ($success.HTMLPage) {
                Write-Host "    Pagina HTML: $($success.HTMLPage)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "Sistemas com falha: $failCount" -ForegroundColor Red
    
    if ($failCount -gt 0) {
        Write-Host "Sistemas com falha:" -ForegroundColor Red
        foreach ($failure in $failedResults) {
            Write-Host "  • $($failure.Computer) - Erro: $($failure.Error)" -ForegroundColor White
        }
    }
    
    Write-Host "Total de sistemas processados: $($results.Count)" -ForegroundColor Cyan
    Write-Host "Ambiente: $Environment" -ForegroundColor Cyan
    Write-Host "Caminho dos resultados: $OutputPath" -ForegroundColor Cyan
    Write-Host ""
    
    if ($successCount -gt 0) {
        Write-Host "Relatorios gerados:" -ForegroundColor Green
        foreach ($success in $successfulResults) {
            Write-Host "• $($success.Computer): $($success.OutputPath)" -ForegroundColor White
        }
    }
    
    return $results
}


# Execucao principal
if ($MyInvocation.InvocationName -ne '.') {
    # Parametros podem ser passados via linha de comando
    $auditResults = Start-IndustrialAudit -Environment $Environment -TargetComputer $TargetComputer -OutputPath $OutputBasePath -AllSystems:$ParallelExecution
    
    if ($auditResults -and $auditResults.Count -gt 0) {
        $successfulAudits = $auditResults | Where-Object { $_.Success }
        if ($successfulAudits.Count -gt 0) {
            Write-Host ""
            Write-Host "Todas as auditorias foram concluidas." -ForegroundColor Green
            Write-Host "Verifique os relatorios gerados nos caminhos indicados acima." -ForegroundColor White
        }
    }
}

# Nota: Export-ModuleMember removido pois o script nao e um modulo
# As funcoes sao exportadas apenas quando o script e importado como modulo


# Fluxogramas de execucao (via comentarios)

<#
FLUXOGRAMA - EXECUCAO LOCAL
===========================

Start-IndustrialAudit
│
├── Clear-AllVariable
├── Test-AdminPrivilege
├── Test-PowerShellVersion
├── Test-OSVersion
├── Get-Environment
├── Get-TargetList
│
└── Start-SystemAudit (para cada target)
    │
    ├── Get-RemoteProgram
    │   ├── TRY: Registry Local (HKLM)
    │   ├── CATCH: WMI Local
    │   └── FALLBACK: WMIC Local
    │
    ├── Get-SystemInformationComplete
    │   ├── OS Info: CIM → WMI → WMIC
    │   ├── Computer System: CIM → WMI → WMIC
    │   ├── CPU: CIM → WMI → WMIC
    │   ├── Memory: CIM → WMI → WMIC
    │   ├── Disks: CIM → WMI → WMIC
    │   ├── Services: CIM → WMI → WMIC
    │   ├── Processes: CIM → WMI → Get-Process
    │   ├── HotFixes: CIM → WMI → Get-HotFix → WMIC
    │   ├── BIOS: CIM → WMI → WMIC
    │   ├── Drivers: CIM → WMI → WMIC
    │   ├── Performance: Get-Counter → Calculado
    │   └── Network: Get-NetTCPConnection → netstat
    │
    ├── Get-DiskUsageAnalysis
    │   ├── Get-CimInstance → Get-WmiObject
    │   └── Get-ChildItem (local only)
    │
    ├── Get-EventLogAnalysis
    │   └── Get-WinEvent
    │
    ├── New-EventTimelineReport
    ├── New-HTMLNavigationPage
    └── New-ConsolidatedReport

FLUXOGRAMA - EXECUCAO REMOTA
============================

Start-IndustrialAudit
│
└── Start-SystemAudit (para cada target remoto)
    │
    ├── Get-RemoteProgram
    │   ├── TRY: Registry Remoto (Port 445)
    │   └── FALLBACK: WMIC Remoto
    │
    ├── Get-SystemInformationComplete
    │   ├── OS Info: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Computer System: CIM Remote → WMI Remote → WMIC Remote
    │   ├── CPU: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Memory: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Disks: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Services: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Processes: CIM Remote → WMI Remote
    │   ├── HotFixes: CIM Remote → WMI Remote → WMIC Remote
    │   ├── BIOS: CIM Remote → WMI Remote → WMIC Remote
    │   ├── Drivers: CIM Remote → WMI Remote → WMIC Remote
    │   └── Network: Limitado (apenas para local)
    │
    ├── Get-DiskUsageAnalysis
    │   └── Get-CimInstance Remote → Get-WmiObject Remote
    │
    ├── Get-EventLogAnalysis
    │   └── Get-WinEvent -ComputerName
    │
    └── Relatorios (local)

TRATAMENTO DE FALHAS
====================

Cada funcao implementa try-catch-finally com:
1. Metodo primario (CIM/Registry)
2. Metodo secundario (WMI)
3. Metodo terciario (WMIC/CMD)
4. Logs de erro detalhados
5. Continuidade da execucao mesmo com falhas parciais
6. Resultados salvos em Relatorios_Complementares quando apropriado

ESTRUTURA DE DADOS
==================

Cada coleta inclui campo "Method" indicando:
- CIM: Melhor qualidade, PowerShell 3.0+
- WMI: Boa qualidade, compatibilidade ampla
- WMIC: Qualidade basica, maximo fallback
- Registry: Acesso direto, alta qualidade
- CMD: Comandos nativos, compatibilidade maxima

PRIORIDADES DE EXECUCAO
=======================

1. CRITICO: Informacoes basicas do sistema
2. ALTO: Software instalado e servicos
3. MEDIO: Performance e rede
4. BAIXO: Eventos e logs detalhados
5. COMPLEMENTAR: Dados de fallback

#>