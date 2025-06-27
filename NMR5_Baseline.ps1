# Baseline_NMR5 10.2 para PIC.EE.0246
# Autor: Mauricio Menon
# Versão inicial: FAT NMR5 Houston (2018)
# Versão atual 27/06/2025
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

# Dicionario de traducao de eventos corrigido
$Script:EVENT_TRANSLATION = @{
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
    "4768" = "Ticket de autenticacao Kerberos foi solicitado"
    "4769" = "Ticket de servico Kerberos foi solicitado"
    "4771" = "Falha de pre-autenticacao Kerberos"
    "4776" = "Controlador de dominio tentou validar credenciais"
    "4778" = "Sessao foi reconectada"
    "4779" = "Sessao foi desconectada"
    "1000" = "Falha na aplicacao"
    "1001" = "Relatorio de erro do Windows"
    "1002" = "Travamento da aplicacao"
    "41"   = "Sistema reiniciou sem desligar corretamente"
    "1003" = "Erro critico do sistema (BSOD)"
    "7"    = "Erro de dispositivo"
    "11"   = "Driver detectou erro no controlador"
    "51"   = "Erro de pagina no disco"
    "4201" = "Adaptador de rede desconectado"
    "4202" = "Adaptador de rede conectado"
    "5152" = "Firewall do Windows bloqueou um pacote"
    "5156" = "Firewall do Windows permitiu uma conexao"
    "6"    = "Driver carregado"
    "219"  = "Driver instalado com sucesso"
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
    Write-Host "Versao detectada do sistema operacional: $osVersion" -ForegroundColor Gray
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
    $AlternativeResults = @{}
    
    Write-Host "Coletando informacoes completas do sistema $Computer..." -ForegroundColor Cyan
    
    Write-Host "  • Informacoes do Sistema Operacional..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $Results.OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "CIM"
            }
            catch {
                try {
                    $AlternativeResults["WMI_OSInfo"] = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                    $Results.OSInfo = $AlternativeResults["WMI_OSInfo"]
                    $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $wmicOS = cmd /c "wmic os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $AlternativeResults["WMIC_OSInfo"] = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                        $Results.OSInfo = $AlternativeResults["WMIC_OSInfo"]
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
                    $AlternativeResults["WMI_OSInfo"] = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                    $Results.OSInfo = $AlternativeResults["WMI_OSInfo"]
                    $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $wmicOS = cmd /c "wmic /node:$Computer os get Version,Caption,CountryCode,CSName,Description,InstallDate,SerialNumber,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory,WindowsDirectory /format:csv 2>nul"
                    if ($wmicOS) {
                        $AlternativeResults["WMIC_OSInfo"] = $wmicOS | ConvertFrom-Csv | Where-Object { $_.Version }
                        $Results.OSInfo = $AlternativeResults["WMIC_OSInfo"]
                        $Results.OSInfo | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMIC"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter informacoes do SO: $($_.Exception.Message)"
    }

    Write-Host "  • Coletando informacoes de performance e historico..." -ForegroundColor White
    $Results.Performance = @{}
    
    try {
        if ($isLocal) {
            $cpuUsage = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue
            if ($cpuUsage) {
                $Results.Performance.CPUUsage = ($cpuUsage.CounterSamples | Measure-Object -Property CookedValue -Average).Average
                $Results.Performance.CPUHistory = $cpuUsage.CounterSamples | ForEach-Object { 
                    [PSCustomObject]@{
                        Timestamp = $_.Timestamp
                        Value     = $_.CookedValue
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Falha ao obter CPU usage: $($_.Exception.Message)"
    }
    
    try {
        if ($Results.OSInfo -and $Results.OSInfo.LastBootUpTime) {
            $bootTime = if ($Results.OSInfo.LastBootUpTime -is [string]) {
                [DateTime]::ParseExact($Results.OSInfo.LastBootUpTime.Substring(0, 14), "yyyyMMddHHmmss", $null)
            }
            else {
                $Results.OSInfo.LastBootUpTime
            }
            $Results.Performance.Uptime = (Get-Date) - $bootTime
            $Results.Performance.UptimeDays = [math]::Round($Results.Performance.Uptime.TotalDays, 2)
        }
    }
    catch {
        Write-Verbose "Falha ao calcular uptime: $($_.Exception.Message)"
    }
    
    try {
        $targetPath = Join-Path $OutputPath $Computer
        
        if ($Results.OSInfo) {
            $osPath = Join-Path $targetPath "00_Informacoes"
            Save-ReportWithMethods -Data $Results.OSInfo -BasePath $osPath -FileName "${Timestamp}_Info_Sistema" -PrimaryMethod $Results.OSInfo.Method -AlternativeData $AlternativeResults
        }
        
        if ($Results.Performance) {
            $perfPath = Join-Path $targetPath "08_Performance"
            $Results.Performance | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $perfPath "${Timestamp}_Performance_Completa.json") -Encoding UTF8
            
            $perfReport = @"
Relatorio de Performance do Sistema
===================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

Utilizacao de Recursos:
$(if ($Results.Performance.CPUUsage) { "• CPU Usage: $([math]::Round($Results.Performance.CPUUsage, 2))%" } else { "• CPU Usage: Nao disponivel" })
$(if ($Results.Performance.UptimeDays) { "• Uptime: $($Results.Performance.UptimeDays) dias" } else { "• Uptime: Nao disponivel" })

Historico de CPU (ultimas amostras):
$(if ($Results.Performance.CPUHistory) { 
    ($Results.Performance.CPUHistory | ForEach-Object { "$($_.Timestamp.ToString('HH:mm:ss')): $([math]::Round($_.Value, 2))%" }) -join "`n"
} else { "Nao disponivel" })
"@
            $perfReport | Out-File -FilePath (Join-Path $perfPath "${Timestamp}_Performance_Completa.txt") -Encoding UTF8
        }
        
    }
    catch {
        Write-Warning "Erro ao salvar dados: $($_.Exception.Message)"
    }

    return $Results
}

# Funcao para criar relatorios com multiplos metodos
function Save-ReportWithMethods {
    param(
        [object]$Data,
        [string]$BasePath,
        [string]$FileName,
        [string]$PrimaryMethod = "CIM",
        [hashtable]$AlternativeData = @{}
    )
    
    if ($Data) {
        $Data | Export-Csv -Path (Join-Path $BasePath "${FileName}.csv") -NoTypeInformation -Encoding UTF8
        $Data | Format-Table -AutoSize | Out-File -FilePath (Join-Path $BasePath "${FileName}.txt") -Encoding UTF8 -Width 300
    }
    
    $complementarPath = $BasePath -replace "\\[^\\]+$", "\13_Relatorios_Complementares"
    if (-not (Test-Path $complementarPath)) {
        New-Item -ItemType Directory -Path $complementarPath -Force | Out-Null
    }
    
    $methodPriority = @{
        "CIM"            = 1
        "WMI"            = 2
        "WMIC"           = 3
        "Registry"       = 1
        "CMD"            = 4
        "Get-NetAdapter" = 1
        "netstat"        = 3
    }
    
    foreach ($method in $AlternativeData.Keys) {
        $priority = if ($methodPriority.ContainsKey($method)) {
            $methodPriority[$method] 
        }
        else {
            5 
        }
        $altFileName = "${priority}_${method}_${FileName}"
        
        if ($AlternativeData[$method]) {
            $AlternativeData[$method] | Export-Csv -Path (Join-Path $complementarPath "${altFileName}.csv") -NoTypeInformation -Encoding UTF8
            $AlternativeData[$method] | Format-Table -AutoSize | Out-File -FilePath (Join-Path $complementarPath "${altFileName}.txt") -Encoding UTF8 -Width 300
        }
    }
}

# Funcao para analise completa de rede
function Get-NetworkAnalysisComplete {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $networkResults = @{}
    
    Write-Host "Analisando configuracoes de rede completas..." -ForegroundColor Cyan
    
    Write-Host "  • Coletando informacoes de adaptadores..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $networkResults.Adapters = Get-NetAdapter -ErrorAction Stop
                $networkResults.Adapters | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetAdapter"
            }
            catch {
                try {
                    $networkResults.Adapters = Get-WmiObject -Class Win32_NetworkAdapter -ErrorAction Stop | Where-Object { $_.NetEnabled -eq $true }
                    $networkResults.Adapters | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $wmicNet = cmd /c "wmic path win32_networkadapter where NetEnabled=true get Name,Speed,NetConnectionID,MACAddress,AdapterType /format:csv 2>nul"
                    if ($wmicNet) {
                        $networkResults.Adapters = $wmicNet | ConvertFrom-Csv | Where-Object { $_.Name }
                        $networkResults.Adapters | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMIC"
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter adaptadores de rede: $($_.Exception.Message)"
    }
    
    Write-Host "  • Verificando teaming de interfaces..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $networkResults.Teams = Get-NetLbfoTeam -ErrorAction Stop
                $networkResults.TeamMembers = Get-NetLbfoTeamMember -ErrorAction Stop
                $networkResults.Teams | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetLbfoTeam"
                $networkResults.TeamMembers | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetLbfoTeamMember"
            }
            catch {
                Write-Verbose "Teaming nao disponivel ou nao configurado"
                $networkResults.Teams = @()
                $networkResults.TeamMembers = @()
            }
        }
    }
    catch {
        Write-Warning "Erro ao verificar teaming: $($_.Exception.Message)"
    }
    
    Write-Host "  • Coletando configuracoes IP..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $networkResults.IPConfig = Get-NetIPConfiguration -ErrorAction Stop
                $networkResults.IPConfig | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetIPConfiguration"
            }
            catch {
                try {
                    $networkResults.IPConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -eq $true }
                    $networkResults.IPConfig | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $ipconfigOutput = cmd /c "ipconfig /all 2>nul"
                    $networkResults.IPConfig = $ipconfigOutput
                    $networkResults.IPConfig | Add-Member -NotePropertyName "Method" -NotePropertyValue "ipconfig"
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter configuracoes IP: $($_.Exception.Message)"
    }
    
    Write-Host "  • Analisando conexoes ativas..." -ForegroundColor White
    try {
        if ($isLocal) {
            try {
                $networkResults.Connections = Get-NetTCPConnection -ErrorAction Stop
                $networkResults.UDPEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
                $networkResults.Connections | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetTCPConnection"
                $networkResults.UDPEndpoints | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetUDPEndpoint"
            }
            catch {
                $netstatOutput = cmd /c "netstat -ano 2>nul"
                if ($netstatOutput) {
                    $networkResults.Connections = $netstatOutput | Where-Object { $_ -match "TCP|UDP" }
                    $networkResults.Connections | Add-Member -NotePropertyName "Method" -NotePropertyValue "netstat"
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter conexoes: $($_.Exception.Message)"
    }
    
    Write-Host "  • Identificando processos com atividade de rede..." -ForegroundColor White
    try {
        if ($isLocal) {
            $netstatWithPID = cmd /c "netstat -anob 2>nul"
            if ($netstatWithPID) {
                $networkResults.ProcessConnections = $netstatWithPID
                $networkResults.ProcessConnections | Add-Member -NotePropertyName "Method" -NotePropertyValue "netstat -anob"
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter processos de rede: $($_.Exception.Message)"
    }
    
    Write-Host "  • Analisando atividade incomum..." -ForegroundColor White
    $suspiciousActivity = @()
    
    if ($networkResults.IPConfig -and $networkResults.Connections) {
        $localSubnets = @()
        if ($networkResults.IPConfig.IPv4Address) {
            foreach ($ip in $networkResults.IPConfig.IPv4Address) {
                $subnet = ($ip.IPAddress -split '\.')[0..2] -join '.'
                $localSubnets += $subnet
            }
        }
        
        if ($networkResults.Connections.RemoteAddress) {
            foreach ($conn in $networkResults.Connections) {
                $remoteIP = $conn.RemoteAddress
                $remotePort = $conn.RemotePort
                
                $isExternal = $true
                foreach ($subnet in $localSubnets) {
                    if ($remoteIP -like "$subnet.*") {
                        $isExternal = $false
                        break
                    }
                }
                
                $standardPorts = @(80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995, 3389, 5985, 5986)
                $isNonStandardPort = $remotePort -notin $standardPorts
                
                if ($isExternal -and $isNonStandardPort -and $remoteIP -ne "0.0.0.0" -and $remoteIP -ne "127.0.0.1") {
                    $suspiciousActivity += [PSCustomObject]@{
                        LocalAddress  = $conn.LocalAddress
                        LocalPort     = $conn.LocalPort
                        RemoteAddress = $remoteIP
                        RemotePort    = $remotePort
                        State         = $conn.State
                        Reason        = "IP externo com porta nao padrao"
                        Timestamp     = Get-Date
                    }
                }
            }
        }
    }
    
    $networkResults.SuspiciousActivity = $suspiciousActivity
    
    $netPath = Join-Path $OutputPath $Computer "09_Rede"
    
    if ($networkResults.Adapters) {
        $networkResults.Adapters | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Adaptadores_Rede.csv") -NoTypeInformation -Encoding UTF8
        $networkResults.Adapters | Format-Table -AutoSize | Out-File -FilePath (Join-Path $netPath "${Timestamp}_Adaptadores_Rede.txt") -Encoding UTF8
    }
    
    if ($networkResults.Teams) {
        $networkResults.Teams | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Teams_Rede.csv") -NoTypeInformation -Encoding UTF8
        $networkResults.TeamMembers | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Team_Members.csv") -NoTypeInformation -Encoding UTF8
        
        $teamReport = @"
Configuracao de Teaming de Rede
===============================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

"@
        foreach ($team in $networkResults.Teams) {
            $members = $networkResults.TeamMembers | Where-Object { $_.Team -eq $team.Name }
            $teamReport += @"
Team: $($team.Name)
Status: $($team.Status)
Politica de Agrupamento: $($team.TeamingMode)
Algoritmo de Balanceamento: $($team.LoadBalancingAlgorithm)
Membros: $($members.Name -join ', ')

"@
        }
        $teamReport | Out-File -FilePath (Join-Path $netPath "${Timestamp}_Teams_Rede.txt") -Encoding UTF8
    }
    
    if ($networkResults.IPConfig) {
        $networkResults.IPConfig | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Configuracao_IP.csv") -NoTypeInformation -Encoding UTF8
        $networkResults.IPConfig | Format-List | Out-File -FilePath (Join-Path $netPath "${Timestamp}_Configuracao_IP.txt") -Encoding UTF8
    }
    
    if ($networkResults.Connections) {
        $networkResults.Connections | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Conexoes_TCP.csv") -NoTypeInformation -Encoding UTF8
        $networkResults.Connections | Format-Table -AutoSize | Out-File -FilePath (Join-Path $netPath "${Timestamp}_Conexoes_TCP.txt") -Encoding UTF8
    }
    
    if ($networkResults.SuspiciousActivity -and $networkResults.SuspiciousActivity.Count -gt 0) {
        $networkResults.SuspiciousActivity | Export-Csv -Path (Join-Path $netPath "${Timestamp}_Atividade_Incomum.csv") -NoTypeInformation -Encoding UTF8
        $networkResults.SuspiciousActivity | Format-Table -AutoSize | Out-File -FilePath (Join-Path $netPath "${Timestamp}_Atividade_Incomum.txt") -Encoding UTF8
    }
    
    Write-Host "  Analise de rede concluida" -ForegroundColor Green
    return $networkResults
}

# Funcao para analise de disco detalhada
function Get-DiskUsageAnalysisComplete {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    Write-Host "Analisando utilizacao de disco detalhada para $Computer..." -ForegroundColor Cyan
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $diskAnalysis = @()
    $folderAnalysis = @()
    $userAnalysis = @()
    
    try {
        if ($isLocal) {
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
                $drives | Add-Member -NotePropertyName "Method" -NotePropertyValue "CIM"
            }
            catch {
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
                $drives | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
            }
        }
        else {
            try {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
                $drives | Add-Member -NotePropertyName "Method" -NotePropertyValue "CIM"
            }
            catch {
                $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $Computer -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
                $drives | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
            }
        }
        
        foreach ($drive in $drives) {
            $totalGB = [math]::Round($drive.Size / 1GB, 2)
            $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $usedGB = [math]::Round(($drive.Size - $drive.FreeSpace) / 1GB, 2)
            $usedPercent = [math]::Round((($drive.Size - $drive.FreeSpace) / $drive.Size) * 100, 1)
            
            $barLength = 50
            $filledLength = [math]::Round(($usedPercent / 100) * $barLength)
            $emptyLength = $barLength - $filledLength
            $visualBar = "[" + ("=" * $filledLength) + ("-" * $emptyLength) + "]"
            
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
                    "CRITICO" 
                } 
                elseif ($usedPercent -gt 80) {
                    "ATENCAO" 
                } 
                else {
                    "OK" 
                }
                Method      = $drive.Method
            }
            
            if ($isLocal) {
                try {
                    $drivePath = $drive.DeviceID + "\"
                    Write-Host "  • Analisando pastas do drive $($drive.DeviceID)..." -ForegroundColor White
                    
                    $level1Folders = Get-ChildItem -Path $drivePath -Directory -ErrorAction SilentlyContinue
                    foreach ($folder1 in $level1Folders) {
                        try {
                            $folder1Size = 0
                            $folder1FileCount = 0
                            
                            $level2Folders = Get-ChildItem -Path $folder1.FullName -Directory -ErrorAction SilentlyContinue
                            $level1Files = Get-ChildItem -Path $folder1.FullName -File -ErrorAction SilentlyContinue
                            
                            if ($level1Files) {
                                $folder1Size += ($level1Files | Measure-Object -Property Length -Sum).Sum
                                $folder1FileCount += $level1Files.Count
                            }
                            
                            foreach ($folder2 in $level2Folders) {
                                try {
                                    $level3Folders = Get-ChildItem -Path $folder2.FullName -Directory -ErrorAction SilentlyContinue
                                    $level2Files = Get-ChildItem -Path $folder2.FullName -File -ErrorAction SilentlyContinue
                                    
                                    $folder2Size = 0
                                    if ($level2Files) {
                                        $folder2Size += ($level2Files | Measure-Object -Property Length -Sum).Sum
                                        $folder1FileCount += $level2Files.Count
                                    }
                                    
                                    foreach ($folder3 in $level3Folders) {
                                        try {
                                            $level3Files = Get-ChildItem -Path $folder3.FullName -File -Recurse -ErrorAction SilentlyContinue
                                            if ($level3Files) {
                                                $folder3Size = ($level3Files | Measure-Object -Property Length -Sum).Sum
                                                $folder2Size += $folder3Size
                                                $folder1FileCount += $level3Files.Count
                                            }
                                        }
                                        catch { 
                                        }
                                    }
                                    
                                    $folder1Size += $folder2Size
                                }
                                catch { 
                                }
                            }
                            
                            if ($folder1Size -gt 0) {
                                $folderSizeGB = [math]::Round($folder1Size / 1GB, 3)
                                $folderPercent = [math]::Round(($folder1Size / $drive.Size) * 100, 2)
                                
                                $folderBarLength = 20
                                $folderFilledLength = [math]::Round(($folderPercent / 100) * $folderBarLength)
                                if ($folderFilledLength -lt 1 -and $folderPercent -gt 0) {
                                    $folderFilledLength = 1 
                                }
                                $folderEmptyLength = $folderBarLength - $folderFilledLength
                                $folderBar = "[" + ("=" * $folderFilledLength) + ("-" * $folderEmptyLength) + "]"
                                
                                $folderAnalysis += [PSCustomObject]@{
                                    Drive          = $drive.DeviceID
                                    FolderName     = $folder1.Name
                                    FullPath       = $folder1.FullName
                                    SizeGB         = $folderSizeGB
                                    PercentOfDrive = $folderPercent
                                    VisualBar      = "$folderBar $folderPercent%"
                                    FileCount      = $folder1FileCount
                                    Level          = 1
                                    Owner          = try {
 (Get-Acl $folder1.FullName -ErrorAction SilentlyContinue).Owner 
                                    }
                                    catch {
                                        "Desconhecido" 
                                    }
                                }
                            }
                        }
                        catch { 
                        }
                    }
                }
                catch { 
                }
                
                try {
                    $systemFolders = @("Windows", "Program Files", "Program Files (x86)", "ProgramData")
                    $userFolders = @("Users")
                    
                    $systemSize = 0
                    $userSize = 0
                    $otherSize = 0
                    
                    foreach ($folderItem in $folderAnalysis | Where-Object { $_.Drive -eq $drive.DeviceID }) {
                        if ($folderItem.FolderName -in $systemFolders) {
                            $systemSize += ($folderItem.SizeGB * 1GB)
                        }
                        elseif ($folderItem.FolderName -in $userFolders) {
                            $userSize += ($folderItem.SizeGB * 1GB)
                        }
                        else {
                            $otherSize += ($folderItem.SizeGB * 1GB)
                        }
                    }
                    
                    $userAnalysis += [PSCustomObject]@{
                        Drive         = $drive.DeviceID
                        SystemSizeGB  = [math]::Round($systemSize / 1GB, 2)
                        UserSizeGB    = [math]::Round($userSize / 1GB, 2)
                        OtherSizeGB   = [math]::Round($otherSize / 1GB, 2)
                        SystemPercent = [math]::Round(($systemSize / $drive.Size) * 100, 1)
                        UserPercent   = [math]::Round(($userSize / $drive.Size) * 100, 1)
                        OtherPercent  = [math]::Round(($otherSize / $drive.Size) * 100, 1)
                    }
                }
                catch { 
                }
            }
        }
        
        $diskPath = Join-Path $OutputPath $Computer "10_Disco"
        
        $diskAnalysis | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_Analise_Disco.csv") -NoTypeInformation -Encoding UTF8
        
        $diskReport = @"
Analise de Utilizacao de Disco Detalhada
========================================
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
Metodo: $($disk.Method)

"@
        }
        
        if ($folderAnalysis.Count -gt 0) {
            $diskReport += @"

Analise de Diretorios por Drive:
================================
"@
            
            foreach ($driveId in ($folderAnalysis.Drive | Sort-Object -Unique)) {
                $driveFolders = $folderAnalysis | Where-Object { $_.Drive -eq $driveId } | Sort-Object SizeGB -Descending
                $diskReport += @"

Drive $driveId - Principais Diretorios:
"@
                foreach ($folder in ($driveFolders | Select-Object -First 20)) {
                    $diskReport += @"
$($folder.VisualBar) $($folder.FolderName)
  Tamanho: $($folder.SizeGB) GB ($($folder.PercentOfDrive)% do drive)
  Arquivos: $($folder.FileCount) | Proprietario: $($folder.Owner)
  Caminho: $($folder.FullPath)

"@
                }
            }
        }
        
        if ($userAnalysis.Count -gt 0) {
            $diskReport += @"

Agrupamento por Usuario/Sistema:
===============================
"@
            foreach ($userGroup in $userAnalysis) {
                $diskReport += @"

Drive $($userGroup.Drive):
Sistema: $($userGroup.SystemSizeGB) GB ($($userGroup.SystemPercent)%)
Usuario: $($userGroup.UserSizeGB) GB ($($userGroup.UserPercent)%)
Outros: $($userGroup.OtherSizeGB) GB ($($userGroup.OtherPercent)%)

"@
            }
        }
        
        $diskReport | Out-File -FilePath (Join-Path $diskPath "${Timestamp}_Analise_Disco.txt") -Encoding UTF8
        
        if ($folderAnalysis.Count -gt 0) {
            $folderAnalysis | Sort-Object SizeGB -Descending | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_Analise_Pastas.csv") -NoTypeInformation -Encoding UTF8
            $folderAnalysis | Sort-Object SizeGB -Descending | Format-Table -AutoSize | Out-File -FilePath (Join-Path $diskPath "${Timestamp}_Analise_Pastas.txt") -Encoding UTF8
        }
        
        if ($userAnalysis.Count -gt 0) {
            $userAnalysis | Export-Csv -Path (Join-Path $diskPath "${Timestamp}_Agrupamento_Usuario.csv") -NoTypeInformation -Encoding UTF8
            $userAnalysis | Format-Table -AutoSize | Out-File -FilePath (Join-Path $diskPath "${Timestamp}_Agrupamento_Usuario.txt") -Encoding UTF8
        }
        
        Write-Host "  Analise de disco detalhada concluida" -ForegroundColor Green
        return @{
            DiskAnalysis   = $diskAnalysis
            FolderAnalysis = $folderAnalysis
            UserAnalysis   = $userAnalysis
        }
    }
    catch {
        Write-Warning "Erro na analise de disco para $Computer : $($_.Exception.Message)"
        return @{
            DiskAnalysis   = @()
            FolderAnalysis = @()
            UserAnalysis   = @()
        }
    }
}

# Funcao para analise de processos Java suspeitos
function Get-JavaProcessAnalysis {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $javaProcesses = @()
    $suspiciousJava = @()
    
    Write-Host "  • Analisando processos Java..." -ForegroundColor White
    
    try {
        if ($isLocal) {
            $processes = Get-Process | Where-Object { $_.ProcessName -match "java|javaw|javac" -or $_.MainWindowTitle -match "java" }
            
            foreach ($proc in $processes) {
                try {
                    $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                    $executablePath = $proc.Path
                    
                    $javaProcesses += [PSCustomObject]@{
                        ProcessName    = $proc.ProcessName
                        ProcessId      = $proc.Id
                        CommandLine    = $commandLine
                        ExecutablePath = $executablePath
                        WorkingSet     = [math]::Round($proc.WorkingSet / 1MB, 2)
                        StartTime      = $proc.StartTime
                        WindowTitle    = $proc.MainWindowTitle
                    }
                    
                    $suspiciousIndicators = @()
                    if ($commandLine) {
                        $suspiciousKeywords = @("crack", "keygen", "patch", "hack", "bypass", "serial", "license", "activation")
                        foreach ($keyword in $suspiciousKeywords) {
                            if ($commandLine.ToLower() -match $keyword) {
                                $suspiciousIndicators += "Palavra-chave suspeita: $keyword"
                            }
                        }
                        
                        if ($commandLine -match "temp|tmp|users\\.*\\appdata\\local\\temp") {
                            $suspiciousIndicators += "Executando de diretorio temporario"
                        }
                        
                        if ($executablePath -and (Test-Path $executablePath)) {
                            try {
                                $signature = Get-AuthenticodeSignature $executablePath -ErrorAction SilentlyContinue
                                if ($signature.Status -ne "Valid") {
                                    $suspiciousIndicators += "Assinatura digital invalida ou ausente"
                                }
                            }
                            catch { 
                            }
                        }
                    }
                    
                    if ($suspiciousIndicators.Count -gt 0) {
                        $suspiciousJava += [PSCustomObject]@{
                            ProcessName          = $proc.ProcessName
                            ProcessId            = $proc.Id
                            CommandLine          = $commandLine
                            ExecutablePath       = $executablePath
                            SuspiciousIndicators = $suspiciousIndicators -join "; "
                            RiskLevel            = if ($suspiciousIndicators.Count -gt 2) {
                                "ALTO" 
                            } 
                            elseif ($suspiciousIndicators.Count -gt 1) {
                                "MEDIO" 
                            } 
                            else {
                                "BAIXO" 
                            }
                        }
                    }
                }
                catch { 
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao analisar processos Java: $($_.Exception.Message)"
    }
    
    $procPath = Join-Path $OutputPath $Computer "06_Processos"
    
    if ($javaProcesses.Count -gt 0) {
        $javaProcesses | Export-Csv -Path (Join-Path $procPath "${Timestamp}_Processos_Java.csv") -NoTypeInformation -Encoding UTF8
        $javaProcesses | Format-Table -AutoSize | Out-File -FilePath (Join-Path $procPath "${Timestamp}_Processos_Java.txt") -Encoding UTF8 -Width 300
    }
    
    if ($suspiciousJava.Count -gt 0) {
        $suspiciousJava | Export-Csv -Path (Join-Path $procPath "${Timestamp}_Java_Suspeito.csv") -NoTypeInformation -Encoding UTF8
        
        $javaReport = @"
Relatorio de Processos Java Suspeitos
=====================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de processos Java suspeitos: $($suspiciousJava.Count)

Processos que requerem verificacao:

"@
        $counter = 1
        foreach ($java in $suspiciousJava) {
            $javaReport += @"
$counter. Processo: $($java.ProcessName) (PID: $($java.ProcessId))
   Nivel de Risco: $($java.RiskLevel)
   Caminho: $($java.ExecutablePath)
   Indicadores: $($java.SuspiciousIndicators)
   Linha de Comando: $($java.CommandLine)

"@
            $counter++
        }
        
        $javaReport | Out-File -FilePath (Join-Path $procPath "${Timestamp}_Java_Suspeito.txt") -Encoding UTF8
    }
    
    return @{
        JavaProcesses  = $javaProcesses
        SuspiciousJava = $suspiciousJava
    }
}

# Funcao para analise de logs de eventos com traducao melhorada
function Get-EventLogAnalysis {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $eventAnalysis = @()
    
    Write-Host "Coletando logs de eventos criticos..." -ForegroundColor Cyan
    
    try {
        $logCategories = @("System", "Application", "Security")
        
        foreach ($logName in $logCategories) {
            Write-Host "  • Coletando eventos do log $logName..." -ForegroundColor White
            
            try {
                $events = @()
                
                if ($isLocal) {
                    $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue | 
                        Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Critical" -or $_.Id -in $Script:EVENT_TRANSLATION.Keys }
                }
                else {
                    $events = Get-WinEvent -ComputerName $Computer -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue | 
                        Where-Object { $_.LevelDisplayName -eq "Error" -or $_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Critical" -or $_.Id -in $Script:EVENT_TRANSLATION.Keys }
                }
                
                foreach ($event in $events) {
                    $translatedDescription = if ($Script:EVENT_TRANSLATION.ContainsKey($event.Id.ToString())) {
                        $Script:EVENT_TRANSLATION[$event.Id.ToString()]
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
                                "CRITICO" 
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
                        Method                = "Get-WinEvent"
                    }
                }
                
                Write-Host "    - Coletados $(($events | Measure-Object).Count) eventos de $logName" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Erro ao coletar eventos do log $logName : $($_.Exception.Message)"
            }
        }
        
        $logPath = Join-Path $OutputPath $Computer "11_Eventos"
        
        $eventAnalysis | Sort-Object TimeCreated -Descending | Export-Csv -Path (Join-Path $logPath "${Timestamp}_Logs_Eventos_Completos.csv") -NoTypeInformation -Encoding UTF8
        $eventAnalysis | Sort-Object TimeCreated -Descending | Format-Table TimeCreated, LogName, Id, Severity, Source, TranslatedDescription -AutoSize | Out-File -FilePath (Join-Path $logPath "${Timestamp}_Logs_Eventos_Completos.txt") -Encoding UTF8 -Width 300
        
        $logReport = @"
Analise de Logs de Eventos do Sistema
=====================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de eventos coletados: $($eventAnalysis.Count)
Metodo de Coleta: Get-WinEvent

Eventos Criticos (ultimas 24 horas):
==================================
"@
        
        $criticalEvents = $eventAnalysis | Where-Object { $_.Level -eq "Critical" -and $_.TimeCreated -gt (Get-Date).AddDays(-1) } | Sort-Object TimeCreated -Descending | Select-Object -First 20
        if ($criticalEvents.Count -gt 0) {
            foreach ($event in $criticalEvents) {
                $logReport += "`n$($event.Severity) ID: $($event.Id) - $($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))`n"
                $logReport += "Fonte: $($event.Source)`n"
                $logReport += "Traducao: $($event.TranslatedDescription)`n"
                $logReport += "Descricao: $($event.Description -replace "`r`n", " " -replace "`n", " ")`n`n"
            }
        }
        else {
            $logReport += "`nNenhum evento critico nas ultimas 24 horas.`n"
        }
        
        $logReport += @"

Erros Mais Frequentes (ultimos 7 dias):
=======================================
"@
        
        $frequentErrors = $eventAnalysis | Where-Object { $_.Level -eq "Error" -and $_.TimeCreated -gt (Get-Date).AddDays(-7) } | 
            Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10
        
        foreach ($errorGroup in $frequentErrors) {
            $sampleEvent = ($eventAnalysis | Where-Object { $_.Id -eq $errorGroup.Name } | Select-Object -First 1)
            $logReport += "`nID: $($errorGroup.Name) - Ocorrencias: $($errorGroup.Count)`n"
            $logReport += "Traducao: $($sampleEvent.TranslatedDescription)`n"
            $logReport += "Fonte: $($sampleEvent.Source)`n"
            $logReport += "Ultima ocorrencia: $($sampleEvent.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))`n`n"
        }
        
        $logReport += @"

Resumo por Categoria:
====================
Sistema: $(($eventAnalysis | Where-Object { $_.LogName -eq "System" }).Count) eventos
Aplicacao: $(($eventAnalysis | Where-Object { $_.LogName -eq "Application" }).Count) eventos
Seguranca: $(($eventAnalysis | Where-Object { $_.LogName -eq "Security" }).Count) eventos

Resumo por Severidade:
=====================
Critico: $(($eventAnalysis | Where-Object { $_.Level -eq "Critical" }).Count) eventos
Erro: $(($eventAnalysis | Where-Object { $_.Level -eq "Error" }).Count) eventos
Aviso: $(($eventAnalysis | Where-Object { $_.Level -eq "Warning" }).Count) eventos

Eventos de Seguranca Relevantes:
===============================
"@
        
        $securityEvents = $eventAnalysis | Where-Object { $_.LogName -eq "Security" -and $_.Id -in @("4624", "4625", "4720", "4726", "4740") } | 
            Sort-Object TimeCreated -Descending | Select-Object -First 15
        
        foreach ($secEvent in $securityEvents) {
            $logReport += "$($secEvent.Severity) ID: $($secEvent.Id) - $($secEvent.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))`n"
            $logReport += "Traducao: $($secEvent.TranslatedDescription)`n"
        }
        
        $logReport | Out-File -FilePath (Join-Path $logPath "${Timestamp}_Logs_Eventos_Traduzidos.txt") -Encoding UTF8
        
        foreach ($logName in $logCategories) {
            $categoryEvents = $eventAnalysis | Where-Object { $_.LogName -eq $logName }
            if ($categoryEvents.Count -gt 0) {
                $categoryEvents | Sort-Object TimeCreated -Descending | Export-Csv -Path (Join-Path $logPath "${Timestamp}_Eventos_$logName.csv") -NoTypeInformation -Encoding UTF8
                $categoryEvents | Sort-Object TimeCreated -Descending | 
                    Select-Object TimeCreated, Id, Level, Source, TranslatedDescription, Severity | 
                        Format-Table -AutoSize | 
                            Out-File -FilePath (Join-Path $logPath "${Timestamp}_Eventos_$logName.txt") -Encoding UTF8 -Width 200
            }
        }
        
        Write-Host "  Logs de eventos coletados: $($eventAnalysis.Count) eventos" -ForegroundColor Green
        return $eventAnalysis
    }
    catch {
        Write-Warning "Erro na analise de logs de eventos: $($_.Exception.Message)"
        return @()
    }
}

# Funcao para gerar relatorio de eventos com linha de tempo organizado
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
    
    $eventCategories = @{
        "System"      = $EventAnalysis | Where-Object { $_.LogName -eq "System" }
        "Security"    = $EventAnalysis | Where-Object { $_.LogName -eq "Security" }
        "Application" = $EventAnalysis | Where-Object { $_.LogName -eq "Application" }
        "BSOD_Kernel" = $EventAnalysis | Where-Object { $_.Id -in @("41", "1003", "6008") }
        "Disk_Events" = $EventAnalysis | Where-Object { $_.Id -in @("7", "11", "51") }
        "Network"     = $EventAnalysis | Where-Object { $_.Id -in @("4201", "4202", "5152", "5156") }
        "Hardware"    = $EventAnalysis | Where-Object { $_.Id -in @("6", "219") }
    }
    
    $criticityOrder = @("CRITICO", "ERRO", "AVISO", "INFO")
    
    $timelineReport = @"
Linha de Tempo de Eventos do Sistema
====================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer
Total de eventos analisados: $($EventAnalysis.Count)

Eventos ordenados cronologicamente (mais recentes primeiro):

"@
    
    $sortedEvents = $EventAnalysis | Sort-Object TimeCreated -Descending
    foreach ($event in $sortedEvents) {
        $timelineReport += "[$($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))] $($event.Severity) - ID:$($event.Id)`n"
        $timelineReport += "Fonte: $($event.Source) | Categoria: $($event.LogName)`n"
        $timelineReport += "Descricao: $($event.TranslatedDescription)`n`n"
    }
    
    $timelineReport | Out-File -FilePath (Join-Path $eventPath "${Timestamp}_Timeline_Eventos.txt") -Encoding UTF8
    $EventAnalysis | Export-Csv -Path (Join-Path $eventPath "${Timestamp}_Timeline_Eventos.csv") -NoTypeInformation -Encoding UTF8
    
    $familyReport = @"
Linha de Tempo de Eventos por Familia e Criticidade
===================================================
Data/Hora: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
Sistema: $Computer

"@
    
    foreach ($categoryName in $eventCategories.Keys) {
        $categoryEvents = $eventCategories[$categoryName]
        if ($categoryEvents.Count -gt 0) {
            $familyReport += "`nFAMILIA: $categoryName ($($categoryEvents.Count) eventos)`n"
            $familyReport += "================================================`n`n"
            
            foreach ($criticality in $criticityOrder) {
                $criticalEvents = $categoryEvents | Where-Object { $_.Severity -eq $criticality } | Sort-Object TimeCreated -Descending
                if ($criticalEvents.Count -gt 0) {
                    $familyReport += "--- $criticality ($($criticalEvents.Count) eventos) ---`n`n"
                    foreach ($event in $criticalEvents) {
                        $familyReport += "[$($event.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss'))] ID:$($event.Id) - $($event.TranslatedDescription)`n"
                    }
                    $familyReport += "`n"
                }
            }
        }
    }
    
    $familyReport | Out-File -FilePath (Join-Path $eventPath "${Timestamp}_Timeline_Por_Familia.txt") -Encoding UTF8
    
    foreach ($categoryName in $eventCategories.Keys) {
        $categoryEvents = $eventCategories[$categoryName]
        if ($categoryEvents.Count -gt 0) {
            $categoryEvents | Export-Csv -Path (Join-Path $eventPath "${Timestamp}_Eventos_${categoryName}.csv") -NoTypeInformation -Encoding UTF8
            $categoryEvents | Format-Table TimeCreated, Id, Severity, Source, TranslatedDescription -AutoSize | Out-File -FilePath (Join-Path $eventPath "${Timestamp}_Eventos_${categoryName}.txt") -Encoding UTF8
        }
    }
    
    Write-Host "Relatorios de linha de tempo de eventos criados" -ForegroundColor Green
}

# Funcao para analise de configuracoes de seguranca
function Get-SecurityConfigurationAnalysis {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Timestamp
    )
    
    $isLocal = ($Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME -or $Computer -eq ".")
    $securityResults = @{}
    
    Write-Host "  • Analisando configuracoes de seguranca..." -ForegroundColor White
    
    try {
        if ($isLocal) {
            try {
                $securityResults.LocalUsers = Get-LocalUser -ErrorAction Stop
                $securityResults.LocalGroups = Get-LocalGroup -ErrorAction Stop
                $securityResults.LocalUsers | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-LocalUser"
                $securityResults.LocalGroups | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-LocalGroup"
            }
            catch {
                try {
                    $securityResults.LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
                    $securityResults.LocalGroups = Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True" -ErrorAction Stop
                    $securityResults.LocalUsers | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                    $securityResults.LocalGroups | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $netUserOutput = cmd /c "net user 2>nul"
                    $netGroupOutput = cmd /c "net localgroup 2>nul"
                    $securityResults.LocalUsers = $netUserOutput
                    $securityResults.LocalGroups = $netGroupOutput
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter usuarios e grupos: $($_.Exception.Message)"
    }
    
    try {
        if ($isLocal) {
            try {
                $securityResults.FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
                $securityResults.FirewallRules = Get-NetFirewallRule -Enabled True -ErrorAction Stop | Select-Object -First 100
                $securityResults.FirewallProfiles | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-NetFirewallProfile"
            }
            catch {
                $netshOutput = cmd /c "netsh advfirewall show allprofiles 2>nul"
                $securityResults.FirewallProfiles = $netshOutput
                $securityResults.FirewallProfiles | Add-Member -NotePropertyName "Method" -NotePropertyValue "netsh"
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter configuracoes de firewall: $($_.Exception.Message)"
    }
    
    try {
        if ($isLocal) {
            $auditpolOutput = cmd /c "auditpol /get /category:* 2>nul"
            if ($auditpolOutput) {
                $securityResults.AuditPolicies = $auditpolOutput
                $securityResults.AuditPolicies | Add-Member -NotePropertyName "Method" -NotePropertyValue "auditpol"
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter politicas de auditoria: $($_.Exception.Message)"
    }
    
    try {
        if ($isLocal) {
            try {
                $securityResults.NetworkShares = Get-SmbShare -ErrorAction Stop
                $securityResults.NetworkShares | Add-Member -NotePropertyName "Method" -NotePropertyValue "Get-SmbShare"
            }
            catch {
                try {
                    $securityResults.NetworkShares = Get-WmiObject -Class Win32_Share -ErrorAction Stop
                    $securityResults.NetworkShares | Add-Member -NotePropertyName "Method" -NotePropertyValue "WMI"
                }
                catch {
                    $netShareOutput = cmd /c "net share 2>nul"
                    $securityResults.NetworkShares = $netShareOutput
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter compartilhamentos: $($_.Exception.Message)"
    }
    
    try {
        if ($isLocal) {
            $criticalPaths = @("C:\Windows", "C:\Program Files", "C:\Users")
            $securityResults.DirectoryPermissions = @()
            
            foreach ($path in $criticalPaths) {
                if (Test-Path $path) {
                    try {
                        $acl = Get-Acl $path -ErrorAction SilentlyContinue
                        if ($acl) {
                            $securityResults.DirectoryPermissions += [PSCustomObject]@{
                                Path        = $path
                                Owner       = $acl.Owner
                                AccessRules = ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights):$($_.AccessControlType)" }) -join "; "
                                Method      = "Get-Acl"
                            }
                        }
                    }
                    catch { 
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Erro ao obter permissoes de diretorios: $($_.Exception.Message)"
    }
    
    $secPath = Join-Path $OutputPath $Computer "12_Seguranca"
    
    if ($securityResults.LocalUsers) {
        $securityResults.LocalUsers | Export-Csv -Path (Join-Path $secPath "${Timestamp}_Usuarios_Locais.csv") -NoTypeInformation -Encoding UTF8
        $securityResults.LocalUsers | Format-Table -AutoSize | Out-File -FilePath (Join-Path $secPath "${Timestamp}_Usuarios_Locais.txt") -Encoding UTF8
    }
    
    if ($securityResults.LocalGroups) {
        $securityResults.LocalGroups | Export-Csv -Path (Join-Path $secPath "${Timestamp}_Grupos_Locais.csv") -NoTypeInformation -Encoding UTF8
        $securityResults.LocalGroups | Format-Table -AutoSize | Out-File -FilePath (Join-Path $secPath "${Timestamp}_Grupos_Locais.txt") -Encoding UTF8
    }
    
    if ($securityResults.FirewallProfiles) {
        $securityResults.FirewallProfiles | Export-Csv -Path (Join-Path $secPath "${Timestamp}_Firewall_Profiles.csv") -NoTypeInformation -Encoding UTF8
        $securityResults.FirewallProfiles | Format-Table -AutoSize | Out-File -FilePath (Join-Path $secPath "${Timestamp}_Firewall_Profiles.txt") -Encoding UTF8
    }
    
    if ($securityResults.NetworkShares) {
        $securityResults.NetworkShares | Export-Csv -Path (Join-Path $secPath "${Timestamp}_Compartilhamentos.csv") -NoTypeInformation -Encoding UTF8
        $securityResults.NetworkShares | Format-Table -AutoSize | Out-File -FilePath (Join-Path $secPath "${Timestamp}_Compartilhamentos.txt") -Encoding UTF8
    }
    
    if ($securityResults.DirectoryPermissions) {
        $securityResults.DirectoryPermissions | Export-Csv -Path (Join-Path $secPath "${Timestamp}_Permissoes_Diretorios.csv") -NoTypeInformation -Encoding UTF8
        $securityResults.DirectoryPermissions | Format-Table -AutoSize | Out-File -FilePath (Join-Path $secPath "${Timestamp}_Permissoes_Diretorios.txt") -Encoding UTF8
    }
    
    return $securityResults
}

# Funcao para criar pagina HTML simplificada (sem CSS complexo)
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
        body { font-family: Arial, sans-serif; margin: 20px; }
        .folder { margin: 10px 0; }
        .folder-name { font-weight: bold; cursor: pointer; padding: 5px; background-color: #f0f0f0; }
        .file-list { margin-left: 20px; display: none; }
        .file-item { padding: 3px; cursor: pointer; color: blue; }
        .content-frame { width: 100%; height: 500px; border: 1px solid #ccc; }
    </style>
    <script>
        function toggleFolder(element) {
            const fileList = element.nextElementSibling;
            fileList.style.display = fileList.style.display === 'none' ? 'block' : 'none';
        }
        
        function loadFile(filePath) {
            document.getElementById('contentFrame').src = filePath;
        }
    </script>
</head>
<body>
    <h1>Relatorio de Auditoria - $Computer</h1>
    <p>Sistema: $Computer | Gerado em: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') | Timestamp: $Timestamp</p>
    
    <h2>Estrutura de Arquivos</h2>
"@

    foreach ($folderName in ($Script:FOLDER_STRUCTURE.Keys | Sort-Object)) {
        $folderPath = Join-Path $OutputPath $Computer $folderName
        $description = $Script:FOLDER_STRUCTURE[$folderName]
        
        $htmlContent += @"
    <div class="folder">
        <div class="folder-name" onclick="toggleFolder(this)">$folderName ($description)</div>
        <div class="file-list">
"@
        
        if (Test-Path $folderPath) {
            $files = Get-ChildItem -Path $folderPath -File | Sort-Object Name
            foreach ($file in $files) {
                $relativePath = "./$Computer/$folderName/$($file.Name)"
                $htmlContent += @"
            <div class="file-item" onclick="loadFile('$relativePath')">$($file.Name)</div>
"@
            }
        }
        
        $htmlContent += @"
        </div>
    </div>
"@
    }

    $htmlContent += @"
    
    <h2>Conteudo do Arquivo</h2>
    <iframe id="contentFrame" class="content-frame"></iframe>
</body>
</html>
"@

    $htmlPath = Join-Path $OutputPath "$Computer.html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-Host "Pagina HTML criada: $htmlPath" -ForegroundColor Green
    return $htmlPath
}

# Funcao para gerar relatorio final consolidado
function New-ConsolidatedReportComplete {
    param(
        [string]$Computer,
        [string]$OutputPath,
        [string]$Domain,
        [string]$Timestamp,
        [hashtable]$SystemInfo,
        [array]$SoftwareList,
        [hashtable]$DiskResults,
        [hashtable]$NetworkResults,
        [hashtable]$JavaResults,
        [array]$EventAnalysis
    )
    
    Write-Host "Gerando relatorio consolidado completo..." -ForegroundColor Cyan
    
    try {
        $reportPath = Join-Path $OutputPath $Computer "14_Relatorio"
        
        $totalSoftware = if ($SoftwareList) {
            $SoftwareList.Count 
        }
        else {
            0 
        }
        $suspiciousSoftware = if ($SoftwareList) {
            $SoftwareList | Where-Object { 
                $name = $_.ProgramName.ToLower()
                @("eval", "trial", "demo", "crack", "keygen", "patch", "portable", "unknown") | ForEach-Object { 
                    if ($name -match $_) {
                        return $true 
                    } 
                }
            }
        }
        else {
            @() 
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
        
        $suspiciousJava = if ($JavaResults.SuspiciousJava) {
            $JavaResults.SuspiciousJava.Count 
        }
        else {
            0 
        }
        $suspiciousNetwork = if ($NetworkResults.SuspiciousActivity) {
            $NetworkResults.SuspiciousActivity.Count 
        }
        else {
            0 
        }
        
        $auditDuration = if ($Global:AuditStartTime) {
 ((Get-Date) - $Global:AuditStartTime).ToString('hh\:mm\:ss') 
        }
        else {
            "Nao disponivel" 
        }
        
        $consolidatedReport = @"
################################################################################
                    Relatorio de Auditoria Tecnica - Sistema SCADA
################################################################################

 Informacoes Gerais:
================================================================================
Sistema Analisado: $Computer
Dominio/Ambiente: $Domain
Data/Hora da Auditoria: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
$Script:SCRIPT_HEADER
Duracao da Analise: $auditDuration

 Status Geral do Sistema:
================================================================================
$(if ($SystemInfo.OSInfo) { "Sistema Operacional: $($SystemInfo.OSInfo.Caption) $($SystemInfo.OSInfo.Version)" } else { "Sistema Operacional: Nao disponivel" })
$(if ($SystemInfo.OSInfo -and $SystemInfo.OSInfo.LastBootUpTime) { "Ultimo Boot: $($SystemInfo.OSInfo.LastBootUpTime)" } else { "Ultimo Boot: Nao disponivel" })

 Resumo Executivo - Indicadores Tecnicos:
================================================================================
• Software Instalado: $totalSoftware programas
• Programas Suspeitos: $($suspiciousSoftware.Count) requerem verificacao manual
• Servicos do Sistema: $totalServices ($runningServices executando)
• Processos em Execucao: $totalProcesses
• Drivers do Sistema: $totalDrivers ($loadedDrivers carregados)
• Atualizacoes/Patches: $totalUpdates aplicadas
• Eventos Criticos (7 dias): $criticalEvents
• Eventos de Erro (7 dias): $errorEvents
• Processos Java Suspeitos: $suspiciousJava
• Atividades de Rede Incomuns: $suspiciousNetwork

 Analise de Armazenamento:
================================================================================
"@

        if ($DiskResults.DiskAnalysis -and $DiskResults.DiskAnalysis.Count -gt 0) {
            foreach ($disk in $DiskResults.DiskAnalysis) {
                $consolidatedReport += @"
Drive $($disk.Drive) [$($disk.Label)] - $($disk.Status)
$($disk.VisualBar)
Total: $($disk.TotalGB) GB | Usado: $($disk.UsedGB) GB | Livre: $($disk.FreeGB) GB
Metodo: $($disk.Method)

"@
            }
        }
        else {
            $consolidatedReport += "Informacoes de disco nao disponiveis`n"
        }

        $consolidatedReport += @"

 Analise de Rede e Conectividade:
================================================================================
"@

        if ($NetworkResults.Adapters) {
            $consolidatedReport += "• Adaptadores de Rede: $($NetworkResults.Adapters.Count)`n"
        }
        
        if ($NetworkResults.Teams -and $NetworkResults.Teams.Count -gt 0) {
            $consolidatedReport += "• Teams Configurados: $($NetworkResults.Teams.Count)`n"
            foreach ($team in $NetworkResults.Teams) {
                $consolidatedReport += "  - $($team.Name): $($team.Status) - $($team.TeamingMode)`n"
            }
        }
        else {
            $consolidatedReport += "• Teams de Rede: Nenhum configurado`n"
        }
        
        if ($NetworkResults.Connections) {
            $consolidatedReport += "• Conexoes TCP Ativas: $($NetworkResults.Connections.Count)`n"
        }

        $consolidatedReport += @"

 Analise de Seguranca:
================================================================================
"@

        if ($suspiciousJava -gt 0) {
            $consolidatedReport += "ALERTA: $suspiciousJava processos Java suspeitos detectados - Requerem verificacao manual`n"
        }
        
        if ($suspiciousNetwork -gt 0) {
            $consolidatedReport += "ALERTA: $suspiciousNetwork atividades de rede incomuns detectadas`n"
        }
        
        if ($suspiciousSoftware.Count -gt 0) {
            $consolidatedReport += "ALERTA: $($suspiciousSoftware.Count) programas suspeitos detectados:`n"
            foreach ($software in ($suspiciousSoftware | Select-Object -First 5)) {
                $consolidatedReport += "  - $($software.ProgramName)`n"
            }
            if ($suspiciousSoftware.Count -gt 5) {
                $consolidatedReport += "  ... e mais $($suspiciousSoftware.Count - 5) programas`n"
            }
        }

        $consolidatedReport += @"

 Eventos Criticos Recentes:
================================================================================
"@

        if ($criticalEvents -gt 0) {
            $recentCritical = $EventAnalysis | Where-Object { $_.Level -eq "Critical" -and $_.TimeCreated -gt (Get-Date).AddDays(-7) } | 
                Sort-Object TimeCreated -Descending | Select-Object -First 5
            
            foreach ($event in $recentCritical) {
                $consolidatedReport += "$($event.TimeCreated.ToString('dd/MM/yyyy HH:mm')) - ID:$($event.Id) - $($event.TranslatedDescription)`n"
            }
        }
        else {
            $consolidatedReport += "Nenhum evento critico nos ultimos 7 dias.`n"
        }

        $consolidatedReport += @"

 Recomendacoes Tecnicas:
================================================================================
"@

        $recommendations = @()
        
        if ($DiskResults.DiskAnalysis) {
            $criticalDisks = $DiskResults.DiskAnalysis | Where-Object { $_.UsedPercent -gt 90 }
            if ($criticalDisks.Count -gt 0) {
                $recommendations += "• URGENTE: Limpar espaco em disco nos drives: $(($criticalDisks.Drive) -join ', ')"
            }
            
            $warningDisks = $DiskResults.DiskAnalysis | Where-Object { $_.UsedPercent -gt 80 -and $_.UsedPercent -le 90 }
            if ($warningDisks.Count -gt 0) {
                $recommendations += "• Monitorar utilizacao de disco nos drives: $(($warningDisks.Drive) -join ', ')"
            }
        }
        
        if ($criticalEvents -gt 5) {
            $recommendations += "• Investigar eventos criticos do sistema ($criticalEvents eventos nos ultimos 7 dias)"
        }
        
        if ($errorEvents -gt 20) {
            $recommendations += "• Analisar erros recorrentes do sistema ($errorEvents eventos nos ultimos 7 dias)"
        }
        
        if ($suspiciousJava -gt 0) {
            $recommendations += "• Verificar manualmente os $suspiciousJava processos Java suspeitos"
        }
        
        if ($suspiciousNetwork -gt 0) {
            $recommendations += "• Investigar $suspiciousNetwork atividades de rede incomuns"
        }
        
        if ($SystemInfo.OSInfo -and $SystemInfo.OSInfo.LastBootUpTime) {
            $bootTime = if ($SystemInfo.OSInfo.LastBootUpTime -is [string]) {
                [DateTime]::ParseExact($SystemInfo.OSInfo.LastBootUpTime.Substring(0, 14), "yyyyMMddHHmmss", $null)
            }
            else {
                $SystemInfo.OSInfo.LastBootUpTime
            }
            $uptimeDays = ((Get-Date) - $bootTime).TotalDays
            if ($uptimeDays -gt 30) {
                $recommendations += "• Considerar reinicializacao do sistema (uptime: $([math]::Round($uptimeDays, 1)) dias)"
            }
        }
        
        if ($recommendations.Count -eq 0) {
            $consolidatedReport += "• Sistema esta funcionando dentro dos parametros normais`n"
        }
        else {
            $consolidatedReport += ($recommendations -join "`n") + "`n"
        }

        $consolidatedReport += @"

 Detalhes Tecnicos da Coleta:
================================================================================
• Metodos Utilizados: $Script:SCRIPT_METHODS
• Compatibilidade: $Script:SCRIPT_COMPATIBILITY  
• Escopo da Analise: $Script:SCRIPT_SCOPE
• Timestamp da Execucao: $Timestamp
• Diretorios Analisados: $($Script:FOLDER_STRUCTURE.Count)
• Total de Arquivos Gerados: $(if (Test-Path (Join-Path $OutputPath $Computer)) { (Get-ChildItem -Path (Join-Path $OutputPath $Computer) -Recurse -File).Count } else { "Nao disponivel" })

 Arquivos de Saida Gerados:
================================================================================
"@

        foreach ($folderName in ($Script:FOLDER_STRUCTURE.Keys | Sort-Object)) {
            $folderPath = Join-Path $OutputPath $Computer $folderName
            $description = $Script:FOLDER_STRUCTURE[$folderName]
            
            if (Test-Path $folderPath) {
                $fileCount = (Get-ChildItem -Path $folderPath -File).Count
                $consolidatedReport += "$folderName ($description): $fileCount arquivos`n"
            }
            else {
                $consolidatedReport += "$folderName ($description): Pasta nao criada`n"
            }
        }

        $consolidatedReport += @"

################################################################################
                          FIM DO RELATORIO DE AUDITORIA
################################################################################
"@

        # Salvar relatorio consolidado
        $consolidatedReport | Out-File -FilePath (Join-Path $reportPath "Relatorio_Final_$Computer.txt") -Encoding UTF8
        
        # Salvar versao JSON estruturada para processamento posterior
        $jsonReport = @{
            SystemInfo      = @{
                Computer      = $Computer
                Domain        = $Domain
                Timestamp     = $Timestamp
                AuditDuration = $auditDuration
                OSInfo        = if ($SystemInfo.OSInfo) {
                    $SystemInfo.OSInfo.Caption + " " + $SystemInfo.OSInfo.Version 
                }
                else {
                    "Nao disponivel" 
                }
            }
            Metrics         = @{
                TotalSoftware      = $totalSoftware
                SuspiciousSoftware = $suspiciousSoftware.Count
                TotalServices      = $totalServices
                RunningServices    = $runningServices
                TotalProcesses     = $totalProcesses
                CriticalEvents     = $criticalEvents
                ErrorEvents        = $errorEvents
                SuspiciousJava     = $suspiciousJava
                SuspiciousNetwork  = $suspiciousNetwork
            }
            Recommendations = $recommendations
            Status          = if ($recommendations.Count -eq 0) {
                "OK" 
            } 
            elseif ($recommendations -match "URGENTE") {
                "CRITICO" 
            } 
            else {
                "ATENCAO" 
            }
        }
        
        $jsonReport | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $reportPath "Relatorio_Final_$Computer.json") -Encoding UTF8
        
        Write-Host "Relatorio consolidado gerado com sucesso!" -ForegroundColor Green
        Write-Host "  - Arquivo TXT: $(Join-Path $reportPath "Relatorio_Final_$Computer.txt")" -ForegroundColor Gray
        Write-Host "  - Arquivo JSON: $(Join-Path $reportPath "Relatorio_Final_$Computer.json")" -ForegroundColor Gray
        
        return @{
            ReportPath      = (Join-Path $reportPath "Relatorio_Final_$Computer.txt")
            JsonPath        = (Join-Path $reportPath "Relatorio_Final_$Computer.json")
            Status          = $jsonReport.Status
            Recommendations = $recommendations
        }
    }
    catch {
        Write-Warning "Erro ao gerar relatorio consolidado: $($_.Exception.Message)"
        return $null
    }
}

# Funcao principal para execucao da auditoria
function Start-SystemAudit {
    param(
        [string]$Computer = "localhost",
        [string]$OutputBasePath,
        [string]$Domain = "LOCAL"
    )
    
    $Global:AuditStartTime = Get-Date
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host "                    INICIANDO AUDITORIA TECNICA - SISTEMA SCADA" -ForegroundColor Cyan
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host "$Script:SCRIPT_HEADER" -ForegroundColor White
    Write-Host "Compatibilidade: $Script:SCRIPT_COMPATIBILITY" -ForegroundColor Gray
    Write-Host "Metodos: $Script:SCRIPT_METHODS" -ForegroundColor Gray
    Write-Host "Escopo: $Script:SCRIPT_SCOPE" -ForegroundColor Gray
    Write-Host "################################################################################" -ForegroundColor Cyan
    
    # Determinar caminho de saida
    if (-not $OutputBasePath) {
        $OutputBasePath = Join-Path (Get-Location) "Audit_Results_$timestamp"
    }
    
    # Criar estrutura de diretorios
    Write-Host "Criando estrutura de diretorios..." -ForegroundColor Yellow
    
    $computerPath = Join-Path $OutputBasePath $Computer
    foreach ($folderName in $Script:FOLDER_STRUCTURE.Keys) {
        $folderPath = Join-Path $computerPath $folderName
        if (-not (Test-Path $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }
    }
    
    Write-Host "Estrutura criada em: $OutputBasePath" -ForegroundColor Green
    
    # Verificacoes preliminares
    Write-Host "`nExecutando verificacoes preliminares..." -ForegroundColor Yellow
    $adminPrivilege = Test-AdminPrivilege
    $psVersion = Test-PowerShellVersion
    $osVersion = Test-OSVersion
    $currentEnvironment = Get-Environment
    
    if (-not $psVersion) {
        Write-Error "Versao do PowerShell incompativel. Interrompendo execucao."
        return
    }
    
    Write-Host "Ambiente detectado: $currentEnvironment" -ForegroundColor Cyan
    Write-Host "Target de auditoria: $Computer" -ForegroundColor Cyan
    
    # Iniciar coleta de dados
    Write-Host "`n################################################################################" -ForegroundColor Green
    Write-Host "                              INICIANDO COLETA DE DADOS" -ForegroundColor Green
    Write-Host "################################################################################" -ForegroundColor Green
    
    # 1. Informacoes do Sistema
    Write-Host "`n[1/8] Coletando informacoes completas do sistema..." -ForegroundColor Yellow
    $systemInfo = Get-SystemInformationComplete -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # 2. Software instalado
    Write-Host "`n[2/8] Analisando software instalado..." -ForegroundColor Yellow
    $softwareList = Get-RemoteProgram -ComputerName $Computer
    if ($softwareList -and $softwareList.Count -gt 0) {
        $softwarePath = Join-Path $OutputBasePath $Computer "03_Software"
        $softwareList | Export-Csv -Path (Join-Path $softwarePath "${timestamp}_Software_Instalado.csv") -NoTypeInformation -Encoding UTF8
        $softwareList | Format-Table -AutoSize | Out-File -FilePath (Join-Path $softwarePath "${timestamp}_Software_Instalado.txt") -Encoding UTF8 -Width 300
        Write-Host "  Software coletado: $($softwareList.Count) programas" -ForegroundColor Green
    }
    
    # 3. Analise de disco
    Write-Host "`n[3/8] Executando analise detalhada de disco..." -ForegroundColor Yellow
    $diskResults = Get-DiskUsageAnalysisComplete -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # 4. Analise de rede
    Write-Host "`n[4/8] Analisando configuracoes de rede..." -ForegroundColor Yellow
    $networkResults = Get-NetworkAnalysisComplete -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # 5. Processos Java
    Write-Host "`n[5/8] Verificando processos Java suspeitos..." -ForegroundColor Yellow
    $javaResults = Get-JavaProcessAnalysis -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # 6. Eventos do sistema
    Write-Host "`n[6/8] Coletando logs de eventos..." -ForegroundColor Yellow
    $eventAnalysis = Get-EventLogAnalysis -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # 7. Timeline de eventos
    Write-Host "`n[7/8] Gerando timeline de eventos..." -ForegroundColor Yellow
    New-EventTimelineReport -EventAnalysis $eventAnalysis -OutputPath $OutputBasePath -Computer $Computer -Timestamp $timestamp
    
    # 8. Configuracoes de seguranca
    Write-Host "`n[8/8] Analisando configuracoes de seguranca..." -ForegroundColor Yellow
    $securityResults = Get-SecurityConfigurationAnalysis -Computer $Computer -OutputPath $OutputBasePath -Timestamp $timestamp
    
    # Gerar relatorio final
    Write-Host "`n################################################################################" -ForegroundColor Magenta
    Write-Host "                           GERANDO RELATORIO FINAL" -ForegroundColor Magenta
    Write-Host "################################################################################" -ForegroundColor Magenta
    
    $finalReport = New-ConsolidatedReportComplete -Computer $Computer -OutputPath $OutputBasePath -Domain $Domain -Timestamp $timestamp -SystemInfo $systemInfo -SoftwareList $softwareList -DiskResults $diskResults -NetworkResults $networkResults -JavaResults $javaResults -EventAnalysis $eventAnalysis
    
    # Criar pagina HTML de navegacao
    Write-Host "`nCriando pagina HTML de navegacao..." -ForegroundColor Yellow
    $htmlPage = New-HTMLNavigationPage -OutputPath $OutputBasePath -Computer $Computer -Timestamp $timestamp
    
    # Resumo final
    Write-Host "`n################################################################################" -ForegroundColor Green
    Write-Host "                           AUDITORIA CONCLUIDA COM SUCESSO" -ForegroundColor Green
    Write-Host "################################################################################" -ForegroundColor Green
    
    $auditDuration = (Get-Date) - $Global:AuditStartTime
    Write-Host "Duracao total: $($auditDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Sistema auditado: $Computer" -ForegroundColor White
    Write-Host "Pasta de saida: $OutputBasePath" -ForegroundColor White
    Write-Host "Pagina HTML: $htmlPage" -ForegroundColor White
    
    if ($finalReport) {
        Write-Host "Status do sistema: $($finalReport.Status)" -ForegroundColor $(
            switch ($finalReport.Status) {
                "OK" {
                    "Green" 
                }
                "ATENCAO" {
                    "Yellow" 
                }
                "CRITICO" {
                    "Red" 
                }
                default {
                    "White" 
                }
            }
        )
        
        if ($finalReport.Recommendations -and $finalReport.Recommendations.Count -gt 0) {
            Write-Host "`nRecomendacoes principais:" -ForegroundColor Yellow
            $finalReport.Recommendations | Select-Object -First 3 | ForEach-Object {
                Write-Host "  $_" -ForegroundColor White
            }
        }
    }
    
    Write-Host "`nArquivos principais gerados:" -ForegroundColor Cyan
    Write-Host "  • Relatorio Final: $(Join-Path $OutputBasePath $Computer '14_Relatorio' "Relatorio_Final_$Computer.txt")" -ForegroundColor Gray
    Write-Host "  • Navegacao HTML: $htmlPage" -ForegroundColor Gray
    Write-Host "  • Dados JSON: $(Join-Path $OutputBasePath $Computer '14_Relatorio' "Relatorio_Final_$Computer.json")" -ForegroundColor Gray
    
    Write-Host "`n################################################################################" -ForegroundColor Green
    
    return @{
        OutputPath  = $OutputBasePath
        HtmlPage    = $htmlPage
        FinalReport = $finalReport
        Duration    = $auditDuration
        Status      = if ($finalReport) {
            $finalReport.Status 
        }
        else {
            "CONCLUIDO" 
        }
    }
}

# Funcao principal de entrada
function Invoke-SystemAudit {
    param(
        [ValidateSet("localhost", "ems", "pds", "custom")]
        [string]$Environment = "localhost",
        [string]$TargetComputer = "localhost",
        [string]$OutputBasePath = "",
        [switch]$ParallelExecution = $false,
        [int]$MaxParallelJobs = 5
    )
    
    try {
        # Limpar variaveis antigas
        Clear-AllVariable
        
        # Determinar computadores alvo
        $targetComputers = @()
        
        if ($Environment -eq "localhost" -or $Environment -eq "custom") {
            $targetComputers = @($TargetComputer)
        }
        else {
            $detectedEnvironment = Get-Environment
            $targetList = Get-TargetList -domain $detectedEnvironment
            $targetComputers = $targetList
            
            if ($targetComputers.Count -eq 0) {
                Write-Warning "Nenhum computador encontrado para o ambiente $detectedEnvironment"
                $targetComputers = @("localhost")
            }
        }
        
        Write-Host "Computadores a serem auditados: $($targetComputers.Count)" -ForegroundColor Cyan
        $targetComputers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
        
        # Determinar caminho base de saida
        if (-not $OutputBasePath) {
            $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
            $OutputBasePath = Join-Path (Get-Location) "Audit_Results_$timestamp"
        }
        
        # Executar auditoria
        $results = @()
        
        if ($ParallelExecution -and $targetComputers.Count -gt 1) {
            Write-Host "`nExecutando auditoria em paralelo (max $MaxParallelJobs jobs)..." -ForegroundColor Yellow
            
            $jobs = @()
            $jobQueue = [System.Collections.Queue]::new($targetComputers)
            
            while ($jobQueue.Count -gt 0 -or $jobs.Count -gt 0) {
                # Iniciar novos jobs se houver espaco
                while ($jobs.Count -lt $MaxParallelJobs -and $jobQueue.Count -gt 0) {
                    $computer = $jobQueue.Dequeue()
                    $job = Start-Job -ScriptBlock {
                        param($comp, $outputPath, $scriptContent)
                        
                        # Re-criar funcoes no contexto do job
                        Invoke-Expression $scriptContent
                        
                        return Start-SystemAudit -Computer $comp -OutputBasePath $outputPath -Domain "AUTO"
                    } -ArgumentList $computer, $OutputBasePath, $MyInvocation.MyCommand.Definition
                    
                    $jobs += $job
                    Write-Host "  Iniciado job para $computer (Job ID: $($job.Id))" -ForegroundColor Gray
                }
                
                # Verificar jobs completados
                $completedJobs = $jobs | Where-Object { $_.State -eq "Completed" }
                foreach ($job in $completedJobs) {
                    $result = Receive-Job -Job $job
                    $results += $result
                    Remove-Job -Job $job
                    $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
                    Write-Host "  Job $($job.Id) concluido" -ForegroundColor Green
                }
                
                # Aguardar um pouco antes de verificar novamente
                if ($jobs.Count -gt 0) {
                    Start-Sleep -Seconds 2
                }
            }
        }
        else {
            Write-Host "`nExecutando auditoria sequencial..." -ForegroundColor Yellow
            
            foreach ($computer in $targetComputers) {
                Write-Host "`n--- Auditando $computer ---" -ForegroundColor Cyan
                $result = Start-SystemAudit -Computer $computer -OutputBasePath $OutputBasePath -Domain (Get-Environment)
                $results += $result
            }
        }
        
        # Resumo final de todos os sistemas
        Write-Host "`n################################################################################" -ForegroundColor Magenta
        Write-Host "                              RESUMO GERAL DA AUDITORIA" -ForegroundColor Magenta
        Write-Host "################################################################################" -ForegroundColor Magenta
        
        Write-Host "Total de sistemas auditados: $($results.Count)" -ForegroundColor White
        Write-Host "Pasta principal de saida: $OutputBasePath" -ForegroundColor White
        
        $statusSummary = $results | Group-Object Status
        foreach ($status in $statusSummary) {
            $color = switch ($status.Name) {
                "OK" {
                    "Green" 
                }
                "ATENCAO" {
                    "Yellow" 
                }
                "CRITICO" {
                    "Red" 
                }
                default {
                    "White" 
                }
            }
            Write-Host "$($status.Name): $($status.Count) sistemas" -ForegroundColor $color
        }
        
        Write-Host "`nArquivos HTML de navegacao gerados:" -ForegroundColor Cyan
        foreach ($result in $results) {
            if ($result.HtmlPage) {
                Write-Host "  • $($result.HtmlPage)" -ForegroundColor Gray
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Erro durante a execucao da auditoria: $($_.Exception.Message)"
        Write-Error $_.ScriptStackTrace
        return $null
    }
    finally {
        # Limpeza final
        Clear-AllVariable
    }
}

# Exportar funcoes principais
Export-ModuleMember -Function Invoke-SystemAudit, Start-SystemAudit

# Execucao direta se chamado como script
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SystemAudit -Environment $Environment -TargetComputer $TargetComputer -OutputBasePath $OutputBasePath -ParallelExecution:$ParallelExecution -MaxParallelJobs $MaxParallelJobs
}