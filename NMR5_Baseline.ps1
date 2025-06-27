# Baseline_NMR5 9.0 para PIC.EE.0246
# Autor: Mauricio Menon
# Versão inicial: FAT NMR5 Houston (2018)
# Versão atual 20/07/2023
# Desenvolvido para PowerShell 5.1, versão instalada por padrão no WS2012R2 e W10
# Utiliza portas 445 e 139 para conexão com os servidores/consoles
# TO DO
# - Setar codificação para caracteres com acento
# - Reimplantar scriptblock que foi retirado para debug
# - Lista de conexoes com sucesso;

# Definicao de lista de consoles e servidores do EMS(inclui DTS) e PDS
# EMS Console and Server Lists
$EMSConsoleList = ('bitcon1', 'bitcon2', 'bitcon3', 'bitcon4', 'bitcon5', 'bitcon6', 'bitcon7', 'bitcon8', 'bitcon9', 'bitcon10', 'bitcon11', 'bitcon12', 'bitcon13', 'bitcon14', 'bitcon15', 'bitcon16', 'bitcon17', 'bitcon18', 'bitcon19', 'bitcon20', 'bitcon21', 'bitcon22', 'bitcon23', 'bitcon24', 'bitcon25', 'bitcon26', 'bitcon27', 'bitcon28', 'bitcon29', 'bitcon30', 'bitdtcon1', 'bitdtcon2', 'bitdtcon3', 'bitdtcon4', 'bitdtcon5', 'bitdtcon6', 'bitdtvaps1')
$EMSServerList = ('bitora1', 'bitora2', 'bithis1', 'bithis2', 'bitood1', 'bitood2', 'bitaps1', 'bitaps2', 'biticcp1', 'biticcp2', 'bitdmc1', 'bitdmc2', 'bitpcu1', 'bitpcu2', 'bitims1', 'bitims2', 'bitdtaps1')

# PDS Console and Server Lists
$PDSConsoleList = ('bitpdcon1', 'bitpdcon2', 'bitpdcon3', 'bitpdcon4')
$PDSServerList = ('bitpdaps1', 'bitpdvaps1', 'bitpdpcu1', 'bitpdora1', 'bitpdviccp1', 'bitpdvhis1')

# Limpar todas as variáveis da sessão atual
function Clear-AllVariable {
    $variables = Get-Variable -Scope Global -Exclude PWD, OLDPWD
    $variables | ForEach-Object {
        if ($_.Options -ne "Constant" -and $_.Options -ne "ReadOnly") {
            Set-Variable -Name $_.Name -Value $null -Force -ErrorAction SilentlyContinue
        }
    }
}

# Verificar execução como administrador
function Test-AdminPrivilege {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Este script deve ser executado com privilegios de administrador.'
    }
    else {
        write-warning 'Usuario Administrador'
    }
}

# Verificar a versão do PowerShell
function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    $versionFlag = 0

    # Imprimir a versão para o usuário
    Write-Host "Versao do PowerShell: $psVersion"

    # Verificar se é uma versão compatível (5.1, 6 ou 7)
    if ($psVersion.Major -eq 5 -and $psVersion.Minor -eq 1) {
        $versionFlag = 1
    }
    elseif ($psVersion.Major -gt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -ge 1)) {
        # elseif ($psVersion.Major -ge 6) {         #para pw 6 e acima existe o operador -ge
        #para implementação futura com powershell 6 ou 7
        $versionFlag = 2
    }
    else {
        # Versão inferior a 5
        Write-Host "A versao do PowerShell nao e suportada."
        return
    }
    return $versionFlag
}

# Função para verificar a versão do sistema operacional
function Test-OSVersion {
    #$osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
    $osVersion = (Get-CimInstance -ClassName CIM_OperatingSystem).Version

    # Verificar se é o Windows Server 2012
    # if ($osVersion -notmatch '6\.2|6\.3') {       # Aqui testa para ws2012 e ws2012r2
    if ($osVersion -notmatch '6\.3') {
        Write-Host "Atencao: Este script foi otimizado para o Windows Server 2012 R2. Alguns recursos podem nao funcionar corretamente nesta versao do sistema operacional."
    }
    return $osVersion
}

# Obter o tempo limite de conexão, utilizado para PS6/7. PS51 nao tem suporte a esse parametro
# Sera utilizado em futura versao
function Get-Timeout {
    param (     [int]$defaultTimeout = 500     )
    # Verificar a versão do PowerShell
    $psVersion = $PSVersionTable.PSVersion
    $isPowerShell6OrAbove = $psVersion.Major -ge 6

    # Verificar se a versão é igual a 2 (PowerShell 6 ou superior)
    if ($isPowerShell6OrAbove) {
        $timeout = Read-Host 'Digite o tempo limite de conexão em milissegundos (padrão:'($defaultTimeout)')'
        if ([string]::IsNullOrEmpty($timeout)) {
            $timeout = $defaultTimeout
        }
        else {
            $timeout = [int]$timeout
        }
    }
    else {
        Write-Host "Definir Timeout requer PowerShell 6 ou superior."
        return
    }
    return $timeout
}

# Obter o nome do Domain/Environment
function Get-Environment {
    $domain = $env:USERDNSDOMAIN
    $domain = $domain.ToLower()

    if ($domain -match 'ems') {
        return "ems"
    }
    elseif ($domain -match 'pds') {
        return "pds"
    }
    elseif ($domain -match 'itaipu') {
        # para criar lista para a máquina local no caso de debug do script
        return "itaipu"                             # depende de habilitação de serviço na máquina local
    }
    else {
        return "Dominio nao pertencente ao SCADA"
    }
}

function Get-TargetList {
    param (   [string]$domain    )

    $ConsoleList = @()
    $ServerList = @()

    if ($domain -match 'ems') {
        $ConsoleList = $EMSConsoleList              # Para futura lista separada de console e servidor
        $ServerList = $EMSServerList
    }
    elseif ($domain -match 'pds') {
        $ConsoleList = $PDSConsoleList              # Para futura lista separada de console e servidor
        $ServerList = $PDSServerList
    }
    elseif ($domain -match 'itaipu') {
        # para criar lista para a máquina local no caso de debug do script
        $ConsoleList = ('localhost')               # Somente para teste de execução local
    }
    else {
        Write-Host ""
        return @()
    }

    $targets = $ConsoleList + $ServerList           # Nesta versão cria lista unica
    return $targets
}

# Função para obter a lista de programas remotos
# Adaptado de Get-RemoteProgram Author: Jaap Brasser
# https://github.com/jaapbrasser/SharedScripts/blob/master/Get-RemoteProgram/Get-RemoteProgram.ps1
function Get-RemoteProgram {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [string[]]
        $ComputerName = $env:COMPUTERNAME,
        [Parameter(Position = 0)]
        [string[]]
        $Property,
        [string[]]
        $IncludeProgram,
        [string[]]
        $ExcludeProgram,
        [switch]
        $ProgramRegExMatch,
        [switch]
        $LastAccessTime,
        [switch]
        $ExcludeSimilar,
        [int]
        $SimilarWord
    )

    begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
        'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

        if ($psversiontable.psversion.major -gt 2) {
            $HashProperty = [ordered]@{}
        }
        else {
            $HashProperty = @{}
            $SelectProperty = @('ComputerName', 'ProgramName')
            if ($Property) {
                $SelectProperty += $Property
            }
            if ($LastAccessTime) {
                $SelectProperty += 'LastAccessTime'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            try {
                $socket = New-Object Net.Sockets.TcpClient($Computer, 445)
                if ($socket.Connected) {
                    $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)
                    $RegistryLocation | ForEach-Object {
                        $CurrentReg = $_
                        if ($RegBase) {
                            $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                            if ($CurrentRegKey) {
                                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                    $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg" + $_)).GetValue('DisplayName'))

                                    if ($IncludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notmatch $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                        else {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notlike $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($ExcludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -match $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                        else {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -like $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($DisplayName) {
                                        if ($Property) {
                                            foreach ($CurrentProperty in $Property) {
                                                $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg" + $_)).GetValue($CurrentProperty)
                                            }
                                        }
                                        if ($LastAccessTime) {
                                            $InstallPath = ($RegBase.OpenSubKey("$CurrentReg" + $_)).GetValue('InstallLocation') -replace '\\$', ''
                                            if ($InstallPath) {
                                                $WmiSplat = @{
                                                    ComputerName = $Computer
                                                    Query        = $("ASSOCIATORS OF {Win32_Directory.Name='$InstallPath'} Where ResultClass = CIM_DataFile")
                                                    ErrorAction  = 'SilentlyContinue'
                                                }
                                                $HashProperty.LastAccessTime = Get-WmiObject @WmiSplat |
                                                    Where-Object { $_.Extension -eq 'exe' -and $_.LastAccessed } |
                                                        Sort-Object -Property LastAccessed |
                                                            Select-Object -Last 1 | ForEach-Object {
                                                                $_.ConvertToDateTime($_.LastAccessed)
                                                            }
                                                        }
                                                        else {
                                                            $HashProperty.LastAccessTime = $null
                                                        }
                                                    }

                                                    if ($psversiontable.psversion.major -gt 2) {
                                                        [pscustomobject]$HashProperty
                                                    }
                                                    else {
                                                        New-Object -TypeName PSCustomObject -Property $HashProperty |
                                                            Select-Object -Property $SelectProperty
                                                        }
                                                    }
                                                    $socket.Close()
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Error $_
                            }
                        }
                    }
                }

                function Get-ConnectionResult {
                    param ([string]$target)

                    # Flag de status da conexão
                    $connected = $false

                    try {
                        # Obter a lista de programas
                        $softwareList = Get-RemoteProgram -ComputerName $target -Property DisplayVersion

                        # Adicionar a lista de programas ao arquivo Consoles_$domain.txt
                        $target | Out-File "$OutputPath\Lista_Geral_Software_$domain.txt" -Append
                        $softwareList | Out-File "$OutputPath\Lista_Geral_Software_$domain.txt" -Append

                        try {
                            # Definir os caminhos dos arquivos
                            $csvPath = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Software' -fileType 'csv'
                            $txtPath = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Software' -fileType 'txt'

                            # Exportar a lista de software para arquivos csv e txt
                            $softwareList | Export-Csv -Path $csvPath -NoTypeInformation
                            $softwareList | Out-File $txtPath -Append
                        }
                        catch {
                            # Tratar erros ao obter a lista de software
                            Write-Error "Falha em obter a lista: $_"
                        }

                        # Atualizar a flag de status da conexão
                        $connected = $true
                    }
                    catch {
                        # Tratar erros de conexão
                        Write-Host "Falha ao conectar-se ao alvo $target."
                    }

                    # Retornar o status da conexão
                    return $connected
                }


                function Connect-ToTargets {
                    param (
                        [string]$OutputPath,
                        [int]$attempts = 2, #Duas tentivas de conexão
                        [int]$timeout,
                        [string]$domain,
                        [string[]]$targets
                    )

                    $FailedConnections = @()

                    foreach ($target in $targets) {
                        Write-Host "Conectando ao alvo $($target)..."
                        $connectionAttempts = 0
                        $connected = $false

                        do {
                            $connectionAttempts++
                            $connected = Get-ConnectionResult -target $target

                            if (-not $connected -and $connectionAttempts -lt $attempts) {
                                Write-Host 'Tentando novamente...'
                                Start-Sleep -Milliseconds $timeout
                            }
                        }
                        while (-not $connected -and $connectionAttempts -lt $attempts)

                        if (-not $connected) {
                            $FailedConnections += $target
                        }
                    }

                    $FailedConnections | Out-File "$OutputPath\Falhas_conexao_$domain.txt"
                    Write-Host 'Processo concluido.'
                }

                function Get_Sys_Info {
                    param (
                        [string]$OutputPath,
                        [string]$domain,
                        [string[]]$targets
                    )

                    foreach ($target in $targets) {
                        Write-Host "Obtendo informacoes do alvo $target..."
                        try {
                            # Comando para obter a lista de Servicepack
                            $hotfixes = Get-CimInstance -ClassName Win32_QuickFixEngineering -ComputerName $target
                            $csvPathSP = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'SP' -fileType 'csv'
                            $txtPathSP = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'SP' -fileType 'txt'
                            $hotfixes | Sort-Object InstalledOn | Export-Csv -Path $csvPathSP -NoTypeInformation
                            $hotfixes | Sort-Object InstalledOn | Select-Object Description, FixComments, HotFixID, InstalledBy, InstalledOn | Out-File -FilePath $txtPathSP
            
                            # Comando para obter info de SO
                            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $target
                            $csvPathOS = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'OS' -fileType 'csv'
                            $txtPathOS = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'OS' -fileType 'txt'
                            $osInfo | Export-Csv -Path $csvPathOS -NoTypeInformation
                            $osInfo | Select-Object Version, Caption, CountryCode, CSName, Description, InstallDate, SerialNumber, ServicePackMajorVersion, WindowsDirectory | Out-File -FilePath $txtPathOS

                            # Comando para obter uma lista de serviços
                            $services = Get-CimInstance -ClassName Win32_Service -ComputerName $target
                            $csvPathServices = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Services' -fileType 'csv'
                            $txtPathServices = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Services' -fileType 'txt'
                            $services | Sort-Object State | Select-Object Name, DisplayName, State, StartMode, PathName | Export-Csv -Path $csvPathServices -NoTypeInformation
                            $services | Sort-Object State | Select-Object Name, DisplayName, State, StartMode, PathName | Out-File -FilePath $txtPathServices

                            # Comando para obter dados da BIOS
                            $bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $target
                            $csvPathBios = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'BIOS' -fileType 'csv'
                            $txtPathBios = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'BIOS' -fileType 'txt'
                            $bios | Select-Object Manufacturer, Name, Version, Status, BIOSVersion, Description, EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion, InstallDate, PrimaryBIOS, ReleaseDate, SerialNumber, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, SMBIOSPresent, SystemBIOSMajorVersion, SystemBIOSMinorVersion | Export-Csv -Path $csvPathBios -NoTypeInformation
                            $bios | Select-Object Manufacturer, Name, Version, Status, BIOSVersion, Description, EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion, InstallDate, PrimaryBIOS, ReleaseDate, SerialNumber, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion, SMBIOSPresent, SystemBIOSMajorVersion, SystemBIOSMinorVersion | Out-File -FilePath $txtPathBios

                            # Comando para obter lista de drivers do sistema
                            $sysDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ComputerName $target
                            $csvPathDrivers = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Drivers' -fileType 'csv'
                            $txtPathDrivers = Format-OutputPath -OutputPath $OutputPath -domain $domain -target $target -infoType 'Drivers' -fileType 'txt'
                            $sysDrivers | Sort-Object State | Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType | Export-Csv -Path $csvPathDrivers -NoTypeInformation
                            $sysDrivers | Sort-Object State | Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType | Out-File -FilePath $txtPathDrivers
                        }
                        catch {
                            Write-Error "Falha na exportacao de dados: $_"
                        }
                    }
                    Write-Host "Processo concluido."
                }

                # Validacao de campos evitando valor nulos ou vazio
                function Format-OutputPath {
                    param (
                        [Parameter(Mandatory = $true)]
                        [ValidateNotNullOrEmpty()]
                        [string]$OutputPath,

                        [Parameter(Mandatory = $true)]
                        [ValidateNotNullOrEmpty()]
                        [string]$domain,

                        [Parameter(Mandatory = $true)]
                        [ValidateNotNullOrEmpty()]
                        [string]$target,

                        [ValidateSet('Software', 'SP', 'OS', 'Services', 'BIOS', 'Drivers')]
                        [Parameter(Mandatory = $true)]
                        [string]$infoType, # 'SP' or 'OS'        

                        [ValidateSet('csv', 'txt')]
                        [Parameter(Mandatory = $true)]
                        [string]$fileType  # 'csv' or 'txt'
                    )

                    $filename = "${target}_${domain}_$infoType.$fileType"
                    $fullPath = Join-Path -Path $OutputPath -ChildPath $filename

                    return $fullPath
                }

                function Main {
                    Clear-AllVariable 
                    $domain = Get-Environment
                    # Definicao de diretorio de saida dos dados - nao confundir com o nome do arquivo
                    # $OutputPath = $PSScriptRoot + \$domain + 'Resultados_' + (Get-Date -Format 'yyyyMMdd_HHmm') + '_' + $domain
                    $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath ($domain + '_' + 'Resultados' + '_' + (Get-Date -Format 'yyyyMMdd_HHmm'))
                    $logFile = "$OutputPath\" + "LOG_SCRIPT_$domain.txt"
                    Start-Transcript -Path $logFile     #-Append
                    Test-AdminPrivilege
                    # $PSVersion = Test-PowerShellVersion                 # Uso futuro
                    $OSVersion = Test-OSVersion                           # Uso futuro
                    Write-Host "Versao do Windows: "  $OSVersion
                    $timeout = Get-Timeout

                    Write-Host "Dominio: " $domain
                    $targets = Get-TargetList -domain $domain

                    if (-not (Test-Path -Path $OutputPath -PathType Container)) {
                        $null = New-Item -ItemType Directory -Path $OutputPath
                    }

                    Connect-ToTargets -OutputPath $OutputPath -attempts $attempts -timeout $timeout -domain $domain -targets $targets
                    Get_Sys_Info -OutputPath $OutputPath -domain $domain -targets $targets
                    Stop-Transcript
                }

                Main
