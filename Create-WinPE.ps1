<#
* Author: Roger
* Filename: Create-WinPE.ps1
* Objetivos:
	- Objective 1: Execute steps to create a WinPE image for Windows 11 based on Windows ADK and Windows PE Addon
* Usage:
	- Call the special prompt( Deployment and Imaging Tools Environment) and execute the script
	- Create-WinPE.ps1 [-env <prod|dev|dbg|hmg|test|auto>] [-SelfElevate <0|1|-1>] [-h|--help|--usage]
* Extras docs:
	- https://learn.microsoft.com/pt-br/windows/deployment/customize-boot-image?tabs=powershell
	- Old content with some other links: https://github.com/HaroldMitts/Build-CustomPE
[revision - 20240606 - roger ]
	- Initial version

#todo: Validate form to implement below
https://github.com/hvoges/WinPeServicing/blob/master/New-WinPEVhd.ps1
#>

<#!Ambiente alterado pelo launcher da kit. Tais valores devem ser usados durante o script
Name                           Value
----                           -----
BCDBootRoot                    C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\BCDBoot
DandIRoot                      C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools
DISMRoot                       C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\DISM
HelpIndexerRoot                C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\HelpIndexer
ICDRoot                        C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Imaging and Configuration Designer\x86
ImagingRoot                    C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Imaging
KitsRoot                       C:\Program Files (x86)\Windows Kits\10\
KitsRootRegValueName           KitsRoot10
NewPath                        C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\DISM;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Imaging;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\BCDBoot;C:\Program Files…
OSCDImgRoot                    C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Oscdimg
Path                           C:\Program Files\PowerShell\7;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\DISM;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Imaging;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\…
regKeyPath                     HKLM\Software\Wow6432Node\Microsoft\Windows Kits\Installed Roots
regKeyPathFound                1
USMTRootNoArch                 C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\User State Migration Tool
WdsmcastRoot                   C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Wdsmcast
windir                         C:\Windows
WindowsSetupRootNoArch         C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Setup
WinPERoot                      C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment
WinPERootNoArch                C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment
wowRegKeyPathFound             1
WSIMRoot                       C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\WSIM\x86
#>

#! Variáveis do script
[CmdletBinding(PositionalBinding = $true)] #Permit collect remaing/unecessary/extra/etc args by position
param(
	# Environment name
	[parameter(Mandatory = $False, Position = 0)]
	# Auto elevate flag, with false as default value # 0 - permitt, 1 - already tried, -1 - deny elevation
	[int] $SelfElevate = 0, 
	[Parameter( Mandatory = $false, Position = 1)]
	[ValidateSet('prod', 'dev', 'dbg', 'hmg', 'test', 'auto' , IgnoreCase = $true)]
	[String] $env = 'prod',
	# Remaining arguments to be collected by position
	[parameter(Mandatory = $False, ValueFromRemainingArguments = $True)]
	[Object[]] $RemainArgs
)

$Global:RuntimeInfo = [PSCustomObject]@{
	RootCmdlet     = $PSCmdlet
	RootScriptPath = $PSCmdlet.MyInvocation.MyCommand.Source
	Author         = 'TRE-PB/COINF/SESOP'
	Logo           = "$($MyInvocation.MyCommand) - Gerador de imagem WinPE para Windows 11 baseado na ADK e Windows PE Addon"
	Version        = '0.0.2024.1' 
	EnvName        = $env
	CallBacks      = @{
		'OnLongUsage' = $function:OnLongUsage
		#'OnFOO' 		 = $function:OnFOO.... #Outros callbacks podem ser adicionados
	}
}

function Get-DefaultPSHome {
	[CmdletBinding()]
	param (
		# Environment name
		[Parameter()]
		[String] $EnvName
	)
	switch ($EnvName.ToUpper() ) {
		'DEV' {
			return 'S:\Powershell'
		}
		Default {
			if ( $Env:SESOP:PSHOME) {
				return $Env:SESOP:PSHOME
			}
			else {
				return 'D:\AplicTRE\Suporte\Scripts\Powershell'
			}
		}
	}
}


#! Script scope
$Script:EnvName = $env
$Script:BasicBSModule = 'basic-bs.psm1'
#! Global scope
$Global:DEFAULT_PSHOME = Get-DefaultPSHome -EnvName $Script:EnvName #'D:\AplicTRE\Suporte\Scripts\Powershell'


function Initialize-Bootstrap() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0)]
		[String] $EnvName
	)
	$Error.Clear()
	#Test basic-bs.psm1 at same folder
	$bs = [IO.Path]::Combine( $PSScriptRoot , $Script:BasicBSModule )
	if ( -not (Test-Path -Path $bs) ) {
		#test if basic-bs.psm1 is at $env:SESOP:PSHOME or default path
		if ( $Env:SESOP:PSHOME -and $(Test-Path -Path $Env:SESOP:PSHOME) ) { 
			$bs = [IO.Path]::Combine( $env:SESOP:PSHOME , 'PSAddons', $Script:BasicBSModule )
		}
		else { 
			$bs = [IO.Path]::Combine( $Global:DEFAULT_PSHOME, 'PSAddons', $Script:BasicBSModule ) 
		}
		if ( -not (Test-Path -Path $bs) ) {
			#Test if at all PSModulePath directories
			$bs = Get-Module -ListAvailable -All -Name [IO.Path]::GetFileNameWithoutExtension( $Script:BasicBSModule ) | Select-Object -ExpandProperty Path
			if ( -not $bs ) {
				#throw an error with multiple lines
				throw @'
Não foi possível localizar o módulo básico de inicialização(basic-bs) 
Verifique <SESOP:PSHOME>\PSAddons ou na pasta do script
Acione o suporte(SESOP)
'@
			}
			else {
				$bs = Select-Object -InputObject $bs -First 1
			}
		}
	}
	try {
		Import-Module -FullyQualifiedName $bs -Force 
	}
 catch {
		throw 
		@"
Erro ao importar módulo básico de inicialização: $bs
$($_.Exception.Message)
Verifique o módulo básico de inicialização em <`$env:SESOP:PSHOME>\PSAddons\basic-bs.psm1 ou na plasta atual do script
"@
	}
}

function Script:OnLongUsage {
	<#
	.SYNOPSIS
		Long usage description showed when -h, -help or --help is passed
	.DESCRIPTION
		Describes the script usage in detail
	.INPUTS
		.ExtraArgs
		Extra arguments passed to the script, at least one is help flag
	.OUTPUTS
		A string with the script usage details
	#>
	[CmdletBinding()]
	[OutputType([String])]
	Param(
		[Parameter()]
		[Object[]] $ExtraArgs
	)
	$ret = [System.Collections.Generic.List[String]]::new()
	$ret.Add( $Global:RuntimeInfo.Author )
	$ret.Add( $Global:RuntimeInfo.Logo )
	$ret.Add( "Versão: $($Global:RuntimeInfo.Version)" )
	#* Informações extras
	#todo:dsg ajuste as informações extras
	$ret.Add( '  -Nenhuma informação detalhada de uso informada neste template' )
	return $ret
}


function Test-ADKIstalled() {
	[CmdletBinding()]
	param (  )
	#done: Value loaded by "C:\Windows\system32\cmd.exe /k "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" 
	$envVarList = @(
		'BCDBootRoot', 'DandIRoot', 'DISMRoot', 'HelpIndexerRoot', 'ICDRoot', 'ImagingRoot', 'KitsRoot', 'KitsRootRegValueName',
		'NewPath', 'OSCDImgRoot', 'regKeyPath', 'regKeyPathFound', 'USMTRootNoArch', 'WdsmcastRoot', 'WindowsSetupRootNoArch'
		'WinPERoot', 'WinPERootNoArch', 'wowRegKeyPathFound', 'WSIMRoot' )

	$Fail = $false
	foreach ($envVar in $envVarList) {
		$value = Get-Item -Path "Env:$envVar" -ErrorAction SilentlyContinue
		if ( -not $value ) {
			Write-Error "Variável de ambiente $envVar não encontrada"
			$Fail = $true
		}
		else {
			Write-Host 'OK ' -NoNewline -ForegroundColor Green
			Write-Host "- $envVar = $value"
		}
	}
	if ($Fail) {
		Write-Warning "Este script deve ser chamado a partir do prompt carregado pelo Deployment and Imaging Tools Environment"
		Read-Host 'Pressione enter para encerrar....'
		throw 'Variáveis de ambiente do Windows ADK não encontradas complementamente'
	}

	if ( -not (Test-Path -Path $Global:ADK_PATH ) ) {
		Write-Error "Windows ADK não instalado em $Global:ADK_PATH"
		Write-Error 'Verfique https://learn.microsoft.com/pt-br/windows/deployment/customize-boot-image?tabs=powershell para instalação do Windows ADK'
		throw "Windows ADK não instalado em $Global:ADK_PATH"
	}
 else {
		Write-Host "Windows ADK instalado em $Global:ADK_PATH"
		if ( $( Get-Location ).Path -ne $Global:ADK_PATH ) {
			Write-Warning "Diretório atual precisar ser `"$Global:ADK_PATH`" para execução do script"
			Write-Host 'Alterando o caminho atual para a localização correta...'
			Set-Location -LiteralPath $Global:ADK_PATH
		}
	}
}


function Save-CumulativeUpdates() {
	[CmdletBinding()]
	param (  )
	if (Test-Path -Path $Global:CUMULATIVE_UPDATES_PATH) {
		$items = Get-ChildItem -Path $Global:CUMULATIVE_UPDATES_PATH -Filter '*.msu' -Recurse
		if ($items) {
			Write-Host "Instalando atualizações cumulativas em $Global:CUMULATIVE_UPDATES_PATH"
			throw 'Instalação de atualizações cumulativas não implementada'
		}
		else {
			Write-Host "Nenhuma atualização cumulativa encontrada em $Global:CUMULATIVE_UPDATES_PATH"
		}
	}
 else {
		Write-Warning "Diretório de atualizações cumulativas não encontrado em `"$Global:CUMULATIVE_UPDATES_PATH`""
	}
}

function Add-ADKAditionalPackages {
	[CmdletBinding()]
	param ( 
		#Path to WinPE image
		[Parameter(Mandatory)]
		[String] $WinPEPath,
		#Languages to add to WinPE image
		[Parameter()]
		[String[]] $langs = @( 'pt-br', 'en-us' )
	)
	$DESIRED_PACKAGES = @(
		@{
			Recommended = 1
			Name        = 'WinPE-DismCmdlets.cab'
			Description = 'O WinPE-DismCmdlets contém o módulo DISM PowerShell, que inclui cmdlets usados para gerenciar e atender imagens do Windows.'
			Requires    = 'WinPE-WMI>WinPE-NetFX>WinPE-Scripting>WinPE-PowerShell'
		},
		@{
			Recommended = 0
			Name = 'WinPE-Dot3Svc.cab'
			Description = 'Adiciona suporte para o protocolo de autenticação IEEE 802.1X em redes com fio.'
			Requires = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-EnhancedStorage.cab'
			Description = 'O WinPE-EnhancedStorage permite que o Windows descubra funcionalidades adicionais para os dispositivos de armazenamento, como unidades criptografadas e implementações que combinam especificações Trusted Computing Group (TCG) e IEEE 1667 ("Protocolo Standard para Autenticação em Anexos de Host de Dispositivos de Armazenamento Transitório"). Esse componente opcional permite que o Windows gerencie esses dispositivos de armazenamento nativamente usando o BitLocker.'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FMAPI.cab'
			Description = 'O WinPE-FMAPI fornece acesso à API de Gerenciamento de Arquivos (FMAPI) do Windows PE para descobrir e restaurar arquivos excluídos de volumes não criptografados. O FMAPI também fornece a capacidade de usar um arquivo de chave de recuperação ou senha para a descoberta e recuperação de arquivos excluídos de volumes criptografados da Criptografia de Unidade de Disco BitLocker do Windows.'
			Requires    = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-WMI.cab'
			Description = 'O WinPE-WMI contém um subconjunto dos provedores de Instrumentação de Gerenciamento do Windows (WMI) que permitem o diagnóstico mínimo do sistema.'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-HSP-Driver.cab'
			Description = 'Disponível a partir do Windows 11, versão 22H2. O WinPE-HSP-Driver adiciona suporte ao processador de segurança do Microsoft Pluton no WinPE.`n
				Observação: Esse componente opcional só está disponível para a arquitetura Amd64.'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-HTA.cab'
			Description = 'O WinPE-HTA fornece suporte ao HTA (Aplicativo HTML) para criar aplicativos GUI por meio do mecanismo de script do Windows Internet Explorer e dos serviços HTML. Esses aplicativos são confiáveis e exibem apenas os menus, ícones, barras de ferramentas e informações de título que você cria.'
			Requires    = 'WinPE-Scripting'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-LegacySetup.cab'
			Description = 'O Winpe-LegacySetup contém todos os arquivos de instalação da pasta \Sources na mídia do Windows. Adicione esse componente opcional ao fazer manutenção na instalação ou na pasta \Sources na mídia do Windows. Você deve adicionar esse componente opcional junto com o componente opcional para o recurso de instalação. Para adicionar um novo arquivo Boot.wim à mídia, adicione o WinPE-Setup pai, um dos filhos (WinPE-Setup-Client ou WinPE-Setup-Server) e componentes opcionais de mídia. '
			Requires    = ''
		},
		@{
			#Gera umas ideias interessantes sobre uma automação plena do processo de instalação/deployment
			Recommended = 0
			Name        = 'WinPE-MDAC.cab'
			Description = 'Suporta Microsoft Open Database Connectivity (ODBC), OLE DB e Microsoft ActiveX Data Objects (ADO). Esse conjunto de tecnologias fornece acesso a várias fontes de dados, como o Microsoft SQL Server. Por exemplo, esse acesso permite consultas a instalações do Microsoft SQL Server que contêm objetos ADO. Você pode criar um arquivo de resposta dinâmico com base em informações exclusivas do sistema. Da mesma forma, você pode criar aplicativos de servidor ou cliente controlados por dados que integram informações de uma variedade de fontes de dados, tanto relacionais (SQL Server) quanto não relacionais.'
			Requires    = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-NetFx.cab'
			Description = 'Subconjunto do .NET Framework 4.5 projetado para aplicativos cliente.'
			Requires    = 'WinPE-WMI'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-PlatformId.cab'
			Description = 'Contém os cmdlets do Windows PowerShell para recuperar o Identificador de Plataforma do computador físico.'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-PmemCmdlets.cab'
			Description = '(Dados inseguros) Contém os cmdlets do Windows PowerShell para gerenciamento de memória persistente.'
			Requires    = '????????'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-PowerShell.cab'
			Description = 'Contém diagnósticos baseados no Windows PowerShell que simplificam o uso da Instrumentação de Gerenciamento do Windows (WMI) para consultar o hardware durante a fabricação.'
			Requires    = 'WinPE-WMI>WinPE-NetFX>WinPE-Scripting'
		},
		@{
			Recommended = 0
			Name        = 'WinPE-PPPoE.cab'
			Description = 'O WinPE-PPPoE permite que você use o Protocolo Ponto a Ponto por Ethernet (PPPoE) para criar, conectar, desconectar e excluir conexões PPPoE do Windows PE'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-RNDIS.cab'
			Description = 'O WinPE-RNDIS contém suporte à NDIS Remoto (Driver Interface Specification Remoto). O WinPE-RNDIS habilita o suporte à rede para dispositivos que implementam a especificação do NDIS Remoto por USB.'
			Requires    = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-Scripting.cab'
			Description = 'Ambiente de script de várias linguagens ideal para automatizar tarefas de administração do sistema, como processamento de arquivos em lote. Os scripts executados no ambiente do Windows Script Host (WSH) podem chamar objetos WSH e outras tecnologias baseadas em COM que dão suporte à Automação, como o WMI, para gerenciar os subsistemas do Windows que são centrais para muitas tarefas de administração do sistema'
			Requires    = 'WinPE-WMI>WinPE-NetFX'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-SecureBootCmdlets.cab'
			Description = 'contém os cmdlets do PowerShell para gerenciar as variáveis de ambiente UEFI (Unified Extensible Firmware Interface) para Inicialização Segura.'
			Requires    = 'WinPE-WMI>WinPE-NetFX>WinPE-Scripting>WinPE-PowerShell'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-SecureStartup.cab'
			Description = 'O WinPE-SecureStartup habilita o provisionamento e o gerenciamento do BitLocker e do Trusted Platform Module (TPM). Inclui ferramentas de linha de comando do BitLocker, bibliotecas de gerenciamento WMI do BitLocker, um driver TPM, TPM Base Services (TBS), a classe Win32_TPM, o Assistente de Desbloqueio do BitLocker e bibliotecas de UI do BitLocker. O driver TPM fornece melhor suporte para o BitLocker e o TPM nesse ambiente de pré-inicialização.'
			Requires    = 'WinPE-WMI'
		},
		@{
			Recommended = 0
			Name        = 'WinPE-Setup-ASZ.cab'
			Description = '(Undocumented) Contém componentes para suporte a configurações de zona de segurança automáticas (ASZ) no Windows PE. O ASZ é um recurso de segurança que permite que você defina configurações de segurança para um computador com base em sua localização física. O ASZ é um recurso de segurança que permite que você defina configurações de segurança para um computador com base em sua localização física.'
			Requires    = '????'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-Setup-Client.cab'
			Description = 'Contém os arquivos de identidade visual do cliente para o componente opcional WinPE-Setup pai.'
			Requires    = 'WinPE-Setup'
		},
		@{
			Recommended = 0
			Name        = 'WinPE-Setup-Server.cab'
			Description = 'O WinPE-Setup-Server inclui os arquivos de identidade visual do servidor para o componente opcional WinPE-Setup pai.'
			Requires    = 'WinPE-Setup'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-Setup.cab'
			Description = 'É o pai de WinPE-Setup-Client e WinPE-Setup-Server. Contém todos os arquivos de instalação da pasta \Sources que são comuns ao cliente e ao servidor.'
			Requires    = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-StorageWMI.cab'
			Description = 'Contém cmdlets do PowerShell para gerenciamento de armazenamento. Esses cmdlets usam a API de Gerenciamento de Armazenamento (SMAPI) do Windows para gerenciar o armazenamento local, como disco, partição e objetos de volume. Ou, esses cmdlets usam o SMAPI do Windows junto com o gerenciamento de armazenamento de matriz usando um provedor de gerenciamento de armazenamento. '
			Requires    = 'WinPE-WMI>WinPE-NetFX>WinPE-Scripting>WinPE-PowerShell'
		},
		@{
			Recommended = 1
			Name        = 'WinPE-WDS-Tools.cab'
			Description = 'Inclui APIs para habilitar a ferramenta Captura de Imagem e um cenário multicast que envolve um cliente personalizado dos Serviços de Implantação do Windows. Ele deve ser instalado se você pretende executar o cliente dos Serviços de Implantação do Windows em uma imagem personalizada do Windows PE.'
			Requires    = ''
		},
		@{
			Recommended = 1
			Name        = 'WinPE-WinReCfg.cab'
			Description = 'Inicialize do Windows PE baseado em x64 para definir as configurações do Windows RE em uma imagem do sistema operacional baseada em x86 offline'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-Fonts-Legacy.cab'
			Description = 'Contém 32 arquivos de fonte para vários idiomas/scripts de gravação.'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FontSupport-JA-JP.cab'
			Description = 'WinPE Font Support JA-JP'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FontSupport-KO-KR.cab'
			Description = 'WinPE Font Support KO-KR'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FontSupport-ZH-CN.cab'
			Description = 'WinPE Font Support ZH-CN'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FontSupport-ZH-HK.cab'
			Description = 'WinPE Font Support ZH-HK'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-FontSupport-ZH-TW.cab'
			Description = 'WinPE Font Support ZH-TW'
			Requires    = ''
		},
		@{
			Recommended = 0
			Name        = 'WinPE-GamingPeripherals.cab'
			Description = 'O WinPE-GamingPeripherals adiciona suporte para controles sem fio Xbox no WinPE.'
			Requires    = ''
		}
	)

	#Verify languages subdirs
	$Fail=$false
	$OptCabDir = [IO.Path]::Combine( $Env:WinPERoot, 'amd64' , 'WinPE_OCs' )
	foreach ($lang in $langs) {
		$LangDir = [IO.Path]::Combine( $OptCabDir, $lang )
		if ( -not (Test-Path -Path $LangDir) ) {
			Write-Warning "Diretório de idioma $lang não encontrado em $OptCabDir"
		}
	}
	if ($Fail) {
		throw 'Falha ao verificar diretórios de idiomas desejados'
	}

	#Add packages 
	Push-Location
	try{
		Set-Location $OptCabDir
		foreach ($pkg in $DESIRED_PACKAGES) {
			if ($pkg.Recommended) {
				Write-Host "Instalando o pacote $($pkg.Name)..."
				$PackDir = [IO.Path]::Combine( $OptCabDir, $pkg.Name )
				Add-WindowsPackage -PackagePath $PackDir -Path $WinPEPath -Verbose
				if ($?) {
					#$leaf = $pag.name -replace '.cab', "_$lang.cab"
					foreach( $lang in $langs ) {
						$PackLangDir = [IO.Path]::Combine( $OptCabDir, $lang, $pkg.Name -replace '(?i)\.cab$', "_$lang.cab" )
						if (Test-Path -Path $PackLangDir) {
							Write-Host "Instalando o pacote de idioma $lang para o pacote $($pkg.Name)..."
							Install-WindowsFeature -Name $pkg.Name -Source $LangDir
						}else{
							Write-Host "Pacote de idioma $lang não encontrado para o pacote $($pkg.Name)" -ForegroundColor Black
						}
					}
				}
			}
			else {
				Write-Host "Pacote $($pkg.Name) ignorado - não recomendado para instalação"
			}
		}	
	}finally{
		Pop-Location
	}
}

function Add-AllVirtIODrivers {
	[CmdletBinding()]
	param ( 
		#Path to virtio-win drivers(genereally an mounted ISO image)
		[Parameter(Mandatory)]
		[String] $DriversPath,
		#Path to Windows PE mount point(Dont check if is a valid path)
		[Parameter(Mandatory)]
		[String] $TargetMountPath, #Sample to validate -> $env:WINDOWS_PE_MOUNT_PATH
		#Pattern to search for drivers( based at target Windows version, like win11, win10, etc)
		[Parameter()]
		[String] $DriversPattern = 'win11'
	)
	$DriversPath = 'E:\virtio-win\' #Path to virtio-win drivers
	Get-ChildItem $DriversPath -Include $DriversPattern -Recurse | Where-Object { Test-Path "$_\amd64" } | ForEach-Object {
		Write-Output "Adding the $_\amd64 driver..."
		Add-WindowsDriver -Path $TargetMountPath -Driver "$_\amd64"
	}
}

function Start-Main() {
	[CmdletBinding()]
	[OutputType([PSCustomObject])] #Represents ExitCode from PS Host Process
	Param(
		# $PSCmdlet from parent script
		[Parameter(Mandatory)]
		[System.Management.Automation.PSCmdlet] $RootPSCmdlet
	)
	try {
		try {
			Push-Location
			# Etapa 1: Baixar e instalar o ADK
			Test-ADKIstalled
			# Etapa 2: Baixar e instalar atualizações cumulativas
			Save-CumulativeUpdates
			# Etapa 3 - Criar backup da sessão atual
			Backup-PreviousImg
			# Etapa 4: Montar imagem de inicialização para montar pasta
			Mount-NewWinPEPath
			# Etapa 5: Adicionar drivers à imagem de inicialização (opcional)
			Add-ExtraExternalDrivers
			# Etapa 6: adicionar componentes opcionais à imagem de inicialização(WinPE), nativos do ADK
			Add-ADKAditionalPackages -langs @( 'pt-br', 'en-us' )
			# Etapa 7: Adicionar CU (atualização cumulativa) à imagem de inicialização
			Add-CumulativeUpdates
			# Etapa 8: Copiar arquivos de inicialização da imagem de inicialização montada para o caminho de instalação do ADK
			Copy-BootImgToNewWinPE
			# Etapa 9: executar a limpeza de componentes
			Clear-JunkComponents
			# Etapa 10: verificar se todos os pacotes desejados foram adicionados à imagem de inicialização
			Test-WinPEPackages
			# Etapa 11: Desmontar imagem de inicialização e salvar alterações
			DisMount-NewWinPEPath
			# Etapa 12: Exportar imagem de inicialização para reduzir o tamanho
			Export-NewWinPEImg
			# Etapa 13: atualizar a imagem de inicialização em produtos que a utilizam (se aplicável)
			Update-NewWinPE
		}
		finally {
			Pop-Location
		}

		<#
		ROOT_PATH = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs"
		#>



		<#! Exemplo de uso de argumentos passados ao script - remover aantes do uso
		Set-ExecutionPolicy Bypass -Scope Process -Force
		#$SParams = $RootPSCmdlet.MyInvocation.BoundParameters
		#Write-Host "Executando com os os seguintes argumentos: $( Get-OriginalParameters -Params $Script:PSBoundParameters)"
		Write-Host "Executando com os os seguintes argumentos: $( Get-OriginalParameters -RootCmdlet $RootPSCmdlet)"

		if ( ! $(Test-IsAdmin) ) {
			Write-Host 'Este script requer privilégios de administrador para execução'
			if ($Global:RuntimeInfo.EnvName -ieq 'prod' -and $SelfElevate -lt 0) {
				throw 'Operação requer privilégios de administrador e obtenção de elevação de privilégios automaticamente foi negada pelo autor'
			}
			$ret = $( Start-ThisScriptAsAdmin -Wait )
			write-host "Retorno da execução: $($ret.ExitCode)"
		}else {
			Write-Host 'Executando com privilégios de administrador'
			Read-Host 'Enter para continuar...'
		}
		

		$ParametersStr = $RootPSCmdlet.MyInvocation.BoundParameters | Out-String
		#$Sum = $( $RootPSCmdlet.MyInvocation.BoundParameters.Values | Measure-Object -Sum -ErrorAction Stop).Sum #simulate an error, if some argument value is not a number
		$Sum = $RootPSCmdlet.MyInvocation.BoundParameters.Count
		return [PSCustomObject]@{
			#Simulate a return object. Must be calculated outside from constructor
			ParametersStr = $ParametersStr
			Sum           = $Sum
		}
		#>
	}
 catch {
		$e = [System.ApplicationException]::New( 'Operação falhou com erro não tratado!', $_.Exception )
		if ($_.Exception -is [System.ApplicationException]) {
			$e.HResult = $_.Exception.HResult
		}
		else {
			$e.HResult = 1067 #( 3010-3012 = ERROR_SUCCESS_REBOOT_REQUIRED, 3014 = ADDICTIONAL ACTION REQUIRED, 3019 = REBOOT_REQUIRED_TO_COMPLETE, 1067 = ERROR_PROCESS_ABORTED)
		}
		throw $e
	}
}

<#
-------------------------------------------------------------------------------------------------------
**********************************  Ponto de Entrada   ************************************************
-------------------------------------------------------------------------------------------------------
#>
try {
	$OutEMsg = $null
	Write-Verbose "Iniciando script $(Split-Path -Path $Global:RuntimeInfo.RootScriptPath -Leaf)"
	Initialize-Bootstrap -EnvName $env
	Initialize-Env -EnvName $env -StaticModules @( 'PSLibSESOP' ) -DynamicModules @( 'PSLog' ) -FillModulePath
	Show-Usage -ExtraArgs $RemainArgs
	$LASTEXITCODE = 0
	return $( Start-Main -RootPSCmdlet $PSCmdlet )
}
catch [ApplicationException] {
	$LASTEXITCODE = $_.Exception.HResult
	$OutEMsg = "$($_.Exception.Message)`nCausa: $($_.Exception.InnerException.Message)"
}
catch {
	#ERROR_PROCESS_ABORTED = 1067, inffered by omission
	$LASTEXITCODE = 1067
	$OutEMsg = "Erro: $($_.Exception.Message)"
}
finally {
	Write-Debug "Encerrando ambiente de execução($($Global:RuntimeInfo.EnvName))..."
	Write-Verbose 'Tratamento final do processo de acordo com o host usado...'
	if ($OutEMsg) {
		Write-Error $OutEMsg
		if ( -not $( $Global:RuntimeInfo.EnvName -in @( 'dbg', 'dev' ) ) -and $($env:TERM_PROGRAM -ne 'vscode') ) {
			if ($LASTEXITCODE -ne 0) {
				Write-Error "Retorno da operação = $LASTEXITCODE"
			}
		}
	}
 else {
		Write-Verbose 'Operação finalizada com sucesso!!!'
	}
}