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

#! Script scope
$Script:EnvName = $env
$Script:BasicBSModule = 'basic-bs'

function Initialize-Bootstrap() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, Position = 0)]
		[String] $EnvName
	)
	$Error.Clear()
	#Test basic-bs.psm1 at same folder
	$bs = Join-Path -Path $PSScriptRoot -ChildPath "$($Script:BasicBSModule).psm1"
	if ( -not (Test-Path -Path $bs) ) {
		#test if basic-bs.psm1 is at $env:SESOP:PSHOME or current location
		$PSLibHome = if ($env:SESOP:PSHOME) { $env:SESOP:PSHOME } else { $(Get-Location).Path }
		$bs = Join-Path -Path $PSLibHome -ChildPath "$($Script:BasicBSModule).psm1"
		if ( -not (Test-Path -Path $bs) ) {
			#Test if at all PSModulePath directories
			$bs = Get-Module -ListAvailable -All -Name $Script:BasicBSModule | Select-Object -ExpandProperty Path
			if ( -not $bs ) {
				#throw an error with multiple lines
				throw @'
Não foi possível localizar o módulo básico de inicialização(basic-bs) 
Verifique <SESOP:PSHOME>\PSAddons ou na pasta do script
Acione o suporte(SESOP)
'@
			} else {
				$bs = Select-Object -InputObject $bs -First 1
			}
		}
	}
	try {
		Import-Module -FullyQualifiedName $bs -Force 
	} catch {
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
	$ADK = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit'
	if ( -not (Test-Path -Path $ADK) ) {
		Write-Error 'Windows ADK não instalado em $ADK'
		Write-Error 'Verfique https://learn.microsoft.com/pt-br/windows/deployment/customize-boot-image?tabs=powershell para instalação do Windows ADK'
		throw "Windows ADK não instalado em $ADK"
	} else {
		Write-Host "Windows ADK instalado em $ADK"
		$currDir = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools'
		if (Get-Location -eq $currDir ) {
			throw "Diretório atual precisar ser `"$currDir`" para execução do script"
		}
	}
}


function Install-CumulativeUpdates() {
	[CmdletBinding()]
	param (  )
	if (Test-Path -Path $Global:CUMULATIVE_UPDATES_PATH) {
		$items = Get-ChildItem -Path $Global:CUMULATIVE_UPDATES_PATH -Filter '*.msu' -Recurse
		if ($items) {
			Write-Host "Instalando atualizações cumulativas em $Global:CUMULATIVE_UPDATES_PATH"
			throw 'Instalação de atualizações cumulativas não implementada'
		} else {
			Write-Host "Nenhuma atualização cumulativa encontrada em $Global:CUMULATIVE_UPDATES_PATH"
		}
	} else {
		Write-Error "Diretório de atualizações cumulativas não encontrado em $Global:CUMULATIVE_UPDATES_PATH"
	}
}

function Install-AditionalPackages {
	[CmdletBinding()]
	param ( 
		[Parameter()]
		[String] $lang = 'pt-br'
	)
	$DESIRED_PACKAGES = @{
		'pt-br' = @(
			@{
				Recommended = 1
				Name        = 'WinPE-DismCmdlets.cab'
				Description = 'O WinPE-DismCmdlets contém o módulo DISM PowerShell, que inclui cmdlets usados para gerenciar e atender imagens do Windows.'
				Requires    = 'WinPE-WMI>WinPE-NetFX>WinPE-Scripting>WinPE-PowerShell'
			},
			@{
				Recommended = 0
				Name        = 'WinPE-Dot3Svc.cab'
				Description = 'Adiciona suporte para o protocolo de autenticação IEEE 802.1X em redes com fio.'
				Requires    = ''
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
	}
	foreach ($pkg in $DESIRED_PACKAGES[$lang]) {
		if ($pkg.Recommended) {
			Write-Output "Instalando o pacote $pkg.Name..."
			#Install-WindowsFeature -Name $pkg.Name
		} else {
			Write-Output "Pacote $pkg.Name não recomendado para instalação"
		}
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
	<#
	.SYNOPSIS
		Main function to be edited to aim the script goals
	.DESCRIPTION
		This function is the main entry point of the script, it should be edited to aim the script goals
		Shell arguments are passed to this function by $RootPSCmdlet
	.EXAMPLE
		if ( $RootPSCmdlet.MyInvocation.BoundParameters.<script-parameter>) {
			$data = FOO( $RootPSCmdlet.MyInvocation.BoundParameters.<script-parameter> )
		} else {
			$data = FOO( $null )
		}
		switch ($RootPSCmdlet.ParameterSetName) {
			'CallModelA' {
			}
			'CallModelB' {
			}
			Default {
				throw 'Parâmetros inválidos'
			}
		}
	.PARAMETER RootPSCmdlet
		Parent script PSCmdlet
	.OUTPUTS
		An generic object with the data to be returned to the parent script or host
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject])] #Represents ExitCode from PS Host Process
	Param(
		# $PSCmdlet from parent script
		[Parameter(Mandatory)]
		[System.Management.Automation.PSCmdlet] $RootPSCmdlet
	)
	try {
		# Etapa 1: Baixar e instalar o ADK
		Test-ADKIstalled
		# Etapa 2: Baixar e instalar atualizações cumulativas
		Install-CumulativeUpdates
		# Etapa 3: Baixar e instalar pacotes adicionais
		Install-AditionalPackages -lang 'pt-br'

		<#!Lista de pacotes a instalar:(Ordem ainda a corrigir)
		Recommended;Name()
1;WinPE-DismCmdlets.cab
0;WinPE-Dot3Svc.cab
1;WinPE-EnhancedStorage.cab
0;WinPE-FMAPI.cab
0;WinPE-Fonts-Legacy.cab
0;WinPE-FontSupport-JA-JP.cab
0;WinPE-FontSupport-KO-KR.cab
0;WinPE-FontSupport-WinRE.cab
0;WinPE-FontSupport-ZH-CN.cab
0;WinPE-FontSupport-ZH-HK.cab
0;WinPE-FontSupport-ZH-TW.cab
0;WinPE-GamingPeripherals.cab
0;WinPE-HSP-Driver.cab
0;WinPE-HTA.cab
1;WinPE-LegacySetup.cab
0;WinPE-MDAC.cab
1;WinPE-NetFx.cab
1;WinPE-PlatformId.cab
1;WinPE-PmemCmdlets.cab
1;WinPE-PowerShell.cab
0;WinPE-PPPoE.cab
0;WinPE-RNDIS.cab
1;WinPE-Scripting.cab
1;WinPE-SecureBootCmdlets.cab
1;WinPE-SecureStartup.cab
0;WinPE-Setup-ASZ.cab
1;WinPE-Setup-Client.cab
0;WinPE-Setup-Server.cab
1;WinPE-Setup.cab
1;WinPE-StorageWMI.cab
1;WinPE-WDS-Tools.cab
1;WinPE-WinReCfg.cab
1;WinPE-WMI.cab


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
	} catch {
		$e = [System.ApplicationException]::New( 'Operação falhou com erro não tratado!', $_.Exception )
		if ($_.Exception -is [System.ApplicationException]) {
			$e.HResult = $_.Exception.HResult
		} else {
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
	Initialize-Env -EnvName $env -StaticModules @( 'PSLibSESOP' ) -DynamicModules @( 'PSLog' ) 
	Show-Usage -ExtraArgs $RemainArgs
	$LASTEXITCODE = 0
	return $( Start-Main -RootPSCmdlet $PSCmdlet )
} catch [ApplicationException] {
	$LASTEXITCODE = $_.Exception.HResult
	$OutEMsg = "$_.Exception.Message`nCausa: $($_.Exception.InnerException.Message)"
} catch {
	#ERROR_PROCESS_ABORTED = 1067, inffered by omission
	$LASTEXITCODE = 1067
	$OutEMsg = "Erro: $_.Exception.Message"
} finally {
	Write-Debug "Encerrando ambiente de execução($($Global:RuntimeInfo.EnvName))..."
	Write-Verbose 'Tratamento final do processo de acordo com o host usado...'
	if ($OutEMsg) {
		Write-Error $OutEMsg
		if ( -not $( $Global:RuntimeInfo.EnvName -in @( 'dbg', 'dev' ) ) -and $($env:TERM_PROGRAM -ne 'vscode') ) {
			if ($LASTEXITCODE -ne 0) {
				Write-Error "Retorno da operação = $LASTEXITCODE"
			}
		}
	} else {
		Write-Verbose 'Operação finalizada com sucesso!!!'
	}
}