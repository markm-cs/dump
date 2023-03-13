[CmdletBinding()]

param(

   [Parameter(Position = 1)]

   [ValidateSet('https://api.crowdstrike.com',

       'https://api.eu-1.crowdstrike.com', 'htt

   [string] $BaseAddress,

 

   [Parameter(Position = 2)]

   [ValidatePattern('\w{32}')]

   [string] $ClientId,


   [Parameter(Position = 3)]

   [ValidatePattern('\w{40}')]

   [string] $ClientSecret,


   [Parameter(Position = 4)]

   [ValidatePattern('\w{32}')]

   [string] $MemberCid,


   [Parameter(Position = 5)]

   [string] $PolicyName,


   [Parameter(Position = 6)]

   [string] $InstallParams,


   [Parameter(Position = 7)]

   [string] $LogPath,


   [Parameter(Position = 8)]

   [string] $DeleteInstaller = $true,


   [Parameter(Position = 9)]

   [string] $DeleteScript = $true

)

begin {

   $ScriptName = $MyInvocation.MyCommand.Name

   $ScriptPath = if (!$PSScriptRoot) {

       Split-Path -Parent -Path $MyInvocation.M

   } else {

       $PSScriptRoot

   }

   $WinSystem = [Environment]::GetFolderPath('S

   $WinTemp = $WinSystem -replace 'system32','T

   if (!$LogPath) {

       $LogPath = Join-Path -Path $WinTemp -Chi

   }

   $Falcon = New-Object System.Net.WebClient

   $Falcon.Encoding = [System.Text.Encoding]::U

   $Falcon.BaseAddress = $BaseAddress

   $Patterns = @{

       access_token  = '"(?<name>access_token)"

       build         = '"(?<name>build)": "(?<v

       ccid          = '(?<ccid>\w{32}-\w{2})'

       major_minor   = '"(?<name>sensor_version

       policy_id     = '"(?<name>id)": "(?<id>\

       version       = '"(?<name>sensor_version

   }

   function Get-InstallerHash ([string] $Path)

       $Output = if (Test-Path $Path) {

           $Algorithm = [System.Security.Crypto

           $Hash = [System.BitConverter]::ToStr

               $Algorithm.ComputeHash([System.I

           if ($Hash) {

               $Hash.Replace('-','')

           } else {

               $null

           }

       }

       return $Output

   }

   function Invoke-FalconAuth ([string] $String

       $Falcon.Headers.Add('Accept', 'applicati

       $Falcon.Headers.Add('Content-Type', 'app

       $Response = $Falcon.UploadString('/oauth

       if ($Response -match $Patterns.access_to

           $AccessToken = [regex]::Matches($Res

           $Falcon.Headers.Add('Authorization',

       }

       $Falcon.Headers.Remove('Content-Type')

   }

   function Invoke-FalconDownload ([string] $Pa

       $Falcon.Headers.Add('Accept', 'applicati

       $Falcon.DownloadFile($Path, $Outfile)

   }

   function Invoke-FalconGet ([string] $Path) {

       $Falcon.Headers.Add('Accept', 'applicati

       $Request = $Falcon.OpenRead($Path)

       $Stream = New-Object System.IO.StreamRea

       $Output = $Stream.ReadToEnd()

       @($Request, $Stream) | ForEach-Object {

           if ($null -ne $_) {

               $_.Dispose()

           }

       }

       return $Output

   }

   function Write-FalconLog ([string] $Source,

       $Content = @(Get-Date -Format 'yyyy-MM-d

       if ($Source -notmatch '^(StartProcess|De

       $Falcon.ResponseHeaders.Keys -contains '

           $Content += ,"[$($Falcon.ResponseHea

       }

       "$(@($Content + $Source) -join ' '): $Me

   }

   if (!$PolicyName) {

       $PolicyName = 'platform_default'

   }

   if (!$InstallParams) {

       $InstallParams = '/install /quiet /noreb

   }

}

process {

   if (([Security.Principal.WindowsPrincipal] [

   [Security.Principal.WindowsBuiltInRole]::Adm

       $Message = 'Unable to proceed without ad

       Write-FalconLog 'CheckAdmin' $Message

       throw $Message

   } elseif (Get-Service | Where-Object { $_.Na

       $Message = "'CSFalconService' running"

       Write-FalconLog 'CheckService' $Message

       throw $Message

   } else {

       @($BaseAddress, $ClientId, $ClientSecret

           if (!$_) {

               throw "Missing 'BaseAddress', 'C

           }

       }

       if ([Net.ServicePointManager]::SecurityP

           try {

               [Net.ServicePointManager]::Secur

           } catch {

               $Message = $_

               Write-FalconLog 'TlsCheck' $Mess

               throw $Message

           }

       }

       if (!($PSVersionTable.CLRVersion.ToStrin

           $Message = '.NET Framework 3.5 or ne

           Write-FalconLog 'NetCheck' $Message

           throw $Message

       }

   }

   $ApiClient = "client_id=$ClientId&client_sec

   if ($MemberCid) {

       $ApiClient += "&member_cid=$MemberCid"

   }

   Invoke-FalconAuth $ApiClient

   if ($Falcon.Headers.Keys -contains 'Authoriz

       Write-FalconLog 'GetAuth' "ClientId: $($

   } else {

       $Message = 'Failed to retrieve authoriza

       Write-FalconLog 'GetAuth' $Message

       throw $Message

   }

   $Response = Invoke-FalconGet '/sensors/queri

   if ($Response -match $Patterns.ccid) {

       $Ccid = [regex]::Matches($Response, $Pat

       Write-FalconLog 'GetCcid' 'Retrieved CCI

       $InstallParams += " CID=$Ccid"

   } else {

       $Message = 'Failed to retrieve CCID'

       Write-FalconLog 'GetCcid' $Message

       throw $Message

   }

   $Response = Invoke-FalconGet ("/policy/combi

       "'Windows'%2Bname:'$($PolicyName.ToLower

   $PolicyId = if ($Response -match $Patterns.p

       [regex]::Matches($Response, $Patterns.po

   }

   if ($Response -match $Patterns.build -or $Re

       $Build = [regex]::Matches($Response, $Pa

       $Version = [regex]::Matches($Response, $

       $MajorMinor = if ($Version) {

           [regex]::Matches($Response, $Pattern

       }

       $Patch = if ($Build) {

           ($Build).Split('|')[0]

       } elseif ($Version) {

           ($Version).Split('.')[-1]

       }

       if ($Patch) {

           Write-FalconLog 'GetVersion' "Policy

       } else {

           $Message = "Failed to determine sens

           Write-FalconLog 'GetVersion' $Messag

           throw $Message

       }

   } else {

       $Message = "Failed to match policy name

       Write-FalconLog 'GetPolicy' $Message

       throw $Message

   }

   $Response = Invoke-FalconGet "/sensors/combi

   if ($Response) {

       $BuildMatch = '\d{1,}?\.\d{1,}\.' + $Pat

       if ($MajorMinor) {

           $BuildMatch = "($BuildMatch|$([regex

       }

       $Installer = '"name": "(?<filename>(\w+\

           'a256": "(?<hash>\w{64})",(\n.*){1,}

       $Match = $Response.Split('}') | Where-Ob

       if ($Match) {

           $CloudHash = [regex]::Matches($Match

           $CloudFile = [regex]::Matches($Match

           Write-FalconLog 'GetInstaller' "Matc

       } else {

           $MatchValue = "'$Patch'"

           if ($MajorMinor) {

               $MatchValue += " or '$MajorMinor

           }

           $Message = "Unable to match installe

           Write-FalconLog 'GetInstaller' $Mess

           throw $Message

       }

   } else {

       $Message = 'Failed to retrieve available

       Write-FalconLog 'GetInstaller' $Message

       throw $Message

   }

   $LocalHash = if ($CloudHash -and $CloudFile)

       $LocalFile = Join-Path -Path $WinTemp -C

       Invoke-FalconDownload "/sensors/entities

       if (Test-Path $LocalFile) {

           Get-InstallerHash $LocalFile

           Write-FalconLog 'DownloadFile' "Crea

       }

   }

   if ($CloudHash -ne $LocalHash) {

       $Message = "Hash mismatch on download (L

       Write-FalconLog 'CheckHash' $Message

       throw $Message

   }

   $InstallPid = (Start-Process -FilePath $Loca

   Write-FalconLog 'StartProcess' "Started '$Lo

   @('DeleteInstaller', 'DeleteScript') | ForEa

       if ((Get-Variable $_).Value -eq $true) {

           if ($_ -eq 'DeleteInstaller') {

               Wait-Process -Id $InstallPid

           }

           $FilePath = if ($_ -eq 'DeleteInstal

               $LocalFile

           } else {

               Join-Path -Path $ScriptPath -Chi

           }

           Remove-Item -Path $FilePath -Force

           if (Test-Path $FilePath) {

               Write-FalconLog $_ "Failed to de

           } else {

               Write-FalconLog $_ "Deleted '$Fi

           }

       }

   }

}