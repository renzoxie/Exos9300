<#
.NOTES
    Author: renzoxie@139.com
    Create Date: 26 FEB 2023
    Modified Date: 27 FEB 2023
	Script Version: v1.00

.SYNOPSIS
    Exos 9300 Installation Helper script

.DESCRIPTION
    This script will helps to install prerequisites, IIS features, SQL server 2019 and SQL Server Management Studio for Exos 9300
    
.NOTES
    Set-ExecutionPolicy RemoteSigned [YES]
    Suport version `4.2.2` and `4.2.3`

.EXAMPLE
    .\InstallationHelper.ps1 -Version '4.2.2'

.EXAMPLE
    .\InstallationHelper.ps1 -Version '4.2.3'

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [String]$Version = '4.2.2'
)
# set ErrorAction
$ErrorActionPreference = 'stop'

# ---------------------------
# root location
If ($psVer -lt 5.1) {
    # script location
    $MyScriptRoot = ($pwd).path
} 
Else {
    # set charset
    $PSDefaultParameterValues['*:Encoding'] = 'utf8';
    # Support for TLS 1.2
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
    $MyScriptRoot = $PSScriptRoot
}
# ---------------------------
# Directory name in root
$packageFolders =  Get-ChildItem ($MyScriptRoot) | Select-Object Name | Sort-Object -Property Name
# Root folder as path
$absPackageFolders = @()
For ($i=0; $i -lt ($packageFolders.Length-1); $i++) {
    $dirName = $packageFolders[$i].Name;
    $absPackageFolders += Join-Path $MyScriptRoot $dirName;
}

$dirAddons = $absPackageFolders[0];
$dirDatabase = $absPackageFolders[1];
$dirService = $absPackageFolders[4];
$dirDialog = $absPackageFolders[2];

Switch ($Version) {
    '4.2.2' {
        [String]$dotnetHost = "Microsoft .NET 6.0.5 - Windows Server Hosting"
        [String]$dotnetHostFileName = Join-Path $dirAddons 'dotnet-hosting-6.0.5-win.exe';
        [String]$erlang = "Erlang OTP 24.3.4 (12.3.2)"
        [String]$erlangFileName = Join-Path $dirAddons 'otp_win64_24.3.4.exe';
        [String]$rabbitMq = "RabbitMQ Server 3.10.1"
        [String]$rabbitMqFileName = Join-Path $dirAddons 'rabbitmq-server-3.10.1.exe';
    }
    '4.2.3' {
        [String]$dotnetHost = "Microsoft .NET 6.0.11 - Windows Server Hosting"
        [String]$dotnetHostFileName =  Join-Path $dirAddons 'dotnet-hosting-6.0.11-win.exe';
        [String]$erlang = "Erlang OTP 25.1.2 (13.1.2)"
        [String]$erlangFileName =  Join-Path $dirAddons 'otp_win64_25.1.2.exe';
        [String]$rabbitMq = "RabbitMQ Server 3.11.4"
        [String]$rabbitMqFileName =  Join-Path $dirAddons 'rabbitmq-server-3.11.4.exe';
    }
}

# must run as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
If($isAdmin -eq $False){
    Write-Host "You are not an administrator" -foreground Red;
    Write-Host "Please elevate and run the script again" -foreground Red;
    break;
}

# ---------------------------
# Get-InstalledStatus
function Get-InstalledStatus {
    Param (
        [String]$pName
    )
    $package = (Get-Package -ProviderName "Programs" | Where-Object {$_.Name -eq $pName}).Name
    $condition = ($null -ne $package);
    return $condition
}

# ---------------------------
# Check file versions
Function Get-FileVersion {
    [Alias("File-Version")]
    Param (
        $testFile
    )

    begin {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($testFile);
        $fileExtension = [System.IO.Path]::GetExtension($testFile);
    }

    process {
        # make sure file extension is dot exe
        If ($fileExtension -eq '.exe') {
            $fileVersion = (Get-Item $testFile).VersionInfo.FileVersion;
            return $fileVersion;
        } Else {
            Write-Host "$fileName does not exist";
            Exit
        }
    }
}

# ---------------------------
# valid if file can be download
Function Test-Valid4Download {
    Param (
        [String]$URL
    )

    begin {
        $valid = $false;
        $request = [System.Net.WebRequest]::Create($URL);
        $request.Method = "HEAD";
    }

    process {
        try {
            $response = $request.GetResponse()
            if ($response.StatusCode -eq "OK") {$valid = $true}
            $response.Close()
        } Catch {
            $valid = $false
        }
    }

    end {
        return $valid
    }
}

# ---------------------------
# Install Program
Function Install-Program {
    param (
        [string]$pName,
        [string]$InstallerPath,
        [string]$Arguments
    )

    if (-not(Test-Path $InstallerPath)) {
        Write-Error "Installer file not found: $InstallerPath"
        return
    }

    If (Get-InstalledStatus -pName $pName) {
        Write-Host "$pName was installed" -ForegroundColor Green
    } Else {
        Write-Host "Installing $pName ..." -ForegroundColor White
        Start-Sleep -Seconds 1
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $InstallerPath
        $processStartInfo.Arguments = $Arguments
        $processStartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

        try {
            $process = [System.Diagnostics.Process]::Start($processStartInfo)
            $process.WaitForExit()
        }
        catch {
            Write-Error "$($Error[0].Exception.Message)"
        }

        $installOutput = $process.StandardOutput
        # Check the output for errors
        If ($installOutput -match "Error") {
            Write-Error "$pName installation failed: $installOutput"
            exit 1
        } 
        # Installation succeeded
        Write-Host "$pName installation succeeded" -ForegroundColor Green
    }
}

# ---------------------------
# Download a file and return bool value for fileExist
Function Save-File {
    param (
        [string]$Name,
        [string]$URL,
        [string]$DwPathName
    )

    Begin {}

    Process {
        Write-Host "Writing request for $Name from Microsoft" -ForegroundColor Yellow
        Try { Invoke-WebRequest -Uri $URL -OutFile $DwPathName -PassThru > $Null }
        Catch { Write-Error "An error occurred: $($Error[0].Exception.Message)" }
    }

    End {
        If (Test-Path -Path $DwPathName -PathType Leaf) { 
            Write-Host "Download $Name sucessed" -ForegroundColor Green
        }
        Else {
            Write-Error "Download $Name Failed" 
            Write-Error "Please check your internet or contact your administrator" 
        }
    }
}

# -----------------------------
# Exos 9300 Installation Helper
# -----------------------------
Write-Host; Write-Host; Write-Host
Start-Sleep -Milliseconds 800; Write-Host "-----------------------------------------------" -ForegroundColor Cyan
Start-Sleep -Milliseconds 800; Write-Host "Welcome to Exos 9300 Installation Helper Script" -ForegroundColor Cyan
Start-Sleep -Milliseconds 800; Write-Host "-----------------------------------------------" -ForegroundColor Cyan
Start-Sleep -Milliseconds 800; Write-Host; Start-Sleep -Milliseconds 800
Write-Host "-" -NoNewline -ForegroundColor yellow;Start-Sleep -Milliseconds 800;Write-Host "-" -NoNewline -ForegroundColor yellow;
Start-Sleep -Milliseconds 800;Write-Host "-"-NoNewline -ForegroundColor yellow;Start-Sleep -Milliseconds 800; 
Write-Host ">" -NoNewline -ForegroundColor yellow;Start-Sleep -Milliseconds 800;
Write-Host " Start installing applications for Exos 9300 $Version" -ForegroundColor Yellow; Start-Sleep -Milliseconds 800
# check if dotnet 4.72 was installed
$currentDotNetVersion = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' `
| Get-ItemProperty | Select-Object Version).Version
[Decimal]$dotNetVersion = $currentDotNetVersion.Substring(0,3)
If ($dotNetVersion -lt 4.7) {
    write-host "DotNet framework 4.7.2 was Not Installed" -ForegroundColor Red
    # install .NET framework 4.7.2 and reboot
    Write-Host "Installing .NET framework 4.7.2 ..." -ForegroundColor White
    Start-Process -FilePath "NDP472-KB4054530-x86-x64-AllOS-ENU.exe" -ArgumentList "/q" -Wait
} 
Else {
    Write-Host "DotNET framework 4.7.2 was Installed" -ForegroundColor Green
}
Start-Sleep -Seconds 1;
# ---------------------------
# windows optional features for Exos 9300
# Check the status of the IIS-HttpErrors and IIS-HttpLogging features
Write-Host "Checking IIS features status, please wait ..."  -ForegroundColor Yellow
$featureList  = @(
    "NetFx4Extended-ASPNET45", "IIS-WebServerRole", "IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-Security", `
    "IIS-RequestFiltering", "IIS-StaticContent", "IIS-DefaultDocument", "IIS-DirectoryBrowsing", "IIS-HttpErrors", `
    "IIS-ApplicationDevelopment", "IIS-NetFxExtensibility45", "IIS-ISAPIExtensions", "IIS-ISAPIFilter", `
    "IIS-ASPNET45", "IIS-ASP", "IIS-CGI", "IIS-ServerSideIncludes", "IIS-HealthAndDiagnostics", "IIS-HttpLogging", `
    "IIS-RequestMonitor", "IIS-HttpTracing", "IIS-BasicAuthentication", "IIS-WindowsAuthentication", "IIS-DigestAuthentication", `
    "IIS-Performance", "IIS-HttpCompressionStatic", "IIS-WebServerManagementTools", "IIS-ManagementConsole", "IIS-ManagementScriptingTools", `
    "IIS-ManagementService", "NetFx3ServerFeatures", "NetFx3"
)

foreach ($feature in $featureList) {
    $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature
    if ($featureInfo.State -eq "Disabled") {
        Write-Output "$feature is $($featureInfo.State). Enabling it..."
        Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart `
        -ErrorAction Silentlycontinue -WarningAction SilentlyContinue | Out-Null;
    }
    else {
        Write-Host "$feature is already $($featureInfo.State)" -ForegroundColor Green
    }
}

#------------------------------
# check and install dotnet-host
Install-Program -pName $dotnetHost -InstallerPath $dotnetHostFileName -Arguments "/quiet /norestart";
#------------------------------
# check and install Erlang 
#Install-Program -pName $erlang -InstallerPath $erlangFileName -Arguments "/S /n" 
Install-Program -pName $erlang -InstallerPath $erlangFileName -Arguments "/S /n" 
#------------------------------
# check and install RabbitMQ Server
Install-Program -pName $rabbitMq -InstallerPath $rabbitMqFileName -Arguments "/S";
#------------------------------
# SQL related 
#------------------------------
$installedPrograms = Get-WmiObject -Class Win32_Product | Select-Object -Property Name;
$SqlServerProductName = "Microsoft SQL Server 2019";
$SseiExprUrl = "https://go.microsoft.com/fwlink/?LinkID=866658";
$argFile = '/Q /IAcceptSQLServerLicenseTerms /ACTION=install /FEATURES=SQL /INSTANCENAME="EXOSSQL2019" '
$argFile += '/SQLSVCACCOUNT="NT Authority\System" /SQLSYSADMINACCOUNTS="BUILTIN\Administrators" /UpdateEnabled="False" '
$argFile += '/AGTSVCACCOUNT="NT Authority\System" /SECURITYMODE=SQL /SAPWD="Exos9300"'
[bool]$matchAsBool = $installedPrograms -match $SqlServerProductName;
$netSqlExprFileName = Join-Path $dirAddons 'SQL2019-SSEI-Expr.exe';
$sqlExprFileName = Join-Path $dirAddons 'SQLEXPR_x64_ENU.exe';      
Switch ($matchAsBool) {
   $true {
       Write-Host "$SqlServerProductName was installed" -ForegroundColor Green
   }
   $false {   
        # if SQLExpr not exit
        If (-Not (Test-Path -Path $sqlExprFileName -PathType Leaf)) {
            # if netSQLExpr not exit
            If ( -Not (Test-Path -Path $netSqlExprFileName -PathType Leaf) ) {
                Save-File -Name "SQL2019-SSEI-Expr" -URL $SseiExprUrl -DwPathName $netSqlExprFileName   
            }
            Else {
                $exeVer = Get-FileVersion -testFile $netSqlExprFileName; 
                If ($exeVer -ne '15.2204.5490.2') {
                    Save-File -Name "SQL2019-SSEI-Expr" -URL $SseiExprUrl -DwPathName $netSqlExprFileName   
                }
            }

            Try {
                $processOptions = @{
                    FilePath = $netSqlExprFileName
                    RedirectStandardOutput = "$dirAddons/output.txt"
                    ArgumentList = "/ACTION=Download MEDIAPATH=$dirAddons /MEDIATYPE=Core /QUIET"
                }
                Write-Host "Writing request for SQLEXPR_x64_ENU from Microsoft" -ForegroundColor Yellow
                Start-Process @processOptions -Wait -ErrorAction SilentlyContinue;
            }
            Catch {
                Write-Error "$($Error[0].Exception.Message)"
            }
            
            If (Test-Path -Path $sqlExprFileName -PathType Leaf) { 
                Write-Host "Download SQLEXPR_x64_ENU succeeded" -ForegroundColor Green 
                Remove-Item -Path "$dirAddons/output.txt" -Force -ErrorAction SilentlyContinue
            }
        }

        Try {
            Install-Program -pName $SqlServerProductName -InstallerPath $sqlExprFileName -Arguments $argFile;
        } 
        Catch {
            Write-Error "$SqlServerProductName installation failed";
        }
    }
}

#------------------------------
# check and install SSMS
$ssms = "SQL Server Management Studio"
$ssmsUrl = "https://download.microsoft.com/download/a/3/2/a32ae99f-b6bf-4a49-a076-e66503ccb925/SSMS-Setup-ENU.exe";
[bool]$ssmsMatchAsBool = $installedPrograms -match $ssms
$regex = "\bSSMS-Setup-(ENU|CHS)\.exe\b"
$fileMatch = Get-ChildItem -Path $dirAddons | Where-Object { $_.Name -match $regex }
If ($ssmsMatchAsBool) {
    Write-Host "$ssms was Installed" -ForegroundColor Green
} Else {
    If($fileMatch) {
        $fileName = (Get-ChildItem -Path $dirAddons | Where-Object { $_.Name -match $regex }).Name
        $ssmsFileName = Join-Path $dirAddons $fileName
        Install-Program -pName $ssms -InstallerPath $ssmsFileName -Arguments "/quiet /norestart"
    } Else {
        If (Test-Valid4Download -URL $ssmsUrl) {
           Save-File -Name $ssms -URL $ssmsUrl -DwPathName $ssmsFileName
            If($fileExist) {
                Install-Program -pName $ssms -InstallerPath $ssmsFileName -Arguments "/quiet /norestart"
            }
            $fileExist = $False;
		} else {
			Write-Host "File is not available for download." -ForegroundColor Red
            Write-Host "Please download and install $ssms manually" -ForegroundColor Red
            Start-Sleep -Seconds 5
			exit
		}  
    }
}

Start-Sleep -Seconds 3
Write-Host
Write-Host "----------------" -ForegroundColor DarkCyan
Write-Host "All done, Enjoy!" -ForegroundColor DarkCyan
Write-Host "----------------" -ForegroundColor DarkCyan
Start-Sleep -Seconds 10
