#!/usr/bin/env pwsh

$ErrorActionPreference = 'Stop'
$owner = "rusty-ferris-club"
$repo = "shellclear"
$BinDir = "$Home\.shellclear\bin"
$downloadedFilePath = "${BinDir}\shellclear.zip"
$exeName = "shellclear.exe"
$downloadedExe = "$BinDir\$packageName\${exeName}"

# Get latest shellclear version from github API
$tag = (Invoke-RestMethod -Method GET -Uri "https://api.github.com/repos/${owner}/${repo}/releases")[0].tag_name
Write-Output "Latest tag: ${tag}"

$packageName = "shellclear-${tag}-x86_64-windows"

# GitHub requires TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ResourceUri = "https://github.com/${owner}/${repo}/releases/download/${tag}/${packageName}.zip"

Write-Output "download shellclear binary: ${ResourceUri}"

# Create bin dir if not exists
if (!(Test-Path $BinDir)) {
  New-Item $BinDir -ItemType Directory | Out-Null
}

# Download shellclear zip file from GitHub releases
Invoke-WebRequest $ResourceUri -OutFile $downloadedFilePath -UseBasicParsing -ErrorAction Stop

function Expand-Tar($tarFile, $dest) {

    if (-not (Get-Command Expand-7Zip -ErrorAction Ignore)) {
        Install-Package -Scope CurrentUser -Force 7Zip4PowerShell > $null           
    }
    Expand-7Zip $tarFile $dest
    Copy-Item "$BinDir\$packageName\${exeName}" $BinDir -Force
}

# Unzip download file
Expand-Tar $downloadedFilePath $BinDir

# Remove download file + zip folder
Remove-Item $downloadedFilePath
Remove-Item $BinDir\$packageName -Force -Recurse

$User = [EnvironmentVariableTarget]::User
$Path = [Environment]::GetEnvironmentVariable('Path', $User)
if (!(";$Path;".ToLower() -like "*;$BinDir;*".ToLower())) {
  [Environment]::SetEnvironmentVariable('Path', "$Path;$BinDir", $User)
  $Env:Path += ";$BinDir"
}

Write-Output "${exeName} was installed successfully to $downloadedExe"
Write-Output "Run '${exeName} --help' to get started"