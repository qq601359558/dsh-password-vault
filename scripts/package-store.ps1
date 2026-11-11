param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$package = Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
$name = [string]$package.name
$version = [string]$package.version

$dist = Join-Path $root 'dist'
$stageParent = Join-Path $dist 'stage'
$stage = Join-Path $stageParent $name
$zip = Join-Path $dist "$name-$version.zip"

if (Test-Path -LiteralPath $dist) {
    Remove-Item -LiteralPath $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$files = @(
    'package.json',
    'plugin.json',
    'dsh.plugin.json',
    'cordis.patch.yml',
    'index.js',
    'client.js',
    'README.md',
    'PUBLISH.md',
    'LICENSE',
    'icon.svg'
)
foreach ($file in $files) {
    $source = Join-Path $root $file
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing required file: $file"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $file)
}

foreach ($dir in @('lib', 'locale')) {
    $source = Join-Path $root $dir
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing required directory: $dir"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stage $dir) -Recurse
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stageParent, $zip)
Remove-Item -LiteralPath $stageParent -Recurse -Force

$info = Get-Item -LiteralPath $zip
Write-Output "Created: $($info.FullName)"
Write-Output "Bytes: $($info.Length)"
