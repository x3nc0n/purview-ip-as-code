[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$templateSource = Join-Path $repositoryRoot 'extensions\scanner\infra\main.bicep'
$templateOutput = Join-Path $repositoryRoot 'extensions\scanner\infra\azuredeploy.json'
$bootstrapSource = Join-Path $PSScriptRoot 'Invoke-LabBootstrap.ps1'
$generatedContent = Join-Path $repositoryRoot 'demo\content\generated'
$fixtureManifest = Join-Path $repositoryRoot 'demo\manifests\fixtures.json'
$destination = [System.IO.Path]::GetFullPath($OutputDirectory)
$staging = Join-Path ([System.IO.Path]::GetTempPath()) "pipascode-release-$([guid]::NewGuid().ToString('N'))"
[void](New-Item -ItemType Directory -Path $destination, $staging -Force)

try {
    $compiledTemplate = Join-Path $staging 'azuredeploy.json'
    & az bicep build --file $templateSource --outfile $compiledTemplate
    if ($LASTEXITCODE -ne 0) {
        throw 'Bicep compilation failed.'
    }
    $compiled = [System.IO.File]::ReadAllBytes($compiledTemplate)
    $committed = [System.IO.File]::ReadAllBytes($templateOutput)
    if ([Convert]::ToBase64String($compiled) -ne [Convert]::ToBase64String($committed)) {
        throw 'Compiled ARM JSON differs from the reviewed committed artifact; regenerate and review it before release.'
    }
    if (-not (Test-Path -LiteralPath $generatedContent -PathType Container) -or -not (Test-Path -LiteralPath $fixtureManifest -PathType Leaf)) {
        throw 'Synthetic fixture content or its manifest is missing.'
    }

    Copy-Item -LiteralPath $compiledTemplate -Destination (Join-Path $destination 'azuredeploy.json') -Force
    Copy-Item -LiteralPath $bootstrapSource -Destination (Join-Path $destination 'Invoke-LabBootstrap.ps1') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Connect-ScannerCluster.ps1') -Destination (Join-Path $destination 'Connect-ScannerCluster.ps1') -Force
    [void](New-Item -ItemType Directory -Path (Join-Path $staging 'generated') -Force)
    Copy-Item -Path (Join-Path $generatedContent '*') -Destination (Join-Path $staging 'generated') -Recurse -Force
    Copy-Item -LiteralPath $fixtureManifest -Destination (Join-Path $staging 'fixtures.json') -Force
    Add-Type -AssemblyName System.IO.Compression
    $zipPath = Join-Path $destination 'demo-content.zip'
    $zipStream = [System.IO.File]::Create($zipPath)
    $archive = [System.IO.Compression.ZipArchive]::new($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $staging 'generated') -File -Recurse)
        $files += Get-Item -LiteralPath (Join-Path $staging 'fixtures.json')
        foreach ($file in ($files | Sort-Object FullName)) {
            $entryName = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
            $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [datetimeoffset]::new(2000, 1, 1, 0, 0, 0, [timespan]::Zero)
            $entryStream = $entry.Open()
            $sourceStream = [System.IO.File]::OpenRead($file.FullName)
            try {
                $sourceStream.CopyTo($entryStream)
            }
            finally {
                $sourceStream.Dispose()
                $entryStream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
        $zipStream.Dispose()
    }

    $assetNames = @('azuredeploy.json', 'Invoke-LabBootstrap.ps1', 'Connect-ScannerCluster.ps1', 'demo-content.zip')
    $sumLines = foreach ($name in $assetNames) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $destination $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [System.IO.File]::WriteAllLines((Join-Path $destination 'SHA256SUMS.txt'), $sumLines, [System.Text.UTF8Encoding]::new($false))
    Get-ChildItem -LiteralPath $destination -File | Sort-Object Name | Select-Object Name, Length, @{Name = 'Sha256'; Expression = { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }}
}
finally {
    if (Test-Path -LiteralPath $staging -PathType Container) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}
