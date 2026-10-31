# 在 Windows 上打出 Linux 发布包：dist/megrez-<版本>-linux-amd64.tar.gz
# 用法：powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Version v1.0.0
param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$name = "megrez-$Version-linux-amd64"
$distDir = Join-Path $root "dist"
$outDir = Join-Path $distDir $name
$tarPath = Join-Path $distDir "$name.tar.gz"

New-Item -ItemType Directory -Force $distDir | Out-Null
Remove-Item $outDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $outDir | Out-Null

$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"

Push-Location $root
try {
    & go build -trimpath -ldflags="-s -w" -o (Join-Path $outDir "megrez") ./cmd/megrez
} finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $outDir "megrez"))) {
    throw "go build failed: 编译失败"
}

Copy-Item -Path "deploy\install.sh" -Destination $outDir
Copy-Item -Path "deploy\megrez.service" -Destination $outDir

& tar -czf $tarPath -C $distDir $name
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tarPath)) {
    throw "tar failed: 打包失败"
}

$sizeMB = [math]::Round((Get-Item $tarPath).Length / 1MB, 2)
Write-Host ""
Write-Host "OK. PACKAGE: $tarPath"
Write-Host "SIZE: $sizeMB MB"
Write-Host "FILES:"
& tar -tzf $tarPath
