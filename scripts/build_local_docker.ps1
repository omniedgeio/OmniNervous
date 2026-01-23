# scripts/build_local_docker.ps1
# Builds omninervous using Docker and extracts the binary.
# Best for native amd64 builds.

# Run with:
# powershell -ExecutionPolicy Bypass -File D:\Project-OmniEdge\OmniNervous\scripts\build_local_docker.ps1

$ErrorActionPreference = "Stop"

# Configuration
$ImageName = "omninervous-build-local"
$BinaryName = "omninervous"
$OutputPath = "scripts/omninervous-linux-amd64"

# Get project root
$ScriptDir = $PSScriptRoot
$ProjectRoot = Resolve-Path "$ScriptDir/.."

Write-Host "Building $BinaryName using Docker..."
Push-Location "$ProjectRoot"

try {
    # 0. Preparation: Copy local boringtun to build context
    Write-Host "Staging local boringtun..."
    $BoringTunSrc = Resolve-Path "$ProjectRoot/../boringtun"
    $BoringTunDest = "$ProjectRoot/boringtun_temp"
    
    if (Test-Path $BoringTunDest) { Remove-Item -Recurse -Force $BoringTunDest }
    Copy-Item -Recurse -Force "$BoringTunSrc" "$BoringTunDest"
    
    # 1. Build the Docker image
    # Use -f Dockerfile.local
    docker build -f Dockerfile.local --platform linux/amd64 --no-cache -t "$ImageName" .
    if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }

    # 2. Extract the binary
    Write-Host "Extracting binary to $OutputPath..."
    $ContainerId = docker create --platform linux/amd64 "$ImageName"
    if ($LASTEXITCODE -ne 0) { throw "Docker create failed" }

    # Ensure output directory exists
    docker cp "$ContainerId`:/usr/local/bin/$BinaryName" "$ProjectRoot/$OutputPath"
    if ($LASTEXITCODE -ne 0) { 
        docker rm "$ContainerId" | Out-Null
        if (Test-Path $BoringTunDest) { Remove-Item -Recurse -Force $BoringTunDest }
        throw "Docker cp failed" 
    }

    docker rm "$ContainerId" | Out-Null
    
    # Cleanup staged folder
    if (Test-Path $BoringTunDest) { Remove-Item -Recurse -Force $BoringTunDest }

    # 3. Cleanup (optional)
    # docker system prune -f # safer

    Write-Host "Build complete: $OutputPath"
    Get-Item "$ProjectRoot/$OutputPath" | Select-Object Name, Length, LastWriteTime
}
finally {
    Pop-Location
}
