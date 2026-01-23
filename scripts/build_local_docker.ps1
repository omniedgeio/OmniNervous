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
    # 1. Build the Docker image
    docker build --platform linux/amd64 --no-cache -t "$ImageName" .
    if ($LASTEXITCODE -ne 0) { throw "Docker build failed" }

    # 2. Extract the binary
    Write-Host "Extracting binary to $OutputPath..."
    $ContainerId = docker create "$ImageName"
    if ($LASTEXITCODE -ne 0) { throw "Docker create failed" }

    # Ensure output directory exists
    # If the destination is a file path, 'docker cp' on Windows/Linux works if the parent directory exists.
    # The parent is 'scripts', which definitely exists.
    
    # Note: We use quotes around the source path to handle variables, but avoid backticks unless necessary.
    # "$ContainerId:/..." is safe.
    docker cp "$ContainerId`:/usr/local/bin/$BinaryName" "$ProjectRoot/$OutputPath"
    if ($LASTEXITCODE -ne 0) { 
        docker rm "$ContainerId" | Out-Null
        throw "Docker cp failed" 
    }

    docker rm "$ContainerId" | Out-Null

    # 3. Cleanup (optional)
    # docker system prune -f # safer

    Write-Host "Build complete: $OutputPath"
    Get-Item "$ProjectRoot/$OutputPath" | Select-Object Name, Length, LastWriteTime
}
finally {
    Pop-Location
}
