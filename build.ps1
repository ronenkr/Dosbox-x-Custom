<#
.SYNOPSIS
  Build the LLM-harness flavour of DOSBox-X (agent + debugger + headless) with VS 2022.

.EXAMPLE
  .\build.ps1                       # Agent Release SDL2 | x64
  .\build.ps1 -Configuration "Agent Debug SDL2"
  .\build.ps1 -Target dosbox-x      # only the emulator, skip dependency libraries
  .\build.ps1 -StopRunning          # first stop instances running from the output folder
#>
param(
    [string]$Configuration = "Agent Release SDL2",
    [string]$Platform = "x64",
    [string]$Target = "",
    [switch]$Clean,
    [switch]$StopRunning
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install Visual Studio 2022 Build Tools" }

# The agent configurations use the v143 toolset, which ships with VS 2022 (version 17.x).
$vsPath = & $vswhere -products * -version "[17.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $vsPath) { throw "Visual Studio 2022 with the C++ x64 tools was not found" }
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"

# A running instance locks the executable and makes the link step fail.
$targetExe = Join-Path $root "bin\$Platform\$Configuration\dosbox-x.exe"
$running = Get-Process dosbox-x -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $targetExe }
if ($running) {
    if ($StopRunning) { $running | Stop-Process -Force; Start-Sleep -Milliseconds 500 }
    else { throw "dosbox-x.exe is running from the output folder (PID $($running.Id -join ', ')); close it or pass -StopRunning" }
}

$msbuildArgs = @(
    (Join-Path $root "vs\dosbox-x.sln"),
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    # Dependency projects still say v142 (VS 2019); build everything with the installed v143.
    "/p:PlatformToolset=v143",
    "/m",
    "/nologo",
    "/verbosity:minimal"
)
if ($Target) { $msbuildArgs += "/t:$Target" }
if ($Clean) { $msbuildArgs += "/t:Clean" }

Write-Host "Building $Configuration|$Platform with $msbuild"
& $msbuild @msbuildArgs
if ($LASTEXITCODE -ne 0) { throw "MSBuild failed with exit code $LASTEXITCODE" }

$exe = Join-Path $root "bin\$Platform\$Configuration\dosbox-x.exe"
if (Test-Path $exe) { Write-Host "Built: $exe" }
