# Get the root directory of the repository
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$rootDir = Split-Path -Parent $scriptDir

# Clear log files
Get-ChildItem -Path "$rootDir/logs" -Filter *.log -Recurse | ForEach-Object { Remove-Item $_.FullName -Force }

# Clear __pycache__ directories
Get-ChildItem -Path $rootDir -Recurse -Directory -Filter "__pycache__" | ForEach-Object { Remove-Item $_.FullName -Recurse -Force }