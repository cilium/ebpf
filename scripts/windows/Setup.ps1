# Configure a fresh installation of Windows via SSH.

param (
  [switch] $RunOnce = $false
)

if ($RunOnce) {
  # Visual Studio really doesn't seem to like being installed via SSH, so
  # we invoke from a RunOnce script.
  Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/scripts/Setup-DevEnv.ps1' -OutFile $env:TEMP\Setup-DevEnv.ps1
  &"$env:TEMP\Setup-DevEnv.ps1"

  # sshd needs to be restarted to pick up new environment variables.
  Restart-Service sshd

  return
}

# Enable Developer Mode (so that symlinks work)
# See https://stackoverflow.com/a/40033638
$RegistryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
New-Item -Path $RegistryKeyPath -ItemType Directory -Force
New-ItemProperty -Path $RegistryKeyPath -Name AllowDevelopmentWithoutDevLicense -PropertyType DWORD -Value 1 -Force

# Ensure we have a PROFILE.
#
# This also allows chocolatey to add its hooks.
if (!(Test-Path -Path $PROFILE)) {
  New-Item -ItemType File -Path $PROFILE -Force
}

# Add VS tools to PATH
$addVsToolsToPath = @'
# Add VS to PATH
function Import-VsEnv {
  $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $vspath = & $vswherePath -property installationPath
  $vsDevShell = "${vspath}\Common7\Tools\Launch-VsDevShell.ps1"
  & $vsDevShell -SkipAutomaticLocation
}
'@

if (-not (Get-Content $PROFILE | Select-String "Add VS to PATH")) {
    $addVsToolsToPath | Add-Content -Path $PROFILE
}

# Enable git symlink support globally.
$gitConfig = "${HOME}/.gitconfig"
if (!(Test-Path -Path $gitConfig)) {
  New-Item -ItemType File -Path $gitConfig -Force
}

if (-not (Get-Content $gitConfig | Select-String "symlinks = true")) {
  @'
[core]
symlinks = true
'@ | Add-Content -Path $gitConfig
}

# Install winget version which supports configure -f
# if ([version]($(winget --version).substring(1)) -lt [version]'1.6.0') {
#   echo "Updating winget"
#   # From https://andrewstaylor.com/2023/11/28/winget-powershell-module/
#   Get-PackageProvider NuGet -ForceBootstrap | Out-Null
#   install-module microsoft.winget.client -Force -AllowClobber
#   import-module microsoft.winget.client
#   repair-wingetpackagemanager -Force -Latest -AllUsers
# }

echo "Scheduling installation of eBPF for Windows dependencies for next reboot."
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name 'InstallEFWDependencies' -Value "powershell.exe -command `"start -verb runas powershell.exe -argumentlist \`"-file $PSCommandPath -RunOnce\`""

echo "Rebooting."
Restart-Computer -Force
