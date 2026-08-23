#!/usr/bin/env bash
# Cloud Agent install script for ICS OT Protector.
# Idempotent: safe to run repeatedly and against a cached/snapshotted VM.
#
# The repo ships Bash + PowerShell scanners plus Bash/Pester test suites and a
# Python config compiler. CI (.github/workflows/ci.yml) needs: PowerShell with
# the PSScriptAnalyzer + Pester modules, python3 with PyYAML, and the jq +
# coreutils(timeout) tooling the Bash scan engine depends on.
set -euo pipefail

log() { printf '[install] %s\n' "$*"; }

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
fi

# --- System packages the Bash scanners, tests, and config compiler rely on ---
export DEBIAN_FRONTEND=noninteractive
log "Updating apt package lists"
$SUDO apt-get update -qq

log "Ensuring base tooling (jq, coreutils, git, curl, python3, PyYAML, shellcheck)"
$SUDO apt-get install -y -qq --no-install-recommends \
  jq coreutils git curl ca-certificates \
  python3 python3-yaml \
  shellcheck \
  wget apt-transport-https >/dev/null

# --- PowerShell (pwsh) for the PowerShell scanners, lint, and Pester tests ---
if ! command -v pwsh >/dev/null 2>&1; then
  log "Installing PowerShell via the Microsoft package repository"
  # shellcheck disable=SC1091
  . /etc/os-release
  tmp_deb="$(mktemp --suffix=.deb)"
  wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -O "$tmp_deb"
  $SUDO dpkg -i "$tmp_deb"
  rm -f "$tmp_deb"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq powershell >/dev/null
else
  log "PowerShell already present: $(pwsh --version)"
fi

# --- PowerShell modules required by CI lint + tests (CurrentUser scope) ---
log "Ensuring PSScriptAnalyzer and Pester modules"
# shellcheck disable=SC2016  # PowerShell script body; $m is a PowerShell var, not a Bash one.
pwsh -NoProfile -Command '
  $ErrorActionPreference = "Stop"
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  foreach ($m in "PSScriptAnalyzer","Pester") {
    if (-not (Get-Module -ListAvailable -Name $m)) {
      Write-Host "[install] Installing PowerShell module $m"
      Install-Module $m -Scope CurrentUser -Force
    } else {
      Write-Host "[install] PowerShell module $m already installed"
    }
  }
'

log "Compiling sector configs (validates YAML -> JSON)"
python3 "$(dirname "${BASH_SOURCE[0]}")/../scripts/config/compile_configs.py"

log "Environment ready."
pwsh --version
jq --version
python3 --version
