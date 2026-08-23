#Requires -Version 5.1
<#
.SYNOPSIS
    Offline triage review for ICS OT Protector JSON scan reports.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$ReportPath,

    [switch]$Markdown
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ReportPath)) {
    throw "Report not found: $ReportPath"
}

$doc = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
$summary = $doc.metadata.summary
$findings = @($doc.findings | Sort-Object @{
    Expression = {
        switch ($_.RemediationPriority) {
            'IMMEDIATE' { 0 }
            'URGENT'    { 1 }
            default     { 2 }
        }
    }
}, Host, Port)

if ($Markdown) {
    "# Scan report review"
    ''
    "**Sector:** $($doc.metadata.sector) | **Scanner:** $($doc.metadata.scanner)"
    "**Generated:** $($doc.generated_at)"
    ''
    '## Summary'
    "- Hosts scanned: $($summary.hosts_scanned)"
    "- Findings: $($summary.findings_total)"
    "- Duration: $([math]::Round($summary.duration_ms / 1000, 1))s"
    ''
    '### By priority'
    foreach ($entry in ($summary.findings_by_priority.PSObject.Properties | Sort-Object Name)) {
        "- $($entry.Name): $($entry.Value)"
    }
    ''
    '### Top hosts'
    foreach ($hostEntry in @($summary.top_hosts)) {
        "- $($hostEntry.host): $($hostEntry.findings) finding(s)"
    }
    ''
    '## Findings'
    foreach ($f in $findings) {
        ''
        "### [$($f.RemediationPriority)] $($f.Host):$($f.Port) — $($f.Service)"
        "- **Severity:** $($f.Severity) | **Category:** $($f.Category) | **Owner:** $($f.OwnerRole) | **Action:** $($f.RemediationAction)"
        "- $($f.Description)"
        "- _Remediation:_ $($f.Remediation)"
    }
    return
}

Write-Host '=== ICS OT Protector — Report Review ==='
Write-Host "Sector:     $($doc.metadata.sector)"
Write-Host "Scanner:    $($doc.metadata.scanner)"
Write-Host "Generated:  $($doc.generated_at)"
Write-Host ''
Write-Host 'SUMMARY'
Write-Host "  Hosts scanned: $($summary.hosts_scanned)"
Write-Host "  Findings:      $($summary.findings_total)"
Write-Host "  Duration:      $([math]::Round($summary.duration_ms / 1000, 1))s"
Write-Host ''
Write-Host 'BY PRIORITY'
foreach ($entry in ($summary.findings_by_priority.PSObject.Properties | Sort-Object Name)) {
    Write-Host "  $($entry.Name): $($entry.Value)"
}
Write-Host ''
Write-Host 'TOP HOSTS'
foreach ($hostEntry in @($summary.top_hosts)) {
    Write-Host "  $($hostEntry.host): $($hostEntry.findings) finding(s)"
}
Write-Host ''
Write-Host 'FINDINGS'
foreach ($f in $findings) {
    Write-Host "[$($f.RemediationPriority)] $($f.Host):$($f.Port) $($f.Service) ($($f.Severity))"
    Write-Host "  owner=$($f.OwnerRole) action=$($f.RemediationAction) category=$($f.Category)"
    Write-Host "  $($f.Description)"
    Write-Host "  -> $($f.Remediation)"
    Write-Host ''
}
