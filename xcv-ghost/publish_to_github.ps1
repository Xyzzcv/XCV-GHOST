<#
.SYNOPSIS
    One-click GitHub publisher for XCV-GHOST
.DESCRIPTION
    Creates a public GitHub repo and pushes all code.
    Requires a GitHub Personal Access Token (scope: repo, workflow, delete_repo)
    Get one at: https://github.com/settings/tokens
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$GitHubToken,

    [Parameter(Mandatory=$false)]
    [string]$GitHubUser = "xcv-onee",

    [Parameter(Mandatory=$false)]
    [string]$RepoName = "XCV-GHOST",

    [Parameter(Mandatory=$false)]
    [string]$Description = "AI-Powered CTF Framework - Forensics, Crypto, PWN, Reverse, AI Solver (Gemini)"
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Creating GitHub repository: $GitHubUser/$RepoName" -ForegroundColor Cyan

# Create repo via GitHub API
$headers = @{
    "Authorization" = "Bearer $GitHubToken"
    "Accept"        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

$body = @{
    name = $RepoName
    description = $Description
    private = $false
    auto_init = $false
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method POST -Headers $headers -Body $body
    Write-Host "[+] Repository created: $($response.html_url)" -ForegroundColor Green
} catch {
    if ($_.Exception.Response.StatusCode -eq 422) {
        Write-Host "[*] Repository already exists, skipping creation..." -ForegroundColor Yellow
    } else {
        Write-Error "Failed to create repo: $($_.Exception.Message)"
        exit 1
    }
}

# Add remote and push
$remoteUrl = "https://$GitHubToken@github.com/$GitHubUser/$RepoName.git"
git remote remove origin 2>$null
git remote add origin $remoteUrl
git branch -M main
git push -u origin main

Write-Host ""
Write-Host "[+] Done! Repository at: https://github.com/$GitHubUser/$RepoName" -ForegroundColor Green
Write-Host "[*] Clone with: git clone https://github.com/$GitHubUser/$RepoName.git" -ForegroundColor Cyan
