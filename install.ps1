$ErrorActionPreference = "Stop"

$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillsDir = if ($env:CLAUDE_SKILLS_DIR) { $env:CLAUDE_SKILLS_DIR } else { Join-Path $env:USERPROFILE ".claude\skills" }
$Target = Join-Path $SkillsDir "ai-security-guard"

if (Test-Path $Target) {
    Write-Host "目标已存在：$Target"
    Write-Host "先备份或删除它，再重跑本脚本。"
    exit 1
}

New-Item -ItemType Directory -Force -Path $SkillsDir | Out-Null
Copy-Item -Path $RepoDir -Destination $Target -Recurse -Force
Remove-Item -Path (Join-Path $Target ".git") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $Target "scripts\__pycache__") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $Target "tests\__pycache__") -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "已安装到：$Target"
Write-Host ""
Write-Host "试跑："
Write-Host "  python `"$Target\scripts\guard.py`" scan ."
Write-Host ""
Write-Host "在你的项目里装自动体检："
Write-Host "  cd C:\path\to\your-project"
Write-Host "  python `"$Target\scripts\guard.py`" install-hook"
