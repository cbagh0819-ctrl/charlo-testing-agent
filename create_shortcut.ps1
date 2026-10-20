
$targetExe = 'C:\Users\HP\AppData\Local\Programs\Python\Python312\pythonw.exe'
$scriptPath = 'C:\Users\HP\.gemini\antigravity\scratch\charlo-testing-agent\main.py'
$workingDir = 'C:\Users\HP\.gemini\antigravity\scratch\charlo-testing-agent'
$iconPath = 'C:\Users\HP\.gemini\antigravity\scratch\charlo-testing-agent\charlo_icon.ico'
$wsh = New-Object -ComObject WScript.Shell

$desktops = @(
    'C:\Users\HP\OneDrive\Desktop',
    'C:\Users\HP\Desktop'
)

foreach ($d in $desktops) {
    if (-not (Test-Path $d)) {
        try { New-Item -ItemType Directory -Path $d -Force | Out-Null } catch {}
    }
    if (Test-Path $d) {
        $lnk = Join-Path $d 'CHARLO Testing Agent.lnk'
        $s = $wsh.CreateShortcut($lnk)
        $s.TargetPath = $targetExe
        $s.Arguments = "`"$scriptPath`""
        $s.WorkingDirectory = $workingDir
        $s.IconLocation = "$iconPath,0"
        $s.Description = 'CHARLO Testing Agent - AI Security Testing Laboratory'
        $s.Save()
        Write-Host "SUCCESS: Created shortcut at $lnk"
    }
}
