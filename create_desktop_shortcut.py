import os
import sys
import subprocess

desktop_dirs = [
    os.path.join(os.environ.get("USERPROFILE", r"C:\Users\HP"), "OneDrive", "Desktop"),
    os.path.join(os.environ.get("USERPROFILE", r"C:\Users\HP"), "Desktop"),
]

pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
if not os.path.exists(pythonw_exe):
    pythonw_exe = sys.executable

repo_dir = os.path.abspath(os.path.dirname(__file__))
main_py = os.path.join(repo_dir, "main.py")
ico_file = os.path.join(repo_dir, "charlo_icon.ico")

ps_script_path = os.path.join(repo_dir, "create_shortcut.ps1")
ps_content = f"""
$targetExe = '{pythonw_exe}'
$scriptPath = '{main_py}'
$workingDir = '{repo_dir}'
$iconPath = '{ico_file}'
$wsh = New-Object -ComObject WScript.Shell

$desktops = @(
    '{desktop_dirs[0]}',
    '{desktop_dirs[1]}'
)

foreach ($d in $desktops) {{
    if (-not (Test-Path $d)) {{
        try {{ New-Item -ItemType Directory -Path $d -Force | Out-Null }} catch {{}}
    }}
    if (Test-Path $d) {{
        $lnk = Join-Path $d 'CHARLO Testing Agent.lnk'
        $s = $wsh.CreateShortcut($lnk)
        $s.TargetPath = $targetExe
        $s.Arguments = "`"$scriptPath`""
        $s.WorkingDirectory = $workingDir
        $s.IconLocation = "$iconPath,0"
        $s.Description = 'CHARLO Testing Agent - AI Security Testing Laboratory'
        $s.Save()
        Write-Host "SUCCESS: Created shortcut at $lnk"
    }}
}}
"""

with open(ps_script_path, "w", encoding="utf-8") as f:
    f.write(ps_content)

res = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path], capture_output=True, text=True)
print(res.stdout)
if res.stderr:
    print(res.stderr)
