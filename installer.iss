; Inno Setup Script for CHARLO Testing Agent
; Compiles the PyInstaller dist directory into a professional Windows Setup Installer

#define MyAppName "CHARLO Testing Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CHARLO Engineering"
#define MyAppExeName "CharloTestingAgent.exe"

[Setup]
AppId={{D8A145C8-3F1E-4819-86BC-5F597AE69941}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\CharloTestingAgent
DefaultGroupName={#MyAppName}
OutputDir=dist_installer
OutputBaseFilename=CharloTestingAgent_Setup_v1.0.0
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\CharloTestingAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
