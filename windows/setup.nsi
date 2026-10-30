; Setup for VirusTotal Quarantine. Installs Python for this account if there is no
; Python 3.11 or newer (and leaves it installed when the program is removed: other
; programs may use it), saves the VirusTotal API key, then installs the .msi.
; Built by build.py, which passes VERSION, MSI, ICON, OUTFILE, OLDEST and NEWEST.
; Silent install: setup.exe /S (the key can be entered later from the notification).

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma
AutoCloseWindow true  ; straight on to the last page once installed

!include MUI2.nsh
!include LogicLib.nsh
!include nsDialogs.nsh
!include x64.nsh
!include WinMessages.nsh

; Downloaded only when needed; checked against these before running.
!define PY_VERSION 3.14.10
!define PY_URL https://www.python.org/ftp/python/${PY_VERSION}
!define PY_AMD64 python-${PY_VERSION}-amd64.exe
!define PY_AMD64_SHA256 92480239264744fe0386a1bd8275786fefa126e3129e56a68e22b52c73329965
!define PY_ARM64 python-${PY_VERSION}-arm64.exe
!define PY_ARM64_SHA256 5b9547e4edae2f6fb2fbfec5e26cf91b4ea191e3b07f7727d5a2c5c2cca93ed3
!define PY_X86 python-${PY_VERSION}.exe
!define PY_X86_SHA256 c8f1a16db9afd76ca74b5f8e28eeaad408bca10894c9d080443bde83def3ed09
; Just what's needed: no launcher, shortcuts, file associations, docs, tests, IDLE or pip.
!define PY_OPTIONS "/quiet InstallAllUsers=0 Include_launcher=0 InstallLauncherAllUsers=0 Shortcuts=0 AssociateFiles=0 Include_doc=0 Include_test=0 Include_tcltk=0 Include_dev=0 Include_pip=0 PrependPath=0"

!define KEY_URL https://www.virustotal.com/gui/my-apikey
!define HELP_URL https://github.com/ArianARahimi/vt-quarantine#browser-setup

Name "VirusTotal Quarantine"
Caption "VirusTotal Quarantine ${VERSION} Setup"
OutFile "${OUTFILE}"
BrandingText "vt-quarantine ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "VirusTotal Quarantine"
VIAddVersionKey "FileDescription" "VirusTotal Quarantine Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "vt-quarantine"
VIAddVersionKey "LegalCopyright" "MIT License"

!define MUI_ICON "${ICON}"
Page custom WelcomePage WelcomeLeave
!insertmacro MUI_PAGE_INSTFILES
Page custom DonePage
!insertmacro MUI_LANGUAGE "English"

Var Pythonw         ; pythonw.exe to run it with; empty while there is none
Var PythonInstalled ; 1 if this setup installed Python
Var Key
Var KeyField
Var Quarantine

!define KEY_FILE "$APPDATA\vt-quarantine\api_key"

!macro Fail MSG
  ; Kept for silent installs, which show no message.
  FileOpen $9 "$TEMP\vt-quarantine-setup-error.txt" w
  FileWrite $9 "${MSG}$\r$\n"
  FileClose $9
  MessageBox MB_ICONSTOP|MB_OK "${MSG}" /SD IDOK
  SetErrorLevel 1
  Abort
!macroend

; --- Finding Python (the same places, in the same order, as the .msi) ------------

!macro TryPython ROOT VIEW TAG
  ${If} $Pythonw == ""
    SetRegView ${VIEW}
    ReadRegStr $0 ${ROOT} "Software\Python\PythonCore\${TAG}\InstallPath" "WindowedExecutablePath"
    ${If} $0 != ""
    ${AndIf} ${FileExists} "$0"
      ; The Microsoft Store Python keeps registry writes to itself, so
      ; notifications and autostart wouldn't work from it.
      System::Call 'shlwapi::StrStrIW(w r0, w "\WindowsApps\") p.r1'
      ${If} $1 = 0
        StrCpy $Pythonw $0
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

!macro TryPythonTag TAG
  !insertmacro TryPython HKCU 64 "${TAG}"
  !insertmacro TryPython HKLM 64 "${TAG}"
  !insertmacro TryPython HKLM 32 "${TAG}"
!macroend

Function FindPython
  StrCpy $Pythonw ""
  StrCpy $R9 ${NEWEST}
  ${DoWhile} $R9 >= ${OLDEST}
    !insertmacro TryPythonTag "3.$R9"
    !insertmacro TryPythonTag "3.$R9-arm64"
    !insertmacro TryPythonTag "3.$R9-32"
    IntOp $R9 $R9 - 1
  ${Loop}
  SetRegView default
FunctionEnd

; SHA-256 of the file in $R0, as lowercase hex in $R1 ("" if it can't be read).
; Changes $0-$7.
Function Sha256File
  StrCpy $R1 ""
  System::Call 'kernel32::CreateFileW(w R0, i 0x80000000, i 1, p 0, i 3, i 0x80, p 0) p.r1'
  ${If} $1 = -1
    Return
  ${EndIf}
  System::Call 'advapi32::CryptAcquireContextW(*p .r2, p 0, p 0, i 24, i 0xF0000000) i.r0'
  System::Call 'advapi32::CryptCreateHash(p r2, i 0x800C, p 0, i 0, *p .r3) i.r0'
  System::Alloc 65536
  Pop $4
  ${Do}
    System::Call 'kernel32::ReadFile(p r1, p r4, i 65536, *i .r5, p 0) i.r0'
    ${If} $0 = 0
    ${OrIf} $5 = 0
      ${Break}
    ${EndIf}
    System::Call 'advapi32::CryptHashData(p r3, p r4, i r5, i 0)'
  ${Loop}
  System::Call 'advapi32::CryptGetHashParam(p r3, i 2, p r4, *i 32, i 0) i.r0'
  ${If} $0 <> 0
    StrCpy $5 0
    ${Do}
      IntOp $7 $4 + $5
      System::Call '*$7(&i1 .r6)'
      IntOp $6 $6 & 0xFF
      IntFmt $6 "%02x" $6
      StrCpy $R1 "$R1$6"
      IntOp $5 $5 + 1
    ${LoopUntil} $5 = 32
  ${EndIf}
  System::Free $4
  System::Call 'advapi32::CryptDestroyHash(p r3)'
  System::Call 'advapi32::CryptReleaseContext(p r2, i 0)'
  System::Call 'kernel32::CloseHandle(p r1)'
FunctionEnd

Function InstallPython
  ${If} ${IsNativeARM64}
    StrCpy $1 "${PY_ARM64}"
    StrCpy $R2 "${PY_ARM64_SHA256}"
  ${ElseIf} ${IsNativeAMD64}
    StrCpy $1 "${PY_AMD64}"
    StrCpy $R2 "${PY_AMD64_SHA256}"
  ${Else}
    StrCpy $1 "${PY_X86}"
    StrCpy $R2 "${PY_X86_SHA256}"
  ${EndIf}
  DetailPrint "Downloading Python ${PY_VERSION} from python.org..."
  StrCpy $R0 "$PLUGINSDIR\$1"
  System::Call 'urlmon::URLDownloadToFileW(p 0, w "${PY_URL}/$1", w R0, i 0, p 0) i.r0'
  ${If} $0 <> 0
    !insertmacro Fail "Python couldn't be downloaded. Check your internet connection and run setup again."
  ${EndIf}
  Call Sha256File  ; uses $0-$7
  ${If} $R1 != $R2
    Delete $R0
    !insertmacro Fail "The Python download isn't the file it should be, so it was not run. Run setup again."
  ${EndIf}
  DetailPrint "Installing Python ${PY_VERSION} for your account..."
  ExecWait '"$R0" ${PY_OPTIONS}' $0
  Delete $R0
  Call FindPython
  ${If} $Pythonw == ""
    !insertmacro Fail "Python couldn't be installed (error $0). Install it from https://www.python.org/downloads/ and run setup again."
  ${EndIf}
  StrCpy $PythonInstalled 1
FunctionEnd

; --- Pages -------------------------------------------------------------------------

Function .onInit
  StrCpy $PythonInstalled 0
  Call FindPython
  ; FOLDERID_Downloads: the user may have moved it.
  System::Call 'shell32::SHGetKnownFolderPath(g "{374DE290-123F-4565-9164-39C4925E467B}", i 0, p 0, *p .r1) i.r0'
  ${If} $0 = 0
    System::Call '*$1(&w${NSIS_MAX_STRLEN} .r2)'
    System::Call 'ole32::CoTaskMemFree(p r1)'
  ${Else}
    StrCpy $2 "$PROFILE\Downloads"
  ${EndIf}
  StrCpy $Quarantine "$2\.quarantine"
FunctionEnd

Function OpenKeyPage
  Pop $0
  ExecShell "open" "${KEY_URL}"
FunctionEnd

Function OpenHelp
  Pop $0
  ExecShell "open" "${HELP_URL}"
FunctionEnd

Function WelcomePage
  !insertmacro MUI_HEADER_TEXT "Set up VirusTotal Quarantine" "Checks what your browser downloads before you open it."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 44u "Every file your browser downloads waits in a quarantine folder until VirusTotal has checked it. Clean files move on to your Downloads folder; for anything flagged, you decide. Files VirusTotal has never seen are only uploaded if you say so.$\r$\n$\r$\nInstalls for your account only; no administrator rights needed."
  Pop $0
  StrCpy $3 48
  ${If} $Pythonw == ""
    ${NSD_CreateLabel} 0 $3u 100% 26u "Python ${PY_VERSION} from python.org will be installed first (a 33 MB download). It stays installed if you remove VirusTotal Quarantine later, as other programs may use it."
    Pop $0
    IntOp $3 $3 + 30
  ${EndIf}
  ${NSD_CreateLabel} 0 $3u 100% 10u "Your VirusTotal API key:"
  Pop $0
  IntOp $3 $3 + 11
  ${NSD_CreatePassword} 0 $3u 100% 13u ""
  Pop $KeyField
  IntOp $3 $3 + 16
  ${If} ${FileExists} "${KEY_FILE}"
    ${NSD_CreateLabel} 0 $3u 60% 10u "Leave it empty to keep the key you saved before."
    Pop $0
  ${EndIf}
  ${NSD_CreateLink} 60% $3u 40% 10u "Get a free API key"
  Pop $0
  ${NSD_AddStyle} $0 ${SS_RIGHT}
  ${NSD_OnClick} $0 OpenKeyPage
  GetDlgItem $0 $HWNDPARENT 1
  SendMessage $0 ${WM_SETTEXT} 0 "STR:&Install"
  ${NSD_SetFocus} $KeyField
  nsDialogs::Show
FunctionEnd

Function WelcomeLeave
  ${NSD_GetText} $KeyField $Key
  ; Drop spaces and line breaks that come along when pasting.
  StrCpy $1 ""
  StrCpy $2 0
  ${Do}
    StrCpy $3 $Key 1 $2
    ${If} $3 == ""
      ${Break}
    ${EndIf}
    ${If} $3 != " "
    ${AndIf} $3 != "$\t"
    ${AndIf} $3 != "$\r"
    ${AndIf} $3 != "$\n"
      StrCpy $1 "$1$3"
    ${EndIf}
    IntOp $2 $2 + 1
  ${Loop}
  StrCpy $Key $1
  ${If} $Key == ""
    ${IfNot} ${FileExists} "${KEY_FILE}"
      MessageBox MB_YESNO|MB_ICONQUESTION "Without an API key nothing gets checked, and downloads wait in quarantine.$\r$\n$\r$\nInstall anyway and enter the key later? (A notification will ask for it.)" IDYES +2
      Abort
    ${EndIf}
    Return
  ${EndIf}
  ; 64 hex digits.
  StrLen $1 $Key
  StrCpy $2 0
  ${If} $1 = 64
    ${Do}
      StrCpy $3 $Key 1 $2
      StrCpy $4 0
      ${Do}
        StrCpy $5 "0123456789abcdef" 1 $4
        ${If} $5 == $3  ; == ignores case, so A-F pass too
        ${OrIf} $5 == ""
          ${Break}
        ${EndIf}
        IntOp $4 $4 + 1
      ${Loop}
      ${If} $5 == ""
        ${Break}
      ${EndIf}
      IntOp $2 $2 + 1
    ${LoopUntil} $2 = 64
  ${EndIf}
  ${If} $2 <> 64
    MessageBox MB_ICONEXCLAMATION|MB_OK "That doesn't look like a VirusTotal API key. It's 64 characters long, only digits and the letters a to f. Copy it from the page behind $\"Get a free API key$\"."
    Abort
  ${EndIf}
FunctionEnd

Function CopyPath
  Pop $0
  StrLen $0 $Quarantine
  IntOp $0 $0 + 1
  IntOp $0 $0 * 2
  System::Call 'kernel32::GlobalAlloc(i 0x42, p r0) p.r1'
  System::Call 'kernel32::GlobalLock(p r1) p.r2'
  System::Call 'kernel32::lstrcpyW(p r2, w "$Quarantine")'
  System::Call 'kernel32::GlobalUnlock(p r1)'
  System::Call 'user32::OpenClipboard(p $HWNDPARENT) i.r3'
  ${If} $3 <> 0
    System::Call 'user32::EmptyClipboard()'
    System::Call 'user32::SetClipboardData(i 13, p r1)'
    System::Call 'user32::CloseClipboard()'
  ${EndIf}
FunctionEnd

Function DonePage
  !insertmacro MUI_HEADER_TEXT "VirusTotal Quarantine is running" "It starts by itself whenever you sign in."
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 10u "Last step: make your browser save downloads to this folder."
  Pop $0
  ${NSD_CreateText} 0 13u 78% 13u "$Quarantine"
  Pop $0
  SendMessage $0 ${EM_SETREADONLY} 1 0
  ${NSD_CreateButton} 80% 12u 20% 15u "&Copy"
  Pop $0
  ${NSD_OnClick} $0 CopyPath
  ${NSD_CreateLabel} 0 32u 100% 40u "Firefox: Settings > General > Downloads > Save files to > Browse.$\r$\nChrome or Edge: Settings > Downloads > Location > Change.$\r$\nChecked files then move on to your normal Downloads folder by themselves."
  Pop $0
  ${NSD_CreateLink} 0 74u 100% 10u "Help for other browsers"
  Pop $0
  ${NSD_OnClick} $0 OpenHelp
  StrCpy $3 "To remove it: Settings > Apps > VirusTotal Quarantine > Uninstall."
  ${If} $PythonInstalled = 1
    StrCpy $3 "$3 Python ${PY_VERSION}, installed for it, stays (it's listed there separately)."
  ${EndIf}
  ${NSD_CreateLabel} 0 92u 100% 20u "$3"
  Pop $0
  GetDlgItem $0 $HWNDPARENT 1
  SendMessage $0 ${WM_SETTEXT} 0 "STR:&Finish"
  GetDlgItem $0 $HWNDPARENT 3
  ShowWindow $0 ${SW_HIDE}
  GetDlgItem $0 $HWNDPARENT 2
  ShowWindow $0 ${SW_HIDE}
  nsDialogs::Show
FunctionEnd

; --- Installing ----------------------------------------------------------------------

Function SaveKey
  ${If} $Key != ""
    CreateDirectory "$APPDATA\vt-quarantine"
    FileOpen $0 "${KEY_FILE}" w
    FileWrite $0 "$Key$\n"
    FileClose $0
  ${EndIf}
FunctionEnd

Section
  InitPluginsDir
  ${If} $Pythonw == ""
    Call InstallPython
  ${EndIf}
  ${If} $Key == ""
  ${AndIf} ${FileExists} "${KEY_FILE}"
    ; Kept to put back should removing the old version take it with it.
    FileOpen $0 "${KEY_FILE}" r
    FileRead $0 $Key 64
    FileClose $0
  ${EndIf}
  Call SaveKey
  ; The browser's folder picker needs it to exist.
  CreateDirectory "$Quarantine"

  DetailPrint "Installing VirusTotal Quarantine ${VERSION}..."
  File "/oname=$PLUGINSDIR\vt-quarantine.msi" "${MSI}"
  StrCpy $1 '"$SYSDIR\msiexec.exe" /i "$PLUGINSDIR\vt-quarantine.msi" /qn /norestart PYTHONW="$Pythonw" /l*v "$TEMP\vt-quarantine-setup.log"'
  ExecWait '$1' $0
  ${If} $0 = 1638  ; this version is already installed, from another build
    ExecWait '$1 REINSTALL=ALL REINSTALLMODE=vomus' $0
  ${EndIf}
  ${If} $0 <> 0
  ${AndIf} $0 <> 3010
    !insertmacro Fail "VirusTotal Quarantine couldn't be installed (Windows Installer error $0). Details are in $TEMP\vt-quarantine-setup.log"
  ${EndIf}
  Delete "$TEMP\vt-quarantine-setup.log"
  ${IfNot} ${FileExists} "${KEY_FILE}"
    Call SaveKey
  ${EndIf}
  ; The .msi starts it too; a second copy just exits.
  Exec '"$Pythonw" "$LOCALAPPDATA\vt-quarantine\vt-quarantine.py"'
SectionEnd
