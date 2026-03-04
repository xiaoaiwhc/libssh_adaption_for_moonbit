#Requires -Version 5.1
<#
.SYNOPSIS
    One-time setup for the libssh_mb MoonBit project on Windows.

.DESCRIPTION
    1. Resolves the vcpkg installed-packages directory (x64-windows triplet).
    2. Generates src/main/moon.pkg.json from src/main/moon.pkg.json.template.
    3. Compiles src/ffi/c_stub.c into src/ffi/c_stub.lib via MSVC (cl.exe).
    4. Creates a minimal windows.h stub in the MoonBit TCC include directory so
       that 'moon test --target native' can compile the runtime on Windows.

    Run this script once after cloning the repository, or whenever the vcpkg
    root changes.  It must be executed from the openssh_adaption/ directory.

.PARAMETER VcpkgRoot
    Path to the vcpkg root (the directory that contains vcpkg.exe).
    Defaults to the VCPKG_ROOT environment variable, then tries common locations.

.EXAMPLE
    # Auto-detect from %VCPKG_ROOT%
    .\setup.ps1

    # Supply path explicitly
    .\setup.ps1 -VcpkgRoot "D:\tools\vcpkg"
#>
param(
    [string]$VcpkgRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. Resolve vcpkg root ────────────────────────────────────────────────────

if (-not $VcpkgRoot) {
    if ($env:VCPKG_ROOT) {
        $VcpkgRoot = $env:VCPKG_ROOT
    } else {
        # Try common sibling locations relative to this script
        $candidates = @(
            (Join-Path (Split-Path (Split-Path $PSScriptRoot)) "vcpkg"),
            "C:\vcpkg",
            "C:\Projects\vcpkg",
            "C:\dev\vcpkg"
        )
        foreach ($c in $candidates) {
            if (Test-Path (Join-Path $c "vcpkg.exe")) {
                $VcpkgRoot = $c
                break
            }
        }
    }
}

if (-not $VcpkgRoot -or -not (Test-Path (Join-Path $VcpkgRoot "vcpkg.exe"))) {
    Write-Error @"
Could not locate vcpkg.  Please either:
  • Set the VCPKG_ROOT environment variable, or
  • Pass -VcpkgRoot <path> to this script.
"@
    exit 1
}

$VcpkgRoot        = $VcpkgRoot.TrimEnd('\', '/')
$VcpkgInstalled   = Join-Path $VcpkgRoot "installed\x64-windows"
$VcpkgInstalledFwd = $VcpkgInstalled -replace '\\', '/'

Write-Host "vcpkg root     : $VcpkgRoot"
Write-Host "vcpkg installed: $VcpkgInstalled"

# ── 2. Generate moon.pkg.json from template ──────────────────────────────────

$templatePath = Join-Path $PSScriptRoot "src\main\moon.pkg.json.template"
$outputPath   = Join-Path $PSScriptRoot "src\main\moon.pkg.json"

if (-not (Test-Path $templatePath)) {
    Write-Error "Template not found: $templatePath"
    exit 1
}

$content = Get-Content $templatePath -Raw
$content = $content -replace '\$\{VCPKG_INSTALLED\}', $VcpkgInstalledFwd

# Detect Windows Kits 10 UM lib path for ws2_32.lib / crypt32.lib
# We use the 8.3 short path to avoid spaces that would break TCC linker flags.
$wkBase = "C:\Program Files (x86)\Windows Kits\10\Lib"
$wkUmLib = $null
if (Test-Path $wkBase) {
    $latestWk = Get-ChildItem $wkBase -Directory |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                Sort-Object Name -Descending |
                Select-Object -First 1
    if ($latestWk) {
        $wkUmPath = Join-Path $latestWk.FullName "um\x64"
        if (Test-Path $wkUmPath) {
            # Get the 8.3 short path to avoid spaces in TCC linker flags.
            $fso = New-Object -Com Scripting.FileSystemObject
            try {
                $wkUmLib = ($fso.GetFolder($wkUmPath).ShortPath) -replace '\\', '/'
            } catch {
                # Fallback: use forward-slash version (may have spaces)
                $wkUmLib = $wkUmPath -replace '\\', '/'
            }
        }
    }
}
if (-not $wkUmLib) {
    Write-Warning "Could not locate Windows Kits UM lib directory. ws2_32.lib and crypt32.lib may not be found during native test linking."
    $wkUmLib = "C:/PROGRA~2/WI3CF2~1/10/Lib/100190~1.0/um/x64"  # fallback guess
}
Write-Host "Win Kits UM lib: $wkUmLib"
$content = $content -replace '\$\{WK_UM_LIB\}', $wkUmLib

Set-Content -Path $outputPath -Value $content -Encoding UTF8 -NoNewline
Write-Host "Generated: $outputPath"

# ── 3. Compile c_stub.c to c_stub.lib (requires MSVC in PATH) ───────────────

$ffiDir  = Join-Path $PSScriptRoot "src\ffi"
$stubC   = Join-Path $ffiDir "c_stub.c"
$stubLib = Join-Path $ffiDir "c_stub.lib"
$stubObj = Join-Path $ffiDir "c_stub.obj"

if (-not (Test-Path $stubC)) {
    Write-Error "C stub not found: $stubC"
    exit 1
}

# Locate cl.exe (try vswhere first, then PATH)
$clExe = (Get-Command "cl.exe" -ErrorAction SilentlyContinue)?.Source
if (-not $clExe) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath  = & $vswhere -latest -property installationPath 2>$null
        $msvcDir = Get-ChildItem (Join-Path $vsPath "VC\Tools\MSVC") -Directory |
                   Sort-Object Name -Descending | Select-Object -First 1
        $clExe   = Join-Path $msvcDir.FullName "bin\Hostx64\x64\cl.exe"
    }
}

if (-not $clExe -or -not (Test-Path $clExe)) {
    Write-Warning @"
cl.exe not found in PATH.  Skipping C stub compilation.

To compile manually, load the MSVC environment first, then run:
  cd "$ffiDir"
  cl.exe /nologo /c /MD /W3 /O2 /I "$VcpkgInstalled\include" c_stub.c
  lib.exe /nologo /OUT:c_stub.lib c_stub.obj

If you have Build Tools for Visual Studio 2022 (standalone), load the
environment with:
  & "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64

If you have the full VS 2022 IDE, open 'Developer PowerShell for VS 2022'
from the Start menu.
"@
} else {
    Push-Location $ffiDir
    try {
        Write-Host "Compiling c_stub.c with $clExe..."
        & $clExe /nologo /c /MD /W3 /O2 /I "$VcpkgInstalled\include" c_stub.c
        if ($LASTEXITCODE -ne 0) { throw "cl.exe failed (exit $LASTEXITCODE)" }
        & lib.exe /nologo /OUT:c_stub.lib c_stub.obj
        if ($LASTEXITCODE -ne 0) { throw "lib.exe failed (exit $LASTEXITCODE)" }
        Write-Host "Created: $stubLib"
    } finally {
        Pop-Location
    }
}

Write-Host ""

# ── 4. Create minimal windows.h stub for MoonBit's TCC ──────────────────────
# MoonBit's bundled TCC (used internally by moon for native compilation) does
# not ship Windows SDK headers.  We create a minimal stub in its include
# directory so that runtime.c (which uses a few Win32 APIs) compiles correctly.

$moonInclude = Join-Path $env:USERPROFILE ".moon\include"
if (-not (Test-Path $moonInclude)) {
    $moonInclude = Join-Path $env:APPDATA ".moon\include"
}
if (-not (Test-Path $moonInclude)) {
    # Try to find moon's include dir from the moon executable
    $moonExe = (Get-Command "moon.exe" -ErrorAction SilentlyContinue)?.Source
    if ($moonExe) {
        $moonBin  = Split-Path $moonExe
        $moonInclude = Join-Path (Split-Path $moonBin) "include"
    }
}

if (Test-Path $moonInclude) {
    $winHeaderPath = Join-Path $moonInclude "windows.h"
    if (-not (Test-Path $winHeaderPath)) {
        Write-Host "Creating minimal windows.h stub for MoonBit TCC at: $winHeaderPath"
        $stub = @'
/*
 * Minimal windows.h stub for MoonBit's bundled TCC on Windows.
 * Generated by openssh_adaption/setup.ps1 — do not edit manually.
 * Provides just enough declarations for MoonBit's runtime.c to compile.
 */
#ifndef _WINDOWS_H
#define _WINDOWS_H
typedef unsigned long  DWORD;
typedef int            BOOL;
typedef void *         HANDLE;
typedef unsigned int   UINT;
typedef long           LONG;
typedef char *         LPSTR;
typedef const char *   LPCSTR;
typedef void *         LPVOID;
typedef unsigned char  BYTE;
typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; };
    long long QuadPart;
} LARGE_INTEGER;
#define CP_UTF8                 65001
#define INVALID_HANDLE_VALUE    ((HANDLE)(long long)-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define MAX_PATH                260
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    DWORD ftCreationTime[2]; DWORD ftLastAccessTime[2]; DWORD ftLastWriteTime[2];
    DWORD nFileSizeHigh; DWORD nFileSizeLow;
    DWORD dwReserved0; DWORD dwReserved1;
    char  cFileName[MAX_PATH]; char cAlternateFileName[14];
} WIN32_FIND_DATAA, WIN32_FIND_DATA;
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __declspec
#define __declspec(x)
#endif
#ifndef WINAPI
#define WINAPI
#endif
UINT  GetConsoleOutputCP(void);
BOOL  SetConsoleOutputCP(UINT wCodePageID);
DWORD GetFileAttributes(LPCSTR lpFileName);
HANDLE FindFirstFileA(LPCSTR lpFileName, WIN32_FIND_DATAA *lpFindFileData);
BOOL   FindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA *lpFindFileData);
BOOL   FindClose(HANDLE hFindFile);
#define FindFirstFile  FindFirstFileA
#define FindNextFile   FindNextFileA
DWORD GetLastError(void);
BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
#endif /* _WINDOWS_H */
'@
        Set-Content -Path $winHeaderPath -Value $stub -Encoding UTF8 -NoNewline
        Write-Host "Created: $winHeaderPath"
    } else {
        Write-Host "windows.h stub already exists: $winHeaderPath"
    }
} else {
    Write-Warning "Could not locate MoonBit's TCC include directory; skipping windows.h stub creation."
    Write-Warning "If 'moon test --target native' fails with 'windows.h not found',"
    Write-Warning "manually create a windows.h stub at: <moon_home>\include\windows.h"
}

Write-Host ""
Write-Host "Setup complete.  You can now build with:"
Write-Host "  moon build --target native"
Write-Host "  moon test  --target native"