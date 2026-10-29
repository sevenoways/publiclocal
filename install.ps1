# Installs the latest PublicLocal release on Windows:
#   irm https://publiclocal.app/install.ps1 | iex
# Picks the right build for this PC (x64 or ARM64), verifies its checksum,
# installs to %LOCALAPPDATA%\Programs\publiclocal and adds that folder to your PATH.
# Set $env:PUBLICLOCAL_VERSION = "v0.5.1" first to pin a version.

& {
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue" # much faster downloads in Windows PowerShell 5.1
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = "sevenoways/publiclocal"

    $arch = $env:PROCESSOR_ARCHITEW6432 # set when 32-bit PowerShell runs on 64-bit Windows
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        "AMD64" { $goarch = "amd64" }
        "ARM64" { $goarch = "arm64" }
        default { throw "PublicLocal: unsupported processor '$arch'. Download a build from https://github.com/$repo/releases" }
    }

    $version = $env:PUBLICLOCAL_VERSION
    if (-not $version) {
        $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "publiclocal-install" }).tag_name
    }
    $file = "publiclocal_$($version.TrimStart('v'))_windows_$goarch.zip"
    $url = "https://github.com/$repo/releases/download/$version"

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("publiclocal-" + [Guid]::NewGuid())
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        Write-Host "Downloading PublicLocal $version for windows/$goarch..."
        Invoke-WebRequest "$url/$file" -OutFile "$tmp\$file" -UseBasicParsing
        Invoke-WebRequest "$url/checksums.txt" -OutFile "$tmp\checksums.txt" -UseBasicParsing

        $line = Select-String -Path "$tmp\checksums.txt" -Pattern ([regex]::Escape($file)) | Select-Object -First 1
        if (-not $line) { throw "PublicLocal: $file is not listed in checksums.txt" }
        $want = $line.Line.Split(" ")[0]
        $got = (Get-FileHash "$tmp\$file" -Algorithm SHA256).Hash.ToLower()
        if ($want -ne $got) { throw "PublicLocal: checksum mismatch for $file" }

        Expand-Archive "$tmp\$file" -DestinationPath "$tmp\x" -Force
        $dir = Join-Path $env:LOCALAPPDATA "Programs\publiclocal"
        New-Item -ItemType Directory $dir -Force | Out-Null
        Copy-Item "$tmp\x\publiclocal.exe" "$dir\publiclocal.exe" -Force
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($parts -notcontains $dir) {
        [Environment]::SetEnvironmentVariable("Path", (($parts + $dir) -join ";"), "User")
        Write-Host "Added $dir to your PATH."
    }
    if (($env:Path -split ";") -notcontains $dir) { $env:Path = "$env:Path;$dir" }

    Write-Host ("Installed " + (& "$dir\publiclocal.exe" version) + " to $dir\publiclocal.exe")
    Write-Host "Try it:  publiclocal http 3000"
    Write-Host "Other terminals pick up the new PATH once reopened."
}
