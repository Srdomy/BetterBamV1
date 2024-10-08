$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (NotSigned)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (HashMismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (NotTrusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (UnknownError)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}

# Funzione per determinare il tipo di disco e file system
function Get-DiskInfo {
    param (
        [string]$FilePath
    )

    try {
        $driveLetter = (Split-Path $FilePath -Qualifier)
        $driveInfo = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $driveLetter }
        if ($driveInfo) {
            return "$($driveInfo.FileSystem) ($($driveInfo.Description))"
        } else {
            return "Unknown Disk"
        }
    } catch {
        return "Unknown Disk"
    }
}

# Funzione per determinare se un file è stato eliminato, spostato nel cestino, o cancellato con Shift+Canc
function Check-FileDeletionStatus {
    param (
        [string]$FilePath
    )
    $recycleBinPath = [System.IO.Path]::Combine($env:SystemDrive, "$Recycle.Bin")

    if (!(Test-Path -Path $FilePath)) {
        if (Get-ChildItem -Path $recycleBinPath -Recurse | Where-Object { $_.FullName -like "*$($FilePath)*" }) {
            return "Moved to Recycle Bin"
        } else {
            return "Deleted (Shift+Delete)"
        }
    }
    return "File Exists"
}

# Funzione per determinare se un file è sospetto
function Is-Suspect {
    param (
        [string]$FilePath
    )

    $fileExists = Test-Path -Path $FilePath
    $requiresAdmin = (Get-Acl $FilePath -ErrorAction SilentlyContinue).AreAccessRulesProtected

    if (!$fileExists -or $requiresAdmin) {
        return "Suspect"
    } else {
        return "Not Suspect"
    }
}

Clear-Host

Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Red "   ██████╗░██╗░░░██╗███╗░░░███╗██████╗░"
Write-Host -ForegroundColor Red "   ██╔══██╗██║░░░██║████╗░████║██╔══██╗"
Write-Host -ForegroundColor Red "   ██║░░██║██║░░░██║██╔████╔██║██████╦╝"
Write-Host -ForegroundColor Red "   ██║░░██║██║░░░██║██║╚██╔╝██║██╔══██╗"
Write-Host -ForegroundColor Red "   ██████╔╝╚██████╔╝██║░╚═╝░██║██████╦╝"
Write-Host -ForegroundColor Red "   ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝╚═════╝░"

Write-Host ""
Write-Host -ForegroundColor Red "   ░██████╗░██████╗"
Write-Host -ForegroundColor Red "   ██╔════╝██╔════╝"
Write-Host -ForegroundColor Red "   ╚█████╗░╚█████╗░"
Write-Host -ForegroundColor Red "   ░╚═══██╗░╚═══██╗"
Write-Host -ForegroundColor Red "   ██████╔╝██████╔╝"
Write-Host -ForegroundColor Red "   ╚═════╝░╚═════╝░"

Write-Host ""
Write-Host -ForegroundColor Red "   ██████╗░░█████╗░███╗░░░███╗"
Write-Host -ForegroundColor Red "   ██╔══██╗██╔══██╗████╗░████║"
Write-Host -ForegroundColor Red "   ██████╦╝███████║██╔████╔██║"
Write-Host -ForegroundColor Red "   ██╔══██╗██╔══██║██║╚██╔╝██║"
Write-Host -ForegroundColor Red "   ██████╦╝██║░░██║██║░╚═╝░██║"
Write-Host -ForegroundColor Red "   ╚═════╝░╚═╝░░╚═╝╚═╝░░░░░╚═╝"

Write-Host ""
Write-Host -ForegroundColor Blue "   Made by Srdomy"
Write-Host ""

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    Try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    }
    Catch {
        Write-Warning "Error Mounting HKEY_Local_Machine"
    }
}
$bv = ("bam", "bam\State")
Try {
    $Users = foreach($ii in $bv) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
}
Catch {
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")
$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

$Bam = Foreach ($Sid in $Users) {
    foreach($rp in $rpath) {
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Write-Host -ForegroundColor Red "Extracting " -NoNewLine
        Write-Host -ForegroundColor Blue "$($rp)UserSettings\$SID"
        
        Try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]) 
            $User = $User.Value
        }
        Catch {
            $User = ""
        }
        
        ForEach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item

            if ($key.length -eq 24) {
                $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
                $Biasd = $Bias / 60
                $Dayd = $Day / 60
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss").AddHours($Biasd)
            }

            Write-Host "User: $User  Path: $Item"
        }
    }
}

$sw.Stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host "Total Execution Time: $t Minutes" -ForegroundColor Yellow

# Pausa per prevenire la chiusura immediata
Read-Host "Premi Invio per chiudere la finestra..."
