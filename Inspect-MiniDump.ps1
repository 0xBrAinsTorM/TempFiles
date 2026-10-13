# Read-only Windows minidump metadata and sensitive-data indicators.
# Requires Windows PowerShell 5.1+ or PowerShell 7+.
param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$OutputDirectory = (Join-Path (Get-Location) 'MinidumpReport')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$streamsOut = New-Object 'System.Collections.Generic.List[object]'
$memoryOut  = New-Object 'System.Collections.Generic.List[object]'
$findingsOut = New-Object 'System.Collections.Generic.List[object]'
$summaryOut = New-Object 'System.Collections.Generic.List[object]'
$names = @{3='ThreadList';4='ModuleList';5='MemoryList';6='Exception';7='SystemInfo';9='Memory64List';12='HandleData';15='MiscInfo';16='MemoryInfoList'}
$patterns = [ordered]@{
    'CredentialLabel' = '(?i)\b(pass(word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|bearer|authorization)\b'
    'AccountLabel'    = '(?i)\b(user(name)?|domain|account|logon|principal)\b'
    'NetworkLabel'    = '(?i)\b(ldap|kerberos|ntlm|https?|smb)\b'
}
$files = @(Get-Item -LiteralPath $Path -ErrorAction Stop)
if ($files.Count -eq 1 -and $files[0].PSIsContainer) {
    $files = @(Get-ChildItem -LiteralPath $Path -Filter '*.dmp' -File)
}
foreach ($file in $files) {
    try {
        $b = [IO.File]::ReadAllBytes($file.FullName)
        function Check([long]$p, [long]$n) {
            if ($p -lt 0 -or $n -lt 0 -or $p + $n -gt $b.Length) { throw "Ungueltiger Offset $p / $n" }
        }
        function U16([long]$p) { Check $p 2; [BitConverter]::ToUInt16($b,[int]$p) }
        function U32([long]$p) { Check $p 4; [BitConverter]::ToUInt32($b,[int]$p) }
        function U64([long]$p) { Check $p 8; [BitConverter]::ToUInt64($b,[int]$p) }
        function MdString([long]$p) {
            Check $p 4
            $len = U32 $p
            if ($len -gt 16384 -or ($len % 2)) { return '[invalid string]' }
            Check ($p+4) $len
            [Text.Encoding]::Unicode.GetString($b,[int]($p+4),[int]$len)
        }
        Check 0 32
        if ([Text.Encoding]::ASCII.GetString($b,0,4) -ne 'MDMP') { throw 'Keine MDMP-Datei' }
        $count=U32 8; $dir=U32 12
        if ($count -gt 2000) { throw 'Zu viele Streams' }
        Check $dir ([long]$count*12)
        $info = [ordered]@{File=$file.Name;Size=$b.Length;Streams=$count;OS='';ProcessID='';Exception='';Modules='';Error=''}
        $regions = New-Object 'System.Collections.Generic.List[object]'
        for($i=0;$i -lt $count;$i++) {
            $ent=[long]$dir+[long]$i*12
            $t=U32 $ent; $sz=U32 ($ent+4); $p=U32 ($ent+8)
            Check $p $sz
            $name=if($names.ContainsKey([int]$t)){$names[[int]$t]}else{'Other'}
            $streamsOut.Add([pscustomobject]@{File=$file.Name;Type=$t;Name=$name;Bytes=$sz;FileOffset=$p})
            switch ($t) {
                4 {
                    if ($sz -lt 4) { break }
                    $n=U32 $p
                    if ([long]$n*108+4 -gt $sz) { break }
                    $mods=New-Object 'System.Collections.Generic.List[string]'
                    for($j=0;$j -lt $n;$j++) {
                        $off=[long]$p+4+[long]$j*108
                        $rva=U32 ($off+20)
                        try { $mods.Add((MdString $rva)) } catch {}
                    }
                    $info.Modules=($mods -join '; ')
                }
                5 {
                    if ($sz -lt 4) { break }
                    $n=U32 $p
                    if ([long]$n*16+4 -gt $sz) { break }
                    for($j=0;$j -lt $n;$j++) {
                        $off=[long]$p+4+[long]$j*16
                        $v=U64 $off; $len=U32 ($off+8); $rva=U32 ($off+12)
                        Check $rva $len
                        $regions.Add([pscustomobject]@{Type=5;Address=('0x{0:X16}' -f $v);Offset=[long]$rva;Length=[long]$len})
                    }
                }
                9 {
                    if ($sz -lt 16) { break }
                    $n=U64 $p; $base=U64 ($p+8)
                    if ($n -gt 100000 -or [decimal]$n*16+16 -gt $sz) { break }
                    $cursor=[long]$base
                    for($j=0;$j -lt $n;$j++) {
                        $off=[long]$p+16+[long]$j*16
                        $v=U64 $off; $len=U64 ($off+8)
                        Check $cursor $len
                        $regions.Add([pscustomobject]@{Type=9;Address=('0x{0:X16}' -f $v);Offset=$cursor;Length=[long]$len})
                        $cursor += [long]$len
                    }
                }
                6 {
                    if ($sz -ge 32) {
                        $code=U32 ($p+8); $thread=U32 $p; $addr=U64 ($p+24)
                        $info.Exception=('Thread={0}, Code=0x{1:X8}, Address=0x{2:X16}' -f $thread,$code,$addr)
                    }
                }
                7 {
                    if ($sz -ge 20) {
                        $arch=U16 $p; $maj=U32 ($p+8);$min=U32 ($p+12);$build=U32 ($p+16)
                        $info.OS="Version $maj.$min Build $build (Arch-ID $arch)"
                    }
                }
                15 {
                    if ($sz -ge 12 -and ((U32 ($p+4)) -band 1)) { $info.ProcessID=U32 ($p+8) }
                }
            }
        }
        foreach($r in $regions) {
            $memoryOut.Add([pscustomobject]@{File=$file.Name;Type=$r.Type;VirtualAddress=$r.Address;Bytes=$r.Length;FileOffset=$r.Offset})
            if ($r.Length -eq 0) { continue }
            # Heuristic only: scan bounded memory regions for keyword PRESENCE, never output values.
            $raw=[Text.Encoding]::GetEncoding(28591).GetString($b,[int]$r.Offset,[int]$r.Length)
            $wide=[Text.Encoding]::Unicode.GetString($b,[int]$r.Offset,[int]([math]::Floor($r.Length/2)*2))
            foreach($label in $patterns.Keys) {
                $regex=$patterns[$label]
                $asciiHits=([regex]::Matches($raw,$regex)).Count
                $utf16Hits=([regex]::Matches($wide,$regex)).Count
                if ($asciiHits+$utf16Hits -gt 0) {
                    $findingsOut.Add([pscustomobject]@{File=$file.Name;Region=$r.Address;Category=$label;AsciiHits=$asciiHits;Utf16Hits=$utf16Hits;Note='Keyword only; no secret value extracted'})
                }
            }
        }
        $summaryOut.Add([pscustomobject]$info)
    } catch {
        $summaryOut.Add([pscustomobject]@{File=$file.Name;Size=$file.Length;Streams='';OS='';ProcessID='';Exception='';Modules='';Error=$_.Exception.Message})
    }
}
$summaryOut | Export-Csv -Path (Join-Path $OutputDirectory 'summary.csv') -NoTypeInformation -Encoding UTF8
$streamsOut | Export-Csv -Path (Join-Path $OutputDirectory 'streams.csv') -NoTypeInformation -Encoding UTF8
$memoryOut | Export-Csv -Path (Join-Path $OutputDirectory 'memory-regions.csv') -NoTypeInformation -Encoding UTF8
$findingsOut | Export-Csv -Path (Join-Path $OutputDirectory 'sensitive-indicators.csv') -NoTypeInformation -Encoding UTF8
$summaryOut | Format-Table File,Size,Streams,OS,ProcessID,Exception,Error -AutoSize
Write-Host "Berichte gespeichert in: $OutputDirectory"
Write-Host 'Hinweis: Indikatoren sind heuristisch; keine Aussage ueber tatsaechlich gespeicherte Zugangsdaten.'
